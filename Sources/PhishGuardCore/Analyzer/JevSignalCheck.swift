import Foundation
import SwiftSoup
import os.log

private let logger = Logger(subsystem: "com.phishguard", category: "JevSignalCheck")

/// Asks Jev (TypeSafe's System One model) a few narrow yes/no questions about an email
/// and turns confident answers into points.
///
/// Jev is deliberately *not* asked "is this phishing?": in the public 2,000-email benchmark
/// its direct verdict scored 62.6% accuracy with an 18% false-positive rate, while narrow
/// signal questions combined in code reached ~95%. The local checks already cover headers
/// and URL structure; these signals cover what they cannot — who the email claims to be
/// and what it asks the reader to do. The impersonation signal replaces the keyword-list
/// `BrandImpersonationCheck` whenever Jev answers.
///
/// Jev is only consulted when it can change the outcome (see `needsQuery`), at most
/// `dailyCallLimit` times per day, and once per message per app run.
public actor JevSignalCheck {
    public static let checkName = "AI Signal Check"
    /// UserDefaults key for the user's opt-in toggle.
    public static let enabledDefaultsKey = "jevEnabled"
    /// Credential vault key for the TypeSafe API key.
    public static let apiKeyVaultKey = "typesafeApiKey"

    /// Minimum probability for a signal to count.
    static let threshold = 0.7
    /// Prior clean verdicts needed (with DMARC pass) before a sender domain is trusted without asking Jev.
    static let knownSenderMinimum = 3
    static let maxBodyCharacters = 2_000
    static let maxLinks = 15
    static let cacheLimit = 1_000

    struct Signal: Sendable {
        let id: String
        let points: Int
        let reason: String
        let instructions: String
    }

    /// "Who" signals carry the weight; "what it asks" signals only tip an already-suspicious email
    /// over a threshold, so a legitimate "your password expires soon" mail stays clean.
    static let signals: [Signal] = [
        Signal(
            id: "impersonation", points: 4,
            reason: "Claims to be a known organization but the sender domain is not theirs",
            instructions: "The email presents itself as coming from a well-known company, bank, government agency or delivery service, but the sender domain in `from_domain` does not belong to that organization."
        ),
        Signal(
            id: "generic_sender", points: 3,
            reason: "Free webmail address posing as an organization",
            instructions: "The sender in `from` uses a free webmail address (such as gmail, outlook, hotmail, yahoo or icloud) while presenting themselves as a company, team, department or organization."
        ),
        Signal(
            id: "risky_link_host", points: 3,
            reason: "Link points to a URL shortener or free hosting platform",
            instructions: "At least one link in `links` points to a URL shortener, or to a free hosting, form-builder or file-sharing platform (for example bit.ly, an IPFS gateway, Firebase, GitHub Pages, Google Forms, Weebly), rather than to the organization's own website."
        ),
        Signal(
            id: "payment_request", points: 2,
            reason: "Asks for a payment, bank detail change or gift cards",
            instructions: "The email asks the reader to pay, transfer money, change bank or payment details, or buy gift cards."
        ),
        Signal(
            id: "credential_lure", points: 1,
            reason: "Asks to sign in, verify an account or open a document",
            instructions: "The email asks the reader to sign in, verify or unlock an account, confirm personal or card details, or open a document through a link."
        ),
        Signal(
            id: "pressure", points: 1,
            reason: "Pressures the reader with a deadline or threat",
            instructions: "The email pressures the reader to act quickly, mentions a short deadline, or threatens a consequence such as suspension, a fine or a lost parcel."
        ),
    ]

    static let questions: [String: JevQuestion] = Dictionary(
        uniqueKeysWithValues: signals.map { ($0.id, JevQuestion.noul($0.instructions)) }
    )

    private let client: JevAnswering
    private let verdictStore: VerdictStore?
    private let dailyCallLimit: Int
    private let isEnabled: @Sendable () -> Bool

    private var cache: [String: [CheckResult]] = [:]
    private var budgetDay = Date.distantPast
    private var callsToday = 0

    /// - Parameters:
    ///   - verdictStore: Used to recognise established senders; pass nil to always ask.
    ///   - dailyCallLimit: Safety net against runaway rescans (e.g. a full-mailbox scan).
    ///   - isEnabled: Read on every email so the Settings toggle takes effect immediately.
    public init(
        client: JevAnswering,
        verdictStore: VerdictStore? = nil,
        dailyCallLimit: Int = 500,
        isEnabled: @escaping @Sendable () -> Bool = { true }
    ) {
        self.client = client
        self.verdictStore = verdictStore
        self.dailyCallLimit = dailyCallLimit
        self.isEnabled = isEnabled
    }

    /// Returns signal results (possibly empty), or nil when Jev was not consulted:
    /// disabled, not needed, over budget, or the call failed. Never throws — callers
    /// fall back to the local verdict.
    public func signals(for email: ParsedEmail, context: AnalysisContext, localScore: Int) async -> [CheckResult]? {
        guard isEnabled() else { return nil }
        if let cached = cache[email.messageId] { return cached }
        guard needsQuery(email: email, localScore: localScore) else { return nil }
        guard reserveCall() else {
            logger.info("Daily Jev call limit reached; using local checks only")
            return nil
        }

        do {
            let answers = try await client.probabilities(
                state: Self.state(for: email, context: context),
                questions: Self.questions
            )
            let results = Self.results(from: answers)
            if cache.count >= Self.cacheLimit { cache.removeAll() }
            cache[email.messageId] = results
            return results
        } catch {
            logger.warning("Jev call failed, using local checks only: \(error.localizedDescription)")
            return nil
        }
    }

    /// Whether asking Jev could change the outcome. Skips emails the local checks already
    /// condemned, and authenticated mail from senders that have repeatedly been clean —
    /// the bulk of everyday volume, and mail the user would least want sent to a third party.
    nonisolated func needsQuery(email: ParsedEmail, localScore: Int) -> Bool {
        if localScore >= PhishGuardThresholds.phishing { return false }

        let dmarcPass = email.authenticationResults?.lowercased().contains("dmarc=pass") ?? false
        guard dmarcPass, !email.fromDomain.isEmpty, let store = verdictStore else { return true }

        let priorClean = (try? store.cleanVerdictCount(domain: email.fromDomain, excludingMessageId: email.messageId)) ?? 0
        return priorClean < Self.knownSenderMinimum
    }

    private func reserveCall() -> Bool {
        let today = Calendar.current.startOfDay(for: Date())
        if today != budgetDay {
            budgetDay = today
            callsToday = 0
        }
        guard callsToday < dailyCallLimit else { return false }
        callsToday += 1
        return true
    }

    // MARK: - Request / response mapping

    /// Compact, privacy-reduced view of the email: body truncated, link query strings and
    /// fragments removed (they carry tracking tokens and often the recipient's address).
    static func state(for email: ParsedEmail, context: AnalysisContext) -> [String: String] {
        var state: [String: String] = [
            "from": email.from,
            "from_domain": email.fromDomain,
            "subject": email.subject,
            "body": String(bodyText(of: email).prefix(maxBodyCharacters)),
        ]
        if let replyTo = email.headers["Reply-To"], !replyTo.isEmpty {
            state["reply_to"] = replyTo
        }

        var seen = Set<String>()
        let links = context.links.compactMap { link -> String? in
            guard let url = strippedURL(link.href) else { return nil }
            let text = collapseWhitespace(link.displayText)
            return text.isEmpty ? url : "\(text.prefix(80)) -> \(url)"
        }
        .filter { seen.insert($0).inserted }
        .prefix(maxLinks)
        if !links.isEmpty {
            state["links"] = links.joined(separator: "\n")
        }
        return state
    }

    static func strippedURL(_ href: String) -> String? {
        guard var components = URLComponents(string: href),
              let scheme = components.scheme?.lowercased(), scheme == "http" || scheme == "https",
              components.host != nil else { return nil }
        components.query = nil
        components.fragment = nil
        components.user = nil
        components.password = nil
        return components.string
    }

    static func bodyText(of email: ParsedEmail) -> String {
        if let text = email.textBody, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return collapseWhitespace(text)
        }
        if let html = email.htmlBody, let doc = try? SwiftSoup.parse(html), let text = try? doc.text() {
            return collapseWhitespace(text)
        }
        return ""
    }

    static func results(from answers: [String: Double]) -> [CheckResult] {
        signals.compactMap { signal in
            guard let probability = answers[signal.id], probability >= threshold else { return nil }
            return CheckResult(
                checkName: checkName,
                points: signal.points,
                reason: "\(signal.reason) (AI, \(Int((probability * 100).rounded()))%)"
            )
        }
    }

    private static func collapseWhitespace(_ text: String) -> String {
        text.split(whereSeparator: \.isWhitespace).joined(separator: " ")
    }
}
