import Foundation

/// A `noul` question for Jev: a statement about the email, answered with the
/// probability (0...1) that it is true. Field names in the state are referenced
/// in backticks, as TypeSafe's docs recommend.
public struct JevQuestion: Sendable, Encodable {
    public let type: String
    public let instructions: String

    public static func noul(_ instructions: String) -> JevQuestion {
        JevQuestion(type: "noul", instructions: instructions)
    }
}

/// Abstraction over the Jev API so the analyzer can be tested without network access.
public protocol JevAnswering: Sendable {
    /// Returns the `noul` probability for each question id.
    func probabilities(state: [String: String], questions: [String: JevQuestion]) async throws -> [String: Double]
}

public enum JevError: Error {
    case missingAPIKey
    case http(status: Int)
}

/// Minimal client for TypeSafe's System One API (`POST /v1/systemone`, model `jev-latest`).
/// Billing is per input token only (~$0.042 per 1M tokens as of Sept 2026).
public struct JevClient: JevAnswering {
    public static let defaultEndpoint = URL(string: "https://api.typesafe.ai/v1/systemone")!

    private let endpoint: URL
    private let model: String
    private let apiKey: @Sendable () -> String?
    private let session: URLSession

    /// - Parameters:
    ///   - apiKey: Read on every call so a key entered in Settings takes effect immediately.
    ///   - timeout: Kept short: on timeout the local verdict is used instead.
    public init(
        apiKey: @escaping @Sendable () -> String?,
        endpoint: URL = JevClient.defaultEndpoint,
        model: String = "jev-latest",
        timeout: TimeInterval = 4
    ) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 2
        self.session = URLSession(configuration: config)
        self.endpoint = endpoint
        self.model = model
        self.apiKey = apiKey
    }

    public func probabilities(state: [String: String], questions: [String: JevQuestion]) async throws -> [String: Double] {
        guard let key = apiKey(), !key.isEmpty else { throw JevError.missingAPIKey }

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(RequestBody(state: state, model: model, questions: questions))

        // One retry on rate limit (429) or overload (529); any other failure falls back to local-only.
        var status = 0
        for attempt in 0..<2 {
            let (data, response) = try await session.data(for: request)
            status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if (status == 429 || status == 529) && attempt == 0 {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }
            guard status == 200 else { break }
            let body = try JSONDecoder().decode(ResponseBody.self, from: data)
            return body.answers.compactMapValues { $0.noul }
        }
        throw JevError.http(status: status)
    }

    private struct RequestBody: Encodable {
        let state: [String: String]
        let model: String
        let questions: [String: JevQuestion]
    }

    private struct ResponseBody: Decodable {
        struct Answer: Decodable {
            let noul: Double?
        }
        let answers: [String: Answer]
    }
}
