# PhishGuard — Mac Mail Phishing Detection MVP Plan

## Context

There is **no phishing detection tool for Apple Mail** today — not as an extension, not as a standalone app. SpamSieve does spam filtering but no phishing-specific analysis. Enterprise tools (Mimecast, Proofpoint) have no consumer editions. This is a genuine gap.

Apple's MailKit framework is **unreliable** — SpamSieve's developer (Michael Tsai) documented years of bugs culminating in: *"The extension does essentially nothing because the available functionality is extremely limited and the API still mostly doesn't work"* (Sept 2025). Other developers (SmallCubed, Marketcircle, Mailbutler) confirm the same experience.

**Chosen architecture:** Hybrid — a **menu bar app** does all the real work via IMAP, with a **thin MailKit extension** that reads verdicts from shared storage and applies color labels in Mail.app. If the extension breaks (as MailKit tends to), the menu bar app still catches everything.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  PhishGuard.app  (menu bar app, host for extension) │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  IMAP Monitor (SwiftMail / SwiftNIO)        │    │
│  │  - Connects to mail account                 │    │
│  │  - IDLE for real-time new mail detection     │    │
│  │  - Fetches headers + body of new emails      │    │
│  │  - Can flag/move emails server-side          │    │
│  └──────────────┬──────────────────────────────┘    │
│                 │                                    │
│  ┌──────────────▼──────────────────────────────┐    │
│  │  PhishingAnalyzer (detection engine)         │    │
│  │  - Auth header analysis (SPF/DKIM/DMARC)    │    │
│  │  - Return-Path vs From mismatch             │    │
│  │  - Link analysis (href vs display text)     │    │
│  │  - Blacklist lookup (local cache)           │    │
│  │  - Typosquatting / homoglyph detection      │    │
│  │  → Produces suspicion score + reasons        │    │
│  └──────────────┬──────────────────────────────┘    │
│                 │                                    │
│  ┌──────────────▼──────────────────────────────┐    │
│  │  Shared App Group Storage                    │    │
│  │  verdicts.sqlite:                            │    │
│  │  { messageId, score, reasons[], timestamp }  │    │
│  │  +  blacklist cache                          │    │
│  │  +  brand domain list                        │    │
│  │  +  user allowlist                           │    │
│  └──────────────┬──────────────────────────────┘    │
│                 │                                    │
│  ┌──────────────▼──────────────────────────────┐    │
│  │  Notifications + UI                          │    │
│  │  - macOS notifications for suspicious emails │    │
│  │  - Menu bar dropdown: recent alerts, stats   │    │
│  │  - Settings: accounts, sensitivity, brands   │    │
│  └─────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────┤
│  Mail Extension (thin client, reads shared data)    │
│  ┌─────────────────────────────────────────────┐    │
│  │  MEMessageActionHandler                      │    │
│  │  1. Extract Message-ID from headers          │    │
│  │  2. Look up verdict in shared SQLite         │    │
│  │  3. If found → return color/flag/move        │    │
│  │  4. If not found → lightweight local check   │    │
│  │     (parse Auth-Results header only)         │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

**Why this works:** The menu bar app is the reliable backbone. The Mail extension is a best-effort visual enhancement. If MailKit breaks, users still get notifications and IMAP-side flagging.

---

## IMAP Library

**Primary choice: SwiftMail** (Cocoanetics/SwiftMail)
- Built on apple/swift-nio-imap, async/await with Swift actors
- IDLE support for real-time monitoring
- Supports PLAIN/LOGIN auth over TLS — works with any standard IMAP server
- BSD license, macOS 11+
- Caveat: new (March 2025), no XOAUTH2 yet

**MVP scope: Any IMAP provider** using PLAIN/LOGIN auth over TLS. This covers the majority of providers (iCloud with app-specific password, Telenet, Proximus, Outlook with app password, self-hosted, etc.). Gmail/Outlook OAuth2 support deferred to a later phase.

**Future: OAuth2 for Gmail/Outlook** via `ASWebAuthenticationSession` + Keychain, or switch to MailFoundation (migueldeicaza) which has XOAUTH2 built in (requires Swift 6.2+).

---

## MVP Scope (Phase 1)

### Detection Checks (Tier 1 only — high value, low false-positive risk)

| # | Check | Points | Implementation |
|---|---|---|---|
| 1 | **SPF/DKIM/DMARC fail** | +3 each | Parse `Authentication-Results` header for `fail`/`softfail`/`none` |
| 2 | **Return-Path vs From mismatch** | +3 | Compare envelope sender domain with From domain |
| 3 | **Known phishing domain** | +5 | Check sender domain + URLs against cached Phishing Army blocklist |
| 4 | **Link text vs URL mismatch** | +4 | Parse HTML with SwiftSoup, compare `<a>` display domain vs `href` domain |
| 5 | **IP address in URL** | +4 | Regex detect `https?://\d+\.\d+\.\d+\.\d+` in body links |
| 6 | **Suspicious TLD** | +2 | Sender or link domains using .tk, .ml, .ga, .cf, .gq, .xyz, .top |

**Scoring thresholds:**
- 0–2: Clean — no action
- 3–5: Suspicious — yellow color in Mail, info notification
- 6+: Likely phishing — red color in Mail, move to Junk via IMAP, alert notification

### What's NOT in MVP
- Typosquatting / homoglyph detection (Phase 2)
- Google Safe Browsing / PhishTank API (Phase 2)
- Domain age checking (Phase 3)
- Urgency language scoring (Phase 3)
- ML classifier (Phase 4)
- Attachment analysis (Phase 4)

---

## Implementation Steps

### Step 1: Project Setup
- Create Xcode project: macOS app + Mail Extension target
- Configure App Group entitlement (shared between app and extension)
- Set up SPM dependencies: SwiftMail, SwiftSoup
- Menu bar app skeleton (`NSStatusItem` + SwiftUI popover)
- Target: macOS 14+ (Sonoma) for MailKit stability

### Step 2: Shared Data Layer
- SQLite database in App Group container (via SwiftData or raw SQLite)
- Tables:
  - `verdicts`: messageId (TEXT PK), score (INT), reasons (JSON), timestamp, action_taken
  - `blacklist`: domain (TEXT PK), source (TEXT), last_updated
  - `allowlist`: domain (TEXT PK), added_by_user (BOOL)
- Blacklist loader: download Phishing Army list, parse, populate `blacklist` table
- Schedule periodic refresh (every 6 hours via `BGTaskScheduler` or simple timer)

### Step 3: IMAP Monitor
- Account setup UI: server, port, username, password/app-specific-password
- Store credentials in Keychain (not in UserDefaults)
- Connect via SwiftMail `IMAPServer` actor
- SELECT INBOX, start IDLE
- On new mail: FETCH headers + body
- Extract: Message-ID, From, Return-Path, Authentication-Results, HTML body

### Step 4: Phishing Analyzer Engine
- `PhishingAnalyzer` class with `analyze(email: ParsedEmail) -> Verdict`
- Individual check functions, each returning `(points: Int, reason: String?)`
- Auth header parser: regex for `spf=fail`, `dkim=fail`, `dmarc=fail`
- Return-Path checker: extract domain, compare to From domain
- Link analyzer: SwiftSoup parse HTML → extract all `<a href="...">text</a>` → compare domains
- Blacklist checker: query local SQLite for sender domain + all link domains
- TLD checker: match against suspicious TLD set
- IP URL checker: regex on link hrefs
- Aggregate score + reasons → write verdict to shared SQLite

### Step 5: Actions & Notifications
- Based on score thresholds:
  - IMAP: STORE +FLAGS (\Flagged) or MOVE to Junk
  - macOS notification via `UNUserNotificationCenter`:
    - Title: "Suspicious email detected"
    - Body: "From: fedrex.com — possible FedEx impersonation"
- Notification actions: "View", "Mark Safe" (adds to allowlist)

### Step 6: Mail Extension (Thin Client)
- `MEMessageActionHandler.decideAction(for:)`
- Extract Message-ID from `message.headers`
- Query shared SQLite for verdict
- If verdict found:
  - Score 3-5 → `.setFlag(.orange)` (or equivalent color)
  - Score 6+ → `.moveToJunk`
- If no verdict yet: parse `Authentication-Results` from `message.headers` directly
  - If SPF/DKIM/DMARC fail → `.setFlag(.red)`
  - Otherwise → nil (no action)
- No network calls from extension — all data comes from shared storage

### Step 7: Settings UI
- Menu bar popover with SwiftUI:
  - Account configuration
  - Recent alerts list (last 20 flagged emails with scores/reasons)
  - Sensitivity slider (adjusts score thresholds)
  - Allowlist management
  - Blacklist last-updated timestamp + manual refresh button
  - Extension status indicator (enabled/disabled in Mail)

---

## Key Dependencies

| Package | Purpose | Source |
|---|---|---|
| SwiftMail | IMAP client (connect, IDLE, fetch, flag) | github.com/Cocoanetics/SwiftMail |
| SwiftSoup | HTML parsing (link extraction from email body) | github.com/scinfu/SwiftSoup |
| KeychainAccess | Secure credential storage | github.com/kishikawakatsumi/KeychainAccess |

Plus Apple frameworks: MailKit, SwiftData (or SQLite.swift), UserNotifications, SwiftUI, AppKit.

---

## Phishing Detection Details

### Authentication-Results Parsing
```
Authentication-Results: mx.google.com;
    dkim=pass header.i=@example.com;
    spf=fail (domain not designated) smtp.mailfrom=spoofed.com;
    dmarc=fail (p=REJECT) header.from=example.com
```
Parse with regex: `(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)`

### Link Mismatch Detection
```html
<a href="https://evil-site.com/login">https://paypal.com/verify</a>
```
Extract href domain (`evil-site.com`) and display text domain (`paypal.com`). If different → high suspicion.

### Blacklist Format (Phishing Army)
Plain text, one domain per line. ~50K entries. Download from `https://phishing.army/download/phishing_army_blocklist.txt`

---

## Verification Plan

1. **Unit tests** for each detection check with known phishing email samples
2. **Integration test** with a test IMAP account — send yourself phishing-like emails and verify detection
3. **False-positive test** with legitimate transactional emails (bank statements, delivery notifications, newsletters)
4. **MailKit extension test** — verify color labels appear in Mail.app message list on macOS 14+
5. **Timing test** — verify extension can read verdicts from shared storage after menu bar app processes them
6. **Blacklist update test** — verify periodic refresh downloads and parses correctly
7. **Test with real phishing samples** from public corpora (Nazario phishing corpus, PhishTank recent submissions)
8. **Belgian-specific test** — bpost, Itsme, BNP Paribas Fortis impersonation patterns

---

## Future Phases (Not in MVP)

- **Phase 2:** Typosquatting + homoglyph detection against curated brand list (200+ brands including Belgian banks/services)
- **Phase 3:** Google Safe Browsing API, PhishTank API, domain age checking, urgency language scoring (NL/FR/EN)
- **Phase 4:** ML classifier, attachment analysis, compose extension warning when replying to suspicious senders

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| MailKit extension unreliable | Menu bar app is the primary detection path; extension is best-effort visual layer |
| SwiftMail is young/immature | Start with iCloud (app-specific password, simple PLAIN auth). Add Gmail OAuth2 later. Keep IMAP layer abstracted for library swap. |
| False positives erode trust | Start with Tier 1 checks only (high-confidence signals). Conservative thresholds. Easy "mark safe" allowlist. |
| Blacklist staleness | Multiple sources, 6-hour refresh cycle, fallback to header analysis if blacklist unavailable |
| App Store rejection | Privacy policy, transparent about data access, all processing local, no email content sent externally |
| IMAP credential security | Keychain storage, never persist in UserDefaults or files |
