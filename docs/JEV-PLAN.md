# PhishGuard — Revised Detection Strategy with Jev (Oct 2026)

Supersedes the "Future Phases" and the brand/typosquatting roadmap in [PLAN.md](PLAN.md).
The IMAP backbone, storage and UI stay as they are.

## What changed

TypeSafe released **Jev** (Sept 15, 2026): a "System One" model that answers typed questions
(`choice`, `score`, `noul` = calibrated probability) instead of generating text.

| | Jev | Claude Haiku 4.5 |
|---|---|---|
| Price | $0.042 / 1M input tokens, output free | ~27× more for the same 5 signal questions |
| Latency p50 | ~240–460 ms | ~690–1,200 ms |
| Direct "is this phishing?" verdict | **62.6% accuracy, 18% false-positive rate** | 81.3%, 13.8% FPR |
| 5 narrow signal questions → logistic regression | **95.0% accuracy, AUROC 0.982** | 93.2%, AUROC 0.991 |

Source: [anisselbd/jev-phishing-bench](https://github.com/anisselbd/jev-phishing-bench), 2,000 emails (PhishNChips v5.2).

**Takeaway:** Jev is a weak judge, but a cheap, fast signal extractor. Never ask it "is this
phishing?". Ask narrow questions and combine the answers in our own code. In that same benchmark,
a two-line URL regex (91.8%) beat Jev's best single signal (89.4%). So the local URL and header
checks stay. They're free, offline and strong.

## Architecture: local first, Jev on demand

```
IMAP (unchanged)
   │
   ▼
Allowlisted sender? ── yes ──► clean, no further work
   │ no
   ▼
Local checks (free, offline, ~ms)
  auth headers · return-path · Phishing Army blacklist · link text≠href
  IP-in-URL · suspicious TLD · user blocklist · (brand list, until Phase B)
   │
   ▼
Gate: ask Jev only if ALL hold
  • user enabled it + API key present
  • local score < 6 (not already conclusive)
  • NOT (DMARC=pass AND ≥3 earlier clean verdicts from this exact domain)
  • not already asked for this Message-ID this run
  • under the daily cap (500 calls)
   │
   ▼
Jev: 6 noul questions, 1 HTTP call, 4 s timeout
   │  failure / timeout / 429 after 1 retry → keep local verdict
   ▼
score = local points + Jev signal points   (Jev impersonation replaces the brand-list check)
```

### The six questions (`JevSignalCheck.signals`)

Each one scores only when the probability is ≥ 0.7.

| Signal | Points | Why |
|---|---|---|
| `impersonation`: claims to be a known org, sender domain isn't theirs | 4 | Replaces brand lists, Safeonweb campaigns and the planned typosquat work |
| `generic_sender`: free webmail posing as an organization | 3 | Classic BEC/scam pattern |
| `risky_link_host`: shortener / free hosting / form builder | 3 | Strongest signal in the benchmark |
| `payment_request`: pay, change bank details, gift cards | 2 | BEC, often linkless |
| `credential_lure`: sign in, verify, open document | 1 | Context only |
| `pressure`: deadline, threat, suspension | 1 | Context only |

"Who" signals carry the weight. "What it asks" signals only push an already-suspicious email
over the line, so the real IT department's "your password expires" mail stays clean (1+1=2).
Impersonation + lure + pressure = 6 → phishing. Webmail sender + payment request + pressure = 6 → phishing.

The weights are set by hand. Once roughly 200 verdicts carry user feedback (marked safe, or deleted
or junked), fit a logistic regression over local + Jev signals, as the benchmark did, and replace them.

### What gets sent (privacy)

`from`, `from_domain`, `reply_to`, `subject`, the first 2,000 characters of body text, and up to
15 links as `display text -> scheme://host/path`. Query strings, fragments and userinfo are
stripped, because they carry tracking tokens and often the recipient's address. Nothing is sent
for allowlisted or established senders, which is most everyday mail. The feature is opt-in and
off by default, and the Settings text says exactly what leaves the device. TypeSafe is US-hosted
and its retention policy hasn't been verified yet. Check it before enabling Jev by default or
shipping it to App Store users.

## Cost

Each call is about 1,000 input tokens (≈500 for the email, ≈350 for the questions), so about
**$0.00004 per call**. A heavy user getting 200 mails a day, with half of them passing the gate,
spends **about $1.50 a year**. Cost isn't a meaningful constraint. The gate exists for **privacy,
latency and false positives**, not for money. The daily cap is only a safety net against runaway
rescans, such as a reconnect loop or "scan All" on a 20k mailbox.

## Simplification roadmap

**Phase A: this change (done)**
- `JevClient`: raw HTTP client, no SDK dependency
- `JevSignalCheck`: gate, compact state, signal → points, per-run cache, daily cap
- `PhishingAnalyzer.evaluate` (async, falls back to local), plus a batched variant (4 in flight) for scans
- Opt-in toggle and API key in Settings (macOS and iOS), stored in the existing credential vault

**Phase B: delete the brand machinery (after ~2 weeks of real use confirms `impersonation` is reliable)**
- Remove `Safeonweb/*` (RSS parser, brand extractor, updater), `SafeonwebCampaignStore` and its
  445-article seed list, `UserBrandStore`, `BrandImpersonationCheck`, and their tests:
  **about 1,100 lines**, plus the Brand Watchlist / Safeonweb sections in both Settings screens
- Drop the planned Phase 2 (typosquat/homoglyph lists) and Phase 3 "urgency language scoring
  NL/FR/EN". Jev covers both in every language.
- Check before deleting: Belgian brands (bpost, itsme, BNP Paribas Fortis, KBC, Belfius). Jev's
  knowledge of local brand domains is unverified. If it misses them, keep a 20-line static
  `brand → official domains` hint and pass it in the state instead of keeping the Safeonweb pipeline.

**Phase C: optional**
- Move `risky_link_host` to a local shortener/free-host domain list (the benchmark shows the regex
  beats Jev here), then drop that question.
- Escalate only the ambiguous band (score 3–5 after Jev) to a System-2 LLM (Claude Haiku 4.5) for
  a written explanation in the alert. That's about 1 in 50 emails, still cents a year.

## What we're not doing

- **Not replacing the local checks with Jev.** Its verdict is weak, and headers and URLs are better handled deterministically.
- **No "Jev-only" mode.** Jev is text-only, so QR codes, image-only mails and attachments still need other handling.
- **No shadow mode or A/B infrastructure.** The reasons list shows which signals fired ("AI, 87%"), and the user's mark-safe feedback is the evaluation set.
