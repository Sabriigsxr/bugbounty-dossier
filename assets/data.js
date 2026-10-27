/* ============================================================
   THE MINE — survey data
   Derived from PENTEST_BUGBOUNTY_CV_SUMMARY.md (2026-10-25).
   Every item below is itemised in that document. Items that are
   prepared but not yet filed live in `sealed` and carry no
   reproduction detail.
   ============================================================ */

window.MINE = {
  meta: {
    survey: "26-04",
    compiled: "2026-10-23",
    updated: "2026-10-25",
    operator: "Ahmed Sabry",
    handle: "Sabriigsxr",
    span: "2024—2026",
    source: "PENTEST_BUGBOUNTY_CV_SUMMARY.md"
  },

  ledger: [
    { value: "23", label: "Validated seams", note: "per source ledger" },
    { value: "04", label: "Shafts sunk", note: "4 programs" },
    { value: "01", label: "CVE assigned", note: "CVE-2026-41432" },
    { value: "06", label: "Assets worked out", note: "barren, not skipped" }
  ],

  shafts: [
    {
      id: "prodege",
      numeral: "I",
      name: "Prodege VDP",
      scope: "Swagbucks · InboxDollars · MyPoints · Tada",
      status: "IN PRODUCTION",
      statusTone: "live",
      sunk: "4 platforms · 20+ APIs",
      note: "Four consumer rewards platforms on one shared authentication estate. The webhook layer was the seam that paid; the auth layer was a continuous seam that kept giving.",
      veins: [
        {
          id: "PRD-01",
          title: "Stripe webhook signature bypass",
          klass: "BROKEN AUTH",
          severity: "critical",
          grade: "RICH",
          score: "8.2",
          scale: "CVSS 3.1",
          cve: "CVE-2026-41432",
          triad: { c: 0, i: 3, a: 0 },
          detail:
            "All four platform webhook endpoints returned HTTP 200 for requests carrying no signature, an invalid signature, an empty signature, a forged signature — and for GET requests and malformed JSON. Nothing on the receiving side ever called the Stripe verification routine.",
          impact:
            "An unauthenticated caller can mint checkout and fulfilment events on all four platforms: credit points or cash, trigger reward fulfilment, and write arbitrary balances. Integrity-only, but the dollar value sits downstream.",
          evidence:
            "Standalone Python PoC, six request shapes per endpoint, status codes captured for all four hosts. Reproduced end to end by an independent blind validator.",
          next: {
            label: "Re-run the unsigned probe against every listener",
            cmd:
              "for u in $(cat webhooks.txt); do printf '%-48s ' \"$u\"; curl -s -o /dev/null -w '%{http_code}\\n' -X POST \"$u\" -H 'Content-Type: application/json' -d '{}'; done",
            note:
              "Empty body, no Stripe-Signature. 400 or 401 means constructEvent() is wired in. Anything 2xx means the seam is still open."
          }
        },
        {
          id: "PRD-02",
          title: "No rate limiting on login, all four platforms",
          klass: "BROKEN AUTH",
          severity: "high",
          grade: "HIGH-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "Login endpoints accepted unbounded sequential attempts with no 429, no progressive delay, no captcha challenge. Verified per platform rather than assumed from one.",
          impact:
            "Password spraying and credential stuffing run at full network speed across the whole estate. Combined with the missing lockout in PRD-03, there is no cost to guessing.",
          evidence: "Sequential attempt capture per platform with response-time series; no throttle boundary found inside 200 requests.",
          next: {
            label: "Find the throttle boundary, if one exists",
            cmd:
              "seq 1 40 | xargs -I{} -P1 curl -s -o /dev/null -w '%{http_code} ' -X POST https://<login-host>/api/session -d 'email=a@b.c&password=wrong{}'; echo",
            note:
              "A 429, a 423, or a widening delay inside 10 attempts is a control. Forty straight 200s is the finding."
          }
        },
        {
          id: "PRD-03",
          title: "No account lockout after repeated failure",
          klass: "BROKEN AUTH",
          severity: "medium",
          grade: "PAYABLE",
          score: "—",
          scale: "unscored",
          detail:
            "Accounts remained reachable indefinitely after sustained failed authentication. No soft lock, no cooldown, no notification trigger observed.",
          impact: "Removes the only remaining ceiling on online guessing once rate limiting is absent.",
          evidence: "Continuous failure series against a single controlled account with successful login afterwards.",
          next: {
            label: "Confirm the account still authenticates after the series",
            cmd:
              "curl -s -o /dev/null -w '%{http_code}\\n' -X POST https://<login-host>/api/session -d 'email=<test>@example.com&password=<known-good>'",
            note: "A 200 after 40 failures proves no lockout. Pair it with PRD-02 before writing the report."
          }
        },
        {
          id: "PRD-04",
          title: "No CAPTCHA on authentication surfaces",
          klass: "BROKEN AUTH",
          severity: "medium",
          grade: "PAYABLE",
          score: "—",
          scale: "unscored",
          detail:
            "No challenge was injected at any failure threshold. The login form is a plain POST endpoint with no bot signal attached.",
          impact: "Automated guessing is indistinguishable from a browser at the network layer.",
          evidence: "Form and XHR inspection across all four login flows; zero challenge parameters in request bodies.",
          next: {
            label: "Check whether the challenge is issued only after N failures",
            cmd:
              "curl -s https://<login-host>/login | grep -Eo 'recaptcha|hcaptcha|turnstile|cf-chl' || echo 'no challenge in markup'",
            note: "Client-side absence is not proof; replay the POST directly, skipping the form entirely."
          }
        },
        {
          id: "PRD-05",
          title: "No MFA on any of the four platforms",
          klass: "BROKEN AUTH",
          severity: "high",
          grade: "HIGH-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "No TOTP enrolment, no WebAuthn registration, no recovery-code surface. Second factor is not implemented, not merely optional.",
          impact:
            "Credential compromise is account compromise. There is no step-up to defeat because there is no step-up.",
          evidence: "Account settings enumeration and API probe on each platform; absence confirmed on both surfaces.",
          next: {
            label: "Ask the account API what factors exist",
            cmd:
              "curl -s https://<account-host>/api/v1/me -H \"Authorization: Bearer $TOK\" | jq '{mfa, totp, webauthn, recovery_codes}'",
            note: "null or false across the estate is the finding. Do not infer absence from a missing settings page alone."
          }
        },
        {
          id: "PRD-06",
          title: "Session cookies are bare ALB cookies",
          klass: "SESSION",
          severity: "medium",
          grade: "PAYABLE",
          score: "—",
          scale: "unscored",
          detail:
            "Sessions are the AWS Application Load Balancer cookie and nothing else: no HttpOnly, SameSite=None, and no application-issued session identifier to revoke.",
          impact:
            "Script-readable session material with cross-site send enabled. Revocation is whatever the load balancer does, which is not an application control.",
          evidence: "Set-Cookie capture on login across all four platforms; attribute comparison table in the report.",
          next: {
            label: "Diff the cookie attributes across all four hosts",
            cmd:
              "curl -sI https://<program-host>/login | grep -i '^set-cookie' | tr ';' '\\n' | grep -Ei 'httponly|secure|samesite|domain|path'",
            note: "Missing HttpOnly plus SameSite=None is the pair that matters. Secure alone buys you nothing here."
          }
        },
        {
          id: "PRD-07",
          title: "No rate limit on the profile API",
          klass: "RATE LIMIT",
          severity: "medium",
          grade: "PAYABLE",
          score: "—",
          scale: "unscored",
          detail:
            "api.inboxdollars.com/profile answered 20 of 20 authenticated requests with 200 and no ceiling signal. The limit is absent, not generous.",
          impact: "Authenticated enumeration at will, and a free amplifier for any downstream IDOR or scraping chain.",
          evidence: "20-request burst with per-request status and latency; no 429, no Retry-After.",
          next: {
            label: "Push the burst until the edge reacts",
            cmd:
              "hey -n 200 -c 20 -H \"Authorization: Bearer $TOK\" https://api.<program>/profile | grep -E 'Status code|Requests/sec|Slowest'",
            note: "All 200s at 20 concurrent is the finding. If the edge starts 429ing at 200, the gap is threshold tuning, not absence."
          }
        },
        {
          id: "PRD-08",
          title: "Password reset discloses account existence",
          klass: "ENUMERATION",
          severity: "medium",
          grade: "PAYABLE",
          score: "—",
          scale: "unscored",
          detail:
            "Valid and invalid addresses produce divergent responses on the reset request. The divergence survives at both the body and the timing layer.",
          impact: "Turns an email list into a confirmed customer list, and hands PRD-02 a targeting shortlist.",
          evidence: "Paired requests across known-valid and known-invalid addresses, three repetitions, status and timing recorded.",
          next: {
            label: "Measure status and time on a matched pair",
            cmd:
              "for e in real@example.com ghost@example.com; do curl -s -o /dev/null -w \"$e  %{http_code}  %{time_total}s\\n\" -X POST https://<host>/api/password/forgot -d \"email=$e\"; done",
            note: "Run three times. A stable status or timing split is the oracle; noise is not."
          }
        },
        {
          id: "PRD-09",
          title: "Password reset request is unthrottled",
          klass: "RATE LIMIT",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "Reset requests can be issued without limit, which turns the enumeration in PRD-08 into a bulk operation rather than a per-address guess.",
          impact: "Mail-bomb vector against a known address, plus unmetered oracle queries.",
          evidence: "Sustained request series with no challenge or 429; token expiry left untested by design.",
          next: {
            label: "Bound the window before calling it unthrottled",
            cmd:
              "for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code} ' -X POST https://<host>/api/password/forgot -d 'email=<test>@example.com'; done; echo",
            note: "Fifty 200s in a row is a finding. Fifty 200s over an hour is a slow limit — say so."
          }
        },
        {
          id: "PRD-10",
          title: "OAuth authorisation without PKCE or state validation",
          klass: "OAUTH",
          severity: "medium",
          grade: "PAYABLE",
          score: "—",
          scale: "unscored",
          detail:
            "Swagbucks offers Google and Apple only, with no visible code_challenge and no enforced state parameter on the callback.",
          impact: "Authorisation-code interception and login CSRF on an otherwise well-fenced identity flow.",
          evidence: "Authorise-request inspection and callback replay with a mutated state value.",
          next: {
            label: "Drop PKCE from the request and watch the server",
            cmd:
              "curl -s -o /dev/null -w '%{http_code} %{redirect_url}\\n' \"https://<auth-host>/oauth/authorize?client_id=<public>&response_type=code&redirect_uri=<cb>&scope=openid\"",
            note: "A redirect carrying a code means PKCE is advisory. Then replay the callback with a stale state to test the other half."
          }
        }
      ]
    },

    {
      id: "opensea",
      numeral: "II",
      name: "OpenSea",
      scope: "REST · GraphQL federation · OAuth · JSON-RPC relay",
      status: "HIGH YIELD",
      statusTone: "live",
      sunk: "146 / 146 attack-class cells",
      note: "A coverage-gated sweep where the coverage was the point: 146 of 146 cells closed, five payable seams, and a blind validator that ran six counter-hypotheses without moving the verdict.",
      veins: [
        {
          id: "OPS-01",
          title: "CDN cache key omits the API credential",
          klass: "BROKEN AUTH",
          severity: "medium",
          grade: "PAYABLE",
          score: "6.9",
          scale: "CVSS 4.0",
          detail:
            "The Cloudflare cache key does not include the credential that scopes the response. Credentialed responses are served to unauthenticated callers as cache HITs across seven REST routes and one GraphQL GET path.",
          impact:
            "Cross-user data exposure for anything a logged-in caller requested first. The attacker needs no account and no token — only the URL.",
          evidence: "Cache HIT/AGE headers paired with and without credentials, seven routes, plus a GraphQL GET reproduction.",
          next: {
            label: "Prove the key by replaying without the token",
            cmd:
              "curl -s -D- -o /dev/null \"https://<api>/v2/assets?limit=1\" -H \"Authorization: Bearer $TOK\" | grep -Ei 'cf-cache-status|age|cache-control'; curl -s -D- -o /dev/null \"https://<api>/v2/assets?limit=1\" | grep -Ei 'cf-cache-status|age'",
            note: "Second request says HIT and returns the same body, you have the finding. Vary the query string and watch the key change."
          }
        },
        {
          id: "OPS-02",
          title: "PKCE not enforced by the authorisation server",
          klass: "BROKEN AUTH",
          severity: "medium",
          grade: "PAYABLE",
          score: "6.0",
          scale: "CVSS 4.0",
          detail:
            "The public client accepts code_challenge_method=plain and, separately, accepts an authorisation request with no code_challenge at all. RFC 8252 §8.1 and OAuth 2.1 both require S256 for public clients.",
          impact: "A stolen authorisation code is redeemable without the verifier, which is the entire point of PKCE.",
          evidence: "Four authorisation shapes per client: S256, plain, absent, and mismatched verifier at redemption.",
          next: {
            label: "Send the downgraded challenge and read the redirect",
            cmd:
              "curl -s -o /dev/null -w '%{http_code} %{redirect_url}\\n' \"https://<auth>/oauth2/authorize?client_id=<public>&response_type=code&redirect_uri=<cb>&code_challenge_method=plain&code_challenge=abc123\"",
            note: "A code in the redirect means plain is accepted. Then redeem it with no verifier — that is the second half of the finding."
          }
        },
        {
          id: "OPS-03",
          title: "Feature-flag proxy leaks internal database names",
          klass: "MISCONFIG",
          severity: "medium",
          grade: "PAYABLE",
          score: "6.9",
          scale: "CVSS 4.0",
          detail:
            "features.opensea.io/api/frontend is readable cross-origin with ACAO: *, authenticated by an Unleash token lifted from the public JS bundle. It returns internal store names — gql-assetsDB, gql-ordersDB — and a 32-chain rollout map.",
          impact: "Internal architecture disclosure and live rollout state for every feature flag, readable by anyone with a browser.",
          evidence: "Cross-origin fetch from a neutral page, token recovered from the bundle, response captured with the full flag tree.",
          next: {
            label: "Re-request it from a foreign origin",
            cmd:
              "curl -s https://features.<program>/api/frontend -H 'Origin: https://example.com' -D- | grep -Ei 'access-control-allow-origin|unleash|DB'",
            note: "ACAO:* plus a token that ships in the bundle means the proxy is public. Check whether the token rotates."
          }
        },
        {
          id: "OPS-04",
          title: "GraphQL debugInfo exposes federation topology",
          klass: "MISCONFIG",
          severity: "medium",
          grade: "PAYABLE",
          score: "6.9",
          scale: "CVSS 4.0",
          detail:
            "Both GraphQL entry points return extensions.debugInfo on successful anonymous queries: Apollo sub-service names, per-service timings, the trace ID, and the remaining rate-limit budget.",
          impact:
            "Maps the federated estate and its latency profile without introspection, and hands an attacker a free budget meter for pacing.",
          evidence: "Single anonymous __typename query against both entry points; debugInfo present on 2xx, not only on error.",
          next: {
            label: "Ask for the cheapest possible query",
            cmd:
              "curl -s https://<gql> -H 'Content-Type: application/json' -d '{\"query\":\"{__typename}\"}' | jq '.extensions.debugInfo'",
            note: "debugInfo on a success is the bug. On an error it is configuration. Do not conflate them in the report."
          }
        },
        {
          id: "OPS-05",
          title: "JSON-RPC relay filters chains, not methods",
          klass: "MISCONFIG",
          severity: "medium",
          grade: "PAYABLE",
          score: "6.9",
          scale: "CVSS 4.0",
          detail:
            "The /gunzilla relay applies a chain allowlist but no method filter. eth_sign, eth_signTransaction, eth_sendTransaction, personal_sign and txpool_content are forwarded verbatim to a bare go-ethereum v1.15.0 node.",
          impact:
            "The relay is a signing surface and a mempool reader, not a read-only chain proxy. Whole classes of wallet-drain and front-running primitives become reachable through a public endpoint.",
          evidence: "Method matrix replayed per verb, with upstream version banner and error-code differential for filtered vs unfiltered calls.",
          next: {
            label: "Probe one signing method and one read method",
            cmd:
              "curl -s https://<relay>/gunzilla -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sign\",\"params\":[\"0x0\",\"0x0\"]}' | jq '.error.code // .result'",
            note: "Compare against txpool_content. If both reach upstream, the allowlist is chain-only. A fixed relay returns -32601."
          }
        }
      ]
    },

    {
      id: "tesla",
      numeral: "III",
      name: "Tesla",
      scope: "7 assets · mobile APK 4.61.6 · fleet API",
      status: "PART-WORKED",
      statusTone: "partial",
      sunk: "APK + 6 web estates",
      note: "Seven assets worked, six of them barren at this vantage. The payable seam was in the Android package: a network security config that punches a cleartext hole to the vehicle gateway.",
      veins: [
        {
          id: "TSL-01",
          title: "Network security config permits cleartext to the vehicle gateway",
          klass: "MASVS-NETWORK",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "The APK's network security config carries a cleartextTrafficPermitted exception for 192.168.92.1 — the in-vehicle gateway LAN — rather than a global permit. Correctly scoped, but still a plaintext control channel.",
          impact:
            "An attacker already on the vehicle LAN can read and modify gateway traffic. The blast radius is the LAN, which is why this grades low and not high.",
          evidence:
            "APKPure mirror → HTTP Range resume → SHA256 verify → androguard manifest, ARSC, AXML and sign-block extraction. Signer certs v2 and v3 share a key with O=Tesla Motors.",
          next: {
            label: "Read the exception out of the decoded manifest",
            cmd:
              "apktool d -f tesla.apk -o out && grep -B2 -A6 -i 'cleartextTrafficPermitted' out/res/xml/network_security_config.xml",
            note: "A domain-scoped exception is defensible engineering. A base-config permit is the finding. Quote the exact node in the report."
          }
        },
        {
          id: "TSL-02",
          title: "82 endpoint tokens collapse to 45 Tesla hosts, 13 of them new",
          klass: "RECON",
          severity: "info",
          grade: "TRACE",
          score: "—",
          scale: "asset map",
          detail:
            "Static extraction from the APK yielded 82 endpoint tokens resolving to 45 Tesla-owned hosts. Thirteen were absent from the published asset list. Each was confirmed by DNS and TLS SAN before being counted.",
          impact:
            "Thirteen hosts the program did not know it was exposing. Attack surface, not a vulnerability — but it is the map the next survey starts from.",
          evidence: "Token extraction, DNS resolution, TLS SAN verification per host, and a delta against the program asset list.",
          next: {
            label: "Rebuild the host delta from a fresh package",
            cmd:
              "apktool d -f tesla.apk -o out && grep -rhoE 'https://[a-z0-9.-]+\\.tesla[a-z.]*' out/ | sort -u | httpx -silent -td -sc -title",
            note: "Diff against the previous run. New hosts after a release are the interesting ones — that is where a fresh attack surface appears."
          }
        }
      ]
    },

    {
      id: "zendesk",
      numeral: "IV",
      name: "Zendesk AI Agents",
      scope: "AI Agents API · 26-cell coverage matrix",
      status: "FLOODED",
      statusTone: "blocked",
      sunk: "9 / 26 cells closed",
      note: "A shaft that flooded before it paid. Four scope credentials were never provisioned, and the AI Agents surface rejects standard Zendesk tokens. Nine cells closed as genuine negatives; seventeen deferred with a substantiated coverage-impact record rather than padded.",
      veins: [
        {
          id: "ZEN-01",
          title: "Nine cells closed as validated negatives",
          klass: "NEGATIVE",
          severity: "info",
          grade: "TRACE",
          score: "0",
          scale: "findings",
          detail:
            "TLS 1.2 and 1.3 only, HSTS with a 301 redirect, no CORS and no verbose errors on API paths, and an auth edge that rejects every unauthenticated probe. Recorded as negatives, not omitted.",
          impact:
            "A negative result is a result. It bounds what the next surveyor can skip and it is the difference between a coverage claim and a coverage measurement.",
          evidence: "Coverage matrix with nine closed cells, seven negative tool reports, and CIR-001 covering the seventeen deferrals.",
          next: {
            label: "Re-verify the auth edge before trusting the negative",
            cmd:
              "for p in /ai-agents/api /api/v2 /api/v2/ai/agents; do curl -s -o /dev/null -w \"$p  %{http_code}\\n\" \"https://<sub>.zendesk.com$p\"; done",
            note:
              "The documented AI Agents base is /ai-agents/api, not /api/v2/ai/agents. Probing the wrong base produces a false negative."
          }
        },
        {
          id: "ZEN-02",
          title: "Scope corrections issued to the program",
          klass: "SCOPE",
          severity: "info",
          grade: "TRACE",
          score: "—",
          scale: "correction",
          detail:
            "The published AI Agents base path was wrong, and the wildcard subdomains in scope host nothing. Both were corrected in the deliverable rather than silently worked around.",
          impact: "Stops the next tester from burning a day on a path that was never live.",
          evidence: "Path matrix with per-path status, wildcard DNS resolution results, and CIR-001.",
          next: {
            label: "Enumerate what the wildcard actually resolves to",
            cmd:
              "for s in a b c d; do dig +short \"$s.<wildcard>.zendesk.com\" | head -1; done",
            note: "Four NXDOMAIN or four identical sinks means the wildcard is a paper asset. Say so in the scope section."
          }
        }
      ]
    }
  ],

  /* Assets that were worked and came back empty. Published because a
     survey that only reports payable seams is not a survey. */
  tailings: [
    { asset: "tesla.com", reason: "BARREN", note: "5 live JWT-gated API gateways, 13+ dead Akamai configs, IIS 10.0 exposed directly." },
    { asset: "teslamotors.com", reason: "BARREN", note: "Fleet API (owner-api). Full CORS / TLS / headers / auth negative coverage." },
    { asset: "tesla.cn", reason: "VANTAGE", note: "Geo-fenced. 4 CDN platforms, 854 names → 160 resolved. Needs a CN vantage point." },
    { asset: "tesla.services", reason: "BARREN", note: "Wildcard apex, pet-name gateway zone, cross-apex cert bonds, uniform mTLS fence." },
    { asset: "solarcity.com", reason: "EDGE-BLOCKED", note: "2,132 in-scope hostnames. TLS cert proves mysolarcity.com in scope; chain groundwork only." },
    { asset: "teslainsuranceservices.com", reason: "VANTAGE", note: "Akamai-fronted shell, dangling ALBs, third-party email relays." }
  ],

  /* Prepared, not filed. No hosts, no reproduction, no payloads. */
  sealed: [
    { program: "Retail pharmacy (Intigriti)", klass: "WAF / AUTH BYPASS", items: 3, severity: "critical", status: "PREPARED · NOT FILED", note: "Three reports drafted against a live in-scope estate. Detail stays sealed until they are filed and resolved." },
    { program: "Government assessments", klass: "SUPPLY CHAIN / BRAND", items: 3, severity: "high", status: "PREPARED · NOT FILED", note: "Third-party script allowlist, locale routing, and a coordinated lookalike-brand cluster. Withheld pending disclosure." }
  ],

  github: {
    note: "Every command below runs on your machine against the public GitHub API. This page makes no network calls of its own and holds no token.",
    tabs: [
      {
        id: "cve",
        label: "CVE WATCH",
        blurb: "Track who is citing the advisory, who forked a PoC, and whether a patch landed upstream.",
        lines: [
          { cmd: "gh search code \"CVE-2026-41432\" --limit 100 --json repository,path,url", note: "Code search needs an authenticated gh session; scopes: repo, read:org." },
          { cmd: "gh search issues \"CVE-2026-41432\" --limit 50 --json title,repository,state,updatedAt", note: "Issues surface vendor acknowledgements before the NVD entry updates." },
          { cmd: "gh api -X GET search/repositories -f q='CVE-2026-41432' -f sort=updated -f per_page=30 --jq '.items[] | [.full_name, .stargazers_count, .pushed_at] | @tsv'", note: "Unauthenticated search is 10 req/min. Authenticate before looping." }
        ]
      },
      {
        id: "poc",
        label: "POC FORKS",
        blurb: "A fork graph tells you how fast a primitive travelled. Sort by pushed_at, not stars.",
        lines: [
          { cmd: "gh api -X GET search/repositories -f q='CVE-2026-41432 in:name,description,readme' -f sort=updated --jq '.items[] | [.full_name, .fork, .pushed_at] | @tsv' | head -40", note: "Fork flag distinguishes original research from a copy." },
          { cmd: "gh api -X GET search/commits -f q='CVE-2026-41432' -f sort=committer-date --jq '.items[] | [.repository.full_name, .commit.committer.date, .html_url] | @tsv' | head -40", note: "Commit search finds private-ish patches referenced in public repos." },
          { cmd: "gh repo list <org> --limit 200 --json name,pushedAt --jq '.[] | select(.pushedAt > \"2026-09-01\") | .name'", note: "Swap in the vendor org to catch the fix landing before the advisory." }
        ]
      },
      {
        id: "dorks",
        label: "DORKS",
        blurb: "Scope-bound searches. Replace <program> with the in-scope org and nothing else.",
        lines: [
          { cmd: "org:<program> path:.env (STRIPE_WEBHOOK_SECRET OR UNLEASH_TOKEN OR GITHUB_TOKEN)", note: "Secrets that ship in a deploy repo are the shortest path from recon to a payable seam." },
          { cmd: "org:<program> \"code_challenge_method=plain\" OR \"code_challenge_method\" \"plain\"", note: "Finds clients that hardcode the downgraded PKCE method." },
          { cmd: "org:<program> path:.github/workflows \"pull_request_target\" \"${{ github.event\"", note: "Agentic and classic CI injection both start here." },
          { cmd: "org:<program> filename:network_security_config.xml cleartextTrafficPermitted", note: "Mobile cleartext exceptions, straight from source." },
          { cmd: "\"extensions\" \"debugInfo\" \"apollo\" org:<program>", note: "debugInfo left on in a gateway config is a topology leak waiting for a deploy." }
        ]
      }
    ]
  },

  method: [
    { n: "01", title: "Coverage gate", body: "Every attack-class cell closed or deferred with a substantiated coverage-impact record. No cell is allowed to be quietly empty." },
    { n: "02", title: "Validation gate", body: "An independent blind validator re-derives the evidence chain and reproduces the PoC from the report alone." },
    { n: "03", title: "Skeptic gate", body: "Three briefs, 5/15/25 minutes, each generating counter-hypotheses that get executed as experiments rather than argued." },
    { n: "04", title: "ROE gate", body: "No WAF evasion, no credential stuffing, no unauthorised access. The boundary is the boundary." },
    { n: "05", title: "Severity honesty", body: "The vector matches the demonstrated impact. Latent risk is labelled latent, and no finding is inflated to make the ledger look better." },
    { n: "06", title: "Evidence hygiene", body: "Cookie redaction, PII masking, HAR sanitisation, screenshot discipline. Evidence is a liability if it is handled carelessly." }
  ]
};
