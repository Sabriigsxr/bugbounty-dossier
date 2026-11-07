/* ============================================================
   THE MINE — survey data
   Derived from PENTEST_BUGBOUNTY_CV_SUMMARY.md (2026-11-07).
   Every item below is itemised in that document. Items that are
   prepared but not yet filed live in `sealed` and carry no
   reproduction detail.
   ============================================================ */

window.MINE = {
  meta: {
    survey: "26-05",
    compiled: "2026-10-23",
    updated: "2026-11-07",
    operator: "Ahmed Sabry",
    handle: "Sabriigsxr",
    span: "2024—2026",
    source: "PENTEST_BUGBOUNTY_CV_SUMMARY.md"
  },

  ledger: [
    { value: "52", label: "Bugs hunted with PoC", note: "35 validated + 17 sealed" },
    { value: "11", label: "Shafts sunk", note: "11 programs" },
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
    },

    {
      id: "ticketsmarche",
      numeral: "V",
      name: "TicketsMarche",
      scope: "ticketsmarche.com · www / app / portal / api",
      status: "PART-WORKED",
      statusTone: "partial",
      sunk: "165+ subdomains · 9 cells",
      note: "A ticketing estate behind a single SPA fallback. Headers were thin, the catch-all was thick, and every masked-test class collapsed into one misconfiguration instead of five findings.",
      veins: [
        {
          id: "TKM-01",
          title: "Missing security headers on app, portal, cdn",
          klass: "MISCONFIG",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "app, portal, and cdn returned no Strict-Transport-Security, no Content-Security-Policy, no X-Frame-Options, no X-Content-Type-Options, no Referrer-Policy, and no Permissions-Policy. www carried HSTS, CSP, X-Frame-Options DENY, and nosniff, with a weak CSP allowing unsafe-inline and unsafe-eval, and was missing Permissions-Policy.",
          impact:
            "Clickjacking on frameable pages, MIME sniffing, and downgrade on hosts that never set HSTS. Blast radius is the browser layer, which is why this grades low and not high.",
          evidence: "Header capture per subdomain, seven attributes compared side by side. Re-checked before grading down from the source High to reflect demonstrated impact.",
          next: {
            label: "Diff the header set across all live hosts",
            cmd:
              "for h in www app portal api; do echo \"== $h\"; curl -sI https://$h.ticketsmarche.com/ | grep -Ei 'strict-transport|content-security|x-frame|x-content|referrer|permissions'; done",
            note: "Absent HSTS plus absent CSP is the pair that matters. Missing Permissions-Policy alone is not a seam."
          }
        },
        {
          id: "TKM-02",
          title: "Wildcard catch-all returns 200 for every path",
          klass: "MISCONFIG",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "Every tested path on www, app, portal, and api returned HTTP 200 with identical SPA body sizes (283,267 / 8,863 / 5,626 / 558 bytes). Non-existent pages, admin paths, and /api/ routes all fell back to the frontend instead of returning 404, 401, or 403.",
          impact:
            "Enumeration, admin, SSRF, and IDOR testing all read the same SPA HTML. The routing masks real controls and makes scanner verdicts unreliable until the fallback is fixed.",
          evidence: "Paired request sizes across randomised non-existent paths plus 60 API/auth variants returning identical 300-byte SPA on api. IDOR across 9 user IDs and 4 endpoint types returned identical body and is recorded as a false positive, not a vein.",
          next: {
            label: "Prove the fallback with a random path",
            cmd:
              "for p in /nonexistent-page-12345 /api/nonexistent-endpoint /admin/nonexistent; do curl -s -o /dev/null -w \"$p %{http_code} %{size_download}c\\n\" https://www.ticketsmarche.com$p; done",
            note: "Uniform 200 with uniform size is the fallback. A 404 on any one path proves the rewrite is scoped."
          }
        },
        {
          id: "TKM-03",
          title: "robots.txt discloses the api surface",
          klass: "ENUMERATION",
          severity: "info",
          grade: "TRACE",
          score: "—",
          scale: "asset map",
          detail:
            "www robots.txt discloses Disallow: /api/ for every crawler, and portal discloses /cinema and /request-event. The files advertise which surfaces exist while telling well-behaved crawlers to stay away.",
          impact:
            "Attack surface, not a vulnerability. A map of where to point the next test, including the API that TKM-02 shows is masked.",
          evidence: "robots.txt fetch per host, path list extracted. Recorded as TRACE because robots.txt alone proves no access-control gap.",
          next: {
            label: "Use the disclosure to bound the next survey",
            cmd:
              "curl -s https://www.ticketsmarche.com/robots.txt | grep -i disallow; curl -s https://portal.ticketsmarche.com/robots.txt | grep -i disallow",
            note: "Treat every Disallow as a candidate, then check whether the path returns SPA fallback or a real 404."
          }
        }
      ]
    },

    {
      id: "win",
      numeral: "VI",
      name: "1win Forum",
      scope: "forum.1win.io · IPS · Cloudflare WAF",
      status: "PART-WORKED",
      statusTone: "partial",
      sunk: "manual curl + WAF partial bypass",
      note: "An Invision forum behind Cloudflare. The WAF held for high-severity classes; what remained was a header gap and a robots.txt map, consolidated honestly instead of padded to five Mediums.",
      veins: [
        {
          id: "WIN-01",
          title: "Missing security headers including Cloudflare error pages",
          klass: "MISCONFIG",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "Strict-Transport-Security was missing on the main host and across login, search, and index endpoints. Cloudflare block and error pages on the search path also lacked X-Content-Type-Options, X-XSS-Protection, and Content-Security-Policy, and the main host carried conflicting X-XSS-Protection values (0 alongside 1; mode=block).",
          impact:
            "Downgrade and MIME sniffing on the main host before Cloudflare serves a block page, and reduced defense-in-depth on error pages themselves. X-XSS-Protection is legacy protection, which is why this grades low.",
          evidence: "Header captures on main, login, search, and error-page paths. Seven source items collapsed to one seam; S3, open-redirect, and sitemap candidates marked NOT CONFIRMED were dropped, not published.",
          next: {
            label: "Diff headers on normal and error paths",
            cmd:
              "curl -s -D- -o /dev/null https://forum.1win.io/ | grep -iE 'strict-transport|x-content|x-xss|content-security'; curl -s -D- -o /dev/null 'https://forum.1win.io/search/?do=quicksearch' | grep -iE 'strict-transport|x-content|x-xss|content-security'",
            note: "A header present on 200 but missing on the Cloudflare block page is still a gap. An error page with a 200 status is not."
          }
        },
        {
          id: "WIN-02",
          title: "robots.txt discloses paths, platform fingerprinted",
          klass: "ENUMERATION",
          severity: "info",
          grade: "TRACE",
          score: "—",
          scale: "asset map",
          detail:
            "robots.txt discloses /staff/, /login/, /register/, /search/, and /tags/. The markup carries the ipsApp fingerprint identifying Invision Power Board.",
          impact:
            "Enumeration aid for the next surveyor. Platform identity sets the patch level to check; it is not itself exploitable.",
          evidence: "robots.txt fetch plus body marker grep. Published as TRACE alongside the WAF negative: Cloudflare blocked XSS, IDOR, and XXE payloads.",
          next: {
            label: "Fingerprint, then check the patch level",
            cmd:
              "curl -s https://forum.1win.io/ | grep -io 'ipsApp[^\\\"]*' | head -1; curl -s https://forum.1win.io/robots.txt | grep -i disallow",
            note: "Version the platform from headers and body before claiming a known-CVE match."
          }
        }
      ]
    },

    {
      id: "drypegy",
      numeral: "VII",
      name: "Drypegy",
      scope: "drypegy.com · Shopify storefront",
      status: "PART-WORKED",
      statusTone: "partial",
      sunk: "5 cells · Shopify managed",
      note: "A Shopify Dawn storefront with strong headers and scoped customer mutations. The only payable edge was rate limiting; the rest was by-design surface and verified positives.",
      veins: [
        {
          id: "DRY-01",
          title: "No HTTP rate limit on the Storefront GraphQL endpoint",
          klass: "RATE LIMIT",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "Fifty consecutive Storefront GraphQL requests returned 200 with no 429 and no Retry-After. Shopify cost-based query limits apply per query cost, but no HTTP-level throttle was observed.",
          impact:
            "Enumeration at scale with cheap queries. Cost limiting blunts heavy queries, so the blast radius is pacing and resource use, not data exposure, which is why this grades low.",
          evidence: "Sequential burst with per-request status codes; all 200s. Customer mutations showed proper scope enforcement and cart quantity validation, recorded as positives in the same shaft.",
          next: {
            label: "Push the burst past the cost ceiling",
            cmd:
              "for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code} ' -X POST https://drypegy.com/api/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ shop { name } }\"}'; done; echo",
            note: "Fifty 200s on cheap queries is the seam. A 429 on expensive queries is the cost limit working."
          }
        },
        {
          id: "DRY-02",
          title: "UCP and MCP discovery is public by design",
          klass: "MISCONFIG",
          severity: "info",
          grade: "TRACE",
          score: "—",
          scale: "asset map",
          detail:
            "/.well-known/ucp lists the commerce capabilities, payment handlers, and service schemas, and /api/ucp/mcp accepts JSON-RPC initialize. Storefront GraphQL introspection is likewise enabled. All three are intended for public storefront and agent clients.",
          impact:
            "A map of the agent commerce surface. No sensitive data was shown to be readable; the risk is abuse of a public interface, which belongs in monitoring, not in a payable claim.",
          evidence: "Discovery fetch plus initialize handshake. Recorded as TRACE with Introspection accepted as by-design, matching the program's own stance.",
          next: {
            label: "Enumerate the agent surface before testing it",
            cmd:
              "curl -s https://drypegy.com/.well-known/ucp | jq '.capabilities // .services // keys'",
            note: "An endpoint that answers initialize with a capability list is advertising. Probe whether create_checkout needs a buyer profile."
          }
        }
      ]
    },

    {
      id: "egy4gamers",
      numeral: "VIII",
      name: "Egypt4Gamers",
      scope: "egy4gamers.com · staging WordPress · GTM",
      status: "PART-WORKED",
      statusTone: "partial",
      sunk: "9 subdomains · 3 live",
      note: "A WordPress staging estate with public REST routes and a public login. The interesting work was downgrading inflated severities and publishing the stack map with the blocked-files negative.",
      veins: [
        {
          id: "EGY-001",
          title: "WordPress REST exposes user and content routes",
          klass: "ENUMERATION",
          severity: "low",
          grade: "TRACE",
          score: "—",
          scale: "unscored",
          detail:
            "/wp-json/wp/v2/users and /wp-json/wp/v2/posts returned 200 unauthenticated, listing slugs for the site account, an info account, and an orders account, alongside 45+ advanced-db-cleaner endpoints, WooCommerce, Wordfence, Elementor, RankMath, and WP Rocket routes. wp-admin and wp-login.php were reachable, and ffuf mapped cart, checkout, dashboard, and wp-content paths. load.sgtm and sgtm served Stape GTM containers.",
          impact:
            "User enumeration and plugin inventory for targeted guessing. REST exposure alone does not authenticate or execute, which is why this grades low despite the source Critical label.",
          evidence: "User and post endpoint fetches, ffuf directory map, GTM host banners. Sensitive paths (.env, wp-config backups, backup.sql) returned 403/404 and are recorded as a positive negative, not dropped.",
          next: {
            label: "Distinguish public routes from leaked secrets",
            cmd:
              "curl -s https://staging.egy4gamers.com/wp-json/wp/v2/users | jq -r '.[].slug' ; curl -s -o /dev/null -w '%{http_code}\\n' https://staging.egy4gamers.com/wp-admin/",
            note: "Public user slugs are enumeration. A 200 on wp-admin that only redirects to login is not admin access."
          }
        }
      ]
    },

    {
      id: "priceless",
      numeral: "IX",
      name: "Priceless Demo",
      scope: "demo.priceless.com",
      status: "FLOODED",
      statusTone: "blocked",
      sunk: "verified subset · negatives published",
      note: "A demo estate where the verified subset and the full sweep disagreed. The reconciliation is the finding: one soft key issue, one control misread as a vuln, and a clean set of WAF negatives.",
      veins: [
        {
          id: "PRI-01",
          title: "Google API key ships in client-side JavaScript",
          klass: "MISCONFIG",
          severity: "info",
          grade: "TRACE",
          score: "—",
          scale: "unscored",
          detail:
            "A Google API key matching the AIza pattern was found in client-served JavaScript on the demo host. Browser keys are commonly public when restricted by HTTP referrer or API scope, and no quota or data abuse was demonstrated.",
          impact:
            "Quota burn or impersonated calls only if restrictions are missing. Without a restriction check this is surface, not a payable seam, which is why it grades info.",
          evidence: "Bundle grep for the key pattern. ApplicationAPIKey was searched in the same bundles and not found; a requirement for that key is a control, not a leak, and was not published as a vein.",
          next: {
            label: "Test restrictions before calling it a leak",
            cmd:
              "grep -rhoE 'AIza[0-9A-Za-z_-]{35}' ./client-js/ | head -1 | cut -c1-8; curl -s -o /dev/null -w '%{http_code}\\n' https://demo.priceless.com/api/session",
            note: "A key that only works from the demo origin is restricted. A key that works from anywhere is the seam."
          }
        },
        {
          id: "PRI-02",
          title: "WAF and access controls held under test",
          klass: "NEGATIVE",
          severity: "info",
          grade: "TRACE",
          score: "0",
          scale: "findings",
          detail:
            "SQL injection, XSS, SSRF, and XXE payloads were blocked at the WAF. Product endpoints showed no IDOR, and no ApplicationAPIKey was exposed in client code. Authentication was enforced with no bypass found.",
          impact:
            "A bounded negative. It tells the next surveyor which classes to skip and which to route through a change window.",
          evidence: "Per-class payload matrix with block outcomes, product IDOR series, and bundle key search. Recorded as negatives rather than omitted.",
          next: {
            label: "Re-run the blocked classes before trusting the negative",
            cmd:
              "for p in '/api/session' '/api/login'; do curl -s -o /dev/null -w \"$p %{http_code}\\n\" \"https://demo.priceless.com$p\"; done",
            note: "A WAF block today is not a block after a rule change. Re-verify per release."
          }
        }
      ]
    },

    {
      id: "rpgstash",
      numeral: "X",
      name: "RPGStash",
      scope: "rpgstash.com/monopoly-go · devgg",
      status: "FLOODED",
      statusTone: "blocked",
      sunk: "WAF-blocked sweep",
      note: "A gaming storefront where Cloudflare did the work. One thin header gap and one version disclosure survived; the rest of the sweep was blocks, not bypasses.",
      veins: [
        {
          id: "RPG-01",
          title: "Missing X-XSS-Protection and version disclosure",
          klass: "MISCONFIG",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "The storefront responses carried no X-XSS-Protection header. The dev host served /version.json with a build identifier and build time.",
          impact:
            "Legacy-browser XSS defense-in-depth only, plus build targeting aid. No exploitable call was shown, which is why this grades low.",
          evidence: "Header check plus version fetch. API dropdown endpoints returned 401 and admin and config paths returned SPA fallback; those negatives bound the same shaft.",
          next: {
            label: "Check the header and the version file together",
            cmd:
              "curl -sI https://www.rpgstash.com/monopoly-go/ | grep -i x-xss; curl -s https://devgg.rpgstash.com/version.json",
            note: "A version string without a known-vuln match is a map entry, not an exploit."
          }
        }
      ]
    },

    {
      id: "digitalplayground",
      numeral: "XI",
      name: "DigitalPlayground",
      scope: "digitalplayground.com · realitykings.com",
      status: "FLOODED",
      statusTone: "blocked",
      sunk: "75 + 84 subdomains · WAF-held",
      note: "Two wildcard estates held by Cloudflare. Apex scanning produced only 403s; the reachable support host showed the real gaps, which is the opposite of what the scanner count claimed.",
      veins: [
        {
          id: "DGP-01",
          title: "Exposed JavaScript and thin headers on support host",
          klass: "MISCONFIG",
          severity: "low",
          grade: "LOW-GRADE",
          score: "—",
          scale: "unscored",
          detail:
            "Apex hosts on both domains answered with Cloudflare challenges, but support.digitalplayground.com returned 200 without X-Frame-Options, CSP, HSTS, X-XSS-Protection, or X-Content-Type-Options. Client bundles on the wildcard surface included admin, API monitor, and access group JavaScript plus vite and git config text files.",
          impact:
            "Bundle review may surface endpoints and logic to target, and the support host lacks framing and sniffing defenses. No key or credential was shown to be recoverable, which caps this at low.",
          evidence: "WAF confirm, dirsearch and feroxbuster 403 series, and nuclei with no results on apex; bundle inventory and header capture on the support host. Three duplicate engagement folders collapsed to one.",
          next: {
            label: "Separate WAF blocks from reachable hosts",
            cmd:
              "wafw00f https://www.digitalplayground.com; curl -sI https://support.digitalplayground.com | grep -iE 'x-frame|content-security|strict-transport|x-content'",
            note: "A 403 challenge on apex is a control. A 200 with no headers on support is the gap."
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
    { program: "Government assessments", klass: "SUPPLY CHAIN / BRAND", items: 3, severity: "high", status: "PREPARED · NOT FILED", note: "Third-party script allowlist, locale routing, and a coordinated lookalike-brand cluster. Withheld pending disclosure." },
    { program: "Adobe Stock (bug hunt)", klass: "OPEN REDIRECT / CORS", items: 3, severity: "critical", status: "PREPARED · NOT FILED", note: "Redirect and cross-origin drafts need live body proof and allowlist retest. Detail stays sealed until filed and resolved." },
    { program: "SHEIN wildcard", klass: "MISCONFIG / AUTHORIZATION", items: 4, severity: "high", status: "PREPARED · NOT FILED", note: "Configuration exposure and authorization drafts need body-hash proof against SPA fallback. Withheld pending disclosure." },
    { program: "Lightspark API", klass: "AUTH / GRAPHQL", items: 4, severity: "critical", status: "PREPARED · NOT FILED", note: "Mutation authentication drafts need live unauthenticated differential proof and blind validation. Withheld pending disclosure." }
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
