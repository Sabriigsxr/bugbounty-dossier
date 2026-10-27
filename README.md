# THE MINE

A field survey of four bug bounty and VDP programs, 2024–2026, built as a static page.

**Live:** https://sabriigsxr.github.io/bugbounty-dossier/

Four shafts — Prodege VDP, OpenSea, Tesla, Zendesk AI Agents. Nineteen itemised seams,
one CVE, six barren assets published anyway, and a next dig for every finding.

---

## What this is

The page is a portfolio artefact, not a scanner report. Each seam carries:

- **detail** — what was actually wrong
- **impact** — what it lets an attacker do, stated in the terms the program cares about
- **evidence** — how it was proven, and how it survived a skeptic
- **next dig** — the concrete command a returning surveyor would run next

Severity is graded honestly. A correctly scoped cleartext exception grades low even though
it was a validated finding; a chain of negatives is published as `TRACE` rather than dropped.

## What this is not

- No live target requests. The page is static and makes no calls to any program.
- No analytics, no trackers, no cookies.
- No un-filed findings. Items that are drafted but not yet submitted live in the **Sealed**
  band with a program, a class, a count, and nothing else — no host, no payload, no
  reproduction path.

## Files

```
index.html          page shell
assets/style.css    all styling
assets/app.js       render + filter + copy, no dependencies
assets/data.js      the survey data — edit here to change the page
.nojekyll           serve as-is on GitHub Pages
```

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

Opening `index.html` directly from disk also works.

## Adding a finding

Append an object to the relevant shaft's `veins` array in `assets/data.js`:

```js
{
  id: "OPS-06",
  title: "Short, specific title",
  klass: "BROKEN AUTH",              // free text, shown as a tag
  severity: "medium",                // critical | high | medium | low | info
  grade: "PAYABLE",                  // RICH | HIGH-GRADE | PAYABLE | LOW-GRADE | TRACE
  score: "6.9",                      // or "—" when unscored
  scale: "CVSS 4.0",
  cve: "CVE-2026-00000",             // optional
  triad: { c: 0, i: 3, a: 1 },       // optional 0–3 qualitative bars
  detail: "...",
  impact: "...",
  evidence: "...",
  next: { label: "...", cmd: "...", note: "..." }
}
```

The ledger counts in `index.html` and the `19 of 23` caption are editorial, not computed.
Update them when the counts change.

## Source

Derived from `PENTEST_BUGBOUNTY_CV_SUMMARY.md` (compiled 2026-10-23, updated 2026-10-25).
The source document is not published here because it contains prepared-but-unfiled findings.

## Scope

Every engagement referenced on this page was authorised and in scope. Nothing here is a
disclosure of an unresolved issue.
