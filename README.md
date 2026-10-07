# vuln-tracker

A command-line tracker for security findings. Scanners are good at finding
problems. They are not good at telling you which ones got fixed. This is
the missing middle: log a finding, move it from open to resolved, and
export a report you can hand to a manager or a client.

Standard library only. Findings are stored in a local findings.json file.

## Why I built this

This one comes from the management side of my brain, not the hacking side.

A scan gives you a list of problems. That list is worthless without
ownership and follow-through: who is working on what, what is actually
fixed, what turned out to be a false positive. On a real team, that
tracking is the difference between "we ran a scan" and "we are handling
it." I wanted a tool that treats findings like work items with a
lifecycle, instead of lines in a text dump nobody reads twice.

It also pairs with my web-security-scanner. Run a scan with --json, import
the results here, and now you have a workflow instead of a pile of output.

## What it does

- Add findings with a title, severity (critical, high, medium, low, info),
  source, and description
- Track each finding through a lifecycle: open, in-progress, resolved,
  false-positive
- List findings with filters by status or severity, worst first
- Print a summary: counts by severity and by status
- Export a Markdown report written for a non-technical reader
- Import findings from a JSON scan report, so scanner output becomes
  tracked work
- Seed realistic demo data with one command, so you can try the whole
  workflow immediately

## Usage

```bash
# load 5 realistic demo findings
python3 tracker.py demo

# see everything, worst first
python3 tracker.py list

# just the open items
python3 tracker.py list --status open

# add a finding by hand
python3 tracker.py add --title "TLS 1.0 still enabled" --severity medium \
  --source "manual review" --description "Server still negotiates TLS 1.0."

# move things along
python3 tracker.py update 4 --status in-progress
python3 tracker.py resolve 1

# where do we stand
python3 tracker.py summary

# import scanner output (pairs with web-security-scanner --json)
python3 tracker.py import --file scan.json --source web-security-scanner

# write the report
python3 tracker.py report
```

The summary looks like this:

```
Total findings : 5
Needs work     : 4 (open: 3, in-progress: 1)
Closed out     : 1 resolved, 0 false-positive

By severity:
  critical  2
  high      1
  medium    1
  low       1
  info      0
```

And the exported report.md reads like something you could actually send
someone:

```markdown
# Vulnerability Findings Report
Generated: 2026-10-07T22:55:17

## Summary

Total findings tracked: 5

By severity:

- critical: 2
- high: 1
- medium: 1
- low: 1
- info: 0

By status:

- open: 3
- in-progress: 1
- resolved: 1
- false-positive: 0

## Findings needing attention

### [1] Reflected XSS in site search parameter (critical)

Status: open | Source: web-security-scanner | Found: 2026-10-07T22:55:17

The q parameter on /search reflects input without encoding. Confirmed with
a benign script payload. Any visitor clicking a crafted link runs attacker
JavaScript in the site's origin.

### [3] Missing Content-Security-Policy header (high)

Status: open | Source: web-security-scanner | Found: 2026-10-07T22:55:17

No CSP header on any page. This is the main browser-side defense against
XSS, and without it a single injection runs with full page privileges.

## Resolved

- [5] Server version disclosed in response headers (low)

## False positives

None.
```

## What tripped me up

Status naming. I started with "new," "acknowledged," "mitigated," and
"accepted risk," which is how a lot of enterprise tools talk. Then I tried
to actually use it and kept typing the wrong words. Open, in-progress,
resolved, false-positive: boring, obvious, and I never have to look them
up. Naming things for the person typing at 2am beats naming them for the
framework.

The other thing was the import format. My first version expected the exact
JSON shape of my web scanner, which made it useless for anything else.
Loosening it to "a list of objects with title, severity, description"
took ten minutes and made it work with basically any scanner output.

## What I'd do differently

- This is single-user and file-based, which is fine for a portfolio and a
  small team. The real version of this is multi-user with a database, so
  two people are not editing the same JSON file.
- No due dates or owners on findings. For a team workflow, every open
  finding needs a name and a date next to it. That is the first feature
  I would add.
- The report is Markdown only. An HTML or PDF export would be nicer for
  sending to clients who do not live in a terminal.
- Severity is hand-assigned on import. Scoring it automatically (CVSS or
  even a simple rubric) would make the import path more honest.

## A note on using this

This tracks findings, it does not find them. Pair it with actual scans of
systems you own or are authorized to test, and the report becomes the
paper trail that proves the work got done.
