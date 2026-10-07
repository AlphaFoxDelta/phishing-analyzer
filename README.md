# phishing-analyzer

A CLI tool that reads a suspicious email (.eml), checks it for phishing
signals, and gives you a score and a verdict. Python standard library only.
No dependencies.

## Why I built this

Phishing is still how most breaches start, and I wanted a blue-team tool
that deals with the thing people actually click on. My other projects scan
networks and logs. This one reads the email itself: headers, auth results,
links, attachments, the works.

I also wanted to understand email authentication for real. I had read
about SPF, DKIM, and DMARC in class, but parsing an actual
Authentication-Results header and seeing a spf=fail next to a message
claiming to be PayPal made it click in a way the textbook never did.

## What it checks

Headers first:

- From display name vs. the real address: flags "PayPal Support" sent
  from an address that is not @paypal.com
- Reply-To on a different domain than From
- Return-Path on a different domain than From
- Received chain: counts the hops, shows where the message entered, and
  notes if the claimed sender domain never shows up in the chain at all
- Authentication-Results: parses SPF, DKIM, and DMARC, and scores fails
  harder than softfails and missing results

Then the body:

- Every URL gets checked: IP-literal hosts, punycode domains, URL
  shorteners, and lookalike domains (a small brand list plus edit-distance
  typosquat detection, so paypa1-secure.com gets flagged next to paypal)
- Link text mismatch: the visible text says paypal.com but the href goes
  somewhere else
- Attachments: lists them, flags dangerous extensions (.exe, .scr, .js,
  and friends), and calls out double extensions like Invoice.pdf.exe
- Pressure language: urgent, verify your account, suspended, that kind of
  thing

Each finding adds points. 50 or more is likely phishing, 20 to 49 is
suspicious, under 20 is likely legitimate. Exit code is 1 on likely
phishing, 0 otherwise, so you can wire it into a script.

## Usage

```bash
# analyze an email
python3 analyzer.py sample_phish.eml

# machine-readable output
python3 analyzer.py sample_phish.eml --json
```

Two sample emails are included so you can see both ends of the scale:
`sample_phish.eml` is a fake PayPal phish I wrote, `sample_legit.eml` is
a normal GitHub notification.

## What the output looks like

The phishing sample:

```
Phishing analysis: sample_phish.eml
==============================================================
From    : PayPal Support <support@paypa1-secure.com>
Subject : Urgent: Verify your account now
Date    : Tue, 06 Oct 2026 09:14:22 -0500
Score   : 170
Verdict : LIKELY PHISHING
==============================================================

Findings (16):

[+15] display-name spoof
      Display name says "PayPal Support" but the address is not @paypal.com (it is support@paypa1-secure.com)
[+10] reply-to mismatch
      Reply-To (refunds@paypa1-secure.net) is on a different domain than From (support@paypa1-secure.com)
[+10] return-path mismatch
      Return-Path (bounce@mailer01.example-ru.com) is on a different domain than From (support@paypa1-secure.com)
[+15] SPF fail
      SPF check came back fail
[+15] DMARC fail
      DMARC check came back fail
[+15] link text mismatch
      Link text shows www.paypal.com but actually goes to paypa1-secure.com
[+15] ip-literal url
      Link uses an IP address instead of a domain: http://192.0.2.44/verify
[+10] url shortener
      Link hides its destination behind a shortener: http://bit.ly/3xK7abc
[+20] lookalike domain
      Link domain paypa1-secure.com looks like paypal but is not paypal.com
[+20] dangerous attachment
      Attachment "Invoice_2026.pdf.exe" has an executable extension (.exe)
[+10] double extension
      Attachment "Invoice_2026.pdf.exe" uses a double extension, it looks like a document but runs as code
[+5] pressure language
      Urgency/pressure phrases found: "urgent", "immediately", "verify your account", "suspended"
```

The legitimate sample:

```
Phishing analysis: sample_legit.eml
==============================================================
From    : GitHub <noreply@github.com>
Subject : [octocat/hello-world] Pull request #42 was merged
Date    : Mon, 05 Oct 2026 16:02:11 -0500
Score   : 0
Verdict : LIKELY LEGITIMATE
==============================================================

Findings (1):

[+0] received chain
      1 hops, earliest hop from 192.0.2.10
```

## What's in the repo

```
phishing-analyzer/
├── analyzer.py        # the whole analyzer, one file
├── sample_phish.eml   # fake PayPal phish I wrote for testing
├── sample_legit.eml   # normal GitHub notification for contrast
└── README.md          # you're reading it
```

## Things that tripped me up

- Python's email library parses headers into structured objects when you
  use policy.default, which is great until get_content() throws on a part
  with a weird encoding. I wrapped payload extraction in try/except and
  moved on. A portfolio tool should not crash on a malformed email.
- The Received headers are listed newest-first, so the earliest hop (the
  one that tells you where the message really came from) is the last one
  in the list. I read them backwards the first time and reported the
  recipient's own mail server as the origin. Felt dumb once I saw it.
- HTML link parsing needed the stdlib html.parser, and keeping track of
  which visible text belongs to which href across nested tags took a
  couple of tries. Nothing fancy, just careful state handling.

## What I'd do differently next time

- Actually resolve DNS: check the sending IP against the domain's SPF
  record instead of trusting the Authentication-Results header, which the
  receiving server writes and could be forged in a forwarded sample.
- Screenshot or render the HTML safely to catch visual tricks like
  hidden text and zero-width characters.
- Add VirusTotal or URLhaus lookups for URLs and attachment hashes, with
  an API key flag. Right now everything is offline by design.
- A simple web UI where you paste or upload an email and get the report.
  The CLI is fine for me, but nobody outside security wants to live in a
  terminal.

## A note on using this

This analyzes emails you already have. Do not use it to send phishing
emails to test people without their written consent. That is how you lose
a job, not how you get one.
