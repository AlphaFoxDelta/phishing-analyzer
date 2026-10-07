#!/usr/bin/env python3
"""
phishing-analyzer: read a suspicious email (.eml) and get a verdict.

Parses the headers, authentication results, URLs, and attachments, scores
each suspicious signal, and prints a plain-English report. Standard library
only, no dependencies.

Usage:
    python3 analyzer.py suspicious.eml
    python3 analyzer.py suspicious.eml --json
"""

import argparse
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlparse

# brand name -> the real domain it lives on
BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "netflix": "netflix.com",
    "google": "google.com",
    "ebay": "ebay.com",
    "linkedin": "linkedin.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "t.ly", "shorturl.at",
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "js", "vbs", "vbe", "bat", "cmd", "ps1", "msi",
    "com", "pif", "hta", "jar", "wsf", "lnk", "reg",
}

URGENT_PHRASES = [
    "urgent", "immediately", "verify your account", "account suspended",
    "suspended", "action required", "click here", "limited time",
    "expires today", "password expires", "unusual activity",
    "confirm your identity", "final notice", "act now",
]

URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RECEIVED_FROM_RE = re.compile(r"from\s+([^\s;()]+)", re.IGNORECASE)
RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")

VERDICT_PHISHING = 50
VERDICT_SUSPICIOUS = 20


def levenshtein(a, b):
    # plain dynamic-programming edit distance, for typosquat checks
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[len(b)]


def domain_of(addr):
    addr = (addr or "").strip().lower()
    return addr.split("@")[-1] if "@" in addr else ""


def registrable(host):
    # naive eTLD+1: last two labels. good enough for a demo tool
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []  # list of (href, visible text)
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def load_message(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def first_addr(header_values):
    addrs = getaddresses(header_values or [])
    return addrs[0] if addrs else ("", "")


def message_text(msg):
    # returns (plain_text, html_text)
    plain, html = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and isinstance(payload, str):
                plain.append(payload)
            elif ctype == "text/html" and isinstance(payload, str):
                html.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = ""
        if isinstance(payload, str):
            if msg.get_content_type() == "text/html":
                html.append(payload)
            else:
                plain.append(payload)
    return "\n".join(plain), "\n".join(html)


def check_sender(msg, findings):
    name, addr = first_addr(msg.get_all("From", []))
    from_domain = domain_of(addr)

    for brand, real_domain in BRANDS.items():
        if brand in name.lower() and from_domain != real_domain:
            findings.append({
                "points": 15,
                "check": "display-name spoof",
                "detail": 'Display name says "%s" but the address is not '
                          "@%s (it is %s)" % (name, real_domain, addr or "?"),
            })
            break

    _, reply_addr = first_addr(msg.get_all("Reply-To", []))
    if reply_addr and domain_of(reply_addr) != from_domain:
        findings.append({
            "points": 10,
            "check": "reply-to mismatch",
            "detail": "Reply-To (%s) is on a different domain than From (%s)"
                      % (reply_addr, addr or "?"),
        })

    _, rp_addr = first_addr(msg.get_all("Return-Path", []))
    if rp_addr and domain_of(rp_addr) != from_domain:
        findings.append({
            "points": 10,
            "check": "return-path mismatch",
            "detail": "Return-Path (%s) is on a different domain than "
                      "From (%s)" % (rp_addr, addr or "?"),
        })

    return name, addr, from_domain


def check_received(msg, from_domain, findings):
    received = msg.get_all("Received", [])
    if not received:
        findings.append({
            "points": 5,
            "check": "no received headers",
            "detail": "No Received headers at all, unusual for real mail",
        })
        return

    first_hop = received[-1]  # earliest hop is last in the header list
    m_from = RECEIVED_FROM_RE.search(first_hop)
    m_ip = RECEIVED_IP_RE.search(first_hop)
    origin = m_ip.group(1) if m_ip else (m_from.group(1) if m_from else "?")
    findings.append({
        "points": 0,
        "check": "received chain",
        "detail": "%d hops, earliest hop from %s" % (len(received), origin),
    })

    chain = " ".join(received).lower()
    if from_domain and from_domain not in chain:
        findings.append({
            "points": 5,
            "check": "sender not in received chain",
            "detail": "The claimed From domain never appears in the "
                      "Received headers (weak signal on its own)",
        })


def check_auth(msg, findings):
    ar = msg.get("Authentication-Results")
    if not ar:
        findings.append({
            "points": 10,
            "check": "no authentication results",
            "detail": "No Authentication-Results header, so SPF/DKIM/DMARC "
                      "could not be verified",
        })
        return

    seen = {}
    for method, result in AUTH_RE.findall(str(ar)):
        seen.setdefault(method.lower(), result.lower())

    for method in ("spf", "dkim", "dmarc"):
        result = seen.get(method)
        if result is None:
            continue
        if result == "pass":
            continue
        if result == "fail":
            points = 15
        elif result == "softfail":
            points = 10
        else:  # none, neutral, temperror, policy
            points = 5
        findings.append({
            "points": points,
            "check": "%s %s" % (method.upper(), result),
            "detail": "%s check came back %s" % (method.upper(), result),
        })


def check_url(url, findings):
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return
    if not host:
        return
    host = host.lower().strip(".")

    if IP_RE.match(host):
        findings.append({
            "points": 15,
            "check": "ip-literal url",
            "detail": "Link uses an IP address instead of a domain: %s" % url,
        })
        return

    if "xn--" in host:
        findings.append({
            "points": 15,
            "check": "punycode domain",
            "detail": "Link uses punycode (possible homograph attack): %s" % url,
        })

    reg = registrable(host)
    if reg in URL_SHORTENERS:
        findings.append({
            "points": 10,
            "check": "url shortener",
            "detail": "Link hides its destination behind a shortener: %s" % url,
        })

    for brand, real_domain in BRANDS.items():
        if reg == real_domain:
            break
        tokens = [t for t in re.split(r"[.\-]", host) if len(t) >= 4]
        if any(levenshtein(t, brand) <= 2 for t in tokens):
            findings.append({
                "points": 20,
                "check": "lookalike domain",
                "detail": "Link domain %s looks like %s but is not %s"
                          % (host, brand, real_domain),
            })
            break


def check_urls(plain, html, findings):
    urls = set(URL_RE.findall(plain or ""))
    extractor = LinkExtractor()
    try:
        extractor.feed(html or "")
    except Exception:
        pass
    for href, text in extractor.links:
        if href.lower().startswith(("http://", "https://")):
            urls.add(href)
        # link text shows one URL but goes somewhere else
        m = URL_RE.search(text or "")
        if m and href.lower().startswith(("http://", "https://")):
            try:
                text_host = (urlparse(m.group(0)).hostname or "").lower()
                href_host = (urlparse(href).hostname or "").lower()
            except Exception:
                text_host, href_host = "", ""
            if text_host and href_host and text_host != href_host:
                findings.append({
                    "points": 15,
                    "check": "link text mismatch",
                    "detail": "Link text shows %s but actually goes to %s"
                              % (text_host, href_host),
                })

    if not urls:
        findings.append({
            "points": 0,
            "check": "no urls",
            "detail": "No links found in the message body",
        })
        return

    for url in sorted(urls):
        check_url(url, findings)


def check_attachments(msg, findings):
    names = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            fname = part.get_filename() or "unnamed"
            names.append(fname)
            pieces = fname.split(".")
            ext = pieces[-1].lower() if len(pieces) > 1 else ""
            if ext in DANGEROUS_EXTENSIONS:
                findings.append({
                    "points": 20,
                    "check": "dangerous attachment",
                    "detail": 'Attachment "%s" has an executable '
                              "extension (.%s)" % (fname, ext),
                })
                if len(pieces) > 2:
                    findings.append({
                        "points": 10,
                        "check": "double extension",
                        "detail": 'Attachment "%s" uses a double extension, '
                                  "it looks like a document but runs as code"
                                  % fname,
                    })
    if names:
        findings.append({
            "points": 0,
            "check": "attachments",
            "detail": "%d attachment(s): %s" % (len(names), ", ".join(names)),
        })


def check_language(subject, plain, findings):
    text = ((subject or "") + "\n" + (plain or "")).lower()
    hits = [p for p in URGENT_PHRASES if p in text]
    if hits:
        findings.append({
            "points": 5,
            "check": "pressure language",
            "detail": "Urgency/pressure phrases found: %s"
                      % ", ".join('"%s"' % h for h in hits[:4]),
        })


def analyze(path):
    msg = load_message(path)
    findings = []

    name, addr, from_domain = check_sender(msg, findings)
    check_received(msg, from_domain, findings)
    check_auth(msg, findings)

    plain, html = message_text(msg)
    check_urls(plain, html, findings)
    check_attachments(msg, findings)
    check_language(msg.get("Subject"), plain, findings)

    score = sum(f["points"] for f in findings)
    if score >= VERDICT_PHISHING:
        verdict = "likely phishing"
    elif score >= VERDICT_SUSPICIOUS:
        verdict = "suspicious"
    else:
        verdict = "likely legitimate"

    return {
        "file": path,
        "from": "%s <%s>" % (name, addr) if name else addr,
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def print_report(result):
    bar = "=" * 62
    print("Phishing analysis: %s" % result["file"])
    print(bar)
    print("From    : %s" % result["from"])
    print("Subject : %s" % result["subject"])
    print("Date    : %s" % result["date"])
    print("Score   : %d" % result["score"])
    print("Verdict : %s" % result["verdict"].upper())
    print(bar)
    print()
    print("Findings (%d):" % len(result["findings"]))
    print()
    for f in result["findings"]:
        print("[+%d] %s" % (f["points"], f["check"]))
        print("      %s" % f["detail"])
    print()
    print("A low score is not proof an email is safe. This tool checks "
          "technical signals, it does not read intent.")


def main():
    ap = argparse.ArgumentParser(
        description="Analyze a suspicious email (.eml) and score it for "
                    "phishing signals.")
    ap.add_argument("eml", help="path to the .eml file to analyze")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of text")
    args = ap.parse_args()

    try:
        result = analyze(args.eml)
    except FileNotFoundError:
        print("error: file not found: %s" % args.eml, file=sys.stderr)
        return 2
    except Exception as e:
        print("error: could not parse %s: %s" % (args.eml, e), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    return 1 if result["verdict"] == "likely phishing" else 0


if __name__ == "__main__":
    sys.exit(main())
