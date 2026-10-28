"""Social-engineering indicators for messages and emails.

These rules don't decide the verdict on their own. They explain to the user
which persuasion tactics the message uses, and that's the awareness part of
the project.
"""
import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr

TACTICS = {
    "Urgency / pressure": (
        "high",
        r"\b(urgent|immediately|within \d+ ?(hours?|hrs|minutes?|days?)|act now|final (notice|warning|reminder)"
        r"|expires? (today|soon)|last chance|right away|asap|limited time|don'?t delay)\b",
        "Attackers create time pressure so you act before you think.",
    ),
    "Threat of loss / account suspension": (
        "high",
        r"\b(suspend(ed)?|locked|blocked|deactivat\w*|terminat\w*|unauthori[sz]ed (access|activity|login)"
        r"|unusual (activity|sign.?in)|compromised|legal action|arrest|penalty|fine)\b",
        "Fear of losing access or getting into trouble is the most common phishing hook.",
    ),
    "Request for credentials / OTP": (
        "high",
        r"\b(password|passcode|pin|otp|one.time (password|code)|cvv|card (number|details)|login details"
        r"|verify your (account|identity)|confirm your (account|details|identity)|ssn|aadhaar|pan card|kyc)\b",
        "No legitimate organisation asks for passwords, OTPs or card details by message.",
    ),
    "Too-good-to-be-true reward": (
        "medium",
        r"\b(congratulations|you('ve| have)? won|winner|prize|free (gift|entry|iphone|vouchers?)|claim (your|now)"
        r"|reward|cash ?back|lottery|selected for|guaranteed)\b",
        "Unexpected prizes are bait to collect your data or an 'unlock fee'.",
    ),
    "Money / payment request": (
        "medium",
        r"\b(wire transfer|bank transfer|gift ?cards?|bitcoin|crypto|western union|payment (failed|pending|declined)"
        r"|refund|invoice|outstanding (balance|payment)|processing fee|tax refund)\b",
        "Payment or refund requests out of the blue are a hallmark of fraud.",
    ),
    "Call-to-action link": (
        "low",
        r"\b(click (here|the link|below)|tap (here|the link)|follow the link|log ?in (here|now)|update (now|here)"
        r"|visit .{0,20}link|open the attachment)\b",
        "The message pushes you to click. Hover or long-press to inspect the link first.",
    ),
    "Generic greeting": (
        "low",
        r"^\s*(dear (customer|user|client|member|sir|madam|account holder|valued)|hello (customer|user)|attention)",
        "Your real bank or employer knows your name.",
    ),
    "Secrecy request": (
        "medium",
        r"\b(keep (this|it) (confidential|secret)|do not (tell|share|discuss)|strictly confidential|between us)\b",
        "Asking you to keep quiet stops you from checking with someone else.",
    ),
}
_COMPILED = {k: (sev, re.compile(rx, re.IGNORECASE | re.MULTILINE), why) for k, (sev, rx, why) in TACTICS.items()}


def text_red_flags(text: str) -> list[dict]:
    flags = []
    for title, (sev, rx, why) in _COMPILED.items():
        hits = {m.group(0).strip() for m in rx.finditer(text or "")}
        if hits:
            flags.append({
                "severity": sev,
                "title": title,
                "detail": f"{why} Found: " + ", ".join(f"“{h}”" for h in sorted(hits)[:4]),
            })
    caps = re.findall(r"\b[A-Z]{4,}\b", text or "")
    if len(caps) >= 4:
        flags.append({"severity": "low", "title": "Excessive capital letters",
                      "detail": "Shouting in CAPS is a pressure tactic: " + ", ".join(caps[:4])})
    if (text or "").count("!") >= 3:
        flags.append({"severity": "low", "title": "Excessive exclamation marks",
                      "detail": "Emotional punctuation is used to rush the reader."})
    return flags


def parse_email(raw: str | bytes) -> dict:
    """Parse a raw RFC-822 email (.eml) into headers + plain text body.
    If the input has no headers it is treated as a plain body."""
    if isinstance(raw, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    else:
        msg = Parser(policy=policy.default).parsestr(raw)
    if not msg.keys():
        return {"subject": "", "from": "", "reply_to": "", "return_path": "", "body": raw if isinstance(raw, str)
                else raw.decode("utf-8", "ignore"), "auth_results": "", "has_headers": False}

    body_parts = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html") and not part.is_attachment():
            try:
                content = part.get_content()
            except Exception:
                content = part.get_payload(decode=True).decode("utf-8", "ignore") if part.get_payload(decode=True) else ""
            if ctype == "text/html":
                content = re.sub(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>", r" \1 ", content, flags=re.I)
                content = re.sub(r"<[^>]+>", " ", content)
            body_parts.append(content)
    attachments = [p.get_filename() for p in msg.walk() if p.get_filename()]
    return {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "auth_results": str(msg.get("Authentication-Results", "")),
        "body": "\n".join(body_parts),
        "attachments": attachments,
        "has_headers": True,
    }


RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".html", ".htm",
                    ".zip", ".rar", ".7z", ".docm", ".xlsm", ".lnk", ".hta", ".jar")
FREE_MAIL = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "protonmail.com",
             "mail.ru", "yandex.com", "gmx.com")


def header_red_flags(parsed: dict) -> list[dict]:
    """Checks that need email headers: spoofing, reply redirection, auth failures."""
    flags = []
    if not parsed.get("has_headers"):
        return flags
    name, addr = parseaddr(parsed.get("from", ""))
    from_domain = addr.split("@")[-1].lower() if "@" in addr else ""
    _, reply = parseaddr(parsed.get("reply_to", ""))
    reply_domain = reply.split("@")[-1].lower() if "@" in reply else ""

    if reply_domain and from_domain and reply_domain != from_domain:
        flags.append({"severity": "high", "title": "Reply-To differs from sender",
                      "detail": f"Replies go to '{reply}' rather than '{addr}'. Attackers use this to capture your response."})
    m = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", name or "")
    if m and m.group(0).lower() != addr.lower():
        flags.append({"severity": "high", "title": "Display name spoofing",
                      "detail": f"The display name shows '{m.group(0)}' but the real sender is '{addr}'."})
    from .url_features import BRANDS
    lname = (name or "").lower().replace(" ", "")
    for b in BRANDS:
        if b in lname and b not in from_domain:
            sev = "high" if from_domain in FREE_MAIL else "medium"
            flags.append({"severity": sev, "title": f"Sender claims to be '{b}'",
                          "detail": f"The display name mentions {b}, but the email comes from '{from_domain}'."})
            break
    auth = parsed.get("auth_results", "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail|none|permerror)", auth):
            flags.append({"severity": "high" if mech != "spf" else "medium",
                          "title": f"{mech.upper()} check failed",
                          "detail": f"The receiving server could not verify the sender ({mech.upper()} failed)."})
    for att in parsed.get("attachments", []) or []:
        if att and att.lower().endswith(RISKY_EXTENSIONS):
            flags.append({"severity": "high", "title": "Dangerous attachment",
                          "detail": f"'{att}' can run code or hide malware. Don't open it."})
    return flags
