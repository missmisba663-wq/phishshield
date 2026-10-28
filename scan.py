"""PhishShield command-line scanner.

Examples:
    python scan.py url "http://paypal.com.verify-login.xyz/webscr"
    python scan.py sms "Your account is blocked, update KYC at http://bit.ly/x"
    python scan.py email path/to/message.eml
    python scan.py qr samples/qr/upi_refund_scam.png
    python scan.py url "..." --json
"""
import argparse
import json
import sys
from pathlib import Path

from phishshield import engine

COLORS = {"safe": "\033[92m", "suspicious": "\033[93m", "phishing": "\033[91m", "unknown": "\033[90m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def print_result(r):
    c = COLORS.get(r["verdict"], "")
    print(f"\n{BOLD}{c}  {r['verdict'].upper()}{RESET}   risk {BOLD}{r['risk_score']}{RESET}/100"
          f"   {DIM}(ML probability {r['ml_probability']}){RESET}")
    if r["red_flags"]:
        print(f"\n{BOLD}  Red flags{RESET}")
        for f in r["red_flags"]:
            print(f"   [{f['severity'][0].upper()}] {f['title']}\n       {DIM}{f['detail']}{RESET}")
    if r["explanation"]:
        print(f"\n{BOLD}  Top model signals{RESET}")
        for e in r["explanation"][:6]:
            arrow = "\033[91m+" if e["direction"] == "phishing" else "\033[92m-"
            print(f"   {arrow}{abs(e['contribution']):.2f}{RESET}  {e['feature']}")
    for link in r["details"].get("links", []):
        print(f"   link: {link['url']}  -> {link['verdict']} ({link['risk_score']})")
    print(f"\n{BOLD}  Advice{RESET}")
    for a in r["advice"][:3]:
        print(f"   - {a}")
    print()


def main():
    ap = argparse.ArgumentParser(description="PhishShield phishing scanner")
    ap.add_argument("channel", choices=["sms", "email", "url", "qr"])
    ap.add_argument("input", help="text/URL, or a file path for email (.eml) and qr (image)")
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    if args.channel == "url":
        r = engine.analyze_url(args.input)
    elif args.channel == "sms":
        r = engine.analyze_sms(args.input)
    elif args.channel == "email":
        p = Path(args.input)
        r = engine.analyze_email(p.read_bytes() if p.is_file() else args.input)
    else:
        r = engine.analyze_qr_image(Path(args.input).read_bytes())

    if args.json:
        json.dump(r, sys.stdout, indent=2)
        print()
    else:
        print_result(r)


if __name__ == "__main__":
    main()
