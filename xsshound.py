import requests
import argparse
import sys
import urllib3
import re
import html
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def normalize_variants(payload):
    decoded = urllib.parse.unquote(payload)
    html_decoded = html.unescape(decoded)

    variants = set([
        payload,
        decoded,
        html_decoded,
        decoded.replace(" ", ""),
        html_decoded.replace(" ", ""),
        decoded.strip(),
        html_decoded.strip()
    ])

    return variants


def load_payloads(payload_file):
    try:
        with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File '{payload_file}' not found.")
        sys.exit(1)



def is_escaped(response, payload):
    decoded = urllib.parse.unquote(payload)
    html_decoded = html.unescape(decoded)

    escaped_variants = [
        html.escape(decoded),
        html.escape(html_decoded),
        decoded.replace("<", "&lt;").replace(">", "&gt;"),
        html_decoded.replace("<", "&lt;").replace(">", "&gt;"),
    ]

    for ev in escaped_variants:
        if ev in response:
            return True
    return False



def classify_context(html_doc, reflected):
    idx = html_doc.find(reflected)
    if idx == -1:
        return None, None

    before = html_doc[max(0, idx-150):idx].lower()
    after  = html_doc[idx+len(reflected): idx+len(reflected)+150].lower()

    if "<script" in before and "</script>" in after:
        return "js", idx
    if "<!--" in before and "-->" in after:
        return "comment", idx
    if re.search(r'on\w+\s*=\s*["\']?$', before):
        return "event", idx
    if re.search(r'\w+\s*=\s*["\']\s*$', before):
        return "attr_quoted", idx
    if re.search(r'\w+\s*=\s*$', before):
        return "attr_unquoted", idx
    if ">" in before and "<" in after:
        return "html", idx

    return "other", idx



def confirm_breakout(url, field, headers, method, cookie):
    tests = [
        '"><xsshound>',
        "'><xsshound>"
    ]

    for t in tests:
        try:
            if method == "post":
                r = requests.post(url, data={field: t}, headers=headers, timeout=5, verify=False)
            else:
                r = requests.get(url, params={field: t}, headers=headers, timeout=5, verify=False)

            if "xsshound" in r.text and not is_escaped(r.text, t):
                return True
        except:
            pass
    return False



def scan(url, field, payloads, method, cookie):
    print(f"[*] Target: {url}")
    print(f"[*] Parameter: {field}")
    print(f"[*] Cookies: {cookie}")
    print("-" * 60)

    headers = {
        "User-Agent": "Mozilla/5.0 XSSHound",
        "Cookie": cookie
    }

    found = 0

    for payload in payloads:

        try:
            if method == "post":
                resp = requests.post(url, data={field: payload}, headers=headers, timeout=5, verify=False)
            else:
                resp = requests.get(url, params={field: payload}, headers=headers, timeout=5, verify=False)
        except:
            continue

        text = resp.text

        variants = normalize_variants(payload)

        reflected = None
        for v in variants:
            if v in text:
                reflected = v
                break
        
        if not reflected:
            continue

        if is_escaped(text, reflected):
            continue

        ctx, idx = classify_context(text, reflected)

        if ctx in ["comment", "style", "other", None]:
            continue

        if ctx in ["attr_quoted", "attr_unquoted"]:
            if not confirm_breakout(url, field, headers, method, cookie):
                continue

        print(f"[+] XSS FOUND [{ctx}] : {payload}")
        found += 1

    print("-" * 60)
    print(f"[*] Scan complete. Found {found} verified payloads.")



def main():
    parser = argparse.ArgumentParser(description="XSS Scanner")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-f", "--field", required=True)
    parser.add_argument("-p", "--payloads", required=True)
    parser.add_argument("-m", "--method", default="get", choices=["get", "post"])
    parser.add_argument("-c", "--cookie", required=True)
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    scan(args.url, args.field, payloads, args.method, args.cookie)


if __name__ == "__main__":
    main()
