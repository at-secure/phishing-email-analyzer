from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import dns.resolver
import dkim
import re


print("=" * 50)
print("       PHISHING EMAIL ANALYZER")
print("          HEADER ANALYZER")
print("=" * 50)

def analyze_url(url):
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)

    domain = parsed.netloc

    try:
        ipaddress.ip_address(domain)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    return {
    "url": url,
    "scheme": parsed.scheme,
    "domain": domain,
    "path": parsed.path,
    "is_ip_address": is_ip_address,
    "uses_http": parsed.scheme.lower() == "http"
}

def extract_urls(text):
    if not text:
        return []

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(url_pattern, text)

    return urls

def get_dkim_domain(dkim_header):
    if not dkim_header:
        return None

    match = re.search(r"\bd=([^;\s]+)", dkim_header)

    if match:
        return match.group(1).lower()

    return None

def get_sending_ip(msg):
    received_headers = msg.get_all("Received", [])

    if not received_headers:
        return None

    # For our lab email, use the first Received header.
    received = received_headers[0]

    match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", received)

    if match:
        return match.group(1)

    return None

def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")

        for record in answers:
            text = "".join(
                chunk.decode("utf-8")
                if isinstance(chunk, bytes)
                else chunk
                for chunk in record.strings
            )

            if text.lower().startswith("v=spf1"):
                return text

        return None

    except Exception:
        return None

def check_spf_authentication(domain, sending_ip):
    print("\n========== SPF AUTHENTICATION ==========\n")

    if not domain:
        print("SPF RESULT: UNKNOWN")
        print("Reason: No SPF domain found.")
        return "unknown"

    if not sending_ip:
        print("SPF RESULT: UNKNOWN")
        print("Reason: No sending IP found.")
        return "unknown"

    print("SPF domain:", domain)
    print("Sending IP:", sending_ip)

    spf_record = get_spf_record(domain)

    if not spf_record:
        print("SPF RESULT: NONE")
        print("Reason: No SPF record found.")
        return "none"

    print("SPF record:", spf_record)

    mechanisms = spf_record.split()[1:]

    for mechanism in mechanisms:

        if mechanism == "-all":
            print("\nSPF RESULT: FAIL")
            print("Reason: SPF policy uses -all.")
            return "fail"

        if mechanism == "~all":
            print("\nSPF RESULT: SOFTFAIL")
            print("Reason: SPF policy uses ~all.")
            return "softfail"

        if mechanism == "?all":
            print("\nSPF RESULT: NEUTRAL")
            print("Reason: SPF policy uses ?all.")
            return "neutral"

        if mechanism == "+all":
            print("\nSPF RESULT: PASS")
            print("Reason: SPF policy allows all senders.")
            return "pass"

    print("\nSPF RESULT: UNKNOWN")
    print("Reason: SPF mechanism not yet supported.")

    return "unknown"

def extract_urls(text):
    if not text:
        return []

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(url_pattern, text)

    return urls


email_file = input("\nEnter path to .eml file: ").strip()


# ============================================================
# READ EMAIL
# ============================================================

try:
    with open(email_file, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

except FileNotFoundError:
    print("\n[ERROR] Email file not found.")
    exit()

except Exception as e:
    print("\n[ERROR] Error reading email:", e)
    exit()

# ============================================================
# EXTRACT EMAIL BODY
# ============================================================

body = msg.get_body(preferencelist=("plain", "html"))

if body:
    body_text = body.get_content()
else:
    body_text = ""


# ============================================================
# URL EXTRACTION
# ============================================================

urls = extract_urls(body_text)

print("\n========== URL EXTRACTION ==========\n")

if urls:
    for url in urls:

        details = analyze_url(url)

        print("URL:", details["url"])
        print("Scheme:", details["scheme"])
        print("Domain:", details["domain"])
        print("Path:", details["path"])
        print("IP address:", details["is_ip_address"])
        print("Uses HTTP:", details["uses_http"])
        print()

else:
    print("No URLs found.")

# ============================================================
# BASIC HEADERS
# ============================================================

print("\n========== EMAIL HEADERS ==========\n")

print("From:        ", msg.get("From"))
print("To:          ", msg.get("To"))
print("Subject:     ", msg.get("Subject"))
print("Date:        ", msg.get("Date"))
print("Reply-To:    ", msg.get("Reply-To"))
print("Return-Path: ", msg.get("Return-Path"))
print("Message-ID:  ", msg.get("Message-ID"))


# ============================================================
# RECEIVED HEADERS
# ============================================================

print("\n========== RECEIVED HEADERS ==========\n")

received_headers = msg.get_all("Received", [])

if received_headers:

    for number, received in enumerate(received_headers, start=1):
        print(f"[{number}] {received}")

else:
    print("No Received headers found.")

sending_ip = get_sending_ip(msg)

print("\n========== SENDING IP ==========\n")

if sending_ip:
    print("Sending IP:", sending_ip)
else:
    print("Sending IP: NOT FOUND")


# ============================================================
# AUTHENTICATION HEADERS
# ============================================================

print("\n========== AUTHENTICATION ==========\n")

print("Authentication-Results:")
print(msg.get("Authentication-Results"))

print("\nDKIM-Signature:")
print(msg.get("DKIM-Signature"))

# ============================================================
# DKIM DNS CHECK
# ============================================================

import re


def check_dkim(dkim_header):

    print("\n========== DKIM CHECK ==========\n")

    if not dkim_header:
        print("DKIM: NO SIGNATURE FOUND")
        return

    domain_match = re.search(r"\bd=([^;\s]+)", dkim_header)
    selector_match = re.search(r"\bs=([^;\s]+)", dkim_header)

    if not domain_match or not selector_match:
        print("DKIM: COULD NOT PARSE SIGNATURE")
        return

    domain = domain_match.group(1)
    selector = selector_match.group(1)

    dkim_dns_name = f"{selector}._domainkey.{domain}"

    print("Signing domain:", domain)
    print("Selector:", selector)
    print("DNS name:", dkim_dns_name)

    try:

        answers = dns.resolver.resolve(dkim_dns_name, "TXT")

        print("\nDKIM DNS record found:")

        for record in answers:

            text = "".join(
                chunk.decode("utf-8")
                if isinstance(chunk, bytes)
                else chunk
                for chunk in record.strings
            )

            print(text)

    except dns.resolver.NXDOMAIN:

        print("\nDKIM: DNS RECORD NOT FOUND")

    except dns.resolver.NoAnswer:

        print("\nDKIM: NO DNS ANSWER")

    except Exception as e:

        print("\nDKIM DNS ERROR:", e)

check_dkim(msg.get("DKIM-Signature"))

# ============================================================
# DKIM CRYPTOGRAPHIC VERIFICATION
# ============================================================

print("\n========== DKIM CRYPTOGRAPHIC VERIFICATION ==========\n")

try:

    with open(email_file, "rb") as f:
        email_data = f.read()

    result = dkim.verify(email_data)

    if result:
        print("DKIM RESULT: PASS")
    else:
        print("DKIM RESULT: FAIL")

except Exception as e:

    print("DKIM verification error:", e)


# ============================================================
# EXTRACT FROM DOMAIN
# ============================================================

from_header = msg.get("From")

name, email_address = parseaddr(from_header)

if email_address and "@" in email_address:

    from_domain = email_address.split("@")[-1].lower()

    print("\n========== SENDER DOMAIN ==========\n")

    print("Sender:", email_address)
    print("Domain:", from_domain)

else:

    from_domain = None

    print("\n[WARNING] Could not extract sender domain.")

# Get DKIM signing domain
dkim_domain = get_dkim_domain(msg.get("DKIM-Signature"))

print("\n========== REPLY-TO ANALYSIS ==========\n")

reply_to = msg.get("Reply-To")

if reply_to and from_domain:

    _, reply_email = parseaddr(reply_to)

    if reply_email and "@" in reply_email:

        reply_domain = reply_email.split("@")[-1].lower()

        print("From domain:", from_domain)
        print("Reply-To domain:", reply_domain)

        if from_domain == reply_domain:
            print("REPLY-TO ALIGNMENT: MATCH")
        else:
            print("REPLY-TO ALIGNMENT: MISMATCH")

    else:
        print("Could not extract Reply-To domain.")

else:
    print("Reply-To header not present.")

print("\n========== RETURN-PATH ANALYSIS ==========\n")

return_path = msg.get("Return-Path")

if return_path and from_domain:

    _, return_email = parseaddr(return_path)

    if return_email and "@" in return_email:

        return_domain = return_email.split("@")[-1].lower()

        print("From domain:", from_domain)
        print("Return-Path domain:", return_domain)

        if from_domain == return_domain:
            print("RETURN-PATH ALIGNMENT: MATCH")
        else:
            print("RETURN-PATH ALIGNMENT: MISMATCH")

    else:
        print("Could not extract Return-Path domain.")

else:
    print("Return-Path header not present.")

print("\n========== DKIM ALIGNMENT ==========\n")

if from_domain and dkim_domain:
    print("From domain:", from_domain)
    print("DKIM domain:", dkim_domain)

    if from_domain == dkim_domain:
        print("DKIM ALIGNMENT: PASS")
    else:
        print("DKIM ALIGNMENT: FAIL")
else:
    print("DKIM ALIGNMENT: UNKNOWN")

# Get SPF / MAIL FROM domain from Return-Path
return_path = msg.get("Return-Path")

if return_path:
    _, return_email = parseaddr(return_path)

    if return_email and "@" in return_email:
        spf_domain = return_email.split("@")[-1].lower()
    else:
        spf_domain = None
else:
    spf_domain = None

sending_ip = get_sending_ip(msg)

print("\n========== SPF INPUTS ==========\n")
print("SPF domain:", spf_domain)
print("Sending IP:", sending_ip)


print("\n========== SPF ALIGNMENT ==========\n")

if from_domain and spf_domain:
    print("From domain:", from_domain)
    print("SPF domain:", spf_domain)

    if from_domain == spf_domain:
        print("SPF ALIGNMENT: PASS")
    else:
        print("SPF ALIGNMENT: FAIL")
else:
    print("SPF ALIGNMENT: UNKNOWN")

spf_result = check_spf_authentication(spf_domain, sending_ip)

print("\n========== DMARC RESULT ==========\n")

dkim_pass = False
spf_pass = spf_pass = (spf_result == "pass")

# DKIM authentication result
try:
    with open(email_file, "rb") as f:
        email_data = f.read()

    dkim_pass = dkim.verify(email_data)

except Exception:
    dkim_pass = False


# DMARC requires authentication + alignment
dkim_dmarc_pass = (
    dkim_pass
    and from_domain
    and dkim_domain
    and from_domain == dkim_domain
)

spf_dmarc_pass = (
    spf_pass
    and from_domain
    and spf_domain
    and from_domain == spf_domain
)


print("DKIM authentication:", "PASS" if dkim_pass else "FAIL")
print("DKIM alignment:", "PASS" if from_domain == dkim_domain else "FAIL")

if spf_result == "pass":
    print("SPF authentication: PASS")
elif spf_result == "fail":
    print("SPF authentication: FAIL")
else:
    print("SPF authentication:", spf_result.upper())
print("SPF alignment:", "PASS" if from_domain == spf_domain else "FAIL")


if dkim_dmarc_pass or spf_dmarc_pass:
    dmarc_result = "PASS"
elif spf_result == "fail" and not dkim_pass:
    dmarc_result = "FAIL"
else:
    dmarc_result = "NOT YET DETERMINED"

print("\nDMARC RESULT:", dmarc_result)

# ============================================================
# SPF CHECK
# ============================================================

def check_spf(domain):

    print("\n========== SPF CHECK ==========\n")
    print("Checking SPF for:", domain)

    try:

        answers = dns.resolver.resolve(domain, "TXT")

        spf_records = []

        for record in answers:

            text = "".join(
                chunk.decode("utf-8")
                if isinstance(chunk, bytes)
                else chunk
                for chunk in record.strings
            )

            if text.lower().startswith("v=spf1"):
                spf_records.append(text)


        if spf_records:

            print("SPF: FOUND")

            for spf in spf_records:
                print("Record:", spf)

        else:

            print("SPF: NOT FOUND")


    except dns.resolver.NXDOMAIN:

        print("SPF: DOMAIN DOES NOT EXIST")


    except dns.resolver.NoAnswer:

        print("SPF: NO DNS ANSWER")


    except Exception as e:

        print("SPF: DNS ERROR")
        print(e)


if from_domain:

    check_spf(from_domain)

# ============================================================
# DMARC CHECK
# ============================================================

def check_dmarc(domain):

    print("\n========== DMARC CHECK ==========\n")
    print("Checking DMARC for:", domain)

    dmarc_domain = f"_dmarc.{domain}"

    try:

        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        dmarc_records = []

        for record in answers:

            text = "".join(
                chunk.decode("utf-8")
                if isinstance(chunk, bytes)
                else chunk
                for chunk in record.strings
            )

            if text.lower().startswith("v=dmarc1"):
                dmarc_records.append(text)

        if dmarc_records:

            print("DMARC: FOUND")

            for record in dmarc_records:
                print("Record:", record)

        else:

            print("DMARC: NOT FOUND")

    except dns.resolver.NXDOMAIN:

        print("DMARC: RECORD DOES NOT EXIST")

    except dns.resolver.NoAnswer:

        print("DMARC: NO DNS ANSWER")

    except Exception as e:

        print("DMARC DNS ERROR:", e)


if from_domain:

    check_dmarc(from_domain)

# ============================================================
# RISK ASSESSMENT
# ============================================================

risk_score = 0
risk_indicators = []


# SPF authentication
if spf_result == "fail":
    risk_score += 2
    risk_indicators.append("SPF authentication failed")


# DKIM authentication
if not dkim_pass:
    risk_score += 2
    risk_indicators.append("DKIM verification failed")


# Reply-To mismatch
if reply_to and from_domain:

    _, reply_email = parseaddr(reply_to)

    if reply_email and "@" in reply_email:

        reply_domain = reply_email.split("@")[-1].lower()

        if reply_domain != from_domain:
            risk_score += 2
            risk_indicators.append(
                "Reply-To domain differs from From domain"
            )


# Return-Path mismatch
if return_path and from_domain:

    _, return_email = parseaddr(return_path)

    if return_email and "@" in return_email:

        return_domain = return_email.split("@")[-1].lower()

        if return_domain != from_domain:
            risk_score += 1
            risk_indicators.append(
                "Return-Path domain differs from From domain"
            )


# URL indicators
for url in urls:

    details = analyze_url(url)

    if details["is_ip_address"]:
        risk_score += 2
        risk_indicators.append(
            "URL uses an IP address instead of a domain"
        )

    if details["uses_http"]:
        risk_score += 1
        risk_indicators.append(
            "URL uses HTTP instead of HTTPS"
        )


# Determine risk level
if risk_score >= 6:
    risk_level = "HIGH"

elif risk_score >= 3:
    risk_level = "MEDIUM"

else:
    risk_level = "LOW"


print("\n========== RISK ASSESSMENT ==========\n")

print("Risk Score:", risk_score)
print("Risk Level:", risk_level)

print("\nIndicators:")

if risk_indicators:

    for indicator in risk_indicators:
        print("[!] " + indicator)

else:

    print("No significant indicators detected.")


# ============================================================
# END
# ============================================================

print("\n" + "=" * 50)
print("           ANALYSIS COMPLETE")
print("=" * 50)

# ============================================================
# JSON REPORT
# ============================================================

import json

report = {
    "email": {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path")
    },

    "authentication": {
        "spf_result": spf_result,
        "dkim_result": "PASS" if dkim_pass else "FAIL",
        "dmarc_result": dmarc_result
    },

    "risk_assessment": {
        "score": risk_score,
        "level": risk_level,
        "indicators": risk_indicators
    },

    "urls": [analyze_url(url) for url in urls]
}

with open("output/sample_report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print("\nJSON report saved to: output/sample_report.json")