import dns.resolver
import re

dkim_header = input("Enter DKIM-Signature: ").strip()

domain_match = re.search(r"\bd=([^;\s]+)", dkim_header)
selector_match = re.search(r"\bs=([^;\s]+)", dkim_header)

if not domain_match or not selector_match:
    print("\nCould not extract DKIM domain or selector.")
    exit()

domain = domain_match.group(1)
selector = selector_match.group(1)

dkim_domain = f"{selector}._domainkey.{domain}"

print("\n========== DKIM CHECK ==========")
print("Signing domain:", domain)
print("Selector:", selector)
print("DNS name:", dkim_domain)

try:
    answers = dns.resolver.resolve(dkim_domain, "TXT")

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
    print("\nDKIM DNS record does not exist.")

except dns.resolver.NoAnswer:
    print("\nNo DKIM TXT record found.")

except Exception as e:
    print("\nDNS error:", e)