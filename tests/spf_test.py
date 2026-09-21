import dns.resolver

domain = input("Enter domain to check SPF: ").strip()

print("\nChecking SPF record for:", domain)

try:
    answers = dns.resolver.resolve(domain, "TXT")

    spf_records = []

    for record in answers:
        text = "".join(
            chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
            for chunk in record.strings
        )

        if text.lower().startswith("v=spf1"):
            spf_records.append(text)

    if spf_records:
        print("\nSPF record found:")

        for spf in spf_records:
            print(spf)

    else:
        print("\nNo SPF record found.")

except dns.resolver.NXDOMAIN:
    print("\nDomain does not exist.")

except dns.resolver.NoAnswer:
    print("\nNo TXT records found.")

except dns.resolver.NoNameservers:
    print("\nDNS nameservers could not answer.")

except Exception as e:
    print("\nDNS error:", e)