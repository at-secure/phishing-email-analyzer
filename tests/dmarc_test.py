import dns.resolver


domain = input("Enter domain to check DMARC: ").strip()

dmarc_domain = f"_dmarc.{domain}"

print("\n========== DMARC CHECK ==========")
print("Domain:", domain)
print("DNS name:", dmarc_domain)


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

        print("\nDMARC record found:")

        for record in dmarc_records:
            print(record)

    else:

        print("\nNo DMARC record found.")


except dns.resolver.NXDOMAIN:

    print("\nDMARC record does not exist.")


except dns.resolver.NoAnswer:

    print("\nNo DMARC TXT record found.")


except Exception as e:

    print("\nDNS error:", e)