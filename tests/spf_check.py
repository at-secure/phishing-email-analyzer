import dns.resolver


def check_spf(domain):
    print("\n========== SPF CHECK ==========")
    print("Domain:", domain)

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

        if not spf_records:
            print("SPF: NOT FOUND")
            return None

        print("SPF: FOUND")

        for spf in spf_records:
            print("Record:", spf)

        return spf_records

    except dns.resolver.NXDOMAIN:
        print("Domain does not exist.")
        return None

    except dns.resolver.NoAnswer:
        print("No TXT records found.")
        return None

    except Exception as e:
        print("DNS error:", e)
        return None


domain = input("Enter domain: ").strip()

check_spf(domain)