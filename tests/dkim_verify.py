import dkim

email_file = input("Enter path to .eml file: ").strip()

try:
    with open(email_file, "rb") as f:
        email_data = f.read()

except FileNotFoundError:
    print("\nEmail file not found.")
    exit()

print("\n========== DKIM CRYPTOGRAPHIC VERIFICATION ==========\n")

try:
    result = dkim.verify(email_data)

    if result:
        print("DKIM RESULT: PASS")
    else:
        print("DKIM RESULT: FAIL")

except Exception as e:
    print("DKIM verification error:", e)