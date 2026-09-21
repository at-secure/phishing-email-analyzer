import json
from datetime import datetime


# ============================================================
# SOC REPORT GENERATOR
# ============================================================

with open("output/sample_report.json", "r", encoding="utf-8") as f:
    report = json.load(f)


email = report["email"]
auth = report["authentication"]
risk = report["risk_assessment"]
urls = report["urls"]


report_text = f"""
============================================================
                 SOC PHISHING EMAIL REPORT
============================================================

REPORT DATE
-----------
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


EMAIL INFORMATION
-----------------
From:        {email.get("from")}
To:          {email.get("to")}
Subject:     {email.get("subject")}
Date:        {email.get("date")}
Reply-To:    {email.get("reply_to")}
Return-Path: {email.get("return_path")}


AUTHENTICATION ANALYSIS
-----------------------
SPF:         {auth.get("spf_result")}
DKIM:        {auth.get("dkim_result")}
DMARC:       {auth.get("dmarc_result")}


RISK ASSESSMENT
---------------
Risk Score:  {risk.get("score")}
Risk Level:  {risk.get("level")}


DETECTED INDICATORS
-------------------
"""


if risk.get("indicators"):

    for indicator in risk["indicators"]:
        report_text += f"[!] {indicator}\n"

else:

    report_text += "No URLs detected.\n"


# ============================================================
# ANALYST CONCLUSION
# ============================================================

report_text += """

ANALYST CONCLUSION
------------------
"""


if risk.get("score", 0) >= 6:

    report_text += (
        "Multiple suspicious indicators were detected, including "
        "authentication failures or sender-domain inconsistencies. "
        "The email should be investigated as potentially malicious."
    )

elif risk.get("score", 0) >= 3:

    report_text += (
        "Some suspicious indicators were detected. "
        "Further investigation is recommended before treating "
        "the email as legitimate."
    )

else:

    report_text += (
        "No significant phishing indicators were detected by the "
        "current analysis rules."
    )


report_text += """

============================================================
                     END OF REPORT
============================================================
"""


with open("output/soc_report.txt", "w", encoding="utf-8") as f:
    f.write(report_text)


print("SOC report saved to: output/soc_report.txt")