# Phishing Email Analyzer

I created this project to analyze phishing emails using Python.

The idea was to take a raw `.eml` email file and check different parts of the email that can be useful during a phishing investigation.

## What the project does

The analyzer checks:

* Email headers
* From address
* Reply-To address
* Return-Path
* Received headers
* Sending IP address
* SPF
* DKIM
* DMARC
* SPF and DKIM domain alignment
* URLs inside the email
* URLs using IP addresses
* HTTP URLs
* Suspicious indicators

It then assigns a risk score based on the indicators found and stores the analysis in a JSON file.

I also wrote a separate script that takes the JSON results and creates a simple SOC report.

## Example

I created a test email with a couple of warning signs.

The analyzer detected:

```text
SPF: FAIL
DKIM: FAIL
DMARC: FAIL

Reply-To alignment: MISMATCH
Return-Path alignment: MISMATCH

Risk Score: 7
Risk Level: HIGH
```

The analyzer also showed the specific reasons that contributed to the score:

```text
[!] SPF authentication failed
[!] DKIM verification failed
[!] Reply-To domain differs from From domain
[!] Return-Path domain differs from From domain
```

The score is only based on the indicators currently implemented in the project. It is not intended to prove that an email is malicious by itself.

## Project structure

```text
phishing-email-analyzer/
│
├── analyzer.py
├── soc_report.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── samples/
│   ├── suspicious_email.eml
│   ├── phishing_url_test.eml
│   └── ip_url_test.eml
│
├── output/
│   ├── sample_report.json
│   └── soc_report.txt
│
└── tests/
    ├── dkim_test.py
    ├── dkim_verify.py
    ├── dmarc_test.py
    ├── spf_check.py
    ├── spf_test.py
    ├── phishing_url_test.eml
    └── test_email.eml
```

## How I built it

First, I set up a Python virtual environment for the project.

Then I started working on the email analysis one part at a time.

One of the more difficult things for me was generating the report in JSON format. I wanted to keep the analysis results stored in a proper data structure instead of only printing everything to the terminal.

While building the project, I learnt more about SPF, DKIM and DMARC and how they can be used when breaking down an email.

I also learnt that authentication and domain alignment are not exactly the same thing, so both need to be considered when analyzing an email.

## Running the project

Install the required packages:

```powershell
pip install -r requirements.txt
```

Run the analyzer:

```powershell
python analyzer.py
```

The program will ask for the path of the `.eml` file.

Example:

```text
samples\suspicious_email.eml
```

The JSON report is saved to:

```text
output\sample_report.json
```

To create the SOC report:

```powershell
python soc_report.py
```

The report is saved to:

```text
output\soc_report.txt
```

## Technologies

* Python
* DNS
* SPF
* DKIM
* DMARC
* Email header analysis
* URL analysis
* IOC analysis
* JSON
* SOC investigation

## Current status

This is the current version of the project, and it works with the sample emails included in the repository.

The next thing I am planning to do is test the analyzer with actual `.eml` emails and continue improving the phishing detection logic.

For privacy reasons, actual emails containing confidential or private information should not be uploaded to a public repository.

## Limitations

The SPF implementation is currently basic and does not cover every SPF mechanism and rule.

The phishing detection logic is also simple at this stage. The risk score is based only on the indicators implemented in the project, so this should not be considered a complete phishing detection system.
