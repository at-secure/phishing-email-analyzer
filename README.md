# Phishing Email Analyzer

I created this project to analyze Phishing Emails using Python.

This was to take a raw.eml email file and test parts of the email that can be used in a phishing investigation.

What the project does

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

It then assigns a risk score to the email and stores the analysis in a json file.

I also wrote a different script which takes the JSON results and renders out a very simple SOC report.

Example

I composed an email that has a couple of warning signs.

The analyzer detected:

``text

SPF: FAIL

DKIM: FAIL

DMARC: FAIL

Reply-To alignment: MISMATCH

Return-Path alignment: MISMATCH


Risk Score: 7

Risk Level: HIGH

The analyzer further indicates the specific causes of the scored value: `text

[!] SPF authentication failed

[!] DKIM verification failed

[!] Reply-To domain differs from domain

[!] Return-Path domain differs from domain

Project structure

`text


phishing-email-analyzer/

analyzer.py

soc_report.py

requirements.txt

README.md


.gitignore

|

samples/

suspicious_email.eml


phishingurltest.eml

ipurltest.eml

|

output/

sample_report.json

soc_report.txt

|

tests/

dkim_test.py

dkim_verify.py

dmarc_test.py

spf_check.py

spf_test.py

phishingurltest.eml

test_email.eml

How I built it

First, I set up a python virtual environment for the project.

Then I sat down and started working on the analysing of email one by one.

One of the more difficult things for me to do was to generate the report in JSON format. I was trying to keep the output of the analysis stored in a data structure instead of just simply outputting everything to the terminal.

During the time I was building the project I learnt a little more about SPF, DKIM and DMARC and how they can be used when breaking down an email.

And this is not quite the same thing, you also need to take into account domain alignment and the final authentication result.

Running the project

Install the required packages: `text

pip install -r requirements.txt

Run the analyzer: `text

python analyzer.py

2. How it works The program will request the.eml file.

Example: `text 


samples\suspicious_email.eml

The JSON report is saved to: `text


output\sample_report.json

To create the SOC report: `text

python soc_report.py

The report is saved to:

`text

output\soc_report.txt

Technologies

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

Current status

This is the latest version of the project, and it works with the sample emails in the repo.


The next task I am planning to do is to try the analyzer with actual.eml emails and keep working on the phishing detection logic.

How to encrypt an email? For privacy reasons, actual emails carrying confidential or private content should not be uploaded to a public repository.