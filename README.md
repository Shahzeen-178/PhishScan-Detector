# PhishScan

A desktop tool that checks if an email is a phishing attempt or not.

---

## What it does

You give it an email file (.eml or .txt), it reads it, and tells you one of three things:

- **PHISHING** — this email is dangerous
- **SUSPICIOUS** — something feels off, be careful
- **SAFE** — looks fine

It also shows you a confidence score out of 100 and tells you exactly why it flagged the email.

---

## How to run it

**Step 1 — Install the required libraries (only once)**
```
pip install customtkinter numpy scipy
```

**Step 2 — Put both files in the same folder**
```
phishscan.py
keywords.txt
```

**Step 3 — Run it**
```
python phishscan.py
```

---

## How to test it

Make a text file called `test.txt` and paste this inside:

```
From: PayPal Security <security@paypa1.com>
Subject: Your account will be suspended

Dear Customer,

Unusual activity was detected on your account. Your account will be closed within 24 hours.
Please verify your account immediately by clicking here: http://192.168.1.1/verify

Provide your bank details urgently. This is your last warning. Act now or face legal action.
```

Save it and upload it in the app. It should come back as PHISHING with a high score.

---

## How it works (simple version)

When you upload an email, the app runs 5 checks on it:

**Check 1 — Keywords**
Looks for dangerous words like "verify your account", "bank details", "act now". Words are grouped by how serious they are — more serious words give higher scores.

**Check 2 — Links**
Checks if the email has any suspicious links — like ones using an IP address instead of a domain name, URL shorteners like bit.ly, or sketchy domain endings like .xyz or .tk.

**Check 3 — Sender**
Looks at who sent the email. If someone is pretending to be PayPal but their email is from gmail.com, that's a red flag. Also catches typos in domain names like paypa1.com instead of paypal.com.

**Check 4 — Urgency**
Looks for threatening language — things like "your account will be suspended", "within 24 hours", "legal action", "last warning". These are classic tricks attackers use to make you panic and click.

**Check 5 — Text similarity**
Compares the email text to a collection of known phishing emails and known safe emails. If it reads like a phishing email, the score goes up.

There's also a bonus check that runs before everything else — if the email was sent using a known hacking tool like GoPhish or ZPhisher, it immediately flags it as PHISHING without running any of the other checks.

---

## The keywords.txt file

This file controls what words the app considers suspicious. You can open it in Notepad and add your own keywords anytime without touching the code.

Format:
```
your keyword here,1
```

Use 1 for high risk, 2 for medium, 3 for low risk words.

---

## What it cannot do

- It cannot scan attachments
- It cannot read image-only emails (no text to analyze)
- It does not connect to the internet — everything runs offline

---

## Files

| File | What it does |
|------|-------------|
| phishscan.py | The entire application — all logic and the GUI in one file |
| keywords.txt | The list of phishing keywords you can edit |

---

## Built with

- Python 3.11
- customtkinter (for the GUI)
- re, email, quopri, os, math (all built into Python — no extra install needed)


