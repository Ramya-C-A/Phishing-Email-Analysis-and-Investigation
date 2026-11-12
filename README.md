# Phishing Email Analysis & SOC Investigation (Splunk)

## 1. Executive Summary
A simulated phishing campaign impersonating internal IT Support was detected targeting corporate employees with an urgent Office 365 password expiration lure. Through static email header forensics and SIEM log correlation in **Splunk**, the investigation identified **three targeted employees** and confirmed **one compromised account** (`priya.patel`), which submitted credentials to a malicious domain.

---

## 2. Tools & Techniques Used
* **Static Email Analysis:** Manual header inspection, HTML link extraction, and sender authentication verification (SPF, DKIM, DMARC).
* **SIEM & Log Correlation:** Splunk Enterprise (SPL queries across Email Gateway and Web Proxy logs).
* **Threat Intelligence & Defanging:** Safe IOC handling (`hxxp://` and `[.]` notation).

---

## 3. Email Forensics & Header Analysis
Inspection of the raw `.eml` artifact revealed multiple indicators of spoofing and credential harvesting:
* **Display Name & Reply-To Spoofing:** The email appeared to come from `support@yourcompany.com`, but the `Reply-To` header directed responses to an external domain (`admin-reset@secure-login-verify.net`).
* **Authentication Failures:** 
  * **SPF:** `fail` (Originating IP `192.0.2.145` is not authorized to send for `yourcompany.com`)
  * **DKIM:** `none` (No cryptographic signature present)
  * **DMARC:** `fail`
* **Social Engineering Lure:** Created artificial urgency ("Password Expires in 2 Hours") to trick users into clicking a malicious hyperlink.

---

## 4. Indicators of Compromise (IOCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **Originating IP** | `192.0.2[.]145` | Unauthorized sending mail server |
| **Malicious Domain** | `secure-login-verify[.]net` | Credential harvesting infrastructure |
| **Malicious URL** | `hxxp://secure-login-verify[.]net/office365/auth` | Fake Office 365 login page |
| **Reply-To Address** | `admin-reset@secure-login-verify[.]net` | External attacker inbox |
| **Subject Line** | `URGENT: Your Office 365 Password Expires in 2 Hours!` | Phishing campaign lure |

---

## 5. SIEM Threat Hunting & Scoping (Splunk)

### A. Email Blast Radius (Email Gateway Logs)
To determine how many employees received the phishing email, the following SPL query was executed:
```spl
index="phishing_lab" subject="*Password Expires*" | table timestamp, sender, recipient, action
```
* **Findings:** Three employees were targeted. Two emails were delivered (`rahul.sharma` and `priya.patel`), and one was blocked (`amit.verma`).

![Splunk Email Scope](splunk_email_scope.png)

### B. User Interaction & Compromise Assessment (Web Proxy Logs)
To check if any recipient clicked the malicious link, proxy traffic was queried for the phishing domain:
```spl
index="phishing_lab" url="*secure-login-verify.net*" | table timestamp, user, src_ip, url
```
* **Findings:** User **`priya.patel`** (`10.0.1.22`) visited the phishing URL and subsequently accessed `/office365/submit-password`, confirming credential compromise.

![Splunk Proxy Investigation](splunk_proxy_click.png)

---

## 6. Containment & Remediation Actions
1. **Account Lockdown:** Immediately reset Active Directory / Office 365 credentials for `priya.patel` and revoked all active session tokens.
2. **Email Purge:** Quarantined and deleted the malicious message from the inboxes of `rahul.sharma` and `priya.patel`.
3. **Network Blocking:** Added `secure-login-verify[.]net` and IP `192.0.2[.]145` to the corporate firewall and secure web gateway blocklists.
4. **User Awareness:** Notified targeted staff and enforced Multi-Factor Authentication (MFA) verification on affected accounts.

