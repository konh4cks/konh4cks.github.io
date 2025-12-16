---
title: DNS Settings for Phishing
date: 2025-11-02 00:00:00 +0000
categories: [Sans Red-Team 2025 Lessons]
tags: [sans, red-team]
---


• DMARC: Domain-based Message Authentication, Reporting and
Conformance
– Built on top of SPF and DKIM to allow domain owner to published a policy
of requirements for email
– Receiving server can check new email against the policy to find
inconsistencies indicating spoofing
– SPF: Sender Policy Framework: Identifies predefined set of mail servers
– DKIM: DomainKeys Identified Mail: Adds a signature to email messages
from the legitimate mail server
• Dependent of receiving server to check against the sender domain



DMARC Tags
Attack Infrastructure
v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@pwneip.com
TagPurposeExample
vProtocol versionv=DMARC1
pctPercentage of messages subjected to filteringpct=20
rufReporting URI for forensic reportsruf=mailto:authfail@example.com
ruaReporting URI of aggregate reportsrua=mailto:aggrep@example.com
pPolicy for organizational domainp=quarantine
spPolicy for subdomains of the ODsp=reject
adkimAlignment mode for DKIM (strict || relaxed)adkim=s or adkim=r
aspfAlignment mode for SPF (strict || relaxed)aspf=s or aspf=r

DMARC Tags
A breakdown of the various tags used in a DMARC to communicate how email servers should validate and
respond to email:
• v: Protocol version
• pct: Percentage of messages subjected to filtering
• ruf: Reporting URI for forensic reports
• rua: Reporting URI of aggregate reports
• p: Policy for organizational domain
• sp: Policy for subdomains of the OD
• adkim: Alignment mode for DKIM (strict || relaxed)
• aspf: Alignment mode for SPF (strict || relaxed)
Reference:
https://www.dmarcanalyzer.com/dmarc/


# DNS Setup for Mail Services

• DNS Prerequisites
• mail.pwneip.com. A 10.10.13.37
– A record, fwd resolved to ipv4 address
• pwneip.com. MX 10 mail.pwneip.com.au
– MX record, specifies a mail server to handle email
• pwneip.com. TXT "v=spf1 a mx ~all"
– TXT record, spf version 1, ~all states non-authorized email will be
accepted but marked
• _dmarc.pwneip.com. TXT v=DMARC1; p=none;
– TXT record, dmarc version 1, policy is none

DNS Setup for Mail Services
The slide shows examples of the DNS records needed to properly configure a mail server to participate in
DMARC, but a few values are deliberately set low.
all options:
-all: (fail) non-authorized email will be rejected*.
~all: (soft fail) non-authorized email will be accepted but marked*.
+all: this tag allows any server to send email from your domain, so we advise strongly against it.


# Nix Mail Servers

• Sendmail: Linux mail
software with highly
customizable configuration
• Postfix: Designed as an
alternative to Sendmail.
Postfix attempts to be fast,
easy to administer, and secure.
• Exim: Developed at
the University of Cambridge
with a great deal of flexibility
in the way mail can be routed.

Nix Mail Servers
There have been hundreds of *nix mail servers over the years but three hold most of the market share today.
Sendmail is the oldest with a highly customizable configuration. Sendmail was commercialized by ProofPoint,
Inc. in 2013. Postfix was released by Wietse Venema as an alternative to Sendmail, attempting to be fast and easy
to administer and secure. Exim currently holds the largest market share. Exim is actively maintained and highly
flexible with extensive documentation at https://github.com/Exim/exim/wiki.
References:
https://www.proofpoint.com/us/products/email-protection/open-source-email-solution
https://www.proofpoint.com/us/proofpoint-inc-acquires-sendmail-inc
http://www.postfix.org/
https://www.exim.org/
http://www.securityspace.com/s_survey/data/man.201801/mxsurvey.html

# Third Party Email Hosting

Google for Business
Microsoft Office 365
Zoho Workspace
Rackspace
Amazon WorkMail
Immediate Setup
Instant Reputation
Legal Considerations
Abuse Reports


