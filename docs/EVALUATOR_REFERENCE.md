# Threadsaw 1.3.0 evaluator reference

This document is generated from the same factor registry used by the GUI and CLI. It describes all 72 visible evaluators, including identifiers, behavior, examples, prerequisites, computational load, parameters, case-history requirements, and starter-preset settings.

See [`PHISH_HUNT.md`](PHISH_HUNT.md) for score semantics, evidence-coverage columns, automatic URL/ZIP preparation, trusted-context filtering, and run behavior.

## Inherently Risky

### Sender and Header Deception

#### Reply-To domain differs from From domain

- **Factor ID:** `reply_to_domain_mismatch`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Checks whether the registrable domain in Reply-To differs from the visible From domain.

**Suspicious examples**

- From: accounts@legitcompany.com; Reply-To: paymentdesk@external.test

**Legitimate/nonmatching context**

- From: alerts@company.com; Reply-To: support@company.com

**False-positive note:** Mailing platforms, ticketing systems, and outsourced support services can legitimately use another Reply-To domain.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 25 | `risk_when_yes` |
| Internal | On | 25 | `risk_when_yes` |
| General | On | 25 | `risk_when_yes` |

#### Display name contains an email address with a different domain

- **Factor ID:** `display_name_embedded_email_domain_mismatch`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Extracts email-like text from the sender display name and compares its domain with the actual sender address domain.

**Suspicious examples**

- From: "janesmith@legitcompany.com" <janesmith@external.test>

**Legitimate/nonmatching context**

- From: "Jane Smith" <janesmith@legitcompany.com>

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 30 | `risk_when_yes` |
| General | On | 35 | `risk_when_yes` |

#### Sender domain resembles a configured legitimate organization domain

- **Factor ID:** `sender_domain_lookalike_configured`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Compares the sender domain with analyst-supplied legitimate domains using conservative local lookalike checks.

**Suspicious examples**

- legitcornpany.com resembles configured legitcompany.com

**Legitimate/nonmatching context**

- Exact match legitcompany.com is not flagged.

**False-positive note:** Similar names can belong to unrelated legitimate organizations. Configure only domains relevant to the investigation.

**Parameters**

- `legitimate_domains` (multiline) — Legitimate organization domains

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### Sender domain resembles a recipient domain but does not match

- **Factor ID:** `sender_domain_lookalike_recipient`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** recipient data
- **Evaluator status:** Operational

Compares the sender domain with recipient domains and flags a conservative lookalike mismatch.

**Suspicious examples**

- From billing@legitcornpany.com to employee@legitcompany.com

**Legitimate/nonmatching context**

- Exact sender/recipient domain matches are not flagged.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 25 | `risk_when_yes` |
| General | On | 30 | `risk_when_yes` |

### Security Check Failures

#### Trusted DMARC check failed

- **Factor ID:** `trusted_dmarc_fail`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** trusted authentication-result classification
- **Evaluator status:** Operational

Uses only a stored Authentication-Results record marked trusted by conservative PST-corpus inference and explicitly reporting DMARC fail.

**Suspicious examples**

- dmarc=fail from a PST-inferred trusted authentication service

**Legitimate/nonmatching context**

- Missing, none, or untrusted results return UNKNOWN rather than YES.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 30 | `risk_when_yes` |
| Internal | On | 20 | `risk_when_yes` |
| General | On | 30 | `risk_when_yes` |

#### Trusted DKIM check failed

- **Factor ID:** `trusted_dkim_fail`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** trusted authentication-result classification
- **Evaluator status:** Operational

Uses only a stored Authentication-Results record marked trusted by conservative PST-corpus inference and explicitly reporting DKIM fail.

**Suspicious examples**

- dkim=fail from a PST-inferred trusted authentication service

**Legitimate/nonmatching context**

- No DKIM signature is UNKNOWN, not a failure.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 25 | `risk_when_yes` |
| Internal | On | 25 | `risk_when_yes` |
| General | On | 25 | `risk_when_yes` |

#### Trusted SPF check failed

- **Factor ID:** `trusted_spf_fail`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** trusted authentication-result classification
- **Evaluator status:** Operational

Uses stored SPF results marked trusted by conservative PST-corpus inference. FAIL, SOFTFAIL, and PERMERROR can match; TEMPERROR and missing results are UNKNOWN.

**Suspicious examples**

- spf=fail client-ip=203.0.113.5

**Legitimate/nonmatching context**

- spf=pass does not trigger; missing SPF is UNKNOWN.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 15 | `risk_when_yes` |

### URL Deception and Obfuscation

#### Displayed URL domain differs from actual domain

- **Factor ID:** `displayed_url_domain_mismatch`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks links whose visible text itself looks like a URL/domain and compares it with the actual destination stored by Threadsaw.

**Suspicious examples**

- Visible text: https://login.company.com; actual href: https://attacker.test/login

**Legitimate/nonmatching context**

- A security gateway may rewrite the actual href while leaving the original URL visible.

**False-positive note:** This can produce false positives when the organization rewrites URLs. Disable this factor in URL-rewriting environments.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 30 | `risk_when_yes` |
| Internal | On | 30 | `risk_when_yes` |
| General | On | 30 | `risk_when_yes` |

#### URL uses a literal IP address

- **Factor ID:** `url_literal_ip`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks whether a stored URL directly uses an IPv4 or IPv6 address instead of a hostname.

**Suspicious examples**

- http://192.0.2.25/login
- https://[2001:db8::25]/document

**Legitimate/nonmatching context**

- Some internal appliances use IP-address URLs.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 30 | `risk_when_yes` |
| Internal | On | 30 | `risk_when_yes` |
| General | On | 30 | `risk_when_yes` |

#### URL contains misleading user-information before the hostname

- **Factor ID:** `url_userinfo_misdirection`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks URL userinfo before @, which can make the left side look like the destination while the true host follows @.

**Suspicious examples**

- https://login.legitcompany.com@malicious.test/account

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 40 | `risk_when_yes` |
| Internal | On | 40 | `risk_when_yes` |
| General | On | 40 | `risk_when_yes` |

#### URL uses a non-standard network port

- **Factor ID:** `url_nonstandard_port`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks explicit web ports other than HTTP 80 or HTTPS 443 without connecting to the host.

**Suspicious examples**

- https://example.test:8443/login

**Legitimate/nonmatching context**

- Some legitimate internal or development applications use non-standard ports.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 15 | `risk_when_yes` |

#### URL uses a potentially dangerous URI scheme

- **Factor ID:** `url_dangerous_scheme`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks a bundled conservative list of schemes that may invoke scripts, local resources, applications, or unusual protocol handlers.

**Suspicious examples**

- file://
- smb://
- javascript:
- data:
- ms-msdt:
- search-ms:

**Legitimate/nonmatching context**

- mailto: and tel: are not included by default.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 40 | `risk_when_yes` |
| Internal | On | 40 | `risk_when_yes` |
| General | On | 40 | `risk_when_yes` |

#### URL hostname embeds a configured legitimate domain outside the true registrable domain

- **Factor ID:** `url_embeds_legitimate_domain`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks for an analyst-supplied legitimate domain placed misleadingly in subdomain labels while another registrable domain controls the host.

**Suspicious examples**

- microsoft.com.login.attacker.test (actual registrable domain attacker.test)

**Legitimate/nonmatching context**

- login.microsoft.com is a genuine subdomain and is not flagged.

**Parameters**

- `legitimate_domains` (multiline) — Legitimate domains

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### URL uses an obfuscated numeric IP-address representation

- **Factor ID:** `url_obfuscated_numeric_ip`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Recognizes local-only numeric IPv4 forms such as integer, hexadecimal, octal, or mixed-radix host text.

**Suspicious examples**

- http://2130706433/
- http://0x7f000001/

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 40 | `risk_when_yes` |
| Internal | On | 40 | `risk_when_yes` |
| General | On | 40 | `risk_when_yes` |

### Attachment Deception and Executable Content

#### Attachment contains executable or script content

- **Factor ID:** `attachment_executable_or_script`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** stored executable/script classification
- **Evaluator status:** Operational

Reads the executable/script classification already stored during ingestion or attachment reporting. It never rescans the file during Phish Hunt.

**Suspicious examples**

- PE executable, PowerShell, JavaScript, VBScript, batch, or shell script classification

**Legitimate/nonmatching context**

- UNKNOWN means the earlier check was not run or was inconclusive.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 50 | `risk_when_yes` |
| Internal | On | 50 | `risk_when_yes` |
| General | On | 50 | `risk_when_yes` |

#### Attachment filename uses a double extension

- **Factor ID:** `attachment_double_extension`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks filenames that may disguise the final extension while excluding common compound formats such as tar.gz.

**Suspicious examples**

- invoice.pdf.exe
- payment.docx.lnk

**Legitimate/nonmatching context**

- archive.tar.gz is not flagged by itself.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 35 | `risk_when_yes` |
| General | On | 35 | `risk_when_yes` |

#### Attachment filename contains Unicode direction-control or invisible characters

- **Factor ID:** `attachment_unicode_controls`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Inspects stored filename code points for bidirectional overrides, zero-width characters, and related invisible formatting controls.

**Suspicious examples**

- A filename visually appearing as invoice.pdf while hidden characters reorder its true suffix.

**Legitimate/nonmatching context**

- International text may legitimately contain some formatting controls, though they are unusual in filenames.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 35 | `risk_when_yes` |
| General | On | 35 | `risk_when_yes` |

#### Executable or script attachment has no filename extension

- **Factor ID:** `executable_without_extension`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** stored executable/script classification
- **Evaluator status:** Operational

Combines the existing executable/script classification with the stored filename and does not rescan bytes.

**Suspicious examples**

- Filename Invoice; stored class Windows PE executable

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 45 | `risk_when_yes` |
| Internal | On | 45 | `risk_when_yes` |
| General | On | 45 | `risk_when_yes` |

#### Attachment is a shortcut or Internet shortcut file

- **Factor ID:** `attachment_shortcut`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks stored extensions/types for shortcut and launcher formats without resolving or launching them.

**Suspicious examples**

- Document.lnk
- Secure Portal.url
- Payment.website

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 45 | `risk_when_yes` |
| Internal | On | 45 | `risk_when_yes` |
| General | On | 45 | `risk_when_yes` |

#### Attachment is a disk-image or container format

- **Factor ID:** `attachment_disk_image`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks stored attachment metadata for ISO, IMG, VHD, VHDX, DMG, and similar mountable container formats.

**Suspicious examples**

- payload.iso
- documents.vhdx

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 30 | `risk_when_yes` |
| Internal | On | 30 | `risk_when_yes` |
| General | On | 30 | `risk_when_yes` |

#### Attachment is an HTML or SVG document

- **Factor ID:** `attachment_html_svg`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks stored filename extensions and declared MIME types for HTML, SHTML, XHTML, or SVG attachments. It does not render the attachment.

**Suspicious examples**

- invoice.html
- secure-document.svg

**Legitimate/nonmatching context**

- Web-development and design workflows may legitimately exchange these files.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 40 | `risk_when_yes` |
| Internal | On | 40 | `risk_when_yes` |
| General | On | 40 | `risk_when_yes` |

#### Attachment uses a modern loader, launcher, or macro-enabled Office extension

- **Factor ID:** `attachment_modern_loader_or_macro`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks stored filename extensions for WSF, WSH, SCR, PIF, CPL, CHM, XLL, ONE, IQY, SLK, RDP, MSIX, and macro-enabled Office formats such as DOCM, XLSM, and PPTM.

**Suspicious examples**

- payment.wsf
- invoice.xll
- document.docm

**Legitimate/nonmatching context**

- Administrators and power users may exchange RDP, XLL, or macro-enabled Office files for legitimate work.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 45 | `risk_when_yes` |
| Internal | On | 45 | `risk_when_yes` |
| General | On | 45 | `risk_when_yes` |

### Active HTML Content

#### HTML form is embedded in the message body

- **Factor ID:** `html_form`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored HTML body
- **Evaluator status:** Operational

Statically parses the stored HTML body for form and input elements. It never renders or submits the form.

**Suspicious examples**

- <form><input type=password><button type=submit>

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 35 | `risk_when_yes` |
| General | On | 35 | `risk_when_yes` |

#### HTML body contains an automatic redirect

- **Factor ID:** `html_auto_redirect`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored HTML body
- **Evaluator status:** Operational

Statically checks the stored HTML for automatic redirect mechanisms such as meta refresh. Destinations remain inert text.

**Suspicious examples**

- <meta http-equiv="refresh" content="0;url=https://example.test/login">

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 35 | `risk_when_yes` |
| General | On | 35 | `risk_when_yes` |

#### HTML body contains an embedded frame or active-object element

- **Factor ID:** `html_embedded_active_object`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored HTML body
- **Evaluator status:** Operational

Checks for iframe, frame, object, embed, and applet elements without rendering or retrieving referenced content.

**Suspicious examples**

- <iframe src=...>
- <object data=...>

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 40 | `risk_when_yes` |
| Internal | On | 40 | `risk_when_yes` |
| General | On | 40 | `risk_when_yes` |

#### HTML body contains a script element

- **Factor ID:** `html_script`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored HTML body
- **Evaluator status:** Operational

Checks stored HTML for script elements. No script is executed.

**Suspicious examples**

- <script>...</script>

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 45 | `risk_when_yes` |
| Internal | On | 45 | `risk_when_yes` |
| General | On | 45 | `risk_when_yes` |

#### HTML body contains JavaScript event-handler attributes

- **Factor ID:** `html_event_handlers`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored HTML body
- **Evaluator status:** Operational

Checks stored HTML for inline on* event attributes such as onerror or onclick. No script is executed.

**Suspicious examples**

- <img onerror=...>
- <a onclick=...>

**Legitimate/nonmatching context**

- Some poorly constructed marketing templates include harmless event-handler attributes.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 25 | `risk_when_yes` |
| Internal | On | 25 | `risk_when_yes` |
| General | On | 25 | `risk_when_yes` |

## Situational

### Sender, Domain, and Infrastructure History

#### Return-Path domain differs from From domain

- **Factor ID:** `return_path_domain_mismatch`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Compares the registrable Return-Path and From domains.

**Suspicious examples**

- From billing@company.com; Return-Path bounce@unrelated.test

**Legitimate/nonmatching context**

- Legitimate mailing platforms commonly use a separate bounce domain.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Sender address is newly observed in the case

- **Factor ID:** `sender_address_new`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** none
- **Evaluator status:** Operational

Searches all earlier dated messages in the case for the same normalized sender address.

**Suspicious examples**

- First appearance of a purported vendor address during the campaign window.

**Legitimate/nonmatching context**

- Every legitimate correspondent is new once.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### Sender domain is newly observed in the case

- **Factor ID:** `sender_domain_new`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** none
- **Evaluator status:** Operational

Searches all earlier dated messages for any sender using the same registrable domain.

**Suspicious examples**

- A new lookalike vendor domain first appears during the hunt.

**Legitimate/nonmatching context**

- A new legitimate vendor also introduces a new domain.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Sender infrastructure IP is newly observed for that sender

- **Factor ID:** `sender_ip_new_for_sender`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** trusted boundary IP classification
- **Evaluator status:** Operational

Compares the current trusted-boundary IP with earlier IPs for the same sender. No lookup or geolocation occurs.

**Suspicious examples**

- Established sender suddenly arrives through an unseen trusted-boundary IP.

**Legitimate/nonmatching context**

- Cloud mail providers routinely rotate outbound IP addresses.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### Reply-To address is newly observed for that sender

- **Factor ID:** `reply_to_new_for_sender`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** none
- **Evaluator status:** Operational

Compares the current Reply-To address/domain with earlier messages from the same sender.

**Suspicious examples**

- A known vendor suddenly directs replies to an external mailbox.

**Legitimate/nonmatching context**

- A sender may legitimately change help-desk or billing addresses.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `risk_when_yes` |
| Internal | On | 20 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Return-Path domain is newly observed for that sender

- **Factor ID:** `return_path_new_for_sender`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** none
- **Evaluator status:** Operational

Compares the current Return-Path domain with earlier messages from the same sender.

**Suspicious examples**

- A known sender suddenly uses unfamiliar delivery infrastructure.

**Legitimate/nonmatching context**

- Legitimate senders switch email-service providers.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### Sender uses a common free-email provider

- **Factor ID:** `sender_free_email_provider`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** bundled provider list
- **Evaluator status:** Operational

Compares the sender domain with a bundled, versioned static list of common consumer email providers. No live lookup occurs.

**Suspicious examples**

- A purported corporate executive writes from a consumer mailbox.

**Legitimate/nonmatching context**

- Individuals and small organizations legitimately use consumer providers.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 8 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | On | 8 | `risk_when_yes` |

#### Sender email domain contains Punycode

- **Factor ID:** `sender_domain_punycode`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Checks the sender domain for xn-- labels and decodes them locally for review.

**Suspicious examples**

- billing@xn--legitcompny-...

**Legitimate/nonmatching context**

- Internationalized domains legitimately use Punycode.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 20 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 15 | `risk_when_yes` |

#### Sender header address differs from visible From address

- **Factor ID:** `sender_header_mismatch`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored raw headers
- **Evaluator status:** Operational

Parses the stored raw Sender header and compares it with the visible From address.

**Suspicious examples**

- From payments@company.com; Sender delivery@external.test

**Legitimate/nonmatching context**

- Delegated sending and mailing platforms legitimately use Sender.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

### Thread and Relationship History

#### Corroborated reply to an existing thread

- **Factor ID:** `corroborated_thread_reply`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** stored Message-ID and thread-reference headers
- **Evaluator status:** Operational

Requires a thread-reference match to an earlier case message, plausible normalized subject continuity, and participant overlap.

**Suspicious examples**

- Can be weighted upward when a campaign is known to hijack real threads.

**Legitimate/nonmatching context**

- A well-corroborated earlier thread can be weighted downward, but compromised mailboxes can still reply in genuine threads.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `trust_when_yes` |
| Internal | On | 5 | `trust_when_yes` |
| General | On | 5 | `trust_when_yes` |

#### Thread continuation uses changed sender infrastructure

- **Factor ID:** `thread_continuation_changed_infrastructure`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** stored thread references, case history
- **Evaluator status:** Operational

Requires an exact In-Reply-To/References match to an earlier case Message-ID plus participant overlap, then checks whether Reply-To, Return-Path domain, or trusted sending IP is newly observed for that counterpart. Subject equality is not required for this factor.

**Suspicious examples**

- A genuine vendor thread continues with a changed subject such as 'Invoice — URGENT updated bank details', while replies now route to a new domain or the message arrives from a never-before-seen boundary IP.

**Legitimate/nonmatching context**

- A vendor may migrate mail providers, change routing, or add a new support mailbox.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 35 | `risk_when_yes` |
| Internal | On | 40 | `risk_when_yes` |
| General | On | 35 | `risk_when_yes` |

#### Prior sender-recipient relationship

- **Factor ID:** `prior_sender_recipient`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** recipient data
- **Evaluator status:** Operational

Searches earlier messages for the same sender and at least one matching recipient address.

**Suspicious examples**

- Can be positive for a campaign targeting established relationships.

**Legitimate/nonmatching context**

- Can be negative when prior correspondence is reassuring.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `trust_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | On | 5 | `trust_when_yes` |

#### Prior sender and normalized subject pair

- **Factor ID:** `prior_sender_subject`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** none
- **Evaluator status:** Operational

Searches earlier messages for the same sender and subject after removing common reply/forward prefixes and normalizing whitespace.

**Suspicious examples**

- A known campaign repeatedly reuses a sender-subject signature.

**Legitimate/nonmatching context**

- Recurring legitimate notifications commonly reuse subjects.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `trust_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | On | 5 | `trust_when_yes` |

#### Subject appears to be a reply, but no thread-reference headers are present

- **Factor ID:** `reply_subject_without_references`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored raw headers
- **Evaluator status:** Operational

Checks for a reply-style subject prefix while In-Reply-To and References are absent.

**Suspicious examples**

- Re: Updated payment instructions with no thread headers.

**Legitimate/nonmatching context**

- Exports and some mail clients may omit threading headers.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Thread-reference headers do not match any earlier message in the case

- **Factor ID:** `unmatched_thread_references`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** stored Message-ID and thread-reference headers
- **Evaluator status:** Operational

Checks whether present In-Reply-To/References values fail to match any earlier case Message-ID.

**Suspicious examples**

- Fabricated thread references may not match collected history.

**Legitimate/nonmatching context**

- The referenced message may simply be outside the collected mailbox data.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

### Authentication and Routing Context

#### Trusted ARC check failed

- **Factor ID:** `trusted_arc_fail`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** trusted authentication-result classification
- **Evaluator status:** Operational

Uses only a stored ARC result marked trusted by conservative PST-corpus inference and explicitly reporting failure.

**Suspicious examples**

- arc=fail from a PST-inferred trusted authentication service

**Legitimate/nonmatching context**

- Forwarding and intermediary modification can produce legitimate ARC problems.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### Authentication results conflict across headers

- **Factor ID:** `authentication_conflict`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** multiple authentication-result records
- **Evaluator status:** Operational

Compares multiple stored Authentication-Results records for pass/fail contradictions and records trusted status.

**Suspicious examples**

- Untrusted header says DMARC pass while trusted gateway says fail.

**Legitimate/nonmatching context**

- Multiple legitimate gateways can observe different results after forwarding or modification.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 15 | `risk_when_yes` |

#### Message date differs substantially from trusted Received time

- **Factor ID:** `date_received_discrepancy`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** trusted Received timestamp
- **Evaluator status:** Operational

Uses the existing stored date discrepancy and a user-configured absolute threshold.

**Suspicious examples**

- Header Date differs from trusted Received time by 53 hours.

**Legitimate/nonmatching context**

- Queue delays, migrations, and bad clocks can also create discrepancies.

**Parameters**

- `threshold_hours` (integer) — Difference threshold (hours); default `24`, minimum `0`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Message-ID is missing or malformed

- **Factor ID:** `message_id_missing_or_malformed`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Uses the stored Message-ID and conservative local syntax validation. No domain lookup is performed.

**Suspicious examples**

- No Message-ID or Message-ID: invoice-12345

**Legitimate/nonmatching context**

- Drafts, locally created MSG files, and unusual systems may omit it.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### Message-ID domain differs from visible From domain

- **Factor ID:** `message_id_domain_mismatch`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** none
- **Evaluator status:** Operational

Compares registrable domains in the stored Message-ID and From address.

**Suspicious examples**

- From billing@company.com; Message-ID <id@unrelated.test>

**Legitimate/nonmatching context**

- Marketing, ticketing, and delegated platforms often generate their own Message-ID domain.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

### URL Characteristics

#### SharePoint link differs from configured legitimate SharePoint host

- **Factor ID:** `sharepoint_host_mismatch`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Runs only when the analyst supplies a legitimate SharePoint hostname. Any stored URL containing SharePoint keywords but not matching that host can trigger.

**Suspicious examples**

- Configured company.sharepoint.com; message links to unfamiliar.sharepoint.com

**Legitimate/nonmatching context**

- External collaboration commonly uses another organization's SharePoint tenant.

**Parameters**

- `legitimate_sharepoint_host` (text) — Legitimate SharePoint host

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### External SharePoint tenant is newly observed in the case

- **Factor ID:** `external_sharepoint_tenant_new`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Requires a configured legitimate host, identifies a mismatched SharePoint tenant, and checks whether it appeared in earlier case messages.

**Suspicious examples**

- A newly introduced external tenant appears during a credential-phishing campaign.

**Legitimate/nonmatching context**

- A new collaboration partner also introduces a new tenant.

**Parameters**

- `legitimate_sharepoint_host` (text) — Legitimate SharePoint host

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### URL uses a known shortening service

- **Factor ID:** `url_shortener`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing, bundled shortener list
- **Evaluator status:** Operational

Compares stored URL hosts with a bundled, versioned local list of common shortening services. No redirect is followed.

**Suspicious examples**

- bit.ly or tinyurl.com link conceals the destination.

**Legitimate/nonmatching context**

- Shorteners are common in legitimate notifications and social media.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### URL hostname contains Punycode

- **Factor ID:** `url_punycode`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks stored URL hostnames for xn-- labels and decodes locally for analyst review.

**Suspicious examples**

- A lookalike hostname encoded with Punycode.

**Legitimate/nonmatching context**

- Internationalized domains legitimately use Punycode.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 20 | `risk_when_yes` |
| Internal | On | 20 | `risk_when_yes` |
| General | On | 15 | `risk_when_yes` |

#### URL destination domain is newly observed in the case

- **Factor ID:** `url_domain_new_case`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks whether any destination registrable domain was absent from all earlier case messages.

**Suspicious examples**

- New credential-harvesting infrastructure appears in the hunt window.

**Legitimate/nonmatching context**

- Legitimate correspondence regularly introduces new domains.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### URL destination domain is newly observed for that sender

- **Factor ID:** `url_domain_new_sender`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks whether an established sender links to a destination domain never seen in that sender's earlier messages.

**Suspicious examples**

- A known vendor suddenly links to an unfamiliar host.

**Legitimate/nonmatching context**

- Vendors adopt new platforms and services.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### URL hostname has unusually deep subdomain nesting

- **Factor ID:** `url_deep_subdomains`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Counts labels before the registrable domain and compares with an analyst-supplied minimum depth.

**Suspicious examples**

- secure.login.account.company.attacker.test

**Legitimate/nonmatching context**

- Cloud and enterprise services can use deeply nested legitimate hostnames.

**Parameters**

- `minimum_depth` (integer) — Minimum subdomain depth; default `4`, minimum `1`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### URL contains another full URL inside its query string or fragment

- **Factor ID:** `url_nested_url`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Locally decodes bounded query/fragment values and checks for an embedded complete HTTP(S) URL without following either URL.

**Suspicious examples**

- https://redirector.test/?target=https%3A%2F%2Fattacker.test

**Legitimate/nonmatching context**

- Marketing, authentication, and security rewriting commonly embed destination URLs.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### URL uses plain HTTP rather than HTTPS

- **Factor ID:** `url_plain_http`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks stored web URLs for the http scheme and never connects to them.

**Suspicious examples**

- http://example.test/login

**Legitimate/nonmatching context**

- Legacy and internal systems may legitimately use HTTP.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### URL contains unusually heavy percent-encoding

- **Factor ID:** `url_heavy_percent_encoding`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Counts %xx sequences in stored URL text and compares with an analyst-supplied threshold using a bounded local decoder.

**Suspicious examples**

- A path or query with many encoded characters obscures its visible content.

**Legitimate/nonmatching context**

- Tracking and authentication links frequently use heavy encoding.

**Parameters**

- `minimum_sequences` (integer) — Minimum percent-encoded sequences; default `8`, minimum `1`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### URL contains a large Base64-like encoded value

- **Factor ID:** `url_base64_like`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Checks URL path/query/fragment values for long Base64 or URL-safe Base64 patterns; decoding is local, bounded, and never executed.

**Suspicious examples**

- A long encoded query value conceals recipient or destination data.

**Legitimate/nonmatching context**

- Authentication and tracking links often contain long tokens.

**Parameters**

- `minimum_length` (integer) — Minimum encoded-value length; default `40`, minimum `8`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### URL contains a recipient email address

- **Factor ID:** `url_contains_recipient_email`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing, recipient data
- **Evaluator status:** Operational

Checks literal and locally decoded URL text for a complete recorded recipient email address.

**Suspicious examples**

- Credential link includes employee%40company.com as a parameter.

**Legitimate/nonmatching context**

- Unsubscribe and account-management links often contain recipient identifiers.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### URL destination domain differs from sender domain

- **Factor ID:** `url_domain_differs_sender`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Compares every stored destination registrable domain with the sender domain. No URLs are omitted.

**Suspicious examples**

- A purported vendor links to unrelated credential infrastructure.

**Legitimate/nonmatching context**

- Organizations routinely link to Microsoft, Google, payment processors, and other third parties.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

### Campaign Signatures

#### Payment-change or urgency language is present

- **Factor ID:** `payment_urgency_keywords`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored subject/body text
- **Evaluator status:** Operational

Searches the stored subject and body text for a configurable case-insensitive phrase list and optional IBAN, routing-number, and account-number patterns.

**Suspicious examples**

- updated bank details
- urgent wire
- gift cards
- IBAN DE89...

**Legitimate/nonmatching context**

- Finance teams and vendors routinely discuss payments, banking, and deadlines.

**Parameters**

- `keywords` (multiline) — Keywords or phrases; default `updated bank details
change bank details
wire
urgent
gift card
iban
routing number
account number`
- `include_financial_patterns` (boolean) — Include IBAN/routing/account-number patterns; default `True`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `risk_when_yes` |
| Internal | On | 20 | `risk_when_yes` |
| General | On | 15 | `risk_when_yes` |

#### Exact number of URLs in message

- **Factor ID:** `exact_url_count`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** URL indexing
- **Evaluator status:** Operational

Matches the exact complete URL count recorded by Threadsaw. No URL types or duplicates are omitted from the stored count.

**Suspicious examples**

- Known campaign samples consistently contain exactly 2 URLs.

**Legitimate/nonmatching context**

- This is a campaign signature, not a universal risk signal.

**Parameters**

- `expected_count` (integer) — Expected URL count; default `0`, minimum `0`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### Exact number of attachments in message

- **Factor ID:** `exact_attachment_count`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Matches the exact complete attachment count stored by Threadsaw. No attachment types are omitted.

**Suspicious examples**

- Known samples consistently contain exactly one attachment.

**Legitimate/nonmatching context**

- This is a campaign signature rather than an inherent risk indicator.

**Parameters**

- `expected_count` (integer) — Expected attachment count; default `0`, minimum `0`

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

### Attachment Characteristics

#### Attachment type matches a configured value

- **Factor ID:** `attachment_type_match`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Matches either a stored filename extension or stored detected type using a case-insensitive exact comparison.

**Suspicious examples**

- Known campaign consistently delivers HTML attachments.

**Legitimate/nonmatching context**

- The same type may be routine in another environment.

**Parameters**

- `match_field` (choice) — Match field; default `Filename extension`, choices: `Filename extension`, `Detected file type`
- `match_value` (text) — Value

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | Off | 0 | `risk_when_yes` |
| Internal | Off | 0 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### Attachment type is newly observed for that sender

- **Factor ID:** `attachment_type_new_sender`
- **Load:** Heavy
- **Case history:** Required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Compares current attachment types with earlier messages from the same sender using existing metadata only.

**Suspicious examples**

- A sender that historically sends PDF/XLSX suddenly sends HTML.

**Legitimate/nonmatching context**

- Legitimate senders begin using new file formats.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Attachment is an archive

- **Factor ID:** `attachment_archive`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks stored attachment filename extensions and declared MIME types for common archive formats. It does not open, extract, or inspect archive contents during scoring.

**Suspicious examples**

- A campaign consistently delivers ZIP, 7Z, RAR, TAR, GZ, BZ2, XZ, CAB, or similar archives.

**Legitimate/nonmatching context**

- Archives are commonly used for legitimate file transfer and software distribution.

**False-positive note:** This factor identifies archive packaging only; it does not determine whether the archive is encrypted, malicious, or safe.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 10 | `risk_when_yes` |
| Internal | On | 10 | `risk_when_yes` |
| General | On | 10 | `risk_when_yes` |

#### Attachment is an encrypted or password-protected ZIP-family archive

- **Factor ID:** `attachment_encrypted_zip`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** stored ZIP-family attachment bytes, bounded archive inventory
- **Evaluator status:** Operational

Uses bounded ZIP central-directory metadata to identify archive members whose encryption flag is set. Threadsaw never extracts or decrypts the archive and does not attempt a password.

**Suspicious examples**

- A ZIP attachment contains one or more encrypted members and the message supplies a password or asks the recipient to open it.

**Legitimate/nonmatching context**

- Organizations may legitimately use password-protected ZIP files to transfer sensitive material.

**False-positive note:** The ZIP encryption flag strongly suggests protected content but does not establish maliciousness or prove which password mechanism was used.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 25 | `risk_when_yes` |
| Internal | On | 20 | `risk_when_yes` |
| General | On | 25 | `risk_when_yes` |

#### Message contains an attached email message

- **Factor ID:** `attached_email`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** attachment metadata
- **Evaluator status:** Operational

Checks stored MIME type/extension metadata for EML, MSG, or message/rfc822 without recursively parsing it during scoring.

**Suspicious examples**

- An attached message conceals or reproduces campaign content.

**Legitimate/nonmatching context**

- Forwarding and abuse reporting commonly attach original emails.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

### Recipient and Message Direction

#### Sender and recipient share the same domain

- **Factor ID:** `sender_recipient_same_domain`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** recipient data
- **Evaluator status:** Operational

Checks whether the sender registrable domain matches at least one To, CC, or preserved BCC recipient domain.

**Suspicious examples**

- Can be weighted upward during an internal-account-compromise hunt.

**Legitimate/nonmatching context**

- Can be weighted downward during an external-phishing hunt, but internal spoofing/compromise remains possible.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 15 | `trust_when_yes` |
| Internal | On | 25 | `risk_when_yes` |
| General | Off | 0 | `risk_when_yes` |

#### Sender address mimics a recipient local part on another domain

- **Factor ID:** `sender_mimics_recipient_localpart`
- **Load:** Moderate
- **Case history:** Not required
- **Prerequisites:** recipient data
- **Evaluator status:** Operational

Checks whether sender and recipient share the same mailbox name before @ while their registrable domains differ.

**Suspicious examples**

- From janesmith@external.test to janesmith@company.com

**Legitimate/nonmatching context**

- Generic local parts such as info, billing, or support can legitimately recur across organizations.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 20 | `risk_when_yes` |
| Internal | On | 15 | `risk_when_yes` |
| General | On | 20 | `risk_when_yes` |

#### Message contains no visible recipient address

- **Factor ID:** `no_visible_recipient`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** recipient data
- **Evaluator status:** Operational

Checks whether no usable To or CC address is present. It does not infer BCC use.

**Suspicious examples**

- Bulk campaign hides all visible recipients.

**Legitimate/nonmatching context**

- Mailing lists and privacy-preserving notifications often omit visible recipients.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |

#### Message contains recipients only in BCC

- **Factor ID:** `bcc_only_recipients`
- **Load:** Light
- **Case history:** Not required
- **Prerequisites:** preserved BCC data
- **Evaluator status:** Operational

Requires affirmative preserved BCC recipients plus no usable To or CC recipients. Missing BCC data returns UNKNOWN.

**Suspicious examples**

- Concealed-recipient campaign sent only through BCC.

**Legitimate/nonmatching context**

- Newsletters and privacy-sensitive communications can use BCC.

**Parameters**

None.

**Starter preset settings**

| Preset | Enabled | Weight | Effect mode |
|---|---:|---:|---|
| External | On | 5 | `risk_when_yes` |
| Internal | On | 5 | `risk_when_yes` |
| General | On | 5 | `risk_when_yes` |
