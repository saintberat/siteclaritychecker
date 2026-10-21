# 🌐 Site Clarity Checker

## Live Demo: [https://saintberat.github.io/siteclaritychecker/](https://saintberat.github.io/siteclaritychecker/)

A client-side web security scanner that inspects URLs in real time to detect phishing attempts, malicious scripts, brand impersonation, and social engineering risks.

It performs both structural URL analysis and optional deep source code inspection using CORS proxies, generating a weighted risk score (0–100) and an actionable breakdown of findings.

---

## 🔎 How It Works

### ⚙️ General Logic

When a user submits a URL:

1. **Normalization:** The URL protocol is validated and standardized (ensuring `https://` by default).
2. **Structural Analysis:** Immediate checks are run against the hostname, protocol, path, and query parameters.
3. **Deep Scan (Optional):** The target page's HTML source code is fetched via CORS proxies.
4. **Heuristic Scoring:** All findings are compiled and weighted into an overall risk score from 0 to 100.
5. **Report Presentation:** A detailed verdict with categorized check layers and findings is rendered.

---

## 🌐 Analysis Layers

### 🔐 Protocol Verification
- **HTTPS:** Secure, encrypted transport channel.
- **HTTP:** Flagged as a risk (data transmitted in cleartext).

---

### 🌍 Domain & DNS Inspection
- **Direct IP Access:** Direct IP addresses instead of domain names (classic indicator of phishing infrastructure).
- **Punycode / IDN Spoofing:** Detects `xn--` and Cyrillic/Greek homoglyphs used for visual deception.
- **Suspicious TLDs:** Flags high-abuse extensions (e.g., `.xyz`, `.top`, `.tk`, `.zip`).
- **Trusted Domain Allowlist:** Verified domains receive risk score reductions.

---

### 🧱 URL Structural Patterns
- **Deep Subdomains:** Excessive subdomain layering (often used to obscure the legitimate domain).
- **Abnormal Path Length:** Unusually lengthy paths indicative of redirect obfuscation or exploit payloads.

---

### 🏷️ Brand Impersonation (Phishing & Lookalikes)
- Monitored brand list (Google, Microsoft, PayPal, Amazon, Apple, Banking & Crypto services).
- **Homoglyph & visual character replacement mapping** (e.g., `0` ↔ `o`, `1` ↔ `l`, `rn` ↔ `m`, `vv` ↔ `w`).
- **Levenshtein Distance Analysis:** Identifies fuzzy typographical similarity to major brands.

---

### ⚠️ Social Engineering Keywords
Scans for high-risk phishing vocabulary in the URL path and parameters:
- `login`, `verify`, `secure`, `bank`, `account`, `update`
- `signin`, `confirm`, `bonus`, `wallet`, `suspend`, `password`

---

## 🧠 Strict Mode (Advanced Heuristics)

When enabled, enforces rigorous statistical checks to catch randomly generated malicious domains (DGAs):
- **Excessive Domain Length:** Domains longer than 24 characters.
- **Hyphen Density:** 3 or more hyphens in the hostname.
- **Digit Concentration:** 4 or more numeric digits.
- **Shannon Entropy Analysis:** Detects algorithmic randomness ($H > 3.8\text{ bits}$).

---

## 🧬 Source Code Analysis (Deep Scan)

Optionally retrieves and parses the target website's HTML DOM using multiple CORS proxy fallbacks.

### 🚨 Malicious Code Patterns
- Obfuscated `eval()` execution (`unescape`, `atob`, `String.fromCharCode`)
- Encoded `document.write` payloads
- Dynamic object property obfuscation
- Base64 payload decoding

### 🔁 Covert Redirects
- Automated JavaScript redirects via `window.location`
- HTML `<meta http-equiv="refresh">` tags

### 📡 External Script Ingestion
- Cross-origin script loading
- Excessive disparate script sources

### 🧾 Credential Harvesting & Forms
- Forms submitting sensitive inputs (`password`, `email`, `account`) to third-party domains.

### 🧨 Advanced Threat Signatures
- Browser cryptocurrency mining scripts (CoinHive, Minero, WebMR)
- Keystroke logging patterns (`onkeypress`, `onkeydown` listeners attached to document)

---

## 📊 Scoring Breakdown

| Risk Score | Verdict | Recommendation |
| :---: | :---: | :--- |
| **0 – 24** | 🟢 **Low Risk** | No prominent threat signals found. Proceed with normal caution. |
| **25 – 54** | 🟡 **Medium Risk** | Suspicious elements identified. Avoid entering sensitive credentials. |
| **55 – 100** | 🔴 **High Risk** | Multiple critical danger factors detected. Do not visit or interact. |

---

## 🌐 Bilingual Support

Site Clarity Checker features built-in **English** and **Turkish** interfaces with one-click toggling and saved preferences.

---

## 📄 License

MIT License. Contributions, suggestions, and issues are always welcome!

<!-- sync-activity: 2026-10-21T17:02:01Z (d5c2c05e) -->
