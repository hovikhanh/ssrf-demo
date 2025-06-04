# 🛡️ SSRF Vulnerability Demo

This project demonstrates the understanding, simulation, and exploitation of **Server-Side Request Forgery (SSRF)** vulnerabilities through multiple practical scenarios, conducted using **PortSwigger Web Security Academy** labs.

## 📚 Overview

**Server-Side Request Forgery (SSRF)** is a security vulnerability that allows attackers to make arbitrary requests from the server. It can be abused to:

- Access internal systems
- Steal sensitive metadata (e.g., AWS credentials)
- Perform port scanning
- Exploit blind injection scenarios

This demo is based on our final project for the course "Web Security and Application", UIT - University of Information Technology.

---

## 🎯 Objectives

- Understand the mechanism and risks of SSRF.
- Demonstrate multiple SSRF attack scenarios.
- Test evasion techniques (bypass blacklist, whitelist, URL encoding).
- Evaluate possible impact and propose mitigation methods.

---

## 🧪 Attack Scenarios

| Scenario | Description |
|----------|-------------|
| **1** | Accessing internal resources using `localhost` |
| **2** | Brute-force internal IPs via stockAPI parameter |
| **3** | Abuse of `Referer` header to trigger SSRF |
| **4** | Bypassing blacklist filters with alternative IPs (e.g., `127.1`, case-insensitive `localhost`) |
| **5** | Chaining SSRF with Open Redirect vulnerabilities |
| **6** | Bypassing whitelists using encoded characters (`@`, `%23`) |

Screenshots and payload examples are available in `/labs/`.

---

## 🛠 Tools & Technologies

- Burp Suite (Intercept & Repeater)
- PortSwigger Web Security Labs
- Firefox DevTools
- OAST (Burp Collaborator)
- Custom crafted HTTP requests

---

## 🔐 Mitigation Recommendations

- Validate and sanitize all user inputs strictly.
- Avoid directly using user-supplied URLs in server-side requests.
- Use DNS resolution filtering and IP whitelisting.
- Disable unused URL schemes (`dict://`, `file://`, `gopher://`, etc.).
- Enforce authentication on internal services.
- Use Web Application Firewalls (WAF) and network segmentation.

---

## 👨‍💻 Authors

This project was completed by a student group from UIT - VNUHCM:

- Hồ Vỉ Khánh – [22520633@gm.uit.edu.vn](mailto:22520633@gm.uit.edu.vn)
- Lê Công Danh – [22520199@gm.uit.edu.vn](mailto:22520199@gm.uit.edu.vn)
- Nguyễn Hữu Bình – [22520132@gm.uit.edu.vn](mailto:22520132@gm.uit.edu.vn)
- Phạm Trường Thiên Ân – [22520028@gm.uit.edu.vn](mailto:22520028@gm.uit.edu.vn)

---

## 📷 Demo
 
### Seminar Video: Exploiting CSRF & SSRF on PortSwigger Labs
🔗 [Watch Seminar Video on YouTube](https://youtu.be/1Ta60fm1g2w) \
[![](https://i9.ytimg.com/vi_webp/1Ta60fm1g2w/mq1.webp?sqp=CMyVgsIG-oaymwEmCMACELQB8quKqQMa8AEB-AH-CYAC0AWKAgwIABABGH8gEyg2MA8=&rs=AOn4CLCJ390Q5fJa94nxZLkV97fYM4qrHg)](https://youtu.be/1Ta60fm1g2w "Click to play on Youtube.com")
### Demo Final Project: SSRF Vulnerability Analysis on PortSwigger Labs
🔗 [Watch Demo Project on YouTube](https://youtu.be/PCGBZ5iwHzs) \
[![](https://i9.ytimg.com/vi/PCGBZ5iwHzs/mqdefault.jpg?v=677bfec1&sqp=CKCTgsIG&rs=AOn4CLB8dhAaRs6dRU888Z7yZnH0x7qk8w)](https://youtu.be/PCGBZ5iwHzs "Click to play on Youtube.com")

Link Youtube: https://www.youtube.com/playlist?list=PLgdGPOGIMaGsQ-7JW71rgyX9LEGp9Kjir

---

## 📎 References

- https://portswigger.net/web-security/ssrf  
- https://owasp.org/www-project-web-security-testing-guide/  
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery  
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html  
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery  

---

> ⚠️ This repository is for educational and ethical research purposes only. Do not attempt these attacks on systems you do not own or have explicit permission to test.
