# Cross-Site Scripting (XSS) Hands-on Lab

## Cross-Site Scripting (XSS) Labs Walkthrough — Hacktify Cybersecurity (HCS) Internship

Cross‑Site Scripting (XSS) remains one of the most pervasive and dangerous vulnerabilities affecting modern web applications. In this article, I share my experiences from Week 1 of my penetration testing internship, where I explored multiple XSS attack vectors in controlled lab environments. You’ll learn what XSS is, the different types attackers use, and get a detailed walkthrough of various XSS labs — including the code, technical insights, and best practices to defend against these attacks.

🔗 Documentation:
[**GitHub**](https://github.com/reyincyber/Hacktify-CS); [**Medium**](https://cyberrey.medium.com/cross-site-scripting-xss-hands-on-lab-9f07bb8c8de2); [**Youtube**]()

## Table of Contents
- [Cross-Site Scripting (XSS) Labs Walkthrough](#cross-site-scripting-xss-labs-walkthrough)
- [What is Cross-Site Scripting (XSS)?](#what-is-cross-site-scripting-xss)
- [Types of Cross-Site Scripting (XSS)](#types-of-cross-site-scripting-xss)
- [Cross-Site Scripting (XSS) Labs Walkthrough](#cross-site-scripting-xss-labs-walkthrough)
  - [Sub-Lab 1: Let's Do IT!](#sub-lab-1-lets-do-it)
  - [Sub-Lab 2: Balancing is Important in Life!](#sub-lab-2-balancing-is-important-in-life)
  - [Sub-Lab 3: XSS is Everywhere!](#sub-lab-3-xss-is-everywhere)
  - [Sub-Lab 4: Alternatives are Must!](#sub-lab-4-alternatives-are-must)
  - [Sub-Lab 5: Developer Hates Scripts!](#sub-lab-5-developer-hates-scripts)
  - [Sub-Lab 6: Change the Variation!](#sub-lab-6-change-the-variation)
  - [Sub-Lab 7: Encoding is the Key?](#sub-lab-7-encoding-is-the-key)
  - [Sub-Lab 8: XSS with File Upload (File Name)](#sub-lab-8-xss-with-file-upload-file-name)
  - [Sub-Lab 9: XSS with File Upload (File Content)](#sub-lab-9-xss-with-file-upload-file-content)
  - [Sub-Lab 10: Stored Everywhere!](#sub-lab-10-stored-everywhere)
  - [Sub-Lab 11: DOM’s are Love!](#sub-lab-11-doms-are-love)
- [Best Practices for Mitigating XSS](#best-practices-for-mitigating-xss)
- [References](#references)
- [License](#license)
- [What’s Next](#whats-next)

---
## What is Cross-Site Scripting (XSS)?
XSS is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. When a web application fails to properly validate or encode user input, it becomes possible for an attacker to insert HTML or JavaScript that runs in the browser. This can lead to theft of session cookies, redirection to malicious sites, or even full account takeover.

Recent studies show that XSS vulnerabilities account for a significant percentage of web security issues reported in bug bounty programs. Many high-profile breaches have exploited XSS to compromise user data, emphasizing the urgent need for developers to implement robust sanitization and encoding practices. In 2024, Cross-Site Scripting (XSS) was identified as the most dangerous software weakness, topping the CWE Top 25 list with a score of 56.92.

## Types of Cross-Site Scripting (XSS)
- **Reflected XSS:** Occurs when malicious scripts are reflected off a web application onto a user’s browser. This typically happens through URL parameters or form submissions.
- **Stored XSS:** Involves injecting malicious scripts that are stored on the server and served to users, affecting anyone who accesses the compromised content.
- **DOM-Based XSS:** Arises when client-side scripts manipulate the DOM without proper validation, leading to script execution in the user’s browser.

---
## Cross-Site Scripting (XSS) Labs Walkthrough
In Week 1, I conducted a series of XSS labs designed to test different injection points and payloads. Below, I outline the lab goals, the tools used, and then provide a technical overview of each sub‑lab along with detailed code examples and best practices.

#### Sub-Lab Goals:
- Find an entry point on the web page (often testing multiple points as needed).
- Use an XSS payload (referencing documented payloads, with `<script>` tags for bonus points — except where an `<img>` is recommended).
- Verify that a popup or similar indicator appears on the screen, confirming successful injection.

#### Tools Used:
- Manual testing using browser developer tools (Inspect Element)
- Interception and modification of requests with Burp Suite or OWASP ZAP.
- Text editors for crafting and modifying payload code.

### Sub-Lab 1: Let's Do IT!
By analyzing the form’s input handling and testing with a simple script injection, it was observed that the application executed the injected script, indicating an XSS vulnerability. The form accepts user input through the email field and submits it to lab_1.php using the GET method. If lab_1.php processes this input without proper validation or sanitization, it becomes vulnerable to XSS attacks.
```html
<script>alert('XSS')</script>
```

### Sub-Lab 2: Balancing is Important in Life!
I entered the payload in the email subscription field ``` <script>alert('Hacked')</script> ``` but the response displayed: ``` "You'll receive email on <script>alert('Hacked')</script> ``` . The script tags were not executed, indicating partial sanitization. 
I then inputted the second payload 
```
">Hacked!<script>alert('Hacked')</script> 
```
The application executed the script, displaying an alert with the message "Hacked". This suggests that the application fails to properly handle input containing both quotation marks and script tags, leading to successful script execution.

### Sub-Lab 3: XSS is Everywhere!
During testing, I entered a standard string (test) in the email input field and submitted the form. The application responded with “Please Enter Valid Email address,” indicating some level of input validation. I then entered a string containing a script tag in the email input field and submitted the form.
```html
<script>alert('Hacked!')</script>@test.com
```
The script executed, displaying an alert with the message “Hacked!”. This demonstrated that the application does not adequately sanitize input containing script tags, leading to the execution of injected scripts.

### Sub-Lab 4: Alternatives are Must!
The application allows arbitrary JavaScript execution i.e it does not validate or sanitize user input in the email field before displaying it back on the webpage.
1. I tested normal string (test) → Accepted without validation, showing lack of input filtering.
2. I then tested ``` <script>alert('Hacked!')</script>@test.com ``` which displayed as raw text, showing partial sanitization.
3. This prompted me to use the following payload:
```
"><script>prompt(1)</script>@test.com
```
A prompt box appeared, proving JavaScript execution. This allows attackers to inject malicious JavaScript payloads, leading to Reflected XSS attacks.

### Sub-Lab 5: Developer Hates Scripts!
Goal: Identify an entry point and use a payload with an ``` <img> ``` tag for bonus points.

Instead of using a straightforward <script> tag, I exploited an image tag vulnerability. The onerror attribute executed the JavaScript when the image failed to load, triggering the alert.
```
">hello<IMG SRC=javascript:alert(1)>@test.com"
```
```
<img src=x onerror="alert('XSS: Developer Hates Scripts!')">
```

### Sub-Lab 6: Change the Variation!
Initially, the first payload did not trigger a popup, indicating that the application might be filtering or sanitizing certain inputs. However, by using the second payload, a popup was successfully triggered.
```html
<script>alert(document.cookie)</script>
```
```html
"><img src="x" onerror="alert('XSS')">
```

### Sub-Lab 7: Encoding is the Key?
I submitted the encoded payload via URL Encoding ([URL Encode Tool](https://www.url-encode-decode.com/), or BurpSuite Decoder). 

The ``` "><script>alert('XSS: Encoded!')</script> ``` becomes 
``` 
%22%3E%3Cscript%3Ealert%28%27XSS%3A+Encoded%21%27%29%3C%2Fscript%3E
```

while ``` ">hello<IMG SRC=javascript:alert(1)>@test.com" ``` becomes 
``` 
%22%3Ehello%3CIMG+SRC%3Djavascript%3Aalert%281%29%3E%40test.com%22
```

The browser's decoding led to execution of the script, verifying that encoding does not prevent XSS without proper sanitization.

### Sub-Lab 8: XSS with File Upload (File Name)
Goal: Identify an entry point on the file upload page and use a payload with an ```<img> `` tag.
By renaming an uploaded file with the payload, the unsanitized file name was displayed on the page, triggering the alert.
```
<img src=x onerror="alert('XSS: File Name Exploit')">
```

### Sub-Lab 9: XSS with File Upload (File Content)
After uploading a file with the crafted payload in its content, the server’s reflection of the file content executed the script, confirming the vulnerability.
```html
<script>alert(document.domain + ' XSS: File Content')</script>
```

### Sub-Lab 10: Stored Everywhere!
I registered and logged in with the following payloads as credentials:

First Name: ``` <script>alert('Firstname Stored')</script> ```

Lastname: ``` <img src=x onerror="alert('LName Stored TOO!')"> ```

Email: ``` ">hello<IMG SRC=javascript:alert(emailfieldnotsafetoo)>@test.com" ```

Password:  ```12345```

These were successfully stored on the server.

### Sub-Lab 11: DOM’s are Love!
**Goal**: Find three entry points on the page, use three XSS payloads as specified, and confirm execution via popups.

In this lab, the provided dom.js script contains several potential vulnerabilities due to improper handling of user inputs. Similarly, by manipulating the redir and coin parameters, an attacker can execute arbitrary scripts due to the improper handling of these parameters in the dom.js script.

```
https://..../lab_11.php

https://..../lab_11.php?coin=btc

https://..../lab_11.php?coin=eth

https://..../lab_11.php?coin=doge

https://..../lab_11.php?<img src =x onerror=confirm("COINS_HACKED!")>
```

The analysis confirms that the web application is vulnerable to DOM-based XSS attacks through multiple entry points. DOM-based Cross-Site Scripting (DOM XSS) occurs when client-side scripts of a web application process user input without proper validation or encoding, leading to the execution
of malicious scripts. By addressing these vulnerabilities through proper input validation, sanitization, and avoiding unsafe JavaScript functions, the application can mitigate the risk of DOM-based XSS attacks.

---
## Best Practices for Mitigating XSS:
To protect web applications against these vulnerabilities, consider the following measures along with example code:

### Input Validation and Sanitization:
Ensure that user inputs are validated and sanitized on both client and server sides.
```php
$clean_input = htmlspecialchars($_POST['input'], ENT_QUOTES, 'UTF-8');
```
### Output Encoding:
Always encode outputs before rendering them in the browser.
```php
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');
```
### Content Security Policy (CSP):
Implement a strict CSP header to limit the sources from which scripts can be executed.
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```
### Use Security Libraries:
Leverage established libraries or frameworks that automatically handle input sanitization and encoding.

---
## References:
- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/attacks/xss/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---
## License:
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
## Whats Next
In the First article, I dived into HTML Injection. In my upcoming article, I will delve into more advanced topics, such as SQL Injection and Insecure Direct Object References (IDOR). Stay tuned for more in-depth analyses and real-world remediation techniques.

Have you found similar vulnerabilities on your projects? Share your experiences or ask questions in the comments below.

If you’re passionate about penetration testing, ethical hacking, or cloud security, feel free to connect with me on LinkedIn or check out my GitHub repos for security-focused projects! 🚀 Let’s connect and discuss how we can make web applications safer, one vulnerability at a time.

