# Cross-Origin Resource Sharing (CORS) Hands-on Lab  

## Cross-Origin Resource Sharing (CORS) Labs Walkthrough — Hacktify Cybersecurity (HCS) Internship  

Imagine you’re at a bustling café, connecting to the public Wi-Fi to check your bank account. Unbeknownst to you, a malicious script running on an innocuous-looking website you’ve just visited is silently attempting to access your banking information. This scenario underscores the potential dangers of Cross-Origin Resource Sharing (CORS) misconfigurations — a subtle yet critical vulnerability in web security that can expose sensitive data to unauthorized parties.  

🔗 **Documentation:** [**GitHub**](https://github.com/reyincyber/Hacktify-CS); [**Medium**](https://cyberrey.medium.com/cross-site-request-forgery-csrf-hands-on-lab-34346497f6bf); [**YouTube**]()  

---

## Table of Contents  

- [What is Cross-Origin Resource Sharing (CORS)](#what-is-cross-origin-resource-sharing-cors)  
- [Common Types of CORS Misconfigurations](#common-types-of-cors-misconfigurations)  
- [Recent CORS Attacks in the Real-World](#recent-cors-attacks-in-the-real-world)  
- [Cross-Origin Resource Sharing (CORS) Labs Walkthrough](#cross-origin-resource-sharing-cors-labs-walkthrough)  
  - [Sub Lab 1: CORS With Arbitrary Origin](#sub-lab-1-cors-with-arbitrary-origin)  
  - [Sub Lab 2: CORS with Null origin](#sub-lab-2-cors-with-null-origin)  
  - [Sub Lab 3: CORS with Prefix Match](#sub-lab-3-cors-with-prefix-match)  
  - [Sub Lab 4: CORS with Suffix Match](#sub-lab-4-cors-with-suffix-match)  
  - [Sub Lab 5: CORS with Escape Dot](#sub-lab-5-cors-with-escape-dot)  
  - [Sub Lab 6: CORS with Substring Match](#sub-lab-6-cors-with-substring-match)  
  - [Sub Lab 7: CORS with Arbitrary Subdomain](#sub-lab-7-cors-with-arbitrary-subdomain)  
- [Mitigation Techniques & Best Practices](#mitigation-techniques--best-practices)  
- [What’s Next?](#whats-next)  
- [License](#license)  

---

## What is Cross-Origin Resource Sharing (CORS)  

Cross-Origin Resource Sharing (CORS) is a security feature implemented by web browsers to regulate how resources on a web page can be requested from another domain.  

When a web application requires resources from a different origin, the browser initiates a CORS preflight request, typically using the HTTP OPTIONS method. This preflight request checks with the server to determine if the cross-origin request is allowed. If the server’s response includes the appropriate CORS headers, such as `Access-Control-Allow-Origin`, the browser proceeds with the actual request. Otherwise, the browser blocks the request, safeguarding the user from potential cross-site attacks.  

Misconfigurations in CORS can lead to significant security vulnerabilities, potentially exposing sensitive information. The severity of a CORS vulnerability depends on the specific context and the data exposed. For instance, if Personally Identifiable Information (PII) is leaked due to a CORS misconfiguration, the vulnerability could be classified as a P3 or P2 bug, with a Common Vulnerability Scoring System (CVSS) score ranging from 7 to 8.9, indicating a high severity level.

#### Common Types of CORS Misconfigurations  
- **Overly Permissive Policies:** Ssetting the Access-Control-Allow-Origin header to a wildcard (*) permits any domain to access the resources, which, when combined with Access-Control-Allow-Credentials: true, can lead to unauthorized access to sensitive user data. Such misconfigurations exploit the trust established in authenticated sessions, allowing malicious actors to perform unauthorized actions on behalf of authenticated users.
- **Improper Origin Validation**: Dynamically reflecting the Origin header without proper validation can lead to unauthorized domains gaining access.
- **Trusting Null Origins**: Misinterpreting the null origin as a safe default can be dangerous, as certain contexts, like sandboxed iframes or file-based origins, may inadvertently match this policy.

#### Recent CORS Attacks in the Real-World  
In recent years, several significant CORS-related vulnerabilities have been identified, highlighting the critical need for proper configuration:
- **CVE-2025–1083: Mindskip xzs-mysql 3.9.0 Vulnerability (February 2025):** This vulnerability involved an overly permissive CORS policy that allowed untrusted domains to access sensitive functionalities. Exploiting this flaw required a high level of complexity, but the potential impact underscored the importance of stringent CORS configurations.
- **CVE-2025–24010: Vite JavaScript Framework Vulnerability (January 2025):** The Vite development server’s default CORS settings and inadequate validation of the ‘Origin’ header on WebSocket connections allowed arbitrary websites to send requests and read responses. This flaw exposed sensitive information and highlighted the necessity for robust CORS policies in development tools.
These incidents serve as a stark reminder of the vulnerabilities that can arise from misconfigured CORS policies. Ensuring that CORS settings are meticulously defined and regularly reviewed is paramount in safeguarding web applications against unauthorized cross-origin access.
---

## Cross-Origin Resource Sharing (CORS) Labs Walkthrough  

In this section, I detail my hands-on experience with CORS attack techniques across multiple labs, demonstrating how vulnerabilities were identified and exploited.

**Tools Used:** Web Browser Tools (Inspect and Source Code), Burp Suite, cURL.

### Sub Lab 1: CORS With Arbitrary Origin  
The application accepts and processes requests from any origin without proper validation. This misconfiguration allows attackers to craft malicious websites that can interact with the vulnerable application on behalf of authenticated users, potentially leading to unauthorized data access or actions.​

1. Access the web application at https://…/lab_1/login.php and logged in using the provided credentials.​
2. Launch Burp Suite and enabled the intercept feature.​
3. Perform an action within the application to capture a request.​
4. In the intercepted request, added the Origin header with the value https://attacker.com.​
5. Forward the modified request to the server () and observed the response.​
Note that the server included the header Access-Control-Allow-Origin: https://attacker.com in its response, indicating that it trusts the specified origin.​
6. Utilize cURL to replicate the request:​
```sh
curl -i -H "Origin: https://attacker.com" \
-H "Cookie: PHPSESSID=<session_id>" \
-X GET https://labs.hacktify.in/HTML/cors_lab/lab_1/cors_1.php
```
7. Confirm that the response contained sensitive user data, demonstrating that the server processes requests from arbitrary origins.

### **Sub Lab 2. CORS with Null origin**  
The application improperly trusts requests with a null origin, allowing unauthorized cross-origin interactions. This misconfiguration enables attackers to craft malicious websites that can interact with the vulnerable application on behalf of authenticated users, potentially leading to unauthorized data access or actions.​
1. I access the web application at https://…/lab_2/login.php and log in using the provided credentials.​
2. I launch Burp Suite and enable the intercept feature.​
3. I perform an action within the application to capture a request.​
4. In the intercepted request, I add the Origin header with the value https://attacker.com.​
5. I forward the modified request to the server and observe the response.​
6. I note that the server includes the header Access-Control-Allow-Origin: null in its response, indicating that it trusts the null origin.​
7. I utilized cURL to replicate the request:​  
```bash
curl -i -H "Origin: null" -H "Cookie: PHPSESSID=<session_id>" -X GET https://labs.hacktify.in/HTML/cors_lab/lab_2/cors_2.php
```
8. I confirmed that the response contains sensitive user data, demonstrating that the server processes requests with a null origin

### **Sub Lab 3. CORS with Prefix Match**  
The application accepts and trusts any origin that has a prefix matching its own domain. For example, it considers hacktify.in.attacker.com as a trusted origin because it starts with hacktify.in. This misconfiguration allows attackers to craft malicious subdomains that can interact with the application’s resources, potentially leading to unauthorized data access or actions on behalf of authenticated users.
1. I navigated to the web application’s login page and authenticated using the provided credentials.
2. I enabled the intercept feature in Burp Suite and captured a request to the application.
3. I modified the Origin header to hacktify.in.attacker.com and forwarded the request.
4. I observed that the server responded successfully and included the Access-Control-Allow-Origin: hacktify.in.attacker.com header, indicating that it trusts origins with prefixes matching its domain.

### **Sub Lab 4. CORS with Suffix Match**  
The application is configured to trust any origin that ends with a specific suffix, such as “hacktify.in”. This misconfiguration allows an attacker to exploit the CORS policy by using a malicious domain that ends with the trusted suffix (e.g., “evilhacktify.in”). Consequently, unauthorized websites can interact with the application’s resources, leading to potential data breaches or unauthorized actions on behalf of authenticated users.
1. I navigated to the web application’s login page at https://…/lab_4/login.php and authenticated using the provided credentials.
2. I enabled the intercept feature in Burp Suite and captured a request to the application.
3. I added the Origin header with the value evilhacktify.in to the request.
4. I forwarded the modified request to the repeater and turned off the interceptor.
5. I observed that the server responded successfully, indicating that it accepted the request from the evilhacktify.in domain. This demonstrated that the server’s CORS policy trusts origins with the specified suffix, regardless of the preceding domain.


### **Sub Lab 5. CORS with Escape Dot**  
The application is vulnerable due to improper handling of the ‘Origin’ header in CORS requests. Specifically, the server fails to correctly validate the ‘Origin’ header when dots have not properly escaped in its regular expression pattern. This misconfiguration allows an attacker to craft malicious domains that can bypass the CORS policy, leading to unauthorized access to sensitive user data.​
1. I navigated to the web application at https://../lab_5/login.php and logged in using the provided credentials.​
2. I launched Burp Suite and enabled the intercept feature to capture HTTP requests.​
3. Upon capturing the login request, I sent it to the Repeater module within Burp Suite for further analysis.​
4. In the Repeater, I added the ‘Origin’ header with the value ‘wwwhacktify.in’ to simulate a request from a subdomain that exploits the dot misconfiguration.​
5. I forwarded the modified request and observed the server’s response.​
6. The server responded successfully, including the ‘Access-Control-Allow-Origin’ header set to ‘wwwhacktify.in’, indicating that the server incorrectly trusts the crafted origin

### **Sub Lab 6. CORS with Substring Match**  
The application is configured to allow cross-origin requests from domains that contain a specific substring, such as hacktify. This approach is insecure because it permits any domain with the substring (e.g., hacktify.co) to access resources, potentially exposing sensitive information to unauthorized parties.
1. I navigated to https://…/lab_6/login.php and logged in using the provided credentials.​
2. I launched Burp Suite and enabled the intercept feature to capture HTTP requests.​
3. Upon capturing the login request, I added the Origin header with the value hacktify.co.​
4. I forwarded the modified request to the server and observed the response.​
5. The server responded successfully, indicating that it accepted the cross-origin request from hacktify.co.

### **Sub Lab 7. CORS with Arbitrary Subdomain**  
The application is configured to trust arbitrary subdomains, allowing any subdomain under hacktify.in to access resources. This misconfiguration permits an attacker-controlled subdomain to interact with the application as a trusted origin, potentially leading to unauthorized access to sensitive data.​
1. I accessed the web application at https://…/lab_7/login.php and logged in using the provided credentials.​
2. I enabled the intercept feature in Burp Suite and captured the login request.​
3. I added the ‘Origin’ header with the value somesubdomain.hacktify.in to the request.​
4. I forwarded the modified request to the server and observed the response.​
5. The response included the ‘Access-Control-Allow-Origin’ header set to somesubdomain.hacktify.in, indicating that the server trusts this arbitrary subdomain.

---

## Mitigation Techniques & Best Practices  
Cross-Origin Resource Sharing (CORS) is a powerful mechanism that, when misconfigured, can expose web applications to significant security vulnerabilities. To mitigate these risks and ensure robust web security, consider the following best practices:
1. **Implement strict validation of the Origin header** on the server side before reflecting it in responses to prevent unauthorized access.
— Avoid using wildcard characters (*) in the Access-Control-Allow-Origin header, especially when dealing with sensitive data, as this can inadvertently grant access to untrusted domains.
— Specify explicit origins in the Access-Control-Allow-Origin header to ensure that only trusted domains can access your resources.

2. **Restrict the HTTP methods and headers** allowed in cross-origin requests by appropriately configuring the Access-Control-Allow-Methods and Access-Control-Allow-Headers headers to minimize the attack surface.
— Ensure that the Access-Control-Allow-Credentials header is set to true only when necessary, and never in conjunction with a wildcard origin, to prevent unauthorized access to user credentials.
— Utilize the Access-Control-Max-Age header to cache preflight responses for an appropriate duration, reducing latency and server load without compromising security.

3. **Properly handle preflight requests** by responding to OPTIONS requests with the necessary CORS headers, including only the required methods and headers, to ensure that legitimate cross-origin requests are recognized and processed correctly.

4. Include CORS headers in all server responses, including error messages, to prevent information leakage and ensure consistent application behavior.

5. Regularly audit and test your CORS configurations using tools like browser developer tools or security scanners to identify and rectify potential vulnerabilities promptly.

6. Educate your development team on the importance of secure CORS configurations and the potential risks associated with misconfigurations to foster a culture of security awareness.

By adhering to these best practices, you can effectively mitigate the risks associated with CORS misconfigurations and enhance the overall security posture of your web applications.  

---

## What’s Next?  

In my previous articles, I dived into HTML Injection, Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), SQL Injection, Cross-Site Request Forgery (CSRF). In the last Hacktify series article, I explored Hacktify Internship CTF Hands-on Lab, showcasing real-world attacks and effective mitigation techniques.

Have you encountered CORS vulnerabilities in your projects? Share your experiences or questions in the comments below!

If you’re passionate about Cloud Security, Penetration Testing and Ethical Hacking, connect with me on LinkedIn or check out my GitHub for security-focused projects! 

---

## License  
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  
