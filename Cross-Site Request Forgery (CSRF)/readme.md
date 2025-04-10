# Cross-Site Request Forgery (CSRF) Hands-on Lab  

## Cross-Site Request Forgery (CSRF) Labs Walkthrough — Hacktify Cybersecurity (HCS) Internship  

Imagine logging into your online banking account to check your balance. Unbeknownst to you, merely visiting a seemingly innocent website in another tab initiates a hidden transaction, transferring funds from your account to an attacker’s. You didn’t authorize this transfer, yet it occurred right under your nose. This alarming scenario exemplifies the dangers of Cross-Site Request Forgery (CSRF), a deceptive cyber-attack that exploits the trust between a user and a web application.  

---

## Table of Contents  

- [What is Cross-Site Request Forgery (CSRF)](#what-is-cross-site-request-forgery-csrf)  
- [Exploiting Trust in Authenticated Sessions](#exploiting-trust-in-authenticated-sessions)  
- [Most Recent CSRF Attacks in the Real-World](#most-recent-csrf-attacks-in-the-real-world)  
- [Cross-Site Request Forgery (CSRF) Labs Walkthrough](#cross-site-request-forgery-csrf-labs-walkthrough)  
  - [Sub Lab 1: Eassyy CSRF](#sub-lab-1-eassyy-csrf)  
  - [Sub Lab 2: Always Validate Tokens](#sub-lab-2-always-validate-tokens)  
  - [Sub Lab 3: I hate when someone uses my tokens!](#sub-lab-3-i-hate-when-someone-uses-my-tokens)  
  - [Sub Lab 4: GET Me or POST ME](#sub-lab-4-get-me-or-post-me)  
  - [Sub Lab 5: XSS the saviour](#sub-lab-5-xss-the-saviour)  
  - [Sub Lab 6: rm -rf token](#sub-lab-6-rm-rf-token)  
- [Mitigation Techniques & Best Practices](#mitigation-techniques--best-practices)  
- [What’s Next?](#whats-next)  
- [License](#license)  

---

## What is Cross-Site Request Forgery (CSRF)  

Cross-Site Request Forgery (CSRF) is a malicious exploit where an attacker tricks an authenticated user into performing unintended actions on a web application without their consent. By leveraging the user’s authenticated session, the attacker can execute unauthorized commands, potentially leading to severe consequences such as data theft, unauthorized fund transfers, or changes to account settings. The criticality of CSRF lies in its ability to undermine user trust and compromise the integrity of web applications, making it a significant concern in web security.  

🔗 **Documentation:**  
- [GitHub](https://github.com/reyincyber/Hacktify-CS)  
- [Medium](https://cyberrey.medium.com/cross-site-request-forgery-csrf-hands-on-lab-34346497f6bf)  
- [YouTube](https://youtu.be/P6YhvQkkSpY)  

---

## Exploiting Trust in Authenticated Sessions  

Web applications often rely on session cookies to identify and authenticate users. Once logged in, these cookies are automatically included in subsequent requests, maintaining the user’s authenticated state. CSRF exploits this mechanism by crafting malicious requests that, when executed by the victim’s browser, include these session cookies. Consequently, the web application processes these requests as legitimate actions initiated by the user, leading to unauthorized operations without the user’s knowledge.  

CSRF attacks can be categorized into several classes:  

- **Login CSRF**: This variant forces a user to authenticate as the attacker, potentially allowing the attacker to access sensitive information or perform actions under the victim’s identity. It’s particularly insidious as it can go unnoticed by the victim, who remains unaware that they are logged into a malicious session.
- **Stored CSRF (Persistent CSRF):** In this scenario, the malicious payload is stored on the target server, such as within a forum post or comment. When other users view the infected page, their browsers execute the unintended actions. This amplifies the attack’s reach, as multiple users can be affected over time.
- **Reflected CSRF (Non-Persistent CSRF):** Here, the malicious request is embedded in links or forms and requires the victim to interact with them, often through phishing emails or deceptive websites. The attack is executed immediately upon the victim’s interaction, without being stored on the server. 

#### Most Recent CSRF Attacks in the Real-World  
**CVE-2024–56005 — Posti Shipping Plugin Vulnerability:** In December 2024, a CSRF vulnerability, identified as CVE-2024–56005, was discovered in the Posti Shipping plugin for WordPress. This flaw allowed attackers to execute unauthorized actions on behalf of authenticated users, posing risks such as unauthorized data modifications and potential financial losses. The vulnerability affected versions up to 3.10.3, highlighting the necessity for timely updates and vigilant security practices among users and administrators.

**CVE-2024–47914 — VaeMendis Application Vulnerability:** Reported in November 2024, CVE-2024–47914 exposed a CSRF vulnerability within the VaeMendis application. By exploiting this flaw, attackers could trick authenticated users into executing unintended actions, jeopardizing data integrity and user trust. The vulnerability underscored the importance of implementing robust CSRF defenses, such as anti-CSRF tokens and user authentication mechanisms, to mitigate such risks. 

---

## Cross-Site Request Forgery (CSRF) Labs Walkthrough  
In this section, I detail my hands-on experience with CSRF attack techniques across multiple labs, demonstrating how vulnerabilities were identified and exploited.

**Tools Used:** Web Browser Tools (Inspect and Source Code), Burp Suite Community Edition, CSRF PoC Generator​, Local Web Server (e.g., Python’s HTTP server)

### Sub Lab 1: Eassyy CSRF  
The application lacks proper CSRF protections on the password change functionality. This oversight allows an attacker to craft malicious requests that, when executed by an authenticated user, can change the user’s password without their consent.
- I accessed the web application at https://…/login.php and registered two accounts: one representing the victim and another as the attacker. I then logged into the attacker’s account and accessed the password change functionality.
- I enabled “Intercept” in Burp Suite and captured the HTTP request corresponding to the password change action. I then copied the captured request for analysis.
- Next, I generated a CSRF PoC using the CSRF PoC Generator available at https://hacktify.in/csrf/.
- After which, I disabled “Intercept” after capturing the necessary data. Then I saved the generated CSRF PoC HTML to a local file and hosted it using a local web server.
- I Logged into the victim’s account and accessed the hosted CSRF PoC file via the local server. It was noted that the victim’s password was changed without their interaction, confirming the CSRF vulnerability. 

### Sub Lab 2: Always Validate Tokens  
The application implements a CSRF token mechanism; however, it fails to properly validate the authenticity of these tokens. By manipulating the token value, an attacker can forge requests that are accepted by the server, leading to unauthorized actions such as changing a user’s password without their consent.
- I accessed the web application at https://…/lab_2/login.php and registered two accounts: one representing the attacker and another as the victim.
- I then utilized Burp Suite where I enabled “Intercept” in Burp Suite.
- Next, I logged in as the victim and captured the login request, noting the CSRF token in the request parameters. This prompted me to log in as the attacker and intercepted the password change request.
- I then generated a CSRF PoC using the attacker’s request but substituted the attacker’s CSRF token with the victim’s token, altering a character to test token validation.
- I saved the crafted CSRF PoC HTML to a local file and hosted it using a local web server.
- I logged into the victim’s account again and accessed the hosted CSRF PoC file via the local server. It was noted that the victim’s password was changed without their interaction, indicating improper validation of CSRF tokens.  

### Sub Lab 3: I hate when someone uses my tokens!  
The application is vulnerable to Cross-Site Request Forgery (CSRF) due to improper validation of CSRF tokens. Specifically, the server accepts CSRF tokens from one user session to perform state-changing actions in another user’s session. This flaw allows an attacker to reuse a CSRF token from their own session to execute unauthorized actions on behalf of another user, leading to potential account compromise and unauthorized data modifications.
- I accessed the web application at https://…/lab_4/login.php and registered two accounts: one for the attacker and another for the victim.
- I then captured the Victim’s CSRF Token: Logged in as the victim and used Burp Suite to intercept and capture the CSRF token associated with the victim’s session.
- I logged in as the attacker and intercepted the password change request using Burp Suite. Sent this request to the Repeater tool within Burp Suite for further manipulation.
- I then crafted the CSRF PoC: Replaced the attacker’s CSRF token in the intercepted password change request with the victim’s CSRF token. Generated a CSRF PoC HTML file using this modified request.
- I then saved the crafted CSRF PoC HTML file and hosted it on a local web server.
- Lastly, I logged in as the victim and accessed the hosted CSRF PoC file via the local server. Observed that the victim’s password was changed without their consent, confirming the CSRF vulnerability. 

### Sub Lab 4: GET Me or POST ME  
Vulnerability Description The application is vulnerable to Cross-Site Request Forgery (CSRF) attacks, allowing unauthorized commands to be transmitted from a user that the web application trusts. Specifically, the password change functionality can be exploited by an attacker to change a victim’s password without their consent.
- Access the web application at https://labs.hacktify.in/HTML/csrf_lab/lab_6/login.php and logged in as the attacker.
- Navigate to the change password section.
- Enabled “Intercept” in Burp Suite and captured the password change request.
- Send the captured request to Burp Suite’s Repeater, observing parameters such as newPassword, newPassword2, and csrf.
- Disable “Intercept” in Burp Suite.
- Utilize the captured request details to generate a CSRF PoC using the POST method.
- Save the generated PoC to a local HTML file and hosted it using a local web server.
- Log into the victim’s account and accessed the hosted PoC file via the local server.
- Observe that the victim’s password was changed without their interaction, confirming the CSRF vulnerability.  

### Sub Lab 5: XSS the saviour  
The web application is vulnerable to Cross-Site Request Forgery (CSRF), allowing attackers to perform unauthorized actions on behalf of authenticated users. Specifically, the application fails to validate the origin of state-changing requests, making it susceptible to CSRF attacks.
- Access the web application at https://…/lab_7/login.php and logged in as the victim.​
- Navigate to the input name field within the application.​
- Enable “Intercept” in Burp Suite and captured the request when submitting the name change.​
- Insert the XSS payload <script>alert(document.cookie)</script> into the name parameter of the intercepted request.​
- Forward the modified request to the server.​
- Observe that the browser executed the script, displaying the session ID and CSRF token, confirming the vulnerability.  

### Sub Lab 6: rm -rf token  
The application is vulnerable to Cross-Site Request Forgery (CSRF) due to the absence of proper CSRF token validation. This flaw allows attackers to forge malicious requests that can perform unauthorized actions on behalf of authenticated users, such as changing passwords without the user’s consent.
- Access the web application at https://…/lab_8/login.php and created two accounts: one representing the victim and another as the attacker.​
- Log in as the attacker and navigated to the functionality that allows password changes.​
- Enable “Intercept” in Burp Suite and captured the password change request.​
- Send the captured request to Burp Suite’s Repeater and turned off the intercept to allow normal traffic flow.​
- Remove the CSRF token parameter from the request to test if the server validates its presence.​
- Generate a CSRF PoC using the modified request information.​
- Saved the CSRF PoC to a local HTML file and hosted it using a local web server.​
- Log in as the victim and accessed the hosted PoC file.​
- Observe the victim’s password was changed successfully without their interaction, indicating the application’s failure to validate CSRF tokens properly.
---

## Mitigation Techniques & Best Practices  
Cross-Site Request Forgery (CSRF) poses significant risks to web applications by enabling unauthorized actions on behalf of authenticated users. To effectively mitigate CSRF vulnerabilities, developers should implement a combination of strategies that enhance the security posture of their applications.
- Ensure that each form submission includes a unique, unpredictable token that the server validates before processing the request. This token should be securely generated and associated with the user’s session to prevent attackers from forging valid requests.
- Set the SameSite attribute for cookies to control their inclusion in cross-site requests. Configuring cookies with SameSite=Strict or SameSite=Lax directives helps prevent them from being sent along with cross-site requests, thereby reducing the risk of CSRF attacks.
- Require users to re-authenticate or provide additional verification, such as entering their current password, before performing sensitive actions like changing account settings or making financial transactions. This ensures that the user is intentionally initiating the action.
- Design the application to use HTTP methods appropriately:
    --> Use GET requests exclusively for data retrieval operations that do not cause side effects.
    --> Employ POST, PUT, PATCH, or DELETE methods for actions that modify data or state.
  This practice aligns with RESTful principles and helps prevent unintended actions through simple link clicks or page loads.
- Implement strict validation of the Origin and Referer headers to ensure that incoming requests originate from trusted sources. Be mindful that reliance on these headers may have limitations due to privacy settings or network configurations that can suppress them.
- Educate users about the dangers of phishing attacks and encourage them to avoid clicking on suspicious links or visiting untrusted websites while authenticated to sensitive applications. User awareness is a critical component of a comprehensive security strategy.
- Regularly update and patch all components of the web application, including frameworks and libraries, to protect against known vulnerabilities. Staying current with security updates reduces the risk of exploitation through outdated software.
- By integrating these mitigation techniques and best practices, developers can significantly reduce the risk of CSRF attacks and enhance the overall security of their web applications.  

---

## What’s Next?  

In my previous articles, I explored **HTML Injection, XSS, IDOR, and SQL Injection**. My next article will focus on **Cross-Origin Resource Sharing (CORS) vulnerabilities**, detailing real-world attacks and mitigation strategies.  

Have you encountered CSRF vulnerabilities in your projects? Share your experiences or questions in the comments below!  

If you’re passionate about **Cloud Security, Penetration Testing, and Ethical Hacking**, connect with me on [LinkedIn](#) or check out my [GitHub](https://github.com/reyincyber) for security-focused projects!  

---

## License  

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.  
