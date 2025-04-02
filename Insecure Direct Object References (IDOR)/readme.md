# Insecure Direct Object References (IDOR) Hands-on Lab

## IDOR Labs Walkthrough — Hacktify Cybersecurity (HCS) Internship

Insecure Direct Object References (IDOR) continue to be one of the most critical access control vulnerabilities in modern web applications. This vulnerability allows attackers to manipulate object references in URLs, form fields, or API requests to access unauthorized data.

In this article, I share my hands-on experience from Week 2 of my Hacktify Cybersecurity (HCS) penetration testing internship, where I explored multiple IDOR attack vectors in controlled lab environments. You’ll learn what IDOR is, the different ways attackers exploit it, and a detailed walkthrough of various IDOR labs — complete with code, technical insights, and best practices for mitigation.

## Table of Contents

- [What is Insecure Direct Object References (IDOR)?](#what-is-insecure-direct-object-references-idor)
- [Hacktify IDOR Labs Walkthrough](#hacktify-idor-labs-walkthrough)
  - [Tools Used](#tools-used)
  - [1.1 Give me my amount!!](#11-give-me-my-amount)
  - [1.2 Stop polluting my params!](#12-stop-polluting-my-params)
  - [1.3 Someone changed my Password 🙀!](#13-someone-changed-my-password-)
  - [1.4 Change your methods!](#14-change-your-methods)
- [Mitigation Techniques & Best Practices](#mitigation-techniques--best-practices)
- [What’s Next?](#whats-next)
- [License](#license)

## What is Insecure Direct Object References (IDOR)?

The Open Web Application Security Project (OWASP) defines IDOR as a specific instance of insecure direct object references, where an application exposes a reference to an internal implementation object, such as a file, directory, or database key. Without appropriate access controls, attackers can manipulate these references to access unauthorized data. While IDOR was explicitly listed in earlier OWASP Top Ten lists, it is now considered a subset of the broader category of Broken Access Control, which remains a critical security risk.

IDOR occurs when an application provides direct access to objects — such as user profiles, transaction records, or files — based on user-supplied input without proper authorization checks. Attackers can exploit IDOR to:

- Access other users’ private data
- Modify sensitive information (e.g., balances, passwords, permissions)
- Perform horizontal and vertical privilege escalation

IDOR remains a top concern in API security and is frequently exploited in bug bounty programs.

In February 2025, a critical IDOR vulnerability was identified in Anapi Group’s h6web platform. Authenticated attackers could exploit the “pkrelated” parameter in the “/h6web/ha\_datos\_hermano.php” endpoint to access other users’ information. Moreover, this flaw allowed attackers to impersonate other users, executing requests with elevated privileges.

In December 2024, path traversal and IDOR vulnerabilities were found in the eSignaViewer component of eSigna products (versions 1.0 to 1.5). Unauthenticated attackers could manipulate file paths and object identifiers to access arbitrary files within the document system. These incidents highlight the critical need for robust access control mechanisms in web applications to prevent unauthorized data access and potential breaches.

## Hacktify IDOR Labs Walkthrough

In Week 2, I conducted a series of IDOR labs designed to test different access control weaknesses. Below, I outline the lab goals, the tools used, and provide a detailed breakdown of each attack scenario.

### Tools Used:

- **Burp Suite/OWASP ZAP** — Intercept and modify HTTP requests
- **Browser Developer Tools** — Inspect and manipulate web requests

### 1.1 Give me my amount!!

This lab demonstrates an IDOR vulnerability where transaction details are accessible and modifiable by manipulating the `id` parameter in the URL.

1. Registered and logged in with the credentials `test@test.com` and `test`.
2. Observed the URL format: `profile.php?id=11`.
3. Modified the `id` parameter in the URL (`profile.php?id=11` to `id=1`), accessing other users' profiles.
4. Modified the Transaction 1, Transaction 2, and Transaction 3 values for `benep81280@whwow.com` and saved the updates.
5. Revisited the altered profile and confirmed the changes persisted.

### 1.2 Stop polluting my params!

This lab focuses on accessing unauthorized user profiles by altering the `id` parameter in the URL.

1. Logged in with `test@test.com` and `test` credentials.
2. Modified the default `id` parameter in the URL (`profile.php?id=4` to `id=1` and `id=200`),the profile of [alice@gmail.com](mailto\:alice@gmail.com) and [qwerty@gmail.com](mailto\:qwerty@gmail.com) was accessed respectively.
3. Each User Profile displayed the Username, First Name, and Last Name values respectively.

### 1.3 Someone changed my Password 🙀!

This lab demonstrates how an attacker can reset another user’s password by manipulating the `username` parameter in a request.

1. Logged in without any credentials.
2. Observed an empty User Profile page with Username, Email, and Name fields.
3. Clicked on the "Change password" button.
4. Modified the URL (`https://...username=`) to `https:/...username=admin`.
5. Changed the admin password and confirmed the update.

### 1.4 Change your methods!

This lab highlights an IDOR vulnerability where direct access to user profiles is possible due to weak access controls.

1. Observed that the user profile page URL contained a parameter `id` referencing user-specific data.
2. Accessed the URL `https://...id=473` while authenticated.
3. Modified `id=473` to `id=2`, successfully accessing another user's profile.

## Mitigation Techniques & Best Practices

1. \*\*Implement Comprehensive Access Controls: \*\*Ensure that every request to access or modify data undergoes strict server-side authorization checks. This prevents unauthorized users from accessing or altering resources they shouldn’t have access to.

   Example: In the “Give me my amount!!” lab, unauthorized access to other users’ transaction details was possible by modifying the id parameter. Implementing server-side checks to verify that the authenticated user matches the resource owner would prevent such exploitation.

2. **Use Indirect Object References**: Replace direct references to internal objects (e.g., database IDs) with indirect references, such as cryptographically strong, random values like UUIDs or GUIDs. This approach obscures the actual identifiers, making it more challenging for attackers to guess or manipulate them.

   Example: In the “Stop polluting my params!” lab, sequential user IDs allowed attackers to access other profiles by simply incrementing the ID. Utilizing non-sequential, random identifiers would mitigate this risk.

3. **Enforce Session-Based Authentication**: Tie user actions to their authenticated sessions rather than relying on user-supplied parameters. This ensures that operations are performed only on resources associated with the authenticated user.

   Example: In the “Someone changed my Password 🙀!” lab, the password reset function relied on a username parameter, allowing attackers to reset passwords for other users. Requiring users to be authenticated and associating password changes with their session would prevent such attacks. 

4. **Validate and Sanitize User Inputs**: Implement strict input validation to ensure that user-supplied data conforms to expected formats and values. Reject or sanitize inputs that do not meet these criteria to prevent unauthorized access.

   Example: In the “Change your methods!” lab, altering the id parameter allowed access to other users' profiles. Validating that the id corresponds to resources the authenticated user is permitted to access would mitigate this vulnerability.

5. **Conduct Regular Security Testing**: Perform routine security assessments, including code reviews, automated testing, and penetration testing, to identify and remediate potential IDOR vulnerabilities. Utilizing automated tools can help detect issues related to input handling and access control. 

6. **Educate Developers on Secure Coding Practices:** Awareness of IDOR risks would encourage developers to implement necessary checks, preventing vulnerabilities like those demonstrated in the labs. By integrating these mitigation techniques into the development lifecycle, organizations can significantly reduce the risk of IDOR vulnerabilities and enhance the overall security posture of their applications.

### What’s Next?

In the previous articles, I explored HTML Injection and Cross-Site Scripting (XSS). In my next article, I’ll dive into SQL Injection vulnerabilities, exploring advanced attack techniques and real-world remediation strategies. Stay tuned!

Have you encountered IDOR vulnerabilities in your projects? Share your experiences or questions in the comments below! 🚀

If you’re passionate about penetration testing and ethical hacking, connect with me on LinkedIn or check out my GitHub for security-focused projects!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

