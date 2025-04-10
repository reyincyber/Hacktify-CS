# SQL Injection (SQLi) Hands-on Lab

## SQL Injection (SQLi) Labs Walkthrough — Hacktify Cybersecurity (HCS) Internship

SQL Injection (SQLi) remains one of the most devastating web application vulnerabilities, allowing attackers to manipulate database queries and gain unauthorized access to sensitive information.

This article covers my hands-on experience during Week 2 of my Hacktify Cybersecurity (HCS) penetration testing internship, where I explored multiple SQLi attack vectors in controlled lab environments. You’ll learn what SQLi is, how attackers exploit it, and a detailed walkthrough of various SQLi labs, including best practices to prevent these attacks.

🔗 Documentation: **[GitHub](https://github.com/reyincyber/Hacktify-CS)**; **[Medium](https://cyberrey.medium.com/sql-injection-sqli-hands-on-lab-d049af02b623)**; [**YouTube**](https://youtu.be/XAS5fkZiwfQ)

## Table of Contents

- [What is SQL Injection (SQLi)?](#what-is-sql-injection-sqli)
- [Types of SQL Injection](#types-of-sql-injection)
- [SQL Injection (SQLi) Labs Walkthrough](#sql-injection-sqli-labs-walkthrough)
  - [Strings & Errors Part 1](#strings--errors-part-1)
  - [Strings & Errors Part 2](#strings--errors-part-2)
  - [Strings & Errors Part 3](#strings--errors-part-3)
  - [Let’s Trick ‘em!](#lets-trick-em)
  - [Booleans and Blind!](#booleans-and-blind)
  - [Error-Based: Tricked](#error-based-tricked)
  - [Errors and POST!](#errors-and-post)
  - [User Agents Lead Us!](#user-agents-lead-us)
  - [Referer Lead Us!](#referer-lead-us)
  - [Oh Cookies!](#oh-cookies)
  - [WAF’s are Injected!](#wafs-are-injected)
  - [WAF’s are Injected Part 2](#wafs-are-injected-part-2)
- [Mitigation Techniques & Best Practices](#mitigation-techniques--best-practices)
- [What’s Next?](#whats-next)
- [License](#license)

## What is SQL Injection (SQLi)?

SQL Injection is a code injection technique that exploits vulnerabilities in data-driven applications by inserting malicious SQL statements into an entry field for execution. This allows attackers to interfere with the queries an application makes to its database, potentially accessing or manipulating data beyond their authorized rights.

According to the 2024 OWASP Top 10, SQL Injection remains a leading web vulnerability, responsible for 19% of web application attacks globally. In September 2024, security researchers Ian Carroll and Sam Curry discovered a vulnerability in the FlyCASS system, a third-party website used by smaller airlines to access the Transportation Security Administration’s (TSA) Known Crewmember (KCM) system and Cockpit Access Security System (CASS). This SQL injection flaw allowed unauthorized individuals to add fake pilots to airline rosters, potentially enabling them to bypass TSA security checks and access restricted areas, including aircraft cockpits.

## Types of SQL Injection

- **Classic SQLi**: Direct insertion of malicious SQL code into user inputs that are concatenated into SQL queries.
- **Blind or Inference SQLi**: Occurs when the application does not display error messages but behaves differently based on injected queries, allowing attackers to infer information. This exploits boolean conditions and time delays without direct feedback.
- **Error-Based SQLi**: Exploits error messages returned by the database to reveal information.
- **Union-Based SQLi**: Uses UNION SQL statements to extract data from additional tables.
- **Other types**: Time-Based SQLi, Out-of-Band SQLi, Database Management System-Specific SQLi, and Compounded SQLi.

## SQL Injection (SQLi) Labs Walkthrough

### Strings & Errors Part 1

- Check the page source, on line 96, we see ``` <!-- use of payload 1" OR "1"="1 --> ```
- Thus, we return to the logon page and Enter ``` 1" OR "1"="1 ```  in the email and password fields. The application returned the admin panel, ``` Email: admin@gmail.com | Password: Admin@1414 | Successful Login ``` proving authentication bypass.

### Strings & Errors Part 2

The ID parameter in the URL was vulnerable to SQLi, revealing database table names via error messages.

- Appending `?id=1'` to the URL resulted in the display of admin credentials.
- Adding `?id=1' UNION SELECT 1,2,3,4--+` to the URL returned the database schema  (id) of the Email and password. This behavior indicates that the input is not properly sanitized, allowing malicious SQL code to alter the database query execution.

### Strings & Errors Part 3

The application executed raw SQL queries without sanitization, allowing Union-based SQL Injection.

- Appending `?id=1' UNION SELECT username, password FROM users--` resulted in the display of admin credentials.

### Let’s Trick ‘em!

SQL Injection was possible by altering input values, exploiting the logic of authentication queries.

- Each input field was tested by entering a single quote (') to detect SQL errors. The application returned error messages upon inputting the single quote, indicating potential SQL injection points.
- While checking the Source Code (Ctrl + U), I discovered the following payload `1' || '1'= '1` on line 103 of the source code.
- I used the payload  in both the email and password fields resulted in a successful login, confirming the vulnerability.

### Booleans and Blind!

Blind SQL Injection was possible by observing boolean-based conditions in application responses.

- Appending `?id=1` to the URL resulted in the display of sensitive information.

### Error-Based: Tricked

To test this,

- I started by checking the Source Code (Ctrl + U), I discovered the following payload ` <!--use of payload ") or ("1")=("1  -- ` on line 103 of the source code.
- I then inputted the following payload into both the email and password fields: ` ('a'='a and hi")or ("a"="a `
- Upon submission, the application granted access and displayed the real admin credentials.

This behavior indicates that the application does not properly sanitize user inputs, allowing SQL code to alter the intended query logic.

### Errors and POST!

The SQLi vulnerability was found in POST parameters by modifying POST request to include `' OR '1'='1 ` in parameters. The application granted access without proper credentials, indicating that user inputs were directly embedded into SQL queries without adequate sanitization or parameterization.

### User Agents Lead Us!

SQL Injection was exploitable in the User-Agent HTTP header, which was logged in the database.

- Log in with the credentials `admin@gmail.com ` and `admin123 `, the application displayed the User-Agent string.
- By injecting a single quote (') into the User-Agent header or changing

 ``` User-Agent to Mozilla/5.0' OR '1'='1 ``` 

 or 

``` User-Agent to Mozilla/5.0 " OR "1"="1 ```

  Based on the  observed an SQL error message, it was evident that the input was not properly sanitized, confirming the SQL Injection vulnerability.

### Referer Lead Us!

The application processed Referer headers in SQL queries without validation.
- I used browser developer tools to inspect network requests and identify the Referer header as a potential injection point.
- I also employed Burp Suite to intercept HTTP requests and modify the **_Referrer_ header** with SQL injection payloads ` ' OR 1=1-- ` or ` " OR "1"="1 `.
- I then observed application responses for SQL errors or unexpected behavior indicative of successful injection.

## Oh Cookies!

SQLi was possible via session cookies, leading to session hijacking.

- I logged in using credentials ‘admin’ for both username and password.
- Using browser’s developer tools, I navigated to the "Storage" tab and the "Cookies" sub tab where I click on the webpage link
- I then modified the ‘username’ cookie to include a SQL injection payload: `' union SELECT version(),user(),database()# `
- Upon refreshing the page, the application displayed database version, current user, and database name, confirming successful SQL injection.

## WAF’s are Injected!

SQL Injection was possible despite Web Application Firewall (WAF), using obfuscation techniques.

During testing, the following payload was appended to the URL ` ?id=1&id=0' +union+select+1,@@version,database()--+ `

This payload exploits the SQL Injection vulnerability by injecting a UNION SELECT statement to retrieve the database version and name. This indicates that the application executed the injected SQL command and returned sensitive database information.

### WAF’s are Injected Part 2

he application is vulnerable to SQL Injection attacks, allowing attackers to execute arbitrary SQL code. By inputting specific SQL payloads into the URL parameters, unexpected data was returned, indicating successful injection and WAF bypass.

` ?id=1-- ` 

` ?id=1&param=UNI&param2=ON SEL&param3=ECT 1,2,3-- `

The application responded with login credentials


# Mitigation Techniques & Best Practices

Enhancing the security of your applications against SQL Injection (SQLi) attacks requires implementing targeted remediation measures tailored to the specific vulnerabilities identified:

1. **Error-Based SQL Injection:** The examples exploited above reveals detailed database error messages when unexpected input is provided.
   1. Use prepared statements with ***parameterized queries*** to ensure user inputs are treated strictly as data, preventing them from altering the query structure.
   2. Suppress Detailed Error Messages by configuring the application to display generic error messages to users, avoiding the exposure of database schema or other sensitive information.
2. **SQL Injection via HTTP Headers (User-Agent, Referer, Cookies):** Attackers inject malicious SQL code into HTTP headers, which the application logs or processes without proper sanitization.
   1. Treat all data from ***HTTP headers*** as untrusted input, applying rigorous validation and ***sanitization*** before processing.
   2. &#x20;Ensure the database account used by the application has the ***minimum necessary privileges,*** limiting the potential impact of a successful injection.
3. **Bypassing Web Application Firewalls (WAFs are injected):** Attackers obfuscate SQL injection payloads to evade detection by WAFs.
   1. Keep WAF rules and signatures up to date to recognize and block obfuscated injection attempts.
   2. Use a layered security approach, combining WAFs with secure coding practices like parameterized queries and input validation, to provide defense in depth.
4. **Union-Based SQL Injection:** Attackers manipulate input fields to append malicious SQL statements using the UNION operator, retrieving unauthorized data.

   Use Parameterized Queries and Employ Allow-List Input Validation: Define and enforce strict patterns for acceptable user inputs, rejecting any input that does not conform to these patterns.
5. **Boolean-Based Blind SQL Injection:** Attackers infer database information by injecting conditions that result in different application behaviors based on true or false evaluations.\
   Use Parameterized Queries and Perform manual and automated penetration testing to identify and remediate potential blind SQL injection vulnerabilities.
6. Time-Based Blind SQL Injection: Attackers use SQL commands that cause time delays, allowing them to infer information based on the application’s response time.\
   Use Parameterized Queries and Deploy WAFs to detect and block patterns indicative of time-based SQL injection attempts.
7. **Out-of-Band SQL Injection**: Attackers exploit features like HTTP requests or DNS queries to extract data when in-band methods are not feasible.
   1. Turn off database functionalities that are not in use, reducing the attack surface for out-of-band channels.
   2. Implement network monitoring to detect unusual outbound traffic patterns that may indicate out-of-band data exfiltration attempts.

By implementing these targeted remediation measures, you can significantly strengthen your application’s defenses against various SQL injection attack vectors.

## What’s Next?

In the previous articles, I dived into HTML Injection, Cross-Site Scripting (XSS), and Insecure Direct Object References (IDOR). In my next article, I will explore Cross-Site Request Forgery (CSRF) vulnerabilities, showcasing real-world attacks and effective mitigation techniques.

Have you encountered SQLi vulnerabilities in your projects? Share your experiences or questions in the comments below!

If you’re passionate about Cloud Security, Penetration Testing and Ethical Hacking, connect with me on LinkedIn or check out my GitHub for security-focused projects!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
