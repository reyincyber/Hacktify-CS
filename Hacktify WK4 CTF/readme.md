# Hacktify Internship CTF Hands-on Lab  
## Capture The Flag (CTF) Labs Walkthrough — Hacktify Cybersecurity (HCS) Internship  
In Week 4 of my Hacktify Cybersecurity (HCS) penetration testing internship, I delved into the captivating world of Capture The Flag (CTF) challenges. These challenges are designed to simulate real-world cybersecurity scenarios, testing and enhancing one’s problem-solving skills, technical knowledge, and creativity. This article provides a detailed walkthrough of the CTF challenges I tackled, offering insights into the methodologies and thought processes employed.

🔗 Documentation: [**GitHub**](https://github.com/reyincyber/Hacktify-CS); [**Medium**](https://cyberrey.medium.com/hacktify-ctf-2025-week-4-eed64269651d); [**Youtube**]()

## Table of Contents  
- [What is CTF?](#what-does-capture-the-flag-ctf-challenges-even-mean)  
- [Week 4 2025 CTF Challenges Walkthrough](#week-4-2025-ctf-challenges-walkthrough)  
  - [Tools Used](#tools-used)  
  - **Category: Web**  - [Sub Lab 1: Help Me](#sub-lab-1-help-me)  | [Sub Lab 2: Lock Web](#sub-lab-2-lock-web)  | [Sub Lab 3: The World](#sub-lab-3-the-world)  
  - **Category: Network Forensics**   - [Sub Lab 4: Mail Mystery](#sub-lab-4-mail-mystery)  | [Sub Lab 5: Corrupted](#sub-lab-5-corrupted)  | [Sub Lab 6: Shadow Web](#sub-lab-6-shadow-web)  
  - **Category: Reverse Engineering**  - [Sub Lab 7: It’s easy, y’know](#sub-lab-7-its-easy-yknow)  | [Sub Lab 8: Lost in the Past](#sub-lab-8-lost-in-the-past)  | [Sub Lab 9: Decrypt Quest](#sub-lab-9-decrypt-quest)  
  - **Category: OSINT**  - [Sub Lab 10: Raccoon](#sub-lab-10-raccoon)  | [Sub Lab 11: Time Machine](#sub-lab-11-time-machine)  | [Sub Lab 12: Snapshot Whispers](#sub-lab-12-snapshot-whispers)  
  - **Category: Crypto**  [Sub Lab 13: Time Traveller](#sub-lab-13-time-traveller)  | [Sub Lab 14: Wh@t7he####](#sub-lab-14-wh7he)  | [Sub Lab 15: Success Recipe](#sub-lab-15-success-recipe)  
- [What’s Next?](#whats-next)  
- [License](#license)  

## What does Capture The Flag (CTF) Challenges even mean?  
CTFs are cybersecurity competitions where participants solve security-related tasks to find hidden “flags.” These flags are typically strings of text that prove the completion of a challenge. CTFs come in various formats, including:  

- **Jeopardy-Style**: Participants solve independent tasks across categories like web exploitation, cryptography, and forensics.  
- **Attack-Defense**: Teams defend their own systems while attacking others.  
- **Mixed**: A combination of both formats.  

Participating in CTFs sharpens technical skills, fosters teamwork, and keeps individuals updated on the latest cybersecurity trends.  

## Week 4 2025 CTF Challenges Walkthrough  
Below is a detailed walkthrough of the CTF challenges I engaged with during Week 4:  

### Tools Used  
Throughout these challenges, I employed a variety of tools to aid in the exploitation and analysis:  
- **Burp Suite/OWASP Zap**: For intercepting and modifying HTTP requests.  
- **Wireshark**: Network protocol analyzer.  
- **SQLMap**: Automated SQL injection tool.  
- **John the Ripper**: Password cracking utility.  
- **Steghide**: Steganography tool for embedding and extracting data from images.  
- **Ghidra**: Software reverse engineering framework.  
- **Dcode.fr, CyberChef, Punny Code Converters**: Web-based tools for encryption, encoding, compression, and data analysis.  

---

## Category: Web  

### Sub Lab 1: Help Me  
The “Help Me” challenge requires testing authentication mechanisms, decoding Base64-encoded credentials, analyzing web page sources, and decrypting encoded text to retrieve the final flag.

1. I accessed the login page at https://help-me-web.hackatronics.com/ and attempted to brute-force the credentials using default login credentials (admin:admin). The attempt was unsuccessful, displaying the error message: _“Invalid username or password. Please try again.”_
2. I then attempted SQL Injection using the payload admin” or “1”=”1 but received the same error message, confirming that authentication bypass via SQLi was not possible.
3. Next, I navigated to the Forgot Password page at https://help-me-web.hackatronics.com/forgot_password.php. The page required answering a security question: _“On which date is Navy Day celebrated in India?”_
4. I searched online and found the answer: 4th December. Upon entering this answer, a pop-up appeared displaying encrypted credentials:
```
Username: c29sZGllcg==
Password: aW5kaWE=
```
5. I tested these credentials directly on the login page but received an invalid login error.
6. I then decoded the credentials using Base64 decoding via https://www.base64decode.org/. The decoded credentials were: ```Username: soldier | Password: india```
7. I successfully logged in using these credentials at https://help-me-web.hackatronics.com/home.php.
8. Upon successful login, I analyzed the page source code by right-clicking and selecting View Page Source. Scrolling through the page source, I found a comment on line 85 containing an encoded flag: ```<! — SYNT:{1_nz_ce0h4_0s_h} →```
9. The flag was encoded using ROT13 encryption. I used the ROT13 decoder at https://cryptii.com/pipes/rot13-decoder to decode the text.
```
Flag: {1_am_p…4_0f_}
``` 

### Sub Lab 2: Lock Web  
This challenge involves discovering sensitive information through content discovery techniques. The goal is to bypass a PIN lock system using data extracted from the website’s robots.txt file.
1. Since the hint suggested “Think like a robot beep bop”, I checked the robots.txt file by navigating to https://lock-web-web.hackatronics.com/robots.txt, The file contained the following
```
buildNumber: "v20190816"
debug: false
modelName: "Valencia"
correctPin: "1928"
```
2. I then returned to https://lock-web-web.hackatronics.com and entered 1928. A popup message appeared, displaying the flag.

```
flag{V13w_r0b0t5.txt_c4n_b3_u5…l!!!}
```

### Sub Lab 3: The World  
This challenge involves performing directory fuzzing to uncover hidden files and extract sensitive information. The goal is to explore unlisted paths and retrieve the flag.
1. The hint suggested checking every file, implying hidden resources. I launched DirBuster and a wordlist with the file extension set to .txt into the URL: _https://the-world-web.hackatronics.com_.
2. Among the discovered files, secret.txt stood out due to its different size. Manually navigating to h_ttps://the-world-web.hackatronics.com/secret.txt_ revealed a Base64-encoded string ```
RkxBR3tZMHVfaGF2M180eHBsMHJlRF90aDNfVzByTGQhfQ==```
3. I decoded it using _https://www.base64decode.org/_ which decodes to the FLAG
```
FLAG{Y0u_hav3_4xpl0reD_th3_W0r…}
```

---

## Category: Network Forensics  

### Sub Lab 4: Mail Mystery  
The “Mail Mystery” challenge requires identifying the email file type, extracting its contents, analyzing metadata, and investigating any hidden elements to retrieve the flag.

1. The provided file was named Mail_Mystery, but the file type was unspecified. To determine the file type, on a bash terminal, I used the command ```file Mail_Mystery```. The output indicated that the file contained ASCII text related to SMTP mail, suggesting it was a .eml file.
2. To confirm this, I used the cat command: ```cat Mail_Mystery``` . This displayed the email’s raw content, confirming it was indeed an .eml file.
3. To properly view the email, I uploaded it to _https://msgeml.com/_. The email details were extracted.
4. The email urged the recipient to download payment.pdf to renew the subscription. I retrieved and analyzed the attachment using _https://exif.tools/upload.php_
5. The PDF contained a button labeled “Reactivate my account”, which linked to Netflix’s official signup page: _https://www.netflix.com/signup/planform_.
6. Running ```exiftool``` on the PDF revealed additional metadata, including a Pastebin link: The output contained: _https://pastebin.com/fh4mEK5P_.
7. The Pastebin page was password-protected. Searching through the PDF’s content, I found a small hidden text near the button: ```“Here’s a random string ‘8HKFPC70hF’.”```
8. Using ‘**8HKFPC70hF**’ as the password for the Pastebin link, I successfully accessed the hidden content.
```
flag{DFIR_G3N…}
``` 

### Sub Lab 5: Corrupted  
A file named **chall.png-1740909420074–618633075.png**__ was provide. Attempting to open this file results in an error indicating that the file format is not supported. The objective is to investigate and correct any issues with the file to retrieve the hidden flag.
1. I tried opening chall.png-1740909420074–618633075.png but encountered an error stating the file format is not supported.
2. Therefore, I then opened the file in a hex editor to inspect its header. I noticed that the header bytes did not match the standard PNG file signature ```89 50 4E 47 0D 0A 1A 0A```.
I modified the first eight bytes to match the correct PNG signature.
I then saved the changes and reopened the file using an image viewer. The image displayed contained the flag.
```
flag{m3ss3d_h3a…$}
```

### Sub Lab 6: Shadow Web  
The challenge provided a _pcapng file_ containing captured network traffic. Using _tshark_ and _base64_ decoding, we extracted sensitive data embedded in HTTP POST requests and successfully retrieved the flag.
1. I used tshark to filter and extract data from HTTP POST requests: 
```
tshark -r capture.pcapng -T fields -e http.file_data -Y "http.request.method == POST"
```
2. This command revealed WebKit boundaries containing the hidden content. I then used a [Python script](https://github.com/shacker001/rremove_webkit_boundaries/blob/main/remove_webkit_boundaries.py) to extract the relevant content from the WebKit boundaries.
```
python remove_webKit_boundaries.py
```
3. The extracted content was Base64-encoded:
```
ZmxhZ3ttdWx0MXBsM3A0cnRzYzBuZnVzM3N9
```
4. I used the following command to decode the Base64 string:
```
echo ZmxhZ3ttdWx0MXBsM3A0cnRzYzBuZnVzM3N9 | base64 -d
```
This returned the final flag
```
FLAG: flag{mult1pl3p4rtsc0nfu...} 
```
---

## Category: Reverse Engineering  

### Sub Lab 7: It’s easy, y’know  
This challenge involves analyzing a binary executable file to extract an embedded password using reverse engineering techniques.
1. I identified the file type using the command: ```file crackme2 ```
2. The output confirmed that it was an ELF executable. Running the executable displayed the message: ``` “Good luck, read the source.” This hinted that the password was embedded in the binary. ```
3. I loaded the file into Ghidra for further analysis. The _my_secure_test_ function contained a parameter named param_1, which stored a text string. The string below was identified in param_1, indicating that it was the password ```"1337_pwd" ```
4. Using this password, I retrieved the flag.
```
flag{1337_…}
```

### Sub Lab 8: Lost in the Past  
I enjoyed making small projects when I was at a young age! I used to love hiding random funny texts in my projects that no one else could understand but myself. Coincidentally, I found a project file of something I made at that time. But it’s been so long, I can’t find that text. Can you help me find it?
1. I rename the _CTF.aia-1740910120281–691025702.aia_ file to **CTF.zip**__ and extract its contents.
2. I navigated to find the **Scrum.bky**__ file then open it, the encoded flag is in textbox 1 ```7=28LE__0>F490C6GbCD?8N```
4. I then used _https://rot47.net/_ and decode the string.
```
flag{t00_much_rev3rs…}
```

### Sub Lab 9: Decrypt Quest  
A zip file which contains a text file purportedly holding encrypted secrets amidst a plethora of irrelevant data. The goal is to sift through the noise to find and decrypt the concealed information.
1. I unzipped the ZIP File _Answer.zip-1740910433987–931520235.zip_ to obtain _encrypted_data.txt_.
2. I then opened txt file and looked for patterns or anomalies that stand out from the irrelevant data. I also scanned the file for sequences that resemble encoded data, such as base64 strings, hexadecimal sequences, or other encoding schemes.
3. Finally, I used an online decoder to decode the original message. The decrypted text revealed the flag.
```
Flag: flag{hjwilj111970…}  
```
---

## Category: OSINT  

### Sub Lab 10: Raccoon  
This challenge requires finding the online presence of a pet raccoon named “racckoonn” through open-source intelligence (OSINT) techniques.
1. Since this was an OSINT challenge, I searched for the username **racckoonn**__ on Google.
2. I found an Instagram account matching the name: _https://www.instagram.com/racckoonn_. The Instagram bio mentioned that the raccoon’s owner was **@johnsonm3llisa126**, and she had a YouTube channel.
3. I then searched for the YouTube username: _https://www.youtube.com/@johnsonm3llisa126_
The About section of the YouTube channel contained the flag.
```
flag{OSINTing_is_…}  
```

### Sub Lab 11: Time Machine  

Mr. TrojanHunt has power to travel time. He is hiding some extremely confidential file from the government. Can you help NIA to get secrets of TrojanHunt?
1. I conducted an online search for “**Mr. TrojanHunt**” to gather background information. I found Mr. TrojanHunt’s Internet Archive’s Wayback Machine on _https://archive.org/details/secret_202103_ to view archived versions of Mr. TrojanHunt’s website.
2. Here, I discovered a text file. I then accessed the file and found the flag within its contents.
```
flag{Tr0j3nHunt_t1m3_tr4…}
```

### Sub Lab 12: Snapshot Whispers  
The task requires investigating the origin of an image to determine if it’s genuinely taken by the friend or sourced from elsewhere. This involves using OSINT techniques to trace the image back to its original creator.
1. I uploaded the _Image.png-1740911096032–151980933.png_ to Google Images and search for concert hall in Sydney opera house google reviews where I saw a similar image.
2. I download the image and use tools like exiftool to extract metadata using the ``` exiftool Image.png ```
3. I searched for fields such as “Artist” or “Copyright,” which might contain the photographer’s name and Alas, I found it.
```
flag{Jeffrey_Seid…}  
```
---

## Category: Crypto  

### Sub Lab 13: Time Traveller  
This challenge involves decrypting an encrypted message secured through two stages: a permutation-based encryption and a time-seeded XOR operation. The challenge requires reversing both stages to recover the original flag.
1. The encrypted flag file **flag.enc** and the encryption script **chall.py** were provided for analysis. The encryption involved two stages:
  _Stage 1:_ Encryption using a random permutation of [0,8).
  _Stage 2:_ Appending the current timestamp (18 bytes) and applying an XOR operation with 0x42.
2. The first step was extracting the last 18 bytes of flag.enc, which contained the encrypted timestamp. Each byte was XORed with 0x42 to recover the original timestamp.
3. Using this timestamp as a seed, a pseudo-random number generator was initialized to regenerate the encryption key. The first part of the encrypted message (excluding the last 18 bytes) was decrypted using the generated key by reversing the XOR operation.
4. The decrypted message was still permuted due to Stage 1 encryption. To recover the original text, a brute-force approach was used by iterating through all 8! (40320) permutations of [0,1,2,3,4,5,6,7].
5. For each permutation, the dec function was applied 42 times (as per the encryption pattern in the script) to attempt message reconstruction. The valid plaintext flag was identified.
```
FLAG: {T1m3_15_pr3C10u5_s0_Enj0y_ur_L1F5…}
```

### Sub Lab 14: Wh@t7he####  
The task involves deciphering the cryptic message to uncover the flag. The unusual flag format suggests that the flag itself might consist of special characters
1. I used the file command in a terminal to determine the file’s type: ```file chall.file-1740911737469–67832877.file```
2. I then inspected the file contents by using a hex editor to view its hexadecimal representation: ```xxd chall.file-1740911737469–67832877.file ```
3. Open the provided file using a text editor. I observed that the content consists of characters like ``` +, -, [, ], >, <, ., and ,, ``` which are characteristic of Brainfuck or its derivatives.
4. Navigate to an online ReverseFuck decoder, such as _https://www.dcode.fr/reversefuck-language_
5. Paste the content of the file into the decoder and execute it to obtain the output. The decoder outputs the flag
```
Flag {R3Vers3ddd_70_g3t_…}
```

### Sub Lab 15: Success Recipe  
A chef friend sent a recipe written in an unfamiliar language or code. The task is to decipher the recipe to uncover the hidden flag.
1. I opened the **recipe.txt-1740911941466–466385354.txt** file using a text editor. The content resembles a cooking recipe, indicating it is written in the Chef programming language.
2. I then used an Online Chef Interpreter _esolangpark.vercel.app_, where I pasted the content of the recipe file into the interpreter’s code editor.
3. After resolving any syntax issues, run the code in the interpreter. The interpreter will output a sequence of characters, typically consisting of symbols like ``` +, -, [, ], >, <, ., and ,, ```.
4. I then navigated to an online Brainfuck interpreter _https://www.dcode.fr/reversefuck-language_ where I pasted the Brainfuck code into the interpreter and execute it to obtain the decoded message.
5. The decoded message reveals the flag
```
flag{y0u_40+_s3rv..}
```

---

## What’s Next?  
In my previous Hacktify CS articles, I dived into **HTML Injection, Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), SQL Injection, Cross-Site Request Forgery (CSRF), Cross-Origin Resource Sharing (CORS)**. Check them out in case you missed them.  

Share your CTF experiences or questions in the comments below!  

If you’re passionate about **Cloud Security, Penetration Testing, and Ethical Hacking**, connect with me on **LinkedIn** or check out my **GitHub** for security-focused projects!  

---

## License  
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.  
