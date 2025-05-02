---
title: "HackTheBox - nocturnal"
permalink: /CTFs/HTB-nocturnal/
date: 2025-05-02
categories: [HackTheBox]
tags: [command injection, Linux]
math: true
mermaid: true
image:
  path: /assets/img/CTFs/Nocturnal/nocturnal.jpg
---

## Recon

nmap scan:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-01 19:28 EDT
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   141.48 ms 10.10.16.1
2   70.92 ms  nocturnal.htb (10.10.11.64)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.48 seconds
```
The webapp homepage has a login and a signup page
![image](/assets/img/CTFs/Nocturnal/homepage.png)

First I made a new user to get the PHP cookie to be able to enum the endpoits then I tried dirsearch and I got these endpoints:
```
└─$ dirsearch -u http://nocturnal.htb/ -H "Cookie: PHPSESSID=dkt7g9ap3jrfr19mjvbuhojd9m"


  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                                             
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/machines/noc/reports/http_nocturnal.htb/__25-05-01_19-34-39.txt

Target: http://nocturnal.htb/

[19:34:39] Starting:                                                                                                                                                                                                                                         
[19:34:51] 302 -    0B  - /admin.php  ->  login.php                         
[19:35:05] 301 -  178B  - /backups  ->  http://nocturnal.htb/backups/       
[19:35:05] 403 -  564B  - /backups/                                         
[19:35:10] 200 -    2KB - /dashboard.php                                    
[19:35:19] 200 -  644B  - /login.php                                        
[19:35:20] 302 -    0B  - /logout.php  ->  login.php                        
[19:35:28] 200 -  649B  - /register.php                                     
[19:35:31] 200 -    0B  - /shell                                            
[19:35:36] 403 -  564B  - /uploads                                          
[19:35:36] 403 -  564B  - /uploads/affwp-debug.log                          
[19:35:36] 403 -  564B  - /uploads/                                         
[19:35:36] 403 -  564B  - /uploads/dump.sql                                 
[19:35:36] 403 -  564B  - /uploads_admin                                    
[19:35:37] 302 -    3KB - /view.php  ->  login.php                          
                                                                             
Task Completed  
```
I then tried to upload multiple malicious files to be able to get a reverse shell but I couldn't.

Then I hovered over one of the files that I uploaded to see this URL:
```
http://nocturnal.htb/view.php?username=user&file=sample.pdf
```
Then I created another user and tried to visit the same URL to see if the website is vulnerable to IDOR and it worked! I was able to see the file `sample.pdf` while I was authenticated by another user.

So what if I enumerate both username and password for another valid file???

### privacy.odt
ffuf was the tool for this job

I created a wordlist with the user 'user' in it to filter the the unwanted pages
![image](/assets/img/CTFs/Nocturnal/names1.png)

as we can see there are 2 users who are valid: `user (our crafted account)` and `admin`, so we can filter out all the responses with size of `2985`.
![image](/assets/img/CTFs/Nocturnal/names2.png)
So I got these 3 users
