---
title: "HackTheBox - nocturnal"
permalink: /CTFs/HTB-nocturnal/
date: 2025-05-02
categories: [HackTheBox]
tags: [IDOR, Command Injection, Linux]
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
So I got these 3 users, I tried to fuzz files with each one of them only amanda worked:
![image](/assets/img/CTFs/Nocturnal/privacy.png)

I downloaded this file to see this:
![image](/assets/img/CTFs/Nocturnal/amanda.png)
So I tried to login on the website with these creds and it worked! and I got the admin panal.
![image](/assets/img/CTFs/Nocturnal/admin_panal.png)

---

## Foothold
Upon examining the source code of the website I stumbled across this function:
```
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}
```
So there is a potential command injection in the password parameter. I searched alot of techniques but the ones who worked for me was `%09` and `%0A` (tab and space)

![image](/assets/img/CTFs/Nocturnal/poc.png)
> `📝 NOTE:` If you hover the cursor over an encoded string in burp it will decode it to be able to see the string clearly as it is shown.

Now we can upload a revshell
![image](/assets/img/CTFs/Nocturnal/wget_revshell.png)
And execute it
![image](/assets/img/CTFs/Nocturnal/foothold.png)

Inside the home directory of this user there is a file called `nocturnal_database.db`
![image](/assets/img/CTFs/Nocturnal/tobias_hash.png)

And I got the user after ssh into the machine
![image](/assets/img/CTFs/Nocturnal/user.png)

---
## root
Getting root was easy. After messing around I checked the routing tables and I saw this:
![image](/assets/img/CTFs/Nocturnal/netstat.png)

I cd to `/var/www` to see what service it is hosted
![image](/assets/img/CTFs/Nocturnal/ispconfig.png)
so there is a service called `ispconfig` is hosted only on from the localhost, so I tried to tunnel through it to be able to see it from my host machine using this command:
```
ssh -L 8888:127.0.0.1:8080 tobias@10.10.11.64
```
![image](/assets/img/CTFs/Nocturnal/isphome.png)

I tried a tool called `whatweb` to see what version of this service to be able to search for a public RCE or something but it was fruitless, so I viewed the page source and I found this:
![image](/assets/img/CTFs/Nocturnal/version.png)

I tried the username `admin` with password of the user `tobias` and I got in. We can verify the version from the help page:
![image](/assets/img/CTFs/Nocturnal/admin.png)

then I searched for an exploit for this version and there was a CVE-2023-46818. I searched online for a public exploit and tried it to get root
![image](/assets/img/CTFs/Nocturnal/root.png)
