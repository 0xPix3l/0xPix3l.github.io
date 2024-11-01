---
title: "HackTheBox - MonitorsThree"
permalink: /CTFs/HTB-MonitorsThree/
date: 2024-08-29
categories: [HackTheBox]
tags: [HackTheBox]
math: true
mermaid: true
image:
  path: /assets/img/CTFs/MonitorsThree/MonitorsThree.jpg
---

This was a medium box for me considiring the number of steps, but it was rewarding and I learned alot

## Enumeration


``` bash
# Nmap 7.94SVN scan initiated Mon Aug 26 17:42:14 2024 as: nmap -Pn -p- --min-rate 2000 -sC -sV -oN nmap-scan.txt 10.10.11.30
Nmap scan report for 10.10.11.30
Host is up (0.087s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8084/tcp filtered websnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 26 17:42:56 2024 -- 1 IP address (1 host up) scanned in 41.54 seconds
```

on checking the webpage there was nothing interesting except a login page that has a forgot password endpoit. after checking it and tried some sqli payloads I got this
![image](/assets/img/CTFs/MonitorsThree/forget_pass_sqli.png)
So it is vulnerable to Sql injection.

I fired up `sqlmap` and added the requset to a file to specify it with sqlmap. After sometime and messing around with payloads I got these hashes
![image](/assets/img/CTFs/MonitorsThree/sqlmap.png)
So I managed to crack the admin password.

then I used `ffuf` to enumerate subdomains
![image](/assets/img/CTFs/MonitorsThree/ffuf.png)

upon examining the yielded subdomain it redirected me to `http://cacti.monitorsthree.htb/cacti/` which was a login page so I used the credentails that I obtained to login in and it worked, but there was nothing special there.

---

## Foothold
I noticed that the cacti version was `1.2.26` and after some looking around it was vulnerable to [CVE-2024-25641](https://github.com/5ma1l/CVE-2024-25641).
With the admin credentials I got a shell
![image](/assets/img/CTFs/MonitorsThree/shell1.png)

I noticed a user named `marcus` but I couldn't access it yet.
I looked for network connections using `netstat` to see if some ports are configured to be accessed locally only and there was some interesting ports
![image](/assets/img/CTFs/MonitorsThree/netstat.png)

After spending sometime searching the files on the machine I found a file named `config.php` inside `/var/www/html/cacti/include` which had username and password for sql server.
![image](/assets/img/CTFs/MonitorsThree/config.png)
![image](/assets/img/CTFs/MonitorsThree/sql1.png)
And we are in!

I obtained more hashes from `user_auth` table inside `cacti` db
![image](/assets/img/CTFs/MonitorsThree/sql2.png)

![image](/assets/img/CTFs/MonitorsThree/marcus.png)
And only `marcus`'s password was crackable

Then I tried to SSH into marcus but it wasn't accepting username and password authentcation 
![image](/assets/img/CTFs/MonitorsThree/ssh1.png)

So I had to `su` into marcus and get the `id_rsa` file
![image](/assets/img/CTFs/MonitorsThree/id_rsa.png)

And we got user flag
![image](/assets/img/CTFs/MonitorsThree/user.png)

---
Now it's time to check what on port `8200`
![image](/assets/img/CTFs/MonitorsThree/8200.png)
It appears to be another webpage, but we can only access it from the machine itself. So I had to I create a tunnel, I will use ssh local port forward using the following command
``` bash
ssh -L 8200:127.0.0.1:8200 -i id_rsa marcus@10.10.11.30
```
> we can use `chisel` or other tools to obtain the same goal

    
![image](/assets/img/CTFs/MonitorsThree/8200_rendered.png)
I tried the creds that I obtained but none of them worked.
Duplicati is a central backup management & monitoring system, so we can backup the root.txt. After some googling I found this great [writeup](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) explaining the technique to bypass the login page.

I had to locate the location of the “Duplicati-server.sqlite” file
![image](/assets/img/CTFs/MonitorsThree/duplicati_loc.png)

and we are in!
![image](/assets/img/CTFs/MonitorsThree/duplicati_home.png)

Now all I had to do was creating a new backup and specify the backup file to be `/source/root/root.txt`
After that I went to restore tab to restore the root flag and specify a location for the restore point to be readable by the user, I choosed `/tmp`
![image](/assets/img/CTFs/MonitorsThree/restore.png)

And we got root
![image](/assets/img/CTFs/MonitorsThree/rooted.png)