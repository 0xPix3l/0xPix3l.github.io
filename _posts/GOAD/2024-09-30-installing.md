---
title: "Installing GOAD"
date: 2024-09-30
permalink: /GOAD/installing-goad/
categories: [Active Directory, GOAD]
tags: [installation]
toc: true
toc_sticky: true
toc_label: "On This Page"
# toc_icon: "biohazard"
classes: wide
header:
  teaser: /assets/images/GOAD/installing/game-of-thrones.jpg
  overlay_image: /assets/images/GOAD/installing/game-of-thrones.jpg
  overlay_filter: 0.8
# ribbon: DarkSlateBlue
---

In this blog i am going to explain how i set up [Game Of Active Directory](https://github.com/Orange-Cyberdefense/GOAD/) lab on a Windows host with Vmware pro.

GOAD is a lab enviroment built for pentesters with alot of misconfigurations to practice different attack methods and techniques.

As described on their repo:
> The lab intend to be installed from a Linux host and was tested only on this.
Some people have successfully installed the lab from a windows OS, to do that they create the VMs with vagrant and have done the ansible provisioning part from a linux machine.

So i had two options:
- Install it on any linux distro and have nested VMs which will slow down everything
- Figuring out how to set it up on a Windows, as mentioned that some fellas already managed to successfully install the lab from a Windows host.

# What will we need?
1. Windows host with vagrant installed to download the Windows server 2019 VMs (which i skipped and i will explain later)
2. Ubuntu or any Linux distro to run ansible playbooks scripts
3. I installed the [GOAD-light](https://github.com/Orange-Cyberdefense/GOAD/blob/main/ad/GOAD-Light/README.md) which will have 3 VMs (1 forest and 2 domains):
  - DC01 — kingslanding
  - DC02 — winterfell
  - SRV02 — castelblack

which is shown in the schema below:
![image](/assets/images/GOAD/installing/GOAD-Light_schema.png)

The process is going to be like this:
- Installing the VMs and configuring them
- Provisioning
- Fixing errors

---

# Installing VMs

As I said eariler I skiped the vagrant part to download the VMs because i already had a windows 2019 iso image. So, I installed them on Vmware like any normal windows server with default settings. But in order of them to work we had to tweak things a little.

I checked the Vagrant file folder and realised that this configuration gives the following default IPs to 3 VMs:
- GOAD-DC01: 192.168.56.10
- GOAD-DC02: 192.168.56.11
- GOAD-SRV02: 192.168.56.22

So the network configuration will be as the following:
-  First network adapter to put the 3 VMs and Ubuntu VM on a same host-only network.
-  Second network adapter to put the 3 VMs and Ubuntu VM on a NAT network.

then manually set static IP for each Windows server sequentially.
> ***Important note:*** I had to change the name of `Ethernet0` to `Ethernet1` and `Ethernet1` to `Ethernet2`, because ansible will treat `Ethernet1` as the `192.168.56.xx` (Host-only adapter). The `Ethernet2` one will be the NAT. Or change it from the inventory file.

If you check the inventory file you will see that it uses winrm protocol with user account `vagrant` and password `vagrant`, so I added this user in the 3 VMs and add them in the Administrators group. which can be checked with:
``` powershell
whoami /groups
```
Secondly I configured `winrm` on the VMs using the following:
```powershell
winrm quickconfig
winrm set winrm/config/service/auth @{Basic="true"}
winrm set winrm/config/service @{AllowUnencrypted="true"}
New-NetFirewallRule -Name "Ansible WinRM" -DisplayName "Allow WinRM" -Protocol TCP -LocalPort 5985 -Action Allow
```
Lastly I enabled `File and Printer Sharing (Echo Request - ICMPv4-In)` from firewall inbound rules which enables ping requests using ICMP protocol in order to check the connection between the VMs



Now its time for configuring the Ubuntu VM!

1. Clone the GOAD repo:
```bash
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD/ansible
```
2. Creating a Python virtual enviroment:
```bash
python3 -m venv goad-venv
``` 
3. installing ansible dependencies:
```bash
python3 -m pip install ansible-core pywinrm
ansible-galaxy install -r requirements.yml
```
Now both Ubuntu and Windows VMs are configured

---

# Provisioning and fixing errors
The last and most annoying part, the errors.

I started the ansible playbooks scripts
```bash
ansible-playbook -i ../ad/GOAD-Light/data/inventory -i ../ad/GOAD-Light/providers/virtualbox/inventory main.yml
```
but I encountered this error:
![image](/assets/images/GOAD/installing/unreachable.png)

So it trying to use `HTTPS` and port `5986` but it can't\
I first checked if `winrm` was working and the creds are valid by running `evil-winrm` tool
```bash
evil-winrm -u vagrant -p vagrant -i 192.168.56.10
```
but it worked.. 
Then i checked again `../ad/GOAD-Light/providers/vmware/inventory` file and i saw that both of these line were commented out:
```markdown
# ansible_winrm_transport=basic
# ansible_port=5985
```
All i had to do was uncomment them.
![image](/assets/images/GOAD/installing/port.png)
Then it was able to connect to it using `winrm`


Then i got this error on `DC02`:
![image](/assets/images/GOAD/installing/powershell.png)
I tried to install it with a powershell as admin:
```powershell
Install-Module -Name NuGet 
```
But It didn't work. So i went to [powershell_gallery](https://www.powershellgallery.com/packages/NuGet/1.3.3). downloaded the `nukpkg` file, extracted it and it add to modules path which can be checked by:
```powershell
$env:PSModulePath -split ';'
```
checked if it was installed correctly:
```powershell
Get-Module -ListAvailable -Name PowerShellGet
```
![image](/assets/images/GOAD/installing/powershellget.png)
and it worked!


Again on `DC02`:
![image](/assets/images/GOAD/installing/dns.png)
The script couldn't install the DNS server on it's own. So I manually installed it
```powershell
Install-WindowsFeature -Name DNS
```
Lastly I had some problems on `SRV02` with `IIS` setup, which was caused because of `.NET Framework` was not installed. I tried to install it using powershell:
```powershell
Install-WindowsFeature -Name NET-Framework-Core
```
But it didn't,and after some searching I was able to install it by letting the VM to install Windows updates because it has some versions of `.NET Framework`. Then the script handle the rest of the installation.

After fixing these errors the playbooks run smoothly
![image](/assets/images/GOAD/installing/done.png)


I checked on `DC02` (because it was the one that had the most number of errors) if it was correctly assigned to the domain:
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
```
![image](/assets/images/GOAD/installing/domain.png)


And we are all set up!!

---

I will be writing more posts on how to exploit this lab
