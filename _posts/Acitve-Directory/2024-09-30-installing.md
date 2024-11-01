---
title: "Installing GOAD"
date: 2024-09-30
permalink: /Active-Directory/installing-goad/
categories: [Active Directory, GOAD]
tags: [Installation, Active Directory, GOAD]
math: true
mermaid: true
image:
  path: /assets/img/GOAD/installing/game-of-thrones.jpg
---

Walking through how I set up the [Game Of Active Directory](https://github.com/Orange-Cyberdefense/GOAD/) lab using VMware Pro on a Windows host.

GOAD is a lab enviroment built for pentesters with alot of misconfigurations to practice different attack methods and techniques.

As described on their repo:
> The lab intend to be installed from a Linux host and was tested only on this.
Some people have successfully installed the lab from a windows OS, to do that they create the VMs with vagrant and have done the ansible provisioning part from a linux machine.

So I had two options:
- Install it on any linux distro and have nested VMs which will slow everything down 
- Figuring out how to set it up on a Windows, as mentioned that some fellas already managed to successfully install the lab from a Windows host.

## What will we need?
1. Windows host with vagrant installed to download the Windows server 2019 VMs (which I skipped and I will explain later)
2. Ubuntu or any Linux distro to run ansible playbooks scripts
3. I installed the [GOAD-light](https://github.com/Orange-Cyberdefense/GOAD/blob/main/ad/GOAD-Light/README.md) which will have 3 VMs (1 forest and 2 domains):
  - DC01 — kingslanding
  - DC02 — winterfell
  - SRV02 — castelblack

which is shown in the schema below:
![image](/assets/img/GOAD/installing/GOAD-Light_schema.png)

So the process will work as follows:
- Installing the VMs and configuring them
- Provisioning
- Fixing errors

---

## Installing VMs

As I said earlier I skipped the vagrant part to download the VMs because I already had a Windows 2019 iso image. So, I installed them on VMware like any normal Windows server with default settings. But in order for them to work we had to tweak things a little.

Upon examining the Vagrant file, I discovered that the three VMs are assigned the default IP addresses listed below:
- GOAD-DC01: 192.168.56.10
- GOAD-DC02: 192.168.56.11
- GOAD-SRV02: 192.168.56.22

So the network configuration will be as the following:
-  First network adapter to put the 3 VMs and Ubuntu VM on a same host-only network.
-  Second network adapter to put the 3 VMs and Ubuntu VM on a NAT network.

then manually set static IP for each Windows server sequentially.
> ***Important note:*** I had to change the name of `Ethernet0` to `Ethernet1` and `Ethernet1` to `Ethernet2`, because ansible will treat `Ethernet1` as the `192.168.56.xx` (Host-only adapter). The `Ethernet2` one will be the NAT (for provisioning purposes). Or change it from the inventory file.

If you check the inventory file you will see that it uses winrm protocol with user account `vagrant` and password `vagrant`. Accordingly, I added this user to each of the 3 VMs and added them in the Administrators group. which is verifiable using:
``` powershell
whoami /groups
```
Secondly I configured `winrm` on the VMs using the following:
```powershell
winrm quickconfig
winrm set winrm/config/service/auth @{Basic="true"}
winrm set winrm/config/service @{AllowUnencrypted="true"}
New-NetFirewallRule -Name "Ansible WinRM" -DisplayName "Allow WinRM" -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -Name "Ansible WinRM" -DisplayName "Allow WinRM" -Protocol TCP -LocalPort 5986 -Action Allow
```
In order to check the connection between the VMs, I lastly enabled `File and Printer Sharing (Echo Request - ICMPv4-In)` from firewall incoming rules. This allows ping requests using the ICMP protocol.



Now its time for configuring the Ubuntu VM:

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
The Windows servers and Ubuntu VMs are now set up.

---

## Provisioning and fixing errors
Now for the errors, the final and most unpleasant phase.

I started the ansible playbooks scripts
```bash
ansible-playbook -i ../ad/GOAD-Light/data/inventory -I ../ad/GOAD-Light/providers/virtualbox/inventory main.yml
```
but I encountered this error:
![image](/assets/img/GOAD/installing/unreachable.png)

So it is trying to use `HTTPS` and port `5986` but it can't\
I first checked if `winrm` was working and the creds are valid by running `evil-winrm` tool
```bash
evil-winrm -u vagrant -p vagrant -i 192.168.56.10
```
which has worked.. 
Then I checked again `../ad/GOAD-Light/providers/vmware/inventory` file and I noticed that the two lines below had been commented out:
```markdown
# ansible_winrm_transport=basic
# ansible_port=5985
```
All I had to do was to uncomment them.
![image](/assets/img/GOAD/installing/port.png)
It then succeeded in connecting to it using `winrm`


Then I got this error on `DC02`:
![image](/assets/img/GOAD/installing/powershell.png)
I tried to install it with a powershell as admin:
```powershell
Install-Module -Name NuGet 
```
But It didn't. So I went to [powershell_gallery](https://www.powershellgallery.com/packages/NuGet/1.3.3). downloaded the `nukpkg` file, extracted it and it add to modules path which can be checked by:
```powershell
$env:PSModulePath -split ';'
```
Check to see if it was installed properly:
```powershell
Get-Module -ListAvailable -Name PowerShellGet
```
![image](/assets/img/GOAD/installing/powershellget.png)
and it worked!


Again on `DC02`:
![image](/assets/img/GOAD/installing/dns.png)
The script couldn't install the DNS server on it's own. So I manually installed it
```powershell
Install-WindowsFeature -Name DNS
```
Lastly I had some problems on `SRV02` with `IIS` setup, which was caused because of `.NET Framework` was not installed. I tried to install it using powershell:
```powershell
Install-WindowsFeature -Name NET-Framework-Core
```
However, it didn't, and after some research, I managed to install it by allowing the virtual machine to install Windows updates as it contains various `.NET Framework` versions. The remainder of the installation is then handled by the script.

Then The playbooks operate without a hitch with these corrections.
![image](/assets/img/GOAD/installing/done.png)


I verified that `DC02` was successfully assigned to the domain (since it had the highest number of errors):
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
```
![image](/assets/img/GOAD/installing/domain.png)
Using `netexec` to verify: 
![image](/assets/img/GOAD/installing/poc.png)

Now everything is set up!

---

I'll be posting more on how to take advantage of this lab.
