# Vulnersity Module in Tryhackme

## Recon
1. There are 6 open ports in that machine which i found out using `nmap -sV 10.10.122.147`
2. Squid proxy is running on the version 3.5.12
3. Its running on Ubuntu Operating System
4. Web services are running on `3333`

## Locating Directories

1. We can locate paths in a website using gobuster but here i will be using feroxbuster
2. The command used to run feroxbuster is `feroxbuster -u http://{machine_ip} -d 2 -w /usr/share/dirb/wordlists/big.txt
`
3. I am using feroxbuster because it provides a more broad searching area.
4. Found a directory named internal 

## Compromising the web server
1. using burpsuite we found out that the webserver accepts the `.hptml` extension 
2. Downloaded the premade shell script from pentest monkey and named it `shell.phtml`
3. Ran a Netcat listner
4. Went to the link to the shell and get privilage to access the user bill

## Getting the root flag
1. From seaching i found that we can run Systemctl commands 
2. from gftobins i exploited Systemctl SUID and got the root flag
3. And we got the flag `a58ff8579f0a9270368d33a9966c7fd5`

