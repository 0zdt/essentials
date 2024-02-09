Windows Security Controls: [[Windows Security Controls]]
Reference: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
### System Information

```
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" # Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn # Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% # Get system architecture
```

```
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Version Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **massive attack surface** that a Windows environment presents.

**On the system**

- _post/windows/gather/enum_patches_
    
- _post/multi/recon/local_exploit_suggester_
    
- [_watson_](https://github.com/rasta-mouse/Watson)
    
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_
    

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
    
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)
    

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
    
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
    
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment
```
set

dir env:

Get-ChildItem Env: | ft Key,Value
```
