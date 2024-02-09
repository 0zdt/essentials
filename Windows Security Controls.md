Living Off The Land Binaries, Scripts and Libraries: https://lolbas-project.github.io/
### Check

```
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

AppLocker rules applied to a host can also be **read from the local registry** at `HKLM\Software\Policies\Microsoft\Windows\SrpV2

### Bypass

- Useful **Writable folders** to bypass AppLocker Policy: If AppLocker is allowing to execute anything inside `C:\Windows\System32` or `C:\Windows` there are **writable folders** you can use to **bypass this**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- **Poorly written rules could also be bypassed**
    
    - For example, `**<FilePathCondition Path="%OSDRIVE%*\allowed*"/>**`, you can create a **folder called** `**allowed**` anywhere and it will be allowed.
        
    
    - Organizations also often focus on **blocking the** `**%System32%\WindowsPowerShell\v1.0\powershell.exe**` **executable**, but forget about the **other** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.
        
    

- **DLL enforcement very rarely enabled** due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break. So using **DLLs as backdoors will help bypassing AppLocker**.
    

- You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass AppLocker. For more info check: https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode


### Windows Defender

To check the **status** of **Defender** you can execute the PS cmdlet `**Get-MpComputerStatus**` (check the value of `**RealTimeProtectionEnabled**` to know if it's active):

```
PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
PSComputerName                  :
```

To enumerate it you could also run:

```
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

