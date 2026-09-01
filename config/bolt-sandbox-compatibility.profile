BSC1
# Filesystem runtime compatibility. Version 1 grants read-only access only.
fs-ro|required|system-root|.
fs-ro|required|program-dir|.
fs-meta|required|cwd-anchor|.
fs-ro|optional|program-files|Common Files\SSL\openssl.cnf
fs-ro|optional|user-profile|.rustup\toolchains

# Exact read-only kernel metadata devices required by standard runtimes.
device-ro|required|device|\Device\DeviceApi\CMApi
device-ro|required|device|\\.\MountPointManager

# Public runtime and platform metadata.
reg-ro|required|registry|HKCU\SOFTWARE\Classes
reg-ro|required|registry|HKLM\SOFTWARE\Classes
reg-ro|required|registry|HKLM\SOFTWARE\dotnet\Setup\InstalledVersions
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\.NETFramework
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\.NETFramework
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Fusion
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Fusion
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\StrongName
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\FileSystem
reg-ro|required|registry|HKCU\Control Panel\International\User Profile
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Installer\Assemblies
reg-ro|required|registry|HKLM\SOFTWARE\Classes\Installer\Assemblies
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Lsa
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\MSBuild
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Microsoft SDKs\NETFXSDK
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Microsoft SDKs\NETFXSDK\4.8
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Microsoft SDKs\Windows
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell.exe
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MSBuild.exe
reg-exact-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\MiniNT
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Nls
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\AMSI
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Cryptography
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\msasn1
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Cryptography
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\crypt32
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\SystemCertificates
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\SystemCertificates
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\EnterpriseCertificates
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\EnterpriseCertificates
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\PowerShellCore
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\PowerShell
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\PowerShell
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\PowerShellCore
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\PowerShellCore
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Srp
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones

# Exact metadata and hidden compatibility probes.
reg-exact-ro|required|registry|HKU
reg-exact-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
reg-exact-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
reg-hide|required|registry|HKCU\Environment

# Legacy runtime compatibility is intentionally read-only in the Profile.
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\WinSock2
reg-exact-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\WinSock
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Winsock
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\OLE
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\AppModel\Lookaside\machine
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\AppModel\Lookaside\user
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Wow64\x86\xtajit
reg-exact-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Containers
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\LanguageOverlay\OverlayPackages
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\MpeHttpExt\Payload
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\TenantRestrictions\Payload
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Rpc
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\CCG
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName
reg-ro|required|registry|HKLM\SYSTEM\Setup
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Nls\Sorting\Ids
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Service
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Hvsi
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SspiCache
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\System
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\OLEAUT
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\COM3
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\WindowsRuntime
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
reg-ro|required|registry|HKLM\ZoneMap\Ranges
reg-ro|required|registry|HKCU\ZoneMap\Ranges
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Internet Explorer\Main
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Internet Explorer\Main
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Internet Explorer\Security
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Internet Explorer\Security
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
reg-ro|required|registry|HKLM\OSDATA\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Objects
reg-ro|required|registry|HKCU\SOFTWARE\Policies\Microsoft\Windows\Appx
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Partners\COM\RundownIIDsOfInterest
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\MUI\StringCacheSettings
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem
reg-ro|required|registry|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths
