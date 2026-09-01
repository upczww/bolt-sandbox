BSC1
# Filesystem runtime compatibility. Version 1 grants read-only access only.
fs-ro|required|system-root|.
fs-ro|required|program-dir|.
fs-meta|required|cwd-anchor|.
fs-ro|optional|program-files|Common Files\SSL\openssl.cnf

# Public runtime and platform metadata.
reg-ro|required|registry|HKCU\SOFTWARE\Classes
reg-ro|required|registry|HKLM\SOFTWARE\Classes
reg-ro|required|registry|HKLM\SOFTWARE\dotnet\Setup\InstalledVersions
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Nls
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\AMSI
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Cryptography
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
reg-ro|required|registry|HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer
reg-ro|required|registry|HKLM\SYSTEM\CurrentControlSet\Control\Srp
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server
reg-ro|required|registry|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones
