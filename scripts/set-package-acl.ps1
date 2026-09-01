[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $PackageRoot).Path
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$fullControl = [Security.AccessControl.FileSystemRights]::FullControl
$allow = [Security.AccessControl.AccessControlType]::Allow

function Set-ExactAcl(
    [string]$Path,
    [bool]$Directory
) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $propagation = [Security.AccessControl.PropagationFlags]::None
    foreach ($sid in @($currentSid, $systemSid, $administratorsSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, $fullControl, $inheritance, $propagation, $allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Set-ExactAcl -Path $resolvedRoot -Directory $true
foreach ($item in Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse points are not allowed in a release package: $($item.FullName)"
    }
    Set-ExactAcl -Path $item.FullName -Directory $item.PSIsContainer
}
Write-Output "Package ACL applied: $resolvedRoot"
