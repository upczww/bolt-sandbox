[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $PackageRoot).Path
$allowed = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
[void]$allowed.Add([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
[void]$allowed.Add('S-1-5-18')
[void]$allowed.Add('S-1-5-32-544')
$mutationRights =
    [Security.AccessControl.FileSystemRights]::Write -bor
    [Security.AccessControl.FileSystemRights]::Modify -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
    [Security.AccessControl.FileSystemRights]::FullControl

$items = @((Get-Item -LiteralPath $resolvedRoot)) +
    @(Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse)
foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse point found in package: $($item.FullName)"
    }
    $acl = Get-Acl -LiteralPath $item.FullName
    if (-not $acl.AreAccessRulesProtected) {
        throw "ACL inheritance is still enabled: $($item.FullName)"
    }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        $canMutate = ($rule.FileSystemRights -band $mutationRights) -ne 0
        if ($rule.AccessControlType -eq 'Allow' -and $canMutate -and
            -not $allowed.Contains($sid)) {
            throw "Unexpected mutable package principal: $sid ($($item.FullName))"
        }
    }
}
Write-Output "Package ACL verification passed: $resolvedRoot"
