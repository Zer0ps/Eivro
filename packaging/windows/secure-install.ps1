$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Eivro'
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Installation directory is missing.' }
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
# Replace the ACL, rather than adding entries to a possibly weaker old ACL.
# The service's private recovery directory keeps its SYSTEM-only permissions.
$items = @(Get-Item -LiteralPath $root) + @(Get-ChildItem -LiteralPath $root -File)
foreach ($item in $items) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not allowed in the installation.' }
    if ($item.PSIsContainer) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($system, $admins)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit, 'None', 'Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'ReadAndExecute', $inherit, 'None', 'Allow'))
    Set-Acl -LiteralPath $item.FullName -AclObject $acl
}
