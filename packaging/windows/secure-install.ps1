$ErrorActionPreference = 'Stop'
# This helper runs in Windows PowerShell 5.1 from 64-bit Setup. Use native .NET
# filesystem ACL APIs so only the requested owner/DACL are written. Set-Acl's
# provider path can additionally request privilege to set other descriptor parts.
$stage = 1
try {
    $root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Eivro'
    if (-not [Environment]::Is64BitProcess -or -not [IO.Directory]::Exists($root)) {
        throw 'Missing 64-bit installation directory.'
    }
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $directory = [IO.DirectoryInfo]::new($root)
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Installation directory is a reparse point.'
    }
    $stage = 2
    # Do not descend into the service's SYSTEM-only recovery directory.
    $items = @($directory) + @($directory.GetFiles())
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'A package file is a reparse point.'
        }
        if ($item -is [IO.DirectoryInfo]) {
            $stage = 3
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        } else {
            $stage = 4
            $acl = [Security.AccessControl.FileSecurity]::new()
            $inherit = [Security.AccessControl.InheritanceFlags]::None
        }
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($system, $admins)) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit, 'None', 'Allow'))
        }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'ReadAndExecute', $inherit, 'None', 'Allow'))
        $owner = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner).GetOwner([Security.Principal.SecurityIdentifier])
        if (-not $admins.Equals($owner)) { $acl.SetOwner($admins) }
        $item.SetAccessControl($acl)
        $actual = $item.GetAccessControl([Security.AccessControl.AccessControlSections]'Owner, Access')
        if (-not $actual.AreAccessRulesProtected -or -not $admins.Equals($actual.GetOwner([Security.Principal.SecurityIdentifier]))) {
            throw 'Installed file owner or ACL protection verification failed.'
        }
    }
} catch {
    # Split infrastructure, directory and file failures in disposable CI reports.
    # The low 16 bits preserve the actual Win32/HRESULT without printing paths.
    $cause = $_.Exception.GetBaseException()
    $code = $cause.HResult -band 0xffff
    [Console]::Error.WriteLine("Eivro ACL stage {0}, OS code {1}" -f $stage,$code)
    exit ($stage * 65536 + $code)
}
