function Rename-LinuxVM {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [Parameter(Mandatory=$true)]
        [string]$domainName,

        [ValidateSet("Windows","Linux")]
        [string]$OperatingSystem = (Get-VMOperatingSystem -VMName $VMName)
    )

    if ($OperatingSystem -eq 'Linux') {
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Rename to [$VMName.$Domainname]"

        # /etc/hostname
        $hostname = ("$VMName.$DomainName").ToLower()
        $hostname.split("`n").trim() | out-file $env:temp\hostname -Force -Encoding ASCII
        $cmd = '[ -e /etc/hostname ] && mv /etc/hostname /etc/hostname.org'

        try {
        Invoke-VMScript  -VM $VMName -GuestCredential $GuestCredential -ScriptType Bash -ScriptText { $cmd }
        Copy-VMGuestFile -VM $VMName -GuestCredential $guestCredential -Source $env:temp\hostname -Destination /etc -Force -LocalToGuest
        Get-VM $VMName | Restart-VMGuest
        Wait-ForVMTools -VMName $VMName
        } catch {
            Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Failed to rename Linux VM"
        }
    } else {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "VM is not a Linux VM. Rename failed"
    }
}

