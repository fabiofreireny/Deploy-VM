function Start-VMUpdate {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [switch]$Wait,

        [ValidateSet("Windows","Linux")]
        [string]$OperatingSystem = (Get-VMOperatingSystem -VMName $VMName)
    )

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Install all $OperatingSystem patches"

    if ($OperatingSystem -eq 'Windows') {
        $scriptWindowsUpdate = @'
            #Needs to be Powershell 5 and above
            if ($($PSVersionTable.PSVersion.Major) -ge 5 ) {
                if (-not (Get-PackageProvider -Name NuGet)) { Install-PackageProvider -Name NuGet -Force }
                if (-not (Get-Module PSWindowsUpdate)) { Install-Module PSWindowsUpdate -Force }
                Install-WindowsUpdate -MicrosoftUpdate -AutoReboot -AcceptAll
            } else {
                write-output "Powershell version not 5 or greater"
            }
'@
        $scriptWindowsUpdate.replace("`n","`r`n") | out-file $env:temp\windowsUpdate.ps1 -Force -Encoding ASCII

        Copy-VMGuestFile -VM $VMName -Source $env:temp\windowsUpdate.ps1 -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential
        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText { c:\windows\temp\windowsUpdate.ps1 } | Tee-Object -Variable result
    }

    if ($OperatingSystem -eq 'Linux') {
        $scriptLinuxUpdate = 'yum check-update; yum upgrade -y'

        # prevent error "Index was outside the bounds of the array"
        start-sleep -seconds 5

        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $scriptLinuxUpdate -ScriptType Bash -ErrorVariable Result
    }

    if (($result -match 'fail|unable|GuestOperationsUnavailable')) {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Install patches failed"
    } else {
        if ($Wait) { Wait-ForVMTools -VMName $VMName }
    }
}
