function Add-WindowsVMToDomain {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [Parameter(Mandatory=$true)]
        [pscredential]$DomainCredential,

        # Domain Name
        [string]$DomainName = ((Get-ADDomain).DNSRoot),

        # OU to add VM to
        [string]$OUPath = ((Get-ADDomain).ComputersContainer -replace ("CN=Computers","OU=Servers")),

        [switch]$Wait
    )

    # Rename and reboot. The Powershell command Add-Computer is technically able to rename and add to the Domain in one shot
    # but I find that doesn't always work

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Rename and reboot"

    if ($VMName -eq ((Get-VM $VMName).Guest.HostName)) {
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Already has correct Windows hostname. Skip"
    } else {
        $renameScript = "Rename-Computer -NewName $VMName"
        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText  $renameScript
        Restart-VMGuest -VM $VMName -Confirm:$false
        Start-Sleep -Seconds 20
        Wait-ForVMTools -VMName $VMName
    }

    # There seems to be a bug in Invoke-VMScript where I can't send a PSCredential object directly to it
    # I also can't just put it in a here-string because either it expands everything or nothing
    # My workaround is to create a temporary file with all the values I need, copy it to the VM, then read it on the VM and run my command
    $domainUser = $domainCredential.username
    $domainPassword = $domainCredential.getnetworkcredential().password

    $fileContents = @{
        domainName = $domainName
        domainUser = $domainUser
        domainPassword = $domainPassword
        OUPath = $OUPath
    }

    # If you change the file name here then you must also change $csvGuestFile below, in the here-string
    $csvLocalFile = "$($env:temp)\joinDomain.csv"

    $fileContents.GetEnumerator() | ConvertTo-CSV | Out-File $csvLocalFile -Force

    # If you change the destination here then you must also change $csvGuestFile below (in the here-string)
    Copy-VMGuestFile -Source $csvLocalFile -Destination c:\windows\temp -vm $VMName -Confirm:$False -GuestCredential $guestCredential -LocalToGuest -Force

    Remove-Item $csvLocalFile -Force

    $scriptDomain = @'
        $csvGuestFile = "c:\windows\temp\joinDomain.csv"
        $variables = get-content $csvGuestFile | ConvertFrom-CSV
        Remove-Item $csvGuestFile -Force

        $params = @{
            domainName     = ($variables | ? key -eq domainName).value
            OUPath         = ($variables | ? key -eq OUPath).value
        }

        $domainUser     = ($variables | ? key -eq domainUser).value
        $domainPassword = ($variables | ? key -eq domainPassword).value
        $password =  $domainPassword | ConvertTo-SecureString -asPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($domainUser,$password)

        Add-Computer @params -Credential $credential -Force
'@

    $scriptDomain.replace("`n","`r`n") | out-file $env:temp\addDomain.ps1 -Force -Encoding ASCII

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Join Domain [$DomainName] and reboot"

    Copy-VMGuestFile -VM $VMName -Source $env:temp\addDomain.ps1 -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential

    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText  { c:\windows\temp\addDomain.ps1 } | Tee-Object -Variable result

    if ($result -match 'fail') {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Failed to join to Domain [$domainName]"
    } else {
        Restart-VMGuest -VM $VMName -Confirm:$false
    }

    if ($Wait) {
        Wait-ForVMTools -VMName $VMName
    }
}
