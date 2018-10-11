Set-Variable Default_NumCPU   -Option Constant -Value 2
Set-Variable Default_MemoryGB -Option Constant -Value 4
Set-Variable Default_AdditionalDisks -Option Constant -Value 1

$operatingSystemLookup = @{
    Server2012r2 = "TEMPLATE-SERVER2KR2-VAUTOMATION"
    Server2016   = "TEMPLATE-SERVER2016-VAUTOMATION"
}

# Make sure you are connected to a vCenter!! Create-VM and NewWindowsVM use Dynamic Parameters.
# If you're not connected these parameters can't find out what their valid values are and won't even display.

function Wait-ForVMTools {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )

    Do {
        write-output "Waiting for [$VMName] to come up..."
        Start-Sleep -Seconds 10
        # If VM is rebooting the VMTools check will error out. In this case just wait a bit longer
        try {
            $GuestToolsStatus = (Get-VM -Name $VMName -ErrorAction SilentlyContinue).Guest.ExtensionData.ToolsStatus
        }
        catch {
            Start-Sleep 10
            $GuestToolsStatus = "Rebooting"
        }
    } Until (($GuestToolsStatus -eq "toolsOk") -or ($GuestToolsStatus -eq "toolsOld"))
}

function Create-VM {
    <#
        .SYNOPSIS
        Deploys VM from Template in Content Library

        .DESCRIPTION
        This script deploys VM from Template in Content Library to specified Cluster/Resource Pool and Storage Cluster.
        It also add Tags, assign Network, add drives, modify RAM and CPU count.

        Once this is complete, for Windows machines you should run the other functions to assign IP, rename, add to domain and patch

        NOTE: The script assumes you're already connected to vSphere. If you're not connected the Dynamic Parameters below won't show and you won't be able to proceed.

        DYNAMIC PARAMETERS (all mandatory)
        - Cluster <VMware Cluster Name>

        - Datastore <VMWare Datastore Name>

        - NetworkName <VMWare Network Name>

        - Technical Owner <VMWare Technincal Owner Tag>

        - OperatingSystem <VM Template Image Name>

        .EXAMPLE
        .\Create-VM.ps1 -VMName 'MyVM' -Cluster 'MyCluster' -Datastore 'MyDatastore' -OperatingSystem Server2012r2 -AdditionalDisks 0 -TechnicalOwner 'Fabio Freire' -NetworkName 'VM Network' -Wait
        Will deploy a VM to the specified Cluster and Datastore Cluster, using a Server 2012r2 template, no additional hard drives will be provisioned, the Technical Owner Tag will be assigned as Fabio Freire, and it will wait until the VM is online before exiting

        .LINK
        https://github.com/fabiofreireny/Deploy-VM

        .NOTES
        Author: Fabio Freire (@fabiofreireny)

        Requires VMware PowerCLI (tested on v10.1.0)
    #>

    #requires -module VMware.VimAutomation.Core

    [CmdletBinding(DefaultParameterSetName="PowerOn")]
    param (
        # New VM Name
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        # Assigned CPUs
        [ValidateSet(2,4,6)]
        [int]$NumCPU = $Default_NumCPU,

        # Assigned RAM
        [ValidateSet(4,8,16)]
        [int]$MemoryGB = $Default_MemoryGB,

        # Number of additional disks (0 = Don't add disks, 1 = General Purpose, 4 = SQL)
        [ValidateSet(0,1,4)]
        [int]$AdditionalDisks = $Default_AdditionalDisks,

        # Don't power on VM
        [Parameter(ParameterSetName="NoPowerOn")]
        [switch]$DontPowerOn,

        # Wait for deployment to complete and VM to be powered on
        [Parameter(ParameterSetName="PowerOn")]
        [switch]$Wait
    )
    DynamicParam {
        # Fail if not connected to vSphere
        if (-not $global:DefaultVIServers) {
            Throw "**** You're not connected to any vSphere servers. Connect to vSphere then re-run this command ****"
        }

        # Define dynamic parameters. If defining multiple it's simpler to create an array first
        $DynamicParameters = @(
            @{
                Name = "Cluster"
                Type = [string]
                Position = 1
                Mandatory = $true
                ValidateSet = (Get-Cluster).Name | Sort
            },
            @{
                Name = "Datastore"
                Type = [string]
                Position = 2
                Mandatory = $true
                ValidateSet = (Get-DatastoreCluster).Name | Sort
            },
            @{
                Name = "NetworkName"
                Type = [string]
                Position = 3
                Mandatory = $true
                ValidateSet = (get-virtualportgroup).Name | select -Unique | Sort
            },
            @{
                Name = "TechnicalOwner"
                Type = [string]
                Position = 4
                Mandatory = $true
                ValidateSet = (Get-Tag | Where {$_.Category.Name -eq 'Technical Owner'}).Name | Sort
            },
            @{
                Name = "OperatingSystem"
                Type = [string]
                Position = 5
                Mandatory = $true
                ValidateSet = ($operatingSystemLookup).Keys | Sort
            }
        )

        # Iterate through array and create dynamic aprameters
        $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $DynamicParameters | ForEach-Object {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $_.Mandatory
            $attributes.Position = $_.Position

            $validateScript = $_.ValidateSet
            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)
            $AttributeCollection.Add((New-Object  System.Management.Automation.ValidateSetAttribute($validateScript)))

            $clusterParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($_.Name, $_.Type, $attributeCollection)

            $paramDictionary.Add($_.Name, $clusterParameter)
        }
        return $paramDictionary
    }

    Process {
        # Bind dynamic parameters to variables
        $PsBoundParameters.GetEnumerator() | % { New-Variable -Name $_.Key -Value $_.Value -ErrorAction SilentlyContinue }

        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue ) {
            Write-Output "VM Name: $VMName already exists. Aborting."
            Break
        }

        # Deploy VM from Template
        Write-Output "Deploying VM [$VMName] from Template [$($operatingSystemLookup.$operatingSystem)]"
        $params = @{
            Name = $VMName
            resourcePool = $Cluster
            contentLibraryItem = $operatingSystemLookup.$operatingSystem
            datastore = $datastore
        }

        New-VM  @params

        # Sometimes VMware jumps the gun and you get an error when changing the network (even though it works)
        Start-Sleep -Seconds 5

        # Change VLan
        Write-Output "Assigning VLan [$networkName] to VM [$VMName]"
        Get-NetworkAdapter -VM $VMName | Set-NetworkAdapter -NetworkName $NetworkName -confirm:$false

        # Assign Tag(s)
        Write-Output "Assigning Tag(s) [$technicalOwner] to VM [$VMName]"
        New-TagAssignment -Tag (Get-Tag | ? Name -eq $TechnicalOwner) -Entity $VMName

        $VM = Get-VM -Name $VMName

        if ($numCPU -ne $Default_NumCPU) {
            Write-Output "Assigning [$numCPU] vCPUs to VM [$VMName]"
            $VM | Set-VM -NumCPU $numCPU -Confirm:$false
        }

        if ($MemoryGB -ne $Default_MemoryGB) {
            Write-Output "Assigning [$memoryGB] GB to VM [$VMName]"
            $VM | Set-VM -MemoryGB $memoryGB -Confirm:$false
        }

        # Add disks
        $diskSize = 40
        $index = 1
        While ($index -le $AdditionalDisks) {
            Write-Output "Adding Disk [$index] to VM [$VMName] with capacity $($diskSize)GB"
            New-HardDisk -StorageFormat Thin -CapacityGB $diskSize -VM $VM
            $index ++
        }

        # Power On
        if (-not $DontPowerOn) {
            Start-VM $VM
        }

        if ($wait) {
            Write-Output "Waiting for [$VMName] to come up..."
            Start-Sleep -Seconds 60
            Wait-ForVMTools -VMName $VMName
        }
    }
}

function Configure-WindowsVMTCPIP {
    #requires -module ActiveDirectory

    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [ValidatePattern("(\d{1,3}\.){3}\d{1,3}")]
        [string]$IP,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        # DNS Server(s), defaults to all DCs in current site, randomized
        [ValidatePattern("(\d{1,3}\.){3}\d{1,3}")]
        [string[]]$DNS,

        [ValidateRange(16,31)]
        [int]$SubnetMaskCIDR = 24,

        # Default gateway, If none provided assume it's same as $IP but replacing last octet with .1
        [ValidatePattern("(\d{1,3}\.){3}\d{1,3}")]
        [string]$Gateway
    )

    # Ensure you're connected to vSphere
    if (-not $global:DefaultVIServers) {
        throw "**** You're not connected to any vSphere servers. Connect to vSphere then re-run this command ****"
    }

    # Ensure IP is not already in use
    if (Test-Connection -ComputerName $IP  -ErrorAction SilentlyContinue) {
        Throw "IP: $IP is in use. Aborting."
    }

    # If no DNS provided assume its all DCs in current site, randomized
    if (-not $DNS) {
        $SiteName = (Get-ADDomainController).site
        $DNS = (Get-ADDomainController -Filter { Site -eq $SiteName }).IPv4Address
        $DNS = ($DNS | Get-Random -Count $DNS.Count)
    }

    # If no gateway provided assume it's same as $IP but replacing last octet with .1
    if (-not $Gateway) {
        $Gateway = $IP -replace "\d{1,3}$","1"
    }

    $scriptIP  = @"
        Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_tcpip6
        Get-NetAdapter | Set-NetIPInterface -DHCP Disabled
        Get-NetAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IP -PrefixLength [string]$SubnetMaskCIDR -Type Unicast -DefaultGateway $Gateway
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $($DNS -join ",")
"@

    Write-Output "Configuring TCP/IP on [$VMName]..."
    Write-Output "IP = $IP/$SubnetmaskCIDR"
    Write-Output "Gateway = $Gateway"
    Write-Output "DNS = $DNS"
    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $scriptIP
}

function Initialize-WindowsVMDisks {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential
    )

    # DISKPART commands
    $diskpartCD = @'
        REM Change CD drive letter
        select volume 0
        assign letter=r
'@

    $diskpartDATA = @'
        REM Configure DATA drive
        select disk 1
        online disk
        attrib disk clear readonly
        create partition primary
        select partition 1
        assign letter=d
        format fs=ntfs quick label="DATA"
'@

    $diskpartSQL = @'
        REM Configure SQL LOGS drive
        select disk 2
        online disk
        attrib disk clear readonly
        create partition primary
        select partition 1
        assign letter=l
        format fs=ntfs quick label="LOGS"

        REM Configure SQL SWAP drive
        select disk 3
        online disk
        attrib disk clear readonly
        create partition primary
        select partition 1
        assign letter=s
        format fs=ntfs quick label="SWAP"

        REM Configure SQL TEMP drive
        select disk 4
        online disk
        attrib disk clear readonly
        create partition primary
        select partition 1
        assign letter=t
        format fs=ntfs quick label="TEMP"
'@

    $diskpartBatchFile = @'
        diskpart /s C:\Windows\temp\diskpart.txt

        mkdir c:\Scripts
        mkdir c:\Install
        mkdir c:\Temp
'@

    # Find out how many disks in VM
    $NumDisks = (Get-VM -Name $VMName | Get-Harddisk).count

    switch ($NumDisks) {
        1 { Write-Output "[$VMname] is a special purpose VM (1 disk)"
            $diskpartCommands = $diskpartCD
        }
        2 { Write-Output "[$VMname] is a standard VM (2 disks)"
            $diskpartCommands = $diskpartCD + "`n" + $diskpartDATA
        }
        5 { Write-Output "[$VMname] is a SQL VM (5 disks)"
            $diskpartCommands = $diskpartCD + "`n" + $diskpartDATA + "`n" + $diskpartSQL
        }
    }

    # Dealing with DOS idiosyncrasies
    $diskpartCommands.replace("`n","`r`n") | out-file $env:temp\diskpart.txt -Force -Encoding ASCII

    Write-Output "Configuring [$NumDisks] disk(s)..."

    # Change drive letters. This is done inside Windows, thus the need for it to be powered on and the guest credentials
    Copy-VMGuestFile -VM $VMName -Source $env:temp\diskpart.txt -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential -ErrorVariable $copyError -ErrorAction SilentlyContinue

    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $diskpartBatchFile
}

function Set-WindowsVMTimeZone {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Eastern Standard Time","Pacific Standard Time","Central Standard Time","GMT Standard Time","W. Europe Standard Time","China Standard Time")]
        [string]$TimeZone
    )

    Write-Output "Setting time zone on [$VMName] to [$TimeZone]"

    $timeZoneScript = "tzutil /s ""$TimeZone"" ; tzutil /g"

    Invoke-VMScript -VM $VMName -GuestCredential $GuestCredential -ScriptText $timeZoneScript
}

function Start-WindowsVMUpdate {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential
    )

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

    Write-Output "Installing all Windows patches on [$VMName]. This might take quite some time..."

    Copy-VMGuestFile -VM $VMName -Source $env:temp\windowsUpdate.ps1 -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential

    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText { c:\windows\temp\windowsUpdate.ps1 }
}

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

    Write-Output "Renaming [$VMName] and rebooting..."

    $renameScript = "Rename-Computer -NewName $VMName"
    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText  $renameScript
    Restart-VMGuest -VM $VMName -Confirm:$false
    Wait-ForVMTools -VMName $VMName

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

    Write-Output "Joining [$VMName] to Domain and rebooting..."

    Copy-VMGuestFile -VM $VMName -Source $env:temp\addDomain.ps1 -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential

    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText  { c:\windows\temp\addDomain.ps1 }
    Restart-VMGuest -VM $VMName -Confirm:$false


    if ($Wait) {
        Write-Output "Waiting for VM to respond after reboot..."
        Wait-ForVMTools -VMName $VMName
    }
}

function New-WindowsVM {
    <#
        .SYNOPSIS
        Aggregator function, calls other functions to deploy VM. This is to make easier deploying a VM with one command

        .DESCRIPTION
        It will call, in sequence:
        Create-VM
        Configure-WindowsVMTCPIP
        Initialize-WndowsVMDisks
        Set-WindowsVMTimeZone
        Start-WindowsVMUpdate
        Add-WindowsVMToDomain

        NOTE: The script assumes you're already connected to your vSphere

        DYNAMIC PARAMETERS (all mandatory)
        - Cluster <VMware Cluster Name>

        - Datastore <VMWare Datastore Name>

        - NetworkName <VMWare Network Name>

        - Technical Owner <VMWare Technincal Owner Tag>

        - OperatingSystem <VM Template Image Name>

        .EXAMPLE
        Create-WindowsVM -VMName VM1 -IP DHCP -domainCredential (get-credential) -guestCredential (get-credential) -Cluster 'VMwareCluster' -Datastore 'VMwareDatastore' -TechnicalOwner 'Fabio Freire' -NetworkName 'VM Network' -OperatingSystem 'Server2016'
        Guest Credential is a local administrator account on the VM
        Domain Credential is a domain account that can add a machine to the domain

        .LINK
        https://github.com/fabiofreireny/Deploy-VM

        .NOTES
        Author: Fabio Freire (@fabiofreireny)

        Requires VMware PowerCLI (tested on v10.1.0)
    #>

    #requires -module VMware.VimAutomation.Core

    [CmdletBinding()]
    param (
        # New VM Name
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        # New VM IP Address
        [Parameter(Mandatory=$true)]
        [ValidateScript({($_ -match "(\d{1,3}\.){3}\d{1,3}") -or ($_ -eq "DHCP")})]
        [string]$IP,

        # Domain Credentials (to add VM to Domain)
        [Parameter(Mandatory=$true)]
        [pscredential]$DomainCredential,

        # Guest Credentials (Local Admin on the guest)
        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        # Assigned CPUs
        [ValidateSet(2,4,6)]
        [int]$NumCPU = $Default_NumCPU,

        # Assigned RAM
        [ValidateSet(4,8,16)]
        [int]$MemoryGB = $Default_MemoryGB,

        # Number of additional disks (0 = Don't add disks, 1 = General Purpose (default), 4 = SQL)
        [ValidateSet(0,1,4)]
        [int]$AdditionalDisks = $Default_AdditionalDisks,

        # Default gateway, If none provided assume it's same as $IP but replacing last octet with .1
        [string]$Gateway,

        # Subnet Mask (CIDR)
        [string]$SubnetMaskCIDR = 24,

        # DNS Server(s), defaults to all DCs in current site, randomized
        [string[]]$DNS,

        # Domain Name
        [string]$DomainName = ((Get-ADDomain).DNSRoot),

        # OU to add VM to
        [string]$OUPath = ((Get-ADDomain).ComputersContainer -replace ("CN=Computers","OU=Servers")),

        # Time Zone
        [string]$TimeZone = "Eastern Standard Time"
    )
    DynamicParam {
        # Fail if not connected to vSphere
        if (-not $global:DefaultVIServers) {
            Throw "**** You're not connected to any vSphere servers. Connect to vSphere then re-run this command ****"
        }

        # Define dynamic parameters. If defining multiple it's simpler to create an array first
        $DynamicParameters = @(
            @{
                Name = "Cluster"
                Type = [string]
                Position = 1
                Mandatory = $true
                ValidateSet = (Get-Cluster).Name | Sort
            },
            @{
                Name = "Datastore"
                Type = [string]
                Position = 2
                Mandatory = $true
                ValidateSet = (Get-DatastoreCluster).Name | Sort
            },
            @{
                Name = "NetworkName"
                Type = [string]
                Position = 3
                Mandatory = $true
                ValidateSet = (get-virtualportgroup).Name | select -Unique | Sort
            },
            @{
                Name = "TechnicalOwner"
                Type = [string]
                Position = 4
                Mandatory = $true
                ValidateSet = (Get-Tag | Where {$_.Category.Name -eq 'Technical Owner'}).Name | Sort
            },
            @{
                Name = "OperatingSystem"
                Type = [string]
                Position = 5
                Mandatory = $true
                ValidateSet = ($operatingSystemLookup).Keys | Sort
            }
        )

        # Iterate through array and create dynamic aprameters
        $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $DynamicParameters | ForEach-Object {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $_.Mandatory
            $attributes.Position = $_.Position

            $validateScript = $_.ValidateSet
            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)
            $AttributeCollection.Add((New-Object  System.Management.Automation.ValidateSetAttribute($validateScript)))

            $clusterParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($_.Name, $_.Type, $attributeCollection)

            $paramDictionary.Add($_.Name, $clusterParameter)
        }
        return $paramDictionary
    }

    Process {
        # Bind dynamic parameters to variables
        $PsBoundParameters.GetEnumerator() | % { New-Variable -Name $_.Key -Value $_.Value -ErrorAction SilentlyContinue}

        # This is a workaround for -ErrorAction SilentlyContinue not working as expected
        Try { $Test = Get-ADComputer $VMName }
            Catch { }

        if ($Test) {
            Throw "Active Directory Computer Name: $VMName already exists. Aborting."
        }

        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue ) {
            Throw "VM Name: $VMName already exists. Aborting."
        }

        Create-VM -VMName $VMName -Cluster $Cluster -Datastore $Datastore -NetworkName $NetworkName `
            -TechnicalOwner $technicalOwner -OperatingSystem $operatingSystem -AdditionalDisks $AdditionalDisks `
            -NumCPU $numCPU -MemoryGB $memoryGB -Wait

        if ($IP -ne "DHCP") {
            Configure-WindowsVMTCPIP -VMName $VMName -GuestCredential $guestCredential -IP $IP `
                -SubnetMaskCIDR $subnetMaskCIDR -Gateway $gateway -DNS $DNS
        }

        # I hate to hard code pauses but I can't figure out how to get around this. The copy fails otherwise
        Start-Sleep -Seconds 30
        Initialize-WindowsVMDisks -VMName $VMName -GuestCredential $GuestCredential

        Set-WindowsVMTimeZone     -VMName $VMName -GuestCredential $GuestCredential -TimeZone $TimeZone

        Start-WindowsVMUpdate     -VMName $VMName -GuestCredential $GuestCredential

        Wait-ForVMTools           -VMName $VMName

        Add-WindowsVMToDomain     -VMName $VMName -GuestCredential $GuestCredential -DomainCredential $DomainCredential `
            -DomainName $DomainName -OUPath $OUPath -Wait
    }
}

Export-ModuleMember -Function *