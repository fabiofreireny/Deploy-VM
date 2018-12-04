Set-Variable Default_NumCPU   -Option Constant -Value 2
Set-Variable Default_MemoryGB -Option Constant -Value 4
Set-Variable Default_AdditionalDisks -Option Constant -Value 1

Set-Alias -name New-WindowsVM -Value New-VirtualMachine
Set-Alias -name New-LinuxVM   -Value New-VirtualMachine

$operatingSystemLookup = @{
    Server2012r2   = "template-Server2kr2-vAutomation"
    Server2016     = "Server2016-vAutomation"
    Server2016Core = "Server2016Core-vAutomation"
    CentOS7        = "CentOS7-vAutomation"
    Windows10      = "Windows10.1803-vAutomation"
}

# Make sure you are connected to a vCenter!! Create-VM and New-VirtualMachine use Dynamic Parameters.
# If you're not connected these parameters can't find out what their valid values are and won't even display.

# Images *must* have VMware Tools pre-installed. You will be able to deploy an image and not much else unless VMTools is running

# If you deploy VMs to remote offices over slow links, consider running the command below before connecting to vCenter, to avoid timeouts:
# Set-PowerCLIConfiguration -Scope Session -WebOperationTimeoutSeconds 3600 -Confirm:$false

function Create-CustomAttributes {
    # This only need to be run once (by hand) on each vCenter. it creates the Custom Attributes that are populated when a VM is built
    # Running it more than once has no effect
    $existingCustomAttributes = (get-customattribute).Name

    $customAttributes = @(
        "BornOn",
        "ExpiresOn",
        "FromTemplate",
        "Requestor"
    )

    $customAttributes | % {
        $customAttribute = $_
        if ($existingCustomAttributes -contains $customAttribute) {
            write-output "Custom Attribute $customAttribute already exists"
        } else {
            write-output "Adding Custom Attribute $customAttribute"
            New-CustomAttribute -TargetType "VirtualMachine" -Name $customAttribute
        }
    }
}

function Write-Status {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('FATAL','ERROR','INFO','VERBOSE','SUCCESS')]
        [string]$Severity,

        [Parameter(Mandatory=$true)]
        [string]$Operation,

        [switch]$SQLLogging = $True
    )

    $TimestampCLF = (get-date -Uformat "%d/%b/%Y:%T %Z")
    $TimestampSQL = (get-date -Uformat "%Y-%m-%d %T")
    $TimestampLog = (get-date -Uformat "%Y%m%d_%H%M")

    $Requestor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $gambrinusSQL = "NYCGAMBRINUS01"
    $gambrinusDB  = "Gambrinus"
    $gambrinusTable = "History"

    if ($SQLLogging) {
        Invoke-Sqlcmd -ServerInstance $GambrinusSQL -Database $GambrinusDB -Query "INSERT INTO $gambrinusTable VALUES ('$TimeStampSQL','$VMName','$Requestor','$Severity','$Operation')"
    }

    if (!$script:Transcripting) {
        $script:Transcripting = $True
        $LogFile = "$($env:temp)\deploy-vm_$VMName_$TimestampLog.log"

        if (!(Test-Path $LogFile)) {
            Start-Transcript $LogFile
        }
    }

    switch ($Severity) {
        INFO    { $backgroundColor = 'DarkGreen' }
        ERROR   { $backgroundColor = 'Red' }
        FATAL   { $backgroundColor = 'Magenta'
                  #if (Test-Path $LogFile) {
                    Stop-Transcript
                    Clear-Variable Transcripting
                  #}
                }
        VERBOSE { $backgroundColor = 'Blue'}
        SUCCESS { $backgroundColor = 'Blue'
                  Stop-Transcript
                  Clear-Variable Transcripting
                }
    }

    Write-Host -backgroundColor $backgroundColor "[$TimestampCLF] [$VMName] [$Requestor] [$Severity] [$Operation]"
}

function Wait-ForVMTools {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )

    Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Wait for VM Tools"

    # Timeout control
    $waitTime = 5  # seconds
    $count    = 12 # iterations
    $index    = $count
    Do {
        try {
            # If VM is rebooting the VMTools check may error out. In this case just wait a bit longer
            Start-Sleep -Seconds $waitTime
            $GuestToolsStatus = (Get-VM -Name $VMName -ErrorAction SilentlyContinue).Guest.ExtensionData.ToolsStatus
        }
        catch {
            $GuestToolsStatus = "Rebooting"
            $index --
        }
        if ($GuestToolsStatus -eq "toolsNotRunning") {
            $index --
        }
        #$GuestToolsStatus
    } Until (($GuestToolsStatus -eq "toolsOk") -or ($GuestToolsStatus -eq "toolsOld") -or (!$index))

    if (!$index) {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Operation timed out after [$($count*$waitTime)] seconds"
    }

}

function Get-VMOperatingSystem {
    # Find out if this is a Windows or Linux VM
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName

        # Specify Windows VM
        #[Parameter(ParameterSetName="Windows")]
        #[switch]$Windows,

        # Specify Linux VM
        #[Parameter(ParameterSetName="Linux")]
        #[switch]$Linux
    )

    Wait-ForVMTools -VMName $VMName

    do {
        $OS = (Get-VM $VMName).Guest.GuestFamily
        if (!$OS) {
            start-sleep -Seconds 5
        }
    } until ($OS)

    #if (!$Windows -and !$Linux) {
        switch ($OS) {
            windowsGuest { $VMOperatingSystem = 'Windows' }
            linuxGuest   { $VMOperatingSystem = 'Linux' }
            default      {
                if (((Get-VM $VMName).Guest.OSFullname) -match "Linux") {
#                if ($($operatingSystemLookup.$operatingSystem) -match 'CentOS') {
                    $VMOperatingSystem = 'Linux'
                } else {
                    Write-Status -VMName $VMName -Severity 'FATAL' -Operation "Cannot determine O/S of guest VM. Aborting"
                    Throw
                }
            }
        }
    #}
    Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Operating System is [$VMOperatingSystem]"

    $VMOperatingSystem
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
        [int]$NumCPU,

        # Assigned RAM
        [ValidateSet(4,8,16)]
        [int]$MemoryGB,

        # Number of additional disks (0 = Don't add disks, 1 = General Purpose, 4 = SQL)
        [ValidateSet(0,1,4)]
        [int]$AdditionalDisks = $Default_AdditionalDisks,

        # Notes to be added to VM
        [string]$Notes,

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
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "You're not connected to any vSphere servers. Connect to vSphere then re-run this command"
            Throw
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
                ValidateSet = (Get-DatastoreCluster).Name | Sort #+ (Get-Datastore).Name) | Sort
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
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "VM already exists. Aborting"
            Throw
        }

        $contentLibraryItem = Get-ContentLibraryItem $operatingSystemLookup.$operatingSystem
        if ($contentLibraryItem.count -ne 1) {
            $contentLibraryItem = Get-ContentLibraryItem $operatingSystemLookup.$operatingSystem | ? ContentLibrary -match 'Master'
        }

        # Increase timeout if remote office
        # Doesn't work because value only takes effect on next login and I don't have login info!
        # Reconnect is not enough!
        <#
        $contentLibraryLocations = @(
            "^NYC",
            "^NYH",
            "^BYF",
            "^MDS",
            "^Boston"
        )
        $contentLibraryLocations | % { if ($cluster -match $_) { $localContentLibrary = $true } }
        if (-not $localContentLibrary) {
            Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Increase deploy timeout to [3600] seconds"

            $webOperationTimeoutSeconds = ($global:DefaultVIServer).extensiondata.client.servicetimeout

            Set-PowerCLIConfiguration -Scope Session -WebOperationTimeoutSeconds 3600 -Confirm:$false

            Connect-VIServer -Server $global:DefaultVIServer -Session $global:DefaultVIServer.SessionId
        }
        #>

        # Deploy VM from Template
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Deploy VM from Template [$($operatingSystemLookup.$operatingSystem)]"
        $params = @{
            Name = $VMName
            resourcePool = $Cluster
            contentLibraryItem = $contentLibraryItem
            datastore = $datastore
            diskStorageFormat = 'Thin'
        }

        New-VM  @params

        # Sometimes VMware jumps the gun and you get an error when changing the network (even though it works)
        Start-Sleep -Seconds 5

        # Change VLan
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign VLan [$networkName]"
        Get-NetworkAdapter -VM $VMName | Set-NetworkAdapter -NetworkName $NetworkName -confirm:$false

        # Assign Tag(s)
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign Tag(s) [$technicalOwner]"

        New-TagAssignment -Tag (Get-Tag | ? Name -eq $TechnicalOwner) -Entity $VMName -ErrorAction SilentlyContinue

        $VM = Get-VM -Name $VMName

        if ($numCPU) {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign [$numCPU] vCPUs"
            $VM | Set-VM -NumCPU $numCPU -Confirm:$false
        }

        if ($MemoryGB) {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign [$memoryGB] GB"
            $VM | Set-VM -MemoryGB $memoryGB -Confirm:$false
        }

        # Add disks
        $diskSize = 40
        $index = 1
        While ($index -le $AdditionalDisks) {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Add Disk [$index] with capacity $($diskSize)GB"
            New-HardDisk -StorageFormat Thin -CapacityGB $diskSize -VM $VM
            $index ++
        }

        # Add Custom Attributes (Annotations) and Notes
        $bornOn = get-date
        $expiresOn = 'Not Applicable'
        $fromTemplate = $contentLibraryItem
        $Requestor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign Custom Attributes [$bornOn][$expiresOn][$FromTemplate][$Requestor]"

        # If attribute assignment fails then create attributes and re-try once. Assume that if first attribute assigmnent succeeds then all will
        try {
            $VM | Set-Annotation -CustomAttribute "BornOn" -Value $bornOn -ErrorAction SilentlyContinue
        } catch {
            Create-CustomAttributes
            $VM | Set-Annotation -CustomAttribute "BornOn" -Value $bornOn
        }

        $VM | Set-Annotation -CustomAttribute "ExpiresOn" -Value $expiresOn
        $VM | Set-Annotation -CustomAttribute "FromTemplate" -Value $fromTemplate
        $VM | Set-Annotation -CustomAttribute "Requestor" -Value $Requestor

        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign Notes [$Notes]"
        $VM | Set-VM -Description $Notes -Confirm:$False

        # Power On
        if (-not $DontPowerOn) {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Power On"
            Start-VM $VM
        }

        if ($wait) {
            $OS = Get-VMOperatingSystem -VMName $VMName
            if ($OS -eq 'Windows') {
                Wait-ForVMTools -VMName $VMName
                Write-Status -VMName $VMName -Severity 'INFO' -Operation "Update VM Tools"
                Update-Tools -VM $VMName
                Start-Sleep -Seconds 60
            } else {
                Start-Sleep -Seconds 20
            }

            Wait-ForVMTools -VMName $VMName
        }
    }
}

function Get-IPMagic {
    # Shamelessly copied from http://www.itadmintools.com/2011/08/calculating-tcpip-subnets-with.html
    function toBinary ($dottedDecimal) {
        $dottedDecimal.split(".") | % {$binary = $binary + $([convert]::toString($_, 2).padleft(8, "0"))}
        return $binary
    }
    function toDottedDecimal ($binary) {
        $i = 0
        do {$dottedDecimal += "." + [string]$([convert]::toInt32($binary.substring($i, 8), 2)); $i += 8 } while ($i -le 24)
        return $dottedDecimal.substring(1)
    }
    #read args and convert to binary
    if ($args.count -ne 2) { "`nUsage: .\subnetCalc.ps1 <ipaddress> <subnetmask>`n"; Break }
    $ipBinary = toBinary $args[0]
    $smBinary = toBinary $args[1]
    #how many bits are the network ID
    $netBits = $smBinary.indexOf("0")
    #validate the subnet mask
    if (($smBinary.length -ne 32) -or ($smBinary.substring($netBits).contains("1") -eq $true)) {
        Write-Warning "Subnet Mask is invalid!"
        Break
    }
    #validate that the IP address
    if (($ipBinary.length -ne 32) -or ($ipBinary.substring($netBits) -eq "00000000") -or ($ipBinary.substring($netBits) -eq "11111111")) {
        Write-Warning "IP Address is invalid!"
        Break
    }
    #identify subnet boundaries
    $networkID = toDottedDecimal $($ipBinary.substring(0, $netBits).padright(32, "0"))
    $firstAddress = toDottedDecimal $($ipBinary.substring(0, $netBits).padright(31, "0") + "1")
    $lastAddress = toDottedDecimal $($ipBinary.substring(0, $netBits).padright(31, "1") + "0")
    $broadCast = toDottedDecimal $($ipBinary.substring(0, $netBits).padright(32, "1"))

    $IPMagic = [ordered]@{
        NetworkID = $networkID
        FirstAddress = $firstAddress
        LastAddress = $lastAddress
        Broadcast = $broadCast
        CIDR = $netBits
    }

    $IPMagic
}

function Rename-LinuxVM {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [string]$domainName
    )

    $OS = Get-VMOperatingSystem $VMName

    if ($OS -eq 'Linux') {
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Rename to [$VMName.$Domainname]"

        # /etc/hostname
        $hostname = ("$VMName.$DomainName").ToLower()
        $hostname.split("`n").trim() | out-file $env:temp\hostname -Force -Encoding ASCII
        $cmd = '[ -e /etc/hostname ] && mv /etc/hostname /etc/hostname.org'

        Invoke-VMScript  -VM $VMName -GuestCredential $GuestCredential -ScriptType Bash -ScriptText { $cmd }
        Copy-VMGuestFile -VM $VMName -GuestCredential $guestCredential -Source $env:temp\hostname -Destination /etc -Force -LocalToGuest
        Get-VM $VMName | Restart-VMGuest
        Wait-ForVMTools -VMName $VMName
    } else {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "VM is not a Linux VM. Rename failed."
    }
}

function Initialize-VMTCPIP {
    <#
        .SYNOPSIS
        Configures TCP/IP on a running VM

        .DESCRIPTION
        Configures IP, Gateway, Subnet Mask, DNS on a Windows or Linux VM.

        If Gateway, Subnet Mask or DNS server are not specified it will attempt to conigure sensible defaults

        .EXAMPLE
        .\Initialize-VMTCPIP -VMName MyVM -IP 1.1.1.1 -guestCredential (get-credential)

        .PARAMETER VMName
        Name of VM to be configured

        .PARAMETER IP
        A valid IP

        .PARAMETER GuestCredential
        Credential of the Guest VM (Windows or Linux)

        .PARAMETER Gateway
        Default Gateway. If non provided will simply replace last octet with "1"

        .PARAMETER SubnetMask
        Subnet Mask in dotted decimal format. if none provided will assume 255.255.255.0

        .PARAMETER DNS
        DNS Server(s). If none provided will figure out which DNS server(s) is/are local to the VM and assign those.
        It relies on AD Sites for that, and it assumes a certain naming relation between VM Datacenters and AD Sites.
        If your DNS infrastructure is not Windows-based this won't work.
        See comments for additional info

        .LINK
        https://github.com/fabiofreireny/Deploy-VM

        .NOTES
        Author: Fabio Freire (@fabiofreireny)

        Requires VMware PowerCLI (tested on v10.1.0)
    #>
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

        [ValidatePattern("(\d{1,3}\.){3}\d{1,3}")]
        [string]$SubnetMask = "255.255.255.0",

        # Default gateway, If none provided assume it's same as $IP but replacing last octet with .1
        [ValidatePattern("(\d{1,3}\.){3}\d{1,3}")]
        #[ValidateScript({($_ -match "(\d{1,3}\.){3}\d{1,3}") -or (-not $_)})]
        [string]$Gateway,

        # Do not check if IP already in use
        [switch]$Force = $false
    )

    # Ensure you're connected to vSphere
    if (-not $global:DefaultVIServers) {
        Write-Status -VMName $VMName -Severity 'FATAL' -Operation "You're not connected to any vSphere servers. Connect to vSphere then re-run this command. Aborting"
        Throw
    }

    # Ensure IP is not already in use
    if (!$Force) {
        if (Test-Connection -ComputerName $IP  -ErrorAction SilentlyContinue) {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "$IP is in use. Aborting"
            Throw
        }
    }

    # If no DNS provided assume its all DCs in current AD Site, randomized, plus a root DNS server
    # For this to work as expected the script needs to map between VMware Datacenters and AD Sites
    # The way it's coded is that the AD Site name is contained somewhere in the VM Datacenter name ($siteName = ... line)
    # If you use a different naming convention you'll need to change the logic (or rename your AD Sites or VM Datacenters)
    $DomainName = ((Get-ADDomain).DNSRoot)
    $rootDNS = "10.150.1.5"

    if (-not $DNS) {
        $Datacenter = (Get-VM $VMName | Get-Datacenter).Name
        $SiteName = (Get-ADForest).Sites | Where { $Datacenter -match $_ }
        $DNS = (Get-ADDomainController -Filter { Site -eq $SiteName }).IPv4Address
        $DNS = ($DNS | Get-Random -Count $DNS.Count)
        $DNS += $rootDNS
    }

    $IPMagic = Get-IPMagic $IP $SubnetMask

    # If no gateway provided assume it's same as $IP but replacing last octet with .1
    if (-not $Gateway) {
        $Gateway = $IPMagic.FirstAddress
    }

    # /etc/sysconfig/network-scripts/ifcfg-ens160 (IP, Gateway, Netmask, Broadcast)
    $ifcfg = @"
        DEVICE=ens160
        BOOTPROTO=static
        BROADCAST=$($IPMagic.Broadcast)
        IPADDR=$IP
        NETMASK=$SubnetMask
        NETWORK=$($IPMagic.NetworkID)
        GATEWAY=$Gateway
        ONBOOT=yes
        DNS1=$($DNS[0])
        DNS2=$($DNS[1])
        DOMAIN=$DomainName
"@

    $scriptIPWindows = @"
        Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_tcpip6
        Get-NetAdapter | Set-NetIPInterface -DHCP Disabled
        if (Get-NetIPAddress) { Remove-NetIPAddress -IPAddress $IP -Confirm:0 }
        Get-NetAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IP -PrefixLength $($IPMagic.CIDR) -Type Unicast -DefaultGateway $Gateway
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $($DNS -join ",")
"@

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Configure IP with IP = $IP/$($IPMagic.CIDR), Gateway = $Gateway, DNS = ($DNS)"

    $OS = Get-VMOperatingSystem $VMName

    if ($OS -eq 'Windows') {
        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $scriptIPWindows

        $pingParams = @{
            ScriptText = "ping $Gateway"
        }
    } else {
        $ifcfg.split("`n").trim() | out-file $env:temp\ifcfg-ens160 -Force -Encoding ASCII

        # Backup existing files
        $cmd = '[ -e /etc/sysconfig/network-scripts/ifcfg-ens160 ] && mv /etc/sysconfig/network-scripts/ifcfg-ens160 /etc/sysconfig/network-scripts/ifcfg-ens160.org'
        Invoke-VMScript -VM $VMName -GuestCredential $GuestCredential -ScriptType Bash -ScriptText { $cmd }

        # Configure TCP/IP
        Copy-VMGuestFile -VM $VMName -Source $env:temp\ifcfg-ens160  -Destination /etc/sysconfig/network-scripts -Force -LocalToGuest -GuestCredential $guestCredential

        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText { ifdown ens160; ifup ens160 } -ScriptType Bash

        $pingParams = @{
            ScriptText = "ping $Gateway -c 4"
            ScriptType = Bash
        }
    }

    $pingSuccessString = "TTL=255"
    $pingResult = Invoke-VMScript -VM $VMName -GuestCredential $guestCredential @pingParams

    if ($pingResult.ScriptOutput -match $pingSuccessString ) {
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Gateway [$Gateway] is pingable from IP [$IP]"
    } else {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Gateway [$Gateway] is UNPINGABLE from IP [$IP]"
    }
}

function Initialize-VMDisks {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential
    )

    $OS = Get-VMOperatingSystem $VMName

    if ($OS -eq 'Windows') {
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
            REM Configure SQL Database drive
            select disk 2
            online disk
            attrib disk clear readonly
            create partition primary
            select partition 1
            assign letter=e
            format fs=ntfs quick label="Database"

            REM Configure SQL Log drive
            select disk 3
            online disk
            attrib disk clear readonly
            create partition primary
            select partition 1
            assign letter=l
            format fs=ntfs quick label="Logs"

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

            If (!(Test-Path c:\Scripts)) { mkdir c:\Scripts }
            If (!(Test-Path c:\Install)) { mkdir c:\Install }
            If (!(Test-Path c:\Temp   )) { mkdir c:\Temp }

            Get-ChildItem c:\users\rearm.cmd -Recurse -Force -ErrorAction SilentlyContinue | % { Remove-Item $_ -Force }
'@

        # Find out how many disks in VM
        $NumDisks = (Get-VM -Name $VMName | Get-Harddisk).count

        switch ($NumDisks) {
            1 { Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found 1 disk (Special)"
                $diskpartCommands = $diskpartCD
            }
            2 { Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found 2 disks (General)"
                $diskpartCommands = $diskpartCD + "`n" + $diskpartDATA
            }
            5 { Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found 5 disks (SQL)"
                $diskpartCommands = $diskpartCD + "`n" + $diskpartDATA + "`n" + $diskpartSQL
            }
        }

        # Dealing with DOS idiosyncrasies
        $diskpartCommands.split("`r`n").trim() | out-file $env:temp\diskpart.txt -Force -Encoding ASCII

        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Configure [$NumDisks] disk(s)"

        # Change drive letters. This is done inside Windows, thus the need for it to be powered on and the guest credentials
        Copy-VMGuestFile -VM $VMName -Source $env:temp\diskpart.txt -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential

        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $diskpartBatchFile
    }
}

function Set-VMTimeZone {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Eastern","Central","Pacific","London","Zurich","HongKong")]
        [string]$TimeZone
    )

    $linuxTranslate = @{
        Eastern  = 'America/New_York'
        Pacific  = 'America/Los_Angeles'
        Central  = 'America/Chicago'
        London   = 'Europe/London'
        Zurich   = 'Europe/Zurich'
        HongKong = 'Asia/Hong_Kong'
    }

    $windowsTranslate = @{
        Eastern  = 'Eastern Standard Time'
        Pacific  = 'Pacific Standard Time'
        Central  = 'Central Standard Time'
        London   = 'GMT Standard Time'
        Zurich   = 'W. Europe Standard Time'
        HongKong = 'China Standard Time'
    }

    $OS = Get-VMOperatingSystem -VMName $VMName

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Set time zone to [$TimeZone]"

    if ($OS -eq "Windows") {
        $params = @{
            ScriptText = "tzutil /s ""$($windowsTranslate[$TimeZone])"" ; tzutil /g"
        }
    } else {
        $params = @{
            ScriptText = "mv /etc/localtime /etc/localtime.org; ln -s ../usr/share/zoneinfo/$($linuxTranslate[$timezone]) /etc/localtime"
            ScriptType = "Bash"
        }
    }

    Invoke-VMScript -VM $VMName -GuestCredential $GuestCredential @params
}

function Start-VMUpdate {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [switch]$Wait
    )

    $OS = Get-VMOperatingSystem -VMName $VMName

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Install all $OS patches"

    if ($OS -eq 'Windows') {
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
        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText { c:\windows\temp\windowsUpdate.ps1 }
    } else {
        $scriptLinuxUpdate = 'yum check-update; yum upgrade -y'

        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $scriptLinuxUpdate -ScriptType Bash
    }
    if ($Wait) { Wait-ForVMTools -VMName $VMName }
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

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Join to Domain [$DomainName] and reboot"

    Copy-VMGuestFile -VM $VMName -Source $env:temp\addDomain.ps1 -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential

    Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText  { c:\windows\temp\addDomain.ps1 }

    Restart-VMGuest -VM $VMName -Confirm:$false

    if ($Wait) {
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Wait for VM Tools"
        Wait-ForVMTools -VMName $VMName
    }
}

function New-VirtualMachine {
    <#
        .SYNOPSIS
        Aggregator function, calls other functions to deploy VM. This is to make easier deploying a VM with one command

        .DESCRIPTION
        It will call, in sequence:
        Create-VM
        Initialize-VMTCPIP
        Initialize-VMDisks
        Set-VMTimeZone
        Start-VMUpdate
        Add-WindowsVMToDomain (if applicable)

        NOTE: It is assumed you're already connected to your vSphere

        NOTE2: if Domain Credentials are supplied it is assumed you're trying to build a Windows VM, whereas if they're not supplied then it's a Linux VM. You may force this by specifying the -Windows or -Linux parameters

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

    #[CmdletBinding(DefaultParameterSetName="Linux")]
    param (
        # New VM Name
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        # New VM IP Address
        [Parameter(Mandatory=$true)]
        [ValidateScript({($_ -match "(\d{1,3}\.){3}\d{1,3}") -or ($_ -eq "DHCP")})]
        [string]$IP,

        # Guest Credentials (Local Admin on the guest)
        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        # Domain Credentials (to add VM to Domain)
        [Parameter(Mandatory=$true,ParameterSetName="Windows")]
        [pscredential]$DomainCredential,

        # Assigned CPUs
        [ValidateSet(2,4,6)]
        [int]$NumCPU,

        # Assigned RAM
        [ValidateSet(4,8,16)]
        [int]$MemoryGB,

        # Number of additional disks (0 = Don't add disks, 1 = General Purpose (default), 4 = SQL)
        [ValidateSet(0,1,4)]
        [int]$AdditionalDisks = $Default_AdditionalDisks,

        # Default gateway, If none provided assume it's same as $IP but replacing last octet with .1
        [string]$Gateway,

        # Subnet Mask
        [string]$SubnetMask = "255.255.255.0",

        # DNS Server(s), defaults to all DCs in current site, randomized
        [string[]]$DNS,

        # Domain Name
        [string]$DomainName = ((Get-ADDomain).DNSRoot),

        # OU to add VM to
        [Parameter(ParameterSetName="Windows")]
        [string]$OUPath = ((Get-ADDomain).ComputersContainer -replace ("CN=Computers","OU=Servers")),

        # Time Zone
        [ValidateSet("Eastern","Central","Pacific","London","Zurich","HongKong")]
        [string]$TimeZone = "Eastern",

        #[switch]$Log = $True #,

        # Specify Windows VM
        [Parameter(ParameterSetName="Windows")]
        [switch]$Windows,

        # Specify Linux VM
        [Parameter(ParameterSetName="Linux")]
        [switch]$Linux
    )
    DynamicParam {
        # Fail if not connected to vSphere
        if (-not $global:DefaultVIServers) {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "You're not connected to any vSphere servers. Connect to vSphere then re-run this command. Abort"
            Throw
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
                #ValidateSet = (get-cluster $Cluster | Get-Datastore | Get-DatastoreCluster).Name | Sort
                ValidateSet = (Get-DatastoreCluster).Name | Sort #+ (Get-Datastore).Name) | Sort
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
        $PsBoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ErrorAction SilentlyContinue}

        # This is a workaround for -ErrorAction SilentlyContinue not working as expected
        # For Linux this is meaningless, but if you're trying to build a Linux VM in an environemnt that has an identically named Windows VM then you're crazy or dumb
        Try { $Test = Get-ADComputer $VMName }
            Catch { }

        if ($Test) {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "Active Directory Computer Name already exists. Aborting"
            Throw
        }

        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue ) {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "VM already exists. Aborting"
            Throw
        }

        $params = @{
            VMName = $VMName
            Cluster = $Cluster
            Datastore = $Datastore
            NetworkName = $NetworkName
            TechnicalOwner = $technicalOwner
            OperatingSystem = $operatingSystem
            AdditionalDisks = $AdditionalDisks
            Wait = $true
        }

        if ($NumCPU) {
            $params += @{
                NumCPU = $numCPU
            }
        }

        if ($memoryGB) {
            $params += @{
                MemoryGB = $memoryGB
            }
        }

        Create-VM @params

        Set-VMTimeZone -VMName $VMName -GuestCredential $GuestCredential -TimeZone $TimeZone

        $OS = Get-VMOperatingSystem -VMName $VMName

        if ($OS -eq "Linux") {
            Rename-LinuxVM -VMName $VMName -GuestCredential $guestCredential -DomainName $DomainName
        }

        if ($IP -ne "DHCP") {
            $params = @{
                VMName = $VMName
                GuestCredential = $GuestCredential
                IP = $IP
            }

            if ($SubnetMask) {
                $params += @{
                    SubnetMask = $subnetMask
                }
            }
            if ($Gateway) {
                $params += @{
                    Gateway = $Gateway
                }
            }
            if ($DNS) {
                $params += @{
                    DNS = $DNS
                }
            }

            Initialize-VMTCPIP @params
        }

        Initialize-VMDisks -VMName $VMName -GuestCredential $GuestCredential

        if ($domainName -ne 'strozllc.com') {
            Start-VMUpdate     -VMName $VMName -GuestCredential $GuestCredential
        } else {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Skip patching in strozllc.com -- no access to patch repositories. Crazy!"
        }

        if ($OS -eq "Windows") {
            Add-WindowsVMToDomain -VMName $VMName -GuestCredential $GuestCredential -DomainCredential $DomainCredential `
                -DomainName $DomainName -OUPath $OUPath -Wait
        }

    Write-Status -VMName $VMName -Severity "SUCCESS" -Operation "VM built"
    }
}

Export-ModuleMember -Function * -Alias *