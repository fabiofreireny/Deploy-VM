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
    #requires -module SqlServer

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
        [string]$TimeZone,

        # Notes to be added to VM
        [string]$Notes,

        #[switch]$Log = $True #,

        # Specify Windows VM
        [Parameter(ParameterSetName="Windows")]
        [switch]$Windows,

        # Specify Linux VM
        [Parameter(ParameterSetName="Linux")]
        [switch]$Linux
    )
    DynamicParam {

        # Define dynamic parameters. If defining multiple it's simpler to create an array first
        # Validation is done by consulting a SQL database. If not using SQL then replace the ValidateSet lines with commented versions
        # Commented ValidateSet will retrieve directly from VMware (you must be logged into vCenter for this to work) and is slower then the SQL lookup
        $DynamicParameters = @(
            @{
                Name = "Cluster"
                Type = [string]
                Position = 1
                Mandatory = $true
                ValidateSet = ($validEnvironment).Cluster | Select -Unique | Sort
                #ValidateSet = (Get-Cluster).Name | Sort
            },
            @{
                Name = "Datastore"
                Type = [string]
                Position = 2
                Mandatory = $true
                ValidateSet = ($validEnvironment).Datastore | Select -Unique | Sort
                #ValidateSet = (Get-DatastoreCluster).Name | Sort
            },
            @{
                Name = "NetworkName"
                Type = [string]
                Position = 3
                Mandatory = $true
                ValidateSet = ($validEnvironment).NetworkName | Select -Unique | Sort
                #ValidateSet = (get-virtualportgroup).Name | select -Unique | Sort
            },
            @{
                Name = "TechnicalOwner"
                Type = [string]
                Position = 4
                Mandatory = $true
                ValidateSet = ($validTags | ? Category -match 'Technical Owner').Name | Select -Unique | Sort
                #ValidateSet = (Get-Tag | Where {$_.Category.Name -eq 'Technical Owner'}).Name | Sort
            },
            @{
                Name = "BusinessOwner"
                Type = [string]
                Position = 5
                Mandatory = $false
                ValidateSet = ($validTags | ? Category -match 'Business Owner').Name | Select -Unique | Sort
                #ValidateSet = (Get-Tag | Where {$_.Category.Name -eq 'Business Owner'}).Name | Sort
            },
            @{
                Name = "BusinessUnit"
                Type = [string]
                Position = 6
                Mandatory = $false
                ValidateSet = ($validTags | ? Category -match 'Business Unit').Name | Select -Unique | Sort
                #ValidateSet = (Get-Tag | Where {$_.Category.Name -eq 'Business Unit'}).Name | Sort
            },
            @{
                Name = "OperatingSystem"
                Type = [string]
                Position = 7
                Mandatory = $true
                ValidateSet = ($validOS).Name | Select -Unique | Sort
                #ValidateSet = ($validOS).Keys | Sort
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

        $params = @{
            VMName          = $VMName
            Cluster         = $Cluster
            Datastore       = $Datastore
            NetworkName     = $NetworkName
            TechnicalOwner  = $technicalOwner
            OperatingSystem = $operatingSystem
            AdditionalDisks = $AdditionalDisks
            #Wait            = $true
        }

        if ($businessOwner) {
            $params += @{
                BusinessOwner = $businessOwner
            }
        }

        if ($businessUnit) {
            $params += @{
                BusinessUnit = $businessUnit
            }
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

        if ($notes) {
            $params += @{
                Notes = $notes
            }
        }

        Create-VM @params

        $OperatingSystem = Get-VMOperatingSystem -VMName $VMName

        if ($Timezone) {
            Set-VMTimeZone -VMName $VMName -GuestCredential $GuestCredential -TimeZone $TimeZone -OperatingSystem $OperatingSystem
        } else {
            Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Skip Time Zone configuration. Using image default"
        }

        if ($OperatingSystem -eq "Linux") {
            Rename-LinuxVM -VMName $VMName -GuestCredential $guestCredential -DomainName $DomainName -OperatingSystem $OperatingSystem
            if ($IP -ne 'DHCP') {
                Register-VMDNS -VMName $VMName -DomainName $DomainName -IP $IP
            }
        }

        if ($IP -ne "DHCP") {
            $params = @{
                VMName = $VMName
                GuestCredential = $GuestCredential
                IP = $IP
                OperatingSystem = $operatingSystem
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
        } else {
            Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Skip TCP/IP configuration. DHCP specified"
        }

        Initialize-VMDisks -VMName $VMName -GuestCredential $GuestCredential -OperatingSystem $operatingSystem

        if ($domainName -ne 'strozllc.com') {
            Start-VMUpdate     -VMName $VMName -GuestCredential $GuestCredential -OperatingSystem $operatingSystem -Wait
        } else {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Skip patching in strozllc.com -- no access to patch repositories. Crazy!"
        }

        if ($OperatingSystem -eq "Windows") {
            Add-WindowsVMToDomain -VMName $VMName -GuestCredential $GuestCredential -DomainCredential $DomainCredential `
                -DomainName $DomainName -OUPath $OUPath -Wait
        }

        Write-Status -VMName $VMName -Severity "COMPLETE" -Operation "VM built"
    }
}
