Set-Variable Default_NumCPU   -Option Constant -Value 2
Set-Variable Default_MemoryGB -Option Constant -Value 4
Set-Variable Default_AdditionalDisks -Option Constant -Value 1

Set-Alias -name New-WindowsVM -Value New-VirtualMachine
Set-Alias -name New-LinuxVM   -Value New-VirtualMachine

Clear-Variable transcriptPath -Scope script -ErrorAction SilentlyContinue
Clear-Variable withErrors     -Scope script -ErrorAction SilentlyContinue

$gambrinusSQL                        = "NYCGAMBRINUS01"
$gambrinusDB                         = "Gambrinus"
$gambrinusEnvironmentLookupTable     = "VMware_Lookup-Environment"
$gambrinusTagLookupTable             = "VMware_Lookup-Tags"
$gambrinusvalidOSTable               = "VMWare_Lookup-OperatingSystemImages"

# Used by Dynamic Parameters in Create-VM and New-VirtualMachine. The account the script runs under must have datareader on these tables
$validEnvironment = Invoke-Sqlcmd -ServerInstance $gambrinusSQL -Database $gambrinusDB -Query "SELECT * FROM [$gambrinusEnvironmentLookupTable]"
$validTags        = Invoke-Sqlcmd -ServerInstance $gambrinusSQL -Database $gambrinusDB -Query "SELECT * FROM [$gambrinusTagLookupTable]"
$validOS          = Invoke-Sqlcmd -ServerInstance $gambrinusSQL -Database $gambrinusDB -Query "SELECT * FROM [$gambrinusvalidOSTable]"

# The account the script runs under must also have datawriter on the History table

<#
# Uncomment this if not using SQL to lookup O/S
$validOS = @{
    Server2012r2   = "template-Server2kr2-vAutomation"
    Server2016     = "Server2016-vAutomation"
    Server2016Core = "Server2016Core-vAutomation"
    CentOS7        = "CentOS7-vAutomation"
    Windows10      = "Windows10.1803-vAutomation"
}#>

# Make sure you are connected to a vCenter!! Create-VM and New-VirtualMachine use Dynamic Parameters.
# If you're not connected these parameters can't find out what their valid values are and won't even display.

# Images *must* have VMware Tools pre-installed. You will be able to deploy an image and not much else unless VMTools is running

# If you deploy VMs to remote offices over slow links, consider running the command below before connecting to vCenter, to avoid timeouts:
# Set-PowerCLIConfiguration -Scope Session -WebOperationTimeoutSeconds 3600 -Confirm:$false

. $PSScriptRoot\Add-WindowsVMToDomain.ps1
. $PSScriptRoot\Create-VM.ps1
. $PSScriptRoot\Initialize-VMDisks.ps1
. $PSScriptRoot\Initialize-VMTCPIP.ps1
. $PSScriptRoot\New-VirtualMachine.ps1
. $PSScriptRoot\Register-VMDNS.ps1
. $PSScriptRoot\Rename-LinuxVM.ps1
. $PSScriptRoot\Set-VMTimeZone.ps1
. $PSScriptRoot\Start-VMUpdate.ps1

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
        [ValidateSet('FATAL','ERROR','WARNING','INFO','VERBOSE','COMPLETE')]
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

    if (!$script:transcriptPath) {
        $script:transcriptPath = "$($env:temp)\deploy-vm_$VMName_$TimestampLog.log"

        if (!(Test-Path $script:transcriptPath)) {
            Start-Transcript $script:transcriptPath
        }
    }

    switch ($Severity) {
        INFO     { $backgroundColor = 'DarkGreen' }
        ERROR    { $backgroundColor = 'Red'
                   $script:WithErrors = $True
                 }
        FATAL    { $backgroundColor = 'Magenta'
                   if (Test-Path $script:transcriptPath) {
                    Stop-Transcript
                    Clear-Variable transcriptPath -Scope script
                  }
                 }
        VERBOSE  { $backgroundColor = 'Blue'}
        COMPLETE { $backgroundColor = 'Blue'
                   Stop-Transcript
                   Clear-Variable transcriptPath -Scope script
                   if ($script:WithErrors) {
                       Clear-Variable withErrors -Scope script
                       $backgroundColor = 'Yellow'
                       $Severity = 'WARNING'
                       $Operation += ' with ERRORS'
                   }
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
#                if ($($validOS.$operatingSystem) -match 'CentOS') {
                    $VMOperatingSystem = 'Linux'
                } else {
                    Write-Status -VMName $VMName -Severity 'FATAL' -Operation "Cannot determine O/S of guest VM. Aborting"
                    Throw
                }
            }
        }
    #}
    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Operating System is [$VMOperatingSystem]"

    $VMOperatingSystem
}

function Connect-VCenter {
    # Find out which vCenter I need to connect to based on Cluster name
    # For this to work Cluster names must be unique across environment
    # This relies on the same SQL table used for parameter validation
    param (
        [Parameter(Mandatory=$true)]
        [string]$Cluster
    )

    $vCenter = (Invoke-Sqlcmd -ServerInstance $gambrinusSQL -Database $gambrinusDB -Query "SELECT DISTINCT [vCenter] FROM [$gambrinusEnvironmentLookupTable] WHERE [Cluster] = '$Cluster'").vCenter

    if (!$vCenter) {
        Write-Status -VMName $VMName -Severity 'FATAL' -Operation "Unable to find vCenter for Cluster [$CLuster]"
        throw
    }

    $global:connectedVCenters = $global:DefaultVIServers

    if (($global:connectedVCenters).Name -eq $vCenter) {
        Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Already connected to vCenter [$vCenter]"
    } else {
        if ($global:connectedVCenters) {
            Disconnect-VIServer -Server * -Confirm:$false
        }

        Write-Status -VMName $VMName -Severity 'VERBOSE' -Operation "Connect to vCenter [$vCenter]"
        try {
            Connect-VIServer -Server $vCenter -ErrorAction Stop
        } catch {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "Unable to connect to vCenter [$vCenter]. Abort"
            Throw
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

Export-ModuleMember -Function * -Alias *