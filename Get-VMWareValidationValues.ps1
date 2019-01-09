#requires -module SqlServer
#requires -module VMware.VimAutomation.Core

$gambrinusSQL                        = "NYCGAMBRINUS01"
$gambrinusDB                         = "Gambrinus"
$gambrinusEnvironmentValidationTable = "VMware_Lookup-Environment"
$gambrinusTagValidationTable         = "VMware_Lookup-Tags"
$tempFile                            = "$($env:temp)\tempResults.csv"

$results = @()

$datastoreExceptions = @(
    "HeartBeat",
    "Boot",
    "datastore",
    "localdisk"
)

$NetworkExceptions = @(
    "vmservice",
    "vMotion",
    #"Management",
    "Null",
    "Uplink",
    "Heartbeat"
)

$vCenters = @(
    @{
        Location = "NewYorkCity"
        Server   = "nycvcsa01.strozllc.public"
    },
    @{
        Location = "Hawthorne"
        Server   = "nyhvcsa01.strozllc.public"
    },
    @{
        Location = "Byfleet"
        Server   = "byfvcsa01.strozllc.public"
    },
    @{
        Location = "Maidstone"
        Server   = "mdsvcsa01.strozllc.public"
    },
    @{
        Location = "Boston"
        Server   = "bosvcsa01.strozllc.public"
    }
)

$vCenters | % {
    $vCenter = $_

    if ($global:DefaultVIServers) {
        Disconnect-VIServer * -Confirm:$false
    }

    Connect-VIServer $vCenter.Server -Force

    $Datacenters = Get-Datacenter
    $Datacenters | % {
        $Datacenter = $_

        $Networks = Get-VDSwitch -Location $Datacenter | Get-VDPortGroup | ? Name -NotMatch ($NetworkExceptions -join "|")

        $Clusters = Get-Cluster -Location $Datacenter
        $Clusters | % {
            $Cluster = $_

            $Datastores = $Cluster | Get-Datastore | Get-DatastoreCluster | ? Name -NotMatch ($datastoreExceptions -join "|")
            if (!$Datastores) {
                $Datastores = $Cluster | Get-Datastore | ? Name -NotMatch ($datastoreExceptions -join "|")
            }
            $Datastores | % {
                $Datastore = $_

                $Networks | % {
                    $Network = $_
                    $results += ($vCenter.Server, $Datacenter.Name, $Cluster.Name, $Datastore.Name, $Network.Name) -join ","
                }
            }
        }
    }
}

$results = $results | select -Unique | Out-File -FilePath $tempFile -Force

Invoke-Sqlcmd -ServerInstance $GambrinusSQL -Database $GambrinusDB -Query "DELETE FROM [$GambrinusEnvironmentValidationTable]"
Invoke-Sqlcmd -ServerInstance $GambrinusSQL -Database $GambrinusDB -Query "BULK INSERT [$GambrinusEnvironmentValidationTable] FROM '$tempFile' WITH ( FIELDTERMINATOR = ',', ROWTERMINATOR = '\n')"

# Populate Tags
$Tags = Get-Tag | Select Category, Name | Sort Category, Name
$Tags | % { Write-Output "$($_.Name),$($_.Category.Name)" } | Out-File -FilePath $tempFile -Force

Invoke-Sqlcmd -ServerInstance $GambrinusSQL -Database $GambrinusDB -Query "DELETE FROM [$GambrinusTagValidationTable]"
Invoke-Sqlcmd -ServerInstance $GambrinusSQL -Database $GambrinusDB -Query "BULK INSERT [$GambrinusTagValidationTable] FROM '$tempFile' WITH ( FIELDTERMINATOR = ',', ROWTERMINATOR = '\n')"
