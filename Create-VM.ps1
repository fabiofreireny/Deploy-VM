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

        # Hard disk size
        [int]$hardDiskSize,

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
        $PsBoundParameters.GetEnumerator() | % { New-Variable -Name $_.Key -Value $_.Value -ErrorAction SilentlyContinue }

        # This is a workaround for -ErrorAction SilentlyContinue not working as expected on Get-ADComputer
        # For Linux this is meaningless, but if you're trying to build a Linux VM in an environemnt that has an identically named Windows VM then you're incurring technical debt
        Try { $Test = Get-ADComputer $VMName }
            Catch { }

        if ($Test) {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "Active Directory Computer Name already exists. Aborting"
            Throw
        }

        # make sure you are connected to the correct vCenter
        Connect-VCenter -Cluster $Cluster

        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue ) {
            Write-Status -VMName $VMName -Severity 'FATAL' -Operation "VM already exists. Aborting"
            Throw
        }

        $imageName = ($validOS | ? Name -eq $operatingSystem).ImageName

        $contentLibraryItem = Get-ContentLibraryItem $imageName
        if ($contentLibraryItem.count -ne 1) {
            $contentLibraryItem = Get-ContentLibraryItem $imageName | ? ContentLibrary -match 'Master'
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
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Deploy VM from Template [$imageName]"
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
        try {
            Get-NetworkAdapter -VM $VMName | Set-NetworkAdapter -NetworkName $NetworkName -confirm:$false
        } catch {
            Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Failed to map VM to [$NetworkName]"
        }

        # Assign Tag(s)
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign Tag(s) [$technicalOwner][$businessOwner][$businessUnit]"

        New-TagAssignment -Tag (Get-Tag | Where {($_.Category.Name -eq "Technical Owner") -and ($_.Name -eq $TechnicalOwner)} | Select -Unique ) -Entity $VMName

        if ($BusinessOwner) {
            New-TagAssignment -Tag (Get-Tag | Where {($_.Category.Name -eq "Business Owner") -and ($_.Name -eq $businessOwner)} | Select -Unique ) -Entity $VMName
        }

        if ($BusinessUnit) {
            New-TagAssignment -Tag (Get-Tag | Where {($_.Category.Name -eq "Business Unit") -and ($_.Name -eq $businessUnit)} | Select -Unique ) -Entity $VMName
        }

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
        try {
            $diskSize = 100
            $index = 1
            While ($index -le $AdditionalDisks) {
                Write-Status -VMName $VMName -Severity 'INFO' -Operation "Add Disk [$index] with capacity $($diskSize)GB"
                New-HardDisk -StorageFormat Thin -CapacityGB $diskSize -VM $VM
                $index ++
            }
        } catch {
            Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Failed to add hard drive(s)"
        }

        # Add Custom Attributes (Annotations) and Notes
        $bornOn = get-date
        $expiresOn = 'Not Applicable'
        $fromTemplate = $contentLibraryItem
        $Requestor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign Custom Attributes [$bornOn][$expiresOn][$FromTemplate][$Requestor]"

        # If attribute assignment fails then create attributes and re-try once
        try {
            $VM | Set-Annotation -CustomAttribute "BornOn" -Value $bornOn -ErrorAction SilentlyContinue
            $VM | Set-Annotation -CustomAttribute "ExpiresOn" -Value $expiresOn
            $VM | Set-Annotation -CustomAttribute "FromTemplate" -Value $fromTemplate
            $VM | Set-Annotation -CustomAttribute "Requestor" -Value $Requestor
        } catch {
            try {
            Create-CustomAttributes
            $VM | Set-Annotation -CustomAttribute "BornOn" -Value $bornOn
            $VM | Set-Annotation -CustomAttribute "ExpiresOn" -Value $expiresOn
            $VM | Set-Annotation -CustomAttribute "FromTemplate" -Value $fromTemplate
            $VM | Set-Annotation -CustomAttribute "Requestor" -Value $Requestor
            } catch {
                Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Failed to assign Custom Attributes"
            }
        }

        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Assign Notes [$Notes]"
        $VM | Set-VM -Description $Notes -Confirm:$False

        # Power On
        if (-not $DontPowerOn) {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Power On"
            Start-VM $VM
        }

        $toolsStatus = $VM.guest.extensiondata.ToolsVersionStatus

        switch ($toolsStatus) {
            guestToolsCurrent {
                Write-Status -VMName $VMName -Severity 'INFO' -Operation "VM Tools already up to date. Skip"
            }
            guestToolsUnmanaged {
                Write-Status -VMName $VMName -Severity 'INFO' -Operation "VM Tools is client managed. Skip"
            }
            guestToolsNeedUpgrade {
                Write-Status -VMName $VMName -Severity 'INFO' -Operation "Update VM Tools"
                Update-Tools -VM $VMName
                Start-Sleep -Seconds 40
            }
        }

        if ($wait) {
            Wait-ForVMTools -VMName $VMName
        }
    }
}