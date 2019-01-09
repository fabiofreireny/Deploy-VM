function Register-VMDNS {
    # Assumes the userid this command runs under has access to modify DNS!
    #requires -module ActiveDirectory
    # #requires -module DnsServer
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [string]$domainName,

        [ValidatePattern("(\d{1,3}\.){3}\d{1,3}")]
        [string]$IP
    )

    # Find Domain Controller (i.e. DNS server)
    $DC = (Get-ADDomainController).Name

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Register [$VMName.$DomainName] with IP [$IP] in DNS at [$DC]"

    # Check for pre-existing records
    $ARecord = Resolve-DNSName -Name "$VMName.$DomainName" -ErrorAction SilentlyContinue
    $PTRRecord = Resolve-DNSName -Name $IP -Type PTR -ErrorAction SilentlyContinue

    if ($ARecord)   {
        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found existing A Record [$($ARecord.Name), $($ARecord.IPAddress)]. Removing"
        Remove-DnsServerResourceRecord -Name $VMName -ZoneName $DomainName -RRType A -ComputerName $DC -Force
    }

    if ($PTRRecord) {
        $PTRRecord | % {
            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found existing PTR Record [$($_.NameHost), $($_.Name)]. Removing"
            $Name = ($_.Name).split(".")[0]
            $ZoneName = ($_.Name).split(".",2)[1]
            Remove-DnsServerResourceRecord -Name $Name -ZoneName $ZoneName -RRType PTR -ComputerName $DC -Force
        }
    }

    try {
        Add-DnsServerResourceRecordA -Name $VMName -ZoneName $DomainName -AllowUpdateAny -IPv4Address $IP -CreatePtr -ComputerName $DC
    } catch {
        Write-Status -VMName $VMName -Severity 'ERROR' -Operation "Failed to register [$VMName] with IP [$IP] in DNS at [$DC]"
        $Error | Select -First 1
    }
}
