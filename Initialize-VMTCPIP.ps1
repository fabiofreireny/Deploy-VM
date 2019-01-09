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
        [switch]$Force = $false,

        [ValidateSet("Windows","Linux")]
        [string]$OperatingSystem = (Get-VMOperatingSystem -VMName $VMName)
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
        # Append root DNS if not already there
        if ($DNS -notContains $rootDNS) { $DNS += $rootDNS }
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
        #if (Get-NetIPAddress) { Remove-NetIPAddress -IPAddress $IP -Confirm:0 }
        Get-NetAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IP -PrefixLength $($IPMagic.CIDR) -Type Unicast -DefaultGateway $Gateway
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $($DNS -join ",")
"@

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Configure IP with IP = $IP/$($IPMagic.CIDR), Gateway = $Gateway, DNS = ($DNS)"

    if ($OperatingSystem -eq 'Windows') {
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
            ScriptType = "Bash"
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
