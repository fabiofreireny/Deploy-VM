function Set-VMTimeZone {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Eastern","Central","Pacific","London","Zurich","HongKong")]
        [string]$TimeZone,

        [ValidateSet("Windows","Linux")]
        [string]$OperatingSystem = (Get-VMOperatingSystem -VMName $VMName)
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

    #$OS = Get-VMOperatingSystem -VMName $VMName

    Write-Status -VMName $VMName -Severity 'INFO' -Operation "Set time zone to [$TimeZone]"

    if ($OperatingSystem -eq "Windows") {
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
