# InstallSQL.ps1 for SQL 2016

param (
	[Parameter(Mandatory=$true)]
	[ValidateSet("Developer","Express","Standard")]
	[String]$Edition,

	[string]$svcUsername,
	[string]$svcPassword
)

$Source     = $pwd
$DomainName = "strozllcpublic" #(get-addomain).NetBIOSName

# Find where SQL CD is mounted
$CD = (Get-PSDrive -PSProvider FileSystem | Where { Test-Path "$($_.Root)\Setup.exe" }).Root
#Push-Location $CD

switch ($Edition) {
	"Developer" {$sqlpid="22222-00000-00000-00000-00000"}
	"Express"   {$sqlpid="11111-00000-00000-00000-00000"}
	"Standard"  {$sqlpid="B9GQY-GBG4J-282NY-QRG4X-KQBCR"}
#    "Enterprise" {$sqlpid="748RB-X4T6B-MRM7V-RTVFF-CHC8H"} #PID not SQL 2016
}

if (!(Test-Path "D:\") -or !(Test-Path "F:\") -or !(Test-Path "L:\") -or !(Test-Path "T:\")) {
	"D:, F:, L: and T: drives are required for all installations"
	Break
}

$InstallString = "$($CD)\Setup.exe /CONFIGURATIONFILE=$Source\StrozDefaultInstall.ini /PID=""$sqlpid"" /SQLSYSADMINACCOUNTS=""$DomainName\SQLAdmins"" ""$DomainName\ffreire"""

if ($Edition -ne "Express") {
	$InstallString += " /AGTSVCACCOUNT=""$DomainName\$svcUsername"" /AGTSVCPASSWORD=""$svcPassword"""
}

if ($svcUsername) {
	net localgroup administrators $DomainName\$svcUsername /add
	$InstallString += " /SQLSVCACCOUNT=""$DomainName\$svcUsername"" /SQLSVCPASSWORD=""$svcPassword"""
}

Invoke-Expression $InstallString

Pop-Location

#Patching...
#Not working currently. Seems like it needs a reboot first
#Install-WindowsUpdate -MicrosoftUpdate -AutoReboot -AcceptAll -Install

#Clean up permissions that somehow get screwy
#$nada = icacls d:\* /reset /t
#sleep -seconds 1
#cmd /c rmdir "D:\`$RECYCLE.BIN" /s /q