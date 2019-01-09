#$SQLImageName = 'SQLServer2016SP1-FullSlipstream-x64-ENU-DEV.iso'
$SQLImageName = 'SW_DVD9_NTRL_SQL_Svr_Ent_Core_2016w_SP1_64Bit_English_OEM_VL_X21-22132.ISO'
$SQLImage = Get-ContentLibraryItem -Name $SQLImageName

# There's no way to programatically mount a CD image onto an existing CD drive, so I must create a new one
# Must Power off VM to create drive and mount... sigh...
Stop-VM -VM $VMName -Confirm:$false
Get-VM -Name $VMName | New-CDDrive -ContentLibraryIso $SQLImage -Confirm:$false
Start-VM -VM $VMName
Wait-ForVMTools -VMName $VMName

# This need to be run as local admin on the client computer, but only once
# POWERSHELL 6!!!
# Enable-WSManCredSSP -Role Client -DelegateComputer *
#Connect-WSMan $VMName
#Set-Item WSMan:\$($VMName)*\Service\Auth\CredSSP -Value $True

#Enable-WSManCredSSP -Role Server

#need to allow server for delegation... (how to do in command line??)
$Session = New-PSSession -ComputerName $VMName -Credential $domainCredential #-Authentication CredSSP

Copy-Item -Path installSQL.ps1          -ToSession $Session -Destination c:\temp
Copy-Item -Path StrozDefaultInstall.ini -ToSession $Session -Destination c:\temp

# Here's a trick to avoid kerberos double hop. DOESNT WORK!!!! THIS SUCKS!!!
write-output "1"
Invoke-Command -Session $Session <#-Authentication CredSSP -Credential $domainCredential#> -ScriptBlock {
    cd c:\Temp
    write-output "2"
    #.\installSQL.ps1 -Edition "Express"
    Invoke-Command -Credential $using:domainCredential -ComputerName localhost -ScriptBlock { write-output "3"; c:\temp\installSQL.ps1 -Edition "Express" }
}

Get-PSSession | Remove-PSSession

Stop-VM -VM $VMName -Confirm:$false
Get-VM -Name $VMName | Get-CDDrive | Where { $_.IsoPath } | Remove-CDDrive -Confirm:$false
Start-VM -VM $VMName
Wait-ForVMTools -VMName $VMName

Start-WindowsVMUpdate -VMName $VMName -GuestCredential $guestCredential
Wait-ForVMTools -VMName $VMName