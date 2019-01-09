# Deploy-VM
Module to assist in building VMware VMs
Requires PowerCLI and ActiveDirectory Powershell modules

**I need to update this documentation, but if you happen to stmuble upon this be advised I've made massive changes in the code. For one I can now build CentOS and Windows10 VMs. It is also much more resilient and does better logging/auditing. Because I use this in conjunction with Jenkins (for a front-end) there are things I'm storing in SQL tables that will be used by my script and Jenkins, with a separate script used to populate the tables.**

Module is comprised of the following functions. Use get-help for details

`Create-VM -VMName <String> -Cluster <String> -Datastore <String> -NetworkName <String> -TechnicalOwner <String> -OperatingSystem <String> [-NumCPU <Int32>] [-MemoryGB <Int32>] [-AdditionalDisks <Int32>] [-Wait]`

Creates a VMware VM from a template. Note that this function uses Dynamic Parameters, which means you **must** be logged into vCenter before running it, otherwise some mandatory parameters won't even show up and the script will fail. I tried to make it as foolproof as possible but you'd still need to run the command before realizing you're not connected. If you know of a better way please help!

`Configure-WindowsVMTCPIP [-VMName] <string> [-IP] <string> [-GuestCredential] <pscredential> [[-DNS] <string[]>] [[-SubnetMaskCIDR] <int>] [[-Gateway] <string>]`

Configures TCP/IP remotely. The magic is that at this point the VM is not on the network! It also has "intelligent" defaults for DNS (all DCs in current site, randomized) and the default gateway (replace last octet with '1')

`Initialize-WindowsVMDisks [-VMName] <string> [-GuestCredential] <pscredential>`

This probably needs customization for your environment. In my environment, CD drives are R:, Data is D:, SQL Log, Swap and Temp are L, S: and T:, respectively. based on the number of disks you specified when you created your VM it assume its role and assigns drive letters and labels. It also creates some standard folders c:\Temp, c:\Scripts and c:\Install

`Set-WindowsVMTimeZone [-VMName] <string> [-GuestCredential] <pscredential> [-TimeZone] {Eastern Standard Time | Pacific Standard Time | Central Standard Time | GMT Standard Time | W. Europe Standard Time | China Standard Time}`

Configures Time Zone. Edit the ValidateSet with valid values for your environment. Use 'tzutil /l' to list possible options. I didn't use dynamic parameters here because I don't want to retrieve every available time zone, only the ones where I have offices

`Start-WindowsVMUpdate [-VMName] <string> [-GuestCredential] <pscredential>`

Installs all available Windows Updates (from Microsoft) and reboot VM. If you have a WSUS server adjust this. It uses the PSWindowsUpdate module which it will try to install if not found. It also requires Powershell 5.1 or greater which you should pre-install in your image

`Add-WindowsVMToDomain [-VMName] <string> [-GuestCredential] <pscredential> [-DomainCredential] <pscredential> [[-DomainName] <string>] [[-OUPath] <string>] [-Wait]`

Renames VM (from self-assigned name), reboots, adds it to Domain, then reboots again. Note that there is a slight security deficiency here as domain credentials are stored in a plain text file for a brief moment, then deleted. There is a chance the delete could fail and the credentials be exposed. To mitigate you should use an account that can only add machines to domain, never domain admin

`New-WindowsVM [-VMName] <String> -Cluster <String> -Datastore <String> -NetworkName <String> -TechnicalOwner <String> -OperatingSystem <String> [-IP] <String> [-DomainCredential] <PSCredential> [-GuestCredential] <PSCredential> [[-NumCPU] <Int32>] [[-MemoryGB] <Int32>] [[-AdditionalDisks] <Int32>] [[-Gateway] <String>] [[-SubnetMaskCIDR] <String>] [[-DNS] <String[]>] [[-DomainName] <String>] [[-OUPath] <String>] [[-TimeZone] <String>]`

This is an aggregator function (if such a term exists). It takes all parameters required by the other functions and calls them, one by one. It essentially is a one-liner to deploy a VM, soup-to-nuts.
This command also used Dynamic Parameters, thus the warning above also applies

Note: that you'll need to edit the module with the VMware template names in your environment

My recommendation is that the VMware image that you create have these characteristics:
- Install all available Windows Updates (this will speed up deployment)
- Pre-install Powershell 5.1 (https://www.microsoft.com/en-us/download/details.aspx?id=54616)
- Pre-install NuGet (Install-Module NuGet -Force)
- Pre-install PSWindowsUpdate (Install-Module PSWindowsUpdate -Force)
- Pre-install VMware Tools (required)
- Sysprep

