function Initialize-VMDisks {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [pscredential]$GuestCredential,

        [ValidateSet("Windows","Linux")]
        [string]$OperatingSystem = (Get-VMOperatingSystem -VMName $VMName)
    )

    # Find out how many disks in VM
    $NumDisks = (Get-VM -Name $VMName | Get-Harddisk).count

    if ($OperatingSystem -eq 'Windows') {
        # DISKPART commands
        $diskpartCD = @'
            REM Change CD drive letter
            select volume 0
            assign letter=r
'@

        $diskpartDATA = @'
            REM Configure DATA drive
            select disk 1
            online disk
            attrib disk clear readonly
            create partition primary
            select partition 1
            assign letter=d
            format fs=ntfs quick label="DATA"
'@

        $diskpartSQL = @'
            REM Configure SQL Database drive
            select disk 2
            online disk
            attrib disk clear readonly
            create partition primary
            select partition 1
            assign letter=e
            format fs=ntfs quick label="Database"

            REM Configure SQL Log drive
            select disk 3
            online disk
            attrib disk clear readonly
            create partition primary
            select partition 1
            assign letter=l
            format fs=ntfs quick label="Logs"

            REM Configure SQL TEMP drive
            select disk 4
            online disk
            attrib disk clear readonly
            create partition primary
            select partition 1
            assign letter=t
            format fs=ntfs quick label="TEMP"
'@

        $diskpartBatchFile = @'
            diskpart /s C:\Windows\temp\diskpart.txt

            If (!(Test-Path c:\Scripts)) { mkdir c:\Scripts }
            If (!(Test-Path c:\Install)) { mkdir c:\Install }
            If (!(Test-Path c:\Temp   )) { mkdir c:\Temp }

            Get-ChildItem c:\users\rearm.cmd -Recurse -Force -ErrorAction SilentlyContinue | % { Remove-Item $_ -Force }
'@

        switch ($NumDisks) {
            1 { Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found 1 disk (Special)"
                $diskpartCommands = $diskpartCD
            }
            2 { Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found 2 disks (General)"
                $diskpartCommands = $diskpartCD + "`n" + $diskpartDATA
            }
            5 { Write-Status -VMName $VMName -Severity 'INFO' -Operation "Found 5 disks (SQL)"
                $diskpartCommands = $diskpartCD + "`n" + $diskpartDATA + "`n" + $diskpartSQL
            }
        }

        # Dealing with DOS idiosyncrasies
        $diskpartCommands.split("`r`n").trim() | out-file $env:temp\diskpart.txt -Force -Encoding ASCII

        Write-Status -VMName $VMName -Severity 'INFO' -Operation "Configure [$NumDisks] disk(s)"

        # Change drive letters. This is done inside Windows, thus the need for it to be powered on and the guest credentials
        Copy-VMGuestFile -VM $VMName -Source $env:temp\diskpart.txt -Destination c:\Windows\Temp -Force -LocalToGuest -GuestCredential $guestCredential

        Invoke-VMScript -VM $VMName -GuestCredential $guestCredential -ScriptText $diskpartBatchFile
    }

    if ($OperatingSystem -eq 'Linux') {
        $disks = @('sdb','sdc','sdd','sde','sdf')

        for ($i=0; $i -lt ($NumDisks-1); $i++) {
            $disk = $disks[$i]

            $scriptText = @"
                parted /dev/$disk mklabel msdos;
                parted -a optimal /dev/$disk mkpart primary 0% 100%;

                pvcreate /dev/$($disk)1;
                vgcreate vg_$($disk)1 /dev/$($disk)1;
                lvcreate -n lv_$($disk)1 --extents 100%FREE vg_$($disk)1;

                mkfs.ext4 /dev/vg_$($disk)1/lv_$($disk)1;

                echo "/dev/vg_$($disk)1/lv_$($disk)1 /mnt/$($disk)1                  ext4    defaults        1 2" >> /etc/fstab;

                mkdir /mnt/$($disk)1;
                mount -a;
"@

            [string]$scriptText = ($scriptText.split("`n").trim())

            $scriptText

            Write-Status -VMName $VMName -Severity 'INFO' -Operation "Configure disk [/dev/$disk]"

            Invoke-VMScript -VM $VMName -GuestCredential $GuestCredential -ScriptText $scriptText -ScriptType Bash
        }
    }
}
