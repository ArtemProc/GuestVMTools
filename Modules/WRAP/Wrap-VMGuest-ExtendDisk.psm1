Function Wrap-VMGuest-ExtendDisk {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"
  write-log -message "Building Disk List"
  [array]$Disksobj = $null
  $Vars.VMDetail.vm_disk_info | where {$_.is_cdrom -eq $false -and $_.disk_address.device_bus -eq "SCSI"} | % {
    $custom = New-Object -Type PSObject
    $custom | add-member NoteProperty BusID $_.disk_address.device_index
    $custom | add-member NoteProperty BusType $_.disk_address.device_bus
    $custom | add-member NoteProperty SizeGB ([decimal]$_.size / 1024 / 1024 / 1024)
    $custom | add-member NoteProperty UUID $_.disk_address.vmdisk_uuid
    [array]$Disksobj += $custom
  }
  $GridArguments = @{
    OutputMode = 'Single'
    Title      = 'Select the SCSI Disk to extend and click OK'
  }
  $Disk = ($Disksobj | Out-GridView @GridArguments)
  
  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [int]$NewSizeGB = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the new disk size in GB", "Add Disk.", "$($Disk.sizeGB)")
  if ($NewSizeGB -lt $Disk.sizeGB){
    do {
      $NewSizeGB = [Microsoft.VisualBasic.Interaction]::InputBox("Disksize has to be higher then $sizeGB GB.", "Disk Size", "$($Disk.sizeGB)")
    } until ($NewSizeGB -ge $Disk.sizeGB)
  }
  
  write-log -message "Adding Disk"
  
  $task = REST-VM-Change-Disk-Size-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -VMDetail $vars.VMDetail `
    -SizeGB $NewSizeGB `
    -SCSIID $Disk.BusID `
    -CLUUID $vars.CLUUID

  do {
    sleep 5
    $tasklist = REST-Px-ProgressMonitor `
      -PxClusterIP $vars.PCClusterIP `
      -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
      -PxClusterPass $vars.PCCreds.getnetworkcredential().password
    $taskstatus = $tasklist.entities | where {$_.id -eq $task.task_Uuid}
  } until ($taskstatus.percentageCompleted -eq 100)

  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Windows.Forms.MessageBox]::Show("Disk Extend task is '$($taskstatus.status)'","Disk Extend",0,64)
  write-log -message "Disk Add has status '$($taskstatus.status)'"
}
Export-ModuleMember *