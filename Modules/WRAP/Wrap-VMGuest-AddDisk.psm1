Function Wrap-VMGuest-AddDisk {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  [int]$SizeGB = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the disk size in GB", "Add Disk.", "40")
  if ($SizeGB -le 0){
    do {
      $SizeGB = [Microsoft.VisualBasic.Interaction]::InputBox("Disksize has to be higher then 0.", "Disk Size", "$($SizeGB)")
    } until ($SizeGB -gt 0)
  }

  write-log "Getting all Containers"

  $containers = REST-Get-PRX-Containers `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID
  [array] $Disksobj = $null
  $containers.entities | % {
    $free = [math]::Truncate([decimal]$_.usageStats.'storage.user_unreserved_free_bytes' / 1024 / 1024 / 1024 / 1024)
    $custom = New-Object -Type PSObject
    $custom | add-member NoteProperty Name $_.name
    $custom | add-member NoteProperty Compression $_.compressionEnabled
    $custom | add-member NoteProperty ErasureCode $_.erasureCode
    $custom | add-member NoteProperty Dedup $_.onDiskDedup    
    $custom | add-member NoteProperty FreeSpaceTB $free 
    $custom | add-member NoteProperty UUID $_.containerUuid
    [array]$Disksobj += $custom
  }
  $GridArguments = @{
    OutputMode = 'Single'
    Title      = 'Select the SCSI Disk to extend and click OK'
  }
  do {
    $Container = ($Disksobj | Out-GridView @GridArguments)
  } until ($container)

  write-log -message "Adding Disk"

  $task= REST-VM-Add-Disk-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMDetail $vars.VMDetail `
    -SizeGB $SizeGB `
    -containerUUID $Container.UUID
  
  do {
    sleep 5
    $tasklist = REST-Px-ProgressMonitor `
      -PxClusterIP $vars.PCClusterIP `
      -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
      -PxClusterPass $vars.PCCreds.getnetworkcredential().password
    $taskstatus = $tasklist.entities | where {$_.id -eq $task.taskUuid}
  } until ($taskstatus.percentageCompleted -eq 100)

  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Windows.Forms.MessageBox]::Show("Disk Add task is '$($taskstatus.status)'","Disk Add",0,64)

  write-log -message "Disk Add has status '$($taskstatus.status)'"

}
Export-ModuleMember *