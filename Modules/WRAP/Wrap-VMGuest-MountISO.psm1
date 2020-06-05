Function Wrap-VMGuest-MountISO {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  write-log -message "Getting all Images"

  $Images = REST-Query-Images-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID

  [array] $Imagesobj = $null
  $Images.entities | where {$_.status.state -eq "COMPLETE" -and $_.status.resources.image_type -eq "ISO_IMAGE"} | % {
    $Size = [math]::Round(([decimal]$_.status.resources.size_bytes / 1024 / 1024 ),2)
    $custom = New-Object -Type PSObject
    $custom | add-member NoteProperty Name $_.spec.name
    $custom | add-member NoteProperty Description $_.spec.description
    $custom | add-member NoteProperty SizeMB $Size
    $custom | add-member NoteProperty UUID $_.metadata.uuid
    [array]$Imagesobj += $custom
  }
  $GridArguments = @{
    OutputMode = 'Single'
    Title      = 'Select the ISO Image to Mount'
  }
  do {
    $image = ($Imagesobj | Out-GridView @GridArguments)
  } until ($image)
  $Realimage = $images.entities | where {$_.metadata.uuid -eq $image.uuid}
  [array] $CDDrivesobj = $null
  [array]$CDRomDrives = $vars.vmdetail.vm_disk_info | where {$_.is_cdrom -eq $true}
  if ($CDRomDrives.count -gt 1){
    $CDRomDrives | % {
      $custom = New-Object -Type PSObject
      $custom | add-member NoteProperty Index $_.disk_address.device_index
      $custom | add-member NoteProperty BusType $_.disk_address.device_bus
      $custom | add-member NoteProperty IsEmpty $_.is_empty
    [array]$CDDrivesobj += $custom
    }
    $GridArguments = @{
      OutputMode = 'Single'
      Title      = 'Select the CDrom Drive to mount the image'
    }
    do {
      $CDRom = ($CDDrivesobj | Out-GridView @GridArguments)
    } until ($CDRom)
  } else {
    $CDROM = $CDRomDrives
  }
  if ($cdrom.is_empty -eq $false){
    $Eject = [System.Windows.Forms.MessageBox]::Show("This drive has an ISO mounted.`nCan we eject and replace for the new image?","VM Status", 4)
    if ($eject -eq "Yes"){
      $task = REST-Unmount-CDRom-PRX `
        -PCClusterIP $vars.PCClusterIP `
        -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
        -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
        -CLUUID $vars.CLUUID `
        -VMUUID $vars.VMDetail.UUID `
        -CDROM $CDROM
      do {
        $tasklist = REST-Px-ProgressMonitor `
          -PxClusterIP $vars.PCClusterIP `
          -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
          -PxClusterPass $vars.PCCreds.getnetworkcredential().password
        $taskstatus = $tasklist.entities | where {$_.id -eq $task.task_Uuid}
      } until ($taskstatus.percentageCompleted -eq 100)
      [System.Windows.Forms.MessageBox]::Show("Unmount Task has '$($taskstatus.status)'","Unmount",0)
    } else {
      write-log -message "User did not approve the eject" -sev "ERROR"
    }
  }
  $imagesdetails = REST-Get-Image-Sizes `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID 
    
  $imagedetail = $imagesdetails.entities | where {$_.uuid -eq $Realimage.metadata.uuid}

  $task = REST-Mount-CDRom-Image-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMUUID $vars.VMDetail.UUID `
    -CDROM $CDROM `
    -Image $imagedetail
  do {
    $tasklist = REST-Px-ProgressMonitor `
      -PxClusterIP $vars.PCClusterIP `
      -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
      -PxClusterPass $vars.PCCreds.getnetworkcredential().password
    $taskstatus = $tasklist.entities | where {$_.id -eq $task.task_Uuid}
  } until ($taskstatus.percentageCompleted -eq 100)

  [System.Windows.Forms.MessageBox]::Show("The ISO Mount task is '$($taskstatus.status)'","ISO Mount",0)  
}
Export-ModuleMember *