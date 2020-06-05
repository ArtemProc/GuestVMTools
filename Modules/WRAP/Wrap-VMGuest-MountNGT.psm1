Function Wrap-VMGuest-MountNGT {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"
  [array]$emptyDrives = $vars.VMdetail.vm_disk_info | where {$_.is_cdrom -eq $true -and $_.is_empty -eq $true } | select -first 1 
  if ($emptyDrives.count -eq 0){
    [array]$CDrom = $vars.VMdetail.vm_disk_info | where {$_.is_cdrom -eq $true } | select -first 1
    if ($cdrom.is_empty -eq $false){
      $Eject = [System.Windows.Forms.MessageBox]::Show("This (first) drive has an ISO mounted.`nCan we eject and replace for the NGT Tools?","VM Status", 4)
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
  }
  $mount = REST-Mount-NGT-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMUUID $vars.VMDetail.UUID
  if ($mount.toolsMounted -eq $true){
    [System.Windows.Forms.MessageBox]::Show("NGT Tools was mounted","Done",0) 
  } else {
    write-log -message "NGT Mount command reported 'not mounted' after execution.`nPlease check Prism" -sev "ERROR"
  }
   
}
Export-ModuleMember *