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
  
  write-log -message "Adding Disk"
  
  REST-VM-Add-Disk-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMDetail $vars.VMDetail `
    -SizeGB $SizeGB 
}
Export-ModuleMember *