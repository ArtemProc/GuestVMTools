Function Wrap-VMGuest-Ram {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  $currentRAMGB = $vars.VMDetail.memory_mb/1024

  $RAM = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the amount of RAM in GB", "Update RAM.", "$($currentRAMGB)")
  if ($ram -lt $currentRAMGB){
    do {
      $RAM = [Microsoft.VisualBasic.Interaction]::InputBox("Ram has to be higher then current.", "Update RAM.", "$($currentRAMGB)")
    } until ($ram -ge $currentRAMGB)
  }
  write-log -message "Updating RAM"

  REST-Add-VM-RAM-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMDetail $vars.VMDetail `
    -GBRam $RAM 
}
Export-ModuleMember *