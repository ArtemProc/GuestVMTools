Function Wrap-VMGuest-Ram {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  [decimal]$currentRAMGB = $vars.VMDetail.memory_mb/1024

  write-log -message "Current Ram is '$currentRAMGB' GB"

  [decimal]$RAM = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the amount of RAM in GB", "Update RAM.", "$($currentRAMGB)")

  write-log -message "User Selected '$ram' GB"

  if ($ram -lt $currentRAMGB){
    do {
      $RAM = [Microsoft.VisualBasic.Interaction]::InputBox("Ram has to be higher then current.", "Update RAM.", "$($ram)")
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

  sleep 5

  $VMDetail = REST-Get-VM-Detail-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMUUID $vars.VMDetail.UUID

  [decimal]$currentRAMGB = $VMDetail.memory_mb/1024

  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Windows.Forms.MessageBox]::Show("VM Ram is now '$currentRAMGB' GB","RAM Status",0,64)
  write-log -message "VM Ram is now '$currentRAMGB' GB" -d 0

}
Export-ModuleMember *