Function Wrap-VMGuest-Description {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  [string]$Description = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the VM Description", "Description Value", $vars.VMDetail.Description)

  REST-Set-VM-Description-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -VMDetail $vars.VMDetail `
    -cluuid $vars.cluuid `
    -Description $Description

  sleep 5

  $VMDetail = REST-Get-VM-Detail-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMUUID $vars.VMDetail.UUID

  if ($VMDetail.description -eq $Description){  
    [System.Windows.Forms.MessageBox]::Show('Description updated', "Info" , 0)
  } else {
    [System.Windows.Forms.MessageBox]::Show('Description update failed', "ERROR", 'OK' , 'ERROR')
  }

}
Export-ModuleMember *