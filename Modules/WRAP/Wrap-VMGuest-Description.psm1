Function Wrap-VMGuest-Description {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  [decimal]$SNAPNAME = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the VM Description", "Description Value", "Before Change xyz")

  REST-Set-VM-Description-PRX`
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -VMDetail $vars.VMDetail `
    -cluuid $vars.cluuid 

  [System.Windows.Forms.MessageBox]::Show('Description updated' , "Info" , 0)

}
Export-ModuleMember *