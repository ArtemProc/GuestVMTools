Function Wrap-VMGuest-Snapshot {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  [string]$SNAPNAME = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the snapshotname", "Snapshot Name", "Before Change xyz")

  REST-Create-VM-Snapshot-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -VMUUIDLong "$($vars.CLUUID)::$($vars.VMDetail.UUID)" `
    -snapname $SNAPNAME

  [System.Windows.Forms.MessageBox]::Show('Snapshot Created' , "Info" , 0)

}
Export-ModuleMember *