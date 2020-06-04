Function Wrap-VMGuest-SecureBoot {
  param (
   [object] $Vars
  ) 
  [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
  Add-Type -AssemblyName PresentationFramework

  $PEhosts = REST-Get-PRX-Hosts `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID

  write-log -message "We have '$($PEhosts.entities.count)' PE Hosts"
  [array]$PEHost = $PEhosts.entities | where {$_.uuid -eq $vars.VMDetail.host_uuid}

  if ($PEHost.hypervisorFullName -notmatch "2019|2020|2021|2022|2023|2024"){
    
    write-log -message "HyperVisor $($PEHost.hypervisorFullName) is not secure boot capable." -sev "ERROR"

  }

  $VMDetail = REST-Get-VM-Detail-PRX `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID `
    -VMUUID $vars.VMDetail.UUID

  $orgVMDetail = $VMDetail 

  if ($VMDetail.power_state -eq "on"){
    $Target= [System.Windows.Forms.MessageBox]::Show("PowerOff VM $($vars.vmdetail.name)", "Power Off Request", 4)
    if ($target -eq  "Yes"){
      $Target= [System.Windows.Forms.MessageBox]::Show("Sure? We will send an ACPI Shutdown.", "Power Off Request", 4)
      if ($target -eq "Yes"){
        $shutdown = REST-Set-VM-Power-State-PRX `
         -PCClusterIP $vars.PCClusterIP `
         -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
         -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
         -CLUUID $vars.CLUUID `
         -VMUUID $vars.VMDetail.UUID 
         -State "ACPI_SHUTDOWN"
         [System.Windows.Forms.MessageBox]::Show("VM ACPI Shutdown sent","VM Status", 0)
      } else {

        write-log -message "User did not accept the power off command." -sev "ERROR"

      }
    }
  }
  $count = 0
  do {
    sleep 30
    $count++
    $VMDetail = REST-Get-VM-Detail-PRX `
      -PCClusterIP $vars.PCClusterIP `
      -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
      -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
      -CLUUID $vars.CLUUID `
      -VMUUID $vars.VMDetail.UUID
    if ($VMDetail.power_state -ne "OFF"){
      [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
      [System.Windows.Forms.MessageBox]::Show("VM is still powered on, waiting","VM Status", 0)
      if ($count -ge 3){
        $Hardpower = [System.Windows.Forms.MessageBox]::Show("Do you want to hard power off the VM?","VM Status", 4)
        if ($Hardpower -eq "YES"){
          $Hardpower = [System.Windows.Forms.MessageBox]::Show("Sending Hard power off","VM Status", 0)
          $shutdown = REST-Set-VM-Power-State-PRX `
            -PCClusterIP $vars.PCClusterIP `
            -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
            -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
            -CLUUID $vars.CLUUID `
            -VMUUID $vars.VMDetail.UUID 
            -State "OFF"     
        }
      }
    }
  } until ($VMDetail.power_state -eq "OFF" -or $count -ge 5)
  if ($count -ge 5) {

    write-log -message "VM is still not in OFF state. We cannot continue" -sev "ERROR"

  } else {

    REST-Set-VM-Secure-Boot-PRX `
      -PCClusterIP $vars.PCClusterIP `
      -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
      -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
      -CLUUID $vars.CLUUID `
      -VMDetail $VMDetail

   $count = 0
   do {
     sleep 30
     $count++
     $VMDetail = REST-Get-VM-Detail-PRX `
       -PCClusterIP $vars.PCClusterIP `
       -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
       -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
       -CLUUID $vars.CLUUID `
       -VMUUID $vars.VMDetail.UUID
   } until ($VMDetail.boot.secure_boot -eq $true -or $count -ge 3)

   if ($count -ge 3){

    write-log -message "Secure boot is not enabled." -sev "ERROR"

   } else {

     [System.Windows.Forms.MessageBox]::Show("Secureboot enable was a success","VM Status", 0)
     if  ($orgVMDetail.power_state -eq "OFF") {

        write-log -message "VM Was already off, not powering back on." 

     } else {
        $PowerOn = REST-Set-VM-Power-State-PRX `
          -PCClusterIP $vars.PCClusterIP `
          -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
          -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
          -CLUUID $vars.CLUUID `
          -VMUUID $vars.VMDetail.UUID 
          -State "ON"   
     }
   }

}
Export-ModuleMember *