#Prompt section
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
Add-Type -AssemblyName PresentationFramework
$License = [System.Windows.Forms.MessageBox]::Show("Use at your own risk, This software is NOT linked to Nutanix.", "Nutanix License" , 4)
if ($license -eq "Yes"){

  write-log -message "User accepted the license"

} else {

  write-log -message "User did not accept the license!" -SEV "ERROR"

}

$shell = New-Object -ComObject "Shell.Application"
$shell.minimizeall()

$PCCreds            = get-credential -message "Enter the PC Credentials, UPN or local account, UI Admin"

$PCClusterIP = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Prism Central IP", "Prism Central IP address", "10.10.0.32")
$Target= [System.Windows.Forms.MessageBox]::Show("Use Local VM as Target?" , "Status" , 4)
#$Target = [Microsoft.VisualBasic.Interaction]::InputBox("Local Target will find the local VM, remote will prompt", "Local target or Remote", "Local")

if ($target -eq "Yes"){
  $target = "Local"
}
$Global:Debug = 1
$mode = $null #hardcode the mode if you dont want menu prompts

$folder = "PWD"
#Loading Modules
if ($Folder -eq "PWD"){
	$dir = $pwd
} else {
	$dir = $Folder
}

get-childitem $dir -Recurse *.psm1 | % {import-module $_.versioninfo.filename -DisableNameChecking;}
$allcontent = $null
get-childitem $($dir) -Recurse *.psm1 | % {$allcontent += get-content $_.versioninfo.filename }
$functions = ($allcontent | where {$_ -match "Function"}).count

write-log -message "'$($functions)' Functions loaded"
write-log -message "Agentless Guest VM Tools Has been initialized"

if ($PSVersionTable.PSVersion.Major -lt 5){

  write-log -message "You need to run this on Powershell 5 or greater...." -sev "ERROR"

} elseif ($PSVersionTable.PSVersion.Major -match 5 ){

  write-log -message "Disabling SSL Certificate Check for PowerShell 5"

  PSR-SSL-Fix

}

if ($PCClusterIP -eq "" -or $Target -eq "" -or $Folder -eq "" -or $PCCreds.getnetworkcredential().password -eq $null){
  write-log -message "User canceled Request" -sev "Error"
}

write-log -message "Loading All Prism Central VMs"

$VMs = REST-PC-Get-VMs `
  -PCClusterIP $PCClusterIP `
  -PxClusterUser $PCCreds.getnetworkcredential().username `
  -PxClusterPass $PCCreds.getnetworkcredential().password

write-log -message "Creating Custom Object"
  
[object]$custom = $null
[array]$customVMs = $null
$vms.entities | % {
  $custom = New-Object -Type PSObject
  $custom | add-member NoteProperty Name $_.status.Name
  $custom | add-member NoteProperty ClusterName $_.status.cluster_reference.name
  $custom | add-member NoteProperty VMUUID $_.metadata.uuid
  $custom | add-member NoteProperty ClusterUUID $_.status.cluster_reference.uuid
  $customVMs += $custom
}

write-log -message "Loading All Prism Central Clusters"

$PCClusters = REST-Query-PC-Clusters `
  -PCClusterIP $PCClusterIP `
  -PxClusterUser $PCCreds.getnetworkcredential().username `
  -PxClusterPass $PCCreds.getnetworkcredential().password 

if ($target -eq "Local"){
  $VMUUID = (get-ciminstance win32_bios | select serialnumber).serialnumber
  $CLUUID = ($CustomVMs | where {$_.VMUUID -eq $VMUUID}).ClusterUUID
} else {
  $GridArguments = @{
      OutputMode = 'Single'
      Title      = 'Please select a VM from the list'
  }
  $CustomVM = $customVMs | Out-GridView @GridArguments
  $VMUUID = $CustomVM.VMUUID
  $CLUUID = $CustomVM.ClusterUUID
}

write-log -message "Lets get the VM Detail object"

$VMDetail = REST-Get-VM-Detail-PRX `
  -PCClusterIP $PCClusterIP `
  -PxClusterUser $PCCreds.getnetworkcredential().username `
  -PxClusterPass $PCCreds.getnetworkcredential().password `
  -CLUUID $CLUUID `
  -VMUUID $VMUUID

if (!$VMDetail){
  write-log -message "VM was not found...." -sev "ERROR"
}

if (!$mode){
  $GridArguments = @{
      OutputMode = 'Single'
      Title      = 'Please select a mode and click OK'
  }
  
  $modes = ,,"Add-Disk","Remove-Disk","Extend-Disk"

  $custom = New-Object -Type PSObject
  $custom | add-member NoteProperty Mode "Report"
  $custom | add-member NoteProperty Description "Generate a report for the VM, host details, output options."
  [array]$Modesobj += $custom
  $custom = New-Object -Type PSObject
  $custom | add-member NoteProperty Mode "Change Ram"
  $custom | add-member NoteProperty Description "Increase the amount of ram on a running VM"
  [array]$Modesobj += $custom
  $custom = New-Object -Type PSObject
  $custom | add-member NoteProperty Mode "Add-Disk"
  $custom | add-member NoteProperty Description "Add a disk to a running VM"
  [array]$Modesobj += $custom  
  $custom = New-Object -Type PSObject
  $custom | add-member NoteProperty Mode "Extend-Disk"
  $custom | add-member NoteProperty Description "Increase the Disk size of an existing disk."
  [array]$Modesobj += $custom  
  if ($target -ne "Local"){
    $custom = New-Object -Type PSObject
    $custom | add-member NoteProperty Mode "Secure-Boot"
    $custom | add-member NoteProperty Description "Enable Secure boot on another VM. (powered off state is required)"
    [array]$Modesobj += $custom
  } 
  $mode = ($Modesobj | Out-GridView @GridArguments).mode
} 

$vars = @{
  PCClusterIP = $PCClusterIP
  PCCreds     = $PCCreds
  VMDetail    = $VMdetail
  CLUUID      = $CLUUID
}

switch($mode) {
   "Report"       { Wrap-VMGuest-Report -Vars $Vars     } 
   "Change Ram"   { Wrap-VMGuest-Ram -Vars $Vars        } 
   "Add-Disk"     { Wrap-VMGuest-AddDisk -Vars $vars    }
   "Extend-Disk"  { Wrap-VMGuest-ExtendDisk -Vars $Vars }
   "Secure-Boot"  { Wrap-VMGuest-SecureBoot -Vars $Vars }
}

exit