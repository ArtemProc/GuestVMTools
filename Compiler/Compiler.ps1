$mainscript = $null
Function write-log {
  param (
  $message,
  $sev = "INFO",
  $D = 0
  ) 
  ## This write log module is designed for nutanix calm output
  if ($sev -eq "INFO" -and $Debug -ge $D){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' | INFO  | $message "
  } elseif ($sev -eq "WARN"){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | $message " -ForegroundColor  Yellow
  } elseif ($sev -eq "ERROR"){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| $message " -ForegroundColor  Red
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.MessageBox]::Show($message,"GuestVM Tools stopped",0,16)
    sleep 5
    [Environment]::Exit(1)
  } elseif ($sev -eq "CHAPTER"){
    write-host ""
    write-host "####################################################################"
    write-host "#                                                                  #"
    write-host "#     $message"
    write-host "#                                                                  #"
    write-host "####################################################################"
    write-host ""
  }
} 

Function Get-Folder {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory

    if($foldername.ShowDialog() -eq "OK")
    {
        $folder += $foldername.SelectedPath
    }
    return $folder
}

$folder = Get-folder

$items = Get-ChildItem -Recurse "$($folder)\*.psm1"

write-log -message "Testing Code...."

get-childitem -Recurse "$($folder)\*.psm1" | % {import-module $_.versioninfo.filename -DisableNameChecking;}


foreach ($item in $items){
  $content = get-content $item.fullname
  [array]$mainscript += $content
}
$main = get-content "$($folder)\GuestVMTools.ps1"
$mainscript += $main
$mainscript | where {$_ -notmatch "ModuleMember" } | out-file "$($folder)\Compiled.ps1"
