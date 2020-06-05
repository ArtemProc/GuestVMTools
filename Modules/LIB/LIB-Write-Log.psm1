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
    [System.Windows.Forms.MessageBox]::Show($message,"GuestVM Tools stopped", 'OK' , 'ERROR')
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