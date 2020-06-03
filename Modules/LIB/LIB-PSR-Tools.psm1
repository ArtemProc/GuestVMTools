function Get-FunctionName {
  param (
    [int]$StackNumber = 1
  ) 
    return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
}


Function PSR-SSL-Fix {

  try {
  add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
                                          WebRequest request, int certificateProblem) {
            return true;
        }
     }
"@

  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

  write-log -message "SSL Certificate has been loaded." 

  } catch {

    write-log -message "SSL Certificate fix is already loaded." -sev "WARN"

  }
}

Function Test-MemoryUsage {
  Param()
 
  $os = Get-Ciminstance Win32_OperatingSystem
  $pctFree = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)
 
  if ($pctFree -ge 45) {
    $Status = "OK"
  } elseif ($pctFree -ge 15 ) {
    $Status = "Warning"
  } else {
    $Status = "Critical"
  }
 
  $os | Select @{Name = "Status";Expression = {$Status}},
  @{Name = "PctFree"; Expression = {$pctFree}},
  @{Name = "FreeGB";Expression = {[math]::Round($_.FreePhysicalMemory/1mb,2)}},
  @{Name = "TotalGB";Expression = {[int]($_.TotalVisibleMemorySize/1mb)}}
 
}

function Get-RandomCharacters($length, $characters) { 
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
    $private:ofs="" 
    return [String]$characters[$random]
}

function IP-toINT64 () { 
  param ($ip) 
 
  $octets = $ip.split(".") 
  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
} 

function INT64-toIP() { 
  param ([int64]$int) 

  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
} 

function Get-IPrange {
param ( 
  [string]$start, 
  [string]$end, 
  [string]$ip, 
  [string]$mask, 
  [int]$cidr 
) 

  if ($ip) {
    $ipaddr = [Net.IPAddress]::Parse($ip)
  } 
  if ($cidr) {
    $maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) 
  } 
  if ($mask) {
    $maskaddr = [Net.IPAddress]::Parse($mask)
  } 
  if ($ip) {
    $networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)
  } 
  if ($ip) {
    $broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))
  } 
  if ($ip) { 
    $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
    $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
  } else { 
    $startaddr = IP-toINT64 -ip $start 
    $endaddr = IP-toINT64 -ip $end 
  } 
   
  for ($i = $startaddr; $i -le $endaddr; $i++) { 
    INT64-toIP -int $i 
  }

}

Function PSR-GetDHCP-Leases {
  param (
    [string]$DHCPAPIUser,
    [string]$DHCPAPIPass,
    [string]$DHCPAPIEndp,
    [string]$loggingDir,
    [string]$Service_AccountUser,
    [string]$Service_AccountPass,
    [string]$daemonID
  )

  write-log -message "Creating script";

  [ARRAY]$OUTPUT += [STRING]'start-transcript -path "' + $loggingDir + '\Leases.log"'
  [ARRAY]$OUTPUT += [STRING]'$Securepass = ConvertTo-SecureString "'+ $DHCPAPIPass + '" -AsPlainText -Force;'
  [ARRAY]$OUTPUT += [STRING]'$credential = New-Object System.Management.Automation.PSCredential ( "'+ $DHCPAPIUser + '", $Securepass);'
  [ARRAY]$OUTPUT += [STRING]'$session    = new-pssession -computername "'+ $DHCPAPIEndp + '" -credential $credential;'
  [ARRAY]$OUTPUT += [STRING]'$Leases     = invoke-command -session $session -command {Get-DhcpServerv4Scope | Get-DhcpServerv4Lease | where {$_.LeaseExpiryTime -ge (get-date)}}'
  [ARRAY]$OUTPUT += [STRING]'$leases | export-csv "' + $loggingDir + '\leases.csv"'

  write-log -message "Creating Task with daemon '$daemonID'"

  $OUTPUT | OUT-FILE "$($loggingDir)\Leases.ps1" -force
  $argumentList = "-file $($loggingDir)\Leases.ps1"

  $jobname = "PowerShell Leases DoubleHop - $deamonID";
  $action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$argumentList";
  $trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd;
  $SecurePassword = $Service_AccountPass | ConvertTo-SecureString -AsPlainText -Force
  $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $Service_AccountUser, $SecurePassword
  $CredPassword = $Credentials.GetNetworkCredential().Password 

  write-log -message "Creating Task with User '$($env:userdomain)\$($Service_AccountUser)'"

  $task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -Settings $settings -runlevel "Highest" -User "$($env:userdomain)\$($Service_AccountUser)" -Password $CredPassword -ea:4
  sleep 5
  Get-ScheduledTask $jobname -ea:4 | start-scheduledtask
  sleep 15
  Get-ScheduledTask $jobname -ea:4 | unregister-scheduledtask -confirm:0
  try{
    $output = import-csv "$($loggingDir)\Leases.csv" -ea:4
  }catch{}
  $error.clear()
  if ($debug -ge 1){

    write-log -message "We found '$($output.count)' leases on this DHCP endpoint."
  }
  return $output
}

function Remove-StringSpecialCharacter{
  param(
    [Parameter(ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [Alias('Text')]
    [System.String[]]$String,
    
    [Alias("Keep")]
    #[ValidateNotNullOrEmpty()]
    [String[]]$SpecialCharacterToKeep
  )
  PROCESS
  {
    IF ($PSBoundParameters["SpecialCharacterToKeep"])
    {
      $Regex = "[^\p{L}\p{Nd}"
      Foreach ($Character in $SpecialCharacterToKeep)
      {
        IF ($Character -eq "-"){
          $Regex +="-"
        } else {
          $Regex += [Regex]::Escape($Character)
        }
        #$Regex += "/$character"
      }
      
      $Regex += "]+"
    } #IF($PSBoundParameters["SpecialCharacterToKeep"])
    ELSE { $Regex = "[^\p{L}\p{Nd}]+" }
    
    FOREACH ($Str in $string)
    {
      Write-Verbose -Message "Original String: $Str"
      $Str -replace $regex, ""
    }
  } #PROCESS
}

Function Test-CPUUsage {
  Param()
 
  $sample1 = (Get-Counter -Counter "\Processor(_Total)\% Processor Time").countersamples.cookedvalue
  sleep 15
  $sample2 = (Get-Counter -Counter "\Processor(_Total)\% Processor Time").countersamples.cookedvalue
  $totalav = ($sample1 + $sample2)/2
  return $totalav
}

function Wait-Project-Save-State {
  param(
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $project
  )
  write-log -message "Project '$($project.metadata.uuid)', waiting 'Complete' state"
  sleep 10
  if ($debug -ge 2 ){

    write-log -message "Username is '$PxClusterUser'"
    write-log -message "Username is '$PxClusterPass'"
  }
  $createcount = 0
  do {
    $createcount ++
    $projectdetail = REST-Get-ProjectDetail -PxClusterUser $PxClusterUser -PxClusterPass $PxClusterPass -PCClusterIP $PCClusterIP -project $project
    if ($projectdetail.status.state -ne "COMPLETE"){

      write-log -message "Project state is: '$($projectdetail.status.state)' sleeping 30 seconds"

      Sleep 30
    } else {

      write-log -message "Project is in state: '$($projectdetail.status.state)', proceeding.."
    }
  } until ($projectdetail.status.state  -eq "COMPLETE" -or $createcount -ge 20)
  if ($createcount -ge 20){

    return "ERROR"

  } else {

    return "GO"

  }
}

function Wait-Ansible-Job-State {
  param(
    [string] $endpoint,
    [string] $username,
    [string] $password,
    [string] $jobid
  )
  write-log -message "Tracking Job ID '$($jobid)', waiting 'Complete' state"
  sleep 10
  if ($debug -ge 2 ){

    write-log -message "Username is '$username'"
    write-log -message "password is '$password'"
  }
  $createcount = 0
  do {
    $createcount ++
    $jobs = REST-Ansible-Get-Job `
      -password $password `
      -username $username `
      -endpoint $endpoint `
      -jobid $jobid
    $job = $jobs.results | where {$_.id -eq $jobid}

    if ($job.status -notmatch "successful|failed"){

      write-log -message "Ansible Job state is: '$($job.status)' sleeping 30 seconds"

      Sleep 30
    } else {

      write-log -message "Ansible Job state is: '$($job.status)', proceeding.."
      if ($job.status -eq "failed"){

        write-log -message "This job is not good..." -sev "WARN"
        return "BadBoy"
      } else {
        return "GoodBoy"
      }
    }
  } until ($job.status -match "successful|failed" -or $createcount -ge 20)
  if ($createcount -ge 20){

    write-log -message "Ansible Job state is: '$($job.status)', after waiting for 600 seconds" -sev "ERROR"

  }
}


Function Set-AutoLogon{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultUsername,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultPassword,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultDomain,
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$AutoLogonCount,
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$Script            
    )
    Begin
    {
        #Registry path declaration
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $RegROPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    Process
    {
        try
        {
            #setting registry values
            Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String  
            Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String  
            Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
            Set-ItemProperty $RegPath "DefaultDomainName" -Value "$DefaultDomain" -type String
            if($AutoLogonCount)
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
            }
            else
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
            }
            if($Script)
            {
                Set-ItemProperty $RegROPath "(Default)" -Value "$Script" -type String
            }
            else
            {
                Set-ItemProperty $RegROPath "(Default)" -Value "" -type String
            }        
        }

        catch
        {

            Write-Output "An error had occured $Error"
            
        }
    }
    End
    {
        
        #End

    }
}

Function Wait-ImageUpload-Task{
  param(
    $datavar
  )
  write-log -message "Wait for Image Upload Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^ImageUpload" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^ImageUpload" }
      } catch {}
    }
    if ($Looper % 4 -eq 0){
      write-log -message "We found $($tasks.count) task";
    }
    [array] $allready = $null
    if ($Looper % 4 -eq 0){
      write-log "Cycle $looper out of 200"
    }
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
          
          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is ready."
          }
          $allReady += 1
      
        } else {
      
          $allReady += 0

          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is $($task.state)."
          }
        };
      };
      sleep 20
    } else {
      $allReady = 0
      sleep 20
      if ($Looper % 4 -eq 0){
        write-log -message "There are no jobs to process."
      }
    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}


Function PSR-MulticlusterPE-PC {
  param(
    [object] $datagen,
    [object] $datavar
  )

  write-log "Checking current status"
  do {
    $count ++
    $current = REST-PE-GET-MultiCluster -datavar $datavar -datagen $datagen
    if ($current.clusterUuid){
      if ($current.clusterUuid.length -ge 5 ){
        $result = "Success"

        write-log -message "Cluster is added to '$($current.clusterDetails.ipAddresses)'";

      }
    } else {
      write-log -message "Adding Multicluster to PE Cluster";
        
      $hide = REST-PE-Add-MultiCluster -datavar $datavar -datagen $datagen

    }
    write-log -message "Waiting for the registration process";
    sleep 90
    $current = REST-PE-GET-MultiCluster -datavar $datavar -datagen $datagen
    if ($current.clusterUuid){
      if ($current.clusterUuid.length -ge 5 ){
        $result = "Success"

        write-log -message "Cluster is added to '$($current.clusterDetails.ipAddresses)'";

      }
    } else {

      write-log -message "Error While adding, resetting PE Gateway, lets wait for Depending / Running PE tasks" -sev "WARN"

      wait-ImageUpload-Task -datavar $datavar

      write-log -message "All Paralel threads should be in the correct state for an AOS Cluster restart.";
      write-log -message "Preparing Restart, Build SSH connection to cluster";

      $Securepass = ConvertTo-SecureString $datavar.pepass -AsPlainText -Force;
      $credential = New-Object System.Management.Automation.PSCredential ('nutanix', $Securepass);
      try {
        $session = New-SSHSession -ComputerName $datavar.PEClusterIP -Credential $credential -AcceptKey;
      } catch {
        sleep 30
        $session = New-SSHSession -ComputerName $datavar.PEClusterIP -Credential $credential -AcceptKey;
      }
      write-log -message "Building a stream session";

      $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)

      write-log -message "Restarting Prism";

      $hide = Invoke-SSHStreamShellCommand -ShellStream $stream -Command "allssh genesis stop prism ; cluster start"

      write-log -message "Sleeping 3 minutes after restart Prism";

      sleep 119

      write-log -message "Reattempting to join";

      sleep 20

      $hide = REST-PE-Add-MultiCluster -datavar $datavar -datagen $datagen

      write-log -message "Waiting for the registration process";

      sleep 90
      $current = REST-PE-GET-MultiCluster -datavar $datavar -datagen $datagen     
      if ($current.clusterUuid){
        if ($current.clusterUuid.length -ge 5 ){
          $result = "Success"
          $status = "Success"
          write-log -message "Cluster is added to $($current.clusterDetails.ipAddresses)";

        }
      } 
    }
  } until ($result -eq "Success" -or $count -ge 3)
  sleep 20
  if ($result -match "Success"){
    $status = "Success"

    write-log -message "Pe has been Joined to PC";
    write-log -message "Loving it";

  } else {

    $status = "Failed"

    write-log -message "Danger Will Robbinson." -sev "ERROR";

  }
  $resultobject =@{
    Result = $status
  };
  return $resultobject
}



Function Wait-Forest-Task{
  param(
    $datavar
  )
  write-log -message "Wait for Forest Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^Forest" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^Forest" }
      } catch {}
    }

    write-log -message "We found $($tasks.count) task";

    [array] $allready = $null
    write-log "Cycle $looper out of 200"
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
    
          write-log -message "Task $($task.taskname) is ready."
    
          $allReady += 1
      
        } else {
      
          $allReady += 0

          write-log -message "Task $($task.taskname) is $($task.state)."
      
        };
      };
      sleep 60
    } else {
      $allReady = 1

      write-log -message "There are no jobs to process."

    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}


Function Wait-Files-Task{
  param(
    $datavar
  )
  write-log -message "Wait for Files Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^Files" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^Files" }
      } catch {}
    }

    write-log -message "We found $($tasks.count) task";

    [array] $allready = $null
    write-log "Cycle $looper out of 200"
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
    
          write-log -message "Task $($task.taskname) is ready."
    
          $allReady += 1
      
        } else {
      
          $allReady += 0

          write-log -message "Task $($task.taskname) is $($task.state)."
      
        };
      };
      sleep 60
    } else {
      $allReady = 0

      write-log -message "There are no jobs to process."

    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}

Function Test-LdapConnectivity { 
  param( 
    [String]$ServerName = "", 
    [UInt16]$Port = 389, 
    [String]$UserName = "", 
    [String]$Password = "" 
  ) 
 
  #Load the assemblies 
  [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") 
  [System.Reflection.Assembly]::LoadWithPartialName("System.Net") 
   
  #Connects to Server on the standard port 
  $dn = "$ServerName"+":"+"$Port" 
  $c = New-Object System.DirectoryServices.Protocols.LdapConnection "$dn"
  if ($port -match "636|3269"){
    $c.SessionOptions.SecureSocketLayer = $true; 

    write-log -message "Enable SSL"

  } else {
    $c.SessionOptions.SecureSocketLayer = $false; 
  }
  $c.SessionOptions.ProtocolVersion = 3 

  write-log -message "Using Port '$Port'"
  write-log -message "Using Username '$UserName'"
   
  # Pick Authentication type: 
  # Anonymous, Basic, Digest, DPA (Distributed Password Authentication), 
  # External, Kerberos, Msn, Negotiate, Ntlm, Sicily 
  $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic 
   
  $credentials = new-object "System.Net.NetworkCredential" -ArgumentList $UserName,$Password 
   
  # Bind with the network credentials. Depending on the type of server, 
  # the username will take different forms. Authentication type is controlled 
  # above with the AuthType 
  Try { 
 
    $c.Bind($credentials); 
    return $true 
  } catch { 
    Write-host $_.Exception.Message 
    
    return $false 
  } 
} 

Function Wait-Templates-Task{
  param(
    $datavar
  )
  write-log -message "Wait for Templates Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^ImagesVmware" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^ImagesVmware" }
      } catch {}
    }

    write-log -message "We found $($tasks.count) task";

    [array] $allready = $null
    write-log "Cycle $looper out of 200"
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
    
          write-log -message "Task $($task.taskname) is ready."
    
          $allReady += 1
      
        } else {
      
          $allReady += 0

          write-log -message "Task $($task.taskname) is $($task.state)."
      
        };
      };
      sleep 60
    } else {
      $allReady = 1

      write-log -message "There are no jobs to process."

    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}



Function Generate-Password {

  write-log -message "Generating Password"

  $url = "https://passwordwolf.com/api/?length=11&exclude=%60%27%22%23*%3F!,.@()%3C$%3Eli1I0OB8%60&repeat=1"
  try {
    $result = Invoke-RestMethod -Uri $URL -method "GET" -ea:4;
  } catch { 
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    sleep 10
    $result = Invoke-RestMethod -Uri $URL -method "GET" -ea:4;
  }

  return $result

} 

Function Generate-DomainContent{
  param(
    $UserPassword,
    $WindowsDomain,
    $servicePassword,
    $serviceuser,
    $domainPassword,
    $domainInstallUser,
    $tier,
    $SiteLongCode,
    $SiteshortCode,
    $FirstdomaincontrollerIP = (Test-Connection $WindowsDomain -count 1).ipv4address.ipaddresstostring
  )

  $password = $domainPassword | ConvertTo-SecureString -asplaintext -force;
  $domain = ((Get-WmiObject Win32_ComputerSystem).Domain)
  $credential = New-Object System.Management.Automation.PsCredential("$($WindowsDomain)\$($domainInstallUser)",$password);

  write "Connecting to the first responding DC $FirstdomaincontrollerIP"

  $Dnsname = ([System.Net.Dns]::GetHostbyAddress("$FirstdomaincontrollerIP")).hostname 
  
  write "here $dnsname" 

  write "Reconnecting to latest OS version Name $Dnsname"

  $LatestDomainControllerIP = invoke-command -computername $Dnsname -credential $credential {
    $allDCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ }
    ($allDCs | sort [version]OperatingSystemVErsion -Desc | select -first 1).IPv4Address
  }

  write "Reconnecting to latest OS version DC $LatestDomainControllerIP"

  $Dnsname = ([System.Net.Dns]::GetHostbyAddress("$LatestDomainControllerIP")).hostname 

  write "Reconnecting to latest OS version Name $Dnsname"

  [array]$output = invoke-command -computername $Dnsname -credential $credential {
    start-transcript c:\windows\temp\ADConfig.log 
    $DomainPath       = ((((Get-ADOrganizationalUnit -Filter *) | select -first 1).DistinguishedName).split(',') | where {$_ -match "DC"}) -join(',') 
    $tier             = $args[0]
    $servicePassword  = $args[1]
    $DummyADContent   = $args[2]
    $serviceuser      = $args[3]
    $WindowsDomain    = $args[4]
    $SiteshortCode    = $args[5]
    $SiteLongCode     = $args[6]
    $DNSdomain        = (Get-ADDomain).dnsroot
    $ServiceAccounts  = "svc_1cd","svc_sql","svc_mgt","svc_files";
    $servicePassword  = $servicePassword | convertto-securestring -AsPlainText -Force
    write "Using Domain Path '$DomainPath'"
    write "(Re-)Creating the Parent OUs"
    write "Cleaning first"
    write "Using site '$SiteLongCode'"
    try {
      New-ADOrganizationalUnit -Name "$($SiteLongCode)" -Path "OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "$($SiteLongCode)" -Path "OU=RoboSites,$($DomainPath)";
    };
    try {
      New-ADOrganizationalUnit -Name "CDC" -Path "OU=RoboSites,$($DomainPath)";  
      write "Creating the CDC OU"
    } catch {}
    try {
      New-ADOrganizationalUnit -Name "$tier" -Path "OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      
      New-ADOrganizationalUnit -Name "$tier" -Path "OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };
    write "(Re-)Creating the Service Account OU"
    try {
      New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=Service Accounts,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=Service Accounts,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };
    write "(Re-)Creating the Groups OU"
    try {
      New-ADOrganizationalUnit -Name "Groups" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=Groups,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=Groups,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "Groups" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };
    write "(Re-)Creating the Users OU"
    try {
      New-ADOrganizationalUnit -Name "User Accounts" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=User Accounts,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=User Accounts,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "User Accounts" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };
    write "(Re-)Creating the Admins OU"
    try {
      New-ADOrganizationalUnit -Name "Admin Accounts" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=Admin Accounts,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=Admin Accounts,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "Admin Accounts" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };
    write "(Re-)Creating the Servers OU"
    try {
      New-ADOrganizationalUnit -Name "Servers" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=Servers,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=Servers,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "Servers" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };
    write "(Re-)Creating the Nutanix OU"
    try {
      New-ADOrganizationalUnit -Name "Nutanix" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    } catch {
      Get-ADOrganizationalUnit -Identity "OU=Nutanix,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
      Get-ADOrganizationalUnit -Identity "OU=Nutanix,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" | remove-ADOrganizationalUnit -Recursive -confirm:0
      New-ADOrganizationalUnit -Name "Nutanix" -Path "OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)";
    };    
    write "Creating the Groups"
    try {
        #Global First
      new-adgroup -groupscope 1 -name "Robo-Service-Accounts-Group" -path "OU=CDC,OU=RoboSites,$($DomainPath)"
    } catch {

    }
    new-adgroup -groupscope 1 -name "$($SiteLongCode)-$($Tier)-Admin-Accounts-Group" -path "OU=Groups,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" 
    new-adgroup -groupscope 1 -name "$($SiteLongCode)-$($Tier)-Service-Accounts-Group" -path "OU=Groups,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)"
    new-adgroup -groupscope 1 -name "$($SiteLongCode)-$($Tier)-User-Accounts-Group" -path "OU=Groups,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)" 
        
    Write "Creating Service Accounts"
    foreach ($serviceaccount in $ServiceAccounts){;
      try {
        new-aduser -name "$($serviceaccount)" -AccountPassword $servicePassword -PasswordNeverExpires $true -userPrincipalName "$($serviceaccount)@$($DNSdomain)" -path "OU=CDC,OU=RoboSites,$($DomainPath)" -ea:4;
      }catch {}
      try {
        add-ADGroupMember  "Robo-Service-Accounts-Group" "$($serviceaccount)" -ea:4 | out-null;
      }catch{}
    };

    write "OU=Servers,OU=$tier,OU=$($SiteLongCode),OU=RoboSites,$($DomainPath)"
 
  } -args $tier,$servicePassword,$DummyADContent,$serviceuser,$WindowsDomain,$SiteshortCode,$SiteLongCode
  $output | out-file c:\windows\temp\ADConfig.log 
  $output = $output -split " "
  $ServerOU = $output | select -last 1
  $error.clear()

  if ($debug -ge 1){

    write $output

  }

  return $ServerOU
}


Function PSR-Join-Domain {
  param (
    [string]$SysprepPassword,
    [string]$IP,
    [string]$DNSServer,
    [string]$Domainname
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential objects (2).";

  $password = $SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $LocalCreds = New-Object System.Management.Automation.PsCredential("administrator",$password);
  $DomainCreds = New-Object System.Management.Automation.PsCredential("$($Domainname)\administrator",$password);

  $installsuccess = $false
  $installcount = 0
  $promotesuccess = $false
  $promotecount = 0
  $Joincount = 0
  $JoinSuccess = $true

  write-log -message "Joining the machine to the domain.";
 
  do{
    $Joincount++
    write-log -message "How many times am i doing this $Joincount"
    try {
      if (-not (Test-Connection -ComputerName $IP -Quiet -Count 1)) {
      
        write-log -message "Could not reach $IP" -sev "WARN"
      
      } else {
      
        write-log -message "$IP is being added to domain $Domainname..."
      
        try {
          Add-Computer -ComputerName $IP -Domain $Domainname -restart -Localcredential $LocalCreds -credential $DomainCreds -force 

        } catch {
          
          sleep 70

          try {
            $connect = invoke-command -computername $ip -credential $DomainCreds {
              (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            } -ea:4
          }  catch {  
            write-log -message "I dont want to be here."
          }
        }
        while (Test-Connection -ComputerName $IP -Quiet -Count 1 -or $countrestart -le 30) {
          
          write-log -message "Machine is restarting"

          $countrestart++
          Start-Sleep -Seconds 2
          }
      
          write-log -message "$IP was added to domain $Domain..."
          sleep 20
       }

    } catch {

      write-log -message "Join domain almost always throws an error..."

      sleep 40
      try {
        $connect = invoke-command -computername $ip -credential $DomainCreds {
          (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        } -ea:4
      } catch {
        $connect = $false 
      }
      if ($connect -eq $true ){
        $Joinsucces = $true

        write-log -message "Machine Domain Join Confirmed"

      } else {

        write-log -message "If you can read this.. $Joincount"

      }
    };
    sleep 30
  } until ($Joincount -ge 3 -or $connect -eq $true)

  


  if ($Joinsucces -eq $true ){
    $status = "Success"

    write-log -message "All Done here, ready for some Content";
    write-log -message "Please pump me full of lead.";

  } else {
    $status = "Failed"
    write-log -message "Danger Will Robbinson." -sev "ERROR";
  }
  $resultobject =@{
    Result = $status
  };
  return $resultobject
};


Function PSR-Generate-FilesContent {
  param (
    [object]$datagen,
    [object]$datavar,
    [string]$dc
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";

  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $DomainCreds = New-Object System.Management.Automation.PsCredential("$($datagen.SEUPN)",$password);
  $username =  $datagen.SEUPN
  $password = $datagen.SysprepPassword
  write-log -message "Executing Files Content Generation.";
  write-log -message "This will take a while.";
  $fsname = "$($datagen.FS1_IntName)"
  write-log -message "Using File Server $fsname";
  $domainname = $datagen.domainname
    invoke-command -computername $dc -credential $DomainCreds {
    
      $username = $args[1]
      $password = $args[2]
      $domainname = $args[3]
      $fsname = $args[0]
      [ARRAY]$OUTPUT += [STRING]'start-transcript c:\windows\temp\content.log'
      [ARRAY]$OUTPUT += [STRING]'$Username = ' + '"' + $username + '"'
      [ARRAY]$OUTPUT += [STRING]'$password = ' + '"' + $password + '"'
      [ARRAY]$OUTPUT += [STRING]'$domainname = ' + '"' + $domainname + '"'
      [ARRAY]$OUTPUT += [STRING]'$fsname = ' + '"' + $fsname + '"'
      [ARRAY]$OUTPUT += [STRING]'$secpassword = $password | ConvertTo-SecureString -asplaintext -force;'
      [ARRAY]$OUTPUT += [STRING]'$DomainCreds = New-Object System.Management.Automation.PsCredential($Username,$secpassword);'
      [ARRAY]$OUTPUT += [STRING]'write "Content Indexing Starting"'
      [ARRAY]$OUTPUT += [STRING]'$Wavfiles = get-childitem -recurse "c:\*.wav" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'write "Wav Files $($Wavfiles.count) Done, doing doc"'
      [ARRAY]$OUTPUT += [STRING]'$docfiles = get-childitem -recurse "c:\*.doc" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'write "doc Files $($docfiles.count) Done, doing jpg"'
      [ARRAY]$OUTPUT += [STRING]'$jpgfiles = get-childitem -recurse "c:\*.jpg" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'write "JPG Files $($jpgfiles.count) Done, doing cab"'
      [ARRAY]$OUTPUT += [STRING]'$Cabfiles = get-childitem -recurse "c:\*.cab" -ea:4 | select -first 20'
      [ARRAY]$OUTPUT += [STRING]'write "CAB Files $($Cabfiles.count) Done, doing zip"'
      [ARRAY]$OUTPUT += [STRING]'$zipfiles = get-childitem -recurse "c:\*.zip" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'write "Zip Files $($zipfiles.count) Done, doing Txt"'
      [ARRAY]$OUTPUT += [STRING]'$txtfiles = get-childitem -recurse "c:\*.txt" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'write "TXT Files $($txtfiles.count) Done, doing AVI"'
      [ARRAY]$OUTPUT += [STRING]'$avifiles = get-childitem -recurse "c:\*.avi" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'write "Content Indexing Completed, $($avifiles.count)"'
      [ARRAY]$OUTPUT += [STRING]'Get-ADUser -Filter * | Foreach-Object{'
      [ARRAY]$OUTPUT += [STRING]'  $user = $_'
      [ARRAY]$OUTPUT += [STRING]'  $sam = $_.SamAccountName'
      [ARRAY]$OUTPUT += [STRING]'  write "Working on $sam"'
      [ARRAY]$OUTPUT += [STRING]'  Set-ADuser -Identity $_ -HomeDrive "H:" -HomeDirectory "\\$($fsname)\$sam" -ea:4'
      [ARRAY]$OUTPUT += [STRING]'  $homeShare = new-item -path "\\$($fsname)\UserHome\$sam" -ItemType Directory -force'
      [ARRAY]$OUTPUT += [STRING]'  $acl = Get-Acl $homeShare -ea:4'
      [ARRAY]$OUTPUT += [STRING]'  $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"'
      [ARRAY]$OUTPUT += [STRING]'  $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow'
      [ARRAY]$OUTPUT += [STRING]'  $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"'
      [ARRAY]$OUTPUT += [STRING]'  $PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"'
      [ARRAY]$OUTPUT += [STRING]'  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)'
      [ARRAY]$OUTPUT += [STRING]'  $acl.AddAccessRule($AccessRule)'
      [ARRAY]$OUTPUT += [STRING]'  Set-Acl -Path $homeShare -AclObject $acl -ea:4'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $Wavfiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 3'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).wav"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $cabfiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 10'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).cab"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $docfiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 50'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).doc"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $jpgfiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 19'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).jpg"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $zipfiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 20'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).zip"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $txtfiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 20'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).txt"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $avifiles){'
      [ARRAY]$OUTPUT += [STRING]'    [int]$number =get-random -max 30'
      [ARRAY]$OUTPUT += [STRING]'    [int]$count = 0'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      [int]$count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\UserHome\$($sam)\$($targetfilename).avi"'
      [ARRAY]$OUTPUT += [STRING]'    } until ([int]$count -ge [int]$number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'}'
      [ARRAY]$OUTPUT += [STRING]''
      [ARRAY]$OUTPUT += [STRING]'[array]$array += "Finance"'
      [ARRAY]$OUTPUT += [STRING]'[array]$array += "IT"'
      [ARRAY]$OUTPUT += [STRING]'[array]$array += "HR"'
      [ARRAY]$OUTPUT += [STRING]'[array]$array += "Factory"'
      [ARRAY]$OUTPUT += [STRING]'[array]$array += "RnD"'
      [ARRAY]$OUTPUT += [STRING]'[array]$array += "Management"'
      [ARRAY]$OUTPUT += [STRING]'foreach ($item in $array){'
      [ARRAY]$OUTPUT += [STRING]'  copy-item -type "Directory" "\\$($fsname)\Department\$item"'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $Wavfiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      write $targetfilename'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).wav"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  $count =0'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $docfiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      write $targetfilename'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).doc"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $jpgfiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      write $targetfilename'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).jpg"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $Cabfiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      write $targetfilename'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).cab"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $zipfiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      write $targetfilename'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).zip"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $txtfiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).txt"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'  foreach ($file in $avifiles){'
      [ARRAY]$OUTPUT += [STRING]'    $count =0'
      [ARRAY]$OUTPUT += [STRING]'    $number =get-random -max 100'
      [ARRAY]$OUTPUT += [STRING]'    do {'
      [ARRAY]$OUTPUT += [STRING]'      $count++'
      [ARRAY]$OUTPUT += [STRING]'      $targetfilename = Get-Random'
      [ARRAY]$OUTPUT += [STRING]'      copy-item "$($file.fullname)" "\\$($fsname)\Department\$item\$($targetfilename).avi"'
      [ARRAY]$OUTPUT += [STRING]'    } until ($count -ge $number)'
      [ARRAY]$OUTPUT += [STRING]'  }'
      [ARRAY]$OUTPUT += [STRING]'}'
      $OUTPUT | OUT-FILE C:\windows\temp\content.ps1
      $argumentList = "-file C:\Windows\Temp\Content.ps1"
      $jobname = "PowerShell Content Generate";
      $action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$argumentList";
      $trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd;
      $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
      #$Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
      #$CredPassword = $Credentials.GetNetworkCredential().Password 
      $task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -Settings $settings -runlevel "Highest" -User $username -Password $password
      # 
      Get-ScheduledTask "PowerShell Content Generate" | start-scheduledtask
      sleep 60
      Get-ScheduledTask "PowerShell Content Generate" | start-scheduledtask

    } -args $FSname,$username,$password,$domainname
  $counter = 0
  write-log -message "Tailing the log from the remote session to capture success"

     $status = "Success"
 



  write-log -message "All Done here, full of File Content";
  write-log -message "Please play with me.";

  $resultobject =@{
    Result = $status
  };
  return $resultobject
};


Function Wait-Mgt-Task{
  param(
    $datavar
  )
  write-log -message "Wait for Management Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^mgmtVM" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^mgmtVM" }
      } catch {}
    }

    write-log -message "We found $($tasks.count) task";

    [array] $allready = $null
    write-log "Cycle $looper out of 200"
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
    
          write-log -message "Task $($task.taskname) is ready."
    
          $allReady += 1
      
        } else {
      
          $allReady += 0

          write-log -message "Task $($task.taskname) is $($task.state)."
      
        };
      };
      sleep 60
    } else {
      $allReady = 0
      # Dont ever change this or ERA will start too soon
      write-log -message "There are no jobs to process."
      sleep 60
    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}


Function Wait-Image-Task{
  param(
    $datavar
  )
  write-log -message "Wait for Immage Convert Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^WaitImage" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^WaitImage" }
      } catch {}
    }

    write-log -message "We found $($tasks.count) task";

    [array] $allready = $null
    write-log "Cycle $looper out of 200"
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
    
          write-log -message "Task $($task.taskname) is ready."
    
          $allReady += 1
      
        } else {
      
          $allReady += 0

          write-log -message "Task $($task.taskname) is $($task.state)."
      
        };
      };
      sleep 60
    } else {
      $allReady = 0

      write-log -message "There are no jobs to process."
      sleep 60
    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}


Function Wait-POSTPC-Task{
  param(
    $datavar
  )
  write-log -message "Wait for POST PC Task with ID $($datavar.queueuuid)"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^POSTPC" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^POSTPC" }
      } catch {}
    }
    if ($Looper % 4 -eq 0){
      write-log -message "We found $($tasks.count) task";
    }
    [array] $allready = $null
    if ($Looper % 4 -eq 0){
      write-log "Cycle $looper out of 200"
    }
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
          
          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is ready."
          }
          $allReady += 1
      
        } else {
      
          $allReady += 0

          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is $($task.state)."
          }
        };
      };
      sleep 60
    } else {
      $allReady = 0
      sleep 60
      if ($Looper % 4 -eq 0){
        write-log -message "There are no jobs to process."
      }
    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}

Function Wait-MySQL-Task{
  param(
    $datavar
  )
  write-log -message "Wait for MySQL Task with ID $($datavar.queueuuid), OVF is single threaded. If MySQL is running ERA OVF is done"
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^ERA_MySQL" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^ERA_MySQL" }
      } catch {}
    }
    if ($Looper % 4 -eq 0){
      write-log -message "We found $($tasks.count) task";
    }
    [array] $allready = $null
    if ($Looper % 4 -eq 0){
      write-log "Cycle $looper out of 200"
    }
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
          
          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is ready."
          }
          $allReady += 1
      
        } else {
      
          $allReady += 1

          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is $($task.state)."
          }
        };
      };
      sleep 60
    } else {
      $allReady = 0
      sleep 60
      if ($Looper % 4 -eq 0){
        write-log -message "There are no jobs to process."
      }
    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}


Function Wait-XRAY-Task{
  param(
    $datavar
  )
  write-log -message "Wait for XRAY Task with ID $($datavar.queueuuid), OVF is single threaded."
  do {
    $Looper++
    try{
      [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^X-Ray" }
    } catch {
      try {
        [array]$tasks = Get-ScheduledTask | where {$_.taskname -match $datavar.queueuuid -and $_.taskname -match "^X-Ray" }
      } catch {}
    }
    if ($Looper % 4 -eq 0){
      write-log -message "We found $($tasks.count) task";
    }
    [array] $allready = $null
    if ($Looper % 4 -eq 0){
      write-log "Cycle $looper out of 200"
    }
    if ($tasks){
      Foreach ($task in $tasks){
        if ($task.state -eq "ready"){
          
          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is ready."
          }
          $allReady += 1
      
        } else {
      
          $allReady += 0

          if ($Looper % 4 -eq 0){
            write-log -message "Task $($task.taskname) is $($task.state)."
          }
        };
      };
      sleep 60
    } else {
      $allReady = 0
      sleep 60
      if ($Looper % 4 -eq 0){
        write-log -message "There are no jobs to process."
      }
    }
  } until ($Looper -ge 200 -or $allReady -notcontains 0)
}

Function Wait-LCM-Task{
  param(
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [int]$modecounter = 35,
    [string] $taskid = $null,
    [string] $mode
  )
  do {
    try{
      $counter++
      write-log -message "Waiting on LCM Task Cycle '$counter' out of '$($modecounter)'(minutes)."
  
      $tasks = REST-Px-ProgressMonitor -PxClusterIP $PxClusterIP -PxClusterUser $PxClusterUser -PxClusterPass $PxClusterPass $mode 
      $LCMTasks = $tasks.entities | where { $_.operation -eq "LcmRootTask"} 
      $Inventorycount = 0
      [array]$Results = $null
      foreach ($item in $LCMTasks){
        if ( $item.percentageCompleted -eq 100) {
          $Results += "Done"
   
          write-log -message "LCM Task '$($item.id)' is completed."
        } elseif ($item.percentageCompleted -ne 100){
          $Inventorycount ++
  
          write-log -message "LCM Task '$($item.id)' is still running."
          write-log -message "We found an LCM task '$($item.status)' and is '$($item.percentageCompleted)' % complete"
  
          $Results += "BUSY"
  
        }
      }
      if ($Results -notcontains "BUSY" -or !$LCMTasks){

        write-log -message "Task is completed."
   
        $Inventorycheck = "Success"
   
      } else{
        sleep 60
      }
  
    }catch{
      sleep 2
      $error.clear()
      write-log -message "Error caught in loop." -sev "WARN"
    }
  } until ($Inventorycheck -eq "Success" -or $counter -ge $modecounter)
  $task = $LCMTasks | sort createTimeUsecs | select -last 1
  return $task
}

Function Wait-AOS-Prescan {
  param(
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $AvailableAOSversion,
    [object] $calmvars
  )

  write-log -message "Checking Upgrade status"
  
  write-log -message "Checking Prescan status"
  $installcounter = 0
  do{
    $installcounter++
    sleep 60
    try{
      $tasks = REST-Get-AOS-LegacyTask -PEClusterIP $PEClusterIP -PxClusterUser $PxClusterUser -PxClusterPass $PxClusterPass

      write-log -message "We found '$($tasks.entities.count)' total tasks"
      write-log -message "Waiting '$installcounter' out of '20' on AOS Prescan."

      $task = $tasks.entities | where {$_.operation -eq "ClusterPreUpgradeTask" }
      $task = $task | select -first 1
      if (!$task){

        write-log -message "Prepare Task is not running."

        if ($installcounter -eq 3 -or $installcounter -eq 6 -or $installcounter -eq 9 -or $installcounter -eq 15){
          #PSR-Wait-PE-Health -CalmVars $CalmVars 2 Node requirement
          sleep 60

          write-log -message "This is the 3rd time already, kicking it again."

          $upgrade = REST-AOS-Upgrade -PEClusterIP $PEClusterIP -PxClusterUser $PxClusterUser -PxClusterPass $PxClusterPass -AvailableAOSVersion $AvailableAOSversion
        }

      } else {

        write-log -message "AOS PreScan is '$($task.status)' at '$($task.percentageCompleted)%'"

        if ($task.status -eq "ERROR"){
          
          #PSR-Wait-PE-Health -CalmVars $CalmVars
          sleep 119
        }
      }
    } catch {

      write-log -message "I Should not be here, or CVM is restarting" -sev "warn"
    }
  } until (($task -and $task.status -ne "running" -and $task.status -ne "ERROR") -or $installcounter -ge 20)
  return $task
}


Function Wait-AOS-Upgrade {
  param(
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Checking Upgrade status"

  $installcounter = 0
  do{
    $installcounter++
    sleep 60
    try{
      $tasks = REST-Get-AOS-LegacyTask -PEClusterIP $PEClusterIP -PxClusterUser $PxClusterUser -PxClusterPass $PxClusterPass

      write-log -message "We found '$($tasks.entities.count)' total tasks"
      write-log -message "AOS upgrade, Waiting '$installcounter' out of '120' cycles"

      $task = $tasks.entities | where {$_.operation -eq "ClusterUpgradeTask"}
      if (!$task){

        write-log -message "Upgrade Task is not running (yet)."

      } else {

        write-log -message "AOS Upgrade is '$($task.status)' at '$($task.percentageCompleted)%'"

      }
    } catch {
      $error.clear()
      write-log -message "I Should not be here, or CVM is restarting" -sev "warn"
    }
  } until (($task -and $task.status -ne "running") -or $installcounter -ge 120)
  return $task
}


Function Wait-AHV-Upgrade {
  param(
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  write-log -message "Checking Upgrade status"
  $installcounter = 0
  do{
    [array]$notready = $null
    $installcounter++
    sleep 60
    try{
      $tasks = REST-Get-AOS-LegacyTask -PEClusterIP $PEClusterIP -PxClusterUser $PxClusterUser -PxClusterPass $PxClusterPass
  
      write-log -message "We found '$($tasks.entities.count)' total tasks"
      write-log -message "Waiting '$installcounter' out of '60' for AHV Upgrade"
  
      $upgrades = $tasks.entities | where {$_.operation -eq "upgrade_hypervisor"}

      write-log -message "We found $($upgrades.count) Upgrade tasks"
      foreach ($upgrade in $upgrades){

        write-log -message "AHV Upgrade is '$($upgrade.status)' at '$($upgrade.percentageCompleted)%'"

        if ($upgrade.status -eq "Running"){
          $notready += 1
        } 
      }
    } catch {
      $notready += 1
      write-log -message "I Should not be here, or CVM is restarting" -sev "warn"
    }
  } until (($notready -eq $null) -or $installcounter -ge 60)
  sleep 60
}



Function PSR-Reboot-PC {
  param (
    [object] $datagen,
    [object] $datavar
  )
  
  write-log -message "Rebooting PC" -SEV "WARN"
  if ($datavar.Hypervisor -match "Nutanix|AHV"){
    $hide = LIB-Connect-PSNutanix -ClusterName $datavar.PEClusterIP -NutanixClusterUsername $datagen.buildaccount -NutanixClusterPassword $datavar.PEPass
    $hide = get-ntnxvm | where {$_.vmname -match "^PC"} | Set-NTNXVMPowerState -transition "ACPI_REBOOT" -ea:4    
  } else {
    $hide = CMD-Connect-VMware -datavar $datavar
    $hide = get-vm | Where {$_.name -match "^PC" } | restart-vm -confirm:0 -ea:4
  }
 
  $rebootsleeper = 0
  do {
    $rebootsleeper ++
    sleep 115
    write-log -message "Keep Calm : $rebootsleeper / 8 "
  } until ($rebootsleeper -ge 8)
}

Function PSR-LCM-ListUpdates-Px {
  param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $mode,
    [object] $hosts,
    [string] $minimalupdates = 1,
    [string] $AHVTargetVer
  )
  write-log -message "Working with update requirement of '$minimalupdates' updates."
  $maxgroupcallLoops = 3
  
  $groupcall = 0
  $AvailableUpdatesList = $null
  $InstalledSoftwareList = $null
  
  $groupcall = 0
  do {
    $groupcall ++
    sleep 10
    if ($minimalupdates -eq 0){
      $AvailableUpdatesGroup = REST-LCMV2-Query-Updates -PxClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser -mode $mode -silent $true
    } else {
      $AvailableUpdatesGroup = REST-LCMV2-Query-Updates -PxClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser -mode $mode
    }
    $ExistingSoftwareGroup = REST-LCMV2-Query-Versions  -PxClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser -mode $mode
  } until (($result.group_results.entity_results.count -ge $minimalupdates -and $names.group_results.entity_results.count -ge $minimalupdates) -or $groupcall -ge $maxgroupcallLoops)
  
  $UUIDS = ($ExistingSoftwareGroup.group_results.entity_results.data | where {$_.name -eq "uuid"}).values.values
  
  write-log -message "Getting Installed Software"
  
  foreach ($app in $UUIDS){
    $nodeUUID = (((($ExistingSoftwareGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "location_id"}).values.values | select -last 1) -split ":")[1]
    $PHhost = $hosts.entities | where {$_.uuid -match $nodeuuid}
    $Entity = [PSCustomObject]@{
      Version     = (($ExistingSoftwareGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "version"}).values.values | select -last 1
      Class       = (($ExistingSoftwareGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "entity_class"}).values.values | select -last 1
      Name        = (($ExistingSoftwareGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "entity_model"}).values.values | select -last 1
      HostUUID    = $phhost.uuid
      HostName    = $phhost.Name
      SoftwareUUID= $app
    }
    [array]$InstalledSoftwareList += $entity     
  }  
  
  write-log -message "Building Update table"
  
  foreach ($app in $UUIDs){
    $version = (($AvailableUpdatesGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "version"}).values.values | select -last 1
    if ($version -match "el.*nutanix.*"){
      $version = (($AvailableUpdatesGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "version"}).values.values | where { $_ -match $AHVTargetVer }
    }
    $nodeUUID = (((($ExistingSoftwareGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "location_id"}).values.values | select -last 1) -split ":")[1]
    $PHhost = $hosts.entities | where {$_.uuid -match $nodeuuid}
    $Entity = [PSCustomObject]@{
      SoftwareUUID= $app
      Version     = $version
      HostUUID    = $phhost.uuid
      HostName    = $phhost.Name
      Class       = (($AvailableUpdatesGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "entity_class"}).values.values | select -last 1
      Name        = (($ExistingSoftwareGroup.group_results.entity_results | where {$_.data.values.values -eq $app}).data | where {$_.name -eq "entity_model"}).values.values | select -last 1
    }
    [array]$AvailableUpdatesList += $entity     
  }

  $Output = [PSCustomObject]@{
    AvailableUpdatesList        = $AvailableUpdatesList
    InstalledSoftwareList       = $InstalledSoftwareList
    Updatecount                 = $AvailableUpdatesGroup.total_entity_count
  }
  return $Output
}


Function Wait-PE-Reboot-Task{
  param(
    $datagen,
    $datavar,
    [int]$modecounter = 45
  )
  do {
    try{
      $counter++
      write-log -message "Wait for LCM Task Cycle $counter out of $($modecounter)(minutes)."
  
      $tasks = REST-Px-ProgressMonitor -datagen $datagen -datavar $datavar -mode "PE" 
      $LCMTasks = $tasks.entities | where { $_.operation -eq "Hypervisor rolling restart"} 
      $RebootCount = 0
      [array]$Results = $null
      foreach ($item in $LCMTasks){
        if ( $item.percentageCompleted -eq 100) {
          $Results += "Done"
   
          write-log -message "PE Reboot Task $($item.id) is completed."
        } elseif ($item.percentageCompleted -ne 100){
          $RebootCount ++
  
          write-log -message "PE Reboot Task $($item.id) is still running."
          write-log -message "We found 1 PE Reboot Task $($item.status) and is $($item.percentageCompleted) % complete"
  
          $Results += "BUSY"
  
        }
      }
      if ($Results -notcontains "BUSY" -or !$LCMTasks){

        write-log -message "Task is completed."
   
        $Reboot = "Success"
   
      } else{
        sleep 60
      }
  
    }catch{
      write-log -message "Error caught in loop."
    }
  } until ($Reboot -eq "Success" -or $counter -ge $modecounter)
  $task = $LCMTasks |sort createdtimeusecs | select -last 1
  return $task
}

Function PSR-Install-NGT {
  param (
    [object]$datagen,
    [object]$datavar,
    [string]$ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";


  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  $password = $datagen.SysprepPassword
  invoke-command -computername $ip -credential $creds {
    $username = $args[0]
    $password = $args[1]

    [ARRAY]$OUTPUT += [STRING]'$driveletter = (Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select DeviceID).deviceid'
    [ARRAY]$OUTPUT += [STRING]'& "$($driveletter)\setup.exe" /quiet ACCEPTEULA=yes /norestart'
    $OUTPUT | OUT-FILE C:\windows\temp\NGT.ps1
    $argumentList = "-file C:\Windows\Temp\NGT.ps1"
    $jobname = "PowerShell NGT Install";
    $action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$argumentList";
    $trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd;
    $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
    $CredPassword = $Credentials.GetNetworkCredential().Password 
    $task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -Settings $settings -runlevel "Highest" -User "administrator" -Password $CredPassword
    # 
    Get-ScheduledTask $jobname | start-scheduledtask
  } -args $username,$password
  $status = "Success"

  write-log -message "All Done here, NGT Done";

  $resultobject =@{
    Result = $status
  };
  return $resultobject
};


Function PSR-Install-FrameAgent {
  param (
    [object]$datagen,
    [object]$datavar,
    [string]$ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";


  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  $password = $datagen.SysprepPassword
  invoke-command -computername $ip -credential $creds {
    $username = $args[0]
    $password = $args[1]

    [ARRAY]$OUTPUT += [STRING]'$driveletter = (Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select DeviceID).deviceid'
    [ARRAY]$OUTPUT += [STRING]'& "$($driveletter)\setup.exe" /quiet ACCEPTEULA=yes /norestart'
    $OUTPUT | OUT-FILE C:\windows\temp\NGT.ps1
    $argumentList = "-file C:\Windows\Temp\NGT.ps1"
    $jobname = "PowerShell NGT Install";
    $action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$argumentList";
    $trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd;
    $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
    $CredPassword = $Credentials.GetNetworkCredential().Password 
    $task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -Settings $settings -runlevel "Highest" -User "administrator" -Password $CredPassword
    # 
    Get-ScheduledTask $jobname | start-scheduledtask
  } -args $username,$password
  $status = "Success"

  write-log -message "All Done here, NGT Done";

  $resultobject =@{
    Result = $status
  };
  return $resultobject
};

Function PSR-Install-Office {
  param (
    [object]$datagen,
    [object]$datavar,
    [string]$ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";




  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  $password = $datagen.SysprepPassword
  invoke-command -computername $ip -credential $creds {
    $username = $args[0]
    $password = $args[1]
    [ARRAY]$OUTPUT += [STRING]'$Path = $env:TEMP;'
    [ARRAY]$OUTPUT += [STRING]'$Installer = "chrome_installer.exe";'    
    [ARRAY]$OUTPUT += [STRING]'Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer;'
    [ARRAY]$OUTPUT += [STRING]'Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait; '
    [ARRAY]$OUTPUT += [STRING]'Remove-Item $Path\$Installer; '
    [ARRAY]$OUTPUT += [STRING]'$MSP = "Office2016.msp";'
    [ARRAY]$OUTPUT += [STRING]'$xml = "Office2016.msp.xml";'
    [ARRAY]$OUTPUT += [STRING]'Invoke-WebRequest "https://dl.dropboxusercontent.com/s/06ttdbg13nz0lpc/Office2016.MSP" -OutFile $Path\$MSP;'
    [ARRAY]$OUTPUT += [STRING]'Invoke-WebRequest "https://dl.dropboxusercontent.com/s/x9axoo0dnl7nfwp/Office2016.MSP.xml" -OutFile $Path\$xml;'
    [ARRAY]$OUTPUT += [STRING]'$driveletter = (Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select DeviceID).deviceid'
    [ARRAY]$OUTPUT += [STRING]'& "$($driveletter)\setup.exe" /adminfile $Path\$MSP'
    
    $OUTPUT | OUT-FILE C:\windows\temp\Office.ps1
    $argumentList = "-file C:\Windows\Temp\Office.ps1"
    $jobname = "PowerShell Office Install";
    $action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$argumentList";
    $trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd;
    $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
    $CredPassword = $Credentials.GetNetworkCredential().Password 
    $task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -Settings $settings -runlevel "Highest" -User "administrator" -Password $CredPassword
    # 
    Get-ScheduledTask $jobname | start-scheduledtask
  } -args $username,$password
  $status = "Success"

  write-log -message "All Done here, Office Install Running";

  $resultobject =@{
    Result = $status
  };
  return $resultobject
};

Function PSR-Set-Time {
  param (
    [object] $datagen,
    [object] $datavar,
    [string] $ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";
  $localdatetime = "$($(get-date).addseconds(30))"
  $localtimezone = (get-timezone).id
  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  invoke-command -computername $ip -credential $creds {
    $localtimezone = $args[0]
    [datetime]$localdatetime = $args[1]
    set-timezone -id $localtimezone
    set-date $localdatetime
  } -args $localtimezone,$localdatetime 
}

Function PSR-Install-WindowsUpdates {
  param (
    [object] $datagen,
    [object] $datavar,
    [string] $ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";


  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  $password = $datagen.SysprepPassword
  invoke-command -computername $ip -credential $creds {
    $username = $args[0]
    $password = $args[1]
    [ARRAY]$OUTPUT += [STRING]'Install-PackageProvider -Name NuGet -Force -confirm:0'
    [ARRAY]$OUTPUT += [STRING]'Install-Module PSWindowsUpdate -confirm:0 -force'
    [ARRAY]$OUTPUT += [STRING]'Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -confirm:0'
    [ARRAY]$OUTPUT += [STRING]'Get-WUInstall -MicrosoftUpdate -AcceptAll –AutoReboot -download -install -confirm:0'
    
    $OUTPUT | OUT-FILE C:\windows\temp\Updates.ps1
    $argumentList = "-file C:\Windows\Temp\Updates.ps1"
    $jobname = "PowerShell Updates Install";
    $action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$argumentList";
    $trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd;
    $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
    $CredPassword = $Credentials.GetNetworkCredential().Password 
    $task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -Settings $settings -runlevel "Highest" -User "administrator" -Password $CredPassword
    # 
    Get-ScheduledTask $jobname | start-scheduledtask
  } -args $username,$password
  $status = "Success"

  write-log -message "All Done here, Updates are running Leave it now, this should be our last step.";

  $resultobject =@{
    Result = $status
  };
  return $resultobject
};

Function PSR-Validate-NGT {
  param (
    [object] $datagen,
    [object] $datavar,
    [string] $ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";
  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  $Present = invoke-command -computername $ip -credential $creds {
    get-item "c:\progra~1\Nutanix\ngtcli\ngtcli.cmd"
  }
  return $Present
}

Function Test-SameSubnet { 
  param ( 
  [parameter(Mandatory=$true)] 
  [Net.IPAddress] 
  $ip1, 
  
  [parameter(Mandatory=$true)] 
  [Net.IPAddress] 
  $ip2, 
  
  [parameter()] 
  [alias("SubnetMask")] 
  [Net.IPAddress] 
  $mask ="255.255.255.0" 
  ) 
  
  if (($ip1.address -band $mask.address) -eq ($ip2.address -band $mask.address)) {
    return $true
  } else {
    return $false
  } 
}

function Convert-IpAddressToMaskLength {
  Param(
    [string] $dottedIpAddressString
    )
  $result = 0; 
  # ensure we have a valid IP address
  [IPAddress] $ip = $dottedIpAddressString;
  $octets = $ip.IPAddressToString.Split('.');
  foreach($octet in $octets)
  {
    while(0 -ne $octet) 
    {
      $octet = ($octet -shl 1) -band [byte]::MaxValue
      $result++; 
    }
  }
  return $result;
}

function Get-LastAddress{
  param(
    $IPAddress,
    $SubnetMask
  )
  filter Convert-IP2Decimal{
      ([IPAddress][String]([IPAddress]$_)).Address
  }
  filter Convert-Decimal2IP{
    ([System.Net.IPAddress]$_).IPAddressToString 
  }
  [UInt32]$ip = $IPAddress | Convert-IP2Decimal
  [UInt32]$subnet = $SubnetMask | Convert-IP2Decimal
  [UInt32]$broadcast = $ip -band $subnet 
  $secondlast = $broadcast -bor -bnot $subnet | Convert-Decimal2IP
  $bc = $secondlast.tostring()
  [int]$Ending = ($bc.split(".") | select -last 1) -2
  [Array]$Prefix = $bc.split(".") | select -first 3;
  $EndingIP = [string]($Prefix -join(".")) + "." + $Ending
  return $endingIP
}


Function PSR-Install-Choco {
  param (
    [object] $datagen,
    [object] $datavar,
    [string] $ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";
  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  invoke-command -computername $ip -credential $creds {
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    get-pssession | remove-pssession
  } 
}

Function PSR-Install-PowerCLI {
  param (
    [object] $datagen,
    [object] $datavar,
    [string] $ip
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential object";
  $username = "administrator"
  $password = $datagen.SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $Creds = New-Object System.Management.Automation.PsCredential($username,$password);
  invoke-command -computername $ip -credential $creds {
    C:\ProgramData\chocolatey\bin\choco.exe install vmware-powercli-psmodule --version 11.3.0.13990089 -y
  }
  get-pssession | remove-pssession 
}


Function PSR-Create-Domain {
  param (
    [string] $SysprepPassword,
    [string] $IP,
    [string] $DNSServer,
    [string] $Domainname
  )
  $netbios = $Domainname.split(".")[0]

  write-log -message "Debug level is $debug";
  write-log -message "Building credential object.";

  $password = $SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $credential = New-Object System.Management.Automation.PsCredential("administrator",$password);

  write-log -message "Installing AD software";
  write-log -message "Awaiting completion install AD software";

  try {  
    $connect = invoke-command -computername $ip -credential $credential { Install-WindowsFeature -Name AD-Domain-Services,GPMC,DNS,RSAT-ADDS -IncludeManagementTools -Restart};
  } catch {

    write-log -message "Retry Promote First DC." -sev "WARN";

    $connect = invoke-command -computername $ip -credential $credential { Install-WindowsFeature -Name AD-Domain-Services,GPMC,DNS,RSAT-ADDS -IncludeManagementTools -Restart};
  }
  write-log -message "Waiting in a 15 second loop before the machine is online again.";
  do {;
    sleep 15;
    $test = test-connection -computername $ip -ea:4;
    $count++;
  } until ($test[0].statuscode -eq 0 -or $count -eq 6 );
  write-log -message "Creating Forest";
  try {
    $connect = invoke-command -computername $ip -credential $credential { 
      $hide = Install-ADDSForest -DomainNetbiosName $Args[2] -DomainName $args[0] -SafeModeAdministratorPassword $Args[1] -force -NoRebootOnCompletion -ea:4;
      shutdown -r -t 30
    } -args $Domainname,$password,$netbios;
  } catch {
    write-log -message "Retry Promote First DC." -sev "WARN"
    sleep 60
    $connect = invoke-command -computername $ip -credential $credential { 
      Install-ADDSForest -DomainNetbiosName $Args[2] -DomainName $args[0] -SafeModeAdministratorPassword $Args[1] -force -NoRebootOnCompletion;
      shutdown -r -t 15
    } -args $Domainname,$password,$netbios;
  }
  write-log -message "Sleeping 300 seconds additional to the completion.";
  sleep 420 ## Minimal stupid Windows leave it 
  write-log -message "Setting DNS Server Forwarder $DNSServer.";

  try{
    $connect = invoke-command -computername $ip -credential $credential { 
      net accounts /maxpwage:unlimited /domain;
      $dns = set-dnsserverforwarder -ipAddress $args[0]
      Get-AdUser -Filter *  | Set-ADUser -PasswordNeverExpires $true
    } -args $DNSServer;
  } catch {
    write-log -message "Retry DNS Record.";
    sleep 119;
    write-log -message "Awaiting completion Forest creation";
    sleep 119;
    $connect = invoke-command -computername $ip -credential $credential { 
      net accounts /maxpwage:unlimited /domain;
      $dns = set-dnsserverforwarder -ipAddress $args[0]
      Get-AdUser -Filter *  | Set-ADUser -PasswordNeverExpires $true
    } -args $DNSServer;
  }
  write-log -message "Rebooting final round for settings to apply";
  try{
    sleep 15
    restart-computer -computername $ip -credential $credential -force -confirm:0 -ea:4
    sleep 60
  } catch {

    write-log -message "Hmm.";

  } 
  write-log -message "Checking DNS Server Forwarder";
  try {
    $result = invoke-command -computername $ip -credential $credential {
      (get-dnsserverforwarder ).ipAddress[0].ipAddresstostring
    } 
  } catch {
    sleep 119
    $result = invoke-command -computername $ip -credential $credential {
      (get-dnsserverforwarder ).ipAddress[0].ipAddresstostring
    } 
  }
  if ($result -match $DNSServer){
    $status = "Success"

    write-log -message "We are all done here, one to beam up.";

  } else {
    $status = "Failed"
    Write-host $result
    write-log -message "Danger Will Robbinson." -sev "ERROR";

  }
  $resultobject =@{
    Result = $status
    Object = $result
  };
  return $resultobject
};

Function PSR-Add-DomainController {
  param (
    [string]$SysprepPassword,
    [string]$IP,
    [string]$DNSServer,
    [string]$Domainname
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential objects (2).";

  $password = $SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $LocalCreds = New-Object System.Management.Automation.PsCredential("administrator",$password);
  $DomainCreds = New-Object System.Management.Automation.PsCredential("$($Domainname)\administrator",$password);

  $installsuccess = $false
  $installcount = 0
  $promotesuccess = $false
  $promotecount = 0
  $Joincount = 0
  $JoinSuccess = $true

  write-log -message "Joining the machine to the domain.";
 
  do{
    $Joincount++
    write-log -message "How many times am i doing this $Joincount"
    try {
      if (-not (Test-Connection -ComputerName $IP -Quiet -Count 1)) {
      
        write-log -message "Could not reach $IP" -sev "WARN"
      
      } else {
      
        write-log -message "$IP is being added to domain $Domainname..."
      
        try {
          Add-Computer -ComputerName $IP -Domain $Domainname -restart -Localcredential $LocalCreds -credential $DomainCreds -force 

        } catch {
          
          sleep 70

          try {
            $connect = invoke-command -computername $ip -credential $DomainCreds {
              (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            } -ea:4
          }  catch {  
            write-log -message "I dont want to be here."
          }
        }
        while (Test-Connection -ComputerName $IP -Quiet -Count 1 -or $countrestart -le 30) {
          
          write-log -message "Machine is restarting"

          $countrestart++
          Start-Sleep -Seconds 2
          }
      
          write-log -message "$IP was added to domain $Domain..."
          sleep 20
       }

    } catch {

      write-log -message "Join domain almost always throws an error..."
      
      sleep 20
      try {
        $connect = invoke-command -computername $ip -credential $DomainCreds {
          (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        } -ea:4
      } catch {
        $connect = $false 
      }
      if ($connect -eq $true ){
        $Joinsucces = $true

        write-log -message "Machine Domain Join Confirmed"

      } else {

        write-log -message "If you can read this.. $Joincount"

      }
    };
    sleep 30
  } until ($Joincount -ge 5 -or $connect -eq $true)

  write-log -message "Installing AD software";
  write-log -message "Awaiting completion install AD software";
  sleep 30
  do{
    $installcount++
    try {
      $connect = invoke-command -computername $ip -credential $DomainCreds { 
        try {
          Install-WindowsFeature -Name AD-Domain-Services,GPMC,DNS,RSAT-ADDS -IncludeManagementTools;
          shutdown -r -t 10;
        } catch {;
          sleep 60;
        };
      };
      sleep 180
      if ($connect.Success -eq $true){
  
        write-log -message "Install success";
        write-log -message "Wait for reboot in 45 sec loop.";
  
        $installsuccess = $true;
      };
    } catch {

      write-log -message "NGT is slowing windows down a bit , causing new timing issues... ";
      write-log -message "Another error bites the dust!!, Retry, this was Attempt $installcount out of 5, 3 min sleep";

    }
  } until ($installcount -ge 5 -or $connect.Success -eq $true)
  
  do {;
    $test = test-connection -computername $ip -ea:4;
    sleep 45;
    $count++;
  } until ($test[0].statuscode -eq 0 -or $count -eq 6 );
  sleep 45

  do{
    $promotecount++

    write-log -message "Promoting next DC in the domain";

    $connect = invoke-command -computername $IP -credential $DomainCreds { 
      try {
        Install-ADDSDomainController -DomainName $args[0] -SafeModeAdministratorPassword $Args[1] -force -credential $args[2] -NoRebootOnCompletion;
        shutdown -r -t 30
      } catch {
        "ERROR"
      }
      sleep 180
    } -args $Domainname,$password,$DomainCreds -ea:4

    if ($connect -notmatch "ERROR"){
      $promotesuccess = $true

      write-log -message "Promote Success, confirmed the end result." 

    } else {
      
      write-log -message "Promote failed, retrying." -sev "WARN"

    }
  } until ($promotecount -ge 5 -or $promotesuccess -eq $true)

  write-log -message "Sleeping 60 sec";

  if ($promotesuccess -eq $true -and $installsuccess -eq $true){
    $status = "Success"

    write-log -message "All Done here, ready for AD Content";
    write-log -message "Please pump me full of lead.";

  } else {
    $status = "Failed"
    write-log -message "Danger Will Robbinson." -sev "ERROR";
  }
  $resultobject =@{
    Result = $status
  };
  return $resultobject
};


Function PSR-Install-CA {
  param (
    [string]$SysprepPassword,
    [string]$IP,
    [string]$Domainname
  )
  write-log -message "Debug level is $debug";
  write-log -message "Building credential objects (2).";

  $password = $SysprepPassword | ConvertTo-SecureString -asplaintext -force;
  $LocalCreds = New-Object System.Management.Automation.PsCredential("administrator",$password);
  $DomainCreds = New-Object System.Management.Automation.PsCredential("$($Domainname)\administrator",$password);

  write-log -message "Installing CA on a DC in the domain.";
 
  try {
    $connect = invoke-command -computername $ip -credential $DomainCreds {
      
      Install-WindowsFeature ADCS-Cert-Authority -confirm:0
           
      Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -CACommonName $env:userdomain -confirm:0
             
      Install-WindowsFeature ADCS-Web-Enrollment -confirm:0
           
      Install-AdcsWebEnrollment -confirm:0

    } -ea:4
  }  catch {  

    write-log -message "I dont want to be here."

  }
  
};


Function PSR-Convert-LogLine {
  param (
    $logline,
    $index,
    $Stage,
    $taskname
  )
  if ($logline -match "^#     Task"){
    $LogType = "Chapter"
    $Message = ($logline -replace "^#     Task(.*)", '$1') -replace "^\s",''
  } elseif ($logline -match "^'[0-9]"){
    $LogType = $logline -replace ".*\|\s(INFO|WARN|ERROR)\s.\|.*", '$1'
    if ($logline -Cmatch "WARN"){
      $LogType = "WARN"
    } elseif ($logline -cmatch "ERROR"){
      $LogType = "ERROR"
    }
    $Message = $logline.split("|")[2] -replace "^\s",''
    [datetime]$LogDate = ($logline.split("|")[0] -replace "'","")
  }
  $logger = New-Object PSObject
  $logger | add-member NoteProperty LogType     $Logtype
  $logger | add-member NoteProperty Date        $LogDate
  $logger | add-member NoteProperty Message     $Message
  $logger | add-member NoteProperty Index       $Index
  $logger | add-member NoteProperty Processed   "0"
  $logger | add-member NoteProperty Stage       $Stage
  $logger | add-member NoteProperty TaskName    $taskname
  if ($message -eq $null){
    $logger | add-member NoteProperty Empty     "1"
  } else {
    $logger | add-member NoteProperty Empty     "0"
  }
  return $logger
}



Function PSR-NetMaskMapping { 
  Param (
    [decimal]$length
  )

$csv = @"
    "Prefix","Size","Usable","Mask"
    "/30","4","2","255.255.255.252"
    "/29","8","6","255.255.255.248"
    "/28","16","14","255.255.255.240"
    "/27","32","30","255.255.255.224"
    "/26","64","62","255.255.255.192"
    "/25","128","126","255.255.255.128"
    "/24","256","254","255.255.255.0"
    "/23","512","510","255.255.254.0"
    "/22","1024","1022","255.255.252.0"
    "/21","2048","2046","255.255.248.0"
    "/20","4096","4094","255.255.240.0"
    "/19","8192","8190","255.255.224.0"
    "/18","16384","16382","255.255.192.0"
    "/17","32768","32766","255.255.128.0"
    "/16","65536","65534","255.255.0.0"
    "/15","131072","131070","255.254.0.0"
    "/14","262144","262142","255.252.0.0"
    "/13","524288","524286","255.248.0.0"
    "/12","1048576","1048574","255.240.0.0"
    "/11","2097152","2097150","255.224.0.0"
    "/10","4194304","4194302","255.192.0.0"
    "/9","8388608","8388606","255.128.0.0"
    "/8","16777216","16777214","255.0.0.0"
    "/7","33554432","33554430","254.0.0.0"
    "/6","67108864","67108862","252.0.0.0"
    "/5","134217728","134217726","248.0.0.0"
    "/4","268435456","268435454","240.0.0.0"
    "/3","536870912","536870910","224.0.0.0"
    "/2","1073741824","1073741822","192.0.0.0"
    "/1","2147483648","2147483646","128.0.0.0"
    "/0","4294967296","4294967294","0.0.0.0"
"@
  $mapping = convertfrom-csv $csv
  $subnet = $Mapping | where {[decimal]$_.size -ge [decimal]$length } | select -first 1
  return $subnet
}

Function PSR-Convert-LogLine {
  param (
    $logline,
    $index,
    $Stage,
    $taskname
  )
  if ($logline -match "^#     Task"){
    $LogType = "Chapter"
    $Message = ($logline -replace "^#     Task(.*)", '$1') -replace "^\s",''
  } elseif ($logline -match "^'[0-9]"){
    $LogType = $logline -replace ".*\|\s(INFO|WARN|ERROR)\s.\|.*", '$1'
    if ($logline -Cmatch "WARN"){
      $LogType = "WARN"
    } elseif ($logline -cmatch "ERROR"){
      $LogType = "ERROR"
    }
    $Message = $logline.split("|")[2] -replace "^\s",''
    [datetime]$LogDate = ($logline.split("|")[0] -replace "'","")
  }
  $logger = New-Object PSObject
  $logger | add-member NoteProperty LogType     $Logtype
  $logger | add-member NoteProperty Date        $LogDate
  $logger | add-member NoteProperty Message     $Message
  $logger | add-member NoteProperty Index       $Index
  $logger | add-member NoteProperty Processed   "0"
  $logger | add-member NoteProperty Stage       $Stage
  $logger | add-member NoteProperty TaskName    $taskname
  if ($message -eq $null){
    $logger | add-member NoteProperty Empty     "1"
  } else {
    $logger | add-member NoteProperty Empty     "0"
  }
  return $logger
}

Function PSR-Wait-PE-Health {
  param (
    [object] $CalmVars
  )

  write-log -message "Waiting max '90' minutes on AOS health status."
  write-log -message "This is generally only required on '2' NODE AOS upgrades."

  [array]$healthItems += "EXTENT_GROUPS"
  [array]$healthItems += "ZOOKEEPER"
  [array]$healthItems += "METADATA"
  [array]$healthItems += "OPLOG"

  do {
    $count ++
    $badhealth = 0
    $health = REST-Get-FT-Health `
      -PEClusterIP $CalmVars.IPAM.SPEClusterIP `
      -PxClusterUser $CalmVars.System.RoboSVCUsername `
      -PxClusterPass $CalmVars.Prompt.RoboSVCPassword

    if ($count % 4 -eq 0){

      write-log -message "Checking Health for Extend Groups, Zookeeper, MetaData and Oplog."

    }
  
    Foreach ($item in $healthItems){
      $values = $health.ComponentFaultTolerancestatus."$($item)".numberOfFailuresTolerable
      foreach ($value in $values){
        if ($value -eq 0){
          [array]$healthstatus += "$($item) is not Healthy"
          $badhealth = 1
        }
      }
    }
    if ($badhealth -eq 1){
      if ($count % 4 -eq 0){

        write-log -message "Cluster health is not green, waiting"
      
      }
      if ($debug -ge 2){
        write $healthstatus
      }

      sleep 180
    }
    if ($badhealth -eq 0){

      write-log -message "'$($healthItems)' Are all self healed, proceeding.."

    }
    if ($count -ge 20){

      write-log -message "We did not self heal in '90' minutes. Cluster is unstable" -sev "ERROR"

    }
  } until ($badhealth -eq 0 -or $count -ge 30)
}


Export-ModuleMember *
