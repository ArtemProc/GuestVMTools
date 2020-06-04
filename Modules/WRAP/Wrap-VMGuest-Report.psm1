Function Wrap-VMGuest-Report {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  $PEhosts = REST-Get-PRX-Hosts `
    -PCClusterIP $vars.PCClusterIP `
    -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
    -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
    -CLUUID $vars.CLUUID

  write-log -message "We have '$($PEhosts.entities.count)' PE Hosts"
  [array]$PEHost = $PEhosts.entities | where {$_.uuid -eq $vars.VMDetail.host_uuid}

  write-log -message "We have '$($PEHost.count)' PE Hosts"

  $secondsup = $PEHost.bootTimeInUsecs / 100000000
  $timespan = new-timespan -seconds $secondsup
  if ($vars.VMDetail.boot.uefi_boot -eq $false){
    $secureboot = $false
  } else {
    if ($VMDetail.boot.secure_boot -ne $true){
      $secureboot = $false   
    }
  }

  $vmobject = @{
    Hostname      = $PEHost.Name
    HostAHV_Ver   = $PEHost.hypervisorFullName
    HostModel     = $PEHost.blockModelName
    HostStatus    = $PEHost.state
    HostPower     = $PEHost.acropolisConnectionState
    HostDays_UP   = $timespan.Days
    HostCores     = $PEHost.numCpuCores
    HostCPU_Usage = [math]::truncate($PEHost.stats.hypervisor_cpu_usage_ppm / 10000)
    HostRAM       = [math]::truncate($PEHost.memoryCapacityInBytes /1000 /1024 /1024)
    HostRAM_Usage = [math]::truncate($PEHost.stats.hypervisor_memory_usage_ppm / 10000)
    VMName        = $vars.VMDetail.name
    VMDisks       = ($vars.VMDetail.vm_disk_info | where {$_.is_cdrom -eq $false }).count
    VMCDrom       = [int]($vars.VMDetail.vm_disk_info | where {$_.is_cdrom -eq $true }).count
    VMUEFI        = $vars.VMDetail.boot.uefi_boot
    VMSecureboot  = $secureboot 
    VMGPUs        = $vars.VMDetail.gpus_assigned
  }

  
  write-log -message "Output VM Details"
  write-log -message "Host Name     : '$($vmobject.Hostname)'"
  write-log -message "Host CPU %    : '$($vmobject.HostCPU_Usage)'"
  write-log -message "Host RAM %    : '$($vmobject.HostRAM_Usage)'"
  write-log -message "Host CPU Cores: '$($vmobject.HostCores)'"
  write-log -message "Host RAM GB   : '$($vmobject.HostRAM)'"  
  write-log -message "Host Days UP  : '$($vmobject.HostDays_UP)'"
  write-log -message "Host Model    : '$($vmobject.HostModel)'"
  write-log -message "Host Version  : '$($vmobject.HostAHV_Ver)'"
  write-log -message "VM Name       : '$($vmobject.VMname)'"  
  write-log -message "VM Disk Count : '$($vmobject.VMDisks)'"
  write-log -message "VM CDROM Count: '$($vmobject.VMCDrom)'"
  write-log -message "VM UEFI ON    : '$($vmobject.VMUEFI)'"  
  write-log -message "VM Secure Boot: '$($vmobject.VMSecureboot)'"
  write-log -message "VM GPUs       : '$($vmobject.VMGPUs)'"

  $GridArguments = @{
    OutputMode = 'Single'
    Title      = 'Overview'
  }
  $List = ($vmobject | Out-GridView @GridArguments)

  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | out-null
  $result = [System.Windows.Forms.MessageBox]::Show('Export File?' , "Info" , 4)
  if ($result -eq "Yes"){
    $folder = Get-Folder
    $vmobject |ConvertTo-Json | convertfrom-json | export-csv "$($folder)\$($vmobject.VMName).csv"
  }

  
}
Export-ModuleMember *