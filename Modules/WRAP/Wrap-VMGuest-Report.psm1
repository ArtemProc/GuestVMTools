Function Wrap-VMGuest-Report {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  $PEhosts = REST-Get-PC-Hosts-PRX `
    -PCClusterIP $PCClusterIP `
    -PxClusterUser $PCCreds.getnetworkcredential().username `
    -PxClusterPass $PCCreds.getnetworkcredential().password `
    -CLUUID $CLUUID

  $PEHost = $PEhosts.entities | where {$_.uuid -eq $vars.VMDetail.host_uuid}

  $secondsup = $PEHost.bootTimeInUsecs / 100000000
  $timespan = new-timespan -seconds $secondsup

  $HostsObject = @{
    Name         = $PEHost.Name
    AHV_Ver      = $PEHost.hypervisorFullName
    Model        = $PEHost.blockModelName
    Status       = $PEHost.state
    Power        = $PEHost.acropolisConnectionState
    Days_UP      = $timespan.Days
    Cores        = $PEHost.numCpuCores
    CPU_Usage    = [math]::truncate($PEHost.stats.hypervisor_cpu_usage_ppm / 10000)
    RAM          = [math]::truncate($PEHost.memoryCapacityInBytes /1000 /1024 /1024)
    RAM_Usage    = [math]::truncate($PEHost.stats.hypervisor_memory_usage_ppm / 10000)
  }
  if ($VMDetail.boot.uefi_boot -eq $false){
    $secureboot = $false
  } else {
    if ($VMDetail.boot.secure_boot -ne $true){
      $secureboot = $false   
    }
  }
  $vmobject = @{
    Disks = ($VMDetail.vm_disk_info | where {$_.is_cdrom -eq $false }).count
    CDrom = [int]($VMDetail.vm_disk_info | where {$_.is_cdrom -eq $true }).count
    UEFI = $VMDetail.boot.uefi_boot
    Secureboot = $secureboot 
    GPUs = $VMDetail.gpus_assigned
  }

  write-log -message "Output VM Details"
  write-log -message "HostName      : '$($PEHost.name)'"
  write-log -message "Host CPU %    : '$($HostsObject.CPU_Usage)'"
  write-log -message "Host RAM %    : '$($HostsObject.RAM_Usage)'"
  write-log -message "Host CPU Cores: '$($HostsObject.Cores)'"
  write-log -message "Host RAM GB   : '$($HostsObject.RAM)'"  
  write-log -message "Host Days UP  : '$($HostsObject.Days_UP)'"
  write-log -message "Host Model    : '$($HostsObject.Model)'"
  write-log -message "Host Version  : '$($HostsObject.AHV_Ver)'"
  write-log -message "VM Name       : '$($VMDetail.name)'"  
  write-log -message "VM Disk Count : '$($vmobject.Disks)'"
  write-log -message "VM CDROM Count: '$($vmobject.CDrom)'"
  write-log -message "VM UEFI ON    : '$($vmobject.UEFI)'"  
  write-log -message "VM Secure Boot: '$($vmobject.Secureboot)'"
  write-log -message "VM GPUs       : '$($vmobject.GPUs)'"

}
Export-ModuleMember *