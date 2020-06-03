Function Wrap-VMGuest-Report {
  param (
   [object] $Vars
  ) 
  write-log -message "Gathering More Details"

  $PEhosts = REST-Get-PRX-Hosts`
    -PCClusterIP $PCClusterIP `
    -PxClusterUser $PCCreds.getnetworkcredential().username `
    -PxClusterPass $PCCreds.getnetworkcredential().password `
    -CLUUID $CLUUID

  $PEHost = $PEhosts.entities | where {$_.uuid -eq $vars.VMDetail.host_uuid}

  $secondsup = $PEHost.bootTimeInUsecs / 100000000
  $timespan = new-timespan -seconds $secondsup
  if ($VMDetail.boot.uefi_boot -eq $false){
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
    VMName        = $VMDetail.name
    VMDisks       = ($VMDetail.vm_disk_info | where {$_.is_cdrom -eq $false }).count
    VMCDrom       = [int]($VMDetail.vm_disk_info | where {$_.is_cdrom -eq $true }).count
    VMUEFI        = $VMDetail.boot.uefi_boot
    VMSecureboot  = $secureboot 
    VMGPUs        = $VMDetail.gpus_assigned
  }

  
  write-log -message "Output VM Details"
  write-log -message "Host Name     : '$($vmobject.Hostname)'"
  write-log -message "Host CPU %    : '$($vmobject.CPU_Usage)'"
  write-log -message "Host RAM %    : '$($vmobject.RAM_Usage)'"
  write-log -message "Host CPU Cores: '$($vmobject.Cores)'"
  write-log -message "Host RAM GB   : '$($vmobject.RAM)'"  
  write-log -message "Host Days UP  : '$($vmobject.Days_UP)'"
  write-log -message "Host Model    : '$($vmobject.Model)'"
  write-log -message "Host Version  : '$($vmobject.AHV_Ver)'"
  write-log -message "VM Name       : '$($vmobject.VMname)'"  
  write-log -message "VM Disk Count : '$($vmobject.VMDisks)'"
  write-log -message "VM CDROM Count: '$($vmobject.VMCDrom)'"
  write-log -message "VM UEFI ON    : '$($vmobject.VMUEFI)'"  
  write-log -message "VM Secure Boot: '$($vmobject.VMSecureboot)'"
  write-log -message "VM GPUs       : '$($vmobject.VMGPUs)'"

  sleep 10
  do {
    $output = [Microsoft.VisualBasic.Interaction]::InputBox("Yes or No","Output File", "Yes")
  } until ($output -match "Yes|No")
  if ($output -eq "Yes"){
    $initialtxt = "Enter an existing path!"
    $initialpath = "c:\temp"
    do {
      $path = [Microsoft.VisualBasic.Interaction]::InputBox($initialtxt, "Select Path", $initialpath )
      $items = get-childitem $path -ea:4
      if (!$items){
        $initialpath = $path
        $initialtxt = "This path does not exist"
      }
    } until ($items)
    $vmobject |ConvertTo-Json | convertfrom-json | export-csv "$($path)\$($vmobject.VMname).csv"
  }
}
Export-ModuleMember *