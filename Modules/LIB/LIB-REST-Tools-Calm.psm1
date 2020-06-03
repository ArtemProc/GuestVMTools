

Function REST-Update-DefaultProject-AHV {
  Param (
    [object] $datagen,
    [object] $datavar,
    [object] $project,
    [object] $subnet,
    [string] $environmentUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $useruuid = ($project.spec.resources.user_reference_list | where {$_.name -eq "svc_build"}).uuid

  write-log -message "Updating Default Project '$($project.metadata.uuid)'"
  write-log -message "With Subnet '$($subnet.uuid)'"
  write-log -message "Build Account UUID $useruuid"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($project.metadata.uuid)"
  write-log -message "Loading Json"
  $json = @"
{
  "spec": {
    "access_control_policy_list": [],
    "project_detail": {
      "name": "default",
      "resources": {
        "account_reference_list": [],
        "user_reference_list": [{
          "kind": "user",
          "name": "admin",
          "uuid": "00000000-0000-0000-0000-000000000000"
        }, {
          "kind": "user",
          "name": "svc_build",
          "uuid": "$useruuid"
        }],
        "environment_reference_list": [{
          "kind": "environment",
          "uuid": "$environmentUUID"
        }],
        "external_user_group_reference_list": [],
        "subnet_reference_list": [{
          "kind": "subnet",
          "name": "$($subnet.name)",
          "uuid": "$($subnet.uuid)"
        }]
      }
    },
    "user_list": [],
    "user_group_list": []
  },
  "api_version": "3.1",
  "metadata": {
    "kind": "project",
    "spec_version": $($project.metadata.spec_version),
    "categories": {},
    "uuid": "$($project.metadata.uuid)"
  }
}
"@
  $object = $json | convertfrom-json
  

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Update-Environment-Object {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $Environmentdetail,
    [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Updating Environment '$($Environment.metadata.uuid)'"
  write-log -message "Stripping 'Status'"

  $Environmentdetail.psobject.members.remove("Status")

  $json1 = $Environmentdetail | ConvertTo-Json -depth 100

  if ($debug -ge 2){
    $json1 | out-file "$($Loggingdir)\EnvironmentdetailFinal.json"
  }

  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/environments/$($Environmentdetail.metadata.uuid)"
  $counter = 0
  do{
    $counter ++
    try{
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
      $exit = 1
    } catch {
      sleep 10
      $exit = 0
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
    }
  } until ($exit -eq 1 -or $counter -ge 5)
  Return $task
}

Function REST-Update-Blueprint-Object {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $blueprintdetail
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Updating Blueprint '$($blueprintdetail.metadata.uuid)'"
  write-log -message "Stripping 'Status'"
  $blueprintdetail.psobject.members.remove("Status")
  $json1 = $blueprintdetail | ConvertTo-Json -depth 100

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($blueprintdetail.metadata.uuid)"
  $counter = 0
  do{
    $counter ++
    try{
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
      $exit = 1
    } catch {
      sleep 10
      $exit = 0
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json1 -ContentType 'application/json' -headers $headers;
    }
  } until ($exit -eq 1 -or $counter -ge 5)
  Return $task
}

Function REST-Update-MarketPlace-Object {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $MKTDetail,
    [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Updating MarketPlace '$($MKTDetail.metadata.uuid)'"
  write-log -message "Stripping 'Status'"

  $MKTDetail.psobject.members.remove("Status")

  $Json = $MKTDetail | ConvertTo-Json -depth 100
   
  if ($debug -ge 2 ){
    $Json | out-file c:\temp\MKTDetail.json
  }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($MKTDetail.metadata.uuid)"

  write-log -message "Executing PUT on $($MKTDetail.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 




Function REST-Update-Project-Object {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $projectdetail,
    [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Updating Project '$($projectdetail.metadata.uuid)'"
  write-log -message "Stripping 'Status'"

  $projectdetail.psobject.members.remove("Status")

  write-log -message "Setting ACP to 'UPDATE'"

  $projectdetail.spec.access_control_policy_list | % {
    $_ | add-member noteproperty operation "UPDATE"
  }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($project.metadata.uuid)"

  $json1 = $projectdetail | ConvertTo-Json -depth 100

  if ($debug -ge 2){
    $json1 | out-file "$($Loggingdir)\projectFinal.json"
  }

  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($projectdetail.metadata.uuid)"
  $counter = 0
  do{
    $counter ++
    try{
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
      $exit = 1
    } catch {
      sleep 10
      $exit = 0
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
    }
  } until ($exit -eq 1 -or $counter -ge 5)
  Return $task
}

Function REST-LIST-Environments {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }


  write-log -message "Getting all Project Environments"
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/environments/list"
  write-log -message "Loading Json"
  $json = @"
{
  "filter": ""
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Get-Environment-Detail {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $env
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Getting Environment Detail '$($env.metadata.uuid)'"
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/environments/$($ENV.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  }

  Return $task
} 

Function REST-List-SSP-Account {
   Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP
   )

   $credPair = "$($PxClusterUser):$($PxClusterPass)"
   $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
   $headers = @{ Authorization = "Basic $encodedCredentials" }

   $AccountID = (new-guid).Guid

   write-log -message "Listing Account / Provider"

   $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts/list"
   write-log -message "Loading Json"
   $json = @"
 {
 }
"@
   try{
     $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json'  -headers $headers;
   } catch {
     sleep 10

     $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

     $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
   }

   Return $task
}



Function REST-Enable-ShowBack {
   Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP
   )

   $credPair = "$($PxClusterUser):$($PxClusterPass)"
   $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
   $headers = @{ Authorization = "Basic $encodedCredentials" }

   $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/app_showback/enable"
   write-log -message "Enabling Showback"
   $json = @"
{
  "showback":true
}
"@
   try{
     $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json'  -headers $headers;
   } catch {
     sleep 10

     $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

     $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
   }

   Return $task
}

   $ShowbackID = (new-guid).Guid

Function REST-Update-SSP-AccountCost {
   Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $accountdetail
   )

   $credPair = "$($PxClusterUser):$($PxClusterPass)"
   $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
   $headers = @{ Authorization = "Basic $encodedCredentials" }
   $accountdetail.psobject.members.remove("Status")
   $ShowbackRatesUUID = (new-guid).Guid
   
$json = @"
{
    "price_items": [{
        "details": {
          "occurrence": "recurring"
        },
        "state_cost_list": [{
          "state": "ON",
          "cost_list": [{
            "interval": "hour",
            "name": "sockets",
            "value": 0.05
          }, {
            "interval": "hour",
            "name": "memory",
            "value": 0.05
          }, {
            "interval": "hour",
            "name": "storage",
            "value": 0.003
          }]
        }, {
          "state": "OFF",
          "cost_list": [{
            "interval": "hour",
            "name": "storage",
            "value": 0.001
          }]
        }],
        "uuid": "$($ShowbackRatesUUID)"
      }]
}
"@
  $Costobject = $json | convertfrom-json
  $accountdetail.spec.resources | Add-Member -notepropertyname "price_items" -notepropertyvalue "0" -force
  $accountdetail.spec.resources.price_items = $Costobject.price_items

  $outputJSON = $accountdetail | ConvertTo-Json -depth 100

  write-log -message "Adding Cost to Account"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts/$($account.entities.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $outputJSON -ContentType 'application/json' -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $outputJSON -ContentType 'application/json' -headers $headers;
  }

  Return $task
}

Function REST-List-SSP-AccountDetail {
   Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $account
   )

   $credPair = "$($PxClusterUser):$($PxClusterPass)"
   $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
   $headers = @{ Authorization = "Basic $encodedCredentials" }


   write-log -message "Listing Account / Provider $($account.metadata.uuid)"

   $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts/$($account.metadata.uuid)"

   try{
     $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
   } catch {
     sleep 10

     $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

     $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
   }

   Return $task
}

Function REST-Verify-SSP-Account {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $Account
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }


  write-log -message "Verifying account $Accountuuid"
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts/$($Account.metadata.uuid)/verify"
  write-log -message "Using URL '$url'"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  }

  Return $task
} 

Function REST-Create-SSP-KarbonAccount {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $karbonClusterUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $AccountID = (new-guid).Guid

  write-log -message "Creating Account / Provider $AccountID"
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts"
  write-log -message "Loading Json"
  $json = @"
{
  "api_version": "3.0",
  "metadata": {
    "kind": "account",
    "uuid": "$AccountID"
  },
  "spec": {
    "name": "Karbon",
    "resources": {
      "type": "k8s",
      "data": {
        "type": "karbon",
        "cluster_uuid": "$($karbonClusterUUID)"
      }
    }
  }
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json'  -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Create-SSP-VMwareAccount {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $AccountID = (new-guid).Guid

  write-log -message "Creating Account / Provider $AccountID"
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts"
  write-log -message "Loading Json"
  $json = @"
{
  "api_version": "3.0",
  "metadata": {
    "kind": "account",
    "uuid": "$AccountID"
  },
  "spec": {
    "name": "VMWare ESXi",
    "resources": {
      "type": "vmware",
      "data": {
        "server": "$($datavar.VCenterIP)",
        "datacenter": "Nutanix",
        "username": "$($datavar.VCenterUser)",
        "password": {
          "value": "$($datavar.VCenterPass)",
          "attrs": {
            "is_secret_modified": true
          }
        },
        "port": "443"
      }
    }
  }
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json'  -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 


Function REST-Calm-ICON-List {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/app_icons/list"

  write-log -message "Query Icons"

  $json = @"

{
    "length": 20,
    "offset": 0
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -Method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4

  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -Method "POST" -body $json -ContentType 'application/json' -headers $headers
  }
  Return $task
}

Function REST-Calm-Upload-App-Image {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $ImageName,
    [string] $ImagePath
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/app_icons/upload"
  write-log -message "Uploading ICON"
  $boundary = [System.Guid]::NewGuid().ToString()
  $ImageFullPath="$($ImagePath)\$($ImageName).jpg"
  $fileBin = [System.IO.File]::ReadAlltext($ImageFullPath)
  $body = @"
--$boundary--
Content-Disposition: form-data; name="$ImageName"; filename="$($ImageName)"

Content-Type: image/jpeg,
$fileBin,
--$boundary--

--$boundary--
Content-Disposition: form-data; name="name",
$ImageName,
--$boundary--

"@


write $body | out-file c:\temp\body.blob
  try{
    $task = Invoke-RestMethod -Uri $URL -Method "POST" -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $body -headers $headers -ea:4

  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -Method "POST" -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $body -headers $headers
  }

  Return $task
} 


Function REST-Create-Environment-AHV {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $project,
    [object] $subnet,
    [object] $Winimage,
    [object] $Linimage,
    [string] $WinImagePass,
    [string] $LinImagePass,
    [string] $name

  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $useruuid = ($project.spec.resources.user_reference_list | where {$_.name -eq "svc_build"}).uuid

  write-log -message "Creating Environment"
  write-log -message "With Subnet '$($subnet.uuid)'"
  write-log -message "Windows Image '$($Winimage.metadata.uuid)'"
  write-log -message "Linux Image '$($Linimage.metadata.uuid)'"
  write-log -message "Name: 'Environment-$($name)'"

  $WincredUUID = (new-guid).Guid
  $LincredUUID = (new-guid).Guid
  $Resource1UUID = (new-guid).Guid
  $Resource2UUID = (new-guid).Guid
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/environments"
  write-log -message "Loading Json"
  $json = @"
{
  "api_version": "3.0",
  "metadata": {
    "kind": "environment"
  },
  "spec": {
    "name": "Environment-$($name)", 
    "resources": {
      "substrate_definition_list": [{
        "variable_list": [],
        "type": "AHV_VM",
        "os_type": "Windows",
        "action_list": [],
        "create_spec": {
          "name": "-@@{calm_array_index}@@-@@{calm_time}@@",
          "resources": {
            "disk_list": [{
              "data_source_reference": {
                "kind": "image",
                "name": "$($Winimage.spec.name)",
                "uuid": "$($Winimage.metadata.uuid)" 
              },
              "device_properties": {
                "device_type": "DISK",
                "disk_address": {
                  "device_index": 0,
                  "adapter_type": "SCSI"
                }
              }
            }],
            "boot_config": {
              "boot_device": {
                "disk_address": {
                  "device_index": 0,
                  "adapter_type": "SCSI"
                }
              }
            },
            "num_sockets": 4,
            "num_vcpus_per_socket": 1,
            "memory_size_mib": 4096,
            "guest_customization": {
              "sysprep": {
                "unattend_xml": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\n    <settings pass=\"oobeSystem\">\n        <component name=\"Microsoft-Windows-International-Core\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n            <InputLocale>0413:00020409</InputLocale>\n            <SystemLocale>en-US</SystemLocale>\n            <UILanguageFallback>en-US</UILanguageFallback>\n            <UserLocale>nl-NL</UserLocale>\n        </component>\n        <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n            <AutoLogon>\n                <Enabled>true</Enabled>\n                <LogonCount>9999999</LogonCount>\n                <Username>Administrator</Username>\n                <Password>\n                    <PlainText>true</PlainText>\n                    <Value>@@{ICC_Creds.secret}@@</Value>\n                </Password>\n            </AutoLogon>\n            <OOBE>\n                <HideEULAPage>true</HideEULAPage>\n                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n                <NetworkLocation>Home</NetworkLocation>\n                <ProtectYourPC>2</ProtectYourPC>\n            </OOBE>\n            <UserAccounts>\n                <AdministratorPassword>\n                    <PlainText>true</PlainText>\n                    <Value>@@{ICC_Creds.secret}@@</Value>\n                </AdministratorPassword>\n            </UserAccounts>\n            <FirstLogonCommands>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm quickconfig -q</CommandLine>\n                    <Description>Win RM quickconfig -q</Description>\n                    <Order>20</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm quickconfig -transport:http</CommandLine>\n                    <Description>Win RM quickconfig -transport:http</Description>\n                    <Order>21</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm set winrm/config @{MaxTimeoutms=\"1800000\"}</CommandLine>\n                    <Description>Win RM MaxTimoutms</Description>\n                    <Order>22</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm set winrm/config/winrs @{MaxMemoryPerShellMB=\"300\"}</CommandLine>\n                    <Description>Win RM MaxMemoryPerShellMB</Description>\n                    <Order>23</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm set winrm/config/service @{AllowUnencrypted=\"true\"}</CommandLine>\n                    <Description>Win RM AllowUnencrypted</Description>\n                    <Order>24</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm set winrm/config/service/auth @{Basic=\"true\"}</CommandLine>\n                    <Description>Win RM auth Basic</Description>\n                    <Order>25</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm set winrm/config/client/auth @{Basic=\"true\"}</CommandLine>\n                    <Description>Win RM auth Basic</Description>\n                    <Order>26</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c winrm set winrm/config/listener?Address=*+Transport=HTTP @{Port=\"5985\"} </CommandLine>\n                    <Description>Win RM listener Address/Port</Description>\n                    <Order>27</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c netsh advfirewall firewall set rule group=\"remote administration\" new enable=yes </CommandLine>\n                    <Description>Win RM adv firewall enable</Description>\n                    <Order>29</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c net stop winrm </CommandLine>\n                    <Description>Stop Win RM Service </Description>\n                    <Order>28</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>cmd.exe /c net start winrm </CommandLine>\n                    <Description>Start Win RM Service</Description>\n                    <Order>32</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <CommandLine>powershell -Command &quot;Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force&quot;</CommandLine>\n                    <Description>Set PowerShell ExecutionPolicy</Description>\n                    <Order>1</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>2</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <CommandLine>powershell -Command &quot;Enable-PSRemoting -Force&quot;</CommandLine>\n                    <Description>Enable PowerShell Remoting</Description>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>61</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <CommandLine>powershell -Command &quot;Enable-NetFirewallRule -DisplayGroup \"Remote Desktop\"&quot;</CommandLine>\n                    <Description>Rule RDP Filewall</Description>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>62</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <CommandLine>powershell -Command &quot;Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\' -Name \"UserAuthentication\" -Value 1&quot;</CommandLine>\n                    <Description>Enable RDP2016</Description>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>63</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <CommandLine>powershell -Command &quot;Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\' -Name \"fDenyTSConnections\" -Value 0&quot;</CommandLine>\n                    <Description>Enable RDP2016p2</Description>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>5</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <Description>RDP adv firewall enable</Description>\n                    <CommandLine>cmd.exe /c netsh advfirewall firewall set rule group=&quot;Remote Desktop&quot; new enable=yes </CommandLine>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>31</Order>\n                    <CommandLine>cmd.exe /c sc config winrm start= auto</CommandLine>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <Description>No-Delay Auto start WinRM on boot</Description>\n                </SynchronousCommand>\n                <SynchronousCommand wcm:action=\"add\">\n                    <Order>30</Order>\n                    <RequiresUserInput>true</RequiresUserInput>\n                    <CommandLine>cmd.exe /c netsh advfirewall set allprofiles state off</CommandLine>\n                    <Description>Disable Windows Firewall</Description>\n                </SynchronousCommand>\n            </FirstLogonCommands>\n<ShowWindowsLive>false</ShowWindowsLive>\n        </component>\n    </settings>\n    <settings pass=\"specialize\">\n        <component name=\"Microsoft-Windows-Deployment\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n            <RunSynchronous>\n                <RunSynchronousCommand wcm:action=\"add\">\n                    <Order>1</Order>\n                    <Path>net user administrator /active:Yes</Path>\n                    <WillReboot>Never</WillReboot>\n                </RunSynchronousCommand>\n            </RunSynchronous>\n        </component>\n        <component name=\"Microsoft-Windows-Security-SPP-UX\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n            <SkipAutoActivation>true</SkipAutoActivation>\n        </component>\n        <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n            <ComputerName>*</ComputerName>\n        </component>\n    </settings>\n    <settings pass=\"windowsPE\">\n        <component name=\"Microsoft-Windows-International-Core-WinPE\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n            <SetupUILanguage>\n            <UILanguage>en-US </UILanguage>\n            </SetupUILanguage>\n            <InputLocale>en-US </InputLocale>\n            <SystemLocale>en-US </SystemLocale>\n            <UILanguage>en-US </UILanguage>\n            <UILanguageFallback>en-US </UILanguageFallback>\n            <UserLocale>en-US </UserLocale>\n        </component>\n    </settings>\n</unattend>"
              }
            },
            "nic_list": [{
              "subnet_reference": {
                "uuid": "$($subnet.uuid)"
              },
              "ip_endpoint_list": []
            }]
          }
        },
        "name": "Untitled",
        "readiness_probe": {
          "connection_type": "POWERSHELL",
          "connection_port": 5985,
          "address": "@@{platform.status.resources.nic_list[0].ip_endpoint_list[0].ip}@@",
          "login_credential_local_reference": {
            "kind": "app_credential",
            "uuid": "$WincredUUID" 
          }
        },
        "editables": {
          "create_spec": {
            "resources": {
              "disk_list": {},
              "nic_list": {},
              "serial_port_list": {}
            }
          }
        },
        "uuid": "$Resource1UUID"
      }, {
        "variable_list": [],
        "type": "AHV_VM",
        "os_type": "Linux",
        "action_list": [],
        "create_spec": {
          "name": "-@@{calm_array_index}@@-@@{calm_time}@@",
          "resources": {
            "disk_list": [{
              "data_source_reference": {
                "kind": "image",
                "name": "$($Linimage.spec.name)",
                "uuid": "$($Linimage.metadata.uuid)" 
              },
              "device_properties": {
                "device_type": "DISK",
                "disk_address": {
                  "device_index": 0,
                  "adapter_type": "SCSI"
                }
              }
            }],
            "boot_config": {
              "boot_device": {
                "disk_address": {
                  "device_index": 0,
                  "adapter_type": "SCSI"
                }
              }
            },
            "guest_customization": {
              "cloud_init": {
                "user_data": "#cloud-config\npassword: @@{centos.secret}@@\nchpasswd: { expire: False }\nssh_pwauth: True"
              }
            },
            "num_sockets": 2,
            "num_vcpus_per_socket": 1,
            "memory_size_mib": 2048,
            "nic_list": [{
              "subnet_reference": {
                "uuid": "$($subnet.uuid)"
              },
              "ip_endpoint_list": []
            }]
          }
        },
        "name": "Untitled",
        "readiness_probe": {
          "connection_type": "SSH",
          "connection_port": 22,
          "address": "@@{platform.status.resources.nic_list[0].ip_endpoint_list[0].ip}@@",
          "login_credential_local_reference": {
            "kind": "app_credential",
            "uuid": "$LincredUUID" 
          }
        },
        "editables": {
          "create_spec": {
            "resources": {
              "disk_list": {},
              "nic_list": {},
              "serial_port_list": {}
            }
          }
        },
        "uuid": "$Resource2UUID"
      }],
      "credential_definition_list": [{
        "name": "ICC_Creds",
        "type": "PASSWORD",
        "username": "administrator",
        "secret": {
          "attrs": {
            "is_secret_modified": true
          },
          "value": "Dummy"
        },
        "uuid": "$WincredUUID"
      }, {
        "name": "LX_Creds",
        "type": "PASSWORD",
        "username": "Dummy",
        "secret": {
          "attrs": {
            "is_secret_modified": true
          },
          "value": "Dummy"
        },
        "uuid": "$LincredUUID"
      }]
    }
  }
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json'  -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 






Function REST-Update-Project {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [array]  $Subnet,
    [array]  $consumer,
    [array]  $projectadmin,
    [array]  $cluster,
    [string] $customer,    
    [array]  $admingroup,
    [array]  $usergroup,    
    [array]  $Project,
    [string]  $environmentUUID,
    [int] $Projectspec,
    [object] $account
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Executing Project Update"
  [int]$spec 
  $UserGroupURL = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($project.metadata.uuid)"
  $json1 = @"

{
  "spec": {
    "access_control_policy_list": [
    ],
    "project_detail": {
      "name": "$($project.spec.name)", 
      "resources": {
        "resource_domain": {
          "resources": [{
              "limit": 1717986918400,
              "resource_type": "STORAGE"
            },
            {
              "limit": 40,
              "resource_type": "VCPUS"
            },
            {
              "limit": 85899345920,
              "resource_type": "MEMORY"
            }
          ]
        },
        "account_reference_list": [

        ],
        "environment_reference_list": [{
          "kind": "environment",
          "uuid": "$environmentUUID"
        }],
        "user_reference_list": [

        ],
        "external_user_group_reference_list": [{
            "kind": "user_group",
            "name": "$($admingroup.status.resources.directory_service_user_group.distinguished_name)",
            "uuid": "$($admingroup.metadata.uuid)"
          },
          {
            "kind": "user_group",
            "name": "$($usergroup.status.resources.directory_service_user_group.distinguished_name)",
            "uuid": "$($usergroup.metadata.uuid)"
          }
        ],
        "subnet_reference_list": [{
          "kind": "subnet",
          "name": "$($subnet.name)",
          "uuid": "$($subnet.uuid)"
        }]
      },
      "description": "$($project.spec.description)"
    },
    "user_list": [

    ],
    "user_group_list": [

    ]
  },
  "api_version": "3.1",
  "metadata": {
    "kind": "project",
    "uuid": "$($project.metadata.uuid)",
    "project_reference": {
      "kind": "project",
      "name": "$($project.spec.name)", 
      "uuid": "$($project.metadata.uuid)"
    },
    "spec_version": $($Projectspec),
    "owner_reference": {
      "kind": "user",
      "uuid": "00000000-0000-0000-0000-000000000000",
      "name": "admin"
    },
    "categories": {

    }
  }
}

"@


 $json2 = @"
        {
          "uuid": "$($account.metadata.uuid)",
          "kind": "account",
          "name": "vmware"
        }
"@

  write-log -message "Converting Child"

  $child = $json2 | convertfrom-json

  write-log -message "Injecting Child into Parent"

  $object1 = $json1 | convertfrom-json
  $object1.spec.project_detail.resources.account_reference_list += $child

  write-log -message "Updating Default Project '$($project.metadata.uuid)'"

  $json1 = $object1 | ConvertTo-Json -depth 100

  $countretry = 0
  do {
    $countretry ++
    try{
      $task = Invoke-RestMethod -Uri $UserGroupURL -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
      $RESTSuccess = 1
      sleep 10
    } catch {
      $task = Invoke-RestMethod -Uri $UserGroupURL -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
      sleep 20
      write-log -message "Retry REST '$countretry'"
    }
  } until ($RESTSuccess -eq 1 -or $countretry -ge 6)

  if ($RESTSuccess -eq 1){
    write-log -message "Project Update Success"
  } else {
    write-log -message "Project Update Failed" 
  }
  Return $task
} 


Function REST-Get-ACPs {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing ACPs List"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/access_control_policies/list"
  $Payload= @{
    kind="access_control_policy"
    offset=0
    length=250
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers;
  }
  write-log -message "We found $($task.entities.count) items."

  Return $task
} 


Function REST-Create-Project {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $SiteLongCode,
    [string] $domainname,
    [Object] $UserGroup,    
    [Object] $AdminGroup,
    [string] $SubnetName,    
    [string] $SubnetUUID,
    [string] $ProjectName,
    [object] $PCAccount,
    [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $domainparts = $domainname.split(".")
  write-log -message "Executing Project Create"

  $UserGroupURL = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal"
  $json = @"
{
  "api_version": "3.0",
  "metadata": {
    "kind": "project"
  },
  "spec": {
    "project_detail": {
      "name": "$($ProjectName)",
      "resources": {
        "user_reference_list": [],
        "external_user_group_reference_list": [{
          "name": "$($usergroup.spec.resources.directory_service_user_group.distinguished_name)",
          "kind": "user_group",
          "uuid": "$($usergroup.metadata.uuid)"
        }, {
          "name": "$($admingroup.spec.resources.directory_service_user_group.distinguished_name)",
          "kind": "user_group",
          "uuid": "$($admingroup.metadata.uuid)"
        }],
        "account_reference_list": [{
          "uuid": "$($PCAccount.metadata.uuid)",
          "kind": "account",
          "name": "nutanix_pc"
        }],

        "external_network_list": [],
        "resource_domain": {
          "resources": [{
            "limit": 549755813888,
            "resource_type": "MEMORY"
          }, {
            "limit": 150,
            "resource_type": "VCPUS"
          }, {
            "limit": 8589934592000,
            "resource_type": "STORAGE"
          }]
        }
      }
    },
    "user_list": [],
    "user_group_list": [{
      "metadata": {
        "kind": "user_group",
        "uuid": "$($usergroup.metadata.uuid)"
      },
      "user_group": {
        "resources": {
          "directory_service_user_group": {
            "distinguished_name": "$($usergroup.spec.resources.directory_service_user_group.distinguished_name)"
          }
        }
      },
      "operation": "ADD"
    }, {
      "metadata": {
        "kind": "user_group",
        "uuid": "$($AdminGroup.metadata.uuid)"
      },
      "user_group": {
        "resources": {
          "directory_service_user_group": {
            "distinguished_name": "$($AdminGroup.spec.resources.directory_service_user_group.distinguished_name)"
          }
        }
      },
      "operation": "ADD"
    }],
    "access_control_policy_list": []
  }
}
"@

  if ($debug -ge 4){
    $json | out-file "$($loggingdir)\projectcreate.json"
  }
  try{
    $task = Invoke-RestMethod -Uri $UserGroupURL -method "post" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $UserGroupURL -method "post" -body $json -ContentType 'application/json' -headers $headers;
  }

  sleep 5
  Return $task

} 


Function REST-Delete-Project {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $projectUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Executing Project Delete"

  $ProjectURL = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$projectUUID"

  try{
    $task = Invoke-RestMethod -Uri $ProjectURL -method "DELETE" -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $ProjectURL -method "DELETE" -headers $headers;
  }

  sleep 5
  Return $task

} 

Function REST-Delete-BluePrint {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $BluePrintUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Executing Blueprint Delete"

  $ProjectURL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$BluePrintUUID"

  try{
    $task = Invoke-RestMethod -Uri $ProjectURL -method "DELETE" -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $ProjectURL -method "DELETE" -headers $headers;
  }

  sleep 5
  Return $task

} 

Function REST-Export-BluePrint {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $BluePrintUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Exporting Blueprint"

  $ProjectURL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$BluePrintUUID/export_file"

  try{
    $task = Invoke-RestMethod -Uri $ProjectURL -method "POST" -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $ProjectURL -method "POST" -headers $headers;
  }

  sleep 5
  Return $task

} 


Function REST-Create-ACP-RoleMap {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Customer,
    [array]  $role,
    [array] $group,
    [array] $project,
    [string] $GroupType
  )
  ## This module is depricated afaik done in project update...
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Executing ACP Create"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/access_control_policies"
  $json = @"
{
  "spec": {
    "name": "ACP $($Customer) for $($GroupType)",
    "resources": {
      "role_reference": {
        "kind": "role",
        "uuid": "$($role.metadata.uuid)"
      },
      "user_reference_list": [],
      "filter_list": {
        "context_list": [{
          "entity_filter_expression_list": [{
            "operator": "IN",
            "left_hand_side": {
              "entity_type": "ALL"
            },
            "right_hand_side": {
              "collection": "ALL"
            }
          }],
          "scope_filter_expression_list": [{
              "operator": "IN",
              "right_hand_side": {
                "uuid_list": ["$($project.metadata.uuid)"]
              },
              "left_hand_side": "PROJECT"
            }

          ]
        }]
      },
      "user_group_reference_list": [{
        "kind": "user_group",
        "uuid": "$($group.metadata.uuid)"
      }]
    },
    "description": "ACP $($Customer) for $($GroupType)"
  },
  "metadata": {
    "kind": "access_control_policy"
  }
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  }catch{
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers;
  }
  Return $task
} 



Function REST-Query-DetailBP {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $uuid
  )

  write-log -message "Debug level is $($debug)";
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Getting Blueprint Detail for BP '$uuid'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($uuid)"

  write-log -message "URL is $url"

  try {
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 





Function REST-Update-RoboWindowsBP {
  Param (
    [object] $blueprintdetail,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $WinImagePass,
    [object] $subnet,
    [object] $winimage,
    [string] $name,
    [string] $loggingdir,
    [string] $CPU,
    [string] $Cores,
    [string] $GBRAM,
    [string] $role,
    [object] $PCServiceCred

  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $BPObject = $blueprintdetail

  write-log -message "Prepping object"

  $BPObject.psobject.properties.Remove('status')

  write-log -message "Setting Credential Objects"

  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "Dummy"}).secret.attrs.is_secret_modified = $true
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "Dummy"}).secret | add-member noteproperty value "Dummy" -force

  $secret = $PCServiceCred.secret
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PCServiceAccount"}).secret.attrs.is_secret_modified = $true
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PCServiceAccount"}).secret | add-member noteproperty value $secret -force
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PCServiceAccount"}).username = $PCServiceCred.username


  write-log -message "Name is '$Name'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "ICC_Name" }).value = $name

  write-log -message "Setting up nic and IP"
  $bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"} | % {$_.create_spec.resources.nic_list.subnet_reference.uuid = $subnet.uuid}

  write-log -message "Setting up Images"
  ($bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"}).create_spec.resources.disk_list | where {$_.disk_size_mib -eq 0 -and $_.device_properties.device_type -ne "CDROM"} | % { $_.data_source_reference.uuid = $Winimage.metadata.uuid }
  ($bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"}).create_spec.resources.disk_list | where {$_.disk_size_mib -eq 0 -and $_.device_properties.device_type -ne "CDROM"} | % { $_.data_source_reference.name = $Winimage.metadata.name }
  #$bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"} | % {$_.create_spec.resources.disk_list.data_source_reference.uuid = $Winimage.metadata.uuid}

  write-log -message "Variables make the world a constant change.."
  write-log -message "Setting nr of sockets to '$cpu'"

  ($bpobject.spec.resources.substrate_definition_list | where {$_.Type -eq "AHV_VM"}).create_spec.resources.num_sockets = $CPU

  write-log -message "Setting nr of cores to '$Cores'"

  ($bpobject.spec.resources.substrate_definition_list | where {$_.Type -eq "AHV_VM"}).create_spec.resources.num_vcpus_per_socket = $cores
  
  write-log -message "Configuring RAM '$GBRAM' GB"
  $RAM = [decimal] $GBRAM * 1024

  ($bpobject.spec.resources.substrate_definition_list | where {$_.Type -eq "AHV_VM"}).create_spec.resources.memory_size_mib = $RAM

  write-log -message "Setting VM name to match role"

  $bpobject.spec.resources.substrate_definition_list[0].name = $role

  write-log -message "Passing the ball to Calm"

  $Json = $BPObject | ConvertTo-Json -depth 100
   
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($blueprintdetail.metadata.uuid)"

  write-log -message "Executing Update using URL '$url'"
  if ($debug -ge 2){
    $json | out-file "$($loggingdir)\WindowsWorkloadBP.json"
  }

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Update-RoboLinuxBP {
  Param (
    [object] $blueprintdetail,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $LinImagePass,
    [string] $Mask,
    [string] $GW,
    [string] $IP,
    [string] $Name,
    [string] $DNS,
    [object] $subnet,
    [object] $Linimage,
    [string] $Loggingdir,
    [string] $WindowsDomain,
    [string] $CPU,
    [string] $Cores,
    [string] $GBRAM,
    [string] $role,
    [object] $PCServiceCred

  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $BPObject = $blueprintdetail
  [array]$DNSarr = $dns.split(",")
  write-log -message "Prepping object"

  $BPObject.psobject.properties.Remove('status')

  write-log -message "Setting Credential Objects"

  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "Dummy"}).secret.attrs.is_secret_modified = $true
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "Dummy"}).secret | add-member noteproperty value "Dummy"

  $secret = $PCServiceCred.secret
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PCServiceAccount"}).secret.attrs.is_secret_modified = $true
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PCServiceAccount"}).secret | add-member noteproperty value $secret -force
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PCServiceAccount"}).username = $PCServiceCred.username
  
  write-log -message "Domain is '$WindowsDomain'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_Mask" }).value = $Mask

  write-log -message "SubnetMask is '$Mask'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_Domain" }).value = $WindowsDomain

  write-log -message "DNS 1 are '$($DNSarr[0])'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_DNS1" }).value = $DNSarr[0]

  write-log -message "DNS 2 are '$($DNSarr[1])'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_DNS2" }).value = $DNSarr[1]

  write-log -message "Gateway is '$GW'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_GW" }).value = $GW

  write-log -message "IP Address is '$IP'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_IP" }).value = $IP

  write-log -message "Name is '$Name'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LX_Name" }).value = $Name

  write-log -message "Setting up nic and IP"
  $bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"} | % {$_.create_spec.resources.nic_list.subnet_reference.uuid = $subnet.uuid}

  write-log -message "Setting up Images"
  ($bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"}).create_spec.resources.disk_list | where {$_.disk_size_mib -eq 0 -and $_.device_properties.device_type -ne "CDROM"} | % { $_.data_source_reference.uuid =  $Linimage.metadata.uuid }
  ($bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"}).create_spec.resources.disk_list | where {$_.disk_size_mib -eq 0 -and $_.device_properties.device_type -ne "CDROM"} | % { $_.data_source_reference.name =  $Linimage.metadata.name }
    write-log -message "Now i am there." -D 2
    #if ($_.create_spec.resources.disk_list.data_source_reference.name -match "[a-z]|[A-Z]"){
      write-log -message "Iam here" -D 2
      
   #}
  write-log -message "Variables make the world a constant change.."
  write-log -message "Setting nr of sockets to '$cpu'"

  ($bpobject.spec.resources.substrate_definition_list | where {$_.Type -eq "AHV_VM"}).create_spec.resources.num_sockets = $CPU

  write-log -message "Setting nr of cores to '$Cores'"

  ($bpobject.spec.resources.substrate_definition_list | where {$_.Type -eq "AHV_VM"}).create_spec.resources.num_vcpus_per_socket = $cores
  
  write-log -message "Configuring RAM '$GBRAM' GB"
  $RAM = [decimal] $GBRAM * 1024

  ($bpobject.spec.resources.substrate_definition_list | where {$_.Type -eq "AHV_VM"}).create_spec.resources.memory_size_mib = $RAM

  write-log -message "Setting VM name to match role"

  $bpobject.spec.resources.substrate_definition_list[0].name = $role

  write-log -message "Passing the ball to Calm"

  $Json = $BPObject | ConvertTo-Json -depth 100
   
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($blueprintdetail.metadata.uuid)"

  write-log -message "Executing Update using URL '$url'"
  if ($debug -ge 2){
    $json | out-file "$($Loggingdir)\LinuxWorkload.json"
  }

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Update-RoboControlBP {
  Param (
    [object] $blueprintdetail,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $LinImagePass,
    [string] $WinImagePass,
    [string] $siteshortcode,
    [string] $SiteLongCode,
    [object] $subnet,
    [string] $daemonID,
    [string] $RoboSiteBandwidth,
    [string] $RoboCountryCode,
    [string] $RoboAdminPassword,
    [string] $RoboSVCPassword,
    [string] $CDCWitnessIP,
    [string] $CDCWitnessPassword,
    [string] $RBCPEBuildAccount,
    [string] $RoboPEClusterIP,
    [string] $EULAName,
    [string] $executioner,
    [string] $SiteNodeCount,
    [string] $NetworkBrand,
    [string] $SDWanBrand,
    [string] $NodeBrand,
    [string] $SiteHandsEmail,
    [string] $SNWDNS,
    [string] $SNWGW,
    [string] $SNWSubnet,
    [string] $SNWVlan,
    [string] $SLC,
    [string] $sc,
    [string] $domainname,
    [string] $Management_IP,
    [string] $Service_Account_User,
    [string] $Service_Account_Pass,
    [string] $loggingdir,
    [string] $WorkloadNetworkName,
    [string] $ReplicationTargetSite,
    [string] $StackAdminGroup,
    [string] $SelfServiceAdminGroup,
    [string] $SiteReplicationType
  ) 

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $BPObject = $blueprintdetail

  write-log -message "Prepping object"

  $BPObject.psobject.properties.Remove('status')

  write-log -message "Setting Credential Objects"

  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PE_Admin"}).secret.attrs.is_secret_modified = $true
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "PE_Admin"}).secret | add-member noteproperty value $LinImagePass -force

  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "MGT_Admin"}).username = $Service_Account_User
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "MGT_Admin"}).secret.attrs.is_secret_modified = $true
  ($BPObject.spec.resources.credential_definition_list | where {$_.name -eq "MGT_Admin"}).secret | add-member noteproperty value $Service_Account_Pass -force

  write-log -message "Calm App Source Code is '$daemonID'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "CalmSourceAppID" }).value = $daemonID

  write-log -message "Site RoboPEClusterIP is '$RoboPEClusterIP'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RBCPEClusterIP" }).value = $RoboPEClusterIP

  write-log -message "Site Replication Target is '$ReplicationTargetSite'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "ReplicationTargetSite" }).value = $ReplicationTargetSite

  write-log -message "Site Bandwidth is '$RoboSiteBandwidth'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RoboSiteBandwidth" }).value = $RoboSiteBandwidth

  write-log -message "Site Stack Admin Group is '$StackAdminGroup'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "StackAdminGroup" }).value = $StackAdminGroup

  write-log -message "Site SelfService Admin Group is '$SelfServiceAdminGroup'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SelfServiceAdminGroup" }).value = $SelfServiceAdminGroup

  write-log -message "Site Workload Network name is '$WorkloadNetworkName'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "WorkloadNetworkName" }).value = $WorkloadNetworkName

  write-log -message "Site Replication Type '$SiteReplicationType'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SiteReplType" }).value = $SiteReplicationType

  write-log -message "Site Country Code is '$RoboCountryCode'"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RoboCountryCode" }).value = $RoboCountryCode

  write-log -message "Robo Admin password is, haha"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RoboAdminPassword" }) | add-member noteproperty value $RoboAdminPassword -force 
  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RoboAdminPassword" }).attrs.is_secret_modified = $true

  write-log -message "Robo Svc password is, haha"

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RoboSVCPassword" }) | add-member noteproperty value $RoboSVCPassword -force
  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RoboSVCPassword" }).attrs.is_secret_modified = $true

  write-log -message "Central Datacenter Witness IP is '$CDCWitnessIP'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "CDCWitnessIP" }).value = $CDCWitnessIP

  write-log -message "Central Datacenter Witness Password"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "CDCWitnessPassword" }) | add-member noteproperty value $CDCWitnessPassword -force
  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "CDCWitnessPassword" }).attrs.is_secret_modified = $true

  write-log -message "Site Build Account is '$RBCPEBuildAccount'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "RBCPEBuildAccount" }).value = $RBCPEBuildAccount

  write-log -message "Site EULA Name is '$EULAName'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "EULAName" }).value = $EULAName

  write-log -message "Calm Executioner is '$executioner'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "CalmExecutioner" }).value = $executioner

  write-log -message "Site Windows Image Password"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "WinImagePass" }) | add-member noteproperty value $WinImagePass -force
  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "WinImagePass" }).attrs.is_secret_modified = $true

  write-log -message "Site Linux Image Password"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LinImagePass" }) | add-member noteproperty value $LinImagePass -force
  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "LinImagePass" }).attrs.is_secret_modified = $true

  write-log -message "Site Node Count is '$SiteNodeCount'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SiteNodeCount" }).value = $SiteNodeCount

  write-log -message "Site Node Brand is '$NodeBrand'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "NodeBrand" }).value = $NodeBrand

  write-log -message "Site SDWan Brand is '$SDWanBrand'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SDWanBrand" }).value = $SDWanBrand

  write-log -message "Site Network Brand is '$NetworkBrand'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "NetworkBrand" }).value = $NetworkBrand

  write-log -message "Site Hands Email is '$SiteHandsEmail'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SiteHandsEmail" }).value = $SiteHandsEmail

  write-log -message "Site Network DNS is '$SNWDNS'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SNWDNS" }).value = $SNWDNS

  write-log -message "Site Network Gateway is '$SNWGW'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SNWGW" }).value = $SNWGW

  write-log -message "Site Network Subnet is '$SNWSubnet'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SNWSubnet" }).value = $SNWSubnet

  write-log -message "Site Network Vlan is '$SNWVlan'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SNWVlan" }).value = $SNWVlan

  write-log -message "Site Long Code is '$SLC'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SLC" }).value = $SLC

  write-log -message "Site Short Code is '$siteshortcode'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "SC" }).value = $siteshortcode

  write-log -message "Site Windows Domain is '$domainname'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "WindowsDomain" }).value = $domainname

  write-log -message "Site Management_IP is '$Management_IP'"  

  ($bpobject.spec.resources.app_profile_list[0].variable_list | where {$_.name -eq "Management_IP" }).value = $Management_IP





  #write-log -message "Setting up nic and IP"
  #$bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"} | % {$_.create_spec.resources.nic_list.subnet_reference.uuid = $subnet.uuid}
#
  #write-log -message "Setting up Images"
  #$bpobject.spec.resources.substrate_definition_list  | where {$_.Type -eq "AHV_VM"} | % {  
  #  if ($_.create_spec.resources.disk_list.data_source_reference.name -match "a-z|A-Z"){
  #    $_.create_spec.resources.disk_list.data_source_reference.uuid = $Linimage.metadata.uuid
  #  }
  #}

  write-log -message "Passing the ball to Calm"

  $Json = $BPObject | ConvertTo-Json -depth 100
   
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($blueprintdetail.metadata.uuid)"

  write-log -message "Executing Update using URL '$url'"
  if ($debug -ge 2){
    $json | out-file "$($loggingdir)\SiteControlPanelBP.json"
  }

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 


Function REST-Add-Custom-Calm-MarketPlace-BP {
  Param (
    [object] $BPobject,
    [object] $project,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $Release,
    [string] $app_group_uuid,
    [string] $IconUUID,
    [string] $name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Stripping Object properties from Detailed object"
  $Description = $BPobject.spec.description | ConvertTo-Json
  $Template = @"
  {
  "api_version": "3.0",
  "metadata": {
    "kind": "marketplace_item"
  },
  "spec": {
    "name": "",
    "description": "",
    "resources": {
      "app_attribute_list": ["FEATURED"],
      "icon_reference_list": [{
          "icon_type": "ICON",
          "icon_reference": {
              "kind": "file_item",
              "uuid": "$($IconUUID)"
          }
      }],
      "author": "1-click-robo",
      "app_blueprint_template": {},
      "version": "$($Release)",
      "app_group_uuid": "$($app_group_uuid)"
    }
  }
}
"@
  
  write-log -message "Stripping BP"

  $BPObject.psobject.properties.Remove('api_version')
  $BPObject.psobject.properties.Remove('metadata')

  write-log -message "Converting Template to Object"
  
  $templateobj = $template | convertfrom-json

  $templateobj.spec.name = $name
  $templateobj.spec.Description = $bpobject.spec.Description

  write-log -message "Adding '$($project.metadata.uuid)' Project into the BluePrint"

  

    $json = @"
{
        "name": "$($project.metadata.project_reference.name)",
        "kind": "project",
        "uuid": "$($project.metadata.uuid)"
}
"@ 
    [array]$projectref = $json | convertfrom-json
    $templateobj.spec.resources.psobject | add-member project_reference_list $projectref -force
 
  $templateobj.spec.resources.app_blueprint_template = $BPobject
  write-log -message "Setting State to Published."

  $templateobj.spec.resources.psobject | add-member app_state "PUBLISHED" -force

  $Json = $templateobj | ConvertTo-Json -depth 100
   
  if ($debug -ge 2 ){
    $Json | out-file c:\temp\bpmarket.json
  }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items"

  write-log -message "Executing POST"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Import-Generic-Blueprint {
  Param (
    [string] $BPfilepath,
    [object] $datagen,
    [string] $ProjectUUID,
    [object] $datavar
  )
  ## This module should be depricated, no more changing strings in JSON
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Loading Json"

  $jsonstring = get-content $BPfilepath
  $jsonstring = $jsonstring -replace "---PROJECTREF---", $($ProjectUUID)
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/import_json"

  write-log -message "Executing Import"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $jsonstring -ContentType 'application/json' -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $jsonstring -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 


Function REST-Publish-CalmMarketPlaceBP {
  Param (
    [object] $BPobject,
    [object] $project,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Stripping Object properties from Detailed object"

  if ($BPobject.psobject.members.name -contains "status"){
    $BPobject.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 

  write-log -message "Adding '$($project.metadata.uuid)' Project into the BluePrint"

  

    $json = @"
{
        "name": "$($project.metadata.project_reference.name)",
        "kind": "project",
        "uuid": "$($project.metadata.uuid)"
}
"@ 
    [array]$projectref = $json | convertfrom-json
    $bpobject.spec.resources.project_reference_list += $projectref
 

  write-log -message "Setting State to Published."

  $bpobject.spec.resources.app_state = "PUBLISHED"

  $Json = $bpobject | ConvertTo-Json -depth 100
   
  if ($debug -ge 2 ){
    $Json | out-file c:\temp\bpmarket.json
  }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($bpobject.metadata.uuid)"

  write-log -message "Executing PUT on $($bpobject.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 





Function REST-Blueprint-Export-WithSecrets {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $BluePrintUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Downloading '$BluePrintUUID' with secrets"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($BluePrintUUID)/export_json?keep_secrets=true"

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;

    write-log -message "Payload Downloaded"

  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  }
  

  Return $task
} 


Function REST-Import-Generic-Blueprint-Object {
  Param (
    [string] $BPfilepath,
    [object] $project,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [bool] $randomizename = $false,
    [string] $BPName
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "PC Endpoint is '$PCClusterIP'"
  write-log -message "Loading Json"

  $object = ($json = get-content $BPfilepath) | convertfrom-json

  write-log -message "Stripping Object properties from Detailed object"

  if ($object.psobject.members.name -contains "contains_secrets"){
    $object.psobject.members.Remove("contains_secrets")

    write-log -message "Removing contains_secrets"

  } 
  if ($object.psobject.members.name -contains "status"){
    $object.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 
  if ($object.psobject.members.name -contains "product_version"){
    $object.psobject.members.Remove("product_version")

    write-log -message "Removing Product Version"

  }
  if ($randomizename){
    $name =  (New-Guid).guid

    write-log -message "Creating random BPname '$name'"

    $object.metadata.name = $name
    $object.spec.name = $name

  } else {

    $object.metadata.name = $BPName
    $object.spec.name = $BPName

  }
  write-log -message "Adding Project $($project.metadata.uuid) ID into BluePrint"

  if (!$object.metadata.project_reference){
    $child = New-Object PSObject
    $child | add-member -notepropertyname uuid "0"
    $child | add-member -notepropertyname kind "project"
    $object.metadata | add-member -notepropertyname project_reference $child
  }
  $object.metadata.project_reference.uuid = $project.metadata.uuid

  $Json = $object | ConvertTo-Json -depth 100
   
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/import_json"

  write-log -message "Executing Import"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Restore-BackupBlueprint {
  Param (
    $blueprint,
    [object] $datagen,
    [object] $datavar
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Loading Json as Object"

  $BPObject = convertfrom-json $blueprint
  $Projectname = $BPObject.metadata.project_reference.name
  if (!$Projectname){
    $Projectname = "default"
  }

  write-log -message "Finding Project by name '$Projectname'"

  $projects = REST-Query-Projects -PCClusterIP $PCClusterIP -PxClusterPass $datavar.PEPass -PxClusterUser $datagen.BuildAccount
  $project = $projects.entities | where {$_.spec.name -eq $Projectname}

  if ($project){

    write-log -message "We found a matching project $($project.spec.name) with UUID $($project.metadata.uuid)"

  } else {

    write-log -message "$Projectname was not found restoring under default."

    $project = $projects.entities | where {$_.spec.name -eq "default"}

    write-log -message "Using default project in this restore with UUID '$($project.metadata.uuid)'"

  }
  if ($BPObject.metadata.project_reference){
    $BPObject.metadata.project_reference.uuid = $project.metadata.uuid
  } else {

    write-log -message "BP Does not contain a default project."

  }
  $jsonstring = $BPObject | ConvertTo-Json -depth 100
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/import_json"

  write-log -message "Restoring BP $($BPObject.spec.name) under project $($project.spec.name)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $jsonstring -ContentType 'application/json' -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on Function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $jsonstring -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 


Function REST-Query-Projects {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Project List Query"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/projects/list"
  $Payload= @{
    kind="project"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers;
  }
  write-log -message "We found '$($task.entities.count)' items."

  Return $task
} 

Function REST-Query-Calm-App-Detail{
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $UUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Query Calm App '$UUID'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($UUID)"

  write-log -message "Using IP '$($PCClusterIP)'"


  try {
    $task = Invoke-RestMethod -Uri $URL -method "GET"  -headers $headers -ea:4
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "GET"  -headers $headers;

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 

Function REST-Query-Calm-Apps {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Query Calm Apps"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/list"

  write-log -message "Using IP '$($PCClusterIP)'"

  $Payload= @{
    kind="app"
    offset=0
    length=250
  } 

  $JSON = $Payload | convertto-json
  try {
    $task = Invoke-RestMethod -Uri $URL -method "POST" -Body $JSON -ContentType 'application/json' -headers $headers -ea:4
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "POST" -Body $JSON -ContentType 'application/json' -headers $headers;

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 

Function REST-Delete-Calm-App {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $appUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Deleting Calm App '$($appUUID)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($appUUID)"

  write-log -message "Using IP '$($PCClusterIP)'"


  $JSON = $Payload | convertto-json
  try {
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers;

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 

Function REST-Query-Calm-BluePrints {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Query Calm BluePrints"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/list"

  write-log -message "Using IP $($datagen.PCClusterIP)"

  $Payload= @{
    kind="blueprint"
    offset=0
    length=250
  } 

  $JSON = $Payload | convertto-json
  write-host  $JSON
  try {
    $task = Invoke-RestMethod -Uri $URL -method "POST" -Body $JSON -ContentType 'application/json' -headers $headers -ea:4
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "POST" -Body $JSON -ContentType 'application/json' -headers $headers;

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 



Function REST-BluePrint-Launch-Generic {
  Param (
      [string] $PCClusterIP,
      [string] $PxClusterPass,
      [string] $PxClusterUser,
      [object] $BPobject,
      [string] $appname,
      [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Working with BP UUID $($BPobject.metadata.uuid)"

  write-log -message "App Name"
  $bpobject.spec  | add-member noteproperty application_name "$AppName" -force
$appprofile = @"
{
    "app_profile_reference": {
      "kind": "app_profile",
      "uuid": "$($BPobject.spec.resources.app_profile_list.uuid)"
    }
}
"@
  $bpobject.spec  | add-member noteproperty app_profile_reference "temp" -force
  $appprofileobj = $appprofile | convertfrom-json
  $bpobject.spec.app_profile_reference = $appprofileobj.app_profile_reference

  write-log -message "Stripping Object properties from Detailed object"

  if ($bpobject.psobject.members.name -contains "contains_secrets"){
    $bpobject.psobject.members.Remove("contains_secrets")

    write-log -message "Removing contains_secrets"

  } 
  if ($bpobject.psobject.members.name -contains "status"){
    $bpobject.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 
  if ($bpobject.psobject.members.name -contains "product_version"){
    $bpobject.psobject.members.Remove("product_version")

    write-log -message "Removing Product Version"

  }
  $bpobject.spec.psobject.members.Remove("name")
  
  write-log -message "Converting Object back to Json Payload"

  $Json = $bpobject | convertto-json -depth 100


  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($BPobject.metadata.uuid)/launch"
  if ($debug -ge 2){
    $Json | out-file "$($loggingdir)\GenbplaunchFull.json"
  }

  write-log -message "Executing Launch on BP '$($BPobject.metadata.uuid)'"
  write-log -message "Using URL '$URL'"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
}




Function REST-Get-Calm-Global-MarketPlace-Items {
  Param (
      [string] $PCClusterIP,
      [string] $PxClusterPass,
      [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
$Json = @"
{
  "filter_criteria": "marketplace_item_type_list==APP",
  "group_member_offset": 0,
  "group_member_count": 5000,
  "entity_type": "marketplace_item",
  "group_member_attributes": [{
    "attribute": "name"
  }, {
    "attribute": "author"
  }, {
    "attribute": "version"
  }, {
    "attribute": "categories"
  }, {
    "attribute": "owner_reference"
  }, {
    "attribute": "owner_username"
  }, {
    "attribute": "project_names"
  }, {
    "attribute": "project_uuids"
  }, {
    "attribute": "app_state"
  }, {
    "attribute": "description"
  }, {
    "attribute": "spec_version"
  }, {
    "attribute": "app_attribute_list"
  }, {
    "attribute": "app_group_uuid"
  }, {
    "attribute": "icon_list"
  }, {
    "attribute": "change_log"
  }, {
    "attribute": "app_source"
  }]
}
"@ 
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/groups"

  write-log -message "Getting All Market Place Items."
  write-log -message "Using URL '$URL'"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-DELETE-Calm-MarketPlace-Item {
 Param (
      [string] $PCClusterIP,
      [string] $PxClusterPass,
      [string] $PxClusterUser,
      [string] $MKTUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($MKTUUID)"

  write-log -message "Deleting Market Place Item Detail."
  write-log -message "Using URL '$URL'"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers;
  }

  Return $task
} 

Function REST-Get-Calm-GlobalMarketPlaceItem-Detail {
 Param (
      [string] $PCClusterIP,
      [string] $PxClusterPass,
      [string] $PxClusterUser,
      [string] $MKTUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($MKTUUID)"

  write-log -message "Getting Market Place Item Detail."
  write-log -message "Using URL '$URL'"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  }

  Return $task
} 

Function REST-Query-Calm-Detailed-App {
  Param (
      [string] $PCClusterIP,
      [string] $PxClusterPass,
      [string] $PxClusterUser,
      [string] $UUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Working with App UUID $($UUID)"

  write-log -message "Query Calm $($UUID) App Detailed"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($UUID)"

  write-log -message "Using URL '$URL'"
  write-log -message "Using IP '$($PCClusterIP)'"

  $JSON = $Payload | convertto-json
  write-host  $JSON
  try {
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;
  } catch {
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers;

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 



function REST-update-project-ACP {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $projectdetail,
    [object] $Subnet,
    [object] $consumer,
    [object] $projectadmin,
    [object] $cluster,
    [string] $sitelongcode,    
    [object] $admingroup,
    [object] $usergroup,
    [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Prepping object"
  $projectdetail.psobject.properties.Remove('status')

  write-log -message "Updating Project $($projectdetail.metadata.uuid)"
  write-log -message "Building child object to be inserted"


  
$json2 = @"
[{
        "acp": {
          "name": "ACP PAdmin for $SiteLongCode",
          "resources": {
            "role_reference": {
              "kind": "role",
              "uuid": "$($ProjectAdmin.metadata.uuid)"
            },
            "user_reference_list": [

            ],
            "filter_list": {
              "context_list": [{
                  "entity_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": {
                      "entity_type": "all"
                    },
                    "right_hand_side": {
                      "collection": "ALL"
                    }
                  }],
                  "scope_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": "PROJECT",
                    "right_hand_side": {
                      "uuid_list": [
                        "$($projectdetail.metadata.uuid)"
                      ]
                    }
                  }]
                },
                {
                  "entity_filter_expression_list": [{
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "category"
                      },
                      "right_hand_side": {
                        "collection": "ALL"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "cluster"
                      },
                      "right_hand_side": {
                        "uuid_list": [
                          "$($cluster.metadata.uuid)"
                        ]
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "directory_service"
                      },
                      "right_hand_side": {
                        "collection": "ALL"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "environment"
                      },
                      "right_hand_side": {
                        "collection": "SELF_OWNED"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "image"
                      },
                      "right_hand_side": {
                        "collection": "ALL"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "marketplace_item"
                      },
                      "right_hand_side": {
                        "collection": "SELF_OWNED"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "project"
                      },
                      "right_hand_side": {
                        "uuid_list": [
                          "$($projectdetail.metadata.uuid)"
                        ]
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "role"
                      },
                      "right_hand_side": {
                        "collection": "ALL"
                      }
                    }
                  ],
                  "scope_filter_expression_list": [

                  ]
                },
                {
                  "entity_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": {
                      "entity_type": "user"
                    },
                    "right_hand_side": {
                      "collection": "ALL"
                    }
                  }],
                  "scope_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": "PROJECT",
                    "right_hand_side": {
                      "uuid_list": [
                        "$($projectdetail.metadata.uuid)"
                      ]
                    }
                  }]
                },
                {
                  "entity_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": {
                      "entity_type": "user_group"
                    },
                    "right_hand_side": {
                      "collection": "ALL"
                    }
                  }],
                  "scope_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": "PROJECT",
                    "right_hand_side": {
                      "uuid_list": [
                        "$($projectdetail.metadata.uuid)"
                      ]
                    }
                  }]
                }
              ]
            },
            "user_group_reference_list": [{
              "kind": "user_group",
              "name": "$($admingroup.spec.resources.directory_service_user_group.distinguished_name)",
              "uuid": "$($admingroup.metadata.uuid)"
            }]
          },
          "description": "prismui-desc-a8527482f0b1123"
        },
          "operation": "ADD",
        "metadata": {
          "kind": "access_control_policy"
        }
      },
      {
        "acp": {
          "name": "ACP Admin for $customer",
          "resources": {
            "role_reference": {
              "kind": "role",
              "uuid": "$($Consumer.metadata.uuid)"
            },
            "user_reference_list": [

            ],
            "filter_list": {
              "context_list": [{
                  "entity_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": {
                      "entity_type": "all"
                    },
                    "right_hand_side": {
                      "collection": "ALL"
                    }
                  }],
                  "scope_filter_expression_list": [{
                    "operator": "IN",
                    "left_hand_side": "PROJECT",
                    "right_hand_side": {
                      "uuid_list": [
                        "$($projectdetail.metadata.uuid)"
                      ]
                    }
                  }]
                },
                {
                  "entity_filter_expression_list": [{
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "category"
                      },
                      "right_hand_side": {
                        "collection": "ALL"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "cluster"
                      },
                      "right_hand_side": {
                        "uuid_list": [
                          "$($cluster.metadata.uuid)"
                        ]
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "image"
                      },
                      "right_hand_side": {
                        "collection": "ALL"
                      }
                    },
                    {
                      "operator": "IN",
                      "left_hand_side": {
                        "entity_type": "marketplace_item"
                      },
                      "right_hand_side": {
                        "collection": "SELF_OWNED"
                      }
                    }
                  ],
                  "scope_filter_expression_list": [

                  ]
                }
              ]
            },
            "user_group_reference_list": [{
              "kind": "user_group",
              "name": "$($usergroup.spec.resources.directory_service_user_group.distinguished_name)",
              "uuid": "$($usergroup.metadata.uuid)"
            }]
          },
          "description": "prismui-desc-9838f052a82f"
        },
        "operation": "ADD",
        "metadata": {
          "kind": "access_control_policy"
        }
      }]
"@

  write-log -message "Converting Child"

  $child = $json2 | convertfrom-json

  try {
    write-log -message "Terminating childs"

    $projectdetail.spec.psobject.properties.Remove('access_control_policy_list')
  } catch {
    write-log -message "Parent does not have childs yet."
  }
  if (!$projectdetail.spec.access_control_policy_list){
    $projectdetail.spec | Add-Member -notepropertyname "access_control_policy_list" $child -force

    write-log -message "So the external user group reference list does not exist yet on this project. Adding a construct."
  }

  write-log -message "Injecting Child into Parent"

  $projectdetail.spec.access_control_policy_list = [array]$child

  write-log -message "Updating Project $($projectdetail.metadata.uuid)"

  $json1 = $projectdetail | ConvertTo-Json -depth 100
  if ($debug -ge 2 ){
    $json1 | out-file "$($loggingdir)\ACP.json"
  }

  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($projectdetail.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

function REST-update-project-RBAC {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $projectdetail,
    [object] $admingroup,
    [object] $usergroup,
    [string] $loggingdir
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Prepping object"
  $projectdetail.psobject.properties.Remove('status')


  write-log -message "Updating Project UUID '$($projectdetail.metadata.uuid)'"
  write-log -message "Updating Project Name '$($projectdetail.spec.project_detail.name)'"
  write-log -message "Adding '$($admingroup.metadata.uuid)' For Admin group"
  write-log -message "Adding '$($usergroup.metadata.uuid)' For User group"
  write-log -message "Building child object to be inserted"
  
   
      $json1 = @"
          {
            "kind": "user_group",
            "name": "$($admingroup.spec.resources.directory_service_user_group.distinguished_name)",
            "uuid": "$($admingroup.metadata.uuid)"
          }
"@
      $json2 = @"
          {
            "kind": "user_group",
            "name": "$($usergroup.spec.resources.directory_service_user_group.distinguished_name)",
            "uuid": "$($usergroup.metadata.uuid)"
          }
"@


  
      write-log -message "Converting Child"
      [array]$childs = $json2 | convertfrom-json
      [array]$childs += $json1 | convertfrom-json

  
  
  write-log -message "Injecting Child into Parent"
  try {
    write-log -message "Terminating childs"

    $projectdetail.spec.project_detail.resources.psobject.properties.Remove('external_user_group_reference_list')
  } catch {
    write-log -message "Parent does not have childs yet."
  }
  if (!$projectdetail.spec.project_detail.resources.external_user_group_reference_list){
    $projectdetail.spec.project_detail.resources | Add-Member -notepropertyname "external_user_group_reference_list" $childs -force

    write-log -message "So the external user group reference list does not exist yet for this project. Adding a construct."
  }

  $projectdetail.spec.project_detail.resources.external_user_group_reference_list += [array]$childs

  write-log -message "Updating Project '$($projectdetail.metadata.uuid)'"

  $json1 = $projectdetail | ConvertTo-Json -depth 100

  if ($debug -ge 2){
    $json1 | out-file "$($Loggingdir)\projectUser.json"
  }

  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($projectdetail.metadata.uuid)"
  $counter = 0
  do{
    $counter ++
    try{
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
      $exit = 1
    } catch {
      sleep 10
      $exit = 0
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
    }
  } until ($exit -eq 1 -or $counter -ge 5)
  Return $task
} 

function REST-update-project-Account {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $projectdetail,
    [object] $accounts
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Prepping object"
  $projectdetail.psobject.properties.Remove('status')

  write-log -message "Updating Project UUID '$($projectdetail.metadata.uuid)'"
  write-log -message "Updating Project Name '$($projectdetail.spec.project_detail.name)'"
  write-log -message "Adding '$($accounts.entities.count)' Account(s).."
  write-log -message "Building child object to be inserted"
  $childs = $null
  foreach ($account in $accounts.entities){
    if ($account.status.resources.type -ne "Nutanix" ){
      $json2 = @"
        {
          "uuid": "$($account.metadata.uuid)",
          "kind": "account",
          "name": "$($account.status.resources.type)"
        }
"@    
      if ($debug -ge 2){ 
        write $json2
      }
      write-log -message "Converting Child"
      $child = $json2 | convertfrom-json
      [array]$childs += $child
    }
  }
  write-log -message "Injecting Child into Parent"
  try {
    write-log -message "Terminating childs"

    $projectdetail.spec.project_detail.resources.psobject.properties.Remove('account_reference_list')
  } catch {
    write-log -message "Parent does not have childs yet."
  }
  if (!$projectdetail.spec.project_detail.resources.account_reference_list){
    $projectdetail.spec.project_detail.resources | Add-Member -notepropertyname "account_reference_list" $childs -force

    write-log -message "So the account reference list does not exist yet on this project. Adding a construct."
  }

  $projectdetail.spec.project_detail.resources.account_reference_list += [array]$childs

  write-log -message "Updating Project '$($projectdetail.metadata.uuid)'"

  $json1 = $projectdetail | ConvertTo-Json -depth 100

  if ($debug -ge 2){
    $json1 | out-file "$($Loggingdir)\projectaccount.json"
  }

  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($projectdetail.metadata.uuid)"
  $counter = 0
  do{
    $counter ++
    try{
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
      $exit = 1
    } catch {
      sleep 119
      $error.clear()
      $exit = 0
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
    }
  } until ($exit -eq 1 -or $counter -ge 5)
  Return $task
} 

function REST-update-project-environment {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $projectdetail,
    [object] $environment
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Prepping object"
  $projectdetail.psobject.properties.Remove('status')

  write-log -message "Updating Project $($projectdetail.metadata.uuid)"
  write-log -message "Adding Environment $($environment.metadata.uuid)"
  write-log -message "Building child object to be inserted"
  
$json2 = @"
{
    "kind":  "environment",
    "uuid":  "$($environment.metadata.uuid)"
}
"@

  write-log -message "Converting Child"

  $child = $json2 | convertfrom-json

  write-log -message "Injecting Child into Parent"

  $projectdetail.spec.project_detail.resources.environment_reference_list += $child

  write-log -message "Updating Project $($projectdetail.metadata.uuid)"

  $json1 = $projectdetail | ConvertTo-Json -depth 100
  if ($debug -ge 2){
    write $json1
  } 
  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($projectdetail.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers -ea:4
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL1 -method "put" -body $json1 -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-Get-ProjectDetail {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [object] $project
  )

  write-log -message "Building Header"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Getting Detailed Project '$($project.metadata.uuid)'"

  $URL1 = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($project.metadata.uuid)"
  
  write-log -message "Using URL '$($url1)'"

  try{
    $task = Invoke-RestMethod -Uri $URL1 -method "GET" -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL1 -method "GET" -headers $headers;
  }
  return $task
}