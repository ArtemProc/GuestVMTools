Function REST-Get-PC-Login-Token {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building PC Batch Login query to get me a token"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/batch"
  $JSON = @"
{
  "action_on_failure": "CONTINUE",
  "execution_order": "SEQUENTIAL",
  "api_request_list": [{
    "operation": "GET",
    "path_and_params": "/api/nutanix/v3/users/me"
  }, {
    "operation": "GET",
    "path_and_params": "/api/nutanix/v3/users/info"
  }],
  "api_version": "3.0"
}
"@
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers -SessionVariable websession;
  } catch {
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers -SessionVariable websession;

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }
  $cookies = $websession.Cookies.GetCookies($url) 
  Return $cookies
} 

Function REST-Category-Value-Create {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $CatObj,
    [string] $Value
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating Value '$Value' on Category '$($CatObj.name)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$($CatObj.name)/$($Value)"

  $Payload= @"
{
      "value": "$Value",
      "description": "$($CatObj.description)"
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Category-Create {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating / Updating Category '$($Name)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$($Name)"
  ## What is cardinality.. Do we care.. We only create once. We dont update.
  $Payload= @"
{
  "api_version": "3.1.0",
  "description": "Created by 1-click-robo.",
  "capabilities": {
    "cardinality": 64
  },
  "name": "$($Name)"
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 



Function REST-Category-Query {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Finding Category with Name '$($Name)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$Name"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    write-log "Category '$Name' does not exist."
  }

  Return $task
}

Function REST-Category-Value-Query {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name,
    [string] $value
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Finding Category Value with Name '$($Name)' and value '$($value)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$($Name)/$($value)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    write-log -message "Category with Name '$($Name)' and value '$($value)' does not exist."
  }

  Return $task
} 

Function REST-Category-Value-Assign {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $tagstring,
    [object] $VM_Cat_MAP
  )

  write-log -message "Adding Categories on project '$($VM_Cat_MAP.metadata.project_reference.uuid)'"
  write-log -message "On VM '$($VM_Cat_Map.metadata.uuid)'"

  [array] $tagarr = $TagString -split ","

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  


  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/batch"


  $payload= @"
  {
  "action_on_failure": "CONTINUE",
  "execution_order": "NON_SEQUENTIAL",
  "api_request_list": [{
    "operation": "PUT",
    "path_and_params": "/api/nutanix/v3/mh_vms/$($VM_Cat_Map.metadata.uuid)",
    "body": {

    }
  }],
  "api_version": "3.0"
}
"@  
  $PayloadObj = $payload | convertfrom-json
  $VM_Cat_MAP.psobject.members.Remove("status")
  foreach ($tag in $tagarr){

    $CategoryName = ($tag -split ":")[0]
    $Value = ($tag -split ":")[1]

    write-log -message "Assigning Value '$Value' inside Category '$($CategoryName)'"
    write-log -message "Towards VMUUID '$($VM_Cat_MAP.metadata.uuid)' inside project '$($VM_Cat_MAP.metadata.project_reference.uuid)',"
    write-log -message "Inside our cluster '$($VM_Cat_Map.spec.cluster_reference.uuid)'"

    if ($VM_Cat_Map.metadata.categories -match $CategoryName){
      if ($value -notin $VM_Cat_Map.metadata.categories."$($CategoryName)" ){
        $VM_Cat_Map.metadata.categories."$($CategoryName)" +=  $Value
        $VM_Cat_Map.metadata.categories_mapping."$($CategoryName)" += $valarr 
        $sendpayload = 1

        write-log -message "Category is present adding value" -sev "WARN" ## We should not be adding more than one tag for the same category no?

      } else {
        $sendpayload = 0

        write-log -message "'$Value' inside Category '$($CategoryName)' is already present for VM " 

      }
    } else {
      write-log -message "Category '$($CategoryName)' does not exist on this VM Map yet" 

      $sendpayload = 1
      [array]$valarr += $value 

      $VM_Cat_Map.metadata.categories | add-member Noteproperty "$($CategoryName)"  $Value
      $VM_Cat_Map.metadata.categories_mapping | add-member Noteproperty "$($CategoryName)" $valarr

    }
  }
  $PayloadObj.api_request_list[0].body = $VM_Cat_Map
  $finalPayload =  $PayloadObj | ConvertTo-Json -depth 100
  if ($debug -ge 3){
    write $finalPayload | out-file c:\temp\debugcategory.json
  }
  if ($sendpayload -eq 1){
    try{
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $finalPayload -ContentType 'application/json' -headers $headers -ea:4;
    } catch {$error.clear()
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $finalPayload -ContentType 'application/json' -headers $headers
    }
    Return $task
  }
  Return "Nothing to do."
 
} 


Function REST-Category-Query-VM-Assign {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $VMUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Finding Category Object for VM '$VMUUID'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/batch"
  ## What is the spec version doing here. What spec version? 
  $Payload= @"
{
  "action_on_failure": "CONTINUE",
  "execution_order": "NON_SEQUENTIAL",
  "api_request_list": [{
    "operation": "GET",
    "path_and_params": "/api/nutanix/v3/mh_vms/$VMUUID"
  }],
  "api_version": "3.0"
}
"@
  if ($debug -ge 2){
    write $payload
  }
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Query-ADGroups {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building UserGroup Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/user_groups/list"
  $Payload= @{
    kind="user_group"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try { 
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }

  Return $task
}


Function REST-Enable-HA {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Enabling HA on PE!"

  $URL = "https://$($PEClusterIP):9440/api/nutanix/v0.8/ha"
  $Payload= @"
{
  "enableFailover": true,
  "numHostFailuresToTolerate": 1
}
"@
  
  try { 
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }

  Return $task
}



Function REST-Configure-Witness {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $WitnessPassword,
    [string] $WitnessIP,
    [string] $RoboClusterName
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Registering Witness '$WitnessIP'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/cluster/metro_witness"
  $json1 = @"
{
  "ip_addresses": ["$($WitnessIP)"],
  "username": "admin",
  "password": "$($WitnessPassword)",
  "cluster_name": "$($RoboClusterName)"
}
"@

  try { 
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json1 -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json1 -ContentType 'application/json' -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }

  Return $task
}


Function REST-PE-Get-MultiCluster {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterUser,
    [string] $PxClusterPass
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PEClusterIP):9440//PrismGateway/services/rest/v1/multicluster/cluster_external_state"

  try{
    $Inventory = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  
    write-log -message "MultiCluster Status Retrieved"
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $Inventory = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }
  Return $Inventory

} 


Function REST-PE-Add-MultiCluster {
  Param (
    [string] $PEClusterIP,
    [string] $PEClusterUser,
    [string] $PEClusterPass,
    [string] $PCClusterIP,
    [string] $PCClusterUser,
    [string] $PCClusterPass
  )

  write-log -message "Building Credential object"
  $credPair = "$($PEClusterUser):$($PEClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/multicluster/prism_central/register"
  $json1 = @"
{
    "ipAddresses": ["$($PCClusterIP)"],
    "username": "$($PCClusterUser)",
    "password": "$($PCClusterPass)",
    "port": 9440
}
"@

  try{
    $Inventory = Invoke-RestMethod -Uri $URL -method "post" -body $json1 -ContentType 'application/json' -headers $headers -ea:4;
  
    write-log -message "MultiCluster Join Request sent"
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $Inventory = Invoke-RestMethod -Uri $URL -method "post" -body $json1 -ContentType 'application/json' -headers $headers
  }
  Return $Inventory

} 

Function REST-PE-Remove-MultiCluster {
  Param (
    [string] $PEClusterIP,
    [string] $PEClusterUser,
    [string] $PEClusterPass,
    [string] $PCClusterIP,
    [string] $PCClusterUser,
    [string] $PCClusterPass
  )

  write-log -message "Building Credential object"
  $credPair = "$($PEClusterUser):$($PEClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/multicluster/prism_central/register"


  try{
    $Inventory = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers -ea:4;
  
    write-log -message "MultiCluster Join Request sent"
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $Inventory = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers
  }
  Return $Inventory

} 

Function REST-Get-PE-Networks {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Query PE Networks"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/networks"

  write-log -message "Using User $PxClusterUser"

  try {
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 

Function REST-Get-Prx-Networks {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ClusterUUID
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Query PE Networks through PC"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v2.0/networks?proxyClusterUuid=$($ClusterUUID)"

  write-log -message "Using URL $URL"

  try {
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 



Function REST-Get-Containers {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Container List"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/containers"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }
  write-log -message "We found $($task.entities.count) items."

  Return $task
} 

Function REST-Get-PE-Hosts {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Get Hosts Query"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/hosts"

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Function REST-Get-PRX-Hosts {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $CLUUID
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Get Hosts Query"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/hosts?proxyClusterUuid=$CLUUID"

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Function REST-Get-PE-Host-Nics-PRX {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $HostUUID,
    [string] $CLUUID
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Get Hosts Query"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/hosts/$($HostUUID)/host_nics?proxyClusterUuid=$CLUUID"

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Function REST-Get-PE-Host-Nics {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $HostUUID
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Get Hosts Query"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/hosts/$($HostUUID)/host_nics"

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 


Function REST-Enable-Calm {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  
  write-log -message "Building Credential object"
  $countcalm = 0 
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building CALM JSON"

  $CALMURL = "https://$($PCClusterIP):9440/api/nutanix/v3/services/nucalm"
  $CALMPayload= @{
    state="ENABLE"
    enable_nutanix_apps=$true
  } 
  $CalmJSON = $CALMPayload | convertto-json

  write-log -message "Enabling Calm"
  do {;
    $countcalm++;
    $successCLAM = $false;
    try {;
      $task = Invoke-RestMethod -Uri $CALMURL -method "post" -body $CalmJSON -ContentType 'application/json' -headers $headers -ea:4;
      
    }catch {;

      write-log -message "Enabling CALM Failed, retry attempt $countcalm out of 5" -sev "WARN";

      sleep 2
       $successCLAM = $false;
    }
    try {
      sleep 90 
      $task = Invoke-RestMethod -Uri $CALMURL -method "post" -body $CalmJSON -ContentType 'application/json' -headers $headers

      write-log -message "Just Checking" 
      
      $successCLAM = $true;

    } catch {$error.clear()
      $successCLAM = $true

      write-log -message "Calm was propperly enabled"
    }
  } until ($successCLAM -eq $true -or $countcalm -eq 5);



  if ($countcalm -eq 5){;
  
    write-log -message "Registration failed after $countEULA attempts" -sev "WARN";
  
  };
  if ($successCLAM -eq $true){
    write-log -message "Enabling Calm success"
    $status = "Success"
  } else {
    $status = "Failed"
  }
  $resultobject =@{
    Result = $status
    TaskUUID = $task.task_uuid
  }
  return $resultobject
};


Function REST-Enable-Flow {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"
  $countflow = 0 
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $FlowURL = "https://$($PCClusterIP):9440/api/nutanix/v3/services/microseg"
  $TestURL = "https://$($PCClusterIP):9440/api/nutanix/v3/services/microseg/status"

  $FlowPayload= @{
    state="ENABLE"
  } 

  $FlowJSON = $FlowPayload | convertto-json

  do {;
    $countFlow++;
    $successflow = $false;
    try {;
      if ($mode -eq "Full"){

        write-log -message "Enabling Flow"

        $task = Invoke-RestMethod -Uri $FlowURL -method "post" -body $FlowJSON -ContentType 'application/json' -headers $headers -ea:4;
      }
      $testercount = 0
      do {
        write-log -message "Checking Flow Enabled status"

        $testercount++
        $testtask = Invoke-RestMethod -Uri $TestURL -method "GET" -headers $headers -ea:4;
        sleep 10
      } until ($testtask.service_enablement_status -eq "ENABLED" -or $testercount -ge 8)
      if ($testtask.service_enablement_status -eq "ENABLED"){
        $successflow = $true
      } else {

        write-log -message "Enabling Flow Failed, retry attempt $countFlow out of 5" -sev "WARN";
        
      }
      
    }catch {;

      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
      $task
      sleep 2
      $successflow = $false;
    }

  } until ($successflow -eq $true -or $countFlow -eq 5);
  if ($countFlow -eq 5){;
  
    write-log -message "Enabling Flow failed after $countEULA attempts" -sev "WARN";
  
  };
  if ($successflow -eq $true){
    write-log -message "Enabling Flow success"
    $status = "Success"
  } else {
    $status = "Failed"
  }
  $resultobject =@{
    Result = $status
    TaskUUID = $task.task_uuid
  }
  return $resultobject
};

Function REST-Enable-Karbon-PC {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Enabling Karbon"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $SET = '{"value":"{\".oid\":\"ClusterManager\",\".method\":\"enable_service_with_prechecks\",\".kwargs\":{\"service_list_json\":\"{\\\"service_list\\\":[\\\"KarbonUIService\\\",\\\"KarbonCoreService\\\"]}\"}}"}'
  $CHECK = '{"value":"{\".oid\":\"ClusterManager\",\".method\":\"is_service_enabled\",\".kwargs\":{\"service_name\":\"KarbonUIService\"}}"}'
  
  try{
    $Checktask1 = Invoke-RestMethod -Uri $URL -method "post" -body $CHECK -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    write-log -message "Going once"

    $Checktask1 = Invoke-RestMethod -Uri $URL -method "post" -body $CHECK -ContentType 'application/json' -headers $headers
    $result = $Checktask1 
  }
  if ($Checktask1 -notmatch "true"){

    write-log -message "Karbon is not enabled yet."

    try{
      $SETtask = Invoke-RestMethod -Uri $URL -method "post" -body $SET -ContentType 'application/json' -headers $headers -ea:4;
    } catch {$error.clear()
      sleep 10

      write-log -message "Going once"
  
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $SET -ContentType 'application/json' -headers $headers
    }
  
    sleep 5 
  
    try{
      $Checktask2 = Invoke-RestMethod -Uri $URL -method "post" -body $CHECK -ContentType 'application/json' -headers $headers -ea:4;
    } catch {$error.clear()
      sleep 10

      write-log -message "Going once"
  
      $Checktask2 = Invoke-RestMethod -Uri $URL -method "post" -body $CHECK -ContentType 'application/json' -headers $headers
    }
    $result = $Checktask2 
  } else {

    write-log -message "Karbon is already enabled."
    $result = "true"

  }
  if ($result -match "true"){
    $status = "Success"

    write-log -message "All Done here";

  } else {
    $status = "Failed"
    write-log -message "Danger Will Robbinson." -sev "ERROR";
  }
  $resultobject =@{
    Result = $status
    Output = $result
  };
  return $resultobject
} 

Function REST-Finalize-Px {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $EULANAME,
    [string] $EULACompany,
    [string] $EULAROLE,
    [string] $EnablePulse
  )

  ###https://pallabpain.wordpress.com/2016/09/14/rest-api-call-with-basic-authentication-in-powershell/

  
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building EULA JSON"

  $EULAURL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/eulas/accept"
  $EULATURL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/eulas"
  $EULAPayload= @{
    username="$($EULANAME)"
    companyName="$($EULACompany)"
    jobTitle="$($EULAROLE)"
  } 
  $EULAJson = $EULAPayload | convertto-json

  write-log -message "Registering Px"
  try {
    $registration = (Invoke-RestMethod -Uri $EULATURL -method "get" -headers $headers -ea:4).entities.userdetailslist;
    
  } catch {$error.clear();
    write-log -message "We Could not query Px to retrieve existing registration" -sev "WARN";
  };
  if ($registration.username -eq $EULANAME ){;

    write-log -message "Px $PxClusterIP is already registrered";

    $successEULA = $true;
    $registration
  } else {;
    do {;
      $countEULA++;
      $successEULA = $false;
      try {;
        Invoke-RestMethod -Uri $EULAURL -method "post" -body $EULAJson -ContentType 'application/json' -headers $headers -ea:4;
        $successEULA = $true;
      }catch {;
  
        write-log -message "Registration failed, retry attempt $countEULA out of 5" -sev "WARN";
        sleep 2
        $successEULA = $false;
      }
    } until ($successEULA -eq $true -or $countEULA -eq 5);
    if ($countEULA -eq 5){;
  
      write-log -message "Registration failed after $countEULA attempts" -sev "WARN";

    };
  };

  
  if ($EnablePulse -eq 1){

    write-log -message "Building Pulse JSON"  

    $PulseURL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/pulse"
    $PulsePayload=@{
        enable="true"
        enableDefaultNutanixEmail="false"
        isPulsePromptNeeded="false"
    }
    $PulseJson = $PulsePayload | convertto-json

    write-log -message "Enabling Pulse"

    do {
      $countPulse++
      $Pulsestatus = $false
      try {
        Invoke-RestMethod -Uri $PulseURL -method "put" -body $PulseJson -ContentType 'application/json' -headers $headers -ea:4;
        $Pulsestatus = $true

      }catch {
        
        write-log -message "Disabling pulse failed, retry attempt $countPulse out of 5" -sev "WARN"

        $Pulsestatus = $false
        sleep 2
      }
    } until ($Pulsestatus -eq $true -or $countPulse -eq 5)
    if ($countPulse -eq 5){

      write-log -message "Disabling Pulse failed after $countEULA attempts" -sev "WARN"

    };
  } else {
    $Pulsestatus -eq $true
  }
  if ($successEULA -eq $true -and $Pulsestatus -eq $true){
    $status = "Success"
  } else {
    $status = "Failed"
  }
  $resultobject =@{
    Result = $status
  }
  return $resultobject
};

Function REST-Image-Import-PC {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $failsilent,
    [string] $siteshortcode
  )
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Cluster JSON" 
  $clusterurl = "https://$($PCClusterIP):9440//api/nutanix/v3/clusters/list"
  $ClusterJSON = @"
{
  "kind": "cluster"
}
"@

  do {;
    write-log -message "Gathering Cluster UUID"
    try {
      $Clusters = (Invoke-RestMethod -Uri $clusterurl -method "POST" -headers $headers -ea:4 -body $ClusterJSON -ContentType 'application/json').entities
      $cluster = $clusters | where {$_.status.name -match $siteshortcode}
      write-log -message "PE Cluster UUID is '$($cluster.metadata.uuid)'"
    } catch {$error.clear();
      write-log -message "We Could not query Px to retrieve existing storage containers" -sev "ERROR";
    };
    write-log -message "Building Image Import JSON" 
    $ImageURL = "https://$($PCClusterIP):9440/api/nutanix/v3/images/migrate"  
    $ImageJSON = @"
{
  "image_reference_list":[],
  "cluster_reference":{
    "uuid":"$($cluster.metadata.uuid)",
    "kind":"cluster",
    "name":"string"}
}
"@
    $countimport++;
    $successImport = $false;
    try {;
      $task = Invoke-RestMethod -Uri $ImageURL -method "post" -body $ImageJSON -ContentType 'application/json' -headers $headers -ea:4;
      $successImport = $true
    } catch {$error.clear();

      write-log -message "Importing Images into PC Failed, retry attempt '$countimport' out of '$failcount'" -sev "WARN";

      sleep 60
      $successImport = $false;
    }
  } until ($successImport -eq $true -or $countimport -eq $failcount);

  if ($successImport -eq $true){
    write-log -message "Importing Images into PC success"
    $status = "Success"
  } else {
    $status = "Failed"
  }
  $resultobject =@{
    Result = $status
    TaskUUID = $task.task_uuid
  }
  return $resultobject
};

Function REST-Install-PC {
  Param (
    [string] $PEClusterIP,
    [string] $PCClusterIP,
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $InfraSubnetmask,
    [string] $InfraGateway,
    [string] $DNSServer,
    [string] $PC1_Name,
    [string] $PC2_Name,
    [string] $PC3_Name,
    [string] $PC1_IP,
    [string] $PC2_IP,
    [string] $PC3_IP,
    [string] $AOSVersion,
    [string] $NetworkName,
    [string] $DisksContainerName,
    [string] $PCmode,
    [string] $PCVersion

  )
  $PCinstallcount = 0 
  
  write-log -message "Building Credential object"
  do {
    $PCinstallcount++
    $credPair = "$($PxClusterUser):$($PxClusterPass)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $containerURL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/storage_containers"
    $networksURL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/networks"
    $queryURL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/upgrade/prism_central_deploy/softwares"
    $installURL = "https://$($PEClusterIP):9440/api/nutanix/v3/prism_central"


   try {
      $Version = (Invoke-RestMethod -Uri $queryURL -method "get" -headers $headers -ea:4).entities.version | sort { [Version]$_} | select -last 1
      write-log -message "Latest Version is $Version"
      write-log -message "Specified version is $pcVersion"


      if ($pcversion -match "Latest|Auto" -or $pcversion -eq $null){

        write-log -message "Using PC Version $Version"

      } else {
        $Version = $pcVersion
      }
      write-log -message "Using PC Version ->$($Version)<-"

    } catch {$error.clear();
      write-log -message "Could not query PE to retrieve PC version" -sev "ERROR";
    };

    $Object = (Invoke-RestMethod -Uri $queryURL -method "get" -headers $headers -ea:4).entities | where {$_.version -eq $Version}
    $sizeL = $object.prismCentralSizes | where {$_.pcvmformfactor -eq "large"}
    sleep 1
    if (!$sizeL.diskSizeInGib){

      write-log -message "Hmm, yeah sideloading does not give me image sizes, let me get the second last one"

      $last2Versions = (Invoke-RestMethod -Uri $queryURL -method "get" -headers $headers -ea:4).entities.version | sort { [Version]$_} | select -last 2 
      $SecondLastVersion = $last2Versions | sort { [Version]$_} | select -first 1
      $Object = (Invoke-RestMethod -Uri $queryURL -method "get" -headers $headers -ea:4).entities | where {$_.version -eq $SecondLastVersion}
      $sizeL = $object.prismCentralSizes | where {$_.pcvmformfactor -eq "large"}
      sleep 1
      if (!$sizeL.diskSizeInGib){

        write-log -message "This should work. $sizeL"

      } else {

        write-log -message "This will not work, we cannot build a dynamic PC size JSON Without PC Sizing."

      }

    }

    $disksizebytes = $sizeL.diskSizeInGib * 1024 * 1024 * 1024
    $memorysizebytes = $sizeL.memorySizeInGib * 1024 * 1024 * 1024

    write-log -message "Deploying Large PC"
    write-log -message "Using Memory Bytes: $memorysizebytes"
    write-log -message "Using Disk Bytes: $disksizebytes"
    write-log -message "Using $($sizeL.vcpus) vCPUs"

    write-log -message "Gathering Storage UUID"
    write-log -message "Searching containers matching $DisksContainerName"

    try {
      $StorageContainer = (Invoke-RestMethod -Uri $containerURL -method "get" -headers $headers -ea:4).entities | where {$_.name -eq $DisksContainerName}
      write-log -message "Storage UUID is $($StorageContainer.storage_container_uuid)"
    } catch {$error.clear();
      write-log -message "We Could not query Px to retrieve existing storage containers" -sev "ERROR";
    };

    write-log -message "Gathering Network UUID"

    try {
      $Network = (Invoke-RestMethod -Uri $networksURL -method "get" -headers $headers -ea:4).entities | where {$_.name -eq "$($NetworkName)"}

      if (!$network){
  
        write-log -message "This is not a blanc cluster, someone did not read the ffing manual." -sev "ERROR"
  
      } 

      write-log -message "Network UUID is $($Network.uuid)"

    } catch {$error.clear();

      write-log -message "We Could not query Px to retrieve existing networks" -sev "ERROR";

    };
    if ($pcmode -ne 1){
      $PCJSON = @"
{
  "resources": {
    "should_auto_register":false,
    "version":"$($Version)",
    "virtual_ip":"$($PCClusterIP)",
    "pc_vm_list":[{
      "data_disk_size_bytes":$disksizebytes,
      "nic_list":[{
        "network_configuration":{
          "subnet_mask":"$($InfraSubnetmask)",
          "network_uuid":"$($Network.uuid)",
          "default_gateway":"$($InfraGateway)"
        },
        "ip_list":["$($PC1_IP)"]
      }],
      "dns_server_ip_list":["$DNSServer"],
      "container_uuid":"$($StorageContainer.storage_container_uuid)",
      "num_sockets":$($sizeL.vcpus),
      "memory_size_bytes":$memorysizebytes,
      "vm_name":"$($PC1_Name)"
    },
    {
      "data_disk_size_bytes":$disksizebytes,
      "nic_list":[{
        "network_configuration":{
          "subnet_mask":"$($InfraSubnetmask)",
          "network_uuid":"$($Network.uuid)",
          "default_gateway":"$($InfraGateway)"
        },
        "ip_list":["$($PC2_IP)"]
      }],
      "dns_server_ip_list":["$($DNSServer)"],
      "container_uuid":"$($StorageContainer.storage_container_uuid)",
      "num_sockets":$($sizeL.vcpus),
      "memory_size_bytes":$memorysizebytes,
      "vm_name":"$($PC2_Name)"
    },
    {
      "data_disk_size_bytes":$disksizebytes,
      "nic_list":[{
        "network_configuration":{
          "subnet_mask":"$($InfraSubnetmask)",
          "network_uuid":"$($Network.uuid)",
          "default_gateway":"$($InfraGateway)"
        },
        "ip_list":["$($PC3_IP)"]
      }],
      "dns_server_ip_list":["$($DNSServer)"],
      "container_uuid":"$($StorageContainer.storage_container_uuid)",
      "num_sockets":$($sizeL.vcpus),
      "memory_size_bytes":$memorysizebytes,
      "vm_name":"$($PC3_Name)"
    }]    
  }
}
"@
    } else {
      $PCJSON = @"
{
  "resources": {
    "should_auto_register":false,
    "version":"$($Version)",
    "pc_vm_list":[{
      "data_disk_size_bytes":$disksizebytes,
      "nic_list":[{
        "network_configuration":{
          "subnet_mask":"$($InfraSubnetmask)",
          "network_uuid":"$($Network.uuid)",
          "default_gateway":"$($InfraGateway)"
        },
        "ip_list":["$($PCClusterIP)"]
      }],
      "dns_server_ip_list":["$DNSServer"],
      "container_uuid":"$($StorageContainer.storage_container_uuid)",
      "num_sockets":$($sizeL.vcpus),
      "memory_size_bytes":$memorysizebytes,
      "vm_name":"$($PC1_Name)"
    }]   
  }
}
"@  }

    write-log -message "Installing Prism Central"

    try { 
      $task = Invoke-RestMethod -Uri $installURL -method "Post" -headers $headers -ea:4 -body $PCJSON -ContentType 'application/json'
      $taskid = $task.task_uuid
      if ($debug -ge 1){
        $task 
        write-host $PCJSON
      }
    } catch {$error.clear()
      
      write-log -message "Failure installing Prism Central, retry $PCinstallcount out of 5" -sev "WARN"
      sleep 60
      if ($debug -ge 1){
        $task 
        write-host $PCJSON
        $task = Invoke-RestMethod -Uri $installURL -method "Post" -headers $headers -body $PCJSON -ContentType 'application/json'
      
      }
    }
  } Until ($taskid -match "[0-9]" -or $PCinstallcount -eq 5)
  if ($taskid -match "[0-9]"){
    $status = "Success"

    write-log -message "Prism Central is installing in $PCmode node mode, we are done."

  } else {
    $status = "Failed"
    write-log -message "Failure installing Prism Central after 5 tries" -sev "ERROR"
  }
  $resultobject =@{
    Result = $status
    TaskID = $taskid
  }
  return $resultobject
};

Function REST-Px-LogonBanner-Config {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name,  
    [string] $Mode,
    [string] $windowsdomain
  )

  
  write-log -message "Building Credential object"
  $count = 0 
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building JSON Array" 

  [array]$JSONA += @"
{"type":"custom_login_screen","key":"color_in","value":"#FFF333"}
"@
  [array]$JSONA += @"
{"type":"custom_login_screen","key":"color_out","value":"#3358FF"}
"@
  if ($mode -eq "PC"){
    [array]$JSONA += @"
{"type":"custom_login_screen","key":"title","value":"Use UPN based $windowsdomain credentails"}
"@
    [array]$JSONA += @"
{"type":"custom_login_screen","key":"product_title","value":"Self - Service - $($Calmvars.system.customername)"}
"@
  } else {
    [array]$JSONA += @"
{"type":"custom_login_screen","key":"product_title","value":"PE - $($Calmvars.system.customername)"}
"@
    [array]$JSONA += @"
{"type":"custom_login_screen","key":"title","value":"Site $Name, use UPN based $windowsdomain credentails"}
"@    
  }
  [array]$JSONA += @"
{"type":"UI_CONFIG","username":"system_data","key":"disable_2048","value":true}
"@
  [array]$JSONA += @"
{"type":"UI_CONFIG","key":"autoLogoutGlobal","value":900000}
"@
  [array]$JSONA += @"
{"type":"UI_CONFIG","key":"welcome_banner","value":"Site $Name"}
"@
  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/application/system_data"
  
  write-log -message "Importing $($JSONA.count) JSONs"

  foreach ($json in $JSONA){
    try {
      Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers -ea:4 
      sleep 2
    } catch {$error.clear();
      Invoke-RestMethod -Uri $URL -method "PUT" -body $json -ContentType 'application/json' -headers $headers -ea:4 
      write-log -message "JSON Already Applied, updating"

    }
  };
  ## Some error out, ignoring
  $resultobject =@{
    Result = "Success"

  }
  return $resultobject
};

Function REST-Set-VM-Power-State {
  Param (
    [string] $VMuuid,
    [string] $State,
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Sending Power State '$State' to '$VMuuid'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMuuid)/set_power_state"

  $Json = @"
{"transition":"$($State)"}
"@ 
  try {

    $task1 = Invoke-RestMethod -Uri $URL -method "POST" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
    sleep 5

  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 60
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $JSON -ContentType 'application/json' -headers $headers

  }
  return $task 
} 

Function REST-Set-VM-Description {
  Param (
    [Object] $VMDetail,
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Description
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Setting VM Description on '$($VMDetail.name)'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMDetail.uuid)"

  $Json = @"
{
  "name": "$($VMDetail.name)",
  "description": "$($Description)"
}
"@ 
 try {

    $task1 = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;

  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 60
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers

  }
  return $task 
} 

Function REST-Set-VM-Secure-Boot {
  Param (
    [Object] $VMDetail,
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Adding secure boot for '$($VMDetail.name)'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMDetail.uuid)"

  $Json = @"
{
  "name": "$($VMDetail.name)",
  "boot": {
    "uefi_boot": true,
    "secure_boot": true
  },
  "vm_features": {
    "FLASH_MODE": false,
    "AGENT_VM": false
  },
  "machine_type": "q35"
}
"@ 
 try {

    $task1 = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;

  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 60
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers

  }
  return $task 
} 

Function REST-Add-VM-RAM-PRX {
  Param (
    [Object] $VMDetail,
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $CLUUID,
    [int] $GBRAM
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Setting '$($VMDetail.name)' to '$($GBRAM)' GB Ram"
  [int]$MBRam = $GBram * 1024

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMDetail.uuid)?proxyClusterUuid=$($CLUUID)"
  write-log -message "using URL $url"
  $Json = @"
{
  "memory_mb": $($MBRam)
}
"@ 
 try {
    $task1 = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;

  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 5
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers

  }
  return $task 
} 


Function REST-Get-VM-Detail-PRX {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $VMUUID,
    [string] $CLUUID
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }


  write-log -message "Executing VM Detail Query using VM UUID '$VMUUID'"
  write-log -message "Located on Cluster UUID '$CLUUID'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMUUID)?include_vm_disk_config=true&include_vm_nic_config=true&includeVMDiskSizes=true&includeAddressAssignments=true&proxyClusterUuid=$CLUUID"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }
  write-log -message "We found a VM called '$($task.name)'"

  Return $task
} 

Function REST-Get-VM-Detail {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $UUID
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }


  write-log -message "Executing VM Detail Query using VM "

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($uuid)?include_vm_disk_config=true&include_vm_nic_config=true&includeVMDiskSizes=true&includeAddressAssignments=true"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }
  write-log -message "We found a VM called '$($task.name)'"

  Return $task
} 

Function REST-Unmount-CDRom {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $UUID,
    [object] $CDROM
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Unmounting CD in VM with ID '$uuid'"
  write-log -message "Unmounting CD ID '$($cdrom.disk_address.device_uuid)'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($uuid)/disks/update"

$Payload= @"
{
  "vm_disks": [{
    "disk_address": {
      "vmdisk_uuid": "$($cdrom.disk_address.device_uuid)",
      "device_index": $($cdrom.disk_address.device_index),
      "device_bus": "$($cdrom.disk_address.device_bus)"
    },
    "flash_mode_enabled": false,
    "is_cdrom": true,
    "is_empty": true
  }]
}
"@ 
  if ($debug -ge 2){
    write $Payload | out-file "c:\temp\unmount.json"
  }
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    #$task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 



Function REST-VM-Change-Disk-Size {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [Object] $VMDetail,
    [INT]    $SizeGB,
    [INT]    $SCSIID
  )
  [array]$vmdisks = $VMDetail.vm_disk_info | where {$_.is_cdrom -eq $false}
  write-log -message "Building a DiskObject"
  $vm_disks = New-Object PSObject
  $vm_disks | add-member Noteproperty vm_disks $vmdisks -force

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  ## We expect the VM Detail object here
  write-log -message "Setting '$($SizeGB)' GB Disk to VM '$($VMDetail.uuid)'"
  

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMDetail.uuid)/disks/update"

  [decimal] $Oldsize = ($vm_disks.vm_disks | where {$_.disk_address.device_index -eq 0}).size
  [decimal] $Newsize = ((($sizeGB * 1024) * 1024 ) * 1024 )

  if ($Oldsize -ge $Newsize){

    Write-log -message "This Function can only increase, old size is '$Oldsize' bites"
    Write-log -message "Requested size is '$Newsize' bites" -sev "warn"
    
  } else {

    Write-log -message "This VM has '$($vm_disks.vm_disks.count)' disk"
    Write-log -message "Setting new disk size on VM '$($vmdetail.name)'"
    Write-log -message "Changing old size '$($Oldsize)' Bites"
    Write-log -message "Into new size '$($Newsize)' Bites"

    $vm_disks.vm_disks | % {

      $vm_disk_create = New-Object PSObject
      $vm_disk_create | add-member Noteproperty storage_container_uuid $_.storage_container_uuid
      if ($SCSIID -eq $_.disk_address.device_index -and $_.disk_address.device_bus -match "scsi"){
         $vm_disk_create | add-member Noteproperty size $Newsize

         write-log -message "Updating SCSI index '$($SCSIID)'"

      } else {
         $vm_disk_create | add-member Noteproperty size $Oldsize
      }
     
      $_ | add-member Noteproperty vm_disk_create $vm_disk_create -force
  
      $_.psobject.members.Remove("source_disk_address")
      $_.psobject.members.Remove("storage_container_uuid")
      $_.psobject.members.Remove("size")

    }
    Write-log -message "Converting to REST Payload"

    $payload = $vm_disks | convertto-json -depth 100
    $vm_disks | convertto-json -depth 100
    if ($payload -eq $null){

      write-log -message "Captain our payload is empty...."

    }
    try{
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  
      write-log -message "Disk has been Updated" 
  
    } catch {$error.clear()
      sleep 10
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
    }
  } 

  Return $task
} 

Function REST-VM-Add-Disk {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [Object] $VMDetail,
    [INT]    $SizeGB
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  ## We expect the VM Detail object here
  write-log -message "Adding a '$($SizeGB)' GB Disk to VM '$($VMDetail.uuid)'"

  $SizeBytes = ((($sizeGB * 1024) * 1024 ) * 1024 )
  $vmdetail.vm_disk_info | where {$_.disk_address.device_bus -match "scsi" } | % { [array]$iscsi += $_.disk_address.device_index}
  $FreeIndex = [INT]($iscsi | sort | select -last 1 ) + 1 

  write-log -message "Assigning SCSI index '$($FreeIndex)'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMDetail.uuid)/disks/attach"

$Payload= @"
{
  "vm_disks": [{
    "is_cdrom": false,
    "disk_address": {
      "device_bus": "scsi",
      "device_index": $($FreeIndex)
    },
    "vm_disk_create": {
      "storage_container_uuid": "$($vmdetail.vm_disk_info[0].storage_container_uuid)",
      "size": $SizeBytes
    }
  }]
}
"@ 
  if ($debug -ge 2){
    $Payload
  }
  if ($SizeBytes -ne 0){
     try{
       $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
   
       write-log -message "Disk has been added" 
   
     } catch {$error.clear()
       sleep 10
       $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
   
       $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Payload -ContentType 'application/json' -headers $headers
     }
  } else {

    write-log -message "'0' in size..." 

  }
  Return $task
} 

Function REST-VM-Add-Disk-PRX {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [Object] $VMDetail,
    [INT]    $SizeGB,
    [string] $CLUUID
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  ## We expect the VM Detail object here
  write-log -message "Adding a '$($SizeGB)' GB Disk to VM '$($VMDetail.uuid)'"

  $SizeBytes = ((($sizeGB * 1024) * 1024 ) * 1024 )
  $vmdetail.vm_disk_info | where {$_.disk_address.device_bus -match "scsi" } | % { [array]$iscsi += $_.disk_address.device_index}
  $FreeIndex = [INT]($iscsi | sort | select -last 1 ) + 1 

  write-log -message "Assigning SCSI index '$($FreeIndex)'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($VMDetail.uuid)/disks/attach?proxyClusterUuid=$($CLUUID)"

$Payload= @"
{
  "vm_disks": [{
    "is_cdrom": false,
    "disk_address": {
      "device_bus": "scsi",
      "device_index": $($FreeIndex)
    },
    "vm_disk_create": {
      "storage_container_uuid": "$($vmdetail.vm_disk_info[0].storage_container_uuid)",
      "size": $SizeBytes
    }
  }]
}
"@ 
  if ($SizeBytes -ne 0){
     try{
       $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
   
       write-log -message "Disk has been added" 
   
     } catch {$error.clear()
       sleep 10
       $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
   
       $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Payload -ContentType 'application/json' -headers $headers
     }
  } else {

    write-log -message "'0' in size..." 

  }
  Return $task
} 

Function REST-Set-PE-Network{
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $network
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "SET PE Network $($network.name)"
  write-log -message "SET PE Network $($network.uuid)"
  write-log -message "SET PE Network $($network.ip_config.dhcp_options.domain_name_servers)"
  

  $URL = "https://$($PEClusterIP):9440/api/nutanix/v0.8/networks/$($network.uuid)"

  $Payload = $network | convertto-json -depth 100

  if ($debug -ge 2){
    $Payload
  }

  try {
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 



Function REST-Mount-NGT {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $VMUUID
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Mounting NGT in VM $VMUUID"

  $URL1 = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/vms/$($VMUUID)/guest_tools/mount"
  $URL2 = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/vms/$($VMUUID)/guest_tools"

$Payload1 = "{}"


$Payload2= @"
{
  "vmId": "$($VMUUID)",
  "enabled": true,
  "applications": {
    "file_level_restore": true,
    "vss_snapshot": true
  }
}
"@ 

  try{
    write-log -message "Executing Part 1"
  
    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $Payload1 -ContentType 'application/json' -headers $headers -ea:4;
  
    sleep 10
    write-log -message "Executing Part 2"
    $task = Invoke-RestMethod -Uri $URL2 -method "post" -body $Payload2 -ContentType 'application/json' -headers $headers

    write-log -message "Guest Tools Mounted" 

  } catch {$error.clear()
    sleep 10
    #$FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    write-log -message "Executing Part 1"
    try {
      $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $Payload1 -ContentType 'application/json' -headers $headers -ea:4;
    } catch {$error.clear()}
    sleep 10
    write-log -message "Executing Part 2"
    $task = Invoke-RestMethod -Uri $URL2 -method "post" -body $Payload2 -ContentType 'application/json' -headers $headers

    write-log -message "Guest Tools Mounted" 
  }

  Return $task
} 


Function REST-LCM-Get-Upgrade-Status {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM Prescan, version: '$URL'"

  $URL1 = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start = '{"value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"is_lcm_operation_in_progress\"}}"}'

  
  [string]$json = $start 
  
  write-log -message "Using JSON $json"

  try{
    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 




Function REST-LCM-Configure-DarkSite-Proxy-Stage1 {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $URL
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM Prescan, version: '$URL'"

  $URL1 = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start = '{"value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"configure\",\"args\":[\"'

  $End = '\",true]}}"}'
  
  [string]$json = $start + $URL + $end
  
  write-log -message "Using JSON $json"

  try{
    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-LCM-Configure-DarkSite-Proxy-Stage2 {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $URL
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM Prescan, version: '$URL'"

  $URL1 = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start = '{"value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"configure\",\"args\":[\"'

  $End = '\",true,\"03:00\",null,null,null,null,true,false]}}"}'
  
  [string]$json = $start + $URL + $end
  
  write-log -message "Using JSON $json"

  try{
    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL1 -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-AOS-PreUpgradeTest {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    $AOSVer
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM Prescan, version: $AOSVer"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start = '{"value":"{\".oid\":\"ClusterManager\",\".method\":\"cluster_upgrade\",\".kwargs\":{\"nos_version\":\"'

  $End = '\",\"manual_upgrade\":false,\"ignore_preupgrade_tests\":false,\"skip_upgrade\":true}}"}'
  
  [string]$json = $start + $AOSVer + $end
  
  write-log -message "Using JSON $json"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-AOS-Reboot {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [array]  $CVMs
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing AOS Reboot on '$($CVMs.count)' hosts"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $jsonP1 = '{ "value": "{\".oid\":\"ClusterManager\",\".method\":\"host_rolling_reboot\",\".kwargs\":{\"svm_ips\":[\"'
  Foreach ($ip in $CVMs){
    $JSONP2 += $ip + '\",\"'
  }
  $JSONP3 = $JSONP2.subString(0, $JSONP2.Length -5) 

  $JSONP4 = $jsonP1 + $JSONP3 + '\"]}}"}'
  
  write-log -message "Using JSON $JSONP4"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSONP4 -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSONP4 -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-AHV-InventorySoftware {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Scanning AHV Available Versions"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/upgrade/hypervisor/softwares"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 


Function REST-AHV-Upgrade {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $AHV
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing AHV Upgrade to version $($AHV.version)"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $json = @"
{
"value":"{\".oid\":\"ClusterManager\",\".method\":\"cluster_hypervisor_upgrade\",\".kwargs\":{\"version\":\"$($AHV.version)\",\"manual_upgrade\":false,\"ignore_preupgrade_tests\":false,\"skip_upgrade\":false,\"username\":null,\"password\":null,\"host_ip\":null,\"md5sum\":\"$($AHV.md5Sum)\"}}"
}
"@
  write-log -message "Using JSON $json"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Px-ProgressMonitor {
  
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Getting Progress Monitor Tasks"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/progress_monitors"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4
  } catch {
    write-log -message "Is PE down?, lets wait a little."
    sleep 60
    $error.clear()

  }

  write-log -message "There are '$($task.entities.count)' Tasks"
  [array]$rtasks =  $task.entities | where {$_.status -eq "Running"}
  write-log -message "There are '$($rtasks.count)' Running Tasks"

  Return $task
} 


Function REST-AOS-InventorySoftware {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Scanning AOS Available Versions"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/upgrade/nos/softwares"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 


Function REST-AOS-Upgrade {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $AvailableAOSVersion
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM List Query"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start= '{"value":"{\".oid\":\"ClusterManager\",\".method\":\"cluster_upgrade\",\".kwargs\":{\"nos_version\":\"'

  $End = '\",\"manual_upgrade\":false,\"ignore_preupgrade_tests\":false,\"skip_upgrade\":false}}"}'
  
  [string]$json = $start + $AvailableAOSVersion + $end
  
  write-log -message "Using URL $json" -d 2

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-PC-Delete-Image {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $uuid
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Deleting PC Image '$UUID'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/images/$($UUID)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers
  }

  Return $task
} 

Function REST-Delete-VM {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $vmuuid
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Deleting VM '$vmuuid'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($vmuuid)?delete_snapshots=true"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers
  }

  Return $task
} 

Function REST-Upload-Image {
  Param (
    [string] $ImageURL,
    [string] $ImageName,
    [string] $imageContainerUUID,
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Adding Image '$ImageName'"

  $URL = "https://$($PEClusterIP):9440/api/nutanix/v0.8/images"

  if ($ImageName -match "ISO"){
    $type = "ISO_IMAGE"
  } else {
    $type = "DISK_IMAGE"
  }

  $var = @"
{
  "name": "$($ImageName)",
  "annotation": "$($ImageName)",
  "imageType": "$($type)",
  "imageImportSpec": {
    "containerUuid": "$($imageContainerUUID)",
    "url": "$($ImageURL)"
  }
}
"@


  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $var -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $var -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Wait-ImageUpload {
  param (
    [string] $imagename,
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $maxloops = 8000
  $images = REST-Query-Images -PxClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser -silent 1
  $imageobj = $images.entities | where {$_.spec.name -eq $imagename }
  if (!$imageobj){

    write-log -message "Image is not there yet, checking image tasks."
    write-log -message "This is the image wait module, so guess what, where waiting..."
    write-log -message "Checking every 15sec, max '$maxloops' times"

    $count = 0
    do {
      $count ++
      if ($count % 4 -eq 0){  
        write-log -message "cycle '$count' out of '$maxloops'"
      }
      $images = REST-Query-Images -PxClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser -silent 1
      $imageobj = $images.entities | where {$_.spec.name -eq $imagename }
      $tasks = REST-Get-AOS-LegacyTask -PEClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser
      $uploadstatus = $tasks.entities | where {$_.operation -eq "ImageCreate" -and $_.status -eq "Running" }
      
      if ($uploadstatus.percentagecompleted -ne 100 -and $uploadstatus){
        sleep 10 
        if ($count % 4 -eq 0){
          write-log -message "An image is still being uploaded. '$($uploadstatus.percentagecompleted)' % Status : '$($uploadstatus.status)'"
        }
      } else {

        write-log -message "Job completed"
        write-log -message "Checking if this is me..."

        $images = REST-Query-Images -PxClusterIP $PxClusterIP -PxClusterPass $PxClusterPass -PxClusterUser $PxClusterUser
        $imageobj = $images.entities | where {$_.spec.name -eq $imagename }

        if ($imageobj){

          write-log -message "Image is present '$($imageobj.status.name)'"
          write-log -message "Image was granted UUID '$($imageobj.metadata.uuid)'"
        
        } else {

          write-log -message "Thats not it..."
          write-log -message "'$imagename' is not present and there are no running upload tasks, this is a temp thing."
          
          sleep 30

        }
      }
    } until ($imageobj -or $count -ge $maxloops )

  } else {

    write-log -message "Image Objects Loving it.. '$($imageobj.status.name)'"
    write-log -message "Image was granted UUID '$($imageobj.metadata.uuid)'"
    write-log -message "Here we go!!"

  }
  $resultobject =@{
    Result = $imageobj.metadata.uuid
  };
  return $resultobject
};


Function REST-Get-Image-Sizes {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $silent =0
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  if ($silent -ne 1){

    write-log -message "Executing Images List Query With Size"

  }
  $URL = "https://$($PxClusterIP):9440/api/nutanix/v0.8/images?includeVmDiskSizes=true"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Function REST-Get-PE-Remote-Sites {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $silent =0
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  if ($silent -ne 1){

    write-log -message "Executing Images List Query With Size"

  }
  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/remote_sites"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
}


Function REST-Get-PRX-Remote-Sites {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ClusterUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Getting PE Remote Sites using PC Proxy, Cluster target '$($ClusterUUID)'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/remote_sites?proxyClusterUuid=$($ClusterUUID)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 


Function REST-Get-PRX-Remote-Site-Detail {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ClusterUUID,
    [string] $sitename
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Getting PE Remote Sites using PC Proxy, Cluster target '$($ClusterUUID)'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/remote_sites/$($sitename)?proxyClusterUuid=$($ClusterUUID)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Function REST-Get-PRX-PD-Snapshots {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ClusterUUID,
    [string] $PDName

  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Getting local snapshots for remote site '$($ClusterUUID)'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/protection_domains/$($PDName)/dr_snapshots?proxyClusterUuid=$($ClusterUUID)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  } catch {$error.clear()
    if ($silent -eq $false){
      sleep 10
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
      $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
    }  
  }

  Return $task
}

Function REST-Update-PRX-Remote-Site {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ClusterUUID,
    [string] $Name,
    [string] $targetIP,
    [string] $BWpolicystart,
    [string] $BWpolicyend,
    [string] $BWcapDay,
    [string] $BWcapNight,
    [object] $NWMap,
    [object] $remotesite

  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating Remote Site through PC Proxy, Cluster target '$($ClusterUUID)'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/remote_sites?proxyClusterUuid=$($ClusterUUID)"


  if ($remotesite.psobject.members.name -contains "stats"){
    $remotesite.psobject.members.Remove("stats")

    write-log -message "Removing Stats"

  } 
  write-log -message "Adding a bandwidthPolicy"

  $BWPolJson = @"
{
  "policyName": "$($Name)_BW_Policy",
  "bandwidthConfigurations": [{
    "startTime": $($BWpolicystart),
    "endTime": $($BWpolicyend),
    "daysSelected": 127,
    "bandwidthLimit": $($BWcapDay)
  }],
  "defaultBandwidthLimit": $($BWcapNight)
}

"@
  
  $BPPolObject = $BWPolJson | convertfrom-json 
  $remotesite.psobject.members.Remove("bandwidthPolicy")
  $remotesite | add-member bandwidthPolicy $BPPolObject
  $remotesite.bandwidthPolicyEnabled = $true
  write-log -message "Mapping DataStores"

  $vstoreNameMap =  New-Object PSObject
  $vstoreNameMap | add-member Noteproperty SelfServiceContainer "SelfServiceContainer"
  $remotesite.vstoreNameMap = $vstoreNameMap

  [array]$NWMapObjects = $null

  write-log -message "Looping through Mappings"

  foreach ($Mapping in $NWMap){
    $NWMapJson = @{
      srcHypervisorType   = "kKvm"
      srcNetworkName      = "$($Mapping.Source)"
      destHypervisorType  = "kKvm"
      destNetworkName     = "$($Mapping.Target)"
    }
    [Array]$NWMapObjects += $NWMapJson 
  }

  $networkMapping = @{
    UUID              = $null
    l2NetworkMappings = $NWMapObjects
  }

  write-log -message "We have '$($NWMapObjects.count)' Network mappings to add"

  $remotesite.networkMapping = $networkMapping

  $Json = $remotesite | ConvertTo-Json -depth 100
  $json | out-file c:\temp\debugsite.json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers
  } catch {$error.clear()
    if ($silent -eq $false){
      sleep 10
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Json -ContentType 'application/json' -headers $headers
    }  
  }

  Return $task
}

Function REST-PE-Protection-Domain-Create {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating Protection Domain"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/protection_domains"

  $Payload= @"
{
  "value": "$($Name)"
}
"@
  if ($debug -ge 2){
    write $url
    write $payload
  }
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers
  }
  Return $task
} 



Function REST-PE-Protection-Domain-AddVMs {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name,
    [array]  $VMUUIDs,
    [string] $ACG = "false"
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Adding Protection Domain Entities"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/protection_domains/$($Name)/add_entities"

  $Payload= @"
{
  "vmAddRemoveType": "LISTED_VMS",
  "protectionDomainName": "$($Name)",
  "vmIds": "",
  "volumeGroupUuids": [],
  "appConsistentSnapshots": $($ACG),
  "protectRelatedEntities": true
}
"@
  $object = $Payload | convertfrom-json
  [array]$object.vmIds += $VMUUIDs
  [array]$object.vmIds = $object.vmIds | Where-Object {$_}
 
  $finalPayload = $object | convertto-json -depth 100
  if ($debug -ge 2){
    write $finalPayload | out-file c:\temp\PD.json
  }
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $finalPayload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $finalPayload -ContentType 'application/json' -headers $headers
  }
  Return $task
} 

Function REST-Get-PE-Protection-Domains {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  # Silent Module
  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/protection_domains"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "get"  -headers $headers -ea:4;
  }

  Return $task
} 


Function REST-PE-Protection-Domain-AddSchedule {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name,
    [object] $schedule,
    [string] $ACG = "false",
    [string] $IntervalType,
    [int]    $IntervalValue,
    [int]    $LocalSnaps,
    [int]    $RemoteSnaps,
    [String] $RemoteSiteName
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Adding Protection Domain Schedules"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/protection_domains/$($Name)/schedules"

  $date = (get-date).addhours(14)
  $schedulestart = (Get-Date -Date $date -UFormat '%s').Replace((Get-Culture).NumberFormat.NumberDecimalSeparator,'') + "0"

  write-log -message "Replication will start at '$($date)'"
  write-log -message "EPOCH '$schedulestart'"

  if ($RemoteSnaps -gt 0){
    $remote = "{`"$($remotesitename)`":$($RemoteSnaps)}" 
  } else {
    $remote = "{}"
  }

  $Payload= @"
{
  "pdName": "$($Name)",
  "type": "$($IntervalType)",
  "values": null,
  "everyNth": $($IntervalValue),
  "userStartTimeInUsecs": $($schedulestart),
  "startTimesInUsecs": null,
  "endTimeInUsecs": null,
  "timezoneOffset": 7200,
  "retentionPolicy": {
    "localMaxSnapshots": $($LocalSnaps),
    "remoteMaxSnapshots": $($remote)
  },
  "rollupScheduleUuid": null,
  "appConsistent": $($ACG)
}
"@
  if ($debug -ge 2 ){
    write $Payload
    write $URL
  }
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers
  }
  Return $task
} 

Function REST-PE-Protection-Domain-Snapshot-Create {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $PD
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating a PD Snapshot for '$($PD.name)'"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/protection_domains/$($PD.Name)/oob_schedules"
  write-log -message "URL is '$URL'"
  $date = (get-date).addminutes(1).ToUniversalTime()
  $schedulestart = (Get-Date -Date $date -UFormat '%s').Replace((Get-Culture).NumberFormat.NumberDecimalSeparator,'') + "0"
  $remotesite = $PD.remoteSiteNames[0]
  $Payload= @"
{
  "remoteSiteNames": ["$remotesite"],
  "scheduleStartTimeUsecs": $($schedulestart),
  "snapshotRetentionTimeSecs": 172800,
  "appConsistent": false
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers 
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers
  }
  $Payload | out-file c:\temp\test.payload
  Return $task
} 


Function REST-Create-PRX-Remote-Site {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ClusterUUID,
    [string] $Name,
    [string] $targetIP
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating Remote Site through PC Proxy, Cluster target '$($ClusterUUID)'"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/remote_sites?proxyClusterUuid=$($ClusterUUID)"

  $Payload= @"
{
  "name": "$($Name)",
  "vstoreNameMap": {},
  "remoteIpPorts": {
    "$($targetIP)": 2020
  },
  "maxBps": null,
  "proxyEnabled": false,
  "bandwidthPolicy": null,
  "compressionEnabled": true,
  "sshEnabled": false,
  "capabilities": ["BACKUP"],
  "networkMapping": {
    "uuid": null,
    "l2NetworkMappings": []
  }
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Get-PC-Image-Distribution-Policy {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  # Silent Module
  $URL = "https://$($PEClusterIP):9440/api/nutanix/v3/images/placement_policies/list"
  $Payload= @"
{
  "kind":"image_placement_policy",
  "length":500,
  "offset":0
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Get-NCC-HealthCheck-Specs {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  # Silent Module
  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/health_checks"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "get"  -headers $headers -ea:4;
  }

  Return $task
} 

Function REST-Get-NCC-HealthCheck-LastRun {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  # Silent Module
  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/ncc/run_summary?detailedSummary=true"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "get"  -headers $headers -ea:4;
  }

  Return $task
} 

Function REST-NCC-Disable-HealthCheck {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $Check
  )
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/health_checks"

  $Check.enabled = "false"

  $json = $check | ConvertTo-Json -depth 100

  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    if ($silent -eq $false){
      sleep 10
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
      $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers
    }  
  }
  
  Return $task
} 

Function REST-Get-AOS-LegacyTask {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  # Silent Module
  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/progress_monitors"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "get"  -headers $headers -ea:4;
  }

  Return $task
} 


Function REST-LCM-BuildPlan {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [array] $updates
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM List Query"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start= '{"value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"generate_plan\",\"args\":[\"http://download.nutanix.com/lcm/2.0\",['
  $End = ']]}}"}'
  
  foreach ($item in $updates){
    $update = "[\`"$($item.SoftwareUUID)\`",\`"$($item.version)\`"],"
    $start = $start + $update
  }
  $start = $start.Substring(0,$start.Length-1)
  $start = $start + $end
  [string]$json = $start

  write-log -message "Using URL '$URL'"
  write-log -message "Using Payload '$json'"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-LCM-Install {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [array] $updates
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM Install"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $Start= '{"value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"perform_update\",\"args\":[\"http://download.nutanix.com/lcm/2.0\",['
  $End = ']]}}"}'
  
  foreach ($item in $updates){

    write-log -message "Adding Update '$($item.SoftwareUUID)' towards version '$($item.version)'"

    $update = "[\`"$($item.SoftwareUUID)\`",\`"$($item.version)\`"],"
    $start = $start + $update
  }
  $start = $start.Substring(0,$start.Length-1)
  $start = $start + $end
  [string]$json = $start
  write-log -message "Using URL '$json'" -d 2

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
}

Function REST-PC-Get-VMs {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/vms/list"

$Payload= @"
{
  "kind": "vm",
  "offset": 0,
  "length": 9999999
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    sleep 5
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  
  write-log -message "We found '$($task.entities.count)' VMs." -D 2

  Return $task
} 


Function REST-LCMV2-Query-Versions {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $mode,
    [string] $silent
  )
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PxClusterIP):9440/api/nutanix/v3/groups"

$Payload= @"
{
  "entity_type": "lcm_entity_v2",
  "group_member_count": 500,
  "group_member_attributes": [{
    "attribute": "id"
  }, {
    "attribute": "uuid"
  }, {
    "attribute": "entity_model"
  }, {
    "attribute": "version"
  }, {
    "attribute": "location_id"
  }, {
    "attribute": "entity_class"
  }, {
    "attribute": "description"
  }, {
    "attribute": "last_updated_time_usecs"
  }, {
    "attribute": "request_version"
  }, {
    "attribute": "_master_cluster_uuid_"
  }, {
    "attribute": "entity_type"
  }, {
    "attribute": "single_group_uuid"
  }],
  "query_name": "lcm:EntityGroupModel",
  "grouping_attribute": "location_id",
  "filter_criteria": ""
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    if ($silent -eq $false){
      sleep 10
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
    }  
  }
  
  write-log -message "We found '$($task.group_results.entity_results.count)' items." -D 2

  Return $task
} 

Function REST-Diable-PCSearch-Tutorial {
  Param (
    [object] $datagen,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

$Json = @"
{
  "type": "UI_CONFIG",
  "key": "hasViewedSearchTutorial",
  "value": true
}
"@ 
  $URL = "https://$($datagen.PCClusterIP):9440/PrismGateway/services/rest/v1/application/user_data"

  write-log -message "Disabling Search Tutorial"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-LCMV2-Query-Updates {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $mode,
    [string] $silent
  )
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PxClusterIP):9440/api/nutanix/v3/groups"


$Payload= @"
{
  "entity_type": "lcm_available_version_v2",
  "group_member_count": 500,
  "group_member_attributes": [{
    "attribute": "uuid"
  }, {
    "attribute": "entity_uuid"
  }, {
    "attribute": "entity_class"
  }, {
    "attribute": "status"
  }, {
    "attribute": "version"
  }, {
    "attribute": "dependencies"
  }, {
    "attribute": "single_group_uuid"
  }, {
    "attribute": "_master_cluster_uuid_"
  }, {
    "attribute": "order"
  }],
  "query_name": "lcm:VersionModel",
  "filter_criteria": "_master_cluster_uuid_==[no_val]"
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    if ($silent -eq $false){
      sleep 10
      $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
    }  
  }
  write-log -message "We found '$($task.group_results.entity_results.count)' items." -D 2

  Return $task
} 


Function REST-LCM-Query-Groups-Names {
  Param (
    [object] $datagen,
    [object] $datavar,
    [string] $mode
  )
  if ($mode -eq "PC"){
    $class =  "PC"
    $clusterIP = $datagen.PCClusterIP
  }  else {
    $class =  "PE"
    $clusterip = $datavar.PEClusterIP
  }  
  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM List Query"

  $URL = "https://$($clusterip):9440/api/nutanix/v3/groups"

$Payload= @"
{
  "entity_type": "lcm_entity",
  "grouping_attribute": "entity_class",
  "group_member_count": 1000,
  "group_member_attributes": [{
    "attribute": "id"
  }, {
    "attribute": "uuid"
  }, {
    "attribute": "entity_model"
  }, {
    "attribute": "version"
  }, {
    "attribute": "location_id"
  }, {
    "attribute": "entity_class"
  }, {
    "attribute": "description"
  }, {
    "attribute": "last_updated_time_usecs"
  }, {
    "attribute": "request_version"
  }, {
    "attribute": "_master_cluster_uuid_"
  }],
  "query_name": "prism:LCMQueryModel",
  "filter_criteria": "_master_cluster_uuid_==[no_val]"
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  write-log -message "We found '$($task.group_results.entity_results.count)' items."

  Return $task
} 

Function REST-LCM-Query-Groups-Versions {
  Param (
    [object] $datagen,
    [object] $datavar,
    [string] $mode
  )
  if ($mode -eq "PC"){
    $clusterIP = $datagen.PCClusterIP
  }  else {
    $clusterip = $datavar.PEClusterIP
  }  
  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing LCM List Query"

  $URL = "https://$($clusterip):9440/api/nutanix/v3/groups"

$Payload= @"
{
  "entity_type": "lcm_available_version",
  "grouping_attribute": "entity_uuid",
  "group_member_count": 1000,
  "group_member_attributes": [
    {
      "attribute": "uuid"
    },
    {
      "attribute": "entity_uuid"
    },
    {
      "attribute": "entity_class"
    },
    {
      "attribute": "status"
    },
    {
      "attribute": "version"
    },
    {
      "attribute": "dependencies"
    },
    {
      "attribute": "order"
    }
  ]
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  write-log -message "We found '$($task.group_results.entity_results.count)' items."

  Return $task
} 

Function REST-Px-Get-Versions {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
 
  $URL1 = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/version"

  write-log -message "Username is '$PxClusterUser'" -D 2
  write-log -message "Password is '$PxClusterPass'" -D 2
  write-log -message "URL is '$URL1'" -D 2

  try{
    $GetVersion = Invoke-RestMethod -Uri $URL1 -method "get" -headers $headers -ea:4;
   
  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 10
    
    $GetVersion = Invoke-RestMethod -Uri $URL1 -method "get" -headers $headers
   
  }
  Return $GetVersion
}

Function REST-Px-Update-NCC {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $target
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Connecting to $clusterip"
  write-log -message "Mode is $mode"
  write-log -message "SE Name is $($datagen.sename)"
  
  $URL1 = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/version"
  $URL2 = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
  $json = @"
{
    "value":"{\".oid\":\"ClusterManager\",\".method\":\"ncc_upgrade\",\".kwargs\":{\"ncc_version\":\"$($target)\"}}"
}
"@
  try{
    $GetNCCVersion = Invoke-RestMethod -Uri $URL1 -method "get" -headers $headers -ea:4;
    if ($GetNCCVersion.nccVersion -eq $target){

      write-log -message "NCC is already running the latest version $($GetNCCVersion.nccVersion)"

    } else {

      $Upgrade = Invoke-RestMethod -Uri $URL2 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      write-log -message "NCC Upgrade started using payload $json"

    }

  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 10
    
    $GetNCCVersion = Invoke-RestMethod -Uri $URL1 -method "get" -headers $headers -ea:4;
    if ($GetNCCVersion.nccVersion -eq $datagen.nccversion){

      write-log -message "NCC is already running the latest version $($GetNCCVersion.nccVersion)"

    } else {
      $Upgrade = Invoke-RestMethod -Uri $URL2 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      write-log -message "NCC Upgrade started using payload $json"
    }
  }
  Return $Upgrade

} 

Function REST-PC-Download-NCC {
  Param (
    [object] $datavar,
    [object] $datagen,
    [string] $mode
  )
  if ($mode -eq "PC"){
    $clusterIP = $datagen.PCClusterIP
  }  else {
    $clusterip = $datavar.PEClusterIP
  }  
  $credPair = "$($datagen.buildaccount):$($datavar.pepass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Connecting to $clusterip"
  write-log -message "Mode is $mode"
  write-log -message "SE Name is $($datagen.sename)"
  $URL1 = "https://$($clusterip):9440/PrismGateway/services/rest/v1/upgrade/ncc/softwares"
  

  try{

    $Payloads = Invoke-RestMethod -Uri $URL1 -method "get" -headers $headers -ea:4;
    $payload = $payloads.entities | where {$_.version -eq $datagen.nccversion}

    write-log -message "Using Payload $JSON"
    if ($payload.status -eq "Available"){

      write-log -message "I am working here!"

      $payload.compatibleVersions = $null
      $payload.transferType = "Download"
      $payload.status = "QUEUED"
      $payload.psobject.members.remove("minNosVersion")
      $payload.psobject.members.remove("minPCVersion")
      $payload.url = $null
      $URL2 = "https://$($clusterip):9440/PrismGateway/services/rest/v1/upgrade/ncc/softwares/$($datagen.nccversion)/download"
      $JSON = $payload  | convertto-json -depth 100

      write-log -message "Using URL $URL2"

      $Download = Invoke-RestMethod -Uri $URL2 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;

    } elseif ($payload.status -eq "COMPLETED"){
     
      write-log -message "Already done boss."


    } elseif ($payload.status -match "INPROG|queue"){

      write-log -message "Almost there!!"

    } else {
      if ($debug -ge 2){
        $payloads
      }
      $Payloads
      write-log -message "Who am i?"

    }

  } catch {$error.clear()

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 5

    $Payloads = Invoke-RestMethod -Uri $URL1 -method "get" -headers $headers -ea:4;
    $payload = $payloads.entities | where {$_.version -eq $datagen.nccversion}

    write-log -message "Using Payload $JSON"
    if ($payload.status -eq "Available"){

      write-log -message "I am working here!"

      $payload.compatibleVersions = $null
      $payload.transferType = "Download"
      $payload.status = "QUEUED"
      $payload.psobject.members.remove("minNosVersion")
      $payload.psobject.members.remove("minPCVersion")
      $payload.url = $null
      $URL2 = "https://$($clusterip):9440/PrismGateway/services/rest/v1/upgrade/ncc/softwares/$($datagen.nccversion)/download"
      $JSON = $payload  | convertto-json -depth 100
      $Download = Invoke-RestMethod -Uri $URL2 -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;

    } elseif ($payload.status -eq "COMPLETED"){
     
      write-log -message "Already done boss."

    } elseif ($payload.status -match "INPROG|queue"){

      write-log -message "Almost there!!"

    } else {
      if ($debug -ge 2){
        $payload.status
      }
      write-log -message "Who am i?"

    }

  }
  Return $payload
}

Function REST-LCM-Update-Engine{
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Connecting to '$PxClusterIP'"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
  $json1 = @"
{
  "value": "{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"configure\",\"args\":[\"http://download.nutanix.com/lcm/2.0\",true,\"03:00\",null,null,null,null,false,true]}}"
}
"@

  try{
    $setAutoUpdate = Invoke-RestMethod -Uri $URL -method "post" -body $JSON1 -ContentType 'application/json' -headers $headers -ea:4;
  
  
    write-log -message "Auto Update enabled."
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $setAutoUpdate = Invoke-RestMethod -Uri $URL -method "post" -body $JSON1 -ContentType 'application/json' -headers $headers -ea:4;

  }
  Return $Inventory

} 



Function REST-LCM-Perform-Inventory {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Connecting to '$PxClusterIP'"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"

  $json2 = @"
{
    "value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"perform_inventory\",\"args\":[\"http://download.nutanix.com/lcm/2.0\"]}}"
}
"@
  try{

    $Inventory = Invoke-RestMethod -Uri $URL -method "post" -body $JSON2 -ContentType 'application/json' -headers $headers -ea:4;
  
    write-log -message "Inventory started"
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $Inventory = Invoke-RestMethod -Uri $URL -method "post" -body $JSON2 -ContentType 'application/json' -headers $headers -ea:4;
  }
  Return $Inventory

} 

Function REST-LCM-Get-Version {
  Param (
    [object] $datavar,
    [object] $datagen,
    [string] $mode
  )
  if ($mode -eq "PC"){
    $clusterIP = $datagen.PCClusterIP
  }  else {
    $clusterip = $datavar.PEClusterIP
  }  
  $credPair = "$($datagen.buildaccount):$($datavar.pepass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Connecting to $clusterip"
  write-log -message "Mode is $mode"
  write-log -message "SE Name is $($datagen.sename)"
  $URL = "https://$($clusterip):9440/PrismGateway/services/rest/v1/genesis"
  $json1 = @"
{
  "value": "{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"get_config\"}}"
}
"@

  try{

    $GetConfig = Invoke-RestMethod -Uri $URL -method "post" -body $JSON1 -ContentType 'application/json' -headers $headers -ea:4;

    write-log -message "Config Retrieved"

  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $GetConfig = Invoke-RestMethod -Uri $URL -method "post" -body $JSON1 -ContentType 'application/json' -headers $headers

  }
  try {
    $trueresult = $GetConfig.value | convertfrom-json -ea:0
    Return $trueresult.".return"
  } catch {$error.clear()
    Return $result
  }
} 

Function REST-Task-List {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  ## This is silent on purpose
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $URL = "https://$($PxClusterIP):9440/api/nutanix/v3/tasks/list"
  $Payload= @{
    kind="task"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try { 
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }
  Return $task
} 


Function REST-Add-DNS-Servers {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [array] $DNSArr
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Adding DNS Servers"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/name_servers/add_list"

  $json = $DNSArr | convertto-json

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Remove-DNS-Servers {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [array] $DNSArr
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Removing DNS Servers"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/name_servers/remove_list"

  if ($DNSArr.count -eq 1){
    $json = '["'+$DNSArr+'"]'
  } else {
    $json = $DNSArr | convertto-json
  }

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  }

  Return $task
} 


Function REST-Get-DNS-Servers {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing DNS List Query"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/name_servers"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
}



Function REST-Query-ADGroup {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $uuid
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building UserGroup Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/user_groups/$($uuid)"

  try {
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }

  Return $task
} 

Function REST-Query-Subnet {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $networkname
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Subnet Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/subnets/list"
  $Payload= @{
    kind="subnet"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json

  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;  
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
    
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }
  if ($task.entities.count -eq 0){

    write-log -message "0? Let me try that again after a small nap."

    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting Subnets, current items found is $($task.entities.count)"
    } until ($count -ge 10 -or $task.entities.count -ge 1)
  }
  write-log -message "We found '$($task.entities.count)' items."
  $result = $task.entities | where {$_.spec.name -eq $networkname}
  Return $result
} 

Function REST-Get-UserGroup {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  write-log -message "Building UserGroup Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/user_groups/list"
  $json = @"
{
  "kind": "user_group",
  "offset": 0,
  "length": 99
}
"@
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers -ea:4
  }catch{
    $error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers
  }
  Return $task
} 



Function REST-Create-UserGroup {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $groupdn,
    [string] $groupname
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building UserGroup Create for group '$groupname'"
  write-log -message "API Query to create a group object for DN: '$($groupdn)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/user_groups"
  $json = @"
{
  "spec": {
    "resources": {
      "directory_service_user_group": {
        "distinguished_name":"$($groupdn)"
      }
    }
  },
  "api_version": "3.1.0",
  "metadata": {
    "kind": "user_group",
    "categories": {},
    "name": "$($groupname)"
  }
}
"@
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers -ea:4
  }catch{
    $error.clear()
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers
  }
  Return $task
} 

Function REST-Create-AdninGroup {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $customer,
    [string] $domainname,
    [string] $grouptype
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $domainparts = $domainname.split(".")
  write-log -message "Building UserGroup Create JSON"
  write-log -message "Using DN CN=Domain Admins,CN=Users,DC=$($($DomainParts)[0]),DC=$($($DomainParts)[1]),DC=$($($DomainParts)[2])"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/user_groups"
  $json = @"
{
  "spec": {
    "resources": {
      "directory_service_user_group": {
        "distinguished_name":"CN=Domain Admins,CN=Users,DC=$($($DomainParts)[0]),DC=$($($DomainParts)[1]),DC=$($($DomainParts)[2])"
      }
    }
  },
  "api_version": "3.1.0",
  "metadata": {
    "kind": "user_group",
    "categories": {},
    "name": "Default-$($grouptype)"
  }
}
"@
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers -ea:4;
  }catch{

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $json -ContentType 'application/json' -headers $headers
  }
  Return $task
} 

Function REST-Query-PE-Cluster-Detail {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $clusterUUID
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/clusters/$clusterUUID"

  write-log -message "Executing PE Cluster Query, using URL '$URL'"

  try{
    [array]$task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4 
  } catch {$error.clear()
    sleep 10
    [array]$task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  write-log -message "We found '$($task.count)' clusters"

  Return $task
} 


Function REST-Query-PE-Clusters {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing PE Cluster Query"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/clusters"

  try{
    [array]$task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    [array]$task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  write-log -message "We found '$($task.count)' clusters"

  Return $task
} 

Function REST-Update-PE-DataServices-IP {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $dataip,
    [object] $Cluster,
    [string] $loggingdir
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/cluster"

  write-log -message "Inserting '$dataip' IP into Cluster '$($Cluster.uuid)' object."

  $payload = @"
{
  "clusterUuid": "$($Cluster.uuid)",
  "genericDTO": {
    "clusterExternalDataServicesIPAddress": "$($dataip)"
  },
  "operation": "EDIT"
}
"@

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PATCH" -body $payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "PATCH" -body $payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Query-PC-Clusters {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Cluster Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/clusters/list"
  $Payload= @{
    kind="cluster"
    offset=0
    length=99999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  if ($task.entities.count -eq 0){
    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting Clusters, current items found is '$($task.entities.count)'"
    } until ($count -ge 10 -or $task.entities.count -ge 1)
  }
  write-log -message "We found '$($task.entities.count)' clusters"

  Return $task
} 

Function REST-Query-DetailCluster {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $uuid
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Cluster Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/clusters/$($uuid)"
  try {
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 




Function REST-GET-PC-Install-State {
  Param (
    [object] $datavar,
    [object] $datagen
  )

  $credPair = "$($datagen.buildaccount):$($datavar.pepass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Checking PC install Status"

  $URL = "https://$($datavar.PEClusterIP):9440/PrismGateway/services/rest/v1/multicluster/cluster_external_state"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;

  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers 
  }
  If ($task.clusterDetails.multicluster -eq $true){

    Return $true

  } else {

    Return $false

  }
} 
Function REST-Px-SMTP-Alerts-Setup {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $SMTPReceiver,
    [string] $SMTPSender,
    [string] $SMTPPort = 25,
    [string] $SMTPServer
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing SMTP Setup"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/alerts/configuration"

  write-log -message "Using URL $URL"

$Payload= @"
{
  "emailContactList": ["$($SMTPReceiver)"],
  "enable": false,
  "enableDefaultNutanixEmail": false,
  "enableEmailDigest": true,
  "skipEmptyAlertEmailDigest": true,
  "defaultNutanixEmail": "nos-alerts@nutanix.com",
  "smtpServer": {
    "address": "$($SMTPServer)",
    "port": $($SMTPPort),
    "username": null,
    "password": null,
    "secureMode": "NONE",
    "fromEmailAddress": "$($SMTPSender)",
    "emailStatus": {
      "status": "UNKNOWN",
      "message": null
    }
  },
  "tunnelDetails": {
    "httpProxy": null,
    "serviceCenter": null,
    "connectionStatus": {
      "lastCheckedTimeStampUsecs": 0,
      "status": "DISABLED",
      "message": {
        "message": ""
      }
    },
    "transportStatus": {
      "status": "UNKNOWN",
      "message": null
    }
  },
  "emailConfigRules": null,
  "emailTemplate": {
    "subjectPrefix": null,
    "bodySuffix": null
  }
}
"@ 

  if ($debug -ge 2){
    write $payload
  }
  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-Px-SMTP-Setup {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $SMTPSender,
    [string] $SMTPPort = 25,
    [string] $SMTPServer
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing SMTP Setup"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/smtp"

  write-log -message "Using URL $URL"

$Payload= @"
{
  "address": "$($SMTPServer)",
  "port": "$($SMTPPort)",
  "username": null,
  "password": null,
  "secureMode": "NONE",
  "fromEmailAddress": "$($SMTPSender)",
  "emailStatus": null
}
"@ 

  if ($debug -ge 2){
    write $payload
  }
  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 



Function REST-PE-Create-Network {
 Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [bool]   $IPAM,
    [string] $SubnetMask,
    [string] $GateWay,
    [string] $DHCPStart,
    [string] $DHCPEnd,
    [string] $Name,
    [string] $VLanID,
    [string] $Address,
    [String] $DNSServers,
    [string] $Domain
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $prefix = Convert-IpAddressToMaskLength $SubnetMask

  $ipconfig = "$($nw1gateway)/$($prefix)"

  write-log -message "Creating Network '$($Name)' on '$PEClusterIP'"
  write-log -message "VLAN: '$($VLanID)' Prefix: '$Prefix'"

  $URL = "https://$($PEClusterIP):9440/api/nutanix/v0.8/networks"

  if ($IPAM -eq $true){

    write-log -message "Gateway: '$($GateWay)' Address: '$Address'"
    write-log -message "DHCPStart: '$($DHCPStart)' DHCPEnd: '$DHCPEnd'"
    write-log -message "Domain: '$($Domain)' DNS: '$DNSServers'"
    write-log -message "Nutanix IPAM Enabled!"

    $Payload= @"
{
  "name": "$($Name)",
  "vlanId": "$($VLanID)",
  "ipConfig": {
    "dhcpOptions": {
      "domainNameServers": "$($DNSServers)",
      "domainName": "$($Domain)"
    },
    "networkAddress": "$($Address)",
    "prefixLength": "$($Prefix)",
    "defaultGateway": "$($GateWay)",
    "pool": [{
      "range": "$($DHCPStart) $($DHCPEnd)"
    }]
  }
}
"@ 
  } else {

    write-log -message "Nutanix IPAM Disabled!"

    $Payload= @"
{
  "name":"$($Name)",
  "vlanId":"$($VLanID)"
}
"@ 
  }

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-Px-Run-Full-NCC {
 Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing NCC on '$PxClusterIP'"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/ncc/checks"
  $Payload= @"
{
  "sendEmail":false
}
"@ 
  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-Px-Query-Alerts {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Alert Query"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/groups"

$Payload= @"
{
  "entity_type": "alert",
  "query_name": "$($(new-guid).guid)",
  "grouping_attribute": "",
  "group_count": 3,
  "group_offset": 0,
  "group_attributes": [],
  "group_member_count": 50,
  "group_member_offset": 0,
  "group_member_attributes": [{
    "attribute": "alert_title"
  }, {
    "attribute": "affected_entities"
  }, {
    "attribute": "impact_type"
  }, {
    "attribute": "severity"
  }, {
    "attribute": "resolved"
  }, {
    "attribute": "acknowledged"
  }, {
    "attribute": "created_time_stamp"
  }, {
    "attribute": "clusterName"
  }, {
    "attribute": "auto_resolved"
  }],
  "filter_criteria": "resolved==false"
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Px-Resolve-Alerts {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $Uuids
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Alert Purge"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/alerts/resolve_list"

  $JSON = [array]$Uuids | convertto-json
  if ($uuids.count -eq 1){
    $json = "[ " + $json + " ]"
  } 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 



Function REST-Get-AuthConfig {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Retrieving AuthConfig"

  $URL   = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Function REST-Get-Objects-AD {
  Param (
    [object] $datagen,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $URL = "https://$($datagen.PCClusterIP):9440/oss/iam_proxy/directory_services"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
}

Function REST-Reset-Px-Password {
  Param (
    [string] $oldPassword,
    [string] $NewPassword,
    [string] $Cluster,
    [string] $username
  )

  $credPair = "$($datagen.PEadmin):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $netbios = $datagen.Domainname.split(".")[0];
$Json = @"
{
  "oldPassword": "$($oldPassword)",
  "newPassword": "$($datavar.pepass)"
}
"@ 
  $URL = "https://$($datavar.PEClusterIP):9440/PrismGateway/services/rest/v1/utils/change_default_system_password"

  write-log -message "Query Object Services"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Add-AuthConfig {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $DomainName,
    [string] $ldapUser,
    [string] $ldapPass,
    [string] $ldapFQDN,
    [string] $ldapPort = 3268
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $Netbios = $domainname.split(".")[0];

  write-log -message "Configuring AuthConfig with server '$($ldapFQDN)'"
  if ($ldapport -eq "636" -or $ldapport -eq "3269"){
    $ldap = "ldaps"
  } else {
    $ldap = "ldap"
  }


  $json = @"
{
  "name": "$Netbios",
  "domain": "$($DomainName)",
  "directoryUrl": "$($ldap)://$($ldapFQDN):$($ldapPort)",
  "groupSearchType": "RECURSIVE",
  "directoryType": "ACTIVE_DIRECTORY",
  "connectionType": "LDAP",
  "serviceAccountUsername": "$($Netbios)\\$($ldapUser)",
  "serviceAccountPassword": "$($ldapPass)"
}
"@
  
  $URL   = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    write $json
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Remove-AuthConfig {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Removing AuthConfig $name"

  
  $URL   = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$name"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "DELETE"  -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    write $json
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "DELETE"  -headers $headers
  }

  Return $task
} 


Function REST-Add-RoleMapping {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $domainname,
    [string] $GroupName
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $netbios = $domainname.split(".")[0];  

  write-log -message "Adding RoleMapptings"

  $json = @"
{
  "directoryName": "$netbios",
  "role": "ROLE_CLUSTER_ADMIN",
  "entityType": "GROUP",
  "entityValues": ["$($GroupName)"]
}
"@

  $URL   = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$($netbios)/role_mappings?&entityType=GROUP&role=ROLE_CLUSTER_ADMIN"


  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Get-RoleMapping {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $domainname
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $netbios = $domainname.split(".")[0]; 

  write-log -message "Getting RoleMapptings set on Domain: $netbios"

  $URL = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$($netbios)/role_mappings"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 


Function REST-ADD-NTP {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ntp
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Adding NTP server '$NTP'"
  $Body = '["'+$NTP+'"]' 

  $URL    = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/ntp_servers/add_list"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Body -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Body -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Remove-NTP {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $ntp
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Removing NTP server '$NTP'"
  $Body = '["'+$NTP+'"]' 

  $URL    = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/ntp_servers/remove_list"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Body -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Body -ContentType 'application/json' -headers $headers -ea:4;
  }

  Return $task
} 


Function REST-List-NTP {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Retrieving NTP servers"

  $URL   = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/ntp_servers"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 



Function REST-Get-VMs {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing VM List"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/vms"
 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }
  write-log -message "We found '$($task.entities.count)' items."

  Return $task
} 

Function REST-Query-Role-List {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $rolename
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Role UUID list"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/roles/list"
    $Payload= @{
    kind="role"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  write-log -message "We found '$($task.entities.count)' items, filtering."

  $result = $task.entities | where {$_.spec.name -eq $rolename}
  Return $result
} 

Function REST-Query-Role-Object {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $RoleUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Getting Role ID: $RoleUUID"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/roles/$($RoleUUID)"
  try{
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers
  }

  Return $task
} 

Function REST-Create-Role-Object {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $roleName,
    [object] $consumerroleObject,
    [string] $projectUUID,
    [string] $projectName
  )

  write-log -message "This function is not used yet."

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Creating Duplicate $rolename Role"
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/roles"
$json = @"
{
  "spec": {
    "name": "$($roleName) V2",
    "resources": {
      "permission_reference_list": 
      $($consumerroleObject.spec.resources.permission_reference_list |ConvertTo-Json)
    },
    "description": "$($consumerroleObject.spec.description)"
  },
  "api_version": "3.1.0",
  "metadata": {
    "spec_version": 0,
    "kind": "role",
    "project_reference": {
      "kind": "project",
      "name": "$($projectName)",
      "uuid": "$($projectUUID)"
    }
  }
}
"@
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  

  Return $result
} 

Function REST-Query-Image-Detail {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $imageUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  if ($silent -ne 1){

    write-log -message "Executing Images List Query"

  }
  $URL = "https://$($PxClusterIP):9440/api/nutanix/v3/images/$($imageUUID)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 


Function REST-Query-Images {
  Param (
    [string] $PxClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $silent =0
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  if ($silent -ne 1){

    write-log -message "Executing Images List Query"

  }
  $URL = "https://$($PxClusterIP):9440/api/nutanix/v3/images/list"
  $Payload= @{
    kind="image"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    #$task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  }
  if ($task.entities.count -eq 0){

    if ($silent -ne 1){
      write-log -message "0? Let me try that again after a small nap."
 
      do {
        sleep 30
        $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
        
        $count++
        if ($silent -ne 1){
          write-log -message "Cycle '$count' Getting Images types, current items found is '$($task.entities.count)'"
        }
      } until ($count -ge 10 -or $task.entities.count -ge 1)
    }
  }
  if ($silent -ne 1){
    write-log -message "We found '$($task.entities.count)' items."
  }
  Return $task
} 


Function REST-Mount-CDRom-Image {
  Param (
    [object] $datagen,
    [object] $datavar,
    [string] $VMuuid,
    [object] $cdrom,
    [object] $Image
  )

  $clusterip = $datavar.PEClusterIP  
  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Mounting CD in VM with ID $VMuuid"
  write-log -message "Using ISO $($Image.Name)"

  $URL = "https://$($clusterip):9440/PrismGateway/services/rest/v2.0/vms/$($VMuuid)/disks/update"

$Payload= @"
{
  "vm_disks": [{
    "disk_address": {
      "vmdisk_uuid": "$($cdrom.disk_address.vmdisk_uuid)",
      "device_index": $($cdrom.disk_address.device_index),
      "device_bus": "$($cdrom.disk_address.device_bus)"
    },
    "flash_mode_enabled": false,
    "is_cdrom": true,
    "is_empty": false,
    "vm_disk_clone": {
      "disk_address": {
        "vmdisk_uuid": "$($Image.vmDiskId)"
      },
      "minimum_size": "$($Image.vmDiskSize)"
    }
  }]
}
"@
  if ($debug -ge 2){
    $Payload
  }
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;

    write-log -message "CDROM mounted" 

  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 



Function REST-Create-Alert-Policy {
  Param (
    [object] $datagen,
    [object] $group,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Replacing JSON String Variables"
$Json = @"
{
  "auto_resolve": true,
  "created_by": "admin",
  "description": "API Generated for XPlay Demo",
  "enabled": true,
  "error_on_conflict": true,
  "filter": "entity_type==vm;(group_entity_type==abac_category;group_entity_id==$($group.entity_id))",
  "impact_types": [
    "Performance"
  ],
  "last_updated_timestamp_in_usecs": 0,
  "policies_to_override": null,
  "related_policies": null,
  "title": "AppFamily:DevOps - VM CPU Usage",
  "trigger_conditions": [
    {
      "condition": "vm.hypervisor_cpu_usage_ppm=gt=400000",
      "condition_type": "STATIC_THRESHOLD",
      "severity_level": "CRITICAL"
    }
  ],
  "trigger_wait_period_in_secs": 0
}
"@ 

  $URL = "https://$($datagen.PCClusterIP):9440/PrismGateway/services/rest/v2.0/alerts/policies"

  if ($debug -eq 2){
    $Json | out-file "C:\temp\Alert.json"
  }

  write-log -message "Executing Import"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-Query-Groups {
  Param (
    [object] $datagen,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Images List Query"

  $URL = "https://$($datagen.PCClusterIP):9440/api/nutanix/v3/groups"
$Payload= @"
{
  "entity_type": "category",
  "query_name": "eb:data:General-1551028671919",
  "grouping_attribute": "abac_category_key",
  "group_sort_attribute": "name",
  "group_sort_order": "ASCENDING",
  "group_count": 20,
  "group_offset": 0,
  "group_attributes": [{
    "attribute": "name",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "immutable",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "cardinality",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "description",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "total_policy_counts",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "total_entity_counts",
    "ancestor_entity_type": "abac_category_key"
  }],
  "group_member_count": 5,
  "group_member_offset": 0,
  "group_member_sort_attribute": "value",
  "group_member_sort_order": "ASCENDING",
  "group_member_attributes": [{
    "attribute": "name"
  }, {
    "attribute": "value"
  }, {
    "attribute": "entity_counts"
  }, {
    "attribute": "policy_counts"
  }, {
    "attribute": "immutable"
  }]
}
"@ 

  $JSON = $Payload 
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  write-log -message "We found '$($task.group_results.entity_results.count)' items."

  Return $task
} 






Function REST-XPlay-Query-PlayBooks {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing ActionTypes Query"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/action_rules/list"
  $Payload= @{
    kind="action_rule"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  write-log -message "We found '$($task.entities.count)' items."
  if ($task.entities.count -eq 0){

    write-log -message "0? Let me try that again after a small nap."

    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting action types, current items found is $($task.entities.count)"
    } until ($count -ge 10 -or $task.entities.count -ge 1)
  }
  Return $task
} 

Function REST-XPlay-Query-ActionTypes {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing ActionTypes Query"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/action_types/list"
  $Payload= @{
    kind="action_type"
    offset=0
    length=999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  write-log -message "We found '$($task.entities.count)' items."
  if ($task.entities.count -eq 0){

    write-log -message "0? Let me try that again after a small nap."

    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting action types, current items found is $($task.entities.count)"
    } until ($count -ge 10 -or $task.entities.count -ge 1)
  }
  Return $task
} 

Function REST-Query-DetailPlaybook {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $uuid
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Playbook Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/action_rules/$($uuid)"
  try {
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 

Function REST-Query-Directory-PC-Services {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser

  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Directory List JSON"
$Json = @"
  {
    "kind": "directory_service",
    "length": 100
  }
"@ 
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/directory_services/list"
  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;

    write-log -message "Nutanix is the best..."

  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }  
  Return $task
} 


Function REST-Query-Directory-PC-Objects {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $DirSvcUUID,
    [string] $SearchString

  )

  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Directory Search JSON"
$Json = @"
{
  "query": "$($SearchString)",
  "returned_attribute_list": ["memberOf", "member", "userPrincipalName", "distinguishedName"],
  "searched_attribute_list": ["name", "userPrincipalName", "distinguishedName"],
  "is_wildcard_search": true
}
"@ 
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/directory_services/$($DirSvcUUID)/search"

  try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;

    write-log -message "Nutanix is the best..."

  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }  
  Return $task
} 




Function REST-Query-DetailAlertPolicy {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $uuid
  )

  
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Alert Query JSON"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v2.0/alerts/policies/$($uuid)"
  try {
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  }  
  Return $task
} 


Function REST-XPlay-Create-Playbook {
  Param (
    [object] $datagen,
    [object] $AlertTriggerObject,
    [object] $AlertActiontypeObject,
    [object] $AlertTypeObject,
    [object] $BluePrintObject,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $alertActiontype = $AlertActiontypeObject.entities | where {$_.status.resources.display_name -eq "REST API"}
  $BPAppID = $(($BluePrintObject.spec.resources.app_profile_list | where {$_.name -eq "IIS"}).uuid)
  write-log -message "Replacing JSON String Variables"
  write-log -message "Using Action Type $($alertActiontype.metadata.uuid)"
  write-log -message "Using Alert Trigger $($AlertTriggerObject.entity_id)"
  write-log -message "Using Alert Type A$($AlertTypeObject.group_results.entity_results.entity_id)"
  write-log -message "Using Blueprint $($BluePrintObject.metadata.uuid)"
  write-log -message "Using BP App $($BPAppID)"

######## THE A IN ALERT TRIGGER TYPE NEEDS TO BE THERE
$Json = @"
{
  "api_version": "3.1",
  "metadata": {
    "kind": "action_rule",
    "spec_version": 0
  },
  "spec": {
    "resources": {
      "name": "IIS Xplay Demo",
      "description": "IIS Xplay Demo",
      "is_enabled": true,
      "should_validate": true,
      "trigger_list": [
        {
          "action_trigger_type_reference": {
            "kind": "action_trigger_type",
            "uuid": "$($AlertTriggerObject.entity_id)",
            "name": "alert_trigger"
          },
          "input_parameter_values": {
            "alert_uid": "A$($AlertTypeObject.group_results.entity_results.entity_id)",
            "severity": "[\"critical\"]",
            "source_entity_info_list": "[]"
          }
        }
      ],
      "execution_user_reference": {
        "kind": "user",
        "name": "admin",
        "uuid": "00000000-0000-0000-0000-000000000000"
      },
      "action_list": [
        {
          "action_type_reference": {
            "kind": "action_type",
            "uuid": "$($alertActiontype.metadata.uuid)",
            "name": "rest_api_action"
          },
          "display_name": "",
          "input_parameter_values": {
            "username":  "$($datagen.buildaccount)",
            "request_body":  "{\n \"spec\": {\n   \"app_profile_reference\": {\n     \"kind\": \"app_profile\",\n     \"name\": \"IIS\",\n     \"uuid\": \"$($BPAppID)\"\n   },\n   \"runtime_editables\": {\n     \"action_list\": [\n       {\n       }\n     ],\n     \"service_list\": [\n       {\n       }\n     ],\n     \"credential_list\": [\n       {\n       }\n     ],\n     \"substrate_list\": [\n       {\n       }\n     ],\n     \"package_list\": [\n       {\n       }\n     ],\n     \"app_profile\": {\n     },\n     \"task_list\": [\n       {\n       }\n     ],\n     \"variable_list\": [\n       {\n       }\n     ],\n     \"deployment_list\": [\n       {\n       }\n     ]\n   },\n   \"app_name\": \"IIS-{{trigger[0].source_entity_info.uuid}}\"\n }\n}",
            "url":  "https://$($datagen.PCClusterIP):9440/api/nutanix/v3/blueprints/$($BluePrintObject.metadata.uuid)/simple_launch",
            "headers":  "Content-Type: application/json",
            "password":  "$($datavar.PEPass)",
            "method":  "POST"
          },
          "should_continue_on_failure": false,
          "max_retries": 0
        }
      ]
    }
  }
}
"@ 
  $URL = "https://$($datagen.PCClusterIP):9440/api/nutanix/v3/action_rules"
  if ($debug -ge 2){
    $Json | out-file c:\temp\bplaunch.json
  }

  write-log -message "Executing Playbook Create Flert "

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;

    write-log -message "Nutanix is the best..."

  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-XPlay-Query-AlertTriggerType {
  Param (
    [object] $datagen,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Replacing JSON String Variables"
$Json = @"
{
  "entity_type": "trigger_type",
  "group_member_attributes": [
    {
      "attribute": "name"
    },
    {
      "attribute": "display_name"
    }
  ],
  "group_member_count": 20
}
"@ 
  $URL = "https://$($datagen.PCClusterIP):9440/api/nutanix/v3/groups"
  if ($debug -ge 2){
    $Json | out-file c:\temp\bplaunch.json
  }

  write-log -message "Executing Alert Type Query"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }
  if ($task.total_group_count -eq 0){

    write-log -message "0? Let me try that again after a small nap."
    $count = 0
    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting Alert trigger types, current items found is $($task.total_group_count)"
    } until ($count -ge 10 -or $task.total_group_count -ge 1)
  }
  Return $task
} 

Function REST-XPlay-Query-AlertUUID {
  Param (
    [object] $datagen,
    [object] $datavar
  )

  $credPair = "$($datagen.buildaccount):$($datavar.PEPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Alert UUID JSON"
$Json = @"
{
  "entity_type": "alert_check_schema",
  "group_member_attributes": [
    {
      "attribute": "alert_title"
    },
    {
      "attribute": "_modified_timestamp_usecs_"
    },
    {
      "attribute": "alert_uid"
    }
  ],
  "group_member_sort_attribute": "_modified_timestamp_usecs_",
  "group_member_sort_order": "DESCENDING",
  "group_member_count": 100,
  "filter_criteria": "alert_title==AppFamily:DevOps - VM CPU Usage;alert_uid!=[no_val]"
}
"@ 
  $URL = "https://$($datagen.PCClusterIP):9440/api/nutanix/v3/groups"

  write-log -message "Executing Alert UUID Query"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "post" -body $Json -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Get-FT-Health {
  Param (
    [string] $PEClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Health Query"

  $URL = "https://$($PEClusterIP):9440/PrismGateway/services/rest/v1/cluster/domain_fault_tolerance_status"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
    sleep 1
  } catch {$error.clear()
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  Return $task
} 

Export-ModuleMember *
