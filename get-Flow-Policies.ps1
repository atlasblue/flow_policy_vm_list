  <# 
  ----------------------------------------------------------------------------
  |   Created by Yassine Malki                                               |
  |   Objective: List Flow Security Policies attached to each VM             |
  |   January 2023                                                           |
  ---------------------------------------------------------------------------- 
  #>

#Certificate information to call Nutanix Prism Central API
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Forcing PoSH to use TLS1.2 as it defaults to 1.0 and Prism requires 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Nutanix Prism Central information
$prism = "10.38.15.137"

# Check to see if secure credential file exists. If not, prompts for credentials and creates file.
$CredPath = "C:\SecureString\SecureCredentials.xml"
$CredPathExists = [System.IO.File]::Exists($CredPath)

if ($CredPathExists -eq $false) {
  Get-Credential | EXPORT-CLIXML "$CredPath"
}

# Run at the start of each script to import the credentials
$Credentials = IMPORT-CLIXML "$CredPath"
$RESTAPIUser = $Credentials.UserName
$RESTAPIPassword = $Credentials.GetNetworkCredential().Password

[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)

# REST API Call to Get VMs List
$UriVM = "https://$($prism):9440/api/nutanix/v3/vms/list"

# REST API Call to Get Categories details
$UriCat = "https://$($prism):9440/api/nutanix/v3/category/query"

$Header = @{
"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RESTAPIUser+":"+$RESTAPIPassword ))}

$jsonvm =@"
{
 "kind": "vm",
 "length": 100
}
"@

#API Call to get list of VMs and their assigned categories 
$getvm = Invoke-RestMethod -Method Post -Uri $UriVM -Headers $Header -Body $jsonvm -ContentType "application/json"

#grab the information we need in each entity (VM) and then check if AppType category is applied to the VM
ForEach ($entity in $getvm.entities) 
{
    $cat = $entity.metadata.categories;
    if ($cat -match "AppType")
    {
      $cat -match "AppType=(?<content>.*)}"
      $apptype=$matches['content']
      $jsoncat =@"
{
    "usage_type": "USED_IN",
    "category_filter": {
        "type": "CATEGORIES_MATCH_ANY",
        "params": {
          "AppType": [
            "$apptype"
          ]
        }
      }
    }
"@
      # API Call to get Security Policy (based on the AppType) applied to VM
      $getcat = Invoke-RestMethod -Method Post -Uri $UriCat -Headers $Header -Body $jsoncat -ContentType "application/json"
      $secpolicy = $getcat.results.kind_reference_list.name
    }
    $myvarVmInfo = [ordered]@{
    "name" = $entity.spec.name;
    "power_state" = $entity.spec.resources.power_state;
    "cluster" = $entity.spec.cluster_reference.name;
    "categories" = $entity.metadata.categories;
    "security policy" = $secpolicy
  }
  $myvarResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
}
# Build CSV report
$myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"VmList.csv")


