param (

[Parameter( Mandatory=$true,
                HelpMessage="Your Personal Access Token.")]
[string]$PAT

)


$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f 'a', $PAT)))  #PAT for all accessible orgs

$RestToGetProfile = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0"

$publicAlias=Invoke-WebRequest -Uri $RestToGetProfile -Method GET -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo)} | ConvertFrom-Json | %{ $_.publicAlias } 

echo $publicAlias
$RestToGetOrgs = "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$publicAlias&api-version=6.0"
echo $RestToGetOrgs
Invoke-WebRequest -Uri $RestToGetOrgs -Method GET -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo)} | ConvertFrom-Json | select -expand value | Select accountName
