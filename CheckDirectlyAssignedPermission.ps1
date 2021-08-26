
param (
[Parameter( Mandatory=$true,
                HelpMessage="Your Org Name")]
[string]$OrgURL = 'neiltest',
[Parameter( Mandatory=$true,
                HelpMessage="User email address or group name")]
[string]$UserOrGroupName ,
[Parameter( Mandatory=$true,
                HelpMessage="User email address or group name")] # https://docs.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops
[string]$permissionType = 'Git Repositories',
[Parameter( Mandatory=$true,
                HelpMessage="Your Personal Access Token.")]
[string]$PAT 

)
[Flags()] enum Git_Repositories_Permission {

        # needs the enum value to convert the string to a permission bit.
        Administer = 1
        GenericRead = 2
        GenericContribute = 4
        ForcePush = 8
        CreateBranch = 16
        CreateTag = 32
        ManageNote = 64
        PolicyExempt = 128
        CreateRepository = 256
        DeleteRepository = 512
        RenameRepository = 1024
        EditPolicies = 2048
        RemoveOthersLocks = 4096
        ManagePermissions = 8192
        PullRequestContribute = 16384
        PullRequestBypassPolicy = 32768
}

[Flags()] enum Build_Permission {
        ViewBuilds = 1
        EditBuildQuality = 2
        RetainIndefinitely = 4
        DeleteBuilds = 8
        ManageBuildQualities = 16
        DestroyBuilds = 32
        UpdateBuildInformation = 64
        QueueBuilds = 128
        ManageBuildQueue = 256
        StopBuilds = 512
        ViewBuildDefinition = 1024
        EditBuildDefinition = 2048
        DeleteBuildDefinition = 4096
        OverrideBuildCheckInValidation = 8192
        AdministerBuildPermissions = 16384
}
[Flags()] enum Iteration_Permission {

        GenericRead = 1
        GenericWrite = 2
        CreateChildren = 4
        Delete = 8
}

$UserOrGroupName=$UserOrGroupName.Replace(' ','%20')
$enumname=$permissionType.Replace(' ','_') + '_Permission'
#$PAT = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PAT)
#$PAT = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PAT)
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f 'a', $PAT)))  

#get security namespace id
$RestToGetSN = "https://dev.azure.com/$($OrgURL)/_apis/securitynamespaces/?api-version=6.0"
$nameSpacesID = Invoke-RestMethod -Method Get -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo)} -Uri $RestToGetSN | select -expand value | select namespaceid, name | %{
#echo $_
if ($_.name -eq $($permissionType)){ 
$_.namespaceId
}
}

echo $nameSpacesID


#get descripter of a group/user
$RestToGetDes="https://vssps.dev.azure.com/$($OrgURL)/_apis/identities?searchFilter=General&filterValue=$($UserOrGroupName)&queryMembership=None&api-version=6.0"

$Descriptor = Invoke-RestMethod -Method Get -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo)} -Uri $RestToGetDes | select -expand value | select descriptor, customDisplayName, isactive | %{

$_.descriptor #get descripter of a group/user
}
echo $Descriptor

#get descripter of a ACL
$RestToGetACL="https://dev.azure.com/$($OrgURL)/_apis/accesscontrollists/$($nameSpacesID)?api-version=6.0"


$projectACLs = Invoke-RestMethod -Method Get -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo)} -Uri $RestToGetACL


echo $enumname
echo $projectACLs


$permission = $projectACLs.value | % {
     $project=$_
     #$_.acesDictionary.psobject.properties.value.descriptor
     $_.acesDictionary.psobject.properties.value | %{
       $result=$_
     if ($_.descriptor -eq $Descriptor){
      $result | Add-Member -MemberType NoteProperty  -Name "token(repoV2/PROJECT_ID/REPO_ID)" -Value $($project.token) -Force
      $result | Add-Member -MemberType NoteProperty  -Name "inheritPermissions" -Value $($project.inheritPermissions) -Force
      $result
      echo "allow: " $_.allow
      ([string][convert]::ToString($_.allow,2)).PadLeft(16,'0') 
      Set-Variable 'haspermission2' -Scope script -Value ($_.allow -as ($enumname -as [type]))
      Set-Variable $haspermission2 -Value ($_.allow -as ($enumname -as [type]))
      echo "this user/group has permission on:  $haspermission2"
      
      echo "deny: " $_.deny
      ([string][convert]::ToString($_.deny,2)).PadLeft(16,'0') 
      Set-Variable 'nopermission' -Scope script -Value ($_.deny -as ($enumname -as [type]))
      echo "this user/group doesn't have permission on: $nopermission "
      echo "---------------------------------------------------"
     }
     }

 }



echo $permission
#az devops security permission show --id 33344d9c-fc72-4d6f-aba5-fa317101a7e9 --subject "[SAW]\Readers" --token ff58a5c4-3020-475d-9782-89b5c0a60ead --organization https://dev.azure.com/neilregion/
