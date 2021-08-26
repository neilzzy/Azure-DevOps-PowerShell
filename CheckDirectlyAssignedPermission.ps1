
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
#Only support below permissions currently
#will add more later


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

[Flags()] enum AnalyticsViews_Permission {

        Read = 1
        Edit = 2
        Delete = 4
        Execute = 8
        ManagePermissions = 16
}

[Flags()] enum CSS_Permission {

        GENERIC_READ = 1
        GENERIC_WRITE = 2
        CREATE_CHILDREN = 4
        DELETE = 8
        WORK_ITEM_READ = 16
        WORK_ITEM_WRITE = 32
        MANAGE_TEST_PLANS = 64
        MANAGE_TEST_SUITES = 128

}


[Flags()] enum DashboardsPrivileges_Permission {
        Read = 1
        Create = 2
        Edit = 4
        Delete = 8
        ManagePermissions = 16
        MaterializeDashboards = 32

}

[Flags()] enum Iteration_Permission {

        GenericRead = 1
        GenericWrite = 2
        CreateChildren = 4
        Delete = 8
}

[Flags()] enum MetaTask_Permission {

        Administer = 1
        Edit = 2
        Delete = 4
}

[Flags()] enum Plan_Permission {

        View = 1
        Edit = 2
        Delete = 4
        Manage = 8
}

[Flags()] enum ReleaseManagement_Permission {

        ViewReleaseDefinition = 1
        EditReleaseDefinition = 2
        DeleteReleaseDefinition = 4
        ManageReleaseApprovers = 8
        ManageReleases = 16
        ViewReleases = 32
        CreateReleases = 64
        EditReleaseEnvironment = 128
        DeleteReleaseEnvironment = 256
        AdministerReleasePermissions = 512
        DeleteReleases = 1024
        ManageDeployments = 2048
        ManageReleaseSettings = 4096
        ManageTaskHubExtension = 8192

}

[Flags()] enum WorkItemQueryFolders_Permission {

        Read = 1
        Contribute = 2
        Delete = 4
        DELETE = 8
        ManagePermissions = 16
        WORK_ITEM_WRITE = 32
        MANAGE_TEST_PLANS = 64
        MANAGE_TEST_SUITES = 128

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
