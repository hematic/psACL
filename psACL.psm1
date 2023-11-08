Function Remove-FolderRights{
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the path to remove rights from.')]
        [String]$Path,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the user to strip rights for.')]
        [String]$UserOrGroup,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='Optional Logfile')]
        [String]$LogPath
    )
    If($LogPath){
        Add-Content -Path $LogPath -Value "Gathering ACL for $Path"    
    }
    $ACL = Get-ACL $Path
    Foreach($Access in ($Acl.Access | Where-Object {$_.identityreference -like "*$UserOrGroup*"})){
        $acl.RemoveAccessRule($Access)
    }
    $ACL.SetAccessRuleProtection($True, $True)
    (Get-Item $Path).SetAccessControl($acl)
    If($LogPath){
        Add-Content -Path $LogPath -Value "Permissions on $Path removed for $UserOrGroup"
    }
}

Function Add-FolderACL{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the path to set the ACL on.')]
        [String]$Path,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the user or group to modify rights for.')]
        [String]$UserOrGroup,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='These are the inheritance flags to set.')]
        [Validateset("None","Container","Object","Both")]
        [String]$InheritanceFlags,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='These are the propagation flags to set.')]
        [Validateset("None","NoPropagateInherit","InheritOnly")]
        [String]$PropagationFlags,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is allow or deny')]
        [String[]]$Rights,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='These are the propagation flags to set.')]
        [Validateset("Allow","Deny")]
        [String]$AccessControlType,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='Optional Logfile')]
        [String]$LogPath
    )
    If($LogPath){
        Add-Content -Path $LogPath -Value "Gathering ACL for $Path"    
    }
    $ACL = Get-ACL $Path
    switch ($InheritanceFlags) {
        'None'        {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None}
        'Container'   {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit}
        'Object'      {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit}
        'Both'        {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit}
    }
    switch ($PropagationFlags) {
        'None'                  {$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None}
        'NoPropagateInherit'    {$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit}
        'InheritOnly'           {$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly}
    }

    $Rights = [System.Security.AccessControl.FileSystemRights]$Rights
    $objType =[System.Security.AccessControl.AccessControlType]::$AccessControlType
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($UserOrGroup, $Rights, $InheritanceFlag, $PropagationFlag, $Objtype)
    $ACL.AddAccessRule($Rule)
    (Get-Item $Path).SetAccessControl($acl)
    If($LogPath){
        Add-Content -Path $LogPath -Value "Permissions on $Path set for $UserOrGroup"
    }
}