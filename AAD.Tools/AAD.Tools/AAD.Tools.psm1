function Import-ADAL(){
  $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
  $modulePath = $moduleDirPath + "\AADGraph"
  if(-not (Test-Path ($modulePath+"\Nugets"))) {New-Item -Path ($modulePath+"\Nugets") -ItemType "Directory" | out-null}
  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
  if($adalPackageDirectories.Length -eq 0){
    Write-Host "Active Directory Authentication Library Nuget doesn't exist. Downloading now ..." -ForegroundColor Yellow
    if(-not(Test-Path ($modulePath + "\Nugets\nuget.exe")))
    {
      Write-Host "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ..." -ForegroundColor Yellow
      $wc = New-Object System.Net.WebClient
      $wc.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
    }
    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -Version 2.19.208020213 -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression $nugetDownloadExpression
  }
  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
  $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
  $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
  if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0){
    Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
    [System.Reflection.Assembly]::LoadFrom($ADAL_Assembly[0].FullName) | out-null
    [System.Reflection.Assembly]::LoadFrom($ADAL_WindowsForms_Assembly.FullName) | out-null
    return $true
  }
  else{
    Write-Host "Fixing Active Directory Authentication Library package directories ..." -ForegroundColor Yellow
    $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null
    Write-Host "Not able to load ADAL assembly. Delete the Nugets folder under" $modulePath ", restart PowerShell session and try again ..."
    return $false
  }
}


<#
.Synopsis
   Get OpenID Connect Endpoint information for a AAD Tenant Name
.DESCRIPTION
   By retrieving OIDC information for a tenant we can determine if the name is in use, and what tenant ID has the name associated with it.
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-AADTTenantNameInfo
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]
        $TenantName
        
    )

    Begin
    {
        
    }
    Process
    {
        foreach ($name in $TenantName)
        {
            $Tenant = $null
            $TenantGUID=$null
            $TenantRegion=$Null
            $TenantCloudInstanceName=$Null

           $TenantUri = "https://login.microsoftonline.com/$Name/.well-known/openid-configuration."

            try
            {
                $Tenant =  Invoke-WebRequest -Uri $TenantUri|% content|ConvertFrom-Json
                $NameFound=$true

                $TenantGUID = $Tenant.issuer.split("/")[3]
                $TenantRegion = $Tenant.tenant_region_scope
                $TenantCloudInstanceName=$tenant.cloud_instance_name
           }
           catch
           {
                $NameFound=$false
           }
           Finally
           {
           $TenantInfo = [pscustomobject]@{NameCheck=$Name;NameFound=$NameFound;TenantGUID=$TenantGUID;TenantRegion=$TenantRegion;TenantCloudInstanceName=$TenantCloudInstanceName}
           }
           Write-Output $TenantInfo
           
        }

    }
    End
    {
    }
}

<#
.Synopsis
   Get Graph Authorization Token from AAD tenant for User or Client credentials
.DESCRIPTION
   Use "application/json" as content type and load assempblies from import-ADAL
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-AADTGraphAuthToken
{
 [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Azure AD Tenant Name
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
		[alias("TenantName")]
        $AADTenantName,
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
		$Credential,
		[ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("graph.windows.net", "graph.microsoft.com")]
        [string]
        $EndPoint="graph.microsoft.com",
		# Utilize a UserCredential or ClientCredential (Application) to get the authorization token
		[ValidateSet("UserCredential", "ClientCredential")]
		$CredentialType = "UserCredential",
		# Return as Authorization Header for use in REST API Calls
		[switch]
		$asAuthHeader,
		[switch]
		$supportMFA,
		# Setup your Application and Service Principal as per https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azurermps-6.0.0
		[string]
		$ClientId
    )



       [uri]$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
       $resourceAppIdURI = "https://"+$EndPoint
       $authority = "https://login.windows.net/$aadTenantName"
	   $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
	   $promptBehavior = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior
	Write-Verbose "Authority = $authority"

	   $authResult = $null
		switch ($CredentialType)
		{
			"UserCredential"
			{
				if ($null -eq $ClientId)
				{
					Write-Error ("ClientID needed for UserCredential! - See Cmdlet help.")
				}

				if ($supportMFA)
				{
					$Prompt = $promptBehavior.Always
					$authResult = $authContext.AcquireToken($resourceAppIdURI, $clientID, $redirectUri,[Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always)
				}
				else
				{
				     $Prompt = $promptBehavior.Auto
					 $aadCreds = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($credential.GetNetworkCredential().username,$credential.GetNetworkCredential().password)
					 $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientID, $aadCreds)
				}
				
			}

			"ClientCredential"
			{
				$aadCreds = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($credential.GetNetworkCredential().username,$credential.GetNetworkCredential().password)
				$authResult = $authContext.AcquireToken($resourceAppIdURI,$aadCreds)
			}

		}

		
		Write-Verbose "AADCreds = $aadCreds"
	


	   if ($asAuthHeader)
	   {
		Write-Output ($authResult|Get-AADTRestAuthHeader)
	   }
	   else
	   {
			Write-Output $authResult
	   }

}

<#
.Synopsis
   Get a formatted REST header from an AAD Authorization Token
.DESCRIPTION
   Use "application/json" as content type and get SDK pieces from http://aka.ms/webpi-azps
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-AADTRestAuthHeader
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param
    (
        # Auth Token provided by Azure AD for accessing a resource
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $AuthToken
    )

    Begin
    {
    }
    Process
    {
        $authheader = @{'Content-Type'='application\json';'Authorization'=$authToken.CreateAuthorizationHeader()}
        
    }
    End
    {
        return $authHeader
    }
}


<#
.Synopsis
   Retrieve users from AAD Tenant
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-AADTUser
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Credential used for connecting to Graph API
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [PSCredential]
        $Credential,

        # Odata Filter
        [string]
        $Filter,

        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("graph.windows.net", "graph.microsoft.com")]
        [string]
        $EndPoint="graph.microsoft.com",
		$ApiVersion = "beta",
		$TenantID
    )

    Begin
    {
		$GraphHeader = Get-AADTGraphAuthToken -TenantID $TenantID -EndPoint $EndPoint -cr
    }
    Process
    {
	    $selectAttributes = $schema.Types["User"].Attributes.Name -join ','

	$uriUsersSelect = "{0}?select={1}" -f $uriUsers,$selectAttributes



	$cmd = 'Invoke-RestMethod -Method Get -Uri $uriUsersSelect -Headers $AADAuthHeader'
	
	

	$statusMsg = "Invoking $cmd"
	$activityName = $MyInvocation.InvocationName

	Write-Progress -Id 1 -Activity $activityName -Status $statusMsg

	$x = Invoke-Expression $cmd

	$pagedUri = $Null

	if ($x)
	{
		do 
		{
			 
			if ($x.Value -is [array])
			{
				$importReturnInfo.CSEntries.Capacity += $x.Value.Count
			}

			$currentParition = $openImportConnectionRunStep.StepPartition.DN

			Write-Output $x.value

			
			if (Get-Member -inputobject $x -name '@odata.nextlink' -MemberType Properties)
			{
				$pagedUri = $x.'@odata.nextlink'
			
				if ($pagedUri -notlike $Null)
				{
				$cmd = 'Invoke-RestMethod -Method Get -Uri $pagedUri -Headers $AADAuthHeader'
				$x = Invoke-Expression $cmd
				}
			}
		}
		while ($pagedUri -notlike $Null)

    }
    End
    {
    }
}
}

function Get-AADTMSGraphObjects
{
[CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Authorization Token from Azure AD
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $AuthHeader,
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
		[string]
		$ObjectType,
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
		[string]
		$APIVersion = "beta",
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
		[string[]]
		$Attributes,
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
		[string]
		$Filter,
		[string]
		$EndPoint = "graph.microsoft.com",
		$Top = "999",
		[switch]
		$UseDeltaQuery,
		[string]
		$DeltaLink


    )

    Begin
    {
			$results = @{}
			$results.Values = $null
			$results.DeltaLink = $null
    }
    Process
    {

		if ($UseDeltaQuery -and ($null -notlike $DeltaLink))
		{
				Write-Verbose "Using DeltaQueryLink!"	
				$uri = $DeltaLink
		}
		else
		{

	
			if ($Attributes -like $null)
			{
				 
				if (!$UseDeltaQuery)
				{
					if ($null -like $filter)
					{
						$uri = ("https://{0}/{1}/{2}s?top={3}" -f $EndPoint,$APIVersion,$ObjectType,$top)
					}
					else {
						
						$uri = ("https://{0}/{1}/{2}s?top={3}&filter={4}" -f $EndPoint,$APIVersion,$ObjectType,$top,$filter)
					}
				}
				else
				{
						$uri = ("https://{0}/{1}/{2}s/delta?top={3}" -f $EndPoint,$APIVersion,$ObjectType,$top)
				}
			}
			else
			{

				if (!$UseDeltaQuery)
				{
		
					$selectAttributes = $attributes -join ','

					if ($null -like $filter)
					{
						$uri = ("https://{0}/{1}/{2}s?select={3}&top={4}" -f $Endpoint,$APIVersion,$ObjectType,$selectAttributes,$top)
					}
					else {
						
						$uri = ("https://{0}/{1}/{2}s?select={3}&top={4}&filter={5}" -f $Endpoint,$APIVersion,$ObjectType,$selectAttributes,$top,$filter)
					}
					
		   
				
				}
				else
				{
					$selectAttributes = $attributes -join ','
					$uri = ("https://{0}/{1}/{2}s/delta?select={3}&top={4}" -f $Endpoint,$APIVersion,$ObjectType,$selectAttributes,$top)
		   
				}
			
			}
		   }


		write-debug ("DEBUG:MS Graph URI:{0}" -f $uri)
		$cmd = 'Invoke-RestMethod -Method Get -Uri $Uri -Headers $AuthHeader'
	
	

		$statusMsg = "VEBOSE:Invoking Expression $cmd"
		write-verbose $statusMsg
		$activityName = $MyInvocation.InvocationName

		Write-Progress -Id 1 -Activity $activityName -Status $statusMsg
		$x = $null
		try{
			$x = Invoke-Expression $cmd
		}
		catch
		{
			write-error $_
		}
		$pagedUri = $Null

	if ($x)
	{
		$i = 1

		
		do 
		{
			 
		   Write-Verbose ("VERBOSE:Query Paging page {0} for {1}" -f $i++,$ObjectType )
		  
			$results.Values += $x.value
			if (Get-Member -inputobject $x -name '@odata.nextlink' -MemberType Properties)
			{
				$pagedUri = $x.'@odata.nextlink'
				if (Get-Member -inputobject $x -name '@odata.deltalink' -MemberType Properties)
			{
				$results.deltalink = $x.'@odata.deltalink'
				Write-Verbose ("Delta Link: {0}" -f $results.deltalink)
			}
				if ($pagedUri -notlike $Null)
				{
				Write-Debug ("DEBUG:Getting Next Page of results using Paging URI: {0}" -f $pagedUri )
				$cmd = 'Invoke-RestMethod -Method Get -Uri $pagedUri -Headers $AuthHeader'
				$x = $null
				$x = Invoke-Expression $cmd
				}
			}
			else
			{
				$pagedUri = $null
			}


			
			
		}
		until ($pagedUri -eq $Null)
        

		if (Get-Member -inputobject $x -name '@odata.deltalink' -MemberType Properties)
			{
				$results.deltalink = $x.'@odata.deltalink'
				Write-Verbose ("Delta Link: {0}" -f $results.deltalink)
			}
		
    }
	}
	
    End
    {
		
        Write-Output ([pscustomobject]$results)
    }
}



<#
.Synopsis
   Add a new External User to an AAD Tenant
.DESCRIPTION
   Utilize the Azure B2B feature to invite a user from their home tenant to the target AAD tenant so they can access resources as an External user
.EXAMPLE
   $Creds = get-credential
   Add-AADExternalUser -Credential $creds -AADTenantName mytenant.onmicrosoft.com -InvitedUserEmailAddress bob.ross@mycompany.com -InvitedUserDisplayName "Bob Ross" -InviteRedirectUrl "http://myapps.microsoft.com" -SendInvitationMessage $true
.EXAMPLE
   $Creds = get-credential
   Add-AADExternalUser -Credential $creds -AADTenantName mytenant.onmicrosoft.com -InvitedUserEmailAddress tara.winstead@mycompany.com -InvitedUserDisplayName "Tara Winstead" -InviteRedirectUrl "http://myapps.microsoft.com" -SendInvitationMessage $true -InviteCCRecipients john.smith@mycompany.com -InviteCustomMessageBody "Accept invite to access the MyCompany Applications" -Verbose
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
    
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Add-AADTExternalUser
{
    [CmdletBinding(DefaultParameterSetName='General', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://graph.microsoft.io/en-us/docs/api-reference/beta/resources/invitation',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Credential of user who holds the global admin or inviter role in the target AAD Tenant.  Credentials must have these roles to submit invites, else you will receive a 501 error from API.
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[pscredential]
        $Credential,

        # AAD Tenant Name to invite user too
		[Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $AADTenantName,

        # Email address of the invited user
		 [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=2)]
		[Alias("EmailAddress")] 
        [String]
        $InvitedUserEmailAddress,

		 # Display name of the invited user
         [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=3)]
        [ValidatePattern("[a-z]*")]
		[Alias("DisplayName")] 
        [String]
        $InvitedUserDisplayName,
		# Invite user as a Guest or Member.  Default is Guest, and a Member can only be invited by a Global Admin in the target AAD Tenant
         [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=4)]
		[ValidateSet("Guest", "Member")]
        [String]
        $InvitedUserType="Guest",
		# URL to redirect user to once they have completed the invite acceptance wizard.
		 [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=5)]
        [ValidatePattern("http*")]
        [String]
        $InviteRedirectUrl="https://myapps.microsoft.com",
		# Send an Email invitation to the invited user if true, else just provide the results and do not send the email to invited user.  If false, redemption link will need to be provided to invited user manually.
		[Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=6)]
		[bool]
		$SendInvitationMessage=$false,
		# Additional recipient to send invite email to.   Can only be a single recipient
		[Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=7)]
		[string]
		$InviteCCRecipients,
		# Content that will be included in invite message body
		[Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=8)]
		[string]
		$InviteCustomMessageBody,
		# Language of invitation.  Default is en-US if not specified.  Ignored if InviteCustomMessageBody is specified.
		[Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=9)]
		[string]
		$InviteMessageLanguage=$null,
		#URI to post invite to via MS Graph API.
		[Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=10)]
		[string]
		$invitationUri = "https://graph.microsoft.com/beta/invitations"


    )

    Begin
    {
		$authToken = $null
		$authHeader = $null
		Write-Verbose "Retrieving AuthToken..."
		$authToken = Get-AADGAuthToken -AADTenantName $AADTenantName -Credential $Credential -EndPoint graph.microsoft.com
		
		Write-Verbose "Creating AuthHeader...."
		$authHeader = Get-AADGRestAuthHeader -AuthToken $authToken

		
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("Target", "Operation"))
        {
			
		
		
			$bodyTable = @{}
			
			$bodyTable.invitedUserEmailAddress=$InvitedUserEmailAddress
			$bodyTable.inviteRedirectUrl=$InviteRedirectUrl
			$bodyTable.invitedUserType=$InvitedUserType

			if ($InvitedUserDisplayName -notlike $null)
			{
				$bodyTable.invitedUserDisplayName=$InvitedUserDisplayName
			}

			if ($SendInvitationMessage)
			{
				$bodyTable.sendInvitationMessage=$true

				
					$invitedUserMessageInfo = @{}

					if ($InviteCCRecipients -notlike $null)
					{
						$recipients = @()
						$recipient = @{}
						$emailAddress = @{}

						$emailAddress.name = $InviteCCRecipients
						$emailAddress.address = $InviteCCRecipients

						$recipient.emailAddress = $emailAddress

						$recipients += $recipient
						$invitedUserMessageInfo.ccRecipients = $recipients
					}

					if ($InviteCustomMessageBody -notlike $null)
					{
						$invitedUserMessageInfo.customizedMessageBody = $InviteCustomMessageBody
					}

					if ($InviteMessageLanguage -notlike $null)
					{
						$invitedUserMessageInfo.messageLanguage = $InviteMessageLanguage
					}
					else
					{
						$invitedUserMessageInfo.messageLanguage = $Null
					}

					$bodyTable.invitedUserMessageinfo = $invitedUserMessageInfo
				
			}

			try
			{

				$bodyJson = $bodyTable|ConvertTo-Json -Depth 6
				Write-Verbose $bodyJson
				Write-Verbose "Posting to $invitationUri..."
				$inviteResult = Invoke-RestMethod -Method Post -Uri $invitationUri -Headers $authHeader -Body $bodyJson -ContentType "application/json"

				Write-Output ($inviteResult)
			}
			catch
			{
				throw $_
			}
        }
    }
    End
    {
    }
}

function Get-AADTGraphObjects
{
[CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Authorization Token from Azure AD
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $AuthHeader,
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
		[string]
		$ObjectType,
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
		[string]
		$APIVersion = "beta",
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
		[string[]]
		$Attributes,
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
		[string]
		$Filter,
		[string]
		$EndPoint = "graph.windows.net",
		$Top,
		[switch]
		$All,
		[string]
		$DeltaLink,
		[string]
		$Organization="myorganization"


    )

    Begin
    {
			$results = @{}
			$results.Values = $null
			$results.DeltaLink = $null
    }
    Process
    {

		if ($UseDeltaQuery -and ($null -notlike $DeltaLink))
		{
				Write-Verbose "Using DeltaQueryLink!"	
				$uri = $DeltaLink
		}
		else
		{

	
			if ($Attributes -like $null)
			{
				 
			
						if ($null -like $top)
						{
							$uri = ("https://{0}/{1}/{2}s?api-version={3}" -f $EndPoint,$organization,$ObjectType,$APIVersion)
						}
						else
						{
							$uri = ("https://{0}/{1}/{2}s?api-version={3}&top={4}" -f $EndPoint,$organization,$ObjectType,$APIVersion,$top)
						}
						
				
			}
			else
			{

				if (!$UseDeltaQuery)
				{
		
					$selectAttributes = $attributes -join ','
					
					$uri = ("https://{0}/{1}/{2}s?api-version={3}top={4}" -f $EndPoint,$organization,$ObjectType,$APIVersion,$top)
		   
				
				}
				else
				{
					$selectAttributes = $attributes -join ','
					$uri = ("https://{0}/{1}/{2}s/delta?select={3}&top={4}" -f $Endpoint,$APIVersion,$ObjectType,$selectAttributes,$top)
		   
				}
			
			}
		   }


		write-debug ("DEBUG:AAD Graph URI:{0}" -f $uri)
		$cmd = 'Invoke-RestMethod -Method Get -Uri $Uri -Headers $AuthHeader'
	
	

		$statusMsg = "VEBOSE:Invoking Expression $cmd"
		write-verbose $statusMsg
		$activityName = $MyInvocation.InvocationName

		Write-Progress -Id 1 -Activity $activityName -Status $statusMsg
		$x = $null
		try{
			$x = Invoke-Expression $cmd
		}
		catch
		{
			write-error $_
		}
		$pagedUri = $Null

	if ($x)
	{
		$i = 1

		
		do 
		{
			 
		   Write-Verbose ("VERBOSE:Query Paging page {0} for {1}" -f $i++,$ObjectType )
		  
			$results.Values += $x.value
			if (Get-Member -inputobject $x -name 'odata.nextlink' -MemberType Properties)
			{
				
				$skipToken = $x.'odata.nextlink'.split('?')[1]
				$pagedUri = ("{0}&{1}" -f $uri,$skipToken)
				
				if ($pagedUri -notlike $Null)
				{
					Write-Debug ("DEBUG:Getting Next Page of results using Paging URI: {0}" -f $pagedUri )
					$cmd = 'Invoke-RestMethod -Method Get -Uri $pagedUri -Headers $AuthHeader'
					$x = $null
					$x = Invoke-Expression $cmd
				}
			}
			else
			{
				$pagedUri = $null
			}


			
			
		}
		until ($pagedUri -eq $Null)
        

		if (Get-Member -inputobject $x -name '@odata.deltalink' -MemberType Properties)
			{
				$results.deltalink = $x.'@odata.deltalink'
				Write-Verbose ("Delta Link: {0}" -f $results.deltalink)
			}
		
    }
	}
	
    End
    {
		
        Write-Output ([pscustomobject]$results)
    }
}