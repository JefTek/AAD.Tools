<#
.Synopsis
   Get Graph Authorization Token from AAD tenant for User or Client credentials
.DESCRIPTION
   Use "application/json" as content type and get SDK pieces from http://aka.ms/webpi-azps
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
		$CredentialType = "UserCredential"
    )

		
		$adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
       $adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
       [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
       [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

		$clientId = "1950a258-227b-4e31-a9cf-717495945fc2" 
       $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
       $resourceAppIdURI = "https://"+$EndPoint
       $authority = "https://login.windows.net/$aadTenantName"
	   $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

		switch ($CredentialType)
		{
			"UserCredential"
			{
				$aadCreds = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($credential.GetNetworkCredential().username,$credential.GetNetworkCredential().password)
				$authResult = $authContext.AcquireToken($resourceAppIdURI, $clientID,$aadCreds)
			}

			"ClientCredential"
			{
				$aadCreds = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($credential.GetNetworkCredential().username,$credential.GetNetworkCredential().password)
				$authResult = $authContext.AcquireToken($resourceAppIdURI,$aadCreds)
			}

		}

		
		Write-Verbose "AADCreds = $aadCreds"
	
	   
       $authResult = $null

	   $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientID,$aadCreds)

	   Write-Output $authResult

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
    [OutputType([int])]
    Param
    (
        # Auth Token provided by Azure AD for accessing a resource
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByValue=$true,
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
		$TenantID,
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

			foreach ($i in $x.Value) 
			{
			
				$csentry = New-CSEntryChange -InputObject $i -ObjectType "User" -Schema $schema
				[void] $importReturnInfo.CSEntries.Add($csentry)
			}

			
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