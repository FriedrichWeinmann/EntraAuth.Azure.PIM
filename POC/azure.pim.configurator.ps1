#requires -Modules Az.Accounts
<#
.SYNOPSIS
	Applies the PIM Configuration config file against the resources specified within.

.DESCRIPTION
	Applies the PIM Configuration config file against the resources specified within.

	For each resource specified, it will read the configuration for each role specified,
	match that against the configured state for the PIM setting defined for that resource
	and role combination, then remediate any deviation from that defined configuration.

	For more details on how the configuration file should be styled, see the example
	config file and its inline documentation.

	This script can test and manage:
	- Role Assignment rules
	- Role Activation rules
	- Role Notification rules

	On the roadmap but not implemented yet:
	- Manage actual role (eligible or active) assignments.

.PARAMETER ConfigPath
	Path to the configuration file defining the desired state.

.PARAMETER NoConnect
	Do not connect as part of the script.
	This requires you to already be connected via Connect-AzAccount before running this script.

.PARAMETER Noop
	Do not execute anything.
	This parameter exists with the intent to dotsource the script, providing access to all the
	commands inside, without actually executing them.
	With that you can execute individual steps of the script as desired.
	This parameter is mostly intended for debugging purposes.

.EXAMPLE
	PS C:\> .\azure.pim.configurator.ps1 -ConfigPath .\myproject.config.psd1

	Applies the configuration specified in "myproject.config.psd1" after connecting interactively.

.EXAMPLE
	PS C:\> .\azure.pim.configurator.ps1 -ConfigPath .\myproject.config.psd1 -NoConnect

	Applies the configuration specified in "myproject.config.psd1" without authenticating.
	This is going to fail - badly - if you are not yet connected before calling this.
	Use Connect-AzAccount to connect first.

.EXAMPLE
	PS C:\> . .\azure.pim.configurator.ps1 -ConfigPath .\myproject.config.psd1 -Noop

	Loads the configuration and script commands into the current console session, without performing
	any of the steps. You can now access the configuration via "$config" and execute all functions
	inside of the script as seems useful.
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string]
	$ConfigPath,

	[switch]
	$NoConnect,

	[switch]
	$Noop
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

$config = Import-PowerShellDataFile -Path $ConfigPath

#region Functions
#region Tasks
function Get-ResourceTask {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Config
	)

	Write-Host "Processing Resource: $Resource"

	$roles = Get-AzPimResourceRole -Resource $Resource

	$tasks = do {
		Get-ConfigTask -Resource $Resource -Config $Config -Roles $roles
		Get-NotificationTask -Resource $Resource -Config $Config -Roles $roles
		# Not Implemented:
		# Get-AssignmentTask -Resource $Resource -Config $Config
	}
	while ($false)

	Write-Verbose "Processing Resource: $Resource - $($tasks.Count) tasks found"
	$tasks
}

function Get-ConfigTask {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Config,
		
		[Parameter(Mandatory = $true)]
		$Roles
	)

	$inScopeRoles = $Config.InScope.Roles
	if ($Config.InScope.$Resource) { $inScopeRoles = $Config.InScope.$Resource }

	foreach ($role in $inScopeRoles) {
		$roleID = $role
		if (-not ($roleID -as [guid])) { $roleID = ($Roles | Where-Object Name -EQ $role).ID }

		if (-not $roleID) {
			Write-Warning "Invalid Role Configuration: $role not found for resource $Resource!"
			continue
		}

		$desired = Resolve-ConfigState -Config $Config -Resource $Resource -Role $Role
		try { $actualSettings = Get-AzPimRoleConfiguration -Resource $Resource -RoleID $roleID }
		catch {
			Write-Warning "Failed to retrieve role configuration $role / $($roleID): $_"
			continue
		}

		$changes = @()

		if ($desired.MaxDuration -ne $actualSettings.UserActivationLimit.TotalMinutes) {
			$changes += New-Change -Property MaxDuration -Old $actualSettings.UserActivationLimit.TotalMinutes -New $desired.MaxDuration
		}
		if ($desired.RequireMFA -ne $actualSettings.EnableReqMFA) {
			$changes += New-Change -Property RequireMFA -Old $actualSettings.EnableReqMFA -New $desired.RequireMFA
		}
		if ($desired.Justification -ne $actualSettings.EnableReqJustification) {
			$changes += New-Change -Property Justification -Old $actualSettings.EnableReqJustification -New $desired.Justification
		}
		if ($desired.Ticket -ne $actualSettings.EnableReqTicket) {
			$changes += New-Change -Property Ticket -Old $actualSettings.EnableReqTicket -New $desired.Ticket
		}
		if ((@($desired.Approver).Count -gt 0) -ne $actualSettings.EnableReqApprover) {
			$changes += New-Change -Property RequiresApprover -Old $actualSettings.EnableReqApprover -New (-not $actualSettings.EnableReqApprover)
		}
		foreach ($approver in $desired.Approver) {
			if ($approver -in $actualSettings.Approvers) { continue }
			$changes += New-Change -Property Approver -New $approver
		}
		foreach ($approver in $actualSettings.Approvers) {
			if ($approver -in $desired.Approver) { continue }
			$changes += New-Change -Property Approver -Old $approver
		}
		if (($desired.EligibleDuration -le -1) -ne $actualSettings.EligiblePermanent) {
			$changes += New-Change -Property EligiblePermanent -Old $actualSettings.EligiblePermanent -New ($desired.EligibleDuration -eq -1)
		}
		if (($desired.EligibleDuration -gt -1) -and $desired.EligibleDuration -ne $actualSettings.EligibleLimit.TotalDays) {
			$changes += New-Change -Property EligibleDuration -Old $actualSettings.EligibleLimit.TotalDays -New $desired.EligibleDuration
		}
		if (($desired.ActiveDuration -le -1) -ne $actualSettings.ActivePermanent) {
			$changes += New-Change -Property ActivePermanent -Old $actualSettings.ActivePermanent -New ($desired.ActiveDuration -eq -1)
		}
		if (($desired.ActiveDuration -gt -1) -and $desired.ActiveDuration -ne $actualSettings.ActiveLimit.TotalDays) {
			$changes += New-Change -Property ActiveDuration -Old $actualSettings.ActiveLimit.TotalDays -New $desired.ActiveDuration
		}

		if (-not $changes) { continue }

		New-Task -Type Config -Resource $Resource -Role $role -Configuration $desired -Object $actualSettings -Changes $changes
	}
}
function Invoke-ConfigTask {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Task
	)

	$roleConfig = Get-AzPimRoleConfiguration -Resource $Task.Resource -RoleID $Task.Object.RoleID -Raw

	$expiration = @{
		Eligible       = $roleConfig.properties.rules | Where-Object id -EQ Expiration_Admin_Eligibility
		Active         = $roleConfig.properties.rules | Where-Object id -EQ Expiration_Admin_Assignment
		UserActivation = $roleConfig.properties.rules | Where-Object id -EQ Expiration_EndUser_Assignment
	}
	$enablement = @{
		Eligibility    = $roleConfig.properties.rules | Where-Object id -EQ Enablement_Admin_Eligibility
		Assignment     = $roleConfig.properties.rules | Where-Object id -EQ Enablement_Admin_Assignment
		UserActivation = $roleConfig.properties.rules | Where-Object id -EQ Enablement_EndUser_Assignment
	}
	$approver = $roleConfig.properties.rules | Where-Object id -EQ Approval_EndUser_Assignment

	#region Apply Changes
	foreach ($change in $Task.Changes) {
		switch ($change.Property) {
			MaxDuration {
				Set-Property -InputObject $expiration.UserActivation -Property maximumDuration -Value ($change.New | ConvertTo-DurationString -AsMinutes)
			}
			RequireMFA {
				if (-not $change.New) {
					Set-Property -InputObject $expiration.UserActivation -Property enabledRules -Value @($enablement.UserActivation.enabledRules | Where-Object { $_ -ne 'MultiFactorAuthentication' })
				}
				else {
					Set-Property -InputObject $expiration.UserActivation -Property enabledRules -DefaultValue @() -Value 'MultiFactorAuthentication' -Add
				}
			}
			Justification {
				if (-not $change.New) {
					Set-Property -InputObject $expiration.UserActivation -Property enabledRules -Value @($enablement.UserActivation.enabledRules | Where-Object { $_ -ne 'Justification' })
				}
				else {
					Set-Property -InputObject $expiration.UserActivation -Property enabledRules -DefaultValue @() -Value 'Justification' -Add
				}
			}
			Ticket {
				if (-not $change.New) {
					Set-Property -InputObject $expiration.UserActivation -Property enabledRules -Value @($enablement.UserActivation.enabledRules | Where-Object { $_ -ne 'Ticketing' })
				}
				else {
					Set-Property -InputObject $expiration.UserActivation -Property enabledRules -DefaultValue @() -Value 'Ticketing' -Add
				}
			}
			RequiresApprover {
				Set-Property -InputObject $approver.setting -Property isApprovalRequired -Value $change.New
			}
			Approver {
				$stage = $approver.setting.approvalStages[0]

				if ($change.Old) {
					Set-Property -InputObject $stage -Property primaryApprovers -Value @($stage.primaryApprovers | Where-Object id -NE $change.Old)
					continue
				}
				
				Set-Property -InputObject $stage -Property primaryApprovers -Value (Resolve-Approver -Id $change.New) -DefaultValue @() -Add
			}
			EligiblePermanent {
				Set-Property -InputObject $expiration.Eligible -Property isExpirationRequired -Value (-not $change.New)
			}
			EligibleDuration {
				Set-Property -InputObject $expiration.Eligible -Property maximumDuration -Value ($change.New | ConvertTo-DurationString -AsDays)
			}
			ActivePermanent {
				Set-Property -InputObject $expiration.Active -Property isExpirationRequired -Value (-not $change.New)
			}
			ActiveDuration {
				Set-Property -InputObject $expiration.Active -Property maximumDuration -Value ($change.New | ConvertTo-DurationString -AsDays)
			}
			default {
				Write-Warning "Failed to apply config update to $($Task.Resource) > $($Task.Role): $($Change.Property) updates have not yet been implemented!"
			}
		}
	}
	#endregion Apply Changes

	# Write back to Azure
	try { Set-AzPimResourceRole -Properties $roleConfig.properties -Resource $Task.Resource -RoleID $Task.Object.RoleID }
	catch { Write-Warning "Failed to update configuration for resource $($Task.Resource) > $($Task.Role): $_" }
}

function Get-NotificationTask {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Config,
		
		[Parameter(Mandatory = $true)]
		$Roles
	)

	$inScopeRoles = $Config.InScope.Roles
	if ($Config.InScope.$Resource) { $inScopeRoles = $Config.InScope.$Resource }

	foreach ($role in $inScopeRoles) {
		$roleID = $role
		if (-not ($roleID -as [guid])) { $roleID = ($Roles | Where-Object Name -EQ $role).ID }

		if (-not $roleID) {
			Write-Warning "Invalid Role Configuration: $role not found for resource $Resource!"
			continue
		}

		$desired = Resolve-NotificationState -Config $Config -Resource $Resource -Role $Role
		$actualSettings = Get-AzPimRoleNotification -Resource $Resource -RoleID $roleID

		$changes = @()

		$toTest = 'AssignEligibleAlert', 'AssignEligibleAssignee', 'AssignEligibleRenewalApprover', 'AssignActiveAlert', 'AssignActiveAssignee', 'AssignActiveRenewalApprover', 'ActivationAlert', 'ActivationRequester', 'ActivationApprover'

		foreach ($testItem in $toTest) {
			$configItem = Resolve-NotificationConfig -Label $testItem -DesiredConfig $desired
			$actualItem = $actualSettings.$testItem

			if ($configItem.Default -ne $actualItem.DefaultEnabled) {
				$changes += New-Change -Property $testItem -SubProperty DefaultEnabled -Old $actualItem.DefaultEnabled -New $configItem.Default
			}
			if ($configItem.CriticalOnly -ne $actualItem.CriticalOnly) {
				$changes += New-Change -Property $testItem -SubProperty CriticalOnly -Old $actualItem.CriticalOnly -New $configItem.CriticalOnly
			}
			foreach ($recipient in $configItem.Additional) {
				if ($recipient -in $actualItem.AdditionalRecipients) { continue }
				$changes += New-Change -Property $testItem -SubProperty Recipient -New $recipient
			}
			foreach ($recipient in $actualItem.AdditionalRecipients) {
				if ($recipient -in $configItem.Additional) { continue }
				$changes += New-Change -Property $testItem -SubProperty Recipient -Old $recipient
			}
		}

		if ($changes.Count -eq 0) { continue }

		New-Task -Type Notification -Resource $Resource -Role $role -Configuration $desired -Object $actualSettings -Changes $changes
	}
}
function Invoke-NotificationTask {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Task
	)

	$roleConfig = Get-AzPimRoleConfiguration -Resource $Task.Resource -RoleID $Task.Object.RoleID -Raw

	$propertyMap = @{
		AssignEligibleAlert           = $roleConfig.properties.rules | Where-Object id -EQ Notification_Admin_Admin_Eligibility
		AssignEligibleAssignee        = $roleConfig.properties.rules | Where-Object id -EQ Notification_Requestor_Admin_Eligibility
		AssignEligibleRenewalApprover = $roleConfig.properties.rules | Where-Object id -EQ Notification_Approver_Admin_Eligibility
		AssignActiveAlert             = $roleConfig.properties.rules | Where-Object id -EQ Notification_Admin_Admin_Assignment
		AssignActiveAssignee          = $roleConfig.properties.rules | Where-Object id -EQ Notification_Requestor_Admin_Assignment
		AssignActiveRenewalApprover   = $roleConfig.properties.rules | Where-Object id -EQ Notification_Approver_Admin_Assignment
		ActivationAlert               = $roleConfig.properties.rules | Where-Object id -EQ Notification_Admin_EndUser_Assignment
		ActivationRequester           = $roleConfig.properties.rules | Where-Object id -EQ Notification_Requestor_EndUser_Assignment
		ActivationApprover            = $roleConfig.properties.rules | Where-Object id -EQ Notification_Approver_EndUser_Assignment
	}

	#region Apply Updates
	foreach ($change in $Task.Changes) {
		$rule = $propertyMap[$change.Property]
		switch ($change.SubProperty) {
			DefaultEnabled {
				$rule.isDefaultRecipientsEnabled = $change.New
			}
			CriticalOnly {
				if ($change.New) { $rule.notificationLevel = 'Critical' }
				else { $rule.notificationLevel = 'All' }
			}
			Recipient {
				if ($rule.PSObject.Properties.Name -notcontains 'notificationRecipients') {
					Add-Member -InputObject $rule -MemberType NoteProperty -Name notificationRecipients -Value @()
				}
				if ($change.New) { $rule.notificationRecipients = @($rule.notificationRecipients) + $change.New }
				else { $rule.notificationRecipients = @($rule.notificationRecipients | Where-Object { $_ -ne $change.Old }) }
			}
			default {
				Write-Warning "Error updating $($Task.Resource) > $($Task.Role): Unexpected change type '$($change.SubProperty)'. This would happen when a code change only applied to the Test routine, but the update routine was not implemented to match and requires a code change to resolve."
			}
		}
	}
	#endregion Apply Updates

	try { Set-AzPimResourceRole -Properties $roleConfig.properties -Resource $Task.Resource -RoleID $Task.Object.RoleID }
	catch { Write-Warning "Failed to update notifications for resource $($Task.Resource) > $($Task.Role): $_" }
}
function Resolve-NotificationConfig {
	[OutputType([hashtable])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Label,

		[Parameter(Mandatory = $true)]
		[hashtable]
		$DesiredConfig
	)

	switch ($Label) {
		AssignEligibleAlert { $DesiredConfig.EligibleAssignment.AssignmentAlert }
		AssignEligibleAssignee { $DesiredConfig.EligibleAssignment.NotificationToAssignee }
		AssignEligibleRenewalApprover { $DesiredConfig.EligibleAssignment.RenewalRequestApproval }
		AssignActiveAlert { $DesiredConfig.ActiveAssignment.AssignmentAlert }
		AssignActiveAssignee { $DesiredConfig.ActiveAssignment.NotificationToAssignee }
		AssignActiveRenewalApprover { $DesiredConfig.ActiveAssignment.RenewalRequestApproval }
		ActivationAlert { $DesiredConfig.EligibleActivation.ActivationAlert }
		ActivationRequester { $DesiredConfig.EligibleActivation.RequesterNotification }
		ActivationApprover { $DesiredConfig.EligibleActivation.ApproverNotification }
	}
}

function Get-AssignmentTask {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Config
	)

	Write-Warning "Role Assignments Not Yet Implemented!"
}


function Resolve-ConfigState {
	[OutputType([hashtable])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Config,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Role
	)

	$settings = @{ }

	foreach ($setting in $Config.Roles.Default.GetEnumerator()) {
		$settings[$setting.Key] = $setting.Value
	}
	
	foreach ($key in $Config.Roles.$Role.Keys) {
		$settings[$key] = $Config.Roles.$Role.$key
	}
	foreach ($key in $Config.Roles.$Resource.Default.Keys) {
		$settings[$key] = $Config.Roles.$Resource.Default.$key
	}
	foreach ($key in $Config.Roles.$Resource.$Role.Keys) {
		$settings[$key] = $Config.Roles.$Resource.$Role.$key
	}

	$settings
}
function Resolve-NotificationState {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Config,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Role
	)

	#region Default Settings
	$rootKeys = @{
		EligibleAssignment = @(
			'AssignmentAlert'
			'NotificationToAssignee'
			'RenewalRequestApproval'
		)
		ActiveAssignment   = @(
			'AssignmentAlert'
			'NotificationToAssignee'
			'RenewalRequestApproval'
		)
		EligibleActivation = @(
			'ActivationAlert'
			'RequesterNotification'
			'ApproverNotification'
		)
	}
	$coreNames = 'Default', 'Additional', 'CriticalOnly'

	$settings = @{
		EligibleAssignment = @{
			AssignmentAlert        = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
			NotificationToAssignee = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
			RenewalRequestApproval = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
		}
		ActiveAssignment   = @{
			AssignmentAlert        = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
			NotificationToAssignee = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
			RenewalRequestApproval = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
		}
		EligibleActivation = @{
			ActivationAlert       = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
			RequesterNotification = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
			ApproverNotification  = @{
				Default      = $true
				Additional   = @()
				CriticalOnly = $false
			}
		}
	}
	#endregion Default Settings

	foreach ($rootKey in $rootKeys.Keys) {
		foreach ($subKey in $rootKeys.$rootKey) {
			foreach ($coreName in $coreNames) {
				if ($Config.Notifications.Default.$rootKey.$subKey.Keys -contains $coreName) {
					$settings.$rootKey.$subKey.$coreName = $Config.Notifications.Default.$rootKey.$subKey.$coreName
				}
				if ($Config.Notifications.$Role.$rootKey.$subKey.Keys -contains $coreName) {
					$settings.$rootKey.$subKey.$coreName = $Config.Notifications.$Role.$rootKey.$subKey.$coreName
				}
				if ($Config.Notifications.$Resource.Default.$rootKey.$subKey.Keys -contains $coreName) {
					$settings.$rootKey.$subKey.$coreName = $Config.Notifications.$Resource.Default.$rootKey.$subKey.$coreName
				}
				if ($Config.Notifications.$Resource.$Role.$rootKey.$subKey.Keys -contains $coreName) {
					$settings.$rootKey.$subKey.$coreName = $Config.Notifications.$Resource.$Role.$rootKey.$subKey.$coreName
				}
			}
		}
	}
	$settings
}
function New-Task {
	[CmdletBinding()]
	param (
		[ValidateSet('Config', 'Notification', 'AddAssignment', 'RemoveAssignment', 'UpdateAssignment')]
		[string]
		$Type,

		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[string]
		$Role,
		
		[Parameter(Mandatory = $true)]
		$Configuration,
		
		[Parameter(Mandatory = $true)]
		$Object,

		$Changes
	)

	[PSCustomObject]@{
		PSTypeName    = 'AzurePIM.Task'
		Resource      = $Resource
		Type          = $Type
		Role          = $Role
		Configuration = $Configuration
		Object        = $Object
		Changes       = $Changes
	}
}

function New-Change {
	[CmdletBinding()]
	param (
		[string]
		$Property,

		[string]
		$SubProperty,

		$Old,
		
		$New
	)

	[PSCustomObject]@{
		PSTypeName  = 'AzurePIM.Change'
		Property    = $Property
		SubProperty = $SubProperty
		Old         = $Old
		New         = $New
	}
}
#endregion Tasks

#region Graph API
function Resolve-Approver {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$ID
	)

	if (-not $script:_ApproverCache) { $script:_ApproverCache = @{ } }
	if ($script:_ApproverCache[$ID]) { return $script:_ApproverCache[$ID] }

	$graphAuthHeader = Get-GraphAuthHeader
	$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$ID" -Headers $graphAuthHeader
	$result = [PSCustomObject]@{
		id          = $ID
		description = $response.displayName
		isBackup    = $false
		userType    = (Get-Culture).TextInfo.ToTitleCase(($response.'@odata.type' -replace '^.+\.'))
	}
	$script:_ApproverCache[$ID] = $result
	$result
}

function Get-GraphAuthHeader {
	[OutputType([hashtable])]
	[CmdletBinding()]
	param ()

	if (-not $script:_GraphToken) {
		$script:_GraphToken = Get-AzAccessToken -ResourceTypeName MSGraph -AsSecureString
	}

	$tempCred = [pscredential]::new("NoMatter", $script:_GraphToken.Token)
	@{
		Authorization = "$($script:_GraphToken.Type) $($tempCred.GetNetworkCredential().Password)"
	}
}
#endregion Graph API

#region PIM API
function Invoke-AzPimRequest {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Request,

		[hashtable]
		$Query = @{},

		$Body,

		[string]
		$Method = 'Get',

		[string]
		$ApiVersion = '2020-10-01'
	)

	$Query['api-version'] = "$ApiVersion"
	$queryStrings = foreach ($pair in $Query.GetEnumerator()) {
		'{0}={1}' -f $pair.Key, $pair.Value
	}

	$payload = @{}
	if ($Body) {
		$payload.Payload = $Body
		if ($Body -isnot [string]) { $payload.Payload = $Body | ConvertTo-Json -Depth 10 -Compress }

	}

	$path = "subscriptions/$($Request.TrimStart('/'))?$($queryStrings -join '&')"

	Invoke-AzRestMethod -Path $path -Method $Method @payload
}

function Get-AzPimResourceRole {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[switch]
		$AsHashtable
	)

	$rolesHash = @{}
	$allRoles = (Invoke-AzPimRequest -Request "$Resource/providers/Microsoft.Authorization/roleDefinitions" -ApiVersion 2022-04-01).Content | ConvertFrom-Json
	foreach ($role in $allRoles.Value) {
		$roleObject = [PSCustomObject]@{
			PSTypeName         = 'AzurePIM.ResourceRole'
			Resource           = $Resource
			ID                 = $role.name
			Name               = $role.properties.roleName
			Type               = $role.properties.type
			FullID             = $role.id
			Description        = $role.properties.description
			AllowedActions     = $role.properties.permissions.actions
			DeniedActions      = $role.properties.permissions.notActions
			AllowedDataActions = $role.properties.permissions.dataActions
			DeniedDataActions  = $role.properties.permissions.notDataActions
		}
		if ($AsHashtable) { $rolesHash[$roleObject.ID] = $roleObject }
		else { $roleObject }
	}

	if ($AsHashtable) { $rolesHash }
}
function Get-AzPimRoleConfiguration {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[Parameter(Mandatory = $true)]
		[string]
		$RoleID,

		[switch]
		$Raw
	)

	$rolePolicyMapping = Get-AzPimRolePolicyMapping -Resource $Resource -AsHashtable

	# https://management.azure.com/subscriptions/a47f11ba-ac24-4645-87fa-4d320d7a2c47/providers/Microsoft.Authorization/roleManagementPolicies/21090545-7ca7-4776-b22c-e363652d74d2?api-version=2020-10-01&$filter=asTarget()
	$roleDataRaw = Invoke-AzPimRequest -Request "$Resource/providers/Microsoft.Authorization/roleManagementPolicies/$($rolePolicyMapping[$RoleID].PolicyID)"
	if ($roleDataRaw.StatusCode -notmatch "^2") {
		$errorData = $roleDataRaw.Content | ConvertFrom-Json
		throw "Error requesting role $RoleID from $($Resource): $($roleDataRaw.StatusCode) | $($errorData.error.code) | $($errorData.error.message)"
	}

	$data = $roleDataRaw.Content | ConvertFrom-Json
	if ($Raw) { return $data }

	$expiration = @{
		Eligible       = $data.properties.rules | Where-Object id -EQ Expiration_Admin_Eligibility
		Active         = $data.properties.rules | Where-Object id -EQ Expiration_Admin_Assignment
		UserActivation = $data.properties.rules | Where-Object id -EQ Expiration_EndUser_Assignment
	}
	$enablement = @{
		Eligibility    = $data.properties.rules | Where-Object id -EQ Enablement_Admin_Eligibility
		Assignment     = $data.properties.rules | Where-Object id -EQ Enablement_Admin_Assignment
		UserActivation = $data.properties.rules | Where-Object id -EQ Enablement_EndUser_Assignment
	}
	$approver = $data.properties.rules | Where-Object id -EQ Approval_EndUser_Assignment

	[PSCustomObject]@{
		PSTypeName             = 'AzurePIM.RoleConfiguration'
		Resource               = $Resource
		RoleID                 = $RoleID

		EligiblePermanent      = $expiration.Eligible.isExpirationRequired -eq $false
		EligibleLimit          = $expiration.Eligible.maximumDuration | ConvertFrom-DurationString
		ActivePermanent        = $expiration.Active.isExpirationRequired -eq $false
		ActiveLimit            = $expiration.Active.maximumDuration | ConvertFrom-DurationString
		UserActivationLimit    = $expiration.UserActivation.maximumDuration | ConvertFrom-DurationString

		EnableReqJustification = $enablement.UserActivation.enabledRules -contains 'Justification'
		EnableReqMFA           = $enablement.UserActivation.enabledRules -contains 'MultiFactorAuthentication'
		EnableReqTicket        = $enablement.UserActivation.enabledRules -contains 'Ticketing'
		EnableReqApprover      = $approver.setting.isApprovalRequired -eq $true
		Approvers              = $approver.setting.approvalStages.primaryApprovers.id

		ActiveReqMFA           = $enablement.Assignment.enabledRules -contains 'MultiFactorAuthentication'
		ActiveReqJustification = $enablement.Assignment.enabledRules -contains 'Justification'

		Notifications          = Get-AzPimRoleNotification -Resource $Resource -RoleID $RoleID -RoleDataRaw $roleDataRaw

		Properties             = $data.properties
	}
}
function Get-AzPimRolePolicyMapping {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[switch]
		$AsHashtable
	)

	if (-not $script:_RolePolicyMapping) { $script:_RolePolicyMapping = @{ } }
	if ($script:_RolePolicyMapping[$Resource]) {
		if ($AsHashtable) { return $script:_RolePolicyMapping[$Resource].Clone() }
		else { return $script:_RolePolicyMapping[$Resource].Values }
	}

	$script:_RolePolicyMapping[$Resource] = @{ }

	$content = (Invoke-AzPimRequest -Request "$Resource/providers/Microsoft.Authorization/roleManagementPolicyAssignments" -ApiVersion '2020-10-01').Content | ConvertFrom-Json
	foreach ($entry in $content.value) {
		$roleID = ($entry.properties.roleDefinitionId -split '/')[-1]
		$policyID = ($entry.properties.policyId -split '/')[-1]
		$script:_RolePolicyMapping[$Resource][$roleID] = [PSCustomObject]@{
			PSTypeName   = 'AzurePIM.RolePolicyMapping'
			Resource     = $Resource
			RoleID       = $roleID
			PolicyID     = $policyID
			RoleIDFull   = $entry.properties.roleDefinintionId
			PolicyIDFull = $entry.properties.policyId
		}
	}

	if ($AsHashtable) { $script:_RolePolicyMapping[$Resource].Clone() }
	else { $script:_RolePolicyMapping[$Resource].Values }
}
function Set-AzPimResourceRole {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Properties,

		[Parameter(Mandatory = $true)]
		[string]
		$Resource,
		
		[Parameter(Mandatory = $true)]
		[string]
		$RoleID
	)

	$rolePolicyMapping = Get-AzPimRolePolicyMapping -Resource $Resource -AsHashtable

	$body = @{ properties = $Properties } | ConvertTo-Json -Depth 99
	$response = Invoke-AzPimRequest -Method Patch -Request "$($Resource)/providers/Microsoft.Authorization/roleManagementPolicies/$($rolePolicyMapping[$RoleID].PolicyID)" -ApiVersion '2020-10-01' -Body $body
	if ($response.StatusCode -notmatch "^2") {
		$script:_errorData = @{
			Data     = $body
			Response = $response
		}
		$errorData = $response.Content | ConvertFrom-Json
		throw "Error requestion role $RoleID from $($Resource): $($response.StatusCode) | $($errorData.error.code) | $($errorData.error.message)"
	}
}
function Get-AzPimRoleNotification {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[Parameter(Mandatory = $true)]
		[string]
		$RoleID,

		[Parameter(DontShow = $true)]
		$RoleDataRaw
	)

	#region Utility Function
	function Resolve-Notification {
		[CmdletBinding()]
		param (
			$Rule
		)

		$obj = [PSCustomObject]@{
			DefaultEnabled       = $Rule.isDefaultRecipientsEnabled
			AdditionalRecipients = $Rule.notificationRecipients
			CriticalOnly         = $Rule.notificationLevel -eq 'Critical'
		}
		Add-Member -InputObject $obj -MemberType ScriptMethod -Name ToString -Value {
			'Default: {0} | CritOnly: {1} | Recipients: {2}' -f $this.DefaultEnabled, $this.CriticalOnly, ($this.AdditionalRecipients -join ', ')
		} -Force -PassThru
	}
	#endregion Utility Function

	
	if (-not $RoleDataRaw) {
		$rolePolicyMapping = Get-AzPimRolePolicyMapping -Resource $Resource -AsHashtable
		$RoleDataRaw = Invoke-AzPimRequest -Request "$Resource/providers/Microsoft.Authorization/roleManagementPolicies/$($rolePolicyMapping[$RoleID].PolicyID)"
		if ($RoleDataRaw.StatusCode -notmatch "^2") {
			$errorData = $RoleDataRaw.Content | ConvertFrom-Json
			throw "Error requestion role $RoleID from $($Resource): $($RoleDataRaw.StatusCode) | $($errorData.error.code) | $($errorData.error.message)"
		}
	}

	$data = $RoleDataRaw.Content | ConvertFrom-Json

	$eligibleAssignment = @{
		AssignmentAlert        = $data.properties.rules | Where-Object id -EQ Notification_Admin_Admin_Eligibility
		NotificationToAssignee = $data.properties.rules | Where-Object id -EQ Notification_Requestor_Admin_Eligibility
		RenewalRequestApproval = $data.properties.rules | Where-Object id -EQ Notification_Approver_Admin_Eligibility
	}
	$activeAssignment = @{
		AssignmentAlert        = $data.properties.rules | Where-Object id -EQ Notification_Admin_Admin_Assignment
		NotificationToAssignee = $data.properties.rules | Where-Object id -EQ Notification_Requestor_Admin_Assignment
		RenewalRequestApproval = $data.properties.rules | Where-Object id -EQ Notification_Approver_Admin_Assignment
	}
	$eligibleActivation = @{
		ActivationAlert       = $data.properties.rules | Where-Object id -EQ Notification_Admin_EndUser_Assignment
		RequesterNotification = $data.properties.rules | Where-Object id -EQ Notification_Requestor_EndUser_Assignment
		ApproverNotification  = $data.properties.rules | Where-Object id -EQ Notification_Approver_EndUser_Assignment
	}

	[PSCustomObject]@{
		PSTypeName                    = 'AzurePIM.RoleNotification'
		Resource                      = $Resource
		RoleID                        = $RoleID

		AssignEligibleAlert           = Resolve-Notification -Rule $eligibleAssignment.AssignmentAlert
		AssignEligibleAssignee        = Resolve-Notification -Rule $eligibleAssignment.NotificationToAssignee
		AssignEligibleRenewalApprover = Resolve-Notification -Rule $eligibleAssignment.RenewalRequestApproval
		AssignActiveAlert             = Resolve-Notification -Rule $activeAssignment.AssignmentAlert
		AssignActiveAssignee          = Resolve-Notification -Rule $activeAssignment.NotificationToAssignee
		AssignActiveRenewalApprover   = Resolve-Notification -Rule $activeAssignment.RenewalRequestApproval
		ActivationAlert               = Resolve-Notification -Rule $eligibleActivation.ActivationAlert
		ActivationRequester           = Resolve-Notification -Rule $eligibleActivation.RequesterNotification
		ActivationApprover            = Resolve-Notification -Rule $eligibleActivation.ApproverNotification
	}
}

function ConvertFrom-DurationString {
	[OutputType([timespan])]
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		[string]
		$InputString
	)

	process {
		if (-not $InputString) { return }

		$timespan = [timespan]::new(0)

		foreach ($match in ($InputString | Select-String '(\d+)([MHD])' -AllMatches).Matches) {
			$number = $match.Groups[1].Value -as [int]
			$type = $match.Groups[2].Value
			switch ($type) {
				'M' { $timespan = $timespan.Add([timespan]::new(0, 0, $number, 0)) }
				'H' { $timespan = $timespan.Add([timespan]::new(0, $number, 0, 0)) }
				'D' { $timespan = $timespan.Add([timespan]::new($number, 0, 0, 0)) }
			}
		}

		$timespan
	}
}
function ConvertTo-DurationString {
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		[int]
		$InputNumber,

		[switch]
		$AsMinutes,

		[switch]
		$AsHours,

		[switch]
		$AsDays
	)

	process {
		$timespan = [timespan]::new($InputNumber, 0, 0, 0)
		if ($AsHours) { $timespan = [timespan]::new(0, $InputNumber, 0, 0) }
		if ($AsMinutes) { $timespan = [timespan]::new(0, 0, $InputNumber, 0) }

		$result = 'P'
		if ($timespan.TotalDays -lt 1) { $result = 'PT' }

		if ($timespan.Days) { $result += "$($timespan.Days)D" }
		if ($timespan.Hours) { $result += "$($timespan.Hours)H" }
		if ($timespan.Minutes) { $result += "$($timespan.Minutes)M" }

		$result
	}
}
#endregion PIM API

#region PowerShell Internals
function Set-Property {
	<#
	.SYNOPSIS
		Sets the property on an object, whether that property exists or not.
	
	.DESCRIPTION
		Sets the property on an object, whether that property exists or not.
		Calls Add-Member to add the property in case of need.
	
	.PARAMETER InputObject
		The object to set the property on.
	
	.PARAMETER Property
		Name of the property to set.
	
	.PARAMETER Value
		The Value to apply.
	
	.PARAMETER Add
		Add the value to the property using a "+=" Operation, rather than directly assigning it.
	
	.PARAMETER DefaultValue
		The default value for the property, which is temporarily used when creating the property, before assigning the value.
		Defaults to $null
		This is primarily used to simplify scenarios, where the property must always be an array, in combination with the -Add parameter.
	
	.EXAMPLE
		PS C:\> Set-Property -InputObject $item -Property Answer -Value 42

		Ensures the object in $item has the property named "Answer", then sets it to 42.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$InputObject,

		[Parameter(Mandatory = $true)]
		[string]
		$Property,
		
		[Parameter(Mandatory = $true)]
		[AllowEmptyCollection()]
		[AllowNull()]
		$Value,

		[switch]
		$Add,

		$DefaultValue = $null
	)

	if ($InputObject.PSObject.Properties.Name -notcontains $Property) {
		Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $Property -Value $DefaultValue -Force
	}
	if ($Add) { $InputObject.$Property += $Value }
	else { $InputObject.$Property = $Value }
}
#endregion PowerShell Internals
#endregion Functions

if ($Noop) { return }
if (-not $NoConnect) { Connect-AzAccount }

foreach ($resource in $config.InScope.Resources) {
	try {
		$tasks = Get-ResourceTask -Resource $resource -Config $config
		foreach ($task in $tasks) {
			switch ($task.Type) {
				Config { Invoke-ConfigTask -Task $task }
				Notification { Invoke-NotificationTask -Task $task }
				<#
				Not Implemented:
				AddAssignment { Add-RoleAssignment -Task $task }
				RemoveAssignment { Remove-RoleAssignment -Task $task }
				UpdateAssignment { Update-RoleAssignment -Task $task }
				#>
				default { Write-Warning "Unexpected Task Type: $($task.Type) for resource '$($task.Resource)'" }
			}
		}
	}
	catch {
		Write-Warning "Error processing $resource : $_"
	}
}