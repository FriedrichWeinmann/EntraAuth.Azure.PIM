#requires -Modules Az.Accounts
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string[]]
	$Resource,

	[Parameter(Mandatory = $true)]
	[string]
	$Group,

	[Parameter(Mandatory = $true)]
	[string]
	$Role,

	[int]
	$Duration = 365,

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

#region Functions

#region AzureRM API
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

function Set-AzPimResourceRoleEligibility {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[Parameter(Mandatory = $true)]
		[string]
		$Principal,

		[Parameter(Mandatory = $true)]
		[string]
		$Role,

		[int]
		$Duration
	)

	$body = @{
		properties = @{
			roleDefinitionId = "/subscriptions/$Resource/providers/Microsoft.Authorization/roleDefinitions/$Role"
			principalId      = $Principal
			requestType      = "AdminAssign"
			scheduleInfo     = @{
				startDateTime = (Get-Date).ToString("o")
				expiration    = @{
					type        = "AfterDuration"
					duration    = "P$($Duration)D"
					endDateTime = $null
				}
			}
		}
	}
	$null = Invoke-AzPimRequest -Method Put -Request "$Resource/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$Role" -ApiVersion '2020-10-01' -Body $body
}
#endregion AzureRM API
#region Graph API
function Resolve-GraphGroupID {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Group
	)

	if ($Group -as [guid]) { return $Group }

	if (-not $script:_GroupCache) { $script:_GroupCache = @{ } }
	if ($script:_GroupCache[$Group]) { return $script:_GroupCache[$Group] }

	$graphAuthHeader = Get-GraphAuthHeader
	$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$Group'" -Headers $graphAuthHeader
	if ($response.value.Count -lt 1) {
		throw "Group not found: $Group"
	}
	if ($response.value.Count -gt 1) {
		Write-Warning "Ambiguous result, group $Group does not resolve to a single group! Try again while specifying a the group ID!"
		foreach ($entry in $response.value) {
			Write-Warning "  $($entry.id) | Created: $($entry.createdDateTime) | DN: $($entry.displayName)"
		}
		throw "Ambiguous result, group $Group does not resolve to a single group! Try again while specifying a the group ID!"
	}
	
	$script:_GroupCache[$Group] = $response.value.id
	$response.value.id
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
#endregion Functions

if ($Noop) { return }
if (-not $NoConnect) { Connect-AzAccount }

$groupID = Resolve-GraphGroupID -Group $Group
foreach ($resourceEntry in $Resource) {
	$roleObject = Get-AzPimResourceRole -Resource $resourceEntry | Where-Object {
		$_.ID -eq $Role -or
		$_.Name -eq $Role
	}
	if (-not $roleObject) {
		Write-Error "Role $Role not found on $resourceEntry"
		continue
	}
	Set-AzPimResourceRoleEligibility -Resource $resourceEntry -Principal $groupID -Role $roleObject.ID -Duration $Duration
}