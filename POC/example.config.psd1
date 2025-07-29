@{
	InScope       = @{
		Resources                                                            = @(
			'00000000-1111-2222-3333-444444444444'
			'00000000-1111-2222-3333-444444444444/resourcegroups/rg_office_test'
		)
		Roles                                                                = @(
			'Reader'
			'Contributor'
		)

		# Example: Roles override for a specific resource
		'00000000-1111-2222-3333-444444444444/resourcegroups/rg_office_test' = @(
			'AcrPush'
			'Reader'
			'Contributor'
		)
	}
	Roles         = @{
		# Global Default
		Default                                                              = @{
			MaxDuration      = 480 # 8 Hours
			RequireMFA       = $true
			Justification    = $true
			Ticket           = $false
			Approver         = @()

			EligibleDuration = -1 # -1 = Permanent
			ActiveDuration   = 365 # -1 = Permanent
		}
		# Per Role Default
		Contributor                                                          = @{
			MaxDuration      = 480 # 8 Hours
			RequireMFA       = $true
			Justification    = $true
			Ticket           = $true
			Approver         = @('5a7211f2-2c60-4510-a48e-f8623e647310')

			EligibleDuration = 365 # -1 = Permanent
			ActiveDuration   = 180 # -1 = Permanent
		}
		# Resource Specific
		'00000000-1111-2222-3333-444444444444/resourcegroups/rg_office_test' = @{
			Default = @{
				MaxDuration      = 450 # 8 Hours
				RequireMFA       = $false
				# Justification = $false
				# Ticket = $false
				Approver         = @(
					'5a7211f2-2c60-4510-a48e-f8623e647310' # Admin
					'5fbd2948-5cf5-469a-bd33-2bbb06bea22f' # Adele Vance
				)

				EligibleDuration = -1 # -1 = Permanent
				ActiveDuration   = -1 # -1 = Permanent
			}
		}
	}
	Notifications = @{
		Default                                                              = @{
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
		<#
		Overrides:

		# Override defaults for all instances of this one role
		<Role> = @{} 

		# Override defaults for a specific resource ...
		<Resource> = @{
			# ... For all roles in this resource
			Default = @{}

			# ... For this specific role in this resource
			<Role> = @{}
		}
		#>
		Contributor                                                          = @{
			ActiveAssignment = @{
				AssignmentAlert = @{
					Additional = @('security.notifications@contoso.com')
				}
			}
		}
		'00000000-1111-2222-3333-444444444444/resourcegroups/rg_office_test' = @{
			Default = @{
				EligibleActivation = @{
					ActivationAlert = @{
						Default = $false
						Additional = @('office.approvers@contoso.com')
					}
				}
			}
			AcrPush = @{
				ActiveAssignment = @{
					AssignmentAlert = @{
						Additional = @()
					}
				}
			}
		}
	}

	# Not Implemented
	Assignments   = @{
		Default = @{
			# Whether this configuration is the definitive state and all other direct assignments should be deleted
			Definitive   = $true

			# For non-permanent assignments, extend them once the number of days remaining drop below this value
			ExtendBefore = 60

			# Permanently active assignments
			Active       = @(
				@{
					Name = 'Project Zero - Maintainers'
					ID   = 'fce6c35a-dbc6-4f5f-9445-b0692d567695'
					Type = 'Group'
					Role = 'Contributor'
				}
			)

			# Eligible assignments
			Eligible     = @(
				@{
					Name = 'Project Zero - Contributors'
					ID   = '973ef2fd-3b94-4987-a091-abada83cf09c'
					Type = 'Group'
					Role = 'Contributor'
				}
				@{
					Name = 'Project Zero - Readers'
					ID   = 'ba689f56-95ae-4c0f-8f38-61fbbcc5606f'
					Type = 'Group'
					Role = 'Reader'
				}
			)
		}
	}
}