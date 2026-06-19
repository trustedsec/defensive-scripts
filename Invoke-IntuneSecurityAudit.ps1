#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Intune Security Posture Audit Module
.DESCRIPTION
    Advanced functions for auditing and hardening Microsoft Intune environments.
    Companion tooling for the blog series: "The Stryker Attack and the Privileged Roles Nobody Talks About"
.AUTHOR
    Carlos Perez - TrustedSec
.NOTES
    Requires Microsoft Graph PowerShell SDK: Install-Module Microsoft.Graph -Scope CurrentUser
    Run Connect-IntuneSecurityAudit before calling any other function.
#>

function Connect-IntuneSecurityAudit {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the scopes required for the Intune security audit functions.
    .DESCRIPTION
        Establishes a Microsoft Graph session with read-only scopes needed for enumeration and auditing.
        If you need write permissions for configuration changes, use the -IncludeWriteScopes switch.
    .PARAMETER IncludeWriteScopes
        Adds ReadWrite scopes for PIM, Conditional Access, and device management configuration.
        Only use this when you are ready to make changes.
    .EXAMPLE
        Connect-IntuneSecurityAudit -Verbose
    .EXAMPLE
        Connect-IntuneSecurityAudit -IncludeWriteScopes -Verbose
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeWriteScopes
    )

    $ReadScopes = @(
        "RoleManagement.Read.Directory",
        "Application.Read.All",
        "User.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementServiceConfig.Read.All",
        "DeviceManagementRBAC.Read.All",
        "AuditLog.Read.All",
        "Directory.Read.All",
        "UserAuthenticationMethod.Read.All",
        "Policy.Read.All"
    )

    $WriteScopes = @(
        "RoleManagement.ReadWrite.Directory",
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementRBAC.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess"
    )

    $Scopes = if ($IncludeWriteScopes) {
        Write-Verbose "Including write scopes for configuration changes"
        $ReadScopes + $WriteScopes | Select-Object -Unique
    } else {
        Write-Verbose "Using read-only scopes for audit operations"
        $ReadScopes
    }

    Write-Verbose "Connecting to Microsoft Graph with $($Scopes.Count) scopes"
    Connect-MgGraph -Scopes $Scopes
    Write-Verbose "Connected successfully. Tenant: $((Get-MgContext).TenantId)"
}


function Get-EntraPrivilegedRoleAssignment {
    <#
    .SYNOPSIS
        Enumerates Entra ID role assignments for Intune-critical privileged roles.
    .DESCRIPTION
        Retrieves all active members of specified Entra ID directory roles. By default, audits
        Global Administrator, Intune Administrator, Cloud Device Administrator, Security Administrator,
        and Conditional Access Administrator. Returns objects suitable for pipeline and Export-Csv.
    .PARAMETER RoleNames
        Array of Entra ID role display names to audit. Defaults to the five Intune-critical roles.
    .EXAMPLE
        Get-EntraPrivilegedRoleAssignment -Verbose
    .EXAMPLE
        Get-EntraPrivilegedRoleAssignment -RoleNames "Global Administrator","Intune Administrator" | Export-Csv -Path .\RoleAudit.csv
    #>
    [CmdletBinding()]
    param(
        [string[]]$RoleNames = @(
            "Global Administrator",
            "Intune Administrator",
            "Cloud Device Administrator",
            "Security Administrator",
            "Conditional Access Administrator"
        )
    )

    foreach ($RoleName in $RoleNames) {
        Write-Verbose "Querying role: $RoleName"
        $Role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue

        if (-not $Role) {
            Write-Verbose "  Role '$RoleName' not found or not activated in this tenant"
            continue
        }

        $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id
        Write-Verbose "  Found $($Members.Count) members assigned to $RoleName"

        foreach ($Member in $Members) {
            $User = Get-MgUser -UserId $Member.Id -Property DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime -ErrorAction SilentlyContinue
            if ($User) {
                [PSCustomObject]@{
                    Role            = $RoleName
                    DisplayName     = $User.DisplayName
                    UPN             = $User.UserPrincipalName
                    Enabled         = $User.AccountEnabled
                    UserType        = $User.UserType
                    AccountCreated  = $User.CreatedDateTime
                }
            }
        }
    }
}


function Get-IntunePIMAssignment {
    <#
    .SYNOPSIS
        Compares permanent (active) vs PIM-eligible role assignments for a specified Entra ID role.
    .DESCRIPTION
        Retrieves both active (permanent) and eligible (PIM-managed) assignments for a given role,
        allowing you to identify accounts that should be converted from permanent to eligible.
        Requires Entra ID P2 licensing for PIM eligibility schedule queries.
    .PARAMETER RoleName
        Display name of the Entra ID role to audit. Defaults to "Intune Administrator".
    .EXAMPLE
        Get-IntunePIMAssignment -Verbose
    .EXAMPLE
        Get-IntunePIMAssignment -RoleName "Global Administrator" | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName = "Intune Administrator"
    )

    Write-Verbose "Resolving role definition ID for: $RoleName"
    $RoleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue

    if (-not $RoleDef) {
        Write-Warning "Role definition not found for '$RoleName'"
        return
    }

    $RoleId = $RoleDef.Id
    Write-Verbose "Role ID: $RoleId"

    Write-Verbose "Querying active (permanent) assignments"
    $ActiveAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$RoleId'" -ErrorAction SilentlyContinue
    Write-Verbose "  Found $($ActiveAssignments.Count) active assignments"

    foreach ($Assignment in $ActiveAssignments) {
        $Principal = Get-MgDirectoryObject -DirectoryObjectId $Assignment.PrincipalId -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            RoleName       = $RoleName
            PrincipalName  = $Principal.AdditionalProperties.displayName
            PrincipalId    = $Assignment.PrincipalId
            AssignmentType = "Active (Permanent)"
            StartDateTime  = $null
            Expiration     = $null
        }
    }

    Write-Verbose "Querying eligible (PIM-managed) assignments"
    $EligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '$RoleId'" -ErrorAction SilentlyContinue
    Write-Verbose "  Found $($EligibleAssignments.Count) eligible assignments"

    foreach ($Assignment in $EligibleAssignments) {
        $Principal = Get-MgDirectoryObject -DirectoryObjectId $Assignment.PrincipalId -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            RoleName       = $RoleName
            PrincipalName  = $Principal.AdditionalProperties.displayName
            PrincipalId    = $Assignment.PrincipalId
            AssignmentType = "Eligible (PIM)"
            StartDateTime  = $Assignment.ScheduleInfo.StartDateTime
            Expiration     = $Assignment.ScheduleInfo.Expiration.EndDateTime
        }
    }
}


function Get-IntuneRBACAssignment {
    <#
    .SYNOPSIS
        Lists all Intune RBAC role definitions and their assignments.
    .DESCRIPTION
        Retrieves every built-in and custom Intune RBAC role along with its assignments,
        scope type, and scope members. Use this to identify overly broad assignments
        (e.g., "All Devices" or "All Users" scope groups).
    .EXAMPLE
        Get-IntuneRBACAssignment -Verbose
    .EXAMPLE
        Get-IntuneRBACAssignment | Where-Object { $_.ScopeType -eq 'allDevicesAndLicensedUsers' } | Format-Table
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Retrieving Intune RBAC role definitions"
    $RoleDefs = Get-MgDeviceManagementRoleDefinition
    Write-Verbose "  Found $($RoleDefs.Count) role definitions ($($($RoleDefs | Where-Object IsBuiltIn).Count) built-in, $($($RoleDefs | Where-Object {-not $_.IsBuiltIn}).Count) custom)"

    Write-Verbose "Retrieving role assignments"
    $Assignments = Get-MgDeviceManagementRoleAssignment

    foreach ($Assignment in $Assignments) {
        $RoleDef = $RoleDefs | Where-Object { $_.Id -eq $Assignment.RoleDefinitionId }
        Write-Verbose "  Processing assignment for role: $($RoleDef.DisplayName)"

        [PSCustomObject]@{
            RoleName     = $RoleDef.DisplayName
            IsBuiltIn    = $RoleDef.IsBuiltIn
            Description  = $Assignment.Description
            ScopeType    = $Assignment.ScopeType
            ScopeMembers = ($Assignment.ScopeMembers -join "; ")
        }
    }
}


function Get-IntuneAppRegistration {
    <#
    .SYNOPSIS
        Finds Entra ID app registrations with Intune-scoped Microsoft Graph API permissions.
    .DESCRIPTION
        Scans all app registrations in the tenant for dangerous DeviceManagement* Graph API permissions.
        Returns each flagged app with its permissions, creation date, and credential expiry status.
        These app registrations are effectively Intune control planes and represent a common blind spot.
    .PARAMETER IncludeReadOnly
        Also flag app registrations with read-only DeviceManagement permissions. By default,
        only ReadWrite and PrivilegedOperations permissions are flagged.
    .EXAMPLE
        Get-IntuneAppRegistration -Verbose
    .EXAMPLE
        Get-IntuneAppRegistration -IncludeReadOnly | Export-Csv -Path .\AppRegistrations.csv
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeReadOnly
    )

    $DangerousPermissions = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "DeviceManagementServiceConfig.ReadWrite.All",
        "DeviceManagementApps.ReadWrite.All",
        "DeviceManagementManagedDevices.PrivilegedOperations.All"
    )

    if ($IncludeReadOnly) {
        Write-Verbose "Including read-only DeviceManagement permissions in scan"
        $DangerousPermissions += @(
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementServiceConfig.Read.All",
            "DeviceManagementApps.Read.All"
        )
    }

    Write-Verbose "Resolving Microsoft Graph service principal for permission ID lookups"
    $GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $GraphPerms = $GraphSP.AppRoles + $GraphSP.Oauth2PermissionScopes

    Write-Verbose "Enumerating all app registrations in tenant"
    $Apps = Get-MgApplication -All
    Write-Verbose "  Found $($Apps.Count) total app registrations"

    $FlaggedCount = 0
    foreach ($App in $Apps) {
        $MatchedPerms = @()

        foreach ($RequiredAccess in $App.RequiredResourceAccess) {
            if ($RequiredAccess.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {
                foreach ($Perm in $RequiredAccess.ResourceAccess) {
                    $PermDef = $GraphPerms | Where-Object { $_.Id -eq $Perm.Id }
                    if ($PermDef.Value -in $DangerousPermissions) {
                        $MatchedPerms += "$($PermDef.Value) ($($Perm.Type))"
                    }
                }
            }
        }

        if ($MatchedPerms.Count -gt 0) {
            $FlaggedCount++
            Write-Verbose "  FLAGGED: $($App.DisplayName) with $($MatchedPerms.Count) Intune permissions"

            $LatestSecretExpiry = ($App.PasswordCredentials | Sort-Object EndDateTime -Descending | Select-Object -First 1).EndDateTime
            $LatestCertExpiry   = ($App.KeyCredentials | Sort-Object EndDateTime -Descending | Select-Object -First 1).EndDateTime
            $HasCredentials     = ($App.PasswordCredentials.Count -gt 0) -or ($App.KeyCredentials.Count -gt 0)

            [PSCustomObject]@{
                AppName           = $App.DisplayName
                AppId             = $App.AppId
                ObjectId          = $App.Id
                CreatedDate       = $App.CreatedDateTime
                Permissions       = ($MatchedPerms -join "; ")
                PermissionCount   = $MatchedPerms.Count
                HasCredentials    = $HasCredentials
                LatestSecretExpiry = $LatestSecretExpiry
                LatestCertExpiry  = $LatestCertExpiry
                SecretCount       = $App.PasswordCredentials.Count
                CertCount         = $App.KeyCredentials.Count
            }
        }
    }

    Write-Verbose "Scan complete: $FlaggedCount of $($Apps.Count) app registrations flagged with Intune permissions"
}


function Get-IntuneAppCredentialStatus {
    <#
    .SYNOPSIS
        Audits credential (secret and certificate) expiry status for specified app registrations.
    .DESCRIPTION
        Accepts app registrations from the pipeline (output of Get-IntuneAppRegistration) or by AppId,
        and returns detailed credential status including days to expiry and risk classification.
    .PARAMETER AppId
        The Application (client) ID to audit. Accepts pipeline input from Get-IntuneAppRegistration.
    .EXAMPLE
        Get-IntuneAppRegistration | Get-IntuneAppCredentialStatus -Verbose
    .EXAMPLE
        Get-IntuneAppCredentialStatus -AppId "00000000-0000-0000-0000-000000000000" -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$AppId
    )

    process {
        Write-Verbose "Auditing credentials for app: $AppId"
        $AppDetail = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue

        if (-not $AppDetail) {
            Write-Warning "App registration not found for AppId: $AppId"
            return
        }

        Write-Verbose "  App: $($AppDetail.DisplayName)"

        foreach ($Secret in $AppDetail.PasswordCredentials) {
            $DaysToExpiry = (New-TimeSpan -Start (Get-Date) -End $Secret.EndDateTime).Days
            $Status = switch ($true) {
                ($DaysToExpiry -lt 0)   { "EXPIRED" }
                ($DaysToExpiry -lt 30)  { "EXPIRING_SOON" }
                ($DaysToExpiry -lt 90)  { "ROTATE_RECOMMENDED" }
                default                 { "Active" }
            }
            Write-Verbose "  Secret '$($Secret.Hint)...' expires in $DaysToExpiry days ($Status)"

            [PSCustomObject]@{
                AppName     = $AppDetail.DisplayName
                AppId       = $AppId
                Type        = "Secret"
                Identifier  = $Secret.Hint
                Created     = $Secret.StartDateTime
                Expires     = $Secret.EndDateTime
                DaysLeft    = $DaysToExpiry
                Status      = $Status
            }
        }

        foreach ($Cert in $AppDetail.KeyCredentials) {
            $DaysToExpiry = (New-TimeSpan -Start (Get-Date) -End $Cert.EndDateTime).Days
            $Status = switch ($true) {
                ($DaysToExpiry -lt 0)   { "EXPIRED" }
                ($DaysToExpiry -lt 30)  { "EXPIRING_SOON" }
                ($DaysToExpiry -lt 90)  { "ROTATE_RECOMMENDED" }
                default                 { "Active" }
            }
            Write-Verbose "  Certificate '$($Cert.DisplayName)' expires in $DaysToExpiry days ($Status)"

            [PSCustomObject]@{
                AppName     = $AppDetail.DisplayName
                AppId       = $AppId
                Type        = "Certificate"
                Identifier  = $Cert.DisplayName
                Created     = $Cert.StartDateTime
                Expires     = $Cert.EndDateTime
                DaysLeft    = $DaysToExpiry
                Status      = $Status
            }
        }

        if (-not $AppDetail.PasswordCredentials -and -not $AppDetail.KeyCredentials) {
            Write-Verbose "  WARNING: No credentials configured (orphaned registration)"
            [PSCustomObject]@{
                AppName     = $AppDetail.DisplayName
                AppId       = $AppId
                Type        = "NONE"
                Identifier  = "No credentials configured"
                Created     = $null
                Expires     = $null
                DaysLeft    = $null
                Status      = "ORPHANED"
            }
        }
    }
}


function Get-AdminPhishingResistantMFA {
    <#
    .SYNOPSIS
        Audits authentication methods for Intune administrators and flags accounts lacking phishing-resistant MFA.
    .DESCRIPTION
        Retrieves registered authentication methods for each member of a specified admin group and
        determines whether at least one phishing-resistant method (FIDO2, Windows Hello for Business,
        or platform credential) is registered. Accounts without phishing-resistant methods need
        FIDO2 keys issued before enforcing authentication strength policies.
    .PARAMETER AdminGroupName
        Display name of the Entra ID security group containing Intune administrators.
        Defaults to "Intune Administrators".
    .EXAMPLE
        Get-AdminPhishingResistantMFA -Verbose
    .EXAMPLE
        Get-AdminPhishingResistantMFA -AdminGroupName "Tier0 Admins" | Where-Object { -not $_.HasPhishResistant }
    #>
    [CmdletBinding()]
    param(
        [string]$AdminGroupName = "Intune Administrators"
    )

    Write-Verbose "Resolving admin group: $AdminGroupName"
    $AdminGroup = Get-MgGroup -Filter "displayName eq '$AdminGroupName'" -ErrorAction SilentlyContinue

    if (-not $AdminGroup) {
        Write-Warning "Group '$AdminGroupName' not found. Verify the group name and try again."
        return
    }

    $AdminMembers = Get-MgGroupMember -GroupId $AdminGroup.Id
    Write-Verbose "  Found $($AdminMembers.Count) members in $AdminGroupName"

    $PhishResistantTypes = @(
        '#microsoft.graph.fido2AuthenticationMethod',
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
        '#microsoft.graph.platformCredentialAuthenticationMethod'
    )

    foreach ($Member in $AdminMembers) {
        $User = Get-MgUser -UserId $Member.Id -Property DisplayName,UserPrincipalName -ErrorAction SilentlyContinue
        if (-not $User) { continue }

        Write-Verbose "  Checking MFA methods for: $($User.UserPrincipalName)"
        $Methods = Get-MgUserAuthenticationMethod -UserId $Member.Id -ErrorAction SilentlyContinue

        $PhishResistant = $Methods | Where-Object {
            $_.AdditionalProperties.'@odata.type' -in $PhishResistantTypes
        }

        $MethodTypes = ($PhishResistant | ForEach-Object {
            $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', ''
        }) -join ", "

        $HasPhishResistant = $PhishResistant.Count -gt 0
        if (-not $HasPhishResistant) {
            Write-Verbose "    WARNING: No phishing-resistant method registered"
        } else {
            Write-Verbose "    Phishing-resistant methods: $MethodTypes"
        }

        [PSCustomObject]@{
            Admin              = $User.DisplayName
            UPN                = $User.UserPrincipalName
            TotalMethods       = $Methods.Count
            HasPhishResistant  = $HasPhishResistant
            PhishResistantType = $MethodTypes
        }
    }
}


function Get-IntuneScriptInventory {
    <#
    .SYNOPSIS
        Lists all PowerShell and Shell scripts deployed through Intune with content preview.
    .DESCRIPTION
        Retrieves every deviceManagementScript from the Intune tenant via the Graph Beta API,
        decodes the Base64-encoded script content, and returns an inventory with a configurable
        content preview length. Use this to identify unknown or unauthorized script deployments.
    .PARAMETER PreviewLength
        Number of characters to include in the script content preview. Defaults to 500.
        Set to 0 to omit the preview, or -1 to include the full script content.
    .EXAMPLE
        Get-IntuneScriptInventory -Verbose
    .EXAMPLE
        Get-IntuneScriptInventory -PreviewLength 1000 | Export-Csv -Path .\ScriptInventory.csv
    .EXAMPLE
        Get-IntuneScriptInventory -PreviewLength -1 | ForEach-Object { $_.ScriptContent | Set-Content ".\scripts\$($_.FileName)" }
    #>
    [CmdletBinding()]
    param(
        [int]$PreviewLength = 500
    )

    Write-Verbose "Retrieving Intune management scripts via Graph Beta API"
    $ScriptsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -ErrorAction SilentlyContinue

    if (-not $ScriptsResponse -or -not $ScriptsResponse.value) {
        Write-Verbose "No management scripts found in this tenant"
        return
    }

    Write-Verbose "  Found $($ScriptsResponse.value.Count) deployed scripts"

    foreach ($Script in $ScriptsResponse.value) {
        Write-Verbose "  Processing: $($Script.displayName) ($($Script.fileName))"

        $Detail = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($Script.id)" `
            -ErrorAction SilentlyContinue

        $DecodedContent = $null
        if ($Detail.scriptContent) {
            try {
                $DecodedContent = [System.Text.Encoding]::UTF8.GetString(
                    [System.Convert]::FromBase64String($Detail.scriptContent)
                )
            } catch {
                Write-Verbose "    WARNING: Failed to decode script content for $($Script.displayName)"
                $DecodedContent = "[DECODE_ERROR]"
            }
        }

        $ContentPreview = if ($PreviewLength -eq 0) {
            "[preview omitted]"
        } elseif ($PreviewLength -lt 0 -or $DecodedContent.Length -le $PreviewLength) {
            $DecodedContent
        } else {
            $DecodedContent.Substring(0, $PreviewLength) + "... [TRUNCATED]"
        }

        [PSCustomObject]@{
            DisplayName     = $Script.displayName
            FileName        = $Script.fileName
            RunAsAccount    = $Script.runAsAccount
            EnforceSignature = $Script.enforceSignatureCheck
            CreatedDateTime = $Script.createdDateTime
            LastModified    = $Script.lastModifiedDateTime
            ScriptId        = $Script.id
            ScriptContent   = $ContentPreview
        }
    }
}


function Get-IntuneWin32AppInventory {
    <#
    .SYNOPSIS
        Lists all Win32 (LOB) applications deployed through Intune.
    .DESCRIPTION
        Retrieves Win32LobApp entries from the Intune tenant, including install command lines
        and publisher information. Use this to identify unauthorized deployments or LOLBin packaging.
    .EXAMPLE
        Get-IntuneWin32AppInventory -Verbose
    .EXAMPLE
        Get-IntuneWin32AppInventory | Where-Object { $_.InstallCmd -match 'certutil|mshta|wscript|cscript' }
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Retrieving Win32 LOB applications from Intune"
    $Win32Apps = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isof('microsoft.graph.win32LobApp')" `
        -ErrorAction SilentlyContinue

    if (-not $Win32Apps -or -not $Win32Apps.value) {
        Write-Verbose "No Win32 LOB applications found in this tenant"
        return
    }

    Write-Verbose "  Found $($Win32Apps.value.Count) Win32 applications"

    foreach ($App in $Win32Apps.value) {
        Write-Verbose "  Processing: $($App.displayName)"

        [PSCustomObject]@{
            DisplayName     = $App.displayName
            Publisher       = $App.publisher
            FileName        = $App.fileName
            InstallCmd      = $App.installCommandLine
            UninstallCmd    = $App.uninstallCommandLine
            CreatedDateTime = $App.createdDateTime
            LastModified    = $App.lastModifiedDateTime
        }
    }
}


function Get-IntuneEnrollmentConfig {
    <#
    .SYNOPSIS
        Retrieves current Intune device enrollment restrictions and per-user device limits.
    .DESCRIPTION
        Lists all enrollment configuration profiles including platform restrictions, device limit
        restrictions, and Enrollment Status Page configurations. Use this to verify that enrollment
        is locked down to authorized groups with appropriate device limits.
    .EXAMPLE
        Get-IntuneEnrollmentConfig -Verbose
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Retrieving device enrollment configurations"
    $Configs = Get-MgDeviceManagementDeviceEnrollmentConfiguration

    if (-not $Configs) {
        Write-Verbose "No enrollment configurations found"
        return
    }

    Write-Verbose "  Found $($Configs.Count) enrollment configurations"

    foreach ($Config in $Configs) {
        $ConfigType = $Config.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
        Write-Verbose "  Processing: $($Config.DisplayName) ($ConfigType)"

        $DeviceLimit = $null
        if ($ConfigType -like '*deviceEnrollmentLimitConfiguration*') {
            $DeviceLimit = $Config.AdditionalProperties.limit
            Write-Verbose "    Per-user device limit: $DeviceLimit"
        }

        [PSCustomObject]@{
            DisplayName     = $Config.DisplayName
            ConfigType      = $ConfigType
            Priority        = $Config.Priority
            DeviceLimit     = $DeviceLimit
            CreatedDateTime = $Config.CreatedDateTime
            LastModified    = $Config.LastModifiedDateTime
        }
    }
}


function Get-IntuneManagedDeviceInventory {
    <#
    .SYNOPSIS
        Exports a full inventory of Intune-enrolled devices with compliance status.
    .DESCRIPTION
        Retrieves all managed devices and exports them to CSV. Includes a summary of device counts
        by operating system and compliance state. Use this to identify unknown devices, non-compliant
        endpoints, and unexpected enrollment patterns.
    .PARAMETER ExportPath
        File path for the CSV export. Defaults to ".\IntuneDeviceInventory.csv".
    .PARAMETER NoExport
        Skip CSV export and only return objects to the pipeline.
    .EXAMPLE
        Get-IntuneManagedDeviceInventory -Verbose
    .EXAMPLE
        Get-IntuneManagedDeviceInventory -ExportPath "C:\Audits\devices.csv" -Verbose
    .EXAMPLE
        Get-IntuneManagedDeviceInventory -NoExport | Where-Object { $_.ComplianceState -ne 'compliant' }
    #>
    [CmdletBinding()]
    param(
        [string]$ExportPath = ".\IntuneDeviceInventory.csv",
        [switch]$NoExport
    )

    Write-Verbose "Retrieving all managed devices from Intune"
    $Devices = Get-MgDeviceManagementManagedDevice -All

    if (-not $Devices) {
        Write-Verbose "No managed devices found"
        return
    }

    Write-Verbose "  Total enrolled devices: $($Devices.Count)"

    $OSGroups = $Devices | Group-Object OperatingSystem
    foreach ($Group in $OSGroups) {
        Write-Verbose "    $($Group.Name): $($Group.Count) devices"
    }

    $ComplianceGroups = $Devices | Group-Object ComplianceState
    foreach ($Group in $ComplianceGroups) {
        Write-Verbose "    Compliance - $($Group.Name): $($Group.Count) devices"
    }

    $Results = $Devices | Select-Object DeviceName, UserPrincipalName, OperatingSystem,
        ManagementAgent, EnrolledDateTime, ComplianceState, SerialNumber,
        Manufacturer, Model | Sort-Object EnrolledDateTime -Descending

    if (-not $NoExport) {
        $Results | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Verbose "  Device inventory exported to: $ExportPath"
    }

    $Results
}


function Get-IntuneAutopilotDevice {
    <#
    .SYNOPSIS
        Lists all Windows Autopilot registered devices.
    .DESCRIPTION
        Retrieves Autopilot device identities including serial numbers, hardware hashes,
        group tags, and enrollment state. Use this to verify that only authorized devices
        are pre-registered for Autopilot enrollment.
    .EXAMPLE
        Get-IntuneAutopilotDevice -Verbose
    .EXAMPLE
        Get-IntuneAutopilotDevice | Where-Object { -not $_.GroupTag } | Format-Table
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Retrieving Windows Autopilot device identities"
    $AutopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction SilentlyContinue

    if (-not $AutopilotDevices) {
        Write-Verbose "No Autopilot devices found"
        return
    }

    Write-Verbose "  Found $($AutopilotDevices.Count) Autopilot registered devices"

    foreach ($Device in $AutopilotDevices) {
        [PSCustomObject]@{
            SerialNumber        = $Device.SerialNumber
            Model               = $Device.Model
            Manufacturer        = $Device.Manufacturer
            GroupTag             = $Device.GroupTag
            EnrollmentState     = $Device.EnrollmentState
            LastContactedDate   = $Device.LastContactedDateTime
            PurchaseOrderId     = $Device.PurchaseOrderIdentifier
        }
    }
}


function Invoke-IntuneSecurityAudit {
    <#
    .SYNOPSIS
        Runs a comprehensive Intune security posture audit and exports results to CSV files.
    .DESCRIPTION
        Combines all audit functions into a single execution that produces a timestamped output
        directory with CSV files covering: Entra role assignments, PIM status, Intune RBAC,
        app registrations with Intune permissions, admin MFA methods, deployed scripts,
        enrolled devices, and enrollment configuration.

        Run this before beginning the hardening implementation to establish a baseline.
    .PARAMETER OutputDirectory
        Base path for the output directory. A timestamped subdirectory is created automatically.
        Defaults to the current directory.
    .PARAMETER AdminGroupName
        Display name of the Entra ID security group containing Intune administrators.
        Used for the MFA audit. Defaults to "Intune Administrators".
    .EXAMPLE
        Invoke-IntuneSecurityAudit -Verbose
    .EXAMPLE
        Invoke-IntuneSecurityAudit -OutputDirectory "C:\Audits" -AdminGroupName "Tier0 Admins" -Verbose
    #>
    [CmdletBinding()]
    param(
        [string]$OutputDirectory = ".",
        [string]$AdminGroupName = "Intune Administrators"
    )

    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputDir = Join-Path $OutputDirectory "IntuneAudit_$Timestamp"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Verbose "Audit output directory: $OutputDir"

    # 1. Entra ID Privileged Role Assignments
    Write-Verbose "=== Step 1/8: Entra ID Privileged Role Assignments ==="
    $RoleResults = Get-EntraPrivilegedRoleAssignment -Verbose:$VerbosePreference
    $RoleResults | Export-Csv "$OutputDir\01_EntraRoleAssignments.csv" -NoTypeInformation
    Write-Verbose "  Exported $($RoleResults.Count) role assignments"

    # 2. PIM Assignment Status
    Write-Verbose "=== Step 2/8: PIM Assignment Status ==="
    $PIMRoles = @("Global Administrator", "Intune Administrator", "Security Administrator")
    $PIMResults = foreach ($Role in $PIMRoles) {
        Get-IntunePIMAssignment -RoleName $Role -Verbose:$VerbosePreference
    }
    $PIMResults | Export-Csv "$OutputDir\02_PIMAssignments.csv" -NoTypeInformation
    Write-Verbose "  Exported $($PIMResults.Count) PIM assignments"

    # 3. Intune RBAC Assignments
    Write-Verbose "=== Step 3/8: Intune RBAC Assignments ==="
    $RBACResults = Get-IntuneRBACAssignment -Verbose:$VerbosePreference
    $RBACResults | Export-Csv "$OutputDir\03_IntuneRBACAssignments.csv" -NoTypeInformation
    Write-Verbose "  Exported $($RBACResults.Count) RBAC assignments"

    # 4. App Registrations with Intune Permissions
    Write-Verbose "=== Step 4/8: App Registrations with Intune Permissions ==="
    $AppResults = Get-IntuneAppRegistration -Verbose:$VerbosePreference
    $AppResults | Export-Csv "$OutputDir\04_IntuneAppRegistrations.csv" -NoTypeInformation
    Write-Verbose "  Exported $($AppResults.Count) flagged app registrations"

    # 5. Admin MFA Method Audit
    Write-Verbose "=== Step 5/8: Admin MFA Method Audit ==="
    $MFAResults = Get-AdminPhishingResistantMFA -AdminGroupName $AdminGroupName -Verbose:$VerbosePreference
    $MFAResults | Export-Csv "$OutputDir\05_AdminMFAMethods.csv" -NoTypeInformation
    $AtRisk = ($MFAResults | Where-Object { -not $_.HasPhishResistant }).Count
    Write-Verbose "  $AtRisk admins lack phishing-resistant MFA"

    # 6. Intune Scripts Inventory
    Write-Verbose "=== Step 6/8: Intune Scripts Inventory ==="
    $ScriptResults = Get-IntuneScriptInventory -PreviewLength 500 -Verbose:$VerbosePreference
    $ScriptResults | Export-Csv "$OutputDir\06_IntuneScripts.csv" -NoTypeInformation
    Write-Verbose "  Exported $($ScriptResults.Count) deployed scripts"

    # 7. Enrolled Devices
    Write-Verbose "=== Step 7/8: Enrolled Devices ==="
    $DevicePath = Join-Path $OutputDir "07_EnrolledDevices.csv"
    $DeviceResults = Get-IntuneManagedDeviceInventory -ExportPath $DevicePath -Verbose:$VerbosePreference
    Write-Verbose "  Exported $($DeviceResults.Count) enrolled devices"

    # 8. Enrollment Configuration
    Write-Verbose "=== Step 8/8: Enrollment Configuration ==="
    $EnrollResults = Get-IntuneEnrollmentConfig -Verbose:$VerbosePreference
    $EnrollResults | Export-Csv "$OutputDir\08_EnrollmentConfig.csv" -NoTypeInformation
    Write-Verbose "  Exported $($EnrollResults.Count) enrollment configurations"

    # Summary
    Write-Verbose "============================================"
    Write-Verbose "AUDIT COMPLETE"
    Write-Verbose "Results exported to: $OutputDir"
    Write-Verbose "============================================"
    Write-Verbose "Key findings to review:"
    Write-Verbose "  - Permanent role assignments (01/02 CSVs)"
    Write-Verbose "  - App registrations with Intune write permissions (04 CSV)"
    Write-Verbose "  - Admins without phishing-resistant MFA (05 CSV): $AtRisk at risk"
    Write-Verbose "  - Unknown scripts in fleet (06 CSV): $($ScriptResults.Count) total"
    Write-Verbose "  - Non-compliant devices (07 CSV)"

    [PSCustomObject]@{
        OutputDirectory        = $OutputDir
        TotalRoleAssignments   = $RoleResults.Count
        TotalPIMAssignments    = $PIMResults.Count
        TotalRBACAssignments   = $RBACResults.Count
        FlaggedAppRegistrations = $AppResults.Count
        AdminsMissingPhishMFA  = $AtRisk
        DeployedScripts        = $ScriptResults.Count
        EnrolledDevices        = $DeviceResults.Count
        EnrollmentConfigs      = $EnrollResults.Count
    }
}
