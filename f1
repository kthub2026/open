<#
.SYNOPSIS
    Adds CyberArk Account Groups from a CSV file using Basic Authentication.

.DESCRIPTION
    This script reads account group definitions from a CSV file and creates them
    in CyberArk using the REST API with Basic Authentication (CyberArk authentication).

.PARAMETER PVWAURL
    The base URL of the PVWA (e.g., https://pvwa.domain.com/PasswordVault)

.PARAMETER CSVPath
    Path to the CSV file containing account group definitions.
    Required columns: GroupName, GroupPlatformID, Safe

.PARAMETER AuthType
    Authentication type. Default is "CyberArk" for basic authentication.

.EXAMPLE
    .\Add-AccountGroups.ps1 -PVWAURL "https://pvwa.domain.com/PasswordVault" -CSVPath ".\AccountGroups.csv"

.NOTES
    Author: PAM Team
    Requires: PowerShell 5.1+
    CyberArk API: Add Account Group endpoint
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PVWAURL,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CSVPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("CyberArk", "LDAP", "RADIUS")]
    [string]$AuthType = "CyberArk"
)

#region Functions

function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Type = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Type) {
        "Info"    { "White" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Success" { "Green" }
    }
    Write-Host "[$timestamp] [$Type] $Message" -ForegroundColor $color
}

function Get-AuthorizationToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PVWAURL,

        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$AuthType = "CyberArk"
    )

    $logonURL = "$PVWAURL/API/Auth/$AuthType/Logon"

    $logonBody = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
    } | ConvertTo-Json -Compress

    try {
        Write-LogMessage -Message "Authenticating to CyberArk..." -Type Info

        $response = Invoke-RestMethod -Uri $logonURL `
            -Method POST `
            -ContentType "application/json" `
            -Body $logonBody `
            -ErrorAction Stop

        Write-LogMessage -Message "Authentication successful." -Type Success
        return $response
    }
    catch {
        Write-LogMessage -Message "Authentication failed: $($_.Exception.Message)" -Type Error
        throw
    }
}

function Close-AuthorizationToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PVWAURL,

        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $logoffURL = "$PVWAURL/API/Auth/Logoff"

    try {
        Invoke-RestMethod -Uri $logoffURL `
            -Method POST `
            -Headers @{ Authorization = $Token } `
            -ContentType "application/json" `
            -ErrorAction Stop | Out-Null

        Write-LogMessage -Message "Session logged off successfully." -Type Success
    }
    catch {
        Write-LogMessage -Message "Logoff warning: $($_.Exception.Message)" -Type Warning
    }
}

function Add-AccountGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PVWAURL,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [string]$GroupPlatformID,

        [Parameter(Mandatory = $true)]
        [string]$Safe
    )

    $addGroupURL = "$PVWAURL/API/AccountGroups/"

    $body = @{
        GroupName       = $GroupName
        GroupPlatformID = $GroupPlatformID
        Safe            = $Safe
    } | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Uri $addGroupURL `
            -Method POST `
            -Headers @{ Authorization = $Token } `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop

        return @{
            Success = $true
            GroupID = $response.GroupID
            Message = "Account group '$GroupName' created successfully."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message

        # Try to extract CyberArk error details
        if ($_.ErrorDetails.Message) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                $errorMessage = $errorDetails.ErrorMessage
            }
            catch {
                # Use original error message
            }
        }

        return @{
            Success = $false
            GroupID = $null
            Message = $errorMessage
        }
    }
}

#endregion Functions

#region Main Script

# Normalize PVWA URL (remove trailing slash)
$PVWAURL = $PVWAURL.TrimEnd("/")

Write-LogMessage -Message "=== CyberArk Account Group Creation Script ===" -Type Info
Write-LogMessage -Message "PVWA URL: $PVWAURL" -Type Info
Write-LogMessage -Message "CSV File: $CSVPath" -Type Info

# Prompt for credentials
$credential = Get-Credential -Message "Enter CyberArk credentials for $AuthType authentication"
if (-not $credential) {
    Write-LogMessage -Message "No credentials provided. Exiting." -Type Error
    exit 1
}

# Import CSV and validate
try {
    $accountGroups = @(Import-Csv -Path $CSVPath -ErrorAction Stop)
    Write-LogMessage -Message "Loaded $($accountGroups.Count) account group(s) from CSV." -Type Info
}
catch {
    Write-LogMessage -Message "Failed to import CSV: $($_.Exception.Message)" -Type Error
    exit 1
}

# Validate CSV headers
$requiredColumns = @("GroupName", "GroupPlatformID", "Safe")
$csvHeaders = $accountGroups[0].PSObject.Properties.Name

foreach ($column in $requiredColumns) {
    if ($column -notin $csvHeaders) {
        Write-LogMessage -Message "Missing required column: $column" -Type Error
        Write-LogMessage -Message "Required columns: $($requiredColumns -join ', ')" -Type Info
        exit 1
    }
}

# Authenticate
$token = $null
try {
    $token = Get-AuthorizationToken -PVWAURL $PVWAURL -Credential $credential -AuthType $AuthType
}
catch {
    Write-LogMessage -Message "Unable to authenticate. Exiting." -Type Error
    exit 1
}

# Process account groups
$results = @()
$successCount = 0
$failCount = 0

foreach ($group in $accountGroups) {
    Write-LogMessage -Message "Processing: $($group.GroupName) | Platform: $($group.GroupPlatformID) | Safe: $($group.Safe)" -Type Info

    $result = Add-AccountGroup -PVWAURL $PVWAURL `
        -Token $token `
        -GroupName $group.GroupName `
        -GroupPlatformID $group.GroupPlatformID `
        -Safe $group.Safe

    if ($result.Success) {
        Write-LogMessage -Message $result.Message -Type Success
        Write-LogMessage -Message "  GroupID: $($result.GroupID)" -Type Info
        $successCount++
    }
    else {
        Write-LogMessage -Message "Failed to create '$($group.GroupName)': $($result.Message)" -Type Error
        $failCount++
    }

    $results += [PSCustomObject]@{
        GroupName       = $group.GroupName
        GroupPlatformID = $group.GroupPlatformID
        Safe            = $group.Safe
        Success         = $result.Success
        GroupID         = $result.GroupID
        Message         = $result.Message
    }
}

# Logoff
if ($token) {
    Close-AuthorizationToken -PVWAURL $PVWAURL -Token $token
}

# Summary
Write-LogMessage -Message "=== Summary ===" -Type Info
Write-LogMessage -Message "Total Processed: $($accountGroups.Count)" -Type Info
Write-LogMessage -Message "Successful: $successCount" -Type Success
Write-LogMessage -Message "Failed: $failCount" -Type $(if ($failCount -gt 0) { "Error" } else { "Info" })

# Export results
$resultsPath = Join-Path -Path (Split-Path $CSVPath -Parent) -ChildPath "AccountGroups_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $resultsPath -NoTypeInformation
Write-LogMessage -Message "Results exported to: $resultsPath" -Type Info

#endregion Main Script
