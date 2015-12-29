﻿#############################################################
# SharePoint Search on local server
# Rob Garrett
# With the help from http://autospinstaller.codeplex.com/

[CmdletBinding()]
param ([bool]$localExec = $true)

$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)

# Source External Functions
. "$env:dp0\Settings\Settings-$env:COMPUTERNAME.ps1"
. "$env:dp0\spConstants.ps1"
. "$env:dp0\spCommonFunctions.ps1"
. "$env:dp0\spSQLFunctions.ps1"
. "$env:dp0\spFarmFunctions.ps1"
. "$env:dp0\spServiceFunctions.ps1"
. "$env:dp0\spSearchFunctions.ps1"
 
# Make sure we're running as elevated.
Use-RunAs;
try {
    # Standard provisioning steps.
    SP-ExecCommonSPServerProvisioning;
    # Configure ULS.
    SP-ConfigureDiagnosticLogging;
    # Configure Claims to Windows Service.
    SP-ConfigureClaimsToWindowsTokenService;
    # Go configure search.
    SP-CreateEnterpriseSearchServiceApp;
    # Post Configuration
    SP-PostInstallation;
}
catch {
    Write-Host -ForegroundColor Red "Critial Error: " $_.Exception.Message;
}


