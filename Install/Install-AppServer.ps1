﻿#############################################################
# SharePoint Services on local server
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
 
# Make sure we're running as elevated.
Use-RunAs;
try {
    # Standard provisioning steps.
    SP-ExecCommonSPServerProvisioning
    # Configure Logging
    SP-ConfigureDiagnosticLogging;
    # Go configure services (search is a separate server).
    SP-CreateStateServiceApp;
    SP-CreateMetadataServiceApp;
    SP-CreateUserProfileServiceApplication;
    SP-ConfigureUPSS;
    SP-CreateSecureStoreServiceApp;
    SP-ConfigureTracing;
    SP-CreateBusinessDataConnectivityServiceApp;
    SP-CreateWordAutomationServiceApp;
    SP-CreateSubscriptionSettingsServiceApp;
    SP-CreateAppManagementServiceApp;
    SP-CreatePowerPointConversionServiceApp;
    SP-CreateMachineTranslationServiceApp;
    SP-CreateWorkManagementServiceApp;
    SP-CreateSPUsageApp;
    # Post Configuration
    SP-PostInstallation;
}
catch {
    Write-Host -ForegroundColor Red "Critial Error: " $_.Exception.Message;
}



