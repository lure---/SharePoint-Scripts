#############################################################
# Analyze SQL Server.
# Rob Garrett

param ([bool]$localExec = $true)

$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)

# Source External Functions
. "$env:dp0\..\Install\spSQLFunctions.ps1"
. "$env:dp0\..\Install\spCommonFunctions.ps1"
. "$env:dp0\spAnalyzeFunctions.ps1"
 
# Make sure we're running as elevated.
Use-RunAs;
try {
    # Register SQL PowerShell Cmdlets
    #SQL-RegisterPS;
}
catch {
    Write-Host -ForegroundColor Red "Critial Error: " $_.Exception.Message;
}

Read-Host "Done, press enter";
