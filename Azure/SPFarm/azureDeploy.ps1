[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][string]$ResourceGroupName,
	[Parameter(Mandatory=$false)][string]$Location = "East US"
);

$0 = $myInvocation.MyCommand.Definition 
$env:dp0 = [System.IO.Path]::GetDirectoryName($0) 

Import-Module Azure -ErrorAction SilentlyContinue;
Set-StrictMode -Version 3

function Login {
	try {
		Get-AzureRmSubscription | Out-Null;
	} catch {
		Login-AzureRmAccount;
	}
}

try {
	# Login to subscription if not already.
	Login;
	# Create a new Resource Group for our deployment.
	$rg = Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue;
	if ($rg -eq $null) { New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location; }
	# Deploy to the new Resource Group.
	New-AzureRmResourceGroupDeployment -Name "$($ResourceGroupName)-Deploy" -ResourceGroupName $ResourceGroupName `
		-TemplateFile "$env:dp0\azureDeploy.json" -TemplateParameterFile "$env:dp0\azureDeployParameters.json";
} catch {
	Write-Error $_.Exception;
}

