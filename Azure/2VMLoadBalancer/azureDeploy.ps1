[CmdletBinding()]Param();

$0 = $myInvocation.MyCommand.Definition 
$env:dp0 = [System.IO.Path]::GetDirectoryName($0) 

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
	$rg = Get-AzureRmResourceGroup -Name 2VMLB -ErrorAction SilentlyContinue;
	if ($rg -eq $null) { New-AzureRmResourceGroup -Name 2VMLB -Location "East US"; }
	# Deploy to the new Resource Group.
	New-AzureRmResourceGroupDeployment -Name 2VMLB-Deploy -ResourceGroupName 2VMLB `
		-TemplateFile "$env:dp0\azureDeploy.json" -TemplateParameterFile "$env:dp0\azureDeployParameters.json";
} catch {
	Write-Error $_.Exception;
}

