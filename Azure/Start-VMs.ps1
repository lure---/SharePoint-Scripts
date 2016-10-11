[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][string]$ResourceGroupName,
	[Parameter(Mandatory=$false)][string]$Location = "East US"
);

$0 = $myInvocation.MyCommand.Definition 
$env:dp0 = [System.IO.Path]::GetDirectoryName($0) 

. "$env:dp0\Invoke-Parallel.ps1";

Import-Module Azure -ErrorAction SilentlyContinue;
Set-StrictMode -Version 3

Function Get-VMPowerState {
    Param([string]$vmName, [string]$resourceGroupName);
    return (Get-AzureRMVM -ResourceGroupName $resourceGroupName -Name $vmName -Status | `
        Select-Object -ExpandProperty Statuses | Where-Object {$_.Code -like '*PowerState*'} | `
        Select-Object @{l='PowerState';e={$_.Code.Split('/')[1]}}).PowerState;
}

Function StartAndWait-ForVM {
    Param([string]$vmName, [string]$resourceGroupName);
    $adPowerState = Get-VMPowerState -vmName $vmName -resourceGroupName $resourceGroupName;
    Write-Verbose "Powerstate of $vmName is $adPowerState";
    If ($adPowerState -ine "Running" ) {
        Write-Host -ForegroundColor Yellow "Starting VM $vmName";
        Start-AzureRmVM -Name $vmName -ResourceGroupName $resourceGroupName -Verbose; 
    }
}

try {
    # Make sure that AD is up first.
    StartAndWait-ForVM -vmName "rdglab-ad" -resourceGroupName "AD";
    # Start the VMs
    $vmName = "$($ResourceGroupName.ToLower())-sql";
    StartAndWait-ForVM -vmName $vmName -resourceGroupName $ResourceGroupName;
    # Start APP and WFE in parallel 
    $spAppVmName = "$($ResourceGroupName.ToLower())-spapp";
    $spWfeVmName = "$($ResourceGroupName.ToLower())-spwfe";
    $spAppVmName, $spWfeVmName | Invoke-Parallel -Parameter $ResourceGroupName -ScriptBlock {
        $vmName = $_;
        $resourceGroupName = $parameter;
        $adPowerState = (Get-AzureRMVM -ResourceGroupName $resourceGroupName -Name $vmName -Status | `
            Select-Object -ExpandProperty Statuses | Where-Object {$_.Code -like '*PowerState*'} | `
            Select-Object @{l='PowerState';e={$_.Code.Split('/')[1]}}).PowerState;
        Write-Verbose "Powerstate of $vmName is $adPowerState";
        If ($adPowerState -ine "Running" ) {
            Write-Host -ForegroundColor Yellow "Starting VM $vmName";
            Start-AzureRmVM -Name $vmName -ResourceGroupName $resourceGroupName -Verbose; 
        }
    }    
} catch {
	Write-Error $_.Exception;
}

