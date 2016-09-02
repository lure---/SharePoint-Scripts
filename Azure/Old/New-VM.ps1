[CmdletBinding()]param();

Import-Module AzureRM.Network -ErrorAction SilentlyContinue;
Import-Module AzureRM.Profile -ErrorAction SilentlyContinue;
Import-Module AzureRM.Resources -ErrorAction SilentlyContinue;

# Subscription IDs
$global:prodSID = "79b47ce2-98d9-489d-a1b8-ed2d1482d416";
$global:devSID = "7baf3f00-e117-405d-ae1f-1e89a43c4fc0";
$global:webSID = "3c03ce8e-d2b2-4e07-96f7-d6d8c8f37401";
$global:msSID = "427865cf-6cfb-40f3-9c1e-a1dc44f8fd25";

$global:scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition);
$global:resourceGroupName = "RobDEV-VM";
$global:vmName = "robdev-dc2";
$global:vnetName = "VDEV";
$global:location = "East US";
$global:vmSize = "Standard_A1";
$global:storageAccName = "robdevvmsdev";

try {
    $devSub = Select-AzureRMSubscription -SubscriptionId $global:devSID;
    $nicName = "$global:vmName-nic";
    $pipName = "$global:vmName-pip";
    $vnet = Get-AzureRmVirtualNetwork -Name $global:vnetName -ResourceGroupName "Default-Network";
    $pip = Get-AzureRmPublicIpAddress -Name $pipName -ResourceGroupName $global:resourceGroupName -ErrorAction SilentlyContinue;
    if ($pip -eq $null) {
        Write-Host -ForegroundColor Yellow "Creating PIP";
        $pip = New-AzureRmPublicIpAddress -Name $pipName -DomainNameLabel $global:vmName -ResourceGroupName $global:resourceGroupName -Location $global:location -AllocationMethod Dynamic;
    }
    $nic = Get-AzureRmNetworkInterface -Name $nicName -ResourceGroupName $global:resourceGroupName -ErrorAction SilentlyContinue;
    if ($nic -eq $null) {
        Write-Host -ForegroundColor Yellow "Creating NIC";
        $nic = New-AzureRmNetworkInterface -Name $nicName -Location $global:location -ResourceGroupName $global:resourceGroupName -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $pip.Id;
    }
    $vm = Get-AzureRMVM -ResourceGroupName $global:resourceGroupName -Name $global:vmName -ErrorAction SilentlyContinue;
    if ($vm -eq $null) {
        Write-Host -ForegroundColor Yellow "Creating VM";
        $pubName="MicrosoftWindowsServer";
        $offerName="WindowsServer";
        $skuName="2012-R2-Datacenter";
        $vm = New-AzureRmVMConfig -VMName $global:vmName -VMSize $global:vmSize;
        $cred = Get-Credential -Message "Type the name and password of the local administrator account." 
        $vm = Set-AzureRmVMOperatingSystem -VM $vm -Windows -ComputerName $global:vmName -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $vm = Set-AzureRmVMSourceImage -VM $vm -PublisherName $pubName -Offer $offerName -Skus $skuName -Version "latest";
        $vm = Add-AzureRmVMNetworkInterface -VM $vm -Id $nic.Id;
        $diskName="$global:vmName-OS";
        $storageAcc = Get-AzureRmStorageAccount -ResourceGroupName $global:resourceGroupName -Name $global:storageAccName;
        $osDiskUri = $storageAcc.PrimaryEndpoints.Blob.ToString() + "vhds/" + $diskName + ".vhd";
        $vm = Set-AzureRmVMOSDisk -VM $vm -Name $diskName -VhdUri $osDiskUri -CreateOption fromImage;
        New-AzureRmVM -VM $vm -Location $global:location -ResourceGroupName $global:resourceGroupName;
    }
} catch {
    Write-Host -ForegroundColor Red $_.Exception; 
}
