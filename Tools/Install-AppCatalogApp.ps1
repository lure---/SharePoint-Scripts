[CmdletBinding()]param();

if ((Get-PSSnapin -Name "Microsoft.SharePoint.PowerShell" -ErrorAction SilentlyContinue) -eq $null) {
    Add-PSSnapin "Microsoft.SharePoint.PowerShell";
}

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Description."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Description."
$cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Description."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no, $cancel)
 
$site = Get-SPSite "https://robdemo-sp.robdemo.local";
$web = $site.RootWeb;

Write-Verbose "Getting apps from the catalog";
$json = Invoke-RestMethod -UseDefaultCredentials -Method Get -Uri "https://robdemo-sp.robdemo.local/_layouts/15/addanapp.aspx?task=GetMyApps&sort=1&query=&myappscatalog=0&ci=1&vd=1";
$json | ? { $_.Catalog -eq 1 } | % {
    $appId = $_.ID;

    Write-Host -foreground Yellow "Title: $($_.Title)";
    Write-Host -foreground Yellow "AppID: $appId";
     
    $result = $host.ui.PromptForChoice("App Install", "Install App $($_.Title)", $options, 1)
    if ($result -eq 2) { break; }
    if ($result -eq 0) {

        Write-Verbose "Get the Corporate Catalog Accessor instance";
        $flags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance;
        $asm = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint");
        $ccaType = $asm.GetType("Microsoft.SharePoint.Marketplace.CorporateCuratedGallery.SPCorporateCatalogAccessor");
        $ccaCtor = $ccaType.GetConstructors($flags) | ? { $_.GetParameters().Count -eq 1; }
        $cca = $ccaCtor.Invoke(@($web));
    
        <#
        Write-Verbose "Getting app details for app ID $appId";
        $method = $ccaType.GetMethod("GetAppDetails", $flags);
        $deets = $method.Invoke($cca, $appId);

        Write-Verbose "Getting permissions XML for app with ID $appId";
        $appType = $asm.GetType("Microsoft.SharePoint.Administration.SPAppPermissionProvider");
        $method = $appType.GetMethod("ValidateAppPermissionRequestsAndExtractAppInfo", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static);
        $validApp = $method.Invoke($null, $deets.BasicDetails.PermissionsXML);
        $appPrincipalId = $validApp.AppPrincipal;
        Write-Host -ForegroundColor Yellow "App Principal ID from permissions: $appPrincipalId";
    
        Write-Verbose "Getting instance of Marketplace App Principal Manager";
        $mapmType = $asm.GetType("Microsoft.SharePoint.Administration.SPMarketplaceAppPrincipalManager")    
        $method = $mapmType.GetMethod("GetManager", [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static);
        $manager = $method.Invoke($null, $web);

        Write-Verbose "Creating App Registration Admin";
        $araType = $asm.GetType("Microsoft.SharePoint.AppRegistrationAdmin");
        $araCtor = $araType.GetConstructors()[0];
        $ara = $araCtor.Invoke(@($web));
    
        Write-Verbose "See if app was added to web";
        $method = $araType.GetMethod("GetAppInfo", $flags);
        $appPrincipalInfo = $method.Invoke($ara, @($appPrincipalId, $false));
    
        if ($appPrincipalInfo -eq $null) {
            Write-Verbose "Getting app principal from the app principal ID";
            $method = $manager.GetType().GetMethod("LookupAppPrincipalOrCreateUsingMarketplaceData");
            [Microsoft.SharePoint.SPAppPrincipal]$appPrincipal = $method.Invoke($manager, $appPrincipalId);
            $property = $appPrincipal.GetType().GetProperty("AppPrincipalInfo", $flags);
            $appPrincipalInfo = $property.GetValue($appPrincipal);
        }
    
        Write-Verbose "Getting instance of App Principal Permissions Manager";
        Write-Verbose "Setting app only policy to true";
        $appm = New-Object Microsoft.SharePoint.SPAppPrincipalPermissionsManager($web);
        $method = $appm.GetType().GetMethod("UpdateAppOnlyPolicy", $flags);
        $method.Invoke($appm, @($appPrincipalInfo, $true));
        Write-Host -ForegroundColor Yellow "App principal name: $($appPrincipalInfo.Name)";
        #>

        Write-Verbose "Getting App Package from the Catalog";
        $method = $ccaType.GetMethods($flags) | ? { $_.Name -ilike "GetAppPackage" -and ($_.GetParameters())[0].ParameterType.Name -eq "String" } 
        $stream = $method.Invoke($cca, @($appId));
    
        Write-Verbose "Installing App from Catalog";
        $spAppType = $asm.GetType("Microsoft.SharePoint.Administration.SPApp");
        $method = $spAppType.GetMethod("CreateAppUsingPackageMetadata", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static);
        [Microsoft.SharePoint.Administration.SPApp]$spApp = $method.Invoke($null, @($stream, $web, 2, $false, $null, $null));
        $appInstanceId = $spApp.CreateAppInstance($web);
        Write-Host -ForegroundColor Yellow "AppInstanceID: $appInstanceId";
        $appInstance = [Microsoft.SharePoint.Administration.SPAppCatalog]::GetAppInstance($web, $appInstanceId);
        $appInstance.Install();
    }
}
