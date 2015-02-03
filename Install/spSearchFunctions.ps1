#############################################################
# SharePoint Search Functions
# Rob Garrett
# With the help from http://autospinstaller.codeplex.com/

function SP-ChangeIndexLocation {
    if ($indexLocation -eq $null -or $indexLocation -eq '') {
        throw "indexLocation not set in the settings file.";
    }
    # Make sure it exists
    if (!(Test-Path $indexLocation)) {
        New-Item -Path $indexLocation -ItemType Directory
    }
    Write-Host -ForegroundColor yellow "Changing Search Index Location to $indexLocation";
    $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
    if ($searchSvc -eq $null) { Throw "  - Unable to retrieve search service." }
    $searchSvc | Set-SPEnterpriseSearchServiceInstance -DefaultIndexLocation $indexLocation
    Write-Host -ForegroundColor yellow "Applying permissions to $indexLocation";
    ApplyExplicitPermissions -path $indexLocation -identity "WSS_WPG" -permissions @("Read","Write");
    ApplyExplicitPermissions -path $indexLocation -identity "WSS_RESTRICTED_WPG_V4" -permissions @("Read","Write");
    ApplyExplicitPermissions -path $indexLocation -identity "WSS_ADMIN_WPG" -permissions @("FullControl");
    $wmiPath = $indexLocation.Replace("\","\\")
    $wmiDirectory = Get-WmiObject -Class "Win32_Directory" -Namespace "root\cimv2" -ComputerName $env:COMPUTERNAME -Filter "Name='$wmiPath'"
    # Check if folder is already compressed
    if (!($wmiDirectory.Compressed)) {
        Write-Host -ForegroundColor Yellow "Compressing $indexLocation and subfolders..."
        $compress = $wmiDirectory.CompressEx("","True")
    }
}

function SP-CreateEnterpriseSearchServiceApp {
    if ($indexLocation -eq $null -or $indexLocation -eq '') {
        throw "indexLocation not set in the settings file.";
    }
    # Create enterprise search service application.
    $secSearchServicePassword = ConvertTo-SecureString -String $spServiceAcctPwd -AsPlainText -Force;
    Write-Host -ForegroundColor White " - Provisioning Enterprise Search...";
    $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
    if ($searchSvc -eq $null) { Throw "  - Unable to retrieve search service." }
    Write-Host -ForegroundColor White "  - Configuring search service..." -NoNewline
    $internetIdentity = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT; MS Search 6.0 Robot)";
    Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService  `
        -ContactEmail $adminEmail -ConnectionTimeout 60 `
          -AcknowledgementTimeout 60 -ProxyType Default `
          -IgnoreSSLWarnings $false -InternetIdentity $internetIdentity -PerformanceLevel "PartlyReduced" `
          -ServiceAccount $spServiceAcctName -ServicePassword $secSearchServicePassword
    if ($?) {Write-Host -ForegroundColor White "Done."}
    # Get application pools
    $secContentAccessAcctPWD = ConvertTo-SecureString -String $spSearchCrawlAcctPwd -AsPlainText -Force
    $pool = Get-SearchServiceApplicationPool;
    $adminPool = Get-SearchAdminApplicationPool "Search Admin App Pool";
    # From http://mmman.itgroove.net/2012/12/search-host-controller-service-in-starting-state-sharepoint-2013-8/
    # And http://blog.thewulph.com/?p=374
    Write-Host -ForegroundColor White "  - Fixing registry permissions for Search Host Controller Service..." -NoNewline
    $acl = Get-Acl HKLM:\System\CurrentControlSet\Control\ComputerName
    $person = [System.Security.Principal.NTAccount] "WSS_WPG" # Trimmed down from the original "Users"
    $access = [System.Security.AccessControl.RegistryRights]::FullControl
    $inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $type = [System.Security.AccessControl.AccessControlType]::Allow
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($person, $access, $inheritance, $propagation, $type)
    $acl.AddAccessRule($rule)
    Set-Acl HKLM:\System\CurrentControlSet\Control\ComputerName $acl
    Write-Host -ForegroundColor White "Done."
    # Checking the search service.
    Write-Host -ForegroundColor White "  - Checking Search Service Instance..." -NoNewline
    if ($searchSvc.Status -eq "Disabled") {
        Write-Host -ForegroundColor White "Starting..." -NoNewline
        $searchSvc | Start-SPEnterpriseSearchServiceInstance
        if (!$?) {Throw "  - Could not start the Search Service Instance."}
        $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
        while ($searchSvc.Status -ne "Online") {
            Write-Host -ForegroundColor Yellow "." -NoNewline
            Start-Sleep 1
            $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
        }
        Write-Host -BackgroundColor Yellow -ForegroundColor Black $($searchSvc.Status)
    }
    else {
        Write-Host -ForegroundColor White "Already $($searchSvc.Status)."
    }
    # Sync Topology
     Write-Host -ForegroundColor White "  - Checking Search Query and Site Settings Service Instance..." -NoNewline
    $searchQueryAndSiteSettingsService = Get-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance -Local
    if ($searchQueryAndSiteSettingsService.Status -eq "Disabled") {
        Write-Host -ForegroundColor White "Starting..." -NoNewline
        $searchQueryAndSiteSettingsService | Start-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance
        if (!$?) {Throw "  - Could not start the Search Query and Site Settings Service Instance."}
            Write-Host -ForegroundColor White "Done."
        }
        else {
            Write-Host -ForegroundColor White "Already $($searchQueryAndSiteSettingsService.Status)."
    }
    # Search Service App.
    Write-Host -ForegroundColor White "  - Checking Search Service Application..." -NoNewline
    $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $searchAppName -ErrorAction SilentlyContinue
    if ($searchApp -eq $null) {
        Write-Host -ForegroundColor White "Creating $($searchAppName)..." -NoNewline
        $searchApp = New-SPEnterpriseSearchServiceApplication -Name $searchAppName `
            -DatabaseServer $dbServer `
            -DatabaseName $($dbPrefix + "_Service_SearchApp") `
            -ApplicationPool $pool `
            -AdminApplicationPool $adminPool `
            -Partitioned:$false
        if (!$?) {Throw "  - An error occurred creating the $($searchAppName) application."}
        Write-Host -ForegroundColor White "Done."
    }
    else {
        Write-Host -ForegroundColor White "Already exists."
    }

    # Update the default Content Access Account
    $pwd = ConvertTo-SecureString "$spSearchCrawlAcctPWD" -AsPlaintext -Force
    Update-SearchContentAccessAccount $($searchAppName) $searchApp $($spSearchCrawlAcctName) $pwd

    # If the index location isn't already set to either the default location or our custom-specified location, set the default location for the search service instance
    if ($indexLocation -ne $searchSvc.DefaultIndexLocation) {
        Write-Host -ForegroundColor White "  - Setting default index location on search service instance..." -NoNewline
        $searchSvc | Set-SPEnterpriseSearchServiceInstance -DefaultIndexLocation $indexLocation -ErrorAction SilentlyContinue
        if ($?) {Write-Host -ForegroundColor White "Done."}
    }

    # Create the search topology
    SP-CreateSearchTopology -searchApp $searchApp -searchSvc $searchSvc;

    # Create proxy
    $searchAppProxyName = "$searchAppName Proxy";
    Write-Host -ForegroundColor White "  - Checking search service application proxy..." -NoNewline
    if (!(Get-SPEnterpriseSearchServiceApplicationProxy -Identity $searchAppProxyName -ErrorAction SilentlyContinue)) {
        Write-Host -ForegroundColor White "Creating..." -NoNewline
        $searchAppProxy = New-SPEnterpriseSearchServiceApplicationProxy -Name $searchAppProxyName -SearchApplication $searchAppName
        if ($?) {Write-Host -ForegroundColor White "Done."}
    }
    else {
        Write-Host -ForegroundColor White "Already exists."
    }

    # Check the Search Host Controller Service for a known issue ("stuck on starting")
    Write-Host -ForegroundColor White "  - Checking for stuck Search Host Controller Service (known issue)..."
    $searchHostServices = Get-SPServiceInstance | ? {$_.TypeName -eq "Search Host Controller Service"}
    foreach ($sh in $searchHostServices) {
        Write-Host -ForegroundColor White "   - Server: $($sh.Parent.Address)..." -NoNewline
        if ($sh.Status -eq "Provisioning") {
            Write-Host -ForegroundColor White "Re-provisioning..." -NoNewline
            $sh.Unprovision()
            $sh.Provision($true)
            Write-Host -ForegroundColor White "Done."
        }
        else {
            Write-Host -ForegroundColor White "OK."
        }
    }

    # Add link to resources list
    SP-AddResourcesLink $searchAppName ("searchadministration.aspx?appid=" +  $searchApp.Id);
}

function SP-CreateTopologyComponent($searchApp, $searchSvc, $searchTopology, $compName, $funcNewComp) {
    # Create a topology component
    Write-Host -ForegroundColor White "  - Checking $compName component..." -NoNewline
    $components = $clone.GetComponents() | Where-Object {$_.Name -like ($compName + "Component*")}
    if (!($components | Where-Object {MatchComputerName $_.ServerName $env:COMPUTERNAME})) {
        Write-Host -ForegroundColor White "Creating..." -NoNewline
        & $funcNewComp –SearchTopology $searchTopology -SearchServiceInstance $searchSvc | Out-Null
        if (!$?) { throw "Failed to create new search component"; }
        Write-Host -ForegroundColor White "Done."
    }
    else {
        Write-Host -ForegroundColor White "Already exists on this server."
    }
    # Get components on this server.
    return $clone.GetComponents() | Where-Object {$_.Name -like ($compName + "Component*") -and `
        $_.ServerName -imatch $env:COMPUTERNAME}; 
}

function SP-RemoveTopologyComponent($searchApp, $searchSvc, $searchTopology, $compName) {
    Write-Host -ForegroundColor White "  - Checking $compName component..." -NoNewline
    $components = $clone.GetComponents() | Where-Object `
        {$_.Name -like ($compName + "Component*") -and $_.ServerName -imatch $env:COMPUTERNAME}; 
    if ($components) {
        # Component exists on this server, so remove it.
        Write-Host -ForegroundColor White "Removing..." -NoNewline
        foreach ($comp in $components) {
            Remove-SPEnterpriseSearchComponent -SearchTopology $searchTopology -Identity $comp -Confirm:$false;
        }
    }
    Write-Host -ForegroundColor White "Done.";
    # Determine if this component lives in the farm on another server.
    return $clone.GetComponents() | Where-Object {$_.Name -like ($compName + "Component*") -and `
        $_.ServerName -inotmatch $env:COMPUTERNAME}; 
}

function SP-NewIndexSearchComponent($SearchTopology, $SearchServiceInstance) {
    # Specify the RootDirectory parameter only if it's different than the default path
    $dataDir = "$env:ProgramFiles\Microsoft Office Servers\$spVer.0\Data";
    if ($indexLocation -ne "$dataDir\Office Server\Applications") {
        New-Item -ItemType Directory -Force $indexLocation;
        $rootDirectorySwitch = @{RootDirectory = $indexLocation }
    }
    else {
        $rootDirectorySwitch = @{}
    }
    New-SPEnterpriseSearchIndexComponent –SearchTopology $SearchTopology `
        -SearchServiceInstance $SearchServiceInstance @rootDirectorySwitch | Out-Null
}

function SP-CreateSearchTopology($searchApp, $searchSvc) {
    # Look for a topology that has components, or is still Inactive, because that's probably our $clone
    $clone = $searchApp.Topologies | Where {$_.ComponentCount -gt 0 -and $_.State -eq "Inactive"} | Select-Object -First 1
    if (!$clone) {
        # Clone the active topology
        Write-Host -ForegroundColor White "  - Cloning the active search topology..."
        #$clone = $searchApp.ActiveTopology.Clone();
        $clone = New-SPEnterpriseSearchTopology -SearchApplication $searchApp -Clone -SearchTopology $searchApp.ActiveTopology;
    }
    else {
        Write-Host -ForegroundColor White "  - Using existing cloned search topology."
        # Since this clone probably doesn't have all its components added yet, we probably want to keep it if it isn't activated after this pass
        $keepClone = $true
    }

    # Count current components in clone.
    $count = $clone.ComponentCount;
    Write-Host -ForegroundColor white "  - Clone has $count components...";

    # Note any new topology must have all the components to activate it.
    $activateTopology = $false;

    # Check if each search component is already assigned to the current server, 
    # then check that it's actually being requested for the current server, then create it as required.
    if ($crawlServers -icontains $env:COMPUTERNAME) {
        # This server is a crawl server.
        # Admin Component
        $adminComponentReady = SP-CreateTopologyComponent `
            -searchApp $searchApp `
            -searchTopology $clone `
            -searchSvc $searchSvc `
            -compName "Admin" `
            -funcNewComp "New-SPEnterpriseSearchAdminComponent"

        # Content Processing Component
        $contentProcessingComponentReady = SP-CreateTopologyComponent `
            -searchApp $searchApp `
            -searchTopology $clone `
            -searchSvc $searchSvc `
            -compName "ContentProcessing" `
            -funcNewComp "New-SPEnterpriseSearchContentProcessingComponent"

        # Analytics Component
        $analyticsProcessingComponentReady = SP-CreateTopologyComponent `
            -searchApp $searchApp `
            -searchTopology $clone `
            -searchSvc $searchSvc `
            -compName "AnalyticsProcessing" `
            -funcNewComp "New-SPEnterpriseSearchAnalyticsProcessingComponent"

        # Crawl Component
        $crawlComponentReady = SP-CreateTopologyComponent `
            -searchApp $searchApp `
            -searchTopology $clone `
            -searchSvc $searchSvc `
            -compName "Crawl" `
            -funcNewComp "New-SPEnterpriseSearchCrawlComponent"

        # Remove Query components?
        if (!($queryServers -icontains $env:COMPUTERNAME)) {
            # Index.
            $indexComponentReady = SP-RemoveTopologyComponent `
                -searchApp $searchApp `
                -searchTopology $clone `
                -searchSvc $searchSvc `
                -compName "Index"
            # Query.
            $queryComponentReady = SP-RemoveTopologyComponent `
                -searchApp $searchApp `
                -searchTopology $clone `
                -searchSvc $searchSvc `
                -compName "QueryProcessing"
        }
    }

    if ($queryServers -icontains $env:COMPUTERNAME) {
        # This server is a query server.
        # Index Component
        $indexComponentReady = SP-CreateTopologyComponent `
            -searchApp $searchApp `
            -searchTopology $clone `
            -searchSvc $searchSvc `
            -compName "Index" `
            -funcNewComp "SP-NewIndexSearchComponent"

        # Query Processing Component
        $queryComponentReady = SP-CreateTopologyComponent `
            -searchApp $searchApp `
            -searchTopology $clone `
            -searchSvc $searchSvc `
            -compName "QueryProcessing" `
            -funcNewComp "New-SPEnterpriseSearchQueryProcessingComponent"

        # Remove crawl components?
        if (!($crawlServers -icontains $env:COMPUTERNAME)) {
            # Admin Component
            $adminComponentReady = SP-RemoveTopologyComponent `
                -searchApp $searchApp `
                -searchTopology $clone `
                -searchSvc $searchSvc `
                -compName "Admin"

            # Content Processing Component
            $contentProcessingComponentReady = SP-RemoveTopologyComponent `
                -searchApp $searchApp `
                -searchTopology $clone `
                -searchSvc $searchSvc `
                -compName "ContentProcessing"

            # Analytics Component
            $analyticsProcessingComponentReady = SP-RemoveTopologyComponent `
                -searchApp $searchApp `
                -searchTopology $clone `
                -searchSvc $searchSvc `
                -compName "AnalyticsProcessing"

            # Crawl Component
            $crawlComponentReady = SP-RemoveTopologyComponent `
                -searchApp $searchApp `
                -searchTopology $clone `
                -searchSvc $searchSvc `
                -compName "Crawl"
        }
    }

    # Activate new topology if all components in the farm.
    if ($adminComponentReady -and $contentProcessingComponentReady -and $analyticsProcessingComponentReady -and `
        $indexComponentReady -and $crawlComponentReady -and $queryComponentReady) {$activateTopology = $true}
    # Check if any new search components were added 
    # (or if we have a clone with more/less components than the current active topology) and if we're ready to activate the topology
    Write-Host -ForegroundColor White "  - Clone components:" $clone.ComponentCount "Current Search App components:" $searchApp.ActiveTopology.ComponentCount;
    if ($newComponentsCreated -or ($clone.ComponentCount -ne $searchApp.ActiveTopology.ComponentCount)) {
        if ($activateTopology) {
            Write-Host -ForegroundColor White "  - Activating Search Topology..." -NoNewline
            $clone.Activate()
            if ($?) {
                Write-Host -ForegroundColor White "Done."
                # Clean up original or previous unsuccessfully-provisioned search topologies
                $inactiveTopologies = $searchApp.Topologies | Where {$_.State -eq "Inactive"}
                if ($inactiveTopologies -ne $null) {
                    Write-Host -ForegroundColor White "  - Removing old, inactive search topologies:"
                    foreach ($inactiveTopology in $inactiveTopologies) {
                        Write-Host -ForegroundColor White "   -"$inactiveTopology.TopologyId.ToString()
                        $inactiveTopology.Delete()
                    }
                }
            }
        }
        else {
            Write-Host -ForegroundColor White "  - Not activating topology yet as there seem to be components still pending."
        }
    }
    elseif ($keepClone -ne $true) {
        # Delete the newly-cloned topology since nothing was done 
        # TODO: Check that the search topology is truly complete and there are no more servers to install
        Write-Host -ForegroundColor White "  - Deleting unneeded cloned topology..."
        $clone.Delete()
    }
    # Clean up any empty, inactive topologies
    $emptyTopologies = $searchApp.Topologies | Where {$_.ComponentCount -eq 0 -and $_.State -eq "Inactive"}
    if ($emptyTopologies -ne $null) {
        Write-Host -ForegroundColor White "  - Removing empty and inactive search topologies:"
        foreach ($emptyTopology in $emptyTopologies) {
            Write-Host -ForegroundColor White "  -"$emptyTopology.TopologyId.ToString()
            $emptyTopology.Delete()
        }
    }
}

function Update-SearchContentAccessAccount ($saName, $sa, $caa, $caapwd) {
    # Set the crawl account.
    try {
        Write-Host -ForegroundColor White "  - Setting content access account for $saName..."
        $sa | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $caa -DefaultContentAccessAccountPassword $caapwd -ErrorVariable err
    }
    catch {
        if ($err -like "*update conflict*") {
            Write-Warning "An update conflict error occured, trying again."
            Update-SearchContentAccessAccount $saName, $sa, $caa, $caapwd
            $sa | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $caa -DefaultContentAccessAccountPassword $caapwd -ErrorVariable err
        }
        else {
            throw $_
        }
    }
    finally {Clear-Variable err}
}


function Get-SearchServiceApplicationPool {
    # Try and get the application pool if it already exists
    # SLN: Updated names
    $pool = Get-SPServiceApplicationPool -Identity $searchSvcAppPoolName -ErrorVariable err -ErrorAction SilentlyContinue
    if ($err) {
        # The application pool does not exist so create.
        Write-Host -ForegroundColor White "  - Getting $($spServiceAcctName) account for application pool..."
        $managedAccountSearch = (Get-SPManagedAccount -Identity $spServiceAcctName -ErrorVariable err -ErrorAction SilentlyContinue)
        if ($err) {
            $appPoolConfigPWD = (ConvertTo-SecureString $spServiceAcctPwd -AsPlainText -force)
            $accountCred = New-Object System.Management.Automation.PsCredential $spServiceAcctName,$appPoolConfigPWD
            $managedAccountSearch = New-SPManagedAccount -Credential $accountCred
        }
        Write-Host -ForegroundColor White "  - Creating $($searchSvcAppPoolName)..."
        $pool = New-SPServiceApplicationPool -Name $($searchSvcAppPoolName) -Account $managedAccountSearch
    }
    return $pool
}

function Get-SearchAdminApplicationPool {
    # Try and get the application pool if it already exists
    # SLN: Updated names
    $pool = Get-SPServiceApplicationPool -Identity $searchAdminAppPoolName -ErrorVariable err -ErrorAction SilentlyContinue
    if ($err) {
        # The application pool does not exist so create.
        Write-Host -ForegroundColor White "  - Getting $($spAppPoolAcctName) account for application pool..."
        $managedAccountSearch = (Get-SPManagedAccount -Identity $spAppPoolAcctName -ErrorVariable err -ErrorAction SilentlyContinue)
        if ($err) {
            $appPoolConfigPWD = (ConvertTo-SecureString $spAppPoolAcctPwd -AsPlainText -force)
            $accountCred = New-Object System.Management.Automation.PsCredential $spAdminAcctName,$appPoolConfigPWD
            $managedAccountSearch = New-SPManagedAccount -Credential $accountCred
        }
        Write-Host -ForegroundColor White "  - Creating $($searchAdminAppPoolName)..."
        $pool = New-SPServiceApplicationPool -Name $($searchAdminAppPoolName) -Account $managedAccountSearch
    }
    return $pool
}

