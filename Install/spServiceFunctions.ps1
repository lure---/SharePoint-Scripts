#############################################################
# SharePoint Service Functions
# Rob Garrett
# With the help from http://autospinstaller.codeplex.com/

function UpdateProcessIdentity ($serviceToUpdate, $svcName = $null) {
    # Update service to use SP service account.
    # Managed Account
    if ($svcName -eq $null) { $svcName = $spServiceAcctName; }
    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($svcName)}
    if ($managedAccountGen -eq $null) { Throw " - Managed Account $($svcName) not found" }
    if ($serviceToUpdate.Service) {$serviceToUpdate = $serviceToUpdate.Service}
    if ($serviceToUpdate.ProcessIdentity.Username -ne $managedAccountGen.UserName) {
        Write-Host -ForegroundColor White " - Updating $($serviceToUpdate.TypeName) to run as $($managedAccountGen.UserName)..."
        # Set the Process Identity to our servic account; otherwise it's set by default to the Farm Account and gives warnings in the Health Analyzer
        $serviceToUpdate.ProcessIdentity.CurrentIdentityType = "SpecificUser"
        $serviceToUpdate.ProcessIdentity.ManagedAccount = $managedAccountGen
        $serviceToUpdate.ProcessIdentity.Update()
        $serviceToUpdate.ProcessIdentity.Deploy()
        Write-Host -ForegroundColor White " - Done."
    }
    else {
        Write-Host -ForegroundColor White " - $($serviceToUpdate.TypeName) is already configured to run as $($managedAccountGen.UserName)."
    }
}

function Get-HostedServicesAppPool {
    # Managed Account
    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spServiceAcctName)}
    if ($managedAccountGen -eq $null) { Throw " - Managed Account $($spservice.username) not found" }
    # App Pool
    $applicationPool = Get-SPServiceApplicationPool "SharePoint Hosted Services" -ea SilentlyContinue
    if ($applicationPool -eq $null) {
        Write-Host -ForegroundColor White " - Creating SharePoint Hosted Services Application Pool..."
        $applicationPool = New-SPServiceApplicationPool -Name "SharePoint Hosted Services" -account $managedAccountGen
        if (-not $?) { Throw "Failed to create the application pool" }
    }
    return $applicationPool
}

function SP-ConfigureSandboxedCodeService {
    # Configure the sandbox code service.
    Write-Host -ForegroundColor White " - Starting Sandboxed Code Service"
    $sandboxedCodeServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
    $sandboxedCodeService = $sandboxedCodeServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
    if ($sandboxedCodeService.Status -ne "Online") {
        try {
            Write-Host -ForegroundColor White " - Starting Microsoft SharePoint Foundation Sandboxed Code Service..."
            UpdateProcessIdentity $sandboxedCodeService
            $sandboxedCodeService.Update()
            $sandboxedCodeService.Provision()
            if (-not $?) {Throw " - Failed to start Sandboxed Code Service"}
        }
        catch {
            throw " - An error occurred starting the Microsoft SharePoint Foundation Sandboxed Code Service"
        }
        Write-Host -ForegroundColor Yellow " - Waiting for Sandboxed Code service..." -NoNewline
        while ($sandboxedCodeService.Status -ne "Online") {
            Write-Host -ForegroundColor Yellow "." -NoNewline
            Start-Sleep 1
            $sandboxedCodeServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
            $sandboxedCodeService = $sandboxedCodeServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        }
        Write-Host -BackgroundColor Yellow -ForegroundColor Black $($sandboxedCodeService.Status)
    }
    Else
    {
        Write-Host -ForegroundColor White " - Sandboxed Code Service already started."
    }
}

function SP-CreateStateServiceApp {
    # Create the state service application.
    try {
        $stateServiceDB = $dbPrefix + "_Service_StateApp";
        $stateServiceProxyName = "$stateServiceName Proxy";
        $getSPStateServiceApplication = Get-SPStateServiceApplication
        if ($getSPStateServiceApplication -eq $null) {
            Write-Host -ForegroundColor White " - Provisioning State Service Application..."
            New-SPStateServiceDatabase -DatabaseServer $dbServer -Name $stateServiceDB | Out-Null
            New-SPStateServiceApplication -Name $stateServiceName -Database $stateServiceDB | Out-Null
            Get-SPStateServiceDatabase | Initialize-SPStateServiceDatabase | Out-Null
            Write-Host -ForegroundColor White " - Creating State Service Application Proxy..."
            Get-SPStateServiceApplication | New-SPStateServiceApplicationProxy -Name $stateServiceProxyName -DefaultProxyGroup | Out-Null
            Write-Host -ForegroundColor White " - Done creating State Service Application."
        }
        else {
            Write-Host -ForegroundColor White " - State Service Application already provisioned."
        }
    }
    catch {
        Write-Output $_
        throw " - Error provisioning the state service application";
    }
}

function SP-CreateMetadataServiceApp {
    # Create a managed metadata service app.
    try {
        $metaDataDB = $dbPrefix + "_Service_MMS";
        $metadataServiceProxyName = "$metadataServiceName Proxy";
        Write-Host -ForegroundColor White " - Provisioning Managed Metadata Service Application"
        $applicationPool = Get-HostedServicesAppPool
        Write-Host -ForegroundColor White " - Starting Managed Metadata Service:"
        # Get the service instance
        $metadataServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
        $metadataServiceInstance = $metadataServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        If (-not $?) { Throw " - Failed to find Metadata service instance" }
        # Start Service instances
        if($metadataServiceInstance.Status -eq "Disabled") {
            Write-Host -ForegroundColor White " - Starting Metadata Service Instance..."
            $metadataServiceInstance.Provision()
            if (-not $?) { Throw " - Failed to start Metadata service instance" }
            Write-Host -ForegroundColor Yellow " - Waiting for Metadata service..." -NoNewline
            while ($metadataServiceInstance.Status -ne "Online") {
                Write-Host -ForegroundColor Yellow "." -NoNewline
                Start-Sleep 1
                $metadataServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
                $metadataServiceInstance = $metadataServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black ($metadataServiceInstance.Status)
        }
        else {
            Write-Host -ForegroundColor White " - Managed Metadata Service already started."
        }
        $metaDataServiceApp = Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
        # Create a Metadata Service Application if we don't already have one
        if ($metaDataServiceApp -eq $null) {
            # Create Service App
            Write-Host -ForegroundColor White " - Creating Metadata Service Application..."
            $metaDataServiceApp = New-SPMetadataServiceApplication -Name $metadataServiceName -ApplicationPool $applicationPool -DatabaseServer $dbServer -DatabaseName $metaDataDB
            if (-not $?) { Throw " - Failed to create Metadata Service Application" }
        }
        else {
            Write-Host -ForegroundColor White " - Managed Metadata Service Application already provisioned."
        }
        $metaDataServiceAppProxy = Get-SPServiceApplicationProxy | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplicationProxy"}
        if ($metaDataServiceAppProxy -eq $null) {
            # create proxy
            Write-Host -ForegroundColor White " - Creating Metadata Service Application Proxy..."
            $metaDataServiceAppProxy = New-SPMetadataServiceApplicationProxy -Name $metadataServiceProxyName -ServiceApplication `
                $metaDataServiceApp -DefaultProxyGroup -ContentTypePushdownEnabled -DefaultKeywordTaxonomy -DefaultSiteCollectionTaxonomy
            if (-not $?) { Throw " - Failed to create Metadata Service Application Proxy" }
        }
        else {
            Write-Host -ForegroundColor White " - Managed Metadata Service Application Proxy already provisioned."
        }
        if ($metaDataServiceApp -or $metaDataServiceAppProxy) {
            # Added to enable Metadata Service Navigation for SP2013, per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=354
            if ($metaDataServiceAppProxy.Properties.IsDefaultSiteCollectionTaxonomy -ne $true) {
                Write-Host -ForegroundColor White " - Configuring Metadata Service Application Proxy..."
                $metaDataServiceAppProxy.Properties.IsDefaultSiteCollectionTaxonomy = $true
                $metaDataServiceAppProxy.Update()
            }
            Write-Host -ForegroundColor White " - Granting rights to Metadata Service Application:"
            # Get ID of "Managed Metadata Service"
            $metadataServiceAppToSecure = Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
            $metadataServiceAppIDToSecure = $metadataServiceAppToSecure.Id
            # Create a variable that contains the list of administrators for the service application
            $metadataServiceAppSecurity = Get-SPServiceApplicationSecurity $metadataServiceAppIDToSecure
            # Create a variable that contains the claims principal for the service accounts
            Write-Host -ForegroundColor White "  - $($spAdminAcctName)..."
            $accountPrincipal = New-SPClaimsPrincipal -Identity $spAdminAcctName -IdentityType WindowsSamAccountName
            # Give permissions to the claims principal you just created
            Grant-SPObjectSecurity $metadataServiceAppSecurity -Principal $accountPrincipal -Rights "Full Access to Term Store"
            # Apply the changes to the Metadata Service application
            Set-SPServiceApplicationSecurity $metadataServiceAppIDToSecure -objectSecurity $metadataServiceAppSecurity
            Write-Host -ForegroundColor White " - Done granting rights."
            Write-Host -ForegroundColor White " - Done creating Managed Metadata Service Application."
        }
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning the Managed Metadata Service Application"
    }
}

function SP-ConfigureClaimsToWindowsTokenService {
    # C2WTS is required by Excel Services, Visio Services and PerformancePoint Services; 
    # if any of these are being provisioned we should start it.
    # Configure Claims to Windows STS
    # Ensure Claims to Windows Token Service is started
    $claimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
    $claimsService = $claimsServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
    if ($claimsService.Status -ne "Online") {
        try {
            Write-Host -ForegroundColor White " - Starting $($claimsService.DisplayName)..."
            SP-RegisterManagedAccount -username $spc2WTSAcctName -password $spc2WTSAcctPwd;
            UpdateProcessIdentity $claimsService -svcName $spc2WTSAcctName;
            $claimsService.Update()
            # Add C2WTS account to local admins
            AddAccountToAdmin -spAccountName $spc2WTSAcctName;
            $claimsService.Provision()
            if (-not $?) {throw " - Failed to start $($claimsService.DisplayName)"}
        }
        catch {
            Write-Output $_;
            throw " - An error occurred starting $($claimsService.DisplayName)"
        }
        Write-Host -ForegroundColor Yellow " - Waiting for $($claimsService.DisplayName)..." -NoNewline
        while ($claimsService.Status -ne "Online") {
            Write-Host -ForegroundColor Yellow "." -NoNewline
            sleep 1
            $claimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
            $claimsService = $claimsServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        }
        Write-Host -BackgroundColor Yellow -ForegroundColor Black $($claimsService.Status)
    }
    else {
        Write-Host -ForegroundColor White " - $($claimsService.DisplayName) already started."
    }
    Write-Host -ForegroundColor White " - Setting C2WTS to depend on Cryptographic Services..."
    Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList "config c2wts depend= CryptSvc" -Wait -NoNewWindow -ErrorAction SilentlyContinue
}

function SetC2WTSToLocalAccount {
    $claimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
    $claimsService = $claimsServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
    if ($claimsService.Status -ne "Online") { throw "C2WTS not online"; }
    $pi = $claimsService.Service.ProcessIdentity 
    $pi.Username = "NT AUTHORITY\SYSTEM"; 
    $pi.Update();
}

function SP-CreateUserProfileServiceApplication {
    # Create user profile service application and set up sync
    try {
        $userProfileServiceProxyName = "$userProfileServiceName Proxy";
        # Get the service instance
        $profileServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
        $profileServiceInstance = $profileServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
         # Start Service instance
        Write-Host -ForegroundColor White " - Starting User Profile Service instance..."
        if (($profileServiceInstance.Status -eq "Disabled") -or ($profileServiceInstance.Status -ne "Online")) {
            $profileServiceInstance.Provision()
            if (-not $?) { Throw " - Failed to start User Profile Service instance" }
            Write-Host -ForegroundColor Yellow " - Waiting for User Profile Service..." -NoNewline
            while ($profileServiceInstance.Status -ne "Online") {
                Write-Host -ForegroundColor Yellow "." -NoNewline
                Start-Sleep 1
                $profileServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
                $profileServiceInstance = $profileServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black $($profileServiceInstance.Status)
        }

        # Create a Profile Service Application
        $profileServiceApp = (Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileApplication"});
        if ($profileServiceApp -eq $null) {
            # Create MySite Host, if not already created
            SP-CreateMySiteHost;
            # Create Service App
            Write-Host -ForegroundColor White " - Creating $userProfileServiceName..."
            CreateUPSAsAdmin
            Write-Host -ForegroundColor Yellow " - Waiting for $userProfileServiceName..." -NoNewline
            $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
            while ($profileServiceApp.Status -ne "Online") {
                [int]$UPSWaitTime = 0
                # Wait 2 minutes for either the UPS to be created, or the UAC prompt to time out
                while (($UPSWaitTime -lt 120) -and ($profileServiceApp.Status -ne "Online")) {
                    Write-Host -ForegroundColor Yellow "." -NoNewline
                    Start-Sleep 1
                    $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                    [int]$UPSWaitTime += 1
                }
                # If it still isn't Online after 2 minutes, prompt to try again
                if (!($profileServiceApp)) {
                    Write-Host -ForegroundColor Yellow "."
                    Write-Warning "Timed out waiting for service creation (maybe a UAC prompt?)"
                    Write-Host "`a`a`a" # System beeps
                    Pause "try again"
                    CreateUPSAsAdmin
                    Write-Host -ForegroundColor Yellow " - Waiting for $userProfileServiceName..." -NoNewline
                    $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                }
                Else {
                    break
                }
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black $($profileServiceApp.Status)
            # Wait a few seconds for the CreateUPSAsAdmin function to complete
            Start-Sleep 30
            # Get our new Profile Service App
            $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
            if (!($profileServiceApp)) {Throw " - Could not get $userProfileServiceName!";}
            # Create Proxy
            Write-Host -ForegroundColor White " - Creating $userProfileServiceName Proxy..."
            $profileServiceAppProxy  = New-SPProfileServiceApplicationProxy -Name "$userProfileServiceProxyName" -ServiceApplication $profileServiceApp -DefaultProxyGroup
            if (-not $?) { Throw " - Failed to create $userProfileServiceName Proxy" }
        }

        # Grant permissions.
        Write-Host -ForegroundColor White " - Granting rights to ($userProfileServiceName):"
        # Create a variable that contains the guid for the User Profile service for which you want to delegate permissions
        $serviceAppIDToSecure = Get-SPServiceApplication $($profileServiceApp.Id);
        # Create a variable that contains the list of administrators for the service application
        $profileServiceAppSecurity = Get-SPServiceApplicationSecurity $serviceAppIDToSecure -Admin;
        # Create a variable that contains the permissions for the service application
        $profileServiceAppPermissions = Get-SPServiceApplicationSecurity $serviceAppIDToSecure;
        # Get account principals
        $currentUserAcctPrincipal = New-SPClaimsPrincipal -Identity $env:USERDOMAIN\$env:USERNAME -IdentityType WindowsSamAccountName
        $spServiceAcctPrincipal = New-SPClaimsPrincipal -Identity $($spServiceAcctName) -IdentityType WindowsSamAccountName
        $spAdminAcctPrincipal = New-SPClaimsPrincipal -Identity $($spAdminAcctName) -IdentityType WindowsSamAccountName
        Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $currentUserAcctPrincipal -Rights "Full Control"
        Grant-SPObjectSecurity $profileServiceAppPermissions -Principal $currentUserAcctPrincipal -Rights "Full Control"
        Grant-SPObjectSecurity $profileServiceAppPermissions -Principal $spServiceAcctPrincipal -Rights "Full Control"
        Grant-SPObjectSecurity $profileServiceAppPermissions -Principal $spAdminAcctPrincipal -Rights "Full Control"
        # Apply the changes to the User Profile service application
        Set-SPServiceApplicationSecurity $serviceAppIDToSecure -objectSecurity $profileServiceAppSecurity -Admin
        Set-SPServiceApplicationSecurity $serviceAppIDToSecure -objectSecurity $profileServiceAppPermissions
        Write-Host -ForegroundColor White " - Done granting rights."

        # Add resource link to CA.
        SP-AddResourcesLink "User Profile Administration" ("_layouts/ManageUserProfileServiceApplication.aspx?ApplicationID=" +  $profileServiceApp.Id);

        # Configure User Profile Sync Service
        if ($disableUPSS -ne $null -and $disableUPSS -eq $false) { SP-ConfigureUPSS; }
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning the User Profile Service Application"
    }
}

function SP-ConfigureUPSS {
    try {
        # Configure User Profile Sync Service
        Write-Host -ForegroundColor White " - Configuring User Profile Sync Service";
        # Get User Profile Service
        $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
        if ($profileServiceApp -eq $null) { throw "User Profile Service App not provisioned"; }
        # Get User Profile Synchronization Service
        Write-Host -ForegroundColor White " - Checking User Profile Synchronization Service..." 
        $profileSyncServices = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"})
        $profileSyncService = $profileSyncServices | ? {MatchComputerName $_.Parent.Address $env:COMPUTERNAME}
        if (!($profileSyncServices | ? {$_.Status -eq "Online"})) {
            # Add Farm account to admins group.
            AddAccountToAdmin -spAccountName $spFarmAcctName;
            # Check for an existing UPS credentials timer job (e.g. from a prior provisioning attempt), and delete it
            $UPSCredentialsJob = Get-SPTimerJob | ? {$_.Name -eq "windows-service-credentials-FIMSynchronizationService"}
            if ($UPSCredentialsJob.Status -eq "Online") {
                Write-Host -ForegroundColor White " - Deleting existing sync credentials timer job..."
                $UPSCredentialsJob.Delete()
            }
            # UPSS account is the UPS account.
            UpdateProcessIdentity $profileSyncService -svcName $spUPSAcctName;
            $profileSyncService.Update()
            Write-Host -ForegroundColor White " - Waiting for User Profile Synchronization Service..." -NoNewline
            # Provision the User Profile Sync Service (machine uses same account as timer service)
            $profileServiceApp.SetSynchronizationMachine($env:COMPUTERNAME, $profileSyncService.Id, $spFarmAcctName, $spFarmAcctPWD);
            if (($profileSyncService.Status -ne "Provisioning") -and ($profileSyncService.Status -ne "Online")) {
                Write-Host -ForegroundColor Yellow "`n - Waiting for User Profile Synchronization Service to start..." -NoNewline
            }
            # Monitor User Profile Sync service status
            while ($profileSyncService.Status -ne "Online") {
                while ($profileSyncService.Status -ne "Provisioning") {
                    Write-Host -ForegroundColor Yellow "." -NoNewline
                    Start-Sleep 1
                    $profileSyncService = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq `
                        "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | ? {MatchComputerName $_.Parent.Address $env:COMPUTERNAME}
                }
                if ($profileSyncService.Status -eq "Provisioning") {
                    Write-Host -BackgroundColor Yellow -ForegroundColor Black $($profileSyncService.Status)
                    Write-Host -ForegroundColor Yellow " - Provisioning User Profile Sync Service, please wait..." -NoNewline
                }
                while($profileSyncService.Status -eq "Provisioning" -and $profileSyncService.Status -ne "Disabled") {
                    Write-Host -ForegroundColor Yellow "." -NoNewline
                    Start-Sleep 1
                    $profileSyncService = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq `
                        "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | ? {MatchComputerName $_.Parent.Address $env:COMPUTERNAME}
                }
                if ($profileSyncService.Status -ne "Online") {
                    Write-Host -ForegroundColor Red ".`a`a"
                    Write-Host -BackgroundColor Red -ForegroundColor Black " - User Profile Synchronization Service could not be started!"
                    break;
                }
                else {
                    Write-Host -BackgroundColor Yellow -ForegroundColor Black $($profileSyncService.Status)
                    # Need to recycle the Central Admin app pool before we can do anything with the User Profile Sync Service
                    Write-Host -ForegroundColor White " - Recycling Central Admin app pool..."
                    # From http://sharepoint.nauplius.net/2011/09/iisreset-not-required-after-starting.html
                    $appPool = gwmi -Namespace "root\MicrosoftIISv2" -class "IIsApplicationPool" | `
                        where {$_.Name -eq "W3SVC/APPPOOLS/SharePoint Central Administration v4"}
                    if ($appPool) { $appPool.Recycle() }
                    $newlyProvisionedSync = $true
                }
            }
        }
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning the User Profile Sync Service"
    }
    finally {
        # Remove the Farm account from admins group.
        RemoveAccountFromAdmin -spAccountName $spFarmAcctName;
    }
}

function CreateUPSAsAdmin {
    # Create the UPS app.
    try {
        $mySiteURL = "http://$env:COMPUTERNAME";
        $mySitePort = 8080
        $mySiteHostLocation = $mySiteURL + ":" + $mySitePort
        $userProfileServiceName = "User Profile Service Application";
        # Set the ProfileDBServer, SyncDBServer and SocialDBServer to the same value ($dbServer). 
        $profileDBServer = $dbServer
        $syncDBServer = $dbServer
        $socialDBServer = $dbServer
        $profileDB = $dbPrefix + "_Service_UPS_Profile";
        $syncDB = $dbPrefix + "_Service_UPS_Sync";
        $socialDB = $dbPrefix + "_Service_UPS_Social";
        # Create the UPS app.
        $applicationPool = Get-HostedServicesAppPool
        $newProfileServiceApp = New-SPProfileServiceApplication -Name $userProfileServiceName -ApplicationPool $applicationPool.Name `
            -ProfileDBName $profileDB -SocialDBName $socialDB -ProfileSyncDBName $syncDB -MySiteHostLocation $mySiteHostLocation;
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning the User Profile Service Application";
    }
}

function SP-CreateSPUsageApp {
    # Create the SharePoint Usage App.
    try {
        $spUsageDB = $dbPrefix + "_Service_UsageApp";
        $getSPUsageApplication = Get-SPUsageApplication
        if ($getSPUsageApplication -eq $null) {
            Write-Host -ForegroundColor White " - Provisioning SP Usage Application..."
            New-SPUsageApplication -Name $spUsageApplicationName -DatabaseServer $dbServer -DatabaseName $spUsageDB | Out-Null
            # Need this to resolve a known issue with the Usage Application Proxy not automatically starting/provisioning
            # Thanks and credit to Jesper Nygaard Schi?tt (jesper@schioett.dk) per http://autospinstaller.codeplex.com/Thread/View.aspx?ThreadId=237578 !
            Write-Host -ForegroundColor White " - Fixing Usage and Health Data Collection Proxy..."
            $spUsageApplicationProxy = Get-SPServiceApplicationProxy | where {$_.DisplayName -eq $spUsageApplicationName}
            $spUsageApplicationProxy.Provision()
            # End Usage Proxy Fix
            Write-Host -ForegroundColor White " - Enabling usage processing timer job..."
            $usageProcessingJob = Get-SPTimerJob | ? {$_.TypeName -eq "Microsoft.SharePoint.Administration.SPUsageProcessingJobDefinition"}
            $usageProcessingJob.IsDisabled = $false
            $usageProcessingJob.Update()
            Write-Host -ForegroundColor White " - Done provisioning SP Usage Application."
        }
        else {
            Write-Host -ForegroundColor White " - SP Usage Application already provisioned."
        }
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning the SP Usage Application"
    }
}

function SP-CreateSecureStoreServiceApp {
    # Create a secure store app.
    try {        
        $secureStoreServiceAppProxyName = "$secureStoreServiceAppName Proxy";
        $secureStoreDB = $dbPrefix + "_Service_SecureStore";
        Write-Host -ForegroundColor White " - Provisioning Secure Store Service Application..."
        $applicationPool = Get-HostedServicesAppPool;
        # Get the service instance
        $secureStoreServiceInstances = Get-SPServiceInstance | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance])}
        $secureStoreServiceInstance = $secureStoreServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        if (-not $?) { Throw " - Failed to find Secure Store service instance" }
        # Start Service instance
        if ($secureStoreServiceInstance.Status -eq "Disabled") {
            Write-Host -ForegroundColor White " - Starting Secure Store Service Instance..."
            $secureStoreServiceInstance.Provision()
            if (-not $?) { Throw " - Failed to start Secure Store service instance" }
            Write-Host -ForegroundColor Yellow " - Waiting for Secure Store service..." -NoNewline
            while ($secureStoreServiceInstance.Status -ne "Online") {
                Write-Host -ForegroundColor Yellow "." -NoNewline
                Start-Sleep 1
                $secureStoreServiceInstances = Get-SPServiceInstance | `
                    ? {$_.GetType().ToString() -eq "Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance"}
                $secureStoreServiceInstance = $secureStoreServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black $($secureStoreServiceInstance.Status)
        }
        # Create Service Application
        $getSPSecureStoreServiceApplication = Get-SPServiceApplication | `
            ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])}
        if ($getSPSecureStoreServiceApplication -eq $null) {
            Write-Host -ForegroundColor White " - Creating Secure Store Service Application..."
            New-SPSecureStoreServiceApplication -Name $secureStoreServiceAppName -PartitionMode:$false -Sharing:$false -DatabaseServer `
                $dbServer -DatabaseName $secureStoreDB -ApplicationPool $($applicationPool.Name) -AuditingEnabled:$true -AuditLogMaxSize 30 | Out-Null
            Write-Host -ForegroundColor White " - Creating Secure Store Service Application Proxy..."
            Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])} `
            | New-SPSecureStoreServiceApplicationProxy -Name $secureStoreServiceAppProxyName -DefaultProxyGroup | Out-Null
            Write-Host -ForegroundColor White " - Done creating Secure Store Service Application."
            # Create keys
            $secureStore = Get-SPServiceApplicationProxy | Where {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplicationProxy])}
            Start-Sleep 5
            Write-Host -ForegroundColor White " - Creating the Master Key..."
            Update-SPSecureStoreMasterKey -ServiceApplicationProxy $secureStore.Id -Passphrase $passphrase
            Start-Sleep 5
            Write-Host -ForegroundColor White " - Creating the Application Key..."
            Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase $passphrase -ErrorAction SilentlyContinue
            Start-Sleep 5
            if (!$?) {
                # Try again...
                Write-Host -ForegroundColor White " - Creating the Application Key (2nd attempt)..."
                Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase $passphrase
            }
        }
        else {
            Write-Host -ForegroundColor White " - Secure Store Service Application already provisioned."
        }
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning secure store application"
    }
    Write-Host -ForegroundColor White " - Done creating/configuring Secure Store Service Application."
}

function SP-ConfigureTracing {
    # Configure tracing.
    # Make sure a credential deployment job doesn't already exist
    if (!(Get-SPTimerJob -Identity "windows-service-credentials-SPTraceV4")) {
        $spTraceV4 = (Get-SPFarm).Services | where {$_.Name -eq "SPTraceV4"}
        $appPoolAcctDomain, $appPoolAcctUser = $spServiceAcctName -Split "\\"
        Write-Host -ForegroundColor White " - Applying service account $($spServiceAcctName) to service SPTraceV4..."
        # Add to Performance Monitor Users group
        Write-Host -ForegroundColor White " - Adding $($spServiceAcctName) to local Performance Monitor Users group..."
        try {
            ([ADSI]"WinNT://$env:COMPUTERNAME/Performance Monitor Users,group").Add("WinNT://$appPoolAcctDomain/$appPoolAcctUser")
            if (-not $?) {Throw}
        }
        catch {
            Write-Host -ForegroundColor White " - $($spServiceAcctName) is already a member of Performance Monitor Users."
        }
        # Add to Performance Log Users group
        Write-Host -ForegroundColor White " - Adding $($spServiceAcctName) to local Performance Log Users group..."
        try {
            ([ADSI]"WinNT://$env:COMPUTERNAME/Performance Log Users,group").Add("WinNT://$appPoolAcctDomain/$appPoolAcctUser")
            if (-not $?) {Throw}
        }
        catch {
            Write-Host -ForegroundColor White " - $($spServiceAcctName) is already a member of Performance Log Users."
        }
        try {
            UpdateProcessIdentity $spTraceV4
        }
        catch {
            Write-Output $_
            Throw " - An error occurred updating the service account for service SPTraceV4."
        }
        # Restart SPTraceV4 service so changes to group memberships above can take effect
        Write-Host -ForegroundColor White " - Restarting service SPTraceV4..."
        Restart-Service -Name "SPTraceV4" -Force
    }
    else {
        Write-Warning "Timer job `"windows-service-credentials-SPTraceV4`" already exists."
        Write-Host -ForegroundColor Yellow "Check that $($spServiceAcctName) is a member of the Performance Log Users and Performance Monitor Users local groups once install completes."
    }
}

function SP-CreateBusinessDataConnectivityServiceApp {
    # Create BCS service app
    try {
        $bdcDataDB = $dbPrefix + "_Service_BCS";
        $bdcAppProxyName = "$bdcAppName Proxy";
        Write-Host -ForegroundColor White " - Provisioning $bdcAppName"
        $applicationPool = Get-HostedServicesAppPool $xmlinput
        Write-Host -ForegroundColor White " - Checking local service instance..."
        # Get the service instance
        $bdcServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
        $bdcServiceInstance = $bdcServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        If (-not $?) { Throw " - Failed to find the service instance" }
        # Start Service instances
        If($bdcServiceInstance.Status -eq "Disabled") {
            Write-Host -ForegroundColor White " - Starting $($bdcServiceInstance.TypeName)..."
            $bdcServiceInstance.Provision()
            If (-not $?) { Throw " - Failed to start $($bdcServiceInstance.TypeName)" }
            # Wait
            Write-Host -ForegroundColor Yellow " - Waiting for $($bdcServiceInstance.TypeName)..." -NoNewline
            while ($bdcServiceInstance.Status -ne "Online") {
                Write-Host -ForegroundColor Yellow "." -NoNewline
                Start-Sleep 1
                $bdcServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
                $bdcServiceInstance = $bdcServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black ($bdcServiceInstance.Status)
        }
        else {
            Write-Host -ForegroundColor White " - $($bdcServiceInstance.TypeName) already started."
        }
        # Create a Business Data Catalog Service Application
        if ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceApplication"}) -eq $null) {
            # Create Service App
            Write-Host -ForegroundColor White " - Creating $bdcAppName..."
            $bdcDataServiceApp = New-SPBusinessDataCatalogServiceApplication -Name $bdcAppName -ApplicationPool $applicationPool -DatabaseServer $dbServer -DatabaseName $bdcDataDB
            if (-not $?) { Throw " - Failed to create $bdcAppName" }
        }
        else {
            Write-Host -ForegroundColor White " - $bdcAppName already provisioned."
        }
        Write-Host -ForegroundColor White " - Done creating $bdcAppName."
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning Business Data Connectivity application"
    }
}

function SP-CreateExcelServiceApp {
    # Create excel services.
    try {
        Write-Host -ForegroundColor White " - Provisioning $excelAppName..."
        $applicationPool = Get-HostedServicesAppPool;
        Write-Host -ForegroundColor White " - Checking local service instance..."
        # Get the service instance
        $excelServiceInstances = Get-SPServiceInstance | `
            ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
        $excelServiceInstance = $excelServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        if (-not $?) { Throw " - Failed to find the service instance" }
        # Start Service instances
        if($excelServiceInstance.Status -eq "Disabled") {
            Write-Host -ForegroundColor White " - Starting $($excelServiceInstance.TypeName)..."
            $excelServiceInstance.Provision()
            if (-not $?) { Throw " - Failed to start $($excelServiceInstance.TypeName) instance" }
            Write-Host -ForegroundColor Yellow " - Waiting for $($excelServiceInstance.TypeName)..." -NoNewline
            while ($excelServiceInstance.Status -ne "Online") {
                Write-Host -ForegroundColor Yellow "." -NoNewline
                Start-Sleep 1
                $excelServiceInstances = Get-SPServiceInstance | `
                    ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
                $excelServiceInstance = $excelServiceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black ($excelServiceInstance.Status)
        }
        else {
            Write-Host -ForegroundColor White " - $($excelServiceInstance.TypeName) already started."
        }
        # Create an Excel Service Application
        $excelServiceApp = Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceApplication"}
        if ($excelServiceApp -eq $null) {
            # Create Service App
            Write-Host -ForegroundColor White " - Creating $excelAppName..."
            # Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
            if (!(Get-Command New-SPExcelServiceApplication -ErrorAction SilentlyContinue)) {
                Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
                Remove-PSSnapin Microsoft.SharePoint.PowerShell
                Load-SharePoint-PowerShell
            }
            $excelServiceApp = New-SPExcelServiceApplication -name $excelAppName -ApplicationPool $($applicationPool.Name) -Default
            if (-not $?) { Throw " - Failed to create $excelAppName" }
            $caUrl = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS").GetValue("CentralAdministrationURL")
            New-SPExcelFileLocation -LocationType SharePoint -IncludeChildren -Address $caUrl -ExcelServiceApplication $excelAppName -ExternalDataAllowed 2 -WorkbookSizeMax 10 | Out-Null
        }
        else {
            Write-Host -ForegroundColor White " - $excelAppName already provisioned."
        }
        Write-Host -ForegroundColor White " - Configuring service app settings..."
        # Configure unattended accounts, based on:
        # http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
        Write-Host -ForegroundColor White " - Setting unattended account credentials..."
        # Reget application to prevent update conflict error message
        $excelServiceApp = Get-SPExcelServiceApplication
        # Get account credentials
        $excelAcct = $spServiceAcctName;
        $excelAcctPWD = $spServiceAcctPWD;
        $secPassword = ConvertTo-SecureString "$excelAcctPWD" -AsPlaintext -Force
        $unattendedAccount = New-Object System.Management.Automation.PsCredential $excelAcct,$secPassword
        # Set the group claim and admin principals
        $groupClaim = New-SPClaimsPrincipal -Identity "nt authority\authenticated users" -IdentityType WindowsSamAccountName
        $adminPrincipal = New-SPClaimsPrincipal -Identity "$($env:userdomain)\$($env:username)" -IdentityType WindowsSamAccountName
        # Set the field values
        $secureUserName = ConvertTo-SecureString $unattendedAccount.UserName -AsPlainText -Force
        $securePassword = $unattendedAccount.Password
        $credentialValues = $secureUserName, $securePassword
        # Set the Target App Name and create the Target App
        $name = "$($excelServiceApp.ID)-ExcelUnattendedAccount"
        Write-Host -ForegroundColor White " - Creating Secure Store Target Application $name..."
        $secureStoreTargetApp = New-SPSecureStoreTargetApplication -Name $name `
            -FriendlyName "Excel Services Unattended Account Target App" `
            -ApplicationType Group `
            -TimeoutInMinutes 3
        # Set the account fields
        $usernameField = New-SPSecureStoreApplicationField -Name "User Name" -Type WindowsUserName -Masked:$false
        $passwordField = New-SPSecureStoreApplicationField -Name "Password" -Type WindowsPassword -Masked:$false
        $fields = $usernameField, $passwordField
        # Get the service context
        $subId = [Microsoft.SharePoint.SPSiteSubscriptionIdentifier]::Default
        $context = [Microsoft.SharePoint.SPServiceContext]::GetContext($excelServiceApp.ServiceApplicationProxyGroup, $subId)
        # Check to see if the Secure Store App already exists
        $secureStoreApp = Get-SPSecureStoreApplication -ServiceContext $context -Name $name -ErrorAction SilentlyContinue
        if ($secureStoreApp -eq $null) { 
            # Doesn't exist so create.
            Write-Host -ForegroundColor White " - Creating Secure Store Application..."
            $secureStoreApp = New-SPSecureStoreApplication -ServiceContext $context `
                -TargetApplication $secureStoreTargetApp `
                -Administrator $adminPrincipal `
                -CredentialsOwnerGroup $groupClaim `
                -Fields $fields;
        }
        # Update the field values
        Write-Host -ForegroundColor White " - Updating Secure Store Group Credential Mapping..."
        Update-SPSecureStoreGroupCredentialMapping -Identity $secureStoreApp -Values $credentialValues
        # Set the unattended service account application ID
        Set-SPExcelServiceApplication -Identity $excelServiceApp -UnattendedAccountApplicationId $name
        Write-Host -ForegroundColor White " - Done creating $excelAppName."
    }
    catch {
        Write-Output $_
        Throw " - Error provisioning Excel Service Application"
    }
}

function SP-CreateAccess2010ServiceApp {
    # Create support for legacy Access Services
    $serviceInstanceType = "Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $access2010AppName `
        -ServiceDBName ($dbPrefix + "_Service_Access2010") `
        -ServiceGetCmdlet "Get-SPAccessServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPAccessServiceApplication -Default" `
        -ServiceProxyNewCmdlet "New-SPAccessServiceApplicationProxy" 
        # Fake cmdlet (and not needed for Access Services), but the CreateGenericServiceApplication function expects something
}

function SP-CreateVisioServiceApp {
    # Create Visio Services App
    $serviceInstanceType = "Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $visioAppName `
        -ServiceDBName ($dbPrefix + "_Service_Visio") `
        -ServiceGetCmdlet "Get-SPVisioServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPVisioServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPVisioServiceApplication" `
        -ServiceProxyNewCmdlet "New-SPVisioServiceApplicationProxy"

    if (Get-Command -Name Get-SPVisioServiceApplication -ErrorAction SilentlyContinue) {
        # http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
        Write-Host -ForegroundColor White " - Setting unattended account credentials..."
        $serviceApplication = Get-SPServiceApplication -name $visioAppName
        # Get account credentials
        $visioAcct = $spServiceAcctName;
        $visioAcctPWD = $spServiceAcctPwd;
        $secPassword = ConvertTo-SecureString "$visioAcctPWD" -AsPlaintext -Force
        $unattendedAccount = New-Object System.Management.Automation.PsCredential $visioAcct,$secPassword
        # Set the group claim and admin principals
        $groupClaim = New-SPClaimsPrincipal -Identity "nt authority\authenticated users" -IdentityType WindowsSamAccountName
        $adminPrincipal = New-SPClaimsPrincipal -Identity "$($env:userdomain)\$($env:username)" -IdentityType WindowsSamAccountName
        # Set the field values
        $secureUserName = ConvertTo-SecureString $unattendedAccount.UserName -AsPlainText -Force
        $securePassword = $unattendedAccount.Password
        $credentialValues = $secureUserName, $securePassword
        # Set the Target App Name and create the Target App
        $name = "$($serviceApplication.ID)-VisioUnattendedAccount"
        Write-Host -ForegroundColor White " - Creating Secure Store Target Application $name..."
        $secureStoreTargetApp = New-SPSecureStoreTargetApplication -Name $name `
            -FriendlyName "Visio Services Unattended Account Target App" `
            -ApplicationType Group `
            -TimeoutInMinutes 3
        # Set the account fields
        $usernameField = New-SPSecureStoreApplicationField -Name "User Name" -Type WindowsUserName -Masked:$false
        $passwordField = New-SPSecureStoreApplicationField -Name "Password" -Type WindowsPassword -Masked:$false
        $fields = $usernameField, $passwordField
        # Get the service context
        $subId = [Microsoft.SharePoint.SPSiteSubscriptionIdentifier]::Default
        $context = [Microsoft.SharePoint.SPServiceContext]::GetContext($serviceApplication.ServiceApplicationProxyGroup, $subId)
        # Check to see if the Secure Store App already exists
        $secureStoreApp = Get-SPSecureStoreApplication -ServiceContext $context -Name $name -ErrorAction SilentlyContinue
        if ($secureStoreApp -eq $null) {
            # Doesn't exist so create.
            Write-Host -ForegroundColor White " - Creating Secure Store Application..."
            $secureStoreApp = New-SPSecureStoreApplication -ServiceContext $context `
                -TargetApplication $secureStoreTargetApp `
                -Administrator $adminPrincipal `
                -CredentialsOwnerGroup $groupClaim `
                -Fields $fields
        }
        # Update the field values
        Write-Host -ForegroundColor White " - Updating Secure Store Group Credential Mapping..."
        Update-SPSecureStoreGroupCredentialMapping -Identity $secureStoreApp -Values $credentialValues
        # Set the unattended service account application ID
        Write-Host -ForegroundColor White " - Setting Application ID for Visio Service..."
        $serviceApplication | Set-SPVisioExternalData -UnattendedServiceAccountApplicationID $name
    }
}

function SP-CreatePerformancePointServiceApp {
    # Create PerformancePoint App.
    $serviceDB = ($dbPrefix + "_Service_PerformancePoint");
    $serviceInstanceType = "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $perfPointAppName `
        -ServiceDBName $serviceDB `
        -ServiceGetCmdlet "Get-SPPerformancePointServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPPerformancePointServiceApplication" `
        -ServiceProxyNewCmdlet "New-SPPerformancePointServiceApplicationProxy"

    $application = Get-SPPerformancePointServiceApplication | ? {$_.Name -eq $serviceConfig.Name}
    if ($application) {
        $farmAcct = $spFarmAcctName;
        Write-Host -ForegroundColor White " - Granting $farmAcct rights to database $serviceDB..."
        Get-SPDatabase | Where {$_.Name -eq $serviceDB} | Add-SPShellAdmin -UserName $farmAcct
        Write-Host -ForegroundColor White " - Setting PerformancePoint Data Source Unattended Service Account..."
        $performancePointAcct = $spServiceAcctName;
        $performancePointAcctPWD = $spServiceAcctPwd;
        $secPassword = ConvertTo-SecureString "$performancePointAcctPWD" -AsPlaintext -Force
        $performancePointCredential = New-Object System.Management.Automation.PsCredential $performancePointAcct,$secPassword
        $application | Set-SPPerformancePointSecureDataValues -DataSourceUnattendedServiceAccount $performancePointCredential
    }
}

function SP-CreateWordAutomationServiceApp {
    # Create Word Automation Service App.
    $serviceDB = ($dbPrefix + "_Service_WordAutomation");
    $serviceInstanceType = "Microsoft.Office.Word.Server.Service.WordServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $wordAutoAppName `
        -ServiceDBName $serviceDB `
        -ServiceGetCmdlet "Get-SPServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPWordConversionServiceApplication -DatabaseServer $dbServer -DatabaseName $serviceDB -Default" `
        -ServiceProxyNewCmdlet "New-SPWordConversionServiceApplicationProxy" 
        # Fake cmdlet, but the CreateGenericServiceApplication function expects something
    # Run the Word Automation Timer Job immediately; otherwise we will have a Health Analyzer error condition until the job runs as scheduled
    if (Get-SPServiceApplication | ? {$_.DisplayName -eq $($serviceConfig.Name)}) {
        Get-SPTimerJob | ? {$_.GetType().ToString() -eq "Microsoft.Office.Word.Server.Service.QueueJob"} | ForEach-Object {$_.RunNow()}
    }
}

function CreateGenericServiceApplication() {
    # Creata generic service application - used for office apps.
    param
    (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceInstanceType,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceName,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceDBName,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceGetCmdlet,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyGetCmdlet,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceNewCmdlet,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyNewCmdlet,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyNewParams
    )
    try {
        $serviceProxyName = "$serviceName Proxy";
        $applicationPool = Get-HostedServicesAppPool
        Write-Host -ForegroundColor White " - Provisioning $serviceName..."
        # get the service instance
        $serviceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq $serviceInstanceType}
        $serviceInstance = $serviceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
        if (!$serviceInstance) { Throw " - Failed to get service instance - check product version (Standard vs. Enterprise)" }
        # Start Service instance
        Write-Host -ForegroundColor White " - Checking $($serviceInstance.TypeName) instance..."
        if (($serviceInstance.Status -eq "Disabled") -or ($serviceInstance.Status -ne "Online")) {
            Write-Host -ForegroundColor White " - Starting $($serviceInstance.TypeName) instance..."
            $serviceInstance.Provision()
            if (-not $?) { Throw " - Failed to start $($serviceInstance.TypeName) instance" }
            Write-Host -ForegroundColor Yellow " - Waiting for $($serviceInstance.TypeName) instance..." -NoNewline
            while ($serviceInstance.Status -ne "Online") {
                Write-Host -ForegroundColor Yellow "." -NoNewline
                Start-Sleep 1
                $serviceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq $serviceInstanceType}
                $serviceInstance = $serviceInstances | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Yellow -ForegroundColor Black $($serviceInstance.Status)
        }
        else {
            Write-Host -ForegroundColor White " - $($serviceInstance.TypeName) instance already started."
        }
        # Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
        if (!(Get-Command $serviceGetCmdlet -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
            Remove-PSSnapin Microsoft.SharePoint.PowerShell
            Load-SharePoint-PowerShell
        }
        $getServiceApplication = Invoke-Expression "$serviceGetCmdlet | ? {`$_.Name -eq `"$serviceName`"}"
        if ($getServiceApplication -eq $null) {
            Write-Host -ForegroundColor White " - Creating $serviceName..."
            If (($serviceInstanceType -eq "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance")) {
                $newServiceApplication = Invoke-Expression `
                    "$serviceNewCmdlet -Name `"$serviceName`" -ApplicationPool `$applicationPool -DatabaseServer `$dbServer -DatabaseName `$serviceDBName"
            }
            else {
                $newServiceApplication = Invoke-Expression "$serviceNewCmdlet -Name `"$serviceName`" -ApplicationPool `$applicationPool"
            }
            $getServiceApplication = Invoke-Expression "$serviceGetCmdlet | ? {`$_.Name -eq `"$serviceName`"}"
            if ($getServiceApplication) {
                Write-Host -ForegroundColor White " - Provisioning $serviceName Proxy..."
                # Because apparently the teams developing the cmdlets for the various service apps didn't communicate with each other, 
                # we have to account for the different ways each proxy is provisioned!
                switch ($serviceInstanceType) {
                    "Microsoft.Office.Server.PowerPoint.SharePoint.Administration.PowerPointWebServiceInstance" `
                    {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -AddToDefaultGroup | Out-Null}
                    "Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance" `
                    {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication.Name | Out-Null}
                    "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance" `
                    {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -Default | Out-Null}
                    "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
                    "Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
                    "Microsoft.Office.Word.Server.Service.WordServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
    				"Microsoft.SharePoint.SPSubscriptionSettingsServiceInstance" `
                    {& $serviceProxyNewCmdlet -ServiceApplication $newServiceApplication | Out-Null}
                    "Microsoft.Office.Server.WorkManagement.WorkManagementServiceInstance" `
                    {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -DefaultProxyGroup | Out-Null}
                    "Microsoft.Office.TranslationServices.TranslationServiceInstance" {} # Do nothing because the service app cmdlet automatically creates a proxy with the default name
                    "Microsoft.Office.Access.Services.MossHost.AccessServicesWebServiceInstance" `
                    {& $serviceProxyNewCmdlet -application $newServiceApplication | Out-Null}
                    "Microsoft.Office.Server.PowerPoint.Administration.PowerPointConversionServiceInstance" `
                    {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -AddToDefaultGroup | Out-Null}
                    "Microsoft.Office.Project.Server.Administration.PsiServiceInstance" {} # Do nothing because the service app cmdlet automatically creates a proxy with the default name
                    Default {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication | Out-Null}
                }
                Write-Host -ForegroundColor White " - Done provisioning $serviceName. "
            }
            else {
                Write-Warning "An error occurred provisioning $serviceName! Check the log for any details, then try again."
            }
        }
        else {
            Write-Host -ForegroundColor White " - $serviceName already created."
        }
    }
    catch {
        Write-Output $_
    }
}

function SP-CreateAppManagementServiceApp {
    # Create the app management service app.
    $serviceDB = $dbPrefix + "_Service_AppManagement";
    $serviceInstanceType = "Microsoft.SharePoint.AppManagement.AppManagementServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $appMgmtName `
        -ServiceDBName = $serviceDB `
        -ServiceGetCmdlet "Get-SPServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
		-ServiceNewCmdlet "New-SPAppManagementServiceApplication -DatabaseServer $dbServer -DatabaseName $serviceDB" `
        -ServiceProxyNewCmdlet "New-SPAppManagementServiceApplicationProxy"
		# Configure your app domain and location
		Write-Host -ForegroundColor White " - Setting App Domain `"$($appDomain)`"..."
	    Set-SPAppDomain -AppDomain $appDomain
}

function SP-CreateSubscriptionSettingsServiceApp {
    # Create the subscription service app.
    $serviceDB = $dbPrefix + "_Service_AppSubscription";
    $serviceInstanceType = "Microsoft.SharePoint.SPSubscriptionSettingsServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $appSubsName `
        -ServiceDBName $serviceDB `
        -ServiceGetCmdlet "Get-SPServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
		-ServiceNewCmdlet "New-SPSubscriptionSettingsServiceApplication -DatabaseServer $dbServer -DatabaseName $serviceDB" `
        -ServiceProxyNewCmdlet "New-SPSubscriptionSettingsServiceApplicationProxy"
		Write-Host -ForegroundColor White " - Setting Site Subscription name `"$($appSubscriptionName)`"..."
        # Wait for the service to be available.
        Start-Sleep 20;
	    Set-SPAppSiteSubscriptionName -Name $appSubscriptionName -Confirm:$false
}

function SP-CreateWorkManagementServiceApp {
    # Create the work management service app.
    $serviceInstanceType = "Microsoft.Office.Server.WorkManagement.WorkManagementServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $workMgmtName `
        -ServiceDBName ($dbPrefix + "_Service_WorkManagement") `
        -ServiceGetCmdlet "Get-SPServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPWorkManagementServiceApplication" `
        -ServiceProxyNewCmdlet "New-SPWorkManagementServiceApplicationProxy"
}

function SP-CreateMachineTranslationServiceApp {
    # Create the translation service app.
    $translationDatabase = $dbPrefix + "_Service_TranslationSvc";
    $serviceInstanceType = "Microsoft.Office.TranslationServices.TranslationServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $transSvcName `
        -ServiceDBName $translationDatabase `
        -ServiceGetCmdlet "Get-SPServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPTranslationServiceApplication -DatabaseServer $dbServer -DatabaseName $translationDatabase -Default" `
        -ServiceProxyNewCmdlet "New-SPTranslationServiceApplicationProxy"
}

function SP-CreateAccessServicesApp {
    # Create the Access Services App - Require Full Text Indexing on DB server.
    $serviceInstanceType = "Microsoft.Office.Access.Services.MossHost.AccessServicesWebServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $accessAppName `
        -ServiceDBName ($dbPrefix + "_Service_AccessServices") `
        -ServiceGetCmdlet "Get-SPAccessServicesApplication" `
        -ServiceProxyGetCmdlet "Get-SPServicesApplicationProxy" `
        -ServiceNewCmdlet "New-SPAccessServicesApplication -DatabaseServer $dbServer -Default" `
        -ServiceProxyNewCmdlet "New-SPAccessServicesApplicationProxy"
}

function SP-CreatePowerPointConversionServiceApp {
    # Create the PowerPoint conversion service.
    $serviceInstanceType = "Microsoft.Office.Server.PowerPoint.Administration.PowerPointConversionServiceInstance"
    CreateGenericServiceApplication `
        -ServiceInstanceType $serviceInstanceType `
        -ServiceName $pwrpntConvApp `
        -serviceDBName ($dbPrefix + "_Service_PowerPointConversion") `
        -ServiceGetCmdlet "Get-SPServiceApplication" `
        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
        -ServiceNewCmdlet "New-SPPowerPointConversionServiceApplication" `
        -ServiceProxyNewCmdlet "New-SPPowerPointConversionServiceApplicationProxy"
}

function SP-ConfigureDistributedCacheService {
    # Configure the distributed cache.
    # Make sure a credential deployment job doesn't already exist, and that we are running SP2013
    if ((!(Get-SPTimerJob -Identity "windows-service-credentials-AppFabricCachingService"))) {
        $distributedCachingSvc = (Get-SPFarm).Services | where {$_.Name -eq "AppFabricCachingService"}
        $appPoolAcctDomain, $appPoolAcctUser = $spServiceAcctName -Split "\\"
        Write-Host -ForegroundColor White " - Applying service account $($spServiceAcctName) to service AppFabricCachingService..."
        try {
            UpdateProcessIdentity $distributedCachingSvc $spServiceAcctName
        }
        catch {
            Write-Output $_
            Write-Warning "An error occurred updating the service account for service AppFabricCachingService."
        }
    }
}

function SP-CreatePWAWebApp {
    $pwaContentDBName = ($dbPrefix + "_Content_PWA");
    SP-CreateWebApp -appPool "PWA App Pool" -webAppName "PWA" `
        -database $pwaContentDBName  -url $pwaWebAppUrl -port 80 -hostheader $pwaWebAppHostHeader
    # Do not provide a site collection template at this time.
    SP-CreateSiteCollection -appPool "PWA App Pool" -database $pwaContentDBName  `
        -siteCollectionName "Project Server" -siteURL $pwaWebAppUrl
}

function SP-ConfigureProjectServer {
    # Configure PWA.
    # There has to be a better way to check whether Project Server is installed...
    $projectServerInstalled = Test-Path -Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\CONFIG\BIN\Microsoft.ProjectServer.dll"
    if ($projectServerInstalled) {
        $serviceInstanceType = "Microsoft.Office.Project.Server.Administration.PsiServiceInstance"
        CreateGenericServiceApplication `
            -ServiceInstanceType $serviceInstanceType `
            -ServiceName $projServerApp `
            -ServiceDBName ($dbPrefix + "_Service_ProjectServer") `
            -ServiceGetCmdlet "Get-SPServiceApplication" `
            -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
			-ServiceNewCmdlet "New-SPProjectServiceApplication -Proxy:`$true" `
            -ServiceProxyNewCmdlet "New-SPProjectServiceApplicationProxy" 
            # We won't be using the proxy cmdlet though for Project Server
        # Update process account for Project services
        $projectServices = @("Microsoft.Office.Project.Server.Administration.ProjectEventService", `
            "Microsoft.Office.Project.Server.Administration.ProjectCalcService", `
            "Microsoft.Office.Project.Server.Administration.ProjectQueueService")
        foreach ($projectService in $projectServices) {
            $projectServiceInstances = (Get-SPFarm).Services | ? {$_.GetType().ToString() -eq $projectService}
            foreach ($projectServiceInstance in $projectServiceInstances) {
                UpdateProcessIdentity $projectServiceInstance
            }
        }
        # Create a Project Server Config DB
        $projServerDB = $dbPrefix + "_Config_PWA";
        Write-Host -ForegroundColor White " - Creating Project Server database `"$projServerDB`"..." -NoNewline
        $pwaDBState = Get-SPProjectDatabaseState -DatabaseServer $dbServer -Name $projServerDB;
        if (!$pwaDBState.Exists) {
            New-SPProjectDatabase -Name $projServerDB -ServiceApplication `
                (Get-SPServiceApplication | Where-Object {$_.Name -eq $projServerApp}) -DatabaseServer $dbServer -Tag "ProjectWebAppDB" | Out-Null
            if ($?) {Write-Host -ForegroundColor Black -BackgroundColor Blue "Done."}
            else {
                Write-Host -ForegroundColor White "."
                throw {"Error creating the Project Server database."}
            }
        }
        else {
            Write-Host -ForegroundColor Black -BackgroundColor Blue "Already exits."
        }
        Write-Host -ForegroundColor White " - Creating PWA web app and site collection";
        SP-CreatePWAWebApp;
        # Configure the new PWA web app
        $web = Get-SPWeb $pwaWebAppUrl 
        $web.Properties["PWA_TAG"]="ProjectWebAppDB" 
        $web.Properties.Update() 
        Enable-SPFeature pwasite -URL $pwaWebAppUrl -ErrorAction SilentlyContinue 
        # Create the new web template
        $PwaWeb = $pwaWebAppUrl + "/PWA";
        Write-Host -ForegroundColor White " - Configuring PWA start URL as $PwaWeb";
        New-SPweb -URL $PwaWeb -Template pwa#0 -ErrorAction SilentlyContinue | Out-Null;
        Sleep 3 
        Upgrade-SPProjectWebInstance -Identity $PwaWeb -Confirm:$False  | Out-Null;
        # Switch permission mode
        Set-SPPRojectPermissionMode –Url $PwaWeb -AdministratorAccount $spAdminAcctName -Mode ProjectServer
    }
    else {
        throw "Project Server binaries not installed";
    }
}

function SP-ConfigureBaseProjectServer {
    # Configure PWA.
    # There has to be a better way to check whether Project Server is installed...
    $projectServerInstalled = Test-Path -Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\CONFIG\BIN\Microsoft.ProjectServer.dll"
    if ($projectServerInstalled) {
        $serviceInstanceType = "Microsoft.Office.Project.Server.Administration.PsiServiceInstance"
        CreateGenericServiceApplication `
            -ServiceInstanceType $serviceInstanceType `
            -ServiceName $projServerApp `
            -ServiceDBName ($dbPrefix + "_Service_ProjectServer") `
            -ServiceGetCmdlet "Get-SPServiceApplication" `
            -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
			-ServiceNewCmdlet "New-SPProjectServiceApplication -Proxy:`$true" `
            -ServiceProxyNewCmdlet "New-SPProjectServiceApplicationProxy" 
            # We won't be using the proxy cmdlet though for Project Server
        # Update process account for Project services
        $projectServices = @("Microsoft.Office.Project.Server.Administration.ProjectEventService", `
            "Microsoft.Office.Project.Server.Administration.ProjectCalcService", `
            "Microsoft.Office.Project.Server.Administration.ProjectQueueService")
        foreach ($projectService in $projectServices) {
            $projectServiceInstances = (Get-SPFarm).Services | ? {$_.GetType().ToString() -eq $projectService}
            foreach ($projectServiceInstance in $projectServiceInstances) {
                UpdateProcessIdentity $projectServiceInstance
            }
        }
    }
    else {
        throw "Project Server binaries not installed";
    }
}

