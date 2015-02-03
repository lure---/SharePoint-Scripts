#############################################################
# SharePoint Farm Functions
# Rob Garrett
# With the help from http://autospinstaller.codeplex.com/

function SP-ExecCommonSPServerProvisioning {
    # Create SQL Alias
    #SQL-CreateAlias
    # Register SharePoint PowerShell Cmdlets
    SP-RegisterPS;
    # Disable loopback check.
    SP-DisableLoopback;
    # Create Farm
    SP-CreateOrJoinFarm;
    # Configure new or existing farm
    SP-ConfigureFarm;
}

function SP-GetFarmCredential {
    # Prompt for the farm account credentials.
    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Farm Account:"
    return $host.ui.PromptForCredential("Farm Setup", "Enter Farm Account Credentials:", "$spFarmAcctName", "NetBiosUserName" )
}

function SP-DisableLoopback {
    # Disable loopback check.
    $item = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -ErrorAction SilentlyContinue;
    if (!$item) {
        New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -Value "1" -PropertyType dword
    }
}

function SP-CreateOrJoinFarm {
    # Look for an existing farm and join the farm if not already joined, or create a new farm
    try {
        $configDB = $dbPrefix + "_Config_Farm";
        Write-Host -ForegroundColor White " - Checking farm membership for $env:COMPUTERNAME in `"$configDB`"..."
        $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB} -ErrorAction SilentlyContinue
    }
    catch {""}
    if ($spFarm -eq $null) {
        $farmCredential = SP-GetFarmCredential;
        $centralAdminContentDB = $dbPrefix + "_Content_Farm";
        Write-Host -ForegroundColor White " - Attempting to join farm on `"$configDB`"..."
        $pp = ConvertTo-SecureString "$passphrase" -AsPlaintext -Force
        $connectFarm = Connect-SPConfigurationDatabase -DatabaseName "$configDB" -Passphrase $pp -DatabaseServer "$dbServer" -ErrorAction SilentlyContinue
        if (-not $?) {
            Write-Host -ForegroundColor White " - No existing farm found.`n - Creating config database `"$configDB`"..."
            # Waiting a few seconds seems to help with the Connect-SPConfigurationDatabase barging in on the New-SPConfigurationDatabase command; not sure why...
            Start-Sleep 5
            New-SPConfigurationDatabase -DatabaseName "$configDB" -DatabaseServer "$dbServer" -AdministrationContentDatabaseName "`
                $centralAdminContentDB" -Passphrase $pp -FarmCredentials $farmCredential
            if (-not $?) {
                throw " - Error creating new farm configuration database"}
            else {
                $farmMessage = " - Done creating configuration database for farm."}
        }
        else {
            $farmMessage = " - Done joining farm."
        }
    }
    else {
        $farmMessage = " - $env:COMPUTERNAME is already joined to farm on `"$configDB`"."
    }
    Write-Host -ForegroundColor White $farmMessage
}

function SP-CheckIfUpgradeNeeded {
    # Check if we need to perform an upgrade.
    $setupType = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS\").GetValue("SetupType")
    if ($setupType -ne "CLEAN_INSTALL") { # For example, if the value is "B2B_UPGRADE" 
        return $true
    }
    else {
        return $false
    }
}

function SP-ConfigureFarm {
    # Check if farm has more than one server, other than DB server
    $configDB = $dbPrefix + "_Config_Farm";
    $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB}
    if ($spFarm -ne $null) {
        Write-Host -ForegroundColor White " - Detecting servers in the farm"
        foreach ($srv in $spFarm.Servers) {
            if (($srv -like "*$dbServer*") -and ($dbServer -ne $env:COMPUTERNAME)) {
                [bool]$dbLocal = $false
            }
        }
        # If we have two servers and the other server is a DB server then we're the first
        # SP server
        if (($dbLocal -eq $false) -and ($($spFarm.Servers.Count) -eq 2)) {
            [bool]$firstServer = $true
        # If database is loca and we only have one server, then this has to be the first
        # SP server
        } else { if (($dbLocal -eq $true) -and ($($spFarm.Servers.Count) -eq 1)) {
            [bool]$firstServer = $true
        } else {
            [bool]$firstServer = $false
        }}
        Write-Host -ForegroundColor White " - Configuring the SharePoint farm/server..."
        # Force a full configuration if this is the first web/app server in the farm
        if (($firstServer -eq $true) -or (SP-CheckIfUpgradeNeeded -eq $true)) {[bool]$doFullConfig = $true}
        # Are we doing a full config?
        if ($doFullConfig)
        {
            # Install Help Files
            Write-Host -ForegroundColor White " - Installing Help Collection..."
            Install-SPHelpCollection -All
        }
        # Secure resources
        Write-Host -ForegroundColor White " - Securing Resources..."
        Initialize-SPResourceSecurity;
        # Install Services
        Write-Host -ForegroundColor White " - Installing Services..."
        Install-SPService;
        if ($doFullConfig)
        {
            # Install (all) features
            Write-Host -ForegroundColor White " - Installing Features..."
            $features = Install-SPFeature -AllExistingFeatures -Force;
        }
        # Create application content.
        if ($doFullConfig)
        {
            Write-Host -ForegroundColor White " - Installing Application Content..."
            Install-SPApplicationContent
        }
        # Configure managed accounts
        SP-CreateManagedAccounts;
        # Check again if we need to run PSConfig, in case a CU was installed
        SP-ConfigFarmAfterUpgrade;
    } else {
        throw "Not connected to the farm";
    }
}

function SP-ChangeCacheServiceAccount {
    # Change the Distributed Cache Service to us the service account
    # Not the farm account.
    if ($spVer -eq "15") {
        $configDB = $dbPrefix + "_Config_Farm";
        $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB}
        if ($spFarm -ne $null) {
            Write-Host -ForegroundColor white " - Changing the Distributed Cache Service account";
            $cacheService = $spFarm.Services | where {$_.Name -eq "AppFabricCachingService"}
            $accnt = Get-SPManagedAccount -Identity $spServiceAcctName;
            $cacheService.ProcessIdentity.CurrentIdentityType = "SpecificUser";
            $cacheService.ProcessIdentity.ManagedAccount = $accnt;
            $cacheService.ProcessIdentity.Update();
        }
    }
}

function SP-ConfigFarmAfterUpgrade {
    # Configure thr farm after an upgrade.
    # Use PSConfig to ensure that we're upgraded.
    if (SP-CheckIfUpgradeNeeded -eq $true) {
        $retryNum = 1
        Run-PSConfig
        $PSConfigLastError = Check-PSConfig
        while (!([string]::IsNullOrEmpty($PSConfigLastError)) -and $retryNum -le 4) {
            Write-Warning $PSConfigLastError.Line
            Write-Host -ForegroundColor White " - An error occurred running PSConfig, trying again ($retryNum)..."
            Start-Sleep -Seconds 5
            $retryNum += 1
            Run-PSConfig
            $PSConfigLastError = Check-PSConfig
        }
        if ($retryNum -ge 5) {
            Write-Host -ForegroundColor White " - After $retryNum retries to run PSConfig, trying GUI-based..."
            Start-Process -FilePath $PSConfigUI -NoNewWindow -Wait
        }
        Clear-Variable -Name PSConfigLastError -ErrorAction SilentlyContinue
        Clear-Variable -Name PSConfigLog -ErrorAction SilentlyContinue
        Clear-Variable -Name retryNum -ErrorAction SilentlyContinue
    }
    $spRegVersion = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\").GetValue("Version")
    if (!($spRegVersion)) {
        Write-Host -ForegroundColor White " - Creating Version registry value (workaround for bug in PS-based install)"
        Write-Host -ForegroundColor White -NoNewline " - Getting version number... "
        $spBuild = "$($(Get-SPFarm).BuildVersion.Major).0.0.$($(Get-SPFarm).BuildVersion.Build)"
        Write-Host -ForegroundColor White "$spBuild"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\" `
            -Name Version -Value $spBuild -ErrorAction SilentlyContinue | Out-Null
    }
    # Set an environment variable for the hive (SharePoint root)
    [Environment]::SetEnvironmentVariable($spVer, "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer", "Machine")

    # Let's make sure the SharePoint Timer Service (SPTimerV4) is running
    # Per workaround in http://www.paulgrimley.com/2010/11/side-effects-of-attaching-additional.html
    if ((Get-Service SPTimerV4).Status -eq "Stopped") {
        Write-Host -ForegroundColor White " - Starting $((Get-Service SPTimerV4).DisplayName) Service..."
        Start-Service SPTimerV4
        if (!$?) {Throw " - Could not start Timer service!"}
    }
}

function SP-CreateCentralAdmin {
    # Create CA if it doesn't already exist.
    # Get all Central Admin service instances in the farm
    $centralAdminServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq `
        "Microsoft.SharePoint.Administration.SPWebServiceInstance" -and $_.Name -eq "WSS_Administration"}
    # Get those Central Admin services that are Online
    $centralAdminServicesOnline = $centralAdminServices | ? {$_.Status -eq "Online"}
    # Get the local Central Admin service
    $localCentralAdminService = $centralAdminServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
    if (($localCentralAdminService.Status -ne "Online")) {
        try {
            # Check if there is already a Central Admin provisioned in the farm; if not, create one
            if (!(Get-SPWebApplication -IncludeCentralAdministration | `
                ? {$_.IsAdministrationWebApplication}) -or $centralAdminServicesOnline.Count -lt 1) {
                # Create Central Admin for farm
                Write-Host -ForegroundColor White " - Creating Central Admin site..."
                $newCentralAdmin = New-SPCentralAdministration -Port $CAportNumber -WindowsAuthProvider "NTLM" -ErrorVariable err
                if (-not $?) {Throw " - Error creating central administration application"}
                Write-Host -ForegroundColor yellow " - Waiting for Central Admin site..." -NoNewline
                while ($localCentralAdminService.Status -ne "Online") {
                    Write-Host -ForegroundColor yellow "." -NoNewline
                    Start-Sleep 1
                    $centralAdminServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq `
                        "Microsoft.SharePoint.Administration.SPWebServiceInstance" -and $_.Name -eq "WSS_Administration"}
                    $localCentralAdminService = $centralAdminServices | ? {MatchComputerName $_.Server.Address $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor yellow -ForegroundColor Black $($localCentralAdminService.Status)
            }
            # Otherwise create a Central Admin site locally, with an AAM to the existing Central Admin
            else {
                Write-Host -ForegroundColor White " - Creating local Central Admin site..."
                $newCentralAdmin = New-SPCentralAdministration
            }
        }
        catch {
            If ($err -like "*update conflict*") {
                Write-Warning "A concurrency error occured, trying again."
                SP-CreateCentralAdmin
            }
            else {
                throw $_
            }
        }
    }
}

function Run-PSConfig {
    # Run PS Config to complete an upgrade.
    $PSConfig = "$env:CommonProgramFiles\microsoft shared\Web Server Extensions\$spVer\BIN\PSCONFIG.exe";
    Start-Process -FilePath $PSConfig -ArgumentList `
        "-cmd upgrade -inplace b2b -force -cmd applicationcontent -install -cmd installfeatures" -NoNewWindow -Wait
}

function Check-PSConfig {
    # Check error from last PSConfig run.
    $PSConfigLogLocation = $((Get-SPDiagnosticConfig).LogLocation) -replace "%CommonProgramFiles%","$env:CommonProgramFiles"
    $PSConfigLog = Get-ChildItem -Path $PSConfigLogLocation | ? {$_.Name -like "PSCDiagnostics*"} | `
        Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
    if ($PSConfigLog -eq $null) {
        Throw " - Could not find PSConfig log file!"
    }
    else {
        # Get error(s) from log
        $PSConfigLastError = $PSConfigLog | select-string -SimpleMatch -CaseSensitive -Pattern "ERR" | Select-Object -Last 1
        return $PSConfigLastError
    }
}

function SP-ConfigureDiagnosticLogging {
    # Configure logging.
    Write-Host -ForegroundColor White " - Configuring SharePoint diagnostic (ULS) logging..."
    Write-Host -ForegroundColor White " - Setting SharePoint diagnostic (ULS) logging options:"
    Write-Host -ForegroundColor White "  - DaysToKeepLogs: $logDaysToKeepLogs"
    Write-Host -ForegroundColor White "  - LogDiskSpaceUsageGB: $logSpaceUsage"
    Write-Host -ForegroundColor White "  - LogLocation: $logLocation"
    Write-Host -ForegroundColor White "  - LogCutInterval: $logCutInterval"
    Set-SPDiagnosticConfig -DaysToKeepLogs $logDaysToKeepLogs -LogMaxDiskSpaceUsageEnabled:$true `
        -LogDiskSpaceUsageGB $logSpaceUsage -LogLocation $logLocation -LogCutInterval $logCutInterval
    # Finally, enable NTFS compression on the ULS log location to save disk space
    # Replace \ with \\ for WMI
    $wmiPath = $logLocation.Replace("\","\\")
    $wmiDirectory = Get-WmiObject -Class "Win32_Directory" -Namespace "root\cimv2" -ComputerName $env:COMPUTERNAME -Filter "Name='$wmiPath'"
    # Check if folder is already compressed
    if (!($wmiDirectory.Compressed)) {
        Write-Host -ForegroundColor White " - Compressing $logLocation and subfolders..."
        $compress = $wmiDirectory.CompressEx("","True")
    }
    else {
        Write-Host -ForegroundColor White " - $folder is already compressed."
    }
    ApplyLogFolderPermissions -path $logLocation;
    $where = ([String]"$env:CommonProgramFiles\microsoft shared\Web Server Extensions\$spVer\LOGS").ToLower();
    if (!$logLocation.ToLower().StartsWith($where)) {
        ApplyLogFolderPermissions -path $where;
    }
}

function SP-ConfigureLanguagePacks {
    # Configure language packs.
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    $languagePackInstalled = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS\").GetValue("LanguagePackInstalled")
    # If there were language packs installed we need to run psconfig to configure them
    if (($languagePackInstalled -eq "1") -and ($installedOfficeServerLanguages.Count -gt 1)) {
        Write-Host -ForegroundColor White " - Configuring language packs..."
        # Let's sleep for a while to let the farm config catch up...
        Start-Sleep 20
        $retryNum += 1
        # Run PSConfig.exe per http://sharepoint.stackexchange.com/questions/9927/sp2010-psconfig-fails-trying-to-configure-farm-after-installing-language-packs
        # Note this was changed from v2v to b2b as suggested by CodePlex user jwthompson98
        Run-PSConfig
        $PSConfigLastError = Check-PSConfig
        while (!([string]::IsNullOrEmpty($PSConfigLastError)) -and $retryNum -le 4) {
            Write-Warning $PSConfigLastError.Line
            Write-Host -ForegroundColor White " - An error occurred running PSConfig, trying again ($retryNum)..."
            Start-Sleep -Seconds 5
            $retryNum += 1
            Run-PSConfig
            $PSConfigLastError = Check-PSConfig
        }
        if ($retryNum -ge 5) {
            Write-Host -ForegroundColor White " - After $retryNum retries to run PSConfig, trying GUI-based..."
            Start-Process -FilePath $PSConfigUI -NoNewWindow -Wait
        }
        Clear-Variable -Name PSConfigLastError -ErrorAction SilentlyContinue
        Clear-Variable -Name PSConfigLog -ErrorAction SilentlyContinue
        Clear-Variable -Name retryNum -ErrorAction SilentlyContinue
    }
}

function SP-RegisterManagedAccount($username, $password) {
    $password = ConvertTo-SecureString "$password" -AsPlaintext -Force
    $alreadyAdmin = $false
    # The following was suggested by Matthias Einig (http://www.codeplex.com/site/users/view/matein78)
    # And inspired by http://todd-carter.com/post/2010/05/03/Give-your-Application-Pool-Accounts-A-Profile.aspx & 
    # http://blog.brainlitter.com/archive/2010/06/08/how-to-revolve-event-id-1511-windows-cannot-find-the-local-profile-on-windows-server-2008.aspx
    try {
        $credAccount = New-Object System.Management.Automation.PsCredential $username,$password
        $managedAccountDomain,$managedAccountUser = $username -Split "\\"
        Write-Host -ForegroundColor White "  - Account `"$managedAccountDomain\$managedAccountUser`:"
        Write-Host -ForegroundColor White "   - Creating local profile for $username..."
        # Add managed account to local admins (very) temporarily so it can log in and create its profile
        if (!($localAdmins -contains $managedAccountUser)) {
            $builtinAdminGroup = Get-AdministratorsGroup
            ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$managedAccountDomain/$managedAccountUser")
        }
        else {
            $alreadyAdmin = $true
        }
        # Spawn a command window using the managed account's credentials, create the profile, and exit immediately
        Start-Process -WorkingDirectory "$env:SYSTEMROOT\System32\" -FilePath `
            "cmd.exe" -ArgumentList "/C" -LoadUserProfile -NoNewWindow -Credential $credAccount
        # Remove managed account from local admins unless it was already there
        $builtinAdminGroup = Get-AdministratorsGroup;
        if (-not $alreadyAdmin) {
            ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Remove("WinNT://$managedAccountDomain/$managedAccountUser")
            if (!$?) {
                Write-Host -ForegroundColor Yellow "   - Could not remove `"$managedAccountDomain\$managedAccountUser`" from local Admins."
                Write-Host -ForegroundColor Yellow "   - Please remove it manually."
            }
        }
    }
    catch {
        $_
        Write-Host -ForegroundColor White "."
        Write-Warning "Could not create local user profile for $username"
        break
    }
    $managedAccount = Get-SPManagedAccount | Where-Object {$_.UserName -eq $username}
    if ($managedAccount -eq $null) {
        Write-Host -ForegroundColor White "   - Registering managed account $username..."
        if ($username -eq $null -or $password -eq $null) {
            Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue "   - Prompting for Account: "
            $credAccount = $host.ui.PromptForCredential("Managed Account", "Enter Account Credentials:", "", "NetBiosUserName" )
        }
        else {
            $credAccount = New-Object System.Management.Automation.PsCredential $username,$password
        }
        New-SPManagedAccount -Credential $credAccount | Out-Null
        if (-not $?) { Throw "   - Failed to create managed account" }
    }
    else {
        Write-Host -ForegroundColor White "   - Managed account $username already exists."
    }
}

function SP-CreateManagedAccounts {
    # Create managed accounts.
    Write-Host -ForegroundColor White " - Adding Managed Accounts..."
    # Get the members of the local Administrators group
    $builtinAdminGroup = Get-AdministratorsGroup
    $adminGroup = ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group")
    # This syntax comes from Ying Li (http://myitforum.com/cs2/blogs/yli628/archive/2007/08/30/powershell-script-to-add-remove-a-domain-user-to-the-local-administrators-group-on-a-remote-machine.aspx)
    $localAdmins = $adminGroup.psbase.invoke("Members") | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
    # Ensure Secondary Logon service is enabled and started
    if (!((Get-Service -Name seclogon).Status -eq "Running")) {
        Write-Host -ForegroundColor White " - Enabling Secondary Logon service..."
        Set-Service -Name seclogon -StartupType Manual
        Write-Host -ForegroundColor White " - Starting Secondary Logon service..."
        Start-Service -Name seclogon
    }
    SP-RegisterManagedAccount -username $spAppPoolAcctName -password $spAppPoolAcctPwd
    SP-RegisterManagedAccount -username $spServiceAcctName -password $spServiceAcctPwd
    SP-RegisterManagedAccount -username $spc2WTSAcctName -password $spc2WTSAcctPwd
}

function SP-CreateWebApp($appPool, $webAppName, $database, $url, $port, $hostheader = $null) {
    # Check for an existing App Pool
    $existingWebApp = Get-SPWebApplication | Where-Object { ($_.ApplicationPool).Name -eq $appPool }
    $appPoolExists = ($existingWebApp -ne $null);
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    # Strip out any protocol value
    [bool]$useSSL = $false;
    if ($url -like "https://*") {$useSSL = $true}
    # Get the auth provider.
    $authProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication;
    $authProviderSwitch = @{AuthenticationProvider = $authProvider}
    # If we are running Win2008 (non-R2), we may need the claims hotfix
    if ((Gwmi Win32_OperatingSystem).Version -like "6.0*") { 
        [bool]$claimsHotfixRequired = $true
        Write-Host -ForegroundColor Yellow " - Web Applications using Claims authentication require an update"
        Write-Host -ForegroundColor Yellow " - Apply the http://go.microsoft.com/fwlink/?LinkID=184705 update after setup."
    }
    if ($appPoolExists) {
        $appPoolAccountSwitch = @{}
    }
    else {
        $appPoolAccountSwitch = @{ApplicationPoolAccount = $($spAppPoolAcctName)}
    }
    # See if the we have the app already
    $getSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $webAppName}
    if ($getSPWebApplication -eq $null) {
        Write-Host -ForegroundColor White " - Creating Web App `"$webAppName`""
        $hostHeaderSwitch = @{}
        $pathSwitch = @{}
        if ($hostheader -ne $null) { $hostHeaderSwitch = @{HostHeader = $hostHeader}; }
        New-SPWebApplication -Name $webAppName -ApplicationPool $appPool -DatabaseServer $dbServer -DatabaseName $database `
            -Url $url -Port $port -SecureSocketsLayer:$useSSL @hostHeaderSwitch @appPoolAccountSwitch @authProviderSwitch @pathSwitch | Out-Null
        if (-not $?) { Throw " - Failed to create web application" }
    }
    else {
        Write-Host -ForegroundColor White " - Web app `"$webAppName`" already provisioned."
    }
}

function SP-CreateSiteCollection($appPool, $database, $siteCollectionName, $siteURL, $template = $null) {
    # Get the web app
    $webApp = Get-SPWebApplication | Where-Object { ($_.ApplicationPool).Name -eq $appPool }
    if ($webApp -eq $null) { throw " - Failed to get web application"; }
    # See if we have the site collection already.
    Write-Host -ForegroundColor White " - Checking for Site Collection `"$siteURL`"..."
    $getSPSiteCollection = Get-SPSite -Limit ALL | Where-Object {$_.Url -eq $siteURL}
    if (($getSPSiteCollection -eq $null)) {
        # Verify that the Language we're trying to create the site in is currently installed on the server
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo(1033);
        $cultureDisplayName = $culture.DisplayName;
        $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
        if (!($installedOfficeServerLanguages | Where-Object {$_ -eq $culture.Name})) {
            Write-Warning "You must install the `"$culture ($cultureDisplayName)`" Language Pack before you can create a site using LCID $LCID"
        }
        else {
            $siteDatabaseExists = Get-SPContentDatabase -Identity $database -ErrorAction SilentlyContinue
            if (!$siteDatabaseExists) {
                Write-Host -ForegroundColor White " - Creating new content database `"$database`"..."
                New-SPContentDatabase -Name $database -WebApplication $webApp | Out-Null
            }
            Write-Host -ForegroundColor White " - Creating Site Collection `"$siteURL`"..."
            if ($template -eq $null) {
                $templateSwitch = @{}
            } else {
                $templateSwitch = @{Template = $template}
            }
            $hostHeaderWebAppSwitch = @{}
            $site = New-SPSite -Url $siteURL -OwnerAlias $spAdminAcctName -SecondaryOwner $env:USERDOMAIN\$env:USERNAME -ContentDatabase $database `
                -Name $siteCollectionName -Language 1033 @templateSwitch @hostHeaderWebAppSwitch -ErrorAction Stop

            # Add the Portal Site Connection to the web app, unless of course the current web app *is* the portal
            # Inspired by http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=264
            if ($site.URL -ne $siteURL) {
                Write-Host -ForegroundColor White " - Setting the Portal Site Connection for `"$siteCollectionName`"..."
                $site.PortalName = $siteCollectionName;
                $site.PortalUrl = $siteURL;
            }
            $site.RootWeb.Update()
        }
    }
    else {
        Write-Host -ForegroundColor White " - Skipping creation of site `"$siteCollectionName`" - already provisioned."
    }
}

function SP-CreateMySiteHost {
    # Create the MySite Host.
    SP-CreateWebApp -appPool "MySite Host App Pool" -webAppName "MySite Host" `
        -database ($dbPrefix + "_Content_MySiteHost") -url "http://$env:COMPUTERNAME" -port 8080
    SP-CreateSiteCollection -appPool "MySite Host App Pool" -database ($dbPrefix + "_Content_MySiteHost") `
        -siteCollectionName "MySite Host" -siteURL ("http://" + $env:COMPUTERNAME + ":8080") -template "SPSMSITEHOST#0"
}

function SP-CreateDefaultWebApps {
    # Create the main portal and my site host apps.
    SP-CreateWebApp -appPool "Portal App Pool" -webAppName "Portal" `
        -database ($dbPrefix + "_Content_Portal") -url "http://$env:COMPUTERNAME" -port 80
    SP-CreateSiteCollection -appPool "Portal App Pool" -database ($dbPrefix + "_Content_Portal") `
        -siteCollectionName "Portal" -siteURL "http://$env:COMPUTERNAME" -template "STS#0"
    SP-CreateMySiteHost;
}

function SP-ConfigureEmail {
    try {
        Write-Host -ForegroundColor White ” – Configuring Outgoing Email…”
        $loadasm = [System.Reflection.Assembly]::LoadWithPartialName(“Microsoft.SharePoint”)
        $SPGlobalAdmin = New-Object Microsoft.SharePoint.Administration.SPGlobalAdmin
        Write-Host $smtpServer $fromEmailAddress;
        $SPGlobalAdmin.UpdateMailSettings($smtpServer, $fromEmailAddress, $fromEmailAddress, 65001);
    }
    catch {
        $_
        Write-Warning "Failed to configure email.";
    }
}

function SP-PostInstallation {
    # Do some post installation tasks.
    Write-Host -ForegroundColor white " - Performing post config tasks.";
    SP-AddHostsFileEntries;
}

function SP-AddHostsFileEntries {
    $file = "C:\Windows\System32\drivers\etc\hosts";
    #add-host -filename $file -ip "127.0.0.1" -hostname $lbPortalName;
    #add-host -filename $file -ip "127.0.0.1" -hostname $lbMySiteHostName;
}

function add-host([string]$filename, [string]$ip, [string]$hostname) {
    Write-Host -ForegroundColor white " - Adding host entry $hostname / $ip";
	remove-host $filename $hostname
	$ip + "`t`t" + $hostname | Out-File -encoding ASCII -append $filename
}

function remove-host([string]$filename, [string]$hostname) {
	$c = Get-Content $filename
	$newLines = @()
	
	foreach ($line in $c) {
		$bits = [regex]::Split($line, "\t+")
		if ($bits.count -eq 2) {
			if ($bits[1] -ne $hostname) {
				$newLines += $line
			}
		} else {
			$newLines += $line
		}
	}
	
	# Write file
	Clear-Content $filename
	foreach ($line in $newLines) {
		$line | Out-File -encoding ASCII -append $filename
	}
}
