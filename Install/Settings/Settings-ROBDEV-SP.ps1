#############################################################
# SharePoint Settings
# Rob Garrett

# Servers
$caServer = "ROBDEV-SP";
$wfeServers = ("ROBDEV-SP");
$appServers = ("ROBDEV-SP");
$crawlServers = ("ROBDEV-SP");
$queryServers = ("ROBDEV-SP");

# SP
$spVer = "15";
$CAportNumber = "2013";
$passphrase = "Sharepoint03";

# Accounts
$domain = $env:USERDOMAIN;
$spFarmAcctName = "$domain\sp_farm";
$spAdminAcctName = "$domain\sp_admin";
$spServiceAcctName = "$domain\sp_service";
$spc2WTSAcctName = "$domain\sp_c2wts";
$spSearchCrawlAcctName = "$domain\sp_search";
$spAppPoolAcctName = "$domain\sp_app_pool";
$spSuperUserAcctName = "$domain\sp_CacheSuperUser";
$spSuperReaderAcctName = "$domain\sp_CacheSuperReader";
$spUPSAcctName = "$domain\sp_farm";

# Passwords
$spFarmAcctPwd = "Sharepoint03";
$spAdminAcctPwd = $spFarmAcctPwd;
$spServiceAcctPwd = $spFarmAcctPwd;
$spc2WTSAcctPwd = $spFarmAcctPwd;
$spSearchCrawlAcctPwd = $spFarmAcctPwd;
$spAppPoolAcctPwd = $spFarmAcctPwd;
$spSuperUserAcctPwd = $spFarmAcctPwd;
$spSuperReaderAcctPwd = $spFarmAcctPwd;
$spUPSAcctPwd = $spFarmAcctPwd;

# SQL
$dbPrefix = "ROBDEV";
$dbServer = "SPSQL"; # Alias used for all SQL connections.
$dbPhysicalServer = "ROBDEV-SQL-HA";
$sqlServerPool = ("ROBDEV-SQL-HA", "ROBDEV-SQL", "ROBDEV-SQL2");

# DNS
$lbPortalName = "ROBDEV-SP";
$lbMySiteHostName = "ROBDEV-SP";

# Logging
$logLocation =  "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\LOGS";
$logSpaceUsage = 10; # in GB
$logDaysToKeepLogs = 14;
$logCutInterval = 30; # Minutes before new file created.

# Email
$smtpServer = "ROBDEV-SP";
$fromEmailAddress = "rgarrett@robdev.local";

# Search
$indexLocation = "C:\SPSearchIndexes";


# Other
$forceRemote = [bool]0;
$adminEmail = "rob@robdev.local";
$appDomain = "apps.robdev.local";

#PWA
$pwaWebAppUrl = "http://projects.robdev.local";
$pwaWebAppHostHeader = "projects.robdev.local";

#S2S
$appsPFX = "c:\Certs\apps.cer";
$s2sSiteUrlHttp = "http://$($lbPortalName).robdev.local";
$s2sSiteUrlHttps = "https://$($lbPortalName).robdev.local";