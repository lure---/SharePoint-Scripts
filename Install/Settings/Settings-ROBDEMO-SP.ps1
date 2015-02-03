#############################################################
# SharePoint Settings
# Rob Garrett

# Servers
$caServer = "ROBDEMO-SP";
$wfeServers = ("ROBDEMO-SP");
$appServers = ("ROBDEMO-SP");
$searchServers = ("ROBDEMO-SP");

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
$dbPrefix = "ROBDEMO";
$dbServer = "SPSQL"; # Alias used for all SQL connections.
$dbPhysicalServer = "ROBDEMO-SP";
$sqlServerPool = ("ROBDEMO-SP");

# Logging
$logLocation =  "E:\SPLOGS";
$logSpaceUsage = 10; # in GB
$logDaysToKeepLogs = 14;
$logCutInterval = 30; # Minutes before new file created.

# Email
$smtpServer = "ROBDEMO-SP";
$fromEmailAddress = "rgarrett@ROBDEMO.local";

# Other
$forceRemote = [bool]0;
$adminEmail = "rob@ROBDEMO.local";
$appDomain = "apps.ROBDEMO.local";

#PWA
$pwaWebAppUrl = "http://projects.ROBDEMO.local";
$pwaWebAppHostHeader = "projects.ROBDEMO.local";
