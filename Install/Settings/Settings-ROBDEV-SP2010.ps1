#############################################################
# SharePoint Settings
# Rob Garrett

# Servers
$caServer = "ROBDEMO-SP2010";
$wfeServers = ("ROBDEMO-SP2010");
$appServers = ("ROBDEMO-SP2010");
$searchServers = ("ROBDEMO-SP2010");

# SP
$spVer = "14";
$CAportNumber = "2010";
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
$dbPhysicalServer = "SPSQL";
$sqlServerPool = ("ROBDEV-SP2010");

# DNS
$lbPortalName = "ROBDEV-SP2010";
$lbMySiteHostName = "ROBDEV-SP2010";

# Logging
$logLocation =  "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\LOGS";
$logSpaceUsage = 10; # in GB
$logDaysToKeepLogs = 14;
$logCutInterval = 30; # Minutes before new file created.

# Email
$smtpServer = "ROBDEV-SP2010";
$fromEmailAddress = "rgarrett@robdev.local";


