###################################
# Catapult Technology and SIGUSA 
# Fix migrated users.

[CmdletBinding()]
Param();

$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)

. "$env:dp0\..\spoFunctions.ps1"
. "$env:dp0\..\msolFunctions.ps1"

# Global Variables
[string]$global:catapultAdmin = "sharepoint1@catapulttechnology.onmicrosoft.com";
[string]$global:sigusaAdmin = "sharepoint1@sigusa.onmicrosoft.com";
[string]$global:password = "GlobalAdmin1";
[string]$global:catapultAdminUrl = "https://catapulttechnology-admin.sharepoint.com";
[string]$global:sigusaAdminUrl = "https://sigusa-admin.sharepoint.com";

function Report-MissingUsers {
    Write-Verbose "Determining missing users";
    $catapultUsers = MSOLGetAllUsers -cred $global:catapultMSOLCred;
    $sigusaUsers = MSOLGetAllUsers -cred $global:sigusaMSOLCred;
    $catapultUsers | % {
        $srcLogin = $_.UserPrincipalName;
        $destLogin = $_.UserPrincipalName -ireplace "catapulttechnology.onmicrosoft.com", "sc3.com";
        $displayName = $_.DisplayName;
        $match = $sigusaUsers | ? { $_.DisplayName -ieq $displayName };
        if (!$match) {
            New-Object -TypeName PSObject -Property @{ DisplayName=$displayName; SrcLogin=$srcLogin; DestLogin=$destLogin };
        }
    } | Export-CSV -Path "$env:dp0\MissingUsers.csv";
}

try {
    SPOLoadAssemblies;
    $global:catapultMSOLCred = MSOLGetCredential -user $global:catapultAdmin -password $global:password;
    $global:sigUSAMSOLCred = MSOLGetCredential -user $global:sigusaAdmin -password $global:password;
    $global:catapultSPOCred = SPOGetCredential -user $global:catapultAdmin -password $global:password;
    $global:sigUSASPOCred = SPOGetCredential -user $global:sigUSAAdmin -password $global:password;
    #Report-MissingUsers;
    SPOIterateSiteCollection -cred $global:catapultSPOCred -siteUrl "https://catapulttechnology.sharepoint.com" `
        -eachSite {
            param(
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Site]$site);
            Write-Verbose "Loaded site collection $($site.Url)";
        } -eachWeb {
            param(
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Web]$web);
            Write-Verbose "Loaded Web $($web.Url)";
        } -eachList {
            param(
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.List]$list);
            $listUrl = SPOGetListAbsUrl -context $context -list $list;
            Write-Verbose "Loaded List $listUrl";  
        } <#-eachListItem {
            param(
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
                [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ListItem]$listItem);
            Write-Verbose "Loaded ListItem $($listItem.Id)";
        }#>
}
catch {
    Write-Host -ForegroundColor Red "Critial Error: " $_.Exception.Message;
}

#Read-Host "Done, press enter";
