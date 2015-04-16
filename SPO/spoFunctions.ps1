#########################################
# Common SPO Functions

function SPOLoadAssemblies {
    if ((Get-Module Microsoft.Online.SharePoint.PowerShell).Count -eq 0) {
        Import-Module Microsoft.Online.SharePoint.PowerShell -DisableNameChecking
    }
}

function SPOGetCredential {
    param (
        [Parameter(Mandatory=$true)][string]$user,
        [Parameter(Mandatory=$true)][string]$password
    )
    try { 
        Write-Verbose "Creating credential for SPO";
        $pwd = ConvertTo-SecureString $password -AsPlainText -Force
        $result = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($user, $pwd);
        Write-Verbose "Established credential for SPO";
        return $result;
    } catch {
        Write-Host -ForegroundColor Red "Failed to establish credential for SPO - $_.Exception";
        return $null;
    }
}

function SPOGetWeb {
    param(
        [Parameter(Mandatory=$true)][string]$url,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.SharePointOnlineCredentials]$cred,
        [Parameter()][ScriptBlock]$s1,
        [Parameter()][ScriptBlock]$e1
    );
    try {
        Write-Verbose "Getting CSOM object for web $url";
        $context = New-Object Microsoft.SharePoint.Client.ClientContext($url);
        $context.Credentials = $cred;
        if ($context.ServerObjectIsNull.Value) { throw "Failed to connect to $url with CSOM"; }
        $web = $context.Web;
        $context.Load($web);
        $context.Load($web.Webs);
        $context.ExecuteQuery();
        Write-Verbose "Obtained reference to web object fotr $url";
        if ($s1 -ne $null) {
            # Call script block with the web.
            . $s1 $context $web; 
        }
    } catch {
        Write-Verbose "Unable to obtain web reference to $url";
        if ($e1 -ne $null) {
            . $e1 $context $error;
        }
    }
}

function SPOEnsureUser {
    param(
        [Parameter(Mandatory=$true)][string]$webUrl,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.SharePointOnlineCredentials]$cred,
        [Parameter(Mandatory=$true)][string]$email
    );
    $userId = -1;
    try {
        SPOGetWeb -url $webUrl -cred $cred -s1 {
            param($context, $web);
            try {
                Write-Verbose "Looking for user with login name $email";
                $user = $web.EnsureUser("i:0#.f|membership|$email");
                $context.Load($user);
                $context.ExecuteQuery();
                # Set parent variable value.
                Set-Variable -Name userId -Scope 2 -Value $user.Id;
            } catch {
                Write-Verbose "Unable to EnsureUser $email - $_.Exception";
            }
        }
    } catch {
        Write-Host -ForegroundColor Red "Error in SPOEnsureUser $_.Exception";
    }
    return $userId;
}

function SPOIterateSiteCollection {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.SharePointOnlineCredentials]$cred,
        [Parameter(Mandatory=$true)][string]$siteUrl,
        [Parameter()][scriptblock]$eachSite,
        [Parameter()][scriptblock]$eachWeb,
        [Parameter()][scriptblock]$eachList,
        [Parameter()][scriptblock]$eachListItem
    );
    Write-Verbose "Getting client context to SPO";
    $context = New-Object Microsoft.SharePoint.Client.ClientContext($siteUrl);
    $context.Credentials = $cred;
    if ($context -eq $null -or $context.ServerObjectIsNull.Value) { throw "Failed to connect to $url with CSOM"; }
    Write-Verbose "Getting site collection object";
    $context.Load($context.Site);
    $context.ExecuteQuery();
    if ($eachSite -ne $null) { . $eachSite -context $context -site $context.Site };
    SPOIterateWeb -context $context -web $context.Web -eachWeb $eachWeb -eachList $eachList -eachListItem $eachListItem;
}

function SPOIterateWeb {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Web]$web,
        [Parameter()][scriptblock]$eachWeb,
        [Parameter()][scriptblock]$eachList,
        [Parameter()][scriptblock]$eachListItem);
    $context.Load($web);
    $context.Load($web.Webs);
    $context.Load($web.Lists);
    $context.ExecuteQuery();
    if ($eachWeb -ne $null) { . $eachWeb -context $context -web $web };
    $web.Lists | ? { $_.Hidden -eq $false } | % {
        SPOIterateList -context $context -list $_ -eachList $eachList -eachListItem $eachListItem;
    }
    $web.Webs | % {
        SPOIterateWeb -context $context -web $_ -eachWeb $eachWeb -eachList $eachList -eachListItem $eachListItem;
    }
}

function SPOIterateList {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.List]$list,
        [Parameter()][scriptblock]$eachList,
        [Parameter()][scriptblock]$eachListItem);
    $context.Load($list);
    $context.Load($list.RootFolder);
    $context.ExecuteQuery();
    if ($eachList -ne $null) { . $eachList -context $context -list $list; }
    if ($eachListItem -ne $null) {
        $query = New-Object Microsoft.SharePoint.Client.CamlQuery;
        $query.ViewXml = "<View><RowLimit>200</RowLimit></View>";
        do {
            $listItems = $list.getItems($query);
            $context.Load($listItems);
            $context.ExecuteQuery();
            $query.ListItemCollectionPosition = $listItems.ListItemCollectionPosition;
            $listItems | % {
                . $eachListItem -context $context -listItem $_;          
            }
        }
        while($query.ListItemCollectionPosition -ne $null);
    }
}

function SPOGetListAbsUrl {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.List]$list);
    $folderUrl = $list.RootFolder.ServerRelativeUrl;
    return "$($context.Site.Url)$folderUrl";
}

function SPFindList {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$context,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Web]$web,
        [Parameter(Mandatory=$true)][string]$listTitle,
        [Parameter()][scriptblock]$eachList);
    if ($eachList -eq $null) { return; }
    $context.Load($web.Lists);
    $context.ExecuteQuery();
    $list = $web.Lists | ? { $_.Title -ieq $listTitle };
    if ($list -ne $null) { . $eachList -context $context -list $list; }
}
