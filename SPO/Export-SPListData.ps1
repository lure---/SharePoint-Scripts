##################################################
#
# Script to download list data with attachments.
# Works with document libraries too.
#
# Rob Garrett (robert.garrett@microsoft.com)
# June 21, 2016.
#
# Requirements:
#    SharePoint Online Client Components SDK (64-bit) (https://www.microsoft.com/en-us/download/details.aspx?id=42038) 
    

[CmdletBinding()]Param(
    [Parameter(Mandatory=$false)][string]$siteUrl,
    [Parameter(Mandatory=$false)][PSCredential]$credentials,
    [Parameter(Mandatory=$false)][string]$action,
    [Parameter(Mandatory=$false)][string]$listName,
    [Parameter(Mandatory=$false)][string]$path
);

$global:systemFieldNames = @(
"ContentTypeId",
    "_ModerationComments", "File_x0020_Type", "ContentType", "Modified", "Created", "Author", "Editor", "_HasCopyDestinations",
    "_CopySource", "owshiddenversion", "WorkflowVersion", "_UIVersion", "_UIVersionString", "Attachments", "_ModerationStatus",
    "Edit", "LinkTitleNoMenu", "LinkTitle", "LinkTitle2", "SelectTitle", "InstanceID", "Order", "GUID", "WorkflowInstanceID",
    "FileRef", "FileDirRef", "Last_x0020_Modified", "Created_x0020_Date", "FSObjType", "SortBehavior", "PermMask", "FileLeafRef",
    "UniqueId", "SyncClientId", "ProgId", "ScopeId", "HTML_x0020_File_x0020_Type", "_EditMenuTableStart", "_EditMenuTableStart2",
    "_EditMenuTableEnd", "LinkFilenameNoMenu", "LinkFilename", "LinkFilename2", "DocIcon", "ServerUrl", "EncodedAbsUrl", "BaseName",
    "MetaInfo", "_Level", "_IsCurrentVersion", "ItemChildCount", "FolderChildCount", "Restricted", "OriginatorId", "NoExecute",
    "AppAuthor", "AppEditor", "SMTotalSize", "SMLastModifiedDate", "SMTotalFileStreamSize", "SMTotalFileCount"
);

$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)

function CheckAction {
    if ([string]::IsNullOrEmpty($action)) { Usage; Exit 0; }
    switch ($action.ToLower()) {
        "enum" { return { Enumerate -clientContext $clientContext; } }
        "export" {
            if ([string]::IsNullOrEmpty($listName)) {
                Write-Host -ForegroundColor Red "List Name parameter missing";
                Usage; Exit 0;
            }
            return { Export -clientContext $clientContext -listName $listName -path $path; }
        }
        default { Usage; Exit 0; }
    }
}

function Usage {
    Write-Host -ForegroundColor Green "Usage: $0 -action <Action> -siteUrl <Site URL> -listName [List Title] -path [Output Path]";
    Write-Host -ForegroundColor Green "Actions include:";
    Write-Host -ForegroundColor Green "`tEnum - Enumerate Lists and Libraries";
    Write-Host -ForegroundColor Green "`tExport - Export a list, requires List Name";
}

function Process-SPWeb {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$clientContext,
        [Parameter(Mandatory=$true)][scriptblock]$s
    );
    $clientContext.Load($clientContext.Site);
    $clientContext.Load($clientContext.Web);
    $clientContext.ExecuteQuery();
    Write-Verbose "Loaded Site Collection $($clientContext.Site.Url)";
    Write-Verbose "Loaded Site $($clientContext.Web.Url)";
    & $s -site $clientContext.Site -web $clientContext.Web;
}

function Enumerate {
    param([Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$clientContext);
    Process-SPWeb -clientContext $clientContext -s {
        param(
            [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Site]$site, 
            [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Web]$web
        );
        Write-Verbose "Iterating Lists and Libraries";
        $lists = $web.Lists;
        $clientContext.Load($lists);
        $clientContext.ExecuteQuery();
        Write-Host -ForegroundColor Black -BackgroundColor Yellow `
            "Note: Item counts reflect draft items and items in the recycle bin, true count determined when processing export";
        $lists | % {
            if ($_.Hidden -eq $false) {
                Write-Host -ForegroundColor Yellow "$($_.Title) ($($_.ItemCount))";
            }
        }
    }
}

function GetFieldTitles {
    param([Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.List]$list);
    $fields = @();
    $list.Fields | % {
        if (!$_.Hidden -and $_.Group -ne "_Hidden" -and $global:systemFieldNames -inotcontains $_.InternalName) {
            $fields += $_;
        }
    };
    return $fields;
}

function Export {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$clientContext,
        [Parameter(Mandatory=$true)][string]$listName,
        [Parameter(Mandatory=$false)][string]$path
    );
    Process-SPWeb -clientContext $clientContext -s {
        param(
            [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Site]$site, 
            [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Web]$web
        );
        Write-Verbose "Looking up list $listName";
        $lists = $web.Lists;
        $clientContext.Load($lists);
        $clientContext.ExecuteQuery();
        [Microsoft.SharePoint.Client.List]$list = $lists | ? { $_.Title -ieq $listName; }
        if ($list -eq $null) { throw "Failed to find list with name $listName"; }
        $clientContext.Load($list);
        $clientContext.Load($list.Fields);
        $clientContext.ExecuteQuery();
        Write-Verbose "List $($list.Title) loaded";
        # Get destination folder.
        Write-Host -ForegroundColor Yellow "Beginning export process";
        if ([string]::IsNullOrEmpty($path)) { $path = $env:dp0 + "\Export"; }
        Write-Verbose "Exporting to $path";
        if (!(Test-Path -LiteralPath $path -PathType Container)) { New-Item -Path $path -ItemType "Directory" | Out-Null; }
        # Are we a document library?
        if ($list.BaseType.ToString() -eq "DocumentLibrary") {
            Write-Verbose "Processing list as document library";
            Process-DocLib -clientContext $clientContext -list $list -path $path;
        } else {
            if (!$list.EnableAttachments) {
                Write-Host -ForegroundColor Yellow "List $($list.Title) does not have attachments enabled, skipping";
            } else {
                Write-Verbose "Processing list list with attachments";
                Process-List -clientContext $clientContext -list $list -path $path;
            }
        }
    }
}

function Process-List {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$clientContext,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.List]$list,
        [Parameter(Mandatory=$true)][string]$path 
    );
    Write-Host -ForegroundColor Yellow "Iterating list $($list.Title) ($($list.ItemCount))";
    Write-Host -ForegroundColor Black -BackgroundColor Yellow `
        "Note: Item count reflects draft items and items in the recycle bin, true count determined when processing export";
    Write-Verbose "Iterating Items";
    $query = New-Object Microsoft.SharePoint.Client.CamlQuery;
    # Query in batches - large list support.
    $query.ViewXml = "<View Scope='RecursiveAll'><RowLimit>1000</RowLimit></View>";
    [Microsoft.SharePoint.Client.ListItemCollectionPosition]$position = $null;
    $counter = 1;
    do {
        [Microsoft.SharePoint.Client.ListItemCollection]$listItems = $null;
        if ($position -ne $null) { $query.ListItemCollectionPosition = $position; }
        $listItems = $list.GetItems($query);
        $clientContext.Load($listItems);
        $clientContext.ExecuteQuery();
        # Export the items.
        $counterEnd = ($counter + $listItems.Count) - 1;
        Write-Host -ForegroundColor Yellow "Exporting list items batch ($counter - $counterEnd)";
        $listItems | % {
            try {
                $item = $_;
                $clientContext.Load($item);
                $clientContext.Load($item.ContentType);
                $clientContext.Load($item.Folder);
                $clientContext.ExecuteQuery();
                if ($item.ContentType.Name -ne "Folder") {
                    Write-Verbose "Getting attachments folder for list item with id $($item.Id)";
                    $rootFolderUrl = $clientContext.Web.ServerRelativeUrl + "/Lists/" + $list.Title;
                    $folderUrl = $item["FileDirRef"].ToString();
                    $subFolderUrl = $folderUrl.Substring($rootFolderUrl.Length).Replace("/", "\");
                    $relUrl = $clientContext.Site.Url + "/Lists/" + $list.Title + "/Attachments/" + $item.Id;
                    $folder = $list.ParentWeb.GetFolderByServerRelativeUrl($relUrl);
                    $clientContext.Load($folder);
                    $clientContext.Load($folder.Folders);
                    $clientContext.Load($folder.Files);
                    $clientContext.ExecuteQuery();
                    Process-Folder -clientContext $clientContext -folder $folder -path ($path + $subFolderUrl);
                } 
            } catch {
                Write-Host -ForegroundColor Red "Unable to get attachments for list item with id $($item.Id) $($_.Exception)";
            }
        }
        # Move onto next batch.
        $counter = $counterEnd + 1;
        $position = $listItems.ListItemCollectionPosition;
    } while ($position -ne $null);
}

function Process-DocLib {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$clientContext,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.List]$list,
        [Parameter(Mandatory=$true)][string]$path 
    );
    $clientContext.Load($list.RootFolder);
    $clientContext.Load($list.RootFolder.Folders);
    $clientContext.Load($list.RootFolder.Files);
    $clientContext.ExecuteQuery();
    Process-Folder -clientContext $clientContext -folder $list.RootFolder -path $path;
}

function Process-Folder {
    param(
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.ClientContext]$clientContext,
        [Parameter(Mandatory=$true)][Microsoft.SharePoint.Client.Folder]$folder,
        [Parameter(Mandatory=$true)][string]$path 
    ); 
    Write-Verbose "Iterating folder $($folder.Name), dumping to $path";
    if (!(Test-Path -LiteralPath $path -PathType Container)) { New-Item -Path $path -ItemType "Directory" | Out-Null; }
    # Iterate the files
    $folder.Files | % {
        try {
            $fullPath = $path + "\"+ $_.Name;
            $fileRef = $_.ServerRelativeUrl;
            [Microsoft.SharePoint.Client.FileInformation]$fileInfo = [Microsoft.SharePoint.Client.File]::OpenBinaryDirect($clientContext, $fileRef);
            $fs = [System.IO.File]::Create($fullPath);
            $fileInfo.Stream.CopyTo($fs);
            $fs.Close();
            Write-Host -ForegroundColor Yellow "Exported $fullPath";
        } catch {
            Write-Host -ForegroundColor Red "Skipped $fullPath due to error $($_.Exception.Message)";
        }
    }
# Sub folders.
    $folder.Folders | % {
        $clientContext.Load($_);
        $clientContext.Load($_.Folders);
        $clientContext.Load($_.Files);
        $clientContext.ExecuteQuery();
        Process-Folder -clientContext $clientContext -folder $_ -path ($path + "\" + $_.Name);
    }
}

try {
    Write-Verbose "Loading client assemblies";
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint.Client") | Out-Null;
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint.Client.Runtime") | Out-Null;
    Write-Verbose "Checking action";
    $actionBlock = CheckAction; 
    Write-Verbose "Connecting to SPO and site collection $siteUrl";
    if ($credentials -eq $null) { $credentials = Get-Credential; }
    $spoCred = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials $credentials.UserName, $credentials.Password;
    $clientContext = New-Object Microsoft.SharePoint.Client.ClientContext $siteUrl
    $clientContext.Credentials = $spoCred;
    Write-Host -ForegroundColor Yellow "Connected to $siteUrl";
    & $actionBlock;

} catch {
    Write-Host -ForegroundColor Red "Critical Failure: " + $_.Exception;
}
