#############################################################
# SharePoint SQL Functions
# Rob Garrett
# With the help from http://autospinstaller.codeplex.com/

function SQL-CreateAlias {
    # Ensure that we create an alias for the primary SQL server.
    # Primary server can be a high-availability group.
    # Important we use the alias in subsequent cmdlets to ensure SharePoint
    # uses the alias.
    if ($localExec -eq $false) {
        Write-Host -ForegroundColor yellow `
        "Interactive commands do not work in remote sessions, make sure you set up the SQL alias on computer $env:COMPUTERNAME"
        $ans = Read-Host "SQL Alias: Did you create the $dbServer alias on $env:COMPUTERNAME ?";
        if ($ans -ne "y" -and $ans -ne "Y") { throw "SQL alias not configured" }
    } else {
        cliconfg.exe
        $ans = Read-Host "SQL Alias: Did you click the alias tab?"
        if ($ans -ne "y" -and $ans -ne "Y") { throw "SQL alias not configured" }
        New-ItemProperty HKLM:SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo -name $dbServer `
            -propertytype String -value "DBMSSOCN,$dbPhysicalServer" -ErrorAction SilentlyContinue;
    }
}

function SQL-ExecuteQuery($server, $database, $query, [scriptblock]$func) {
    if ($Global:EmulateSQL) {
        Write-Host -ForegroundColor Cyan $query;
        return;
    }
    # Connect to server and issue a query
    [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null;
    $conn = New-Object System.Data.SqlClient.SqlConnection;
    $conn.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=SSPI;Connection Timeout=3600";
    try {
        $conn.Open();
        $cmd = SQL-NewCommand -conn $conn -query $query;
        $reader = $cmd.ExecuteReader();
        while ($reader.Read()) {
            $fields = $reader.GetSchemaTable() | Select ColumnName;
            $result = New-Object PSObject;
            foreach ($field in $fields) {
                $result | add-member -type NoteProperty -Name $field.ColumnName -Value $reader[$field.ColumnName];
            }
            $func.Invoke($result);
        }
    }
    catch {
        Write-Host -ForegroundColor red "Failed to execute query $query with exception $($_.Exception.Message)";
    }
    finally {
        $conn.Close();
    }
}

function SQL-ExecuteScalar($server, $database, $query) {
    if ($Global:EmulateSQL) {
        Write-Host -ForegroundColor Cyan $query;
        return;
    }
    # Connect to server and issue a query
    [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null;
    $conn = New-Object System.Data.SqlClient.SqlConnection;
    $conn.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=SSPI;Connection Timeout=3600";
    try {
        $conn.Open();
        $cmd = SQL-NewCommand -conn $conn -query $query;
        return $cmd.ExecuteScalar();
    }
    catch {
        Write-Host -ForegroundColor red "Failed to execute query $query with exception $($_.Exception.Message)";
    }
    finally {
        $conn.Close();
    }
}

function SQL-ExecuteNonQuery($server, $database, $query) {
    if ($Global:EmulateSQL) {
        Write-Host -ForegroundColor Cyan $query;
        return;
    }
    # Connect to server and issue a query
    [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null;
    $conn = New-Object System.Data.SqlClient.SqlConnection;
    $conn.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=SSPI;Connection Timeout=3600";
    try {
        $conn.Open();
        $cmd = SQL-NewCommand -conn $conn -query $query;
        $cmd.ExecuteNonQuery() | Out-Null;
    }
    catch {
        Write-Host -ForegroundColor red "Failed to execute query $query with exception $($_.Exception.Message)";
    }
    finally {
        $conn.Close();
    }
}

function SQL-NewCommand($conn, $query) {
    $cmd = New-Object System.Data.SqlClient.SqlCommand;
    $cmd.connection = $conn;
    $cmd.commandtext = $query;
    $cmd.commandtimeout = 0;
    return $cmd;
}

function SQL-Execute($server, $database, [scriptblock]$func) {
    if ($Global:EmulateSQL) {
        Write-Host -ForegroundColor Cyan $query;
        return;
    }
    # Execute SQL by passing back connection to a delegate.
    [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null;
    $conn = New-Object System.Data.SqlClient.SqlConnection;
    $conn.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=SSPI;Connection Timeout=3600";
    try {
        $conn.Open();
        $func.Invoke($conn);
    }
    catch {
        Write-Host -ForegroundColor red "Failed to execute query with exception $($_.Exception.Message)";
    }
    finally {
        $conn.Close();
    }
}


