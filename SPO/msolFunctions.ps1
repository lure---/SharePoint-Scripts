<<<<<<< HEAD
﻿###########################################
# MSOL functions

function MSOLGetCredential {
    param (
        [Parameter(Mandatory=$true)][string]$user,
        [Parameter(Mandatory=$true)][string]$password
    )
    try { 
        Write-Verbose "Creating credential for MSOL";
        $pwd = ConvertTo-SecureString $password -AsPlainText -Force
        $result = New-Object System.Management.Automation.PSCredential($user, $pwd);
        Write-Verbose "Established credential for MSOL";
        return $result;
    } catch {
        Write-Host -ForegroundColor Red "Failed to establish credential for MSOL - $($_.Exception)";
        return $null;
    }
}

function MSOLGetAllUsers {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$cred
    );
    Connect-MsolService -Credential $cred;
    Get-MsolUser -All;
}

function MSOLUserExists {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$cred,
        [Parameter(Mandatory=$true)][string]$username
    );
    Connect-MsolService -Credential $cred;
    $user = Get-MsolUser -UserPrincipalName $username -ErrorAction SilentlyContinue;
    return [bool]($user -ne $null);
}
=======
﻿###########################################
# MSOL functions

function MSOLGetCredential {
    param (
        [Parameter(Mandatory=$true)][string]$user,
        [Parameter(Mandatory=$true)][string]$password
    )
    try { 
        Write-Verbose "Creating credential for MSOL";
        $pwd = ConvertTo-SecureString $password -AsPlainText -Force
        $result = New-Object System.Management.Automation.PSCredential($user, $pwd);
        Write-Verbose "Established credential for MSOL";
        return $result;
    } catch {
        Write-Host -ForegroundColor Red "Failed to establish credential for MSOL - $($_.Exception)";
        return $null;
    }
}

function MSOLGetAllUsers {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$cred
    );
    Connect-MsolService -Credential $cred;
    Get-MsolUser -All;
}

function MSOLUserExists {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$cred,
        [Parameter(Mandatory=$true)][string]$username
    );
    Connect-MsolService -Credential $cred;
    $user = Get-MsolUser -UserPrincipalName $username -ErrorAction SilentlyContinue;
    return [bool]($user -ne $null);
}
>>>>>>> 4d078243feea082eb95207ae0b32b4ffacaceab7
