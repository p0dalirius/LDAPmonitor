# File name          : psLDAPmonitor.ps1
# Author             : Podalirius (@podalirius_)
# Date created       : 3 Jan 2022

Param (
    [parameter(Mandatory=$true)][string]$dcip = $null,
    [parameter(Mandatory=$false)][string]$Username = $null,
    [parameter(Mandatory=$false)][string]$Password = $null,
    [parameter(Mandatory=$false)][string]$LogFile = $null,
    [parameter(Mandatory=$false)][int]$PageSize = 5000,
    [parameter(Mandatory=$false)][string]$SearchBase = $null,
    [parameter(Mandatory=$false)][int]$Delay = 1,
    [parameter(Mandatory=$false)][switch]$LDAPS,
    [parameter(Mandatory=$false)][switch]$Randomize,
    [parameter(Mandatory=$false)][switch]$IgnoreUserLogons,
    [parameter(Mandatory=$false)][switch]$Help
)

If ($Help) {
    Write-Host "[+]======================================================"
    Write-Host "[+] Powershell LDAP live monitor v1.3      @podalirius_  "
    Write-Host "[+]======================================================"
    Write-Host ""

    Write-Host "Required arguments:"
    Write-Host "  -dcip       : LDAP host to target, most likely the domain controller."
    Write-Host ""
    Write-Host "Optional arguments:"
    Write-Host "  -Help       : Displays this help message"
    Write-Host "  -Username   : User to authenticate as."
    Write-Host "  -Password   : Password for authentication."
    Write-Host "  -PageSize   : Sets the LDAP page size to use in queries (default: 5000)."
    Write-Host "  -SearchBase : Sets the LDAP search base."
    Write-Host "  -LDAPS      : Use LDAPS instead of LDAP."
    Write-Host "  -LogFile    : Log file to save output to."
    Write-Host "  -Delay      : Delay between two queries in seconds (default: 1)."
    Write-Host "  -Randomize  : Randomize delay between two queries, between 1 and 5 seconds."
    Write-Host "  -IgnoreUserLogons  : Ignores user logon events."

    exit 0
}

If ($LogFile.Length -ne 0) {
    # Init log file
    $Stream = [System.IO.StreamWriter]::new($LogFile)
    $Stream.Close()
}

if ($Delay) {
    $DelayInSeconds = $Delay;
} else {
    $DelayInSeconds = 1;
}

#===============================================================================

Function Write-Logger {
    [CmdletBinding()]
    [OutputType([Nullable])]
    Param
    (
        [Parameter(Mandatory=$true)] $Logfile,
        [Parameter(Mandatory=$true)] $Message
    )
    Begin
    {
        Write-Host $Message
        If ($LogFile.Length -ne 0) {
            $Stream = [System.IO.StreamWriter]::new($LogFile, $true)
            $Stream.WriteLine($Message)
            $Stream.Close()
        }
    }
}

Function Init-LdapConnection {
    [CmdletBinding()]
    [OutputType([Nullable])]
    Param
    (
        [Parameter(Mandatory=$true)] $connectionString,
        [Parameter(Mandatory=$false)] $SearchBase,
        [Parameter(Mandatory=$false)] $Username,
        [Parameter(Mandatory=$false)] $Password,
        [Parameter(Mandatory=$false)] $PageSize
    )
    Begin
    {
        $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
        if ($Username) {
            if ($SearchBase.Length -ne 0) {
                # Connect to Domain with credentials
                $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $SearchBase), $Username, $Password)
            } else {
                # Connect to Domain with current session
                $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("$connectionString", $Username, $Password)
            }
        } else {
            if ($SearchBase.Length -ne 0) {
                # Connect to Domain with credentials
                $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $SearchBase))
            } else {
                # Connect to Domain with current session
                $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("$connectionString")
            }
        }
        $ldapSearcher.SearchScope = "Subtree"
        if ($PageSize) {
            $ldapSearcher.PageSize = $PageSize
        } else {
            Write-Verbose ("Setting PageSize to $PageSize");
            $ldapSearcher.PageSize = 5000
        }
        return $ldapSearcher;
    }
}


Function Query-AllNamingContextsOrSearchBase {
    [CmdletBinding()]
    [OutputType([Nullable])]
    Param
    (
        [Parameter(Mandatory=$true)] $namingContexts,
        [Parameter(Mandatory=$true)] $connectionString,
        [Parameter(Mandatory=$false)] $SearchBase,
        [Parameter(Mandatory=$false)] $Username,
        [Parameter(Mandatory=$false)] $Password,
        [Parameter(Mandatory=$false)] $PageSize
    )
    Begin
    {
        if ($SearchBase.Length -ne 0) {
            Write-Verbose "Using SearchBase: $nc"
            $ldapSearcher = Init-LdapConnection -connectionString $connectionString -SearchBase $SearchBase -Username $Username -Password $Password -PageSize $PageSize
            $ldapSearcher.Filter = "(objectClass=*)"
            return $ldapSearcher.FindAll();
        } else {
            $results = [ordered]@{};
            foreach ($nc in $namingContexts) {
                Write-Verbose "Using namingContext as search base: $nc"
                $ldapSearcher = Init-LdapConnection -connectionString $connectionString -SearchBase $nc -Username $Username -Password $Password -PageSize $PageSize
                $ldapSearcher.Filter = "(objectClass=*)"

                Foreach ($item in $ldapSearcher.FindAll()) {
                    if (!($results.Keys -contains $item.Path)) {
                        $results[$item.Path] = $item.Properties;
                    } else {
                        Write-Host "[debug] key already exists: $key (this shouldn't be possible)"
                    }
                }
            }
            return $results;
        }
    }
}


Function ResultsDiff {
    [CmdletBinding()]
    [OutputType([Nullable])]
    Param
    (
        [Parameter(Mandatory=$true)] $ResultsBefore,
        [Parameter(Mandatory=$true)] $ResultsAfter,
        [Parameter(Mandatory=$true)] $connectionString,
        [Parameter(Mandatory=$true)] $Logfile,
        [parameter(Mandatory=$false)][switch]$IgnoreUserLogons
    )
    Begin {
        [System.Collections.ArrayList]$ignored_keys = @();
        If ($IgnoreUserLogons) {
            $ignored_keys.Add("lastlogon") | Out-Null
            $ignored_keys.Add("logoncount") | Out-Null
        }

        $dateprompt = ("[{0}] " -f (Get-Date -Format "yyyy/MM/dd hh:mm:ss"));

        # Get created and deleted entries, and common_keys
        [System.Collections.ArrayList]$commonPaths = @();
        Foreach ($bpath in $ResultsBefore.Keys) {
            if (!($ResultsAfter.Keys -contains $bpath)) {
                Write-Logger -Logfile $Logfile -Message  ("{0}'{1}' was deleted." -f $dateprompt, $bpath.replace($connectionString+"/",""))
            } else {
                $commonPaths.Add($bpath) | Out-Null
            }
        }
        Foreach ($apath in $ResultsAfter.Keys) {
            if (!($ResultsBefore.Keys -contains $apath)) {
                Write-Logger -Logfile $Logfile -Message  ("{0}'{1}' was created." -f $dateprompt, $apath.replace($connectionString+"/",""))
            }
        }

        # Iterate over all the common keys
        [System.Collections.ArrayList]$attrs_diff = @();
        Foreach ($path in $commonPaths) {
            $attrs_diff.Clear();

            # Convert into dictionnaries
            $dict_direntry_before = [ordered]@{};
            $dict_direntry_after = [ordered]@{};

            Foreach ($propkey in $ResultsBefore[$path].Keys) {
                if (!($ignored_keys -Contains $propkey.ToLower())) {
                    $dict_direntry_before.Add($propkey, $ResultsBefore[$path][$propkey][0]);
                }
            };
            Foreach ($propkey in $ResultsAfter[$path].Keys) {
                if (!($ignored_keys -Contains $propkey.ToLower())) {
                    $dict_direntry_after.Add($propkey, $ResultsAfter[$path][$propkey][0]);
                }
            };

            # Store different values
            Foreach ($pname in $dict_direntry_after.Keys) {
                if (($dict_direntry_after.Keys -Contains $pname) -And ($dict_direntry_before.Keys  -Contains $pname)) {
                    if (!($dict_direntry_after[$pname].ToString() -eq $dict_direntry_before[$pname].ToString())) {
                        $attrs_diff.Add(@($path, $pname, $dict_direntry_after[$pname], $dict_direntry_before[$pname])) | Out-Null;
                    }
                } elseif (($dict_direntry_after.Keys -Contains $pname) -And !($dict_direntry_before.Keys  -Contains $pname)) {
                    $attrs_diff.Add(@($path, $pname, $dict_direntry_after[$pname], $null)) | Out-Null;
                } elseif (!($dict_direntry_after.Keys -Contains $pname) -And ($dict_direntry_before.Keys  -Contains $pname)) {
                    $attrs_diff.Add(@($path, $pname, $null, $dict_direntry_before[$pname])) | Out-Null;
                }
            }

            # Show results
            if ($attrs_diff.Length -ge 0) {
                Write-Logger -Logfile $Logfile -Message  ("{0}{1}" -f $dateprompt, $path.replace($connectionString+"/",""))

                Foreach ($t in $attrs_diff) {
                    if (($t[3] -ne $null) -And ($t[2] -ne $null)) {
                        Write-Logger -Logfile $Logfile -Message  (" | Attribute {0} changed from '{1}' to '{2}'" -f $t[1], $t[3], $t[2]);
                    } elseif (($t[3] -eq $null) -And ($t[2] -ne $null)) {
                        Write-Logger -Logfile $Logfile -Message  (" | Attribute {0} = '{1}' was created." -f $t[1], $t[2]);
                    } elseif (($t[3] -ne $null) -And ($t[2] -eq $null)) {
                        Write-Logger -Logfile $Logfile -Message  (" | Attribute {0} = '{1}' was deleted." -f $t[1], $t[3]);
                    }
                }
            }
        }
    }
}

#===============================================================================

Write-Logger -Logfile $Logfile -Message  "[+]======================================================"
Write-Logger -Logfile $Logfile -Message  "[+] Powershell LDAP live monitor v1.3      @podalirius_  "
Write-Logger -Logfile $Logfile -Message  "[+]======================================================"
Write-Logger -Logfile $Logfile -Message  ""

# Handle LDAPS connection
$connectionString = "LDAP://{0}:{1}";
If ($LDAPS) {
    $connectionString = ($connectionString -f $dcip, "636");
} else {
    $connectionString = ($connectionString -f $dcip, "389");
}
Write-Verbose "Using connectionString: $connectionString"

# Connect to LDAP
try {
    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("{0}/RootDSE" -f $connectionString);
    $namingContexts = $rootDSE.Properties["namingContexts"];

    Write-Verbose ("Authentication successful!");

    # First query
    $results_before = Query-AllNamingContextsOrSearchBase -connectionString $connectionString -SearchBase $SearchBase -namingContexts $namingContexts -Username $Username -Password $Password -PageSize $PageSize

    Write-Logger -Logfile $Logfile -Message "[>] Listening for LDAP changes ...";
    Write-Logger -Logfile $Logfile -Message "";

    While ($true) {
        # Update query
        $results_after = Query-AllNamingContextsOrSearchBase -connectionString $connectionString -SearchBase $SearchBase -namingContexts $namingContexts -Username $Username -Password $Password -PageSize $PageSize

        # Diff
        if ($IgnoreUserLogons) {
            ResultsDiff -ResultsBefore $results_before -ResultsAfter $results_after -connectionString $connectionString -Logfile $Logfile -IgnoreUserLogons
        } else {
            ResultsDiff -ResultsBefore $results_before -ResultsAfter $results_after -connectionString $connectionString -Logfile $Logfile
        }

        $results_before = $results_after;
        if ($Randomize) {
            $DelayInSeconds = Get-Random -Minimum 1 -Maximum 5
        }
        Write-Verbose ("Waiting {0} second." -f $DelayInSeconds);
        Start-Sleep -Seconds $DelayInSeconds
    }
} catch {
    Write-Verbose $_.Exception
    Write-Logger -Logfile $Logfile -Message  ("[!] (0x{0:X8}) {1}" -f $_.Exception.HResult, $_.Exception.InnerException.Message)
    exit -1
}
