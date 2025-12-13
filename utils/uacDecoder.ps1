[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int]$UACValue
)

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
$UACs = @{};
$UACs.Add("SCRIPT",1);
$UACs.Add("ACCOUNTDISABLE",2);
$UACs.Add("HOMEDIR_REQUIRED",8);
$UACs.Add("LOCKOUT",16);
$UACs.Add("PASSWD_NOTREQD",32);
$UACs.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128);
$UACs.Add("TEMP_DUPLICATE_ACCOUNT",256);
$UACs.Add("NORMAL_ACCOUNT",512);
$UACs.Add("INTERDOMAIN_TRUST_ACCOUNT",2048);
$UACs.Add("WORKSTATION_TRUST_ACCOUNT",4096);
$UACs.Add("SERVER_TRUST_ACCOUNT",8192);
$UACs.Add("DONT_EXPIRE_PASSWORD",65536);
$UACs.Add("MNS_LOGON_ACCOUNT",131072);
$UACs.Add("SMARTCARD_REQUIRED",262144);
$UACs.Add("TRUSTED_FOR_DELEGATION",524288);
$UACs.Add("NOT_DELEGATED",1048576);
$UACs.Add("USE_DES_KEY_ONLY",2097152);
$UACs.Add("DONT_REQ_PREAUTH",4194304);
$UACs.Add("PASSWORD_EXPIRED",8388608);
$UACs.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216);
$UACs.Add("PARTIAL_SECRETS_ACCOUNT",67108864);

Write-Host "[*] UAC With Value $UACValue Has The Following Flags:"
$UACs.GetEnumerator() | Sort-Object -Property Value |ForEach-Object {
    if (($_.Value -band $UACValue) -ne 0) {
        Write-Host "`t- $($_.Key) ($($_.Value))";
    }
}