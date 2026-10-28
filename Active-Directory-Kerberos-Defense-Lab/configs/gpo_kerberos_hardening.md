# Active Directory Group Policy (GPO) Kerberos Hardening Standard

**Target Environment:** Microsoft Active Directory Domain Services (Windows Server 2019 / 2022) 
**Standard:** CIS Microsoft Windows Server Benchmark (Level 2 Enterprise)

---

## 1. Enforcing AES Kerberos Cipher Suites & Disabling RC4

### Vulnerability Vector
Kerberoasting attacks succeed because Active Directory allows client workstations to request Ticket Granting Service (TGS) tickets using legacy **RC4-HMAC** (`0x17`) encryption. RC4 hashes can be cracked offline at gigahash speeds on commodity GPUs via Hashcat (`hashcat -m 13100`).

### GPO Implementation
Navigate to: 
`Computer Configuration` $\to$ `Policies` $\to$ `Windows Settings` $\to$ `Security Settings` $\to$ `Local Policies` $\to$ `Security Options`

**Policy Name:** `Network security: Configure encryption types allowed for Kerberos`

Set the policy to **Enabled** and check ONLY:
- [x] `AES128_HMAC_SHA1`
- [x] `AES256_HMAC_SHA1`
- [x] `Future encryption types`
- [ ] *Uncheck DES_CBC_CRC*
- [ ] *Uncheck DES_CBC_MD5*
- [ ] *Uncheck RC4_HMAC_MD5*

Registry Equivalent:
```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters]
"SupportedEncryptionTypes"=dword:00000018
```

---

## 2. Transitioning SPN Accounts to Group Managed Service Accounts (gMSA)

Group Managed Service Accounts eliminate the risk of Kerberoasting:
1. Passwords are 128 characters long and generated cryptographically by Active Directory.
2. Passwords automatically rotate every 30 days without service disruption.
3. Interactive logon is permanently disabled.

### PowerShell Provisioning Template
```powershell
# 1. Create the KDS Root Key (Domain Controller)
Add-KdsRootKey -EffectiveImmediately

# 2. Create the gMSA Account with Target SPN
New-ADServiceAccount `
    -Name "gmsa_sqlprod" `
    -DNSHostName "sqlprod.corp.internal" `
    -ServicePrincipalNames @("MSSQLSvc/sqlprod.corp.internal:1433") `
    -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers_Group"

# 3. Test on Host
Test-ADServiceAccount -Identity "gmsa_sqlprod"
```

---

## 3. Protected Users Security Group

Add all domain administrative accounts and high-privilege service accounts to the **Protected Users** security group:
- NTLM authentication is disabled (Kerberos is enforced).
- Kerberos does not use DES or RC4 encryption types.
- Cached credentials and TGTs are never saved to LSASS memory after logoff.
- Kerberos TGT lifetime is restricted to a maximum of 4 hours.
