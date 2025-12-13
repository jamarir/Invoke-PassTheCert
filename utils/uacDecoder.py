#!/usr/bin/python3
import sys

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
nameS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT"
}

def decode_uac(uac_value):
    result = []
    for hexa, name in sorted(nameS.items()):
        if uac_value & hexa:
            result.append(f"{name} (0x{hexa:04X})")
    return result

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"[!] Usage: python3 {sys.argv[0]} <UAC_INT>")
        exit()
    uac_input = int(sys.argv[1])
    print(f"[*] UAC With Value {uac_input} (0x{uac_input:04X}) Has The Following Flags:")
    for flag in decode_uac(uac_input):
        print(f"  - {flag}")
