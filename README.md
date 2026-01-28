# UefiDecoder

**UefiDecoder** is a forensic-grade C# utility for inspecting Windows UEFI Secure Boot configurations. It provides deep visibility into `EFI_SIGNATURE_LIST` variables (`PK`, `KEK`, `db`, `dbx`) and other critical NVRAM variables, offering a significant upgrade over standard hex dump tools.

## Download
**[Ep Download v3.0.0 (Latest Release)](https://github.com/dparksports/UefiDecoder/releases/download/v3.0.0/UefiDecoder_v3.0.0.zip)**

![UefiDecoder Screenshot](screenshot.png)

## Features

### 🔍 Deep Certificate Inspection
Parses `X.509` certificates found in `db`, `KEK`, and `PK` to reveal critical details:
- **Subject & Issuer**: Full Distinguished Names (DN).
- **Serial Number**: Verified against vendor allow-lists.
- **Thumbprint**: SHA-1 fingerprint for quick identification.
- **Validity Period**: `NotBefore` and `NotAfter` timestamps.
- **Extensions**: Decodes OIDs like "Key Usage" and "Basic Constraints".

### 🛡️ Revocation List (dbx) Analysis
Instead of flooding the console with raw data, `UefiDecoder` treats `dbx` intelligently:
- **Silent Indexing**: Automatically indexes hundreds of SHA-256 hashes from `dbx` into memory without cluttering the display.
- **Interactive Search**: Provides a search prompt to instantly check if a specific binary hash (e.g., BlackLotus bootkit) is present in the revocation list.

### 💻 Smart Decoding
- **Boot Order**: Decodes `BootOrder` into a recursive list of `Boot####` IDs.
- **Boot Options**: Parses `EFI_LOAD_OPTION` to display human-readable labels (e.g., "Windows Boot Manager", "USB Drive").
- **State Variables**: clearly displays enabled/disabled states for `SecureBoot`, `SetupMode`, `AuditMode`, and `DeployedMode`.

## Requirements

- **OS**: Windows 10 / 11 / Server (Requires UEFI environment).
- **Privileges**: Must be run as **Administrator** (Required for `SeSystemEnvironmentPrivilege`).
- **Runtime**: .NET Framework or .NET Core (Source is .NET compatible).

## Usage

1. **Build the Project**:
   ```powershell
   dotnet build secureboot/secureboot.csproj
   ```

2. **Run as Administrator**:
   ```powershell
   secureboot/bin/Debug/net10.0/secureboot.exe
   ```

3. **Interactive Mode**:
   After printing the variable report, the tool enters **Search Mode**.
   - Paste a SHA-256 hash or partial hash to check against the indexed `dbx`.
   - Press `Enter` to exit.

## Sample Output

```text
--- Antigravity UEFI Decoder v3.0 (Robust Mode) ---
Scanning NVRAM...

[dbx] d719b2cb-3d3a-4596-a3bc-dad00e67656f (23144 bytes)
    -> Contains 481 revocation entries (Hashes).
[Boot0000] 8be4df61-93ca-11d2-aa0d-00e098032b8c (300 bytes)
    Label: "Windows Boot Manager"
[BootOrder] 8be4df61-93ca-11d2-aa0d-00e098032b8c (2 bytes)
    Order: 0000
[db] d719b2cb-3d3a-4596-a3bc-dad00e67656f (9783 bytes)
    List Type: a5c059a1-94e4-4aa7-87b5-ab155c2bf072
    Cert #1:
      Subject:    CN=Microsoft Corporation UEFI CA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
      Issuer:     CN=Microsoft Corporation Third Party Marketplace Root, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
      Serial No:  6108D3C4000000000004
      Algorithm:  sha256RSA
      Valid From: 6/27/2011 2:22:45 PM
      Expires:    6/27/2026 2:32:45 PM

    List Type: a5c059a1-94e4-4aa7-87b5-ab155c2bf072
    Cert #2:
      Subject:    CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US
      Issuer:     CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
      Serial No:  330000001A888B9800562284C100000000001A
      Algorithm:  sha256RSA
      Valid From: 6/13/2023 11:58:29 AM
      Expires:    6/13/2035 12:08:29 PM

[SetupMode] 8be4df61-93ca-11d2-aa0d-00e098032b8c (1 bytes)
    Value: Disabled (0)
[SecureBoot] 8be4df61-93ca-11d2-aa0d-00e098032b8c (1 bytes)
    Value: Enabled (1)
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
