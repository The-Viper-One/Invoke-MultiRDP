# Invoke-MultiRDP

A modified fork of [fabianosrc/TermsrvPatcher](https://github.com/fabianosrc/TermsrvPatcher), designed for integration with [PsMapExec](https://github.com/The-Viper-One/PsMapExec) which can also be run standalone. This fork also allow for cleanup and restoration of configuration.

This fork incorporates community patches to support the latest Windows versions, including **Windows Server 2025** and **Windows 11 25H2**. As submitted via pull request by the following users:

* [justintubbs1](https://github.com/fabianosrc/TermsrvPatcher/pull/21) - Windows Server 2025 support
* [pesaventofilippo](https://github.com/fabianosrc/TermsrvPatcher/pull/22) - Windows 11 25H2 support

## Requirements

- Administrator rights

## Usage

```powershell
# Enable
Invoke-MultiRDP -Enable

# Disable
Invoke-MultiRDP -Disable
```

> Example Output (Enable)
```
[*] Starting MultiRDP enable process...
[*] The Remote Desktop Services (TermService) has been stopped successfully.
[*] Owner of termsrv.dll: NT AUTHORITY\SYSTEM

SUCCESS: The file (or folder): "C:\Windows\System32\termsrv.dll" now owned by user "ESSOS\GOAD-WS08$".
processed file: C:\Windows\System32\termsrv.dll
Successfully processed 1 files; Failed processing 0 files

[*] Detected OS: Windows 10
[*] The file is already patched. No changes are needed.

[*] MultiRDP has been enabled
```

> Example Output (Disable)
```
[*] Starting MultiRDP disable process...
[*] The Remote Desktop Services (TermService) has been stopped successfully.

SUCCESS: The file (or folder): "C:\Windows\System32\termsrv.dll" now owned by user "ESSOS\GOAD-WS08$".
processed file: C:\Windows\System32\termsrv.dll
Successfully processed 1 files; Failed processing 0 files

[*] Original termsrv.dll restored from backup.
[*] MultiRDP has been disabled
```
