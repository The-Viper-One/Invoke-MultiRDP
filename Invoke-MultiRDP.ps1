Function Invoke-MultiRDP {
    param(
        [switch]$Enable,
        [switch]$Disable
    )

    function Test-AdminPrivileges {
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM" -or 
            $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    }

    if ($Enable -and $Disable) {
        Write-Warning "`n[*] Both -Enable and -Disable specified. Please pick only one."
        return
    }

    if (-not $Enable -and -not $Disable) {
        Write-Warning "`n[*] You must specify either -Enable or -Disable."
        return
    }

    if (-not (Test-AdminPrivileges)) {
        Write-Warning "`n[!] This script must be run with administrative privileges."
        return
    }

    if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) { 

        return 'Not Workstation OS'
    }

    if ($Enable) {
        Enable-MultiRDP
    }
    else {
        Disable-MultiRDP
    }
}

Function Enable-MultiRDP {
    $OperatingSystemArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
    
    $TermsrvDllFilePath    = "$env:SystemRoot\System32\termsrv.dll"
    $TermsrvDllBackupPath  = "$env:SystemRoot\System32\termsrv.dll.copy"
    $TermsrvDllPatchedPath = "$env:SystemRoot\System32\termsrv.dll.patched"

    $BytePatterns = @{
        Pattern = [regex]"39 81 3C 06 00 00 0F (?:[0-9A-F]{2} ){4}00"
        Win24H2 = [regex]"8B 81 38 06 00 00 39 81 3C 06 00 00 75"
    }

    function Get-OSInfo {
        $OperatingSystemInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        return [PSCustomObject]@{
            CurrentBuild     = $OperatingSystemInfo.CurrentBuild
            BuildRevision    = $OperatingSystemInfo.UBR
            FullOSBuild      = "$($OperatingSystemInfo.CurrentBuild).$($OperatingSystemInfo.UBR)"
            DisplayVersion   = $OperatingSystemInfo.DisplayVersion
            InstallationType = $OperatingSystemInfo.InstallationType
        }
    }

    function Get-OSVersion {
        [version]$OSVersion = [System.Environment]::OSVersion.Version
        $SystemInstallationType = (Get-OSInfo).InstallationType

        if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 1) {
            return "Windows 7"
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and $SystemInstallationType -eq "Client") {
            return "Windows 10"
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -ge 22000) {
            return "Windows 11"
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and $SystemInstallationType -eq "Server") {
            return "Windows Server 2016"
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -eq 20348) {
            return "Windows Server 2022"
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -eq 26100) {
            return "Windows Server 2025"
        }
        else {
            return "Unsupported OS"
        }
    }

    function Update-Dll {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [regex]$InputPattern,
            [Parameter(Mandatory)]
            [string]$Replacement,
            [Parameter(Mandatory)]
            [string]$TermsrvDllAsText,
            [Parameter(Mandatory)]
            [string]$TermsrvDllAsFile,
            [Parameter(Mandatory)]
            [string]$TermsrvDllAsPatch,
            [Parameter(Mandatory)]
            [System.Security.AccessControl.FileSecurity]$TermsrvAclObject
        )

        $PatternMatch = $TermsrvDllAsText -match $InputPattern
        $AlreadyPatched = $TermsrvDllAsText -match $Replacement

        if ($PatternMatch) {
            Write-Output "[*] Pattern matching! Patching file..."

            $DllTextReplaced = $TermsrvDllAsText -replace $InputPattern, $Replacement
            [byte[]]$DllBytesReplaced = -split $DllTextReplaced -replace "^", "0x"
            [System.IO.File]::WriteAllBytes($TermsrvDllAsPatch, $DllBytesReplaced)

            Write-Output "[*] Comparing patched and original files..."
            fc.exe /b $TermsrvDllAsPatch $TermsrvDllAsFile | Out-Null
            
            Start-Sleep -Seconds 2
            Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force
            Write-Output "[*] File patched successfully."
        }
        elseif ($AlreadyPatched) {
            Write-Output "[*] The file is already patched. No changes are needed."
        }
        else {
            Write-Warning "[*] The pattern was not found. Nothing will be changed."
            return
        }

        Set-Acl -Path $TermsrvDllAsFile -AclObject $TermsrvAclObject
        Start-Service TermService -PassThru | Out-Null
    }

    function Stop-TermService {
        try {
            Stop-Service -Name TermService -Force -ErrorAction Stop
            while ((Get-Service -Name TermService).Status -ne "Stopped") {
                Start-Sleep -Milliseconds 500
            }
            Write-Output "[*] The Remote Desktop Services (TermService) has been stopped successfully."
        }
        catch {
            Write-Warning "[*] Failed to stop TermService: $($_.Exception.Message)"
            throw
        }
    }

    Write-Output "`n[*] Starting MultiRDP enable process..."
    
    try {
        Stop-TermService

        $TermsrvDllAcl = Get-Acl -Path $TermsrvDllFilePath
        Write-Output "[*] Owner of termsrv.dll: $($TermsrvDllAcl.Owner)"

        Copy-Item -Path $TermsrvDllFilePath -Destination $TermsrvDllBackupPath -Force

        takeown.exe /F $TermsrvDllFilePath
        $CurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        icacls.exe $TermsrvDllFilePath /grant "$($CurrentUserName):F"

        $DllBytes = [System.IO.File]::ReadAllBytes($TermsrvDllFilePath)
        $DllText = ($DllBytes | ForEach-Object { $_.ToString("X2") }) -join " "

        $CommonParameters = @{
            TermsrvDllAsText  = $DllText
            TermsrvDllAsFile  = $TermsrvDllFilePath
            TermsrvDllAsPatch = $TermsrvDllPatchedPath
            TermsrvAclObject  = $TermsrvDllAcl
        }

        $DetectedOSVersion = Get-OSVersion
        Write-Output "`n[*] Detected OS: $DetectedOSVersion"

        switch ($DetectedOSVersion) {
            "Windows 7" {
                if ($OperatingSystemArchitecture -eq "64-bit") {
                    $SystemBuild = (Get-OSInfo).FullOSBuild
                    switch ($SystemBuild) {
                        "7601.23964" {
                            $DllTextReplaced = $DllText `
                                -replace "8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 2F C3 00 00", "B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90" `
                                -replace "4C 24 60 BB 01 00 00 00", "4C 24 60 BB 00 00 00 00" `
                                -replace "83 7C 24 50 00 74 18 48 8D", "83 7C 24 50 00 EB 18 48 8D"
                        }
                        " 7601.24546" {
                            $DllTextReplaced = $DllText `
                                -replace "8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00", "B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90" `
                                -replace "4C 24 60 BB 01 00 00 00", "4C 24 60 BB 00 00 00 00" `
                                -replace "83 7C 24 50 00 74 43 48 8D", "83 7C 24 50 00 EB 18 48 8D"
                        }
                        Default {
                            $DllTextReplaced = $DllText `
                                -replace "8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00", "B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90" `
                                -replace "4C 24 60 BB 01 00 00 00", "4C 24 60 BB 00 00 00 00" `
                                -replace "83 7C 24 50 00 74 43 48 8D", "83 7C 24 50 00 EB 18 48 8D"
                        }
                    }

                    [byte[]]$DllBytesReplaced = -split $DllTextReplaced -replace "^", "0x"
                    [System.IO.File]::WriteAllBytes($TermsrvDllPatchedPath, $DllBytesReplaced)

                    fc.exe /B $TermsrvDllPatchedPath $TermsrvDllFilePath | Out-Null
                    Start-Sleep -Seconds 2
                    Copy-Item -Path $TermsrvDllPatchedPath -Destination $TermsrvDllFilePath -Force
                    Set-Acl -Path $TermsrvDllFilePath -AclObject $TermsrvDllAcl
                    Remove-Item -Path $TermsrvDllPatchedPath -Force -ErrorAction "SilentlyContinue"
                    Start-Service TermService -PassThru | Out-Null
                }
            }
            "Windows 10" {
                Update-Dll @CommonParameters -InputPattern $BytePatterns.Pattern -Replacement "B8 00 01 00 00 89 81 38 06 00 00 90"
            }
            "Windows 11" {
                $SystemDisplayVersion = (Get-OSInfo).DisplayVersion
                if ($SystemDisplayVersion -eq "23H2") {
                    Update-Dll @CommonParameters -InputPattern $BytePatterns.Pattern -Replacement "B8 00 01 00 00 89 81 38 06 00 00 90"
                }
                elseif ($SystemDisplayVersion -eq "24H2" -or $SystemDisplayVersion -eq "25H2") {
                    Update-Dll @CommonParameters -InputPattern $BytePatterns.Win24H2 -Replacement "B8 00 01 00 00 89 81 38 06 00 00 90 EB"
                }
                else {
                    Write-Warning "[*] Unsupported Windows 11 version: $SystemDisplayVersion"
                }
            }
            "Windows Server 2016" {
                Update-Dll @CommonParameters -InputPattern $BytePatterns.Pattern -Replacement "B8 00 01 00 00 89 81 38 06 00 00 90"
            }
            "Windows Server 2022" {
                Update-Dll @CommonParameters -InputPattern $BytePatterns.Pattern -Replacement "B8 00 01 00 00 89 81 38 06 00 00 90"
            }
            "Windows Server 2025" {
                Update-Dll @CommonParameters -InputPattern $BytePatterns.Pattern -Replacement "B8 00 01 00 00 89 81 38 06 00 00 90"
            }
            "Unsupported OS" {
                throw "[*] Unsupported operating system detected."
            }
        }
        
        Write-Output "`n[*] MultiRDP has been enabled"
    }
    catch {
        Write-Error "`n[*] Failed to enable MultiRDP: $($_.Exception.Message)"
        throw
    }
}

Function Disable-MultiRDP {
    
$TermsrvDllFilePath    = "$env:SystemRoot\System32\termsrv.dll"
    $TermsrvDllBackupPath  = "$env:SystemRoot\System32\termsrv.dll.copy"
    $TermsrvDllPatchedPath = "$env:SystemRoot\System32\termsrv.dll.patched"

    function Stop-TermService {
        try {
            Stop-Service -Name TermService -Force -ErrorAction Stop
            while ((Get-Service -Name TermService).Status -ne "Stopped") {
                Start-Sleep -Milliseconds 500
            }
            Write-Output "[*] The Remote Desktop Services (TermService) has been stopped successfully."
        }
        catch {
            Write-Output "[*] Failed to stop TermService: $($_.Exception.Message)"
            throw
        }
    }

    Write-Output "`n[*] Starting MultiRDP disable process..."

    try {
        
    Stop-TermService

        takeown.exe /F $TermsrvDllFilePath
        $CurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        icacls.exe $TermsrvDllFilePath /grant "$($CurrentUserName):F"

        if (Test-Path $TermsrvDllBackupPath) {
            Remove-Item -Force $TermsrvDllFilePath
            Remove-Item -Force $TermsrvDllPatchedPath
            Rename-Item -Path $TermsrvDllBackupPath -NewName $TermsrvDllFilePath -Force
            Write-Output "`n[*] Original termsrv.dll restored from backup."
        }
        else {
            Write-Output "`n[*] Backup file not found. Cannot restore original configuration."
            return
        }

        Start-Sleep -Seconds 3
        Start-Service -Name "TermService"
        
        Write-Output "[*] MultiRDP has been disabled"
    }
    catch {
        Write-Error "`n[*] Failed to disable MultiRDP: $($_.Exception.Message)"
        throw
    }
}
