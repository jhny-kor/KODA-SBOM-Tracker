#define StageDir GetEnv("KODA_WINDOWS_STAGE")
#define OutputDir GetEnv("KODA_WINDOWS_OUTPUT")
#define AppVersion GetEnv("KODA_WINDOWS_VERSION")

[Setup]
AppId={{B77B6C24-8F85-4C76-9D33-4D7C6A6A5F16}
AppName=KODA SBOM Tracker
AppVersion={#AppVersion}
AppPublisher=KODA
DefaultDirName={autopf}\KODA SBOM Tracker
DefaultGroupName=KODA SBOM Tracker
OutputDir={#OutputDir}
OutputBaseFilename=KODA-SBOM-Tracker-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
DisableProgramGroupPage=yes
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=KODA SBOM Tracker

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Excludes: ".env.example"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#StageDir}\.env.example"; DestDir: "{app}"; DestName: ".env"; Flags: onlyifdoesntexist ignoreversion

[Icons]
Name: "{autoprograms}\KODA SBOM Tracker"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\start-windows.ps1"" -OpenDashboard"; WorkingDir: "{app}"; IconFilename: "{sys}\shell32.dll"; IconIndex: 13

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\start-windows.ps1"" -OpenDashboard"; WorkingDir: "{app}"; Description: "KODA SBOM Tracker 시작(먼저 .env 설정 필요)"; Flags: postinstall nowait unchecked

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\start-windows.ps1"" -Action Stop"; WorkingDir: "{app}"; RunOnceId: "StopKodaSbomTracker"; Flags: runhidden waituntilterminated skipifdoesntexist
