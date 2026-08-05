#define StageDir GetEnv("KODA_PREVIEW_STAGE")
#define OutputDir GetEnv("KODA_PREVIEW_OUTPUT")
#define AppVersion GetEnv("KODA_PREVIEW_VERSION")

[Setup]
AppId={{0C3D6E44-3C2E-4E71-AE35-8A2A1F3D5B7C}
AppName=KODA SBOM Tracker Preview
AppVersion={#AppVersion}
AppPublisher=KODA
DefaultDirName={localappdata}\Programs\KODA SBOM Tracker Preview
DefaultGroupName=KODA SBOM Tracker Preview
OutputDir={#OutputDir}
OutputBaseFilename=KODA-SBOM-Tracker-Preview-Setup
ArchitecturesAllowed=x64compatible
PrivilegesRequired=lowest
DisableProgramGroupPage=yes
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=KODA SBOM Tracker Preview
LicenseFile={#StageDir}\legal\LICENSE

[Files]
Source: "{#StageDir}\web\*"; DestDir: "{app}\web"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#StageDir}\scripts\serve-windows-preview.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "{#StageDir}\README-preview.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\legal\*"; DestDir: "{app}\legal"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\KODA SBOM Tracker Preview"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\scripts\serve-windows-preview.ps1"" -Action Start -OpenBrowser"; WorkingDir: "{app}"; IconFilename: "{sys}\shell32.dll"; IconIndex: 13

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\scripts\serve-windows-preview.ps1"" -Action Start -OpenBrowser"; WorkingDir: "{app}"; Description: "KODA SBOM Tracker Preview 시작"; Flags: postinstall nowait unchecked

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\serve-windows-preview.ps1"" -Action Stop"; WorkingDir: "{app}"; RunOnceId: "StopKodaSbomTrackerPreview"; Flags: runhidden waituntilterminated skipifdoesntexist
