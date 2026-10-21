; Inno Setup 6.3+ script for XML-ray.
; The Release Manager passes the version:  ISCC /DMyAppVersion=1.2.3 packaging\installer.iss
; Paths are relative to this file's folder (packaging\).

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#define MyAppName "XML-ray"
#define MyAppExeName "XML-ray.exe"
#define MyAppPublisher "Sbreland18"
#define MyAppURL "https://github.com/Sbreland18/XML-ray"

[Setup]
; Never change AppId: it's how upgrades find the existing install.
AppId={{8F3C2A71-5B4E-4D9A-9C3E-2E7B1A6D4F10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
AppComments=See through your DMARC reports
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Per-user install by default: no admin prompt, so automatic updates are seamless.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
OutputDir=..\dist\installer
OutputBaseFilename=XML-ray-Setup-{#MyAppVersion}
SetupIconFile=..\xmlray\assets\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Remove the previous version's libraries so upgrades start clean.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\XML-ray\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; No skipifsilent: after a silent auto-update, XML-ray reopens by itself.
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall
