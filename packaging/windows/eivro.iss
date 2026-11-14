#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef StageDir
  #error StageDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif

[Setup]
AppId={{B8EE5A97-1D9B-465E-97DE-ED8E79AE7116}
AppName=Eivro
AppVersion={#AppVersion}
AppPublisher=Eivro
AppPublisherURL=https://github.com/Zer0ps/Eivro
DefaultDirName={autopf64}\Eivro
UsePreviousAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
SetupArchitecture=x64
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19045
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=Eivro-{#AppVersion}-windows-x86_64-setup
SetupIconFile=..\..\assets\io.eivro.Client.ico
UninstallDisplayIcon={app}\eivro.exe
WizardStyle=modern
Compression=lzma2/normal
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=no

[Languages]
Name: en; MessagesFile: compiler:Default.isl
Name: ru; MessagesFile: compiler:Languages\Russian.isl

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\eivro-tun.exe"; Flags: dontcopy
Source: "secure-install.ps1"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\Eivro"; Filename: "{app}\eivro.exe"

[Run]
Filename: "{app}\eivro.exe"; Description: "Eivro"; Flags: postinstall nowait skipifsilent runasoriginaluser unchecked; Check: ServiceInstalled

[Code]
var
  ServiceReady: Boolean;
  ServiceStopped: Boolean;

function ServiceInstalled(): Boolean;
begin
  Result := ServiceReady;
end;

function GetCustomSetupExitCode(): Integer;
begin
  if ServiceReady then Result := 0 else Result := 7;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and not ServiceReady then
    WizardForm.FinishedLabel.Caption := 'Eivro installation is incomplete. The tunnel service was not started. Run Setup again to repair the installation.';
end;

function GetFileAttributesW(lpFileName: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Attributes: LongWord;
begin
  Result := '';
  Log('Eivro setup: prepare');
  Attributes := GetFileAttributesW(ExpandConstant('{app}'));
  if (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0) then begin
    Result := 'Eivro installation directory cannot be a link.';
    Exit;
  end;
  ExtractTemporaryFile('eivro-tun.exe');
  if not Exec(ExpandConstant('{tmp}\eivro-tun.exe'), '--stop', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
  begin
    Log(Format('Eivro setup: prepare, exit %d', [Code]));
    Result := 'Eivro could not restore and stop the existing tunnel. Close Eivro and retry.';
  end else
    ServiceStopped := True;
end;

procedure DeinitializeSetup();
var Code: Integer;
begin
  { A cancelled/rolled-back upgrade must not leave the previous service stopped. }
  if ServiceStopped and not ServiceReady then
    Exec(ExpandConstant('{tmp}\eivro-tun.exe'), '--resume', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer;
begin
  if CurStep = ssPostInstall then begin
    Log('Eivro setup: permissions');
    ExtractTemporaryFile('secure-install.ps1');
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\secure-install.ps1') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    begin
      Log(Format('Eivro setup: permissions, exit %d', [Code]));
      RaiseException('Eivro could not protect the installation directory.');
    end;
    Log('Eivro setup: service');
    if not Exec(ExpandConstant('{app}\eivro-tun.exe'), '--install', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    begin
      Log(Format('Eivro setup: service, exit %d', [Code]));
      RaiseException('Eivro tunnel service did not start. Installation is incomplete.');
    end;
    Log('Eivro setup: ready');
    ServiceReady := True;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Code: Integer;
begin
  { usUninstall is after the user's confirmation, before any files are removed. }
  if CurUninstallStep = usUninstall then begin
    if not Exec(ExpandConstant('{app}\eivro-tun.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      RaiseException('Eivro could not close the application and restore the tunnel. Close Eivro through its tray menu in every Windows session, then retry removal.');
  end;
end;
