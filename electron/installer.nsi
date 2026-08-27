; NOVA GPS — NSIS Windows Installer Template
; Electron builder generates this automatically, but this
; provides custom branding and post-install actions.

!include "MUI2.nsh"

Name "NOVA GPS"
OutFile "nova-gps-setup.exe"
InstallDir "$LOCALAPPDATA\NOVA GPS"
InstallDirRegKey HKCU "Software\NOVA GPS" "InstallDir"
RequestExecutionLevel admin

!define MUI_ABORTWARNING
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "icon.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "icon.bmp"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "NOVA GPS" SecMain
    SetOutPath "$INSTDIR"
    File /r "dist\win-unpacked\*.*"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Registry
    WriteRegStr HKCU "Software\NOVA GPS" "InstallDir" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS" \
        "DisplayName" "NOVA GPS"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS" \
        "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS" \
        "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS" \
        "DisplayIcon" '"$INSTDIR\nova-gps.exe"'
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS" \
        "NoModify" 1
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS" \
        "NoRepair" 1

    ; Desktop shortcut
    CreateShortcut "$DESKTOP\NOVA GPS.lnk" "$INSTDIR\nova-gps.exe"

    ; Start menu
    CreateDirectory "$SMPROGRAMS\NOVA GPS"
    CreateShortcut "$SMPROGRAMS\NOVA GPS\NOVA GPS.lnk" "$INSTDIR\nova-gps.exe"
    CreateShortcut "$SMPROGRAMS\NOVA GPS\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
    RMDir /r "$INSTDIR"
    Delete "$DESKTOP\NOVA GPS.lnk"
    RMDir /r "$SMPROGRAMS\NOVA GPS"
    DeleteRegKey HKCU "Software\NOVA GPS"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NOVA GPS"
SectionEnd
