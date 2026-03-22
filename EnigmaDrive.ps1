[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('status', 'encrypt', 'unlock', 'lock', 'decrypt', 'progress')]
    [string]$Action,

    [Parameter(Mandatory = $false, Position = 1)]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$DriveLetter,

    [Parameter(Mandatory = $false)]
    [string]$RecoveryKeyOutputDir = '.\recovery',

    [Parameter(Mandatory = $false)]
    [switch]$Gui
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Bitte PowerShell als Administrator starten.'
    }
}

function Get-MountPoint {
    param([string]$Letter)
    return ($Letter.ToUpper() + ':')
}

function Get-BitLockerLetters {
    return (Get-BitLockerVolume |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.MountPoint) } |
            ForEach-Object { $_.MountPoint.TrimEnd(':').ToUpper() } |
            Sort-Object -Unique)
}

function Prompt-DriveLetter {
    param([string]$Prompt = 'Laufwerksbuchstaben eingeben (z.B. L)')

    $letters = Get-BitLockerLetters
    if ($letters.Count -gt 0) {
        Write-Host ('Verfuegbare Laufwerke: ' + ($letters -join ', '))
    }

    $inputLetter = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($inputLetter)) {
        throw 'Kein Laufwerksbuchstabe angegeben.'
    }

    return $inputLetter.Substring(0, 1).ToUpper()
}

function Watch-Progress {
    param([string]$Letter)

    if ([string]::IsNullOrWhiteSpace($Letter)) {
        Write-Host ''
        $volumes = Get-BitLockerVolume | Where-Object {
            $_.VolumeStatus -in @('EncryptionInProgress', 'DecryptionInProgress', 'EncryptionPaused', 'DecryptionPaused')
        }
        if (-not $volumes) {
            Write-Host 'Kein Laufwerk wird gerade ver-/entschluesselt.'
            return
        }
        $Letter = $volumes[0].MountPoint.TrimEnd(':')
    }

    $mountPoint = Get-MountPoint -Letter $Letter

    Write-Host "Fortschritt fuer $mountPoint (Strg+C zum Beenden):`n"
    while ($true) {
        $vol = Get-BitLockerVolume -MountPoint $mountPoint
        $pct  = $vol.EncryptionPercentage
        $status = $vol.VolumeStatus

        $bar = '[' + ('#' * [math]::Floor($pct / 5)) + (' ' * (20 - [math]::Floor($pct / 5))) + ']'

        Write-Host -NoNewline "`r$bar $pct% - $status         "

        if ($status -in @('FullyEncrypted', 'FullyDecrypted')) {
            Write-Host ""
            Write-Host "Fertig: $status"
            break
        }

        Start-Sleep -Seconds 3
    }
}

function Get-SecureStringLength {
    param([System.Security.SecureString]$Value)

    if ($null -eq $Value) {
        return 0
    }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Length
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Assert-PasswordPolicy {
    param(
        [System.Security.SecureString]$Password,
        [int]$MinLength = 8
    )

    $length = Get-SecureStringLength -Value $Password
    if ($length -lt $MinLength) {
        throw "Passwort zu kurz: mindestens $MinLength Zeichen erforderlich."
    }
}

function Assert-EncryptionStarted {
    param([string]$MountPoint)

    $state = Get-BitLockerVolume -MountPoint $MountPoint
    $started = (
        $state.ProtectionStatus -eq 'On' -or
        $state.VolumeStatus -in @('EncryptionInProgress', 'EncryptionPaused', 'FullyEncrypted')
    )

    if (-not $started) {
        throw "Verschluesselung fuer $MountPoint wurde nicht gestartet. Bitte Fehlermeldungen oben pruefen."
    }
}

function Show-Status {
    $volumes = Get-BitLockerVolume | Sort-Object -Property MountPoint
    if (-not $volumes) {
        Write-Host 'Keine BitLocker-Volumes gefunden.'
        return
    }

    $volumes |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod, EncryptionPercentage, KeyProtector |
        Format-List
}

function Get-ProgressText {
    $volumes = Get-BitLockerVolume | Sort-Object MountPoint
    $lines = @()
    foreach ($v in $volumes) {
        $pct = $v.EncryptionPercentage
        $bar = '[' + ('#' * [math]::Floor($pct / 5)) + (' ' * (20 - [math]::Floor($pct / 5))) + ']'
        $lines += "$($v.MountPoint)  $bar  $pct%  $($v.VolumeStatus)"
    }
    return ($lines -join "`r`n")
}

function Get-StatusText {
    $volumes = Get-BitLockerVolume | Sort-Object -Property MountPoint
    if (-not $volumes) {
        return 'Keine BitLocker-Volumes gefunden.'
    }

    return ($volumes |
            Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod, EncryptionPercentage |
            Format-Table -AutoSize |
            Out-String)
}

function Ensure-RecoveryDir {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }
}

function Add-RecoveryPasswordProtector {
    param([string]$MountPoint)

    $result = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector
    $recovery = $result.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1

    if (-not $recovery) {
        throw 'Recovery-Protector konnte nicht erstellt werden.'
    }

    return $recovery
}

function Save-RecoveryInfo {
    param(
        [string]$MountPoint,
        [string]$Path,
        [object]$RecoveryProtector
    )

    Ensure-RecoveryDir -Path $Path

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeMount = $MountPoint.Replace(':', '')
    $file = Join-Path $Path ("Recovery-$safeMount-$timestamp.txt")

    @(
        "MountPoint: $MountPoint"
        "CreatedAt: $(Get-Date -Format o)"
        "RecoveryPassword: $($RecoveryProtector.RecoveryPassword)"
        "KeyProtectorId: $($RecoveryProtector.KeyProtectorId)"
    ) | Set-Content -Path $file -Encoding UTF8

    Write-Host "Recovery-Datei gespeichert: $file"
}

function Encrypt-Drive {
    param(
        [string]$Letter,
        [System.Security.SecureString]$Password = $null
    )

    if ([string]::IsNullOrWhiteSpace($Letter)) {
        $Letter = Prompt-DriveLetter -Prompt 'Laufwerksbuchstabe fuer Verschluesselung'
    }

    $mountPoint = Get-MountPoint -Letter $Letter

    $volume = Get-BitLockerVolume -MountPoint $mountPoint
    if ($volume.ProtectionStatus -eq 'On') {
        Write-Host "Volume $mountPoint ist bereits geschuetzt."
        return
    }

    if ($mountPoint -eq 'C:') {
        Enable-BitLocker -MountPoint $mountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest -ErrorAction Stop
    }
    else {
        if ($null -eq $Password) {
            $Password = Read-Host -AsSecureString -Prompt "Passwort fuer $mountPoint eingeben"
        }
        Assert-PasswordPolicy -Password $Password
        Enable-BitLocker -MountPoint $mountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -PasswordProtector -Password $Password -ErrorAction Stop
    }

    Assert-EncryptionStarted -MountPoint $mountPoint

    $recovery = Add-RecoveryPasswordProtector -MountPoint $mountPoint
    Save-RecoveryInfo -MountPoint $mountPoint -Path $RecoveryKeyOutputDir -RecoveryProtector $recovery

    Write-Host "Verschluesselung gestartet fuer $mountPoint."
}

function Unlock-Drive {
    param(
        [string]$Letter,
        [System.Security.SecureString]$Password = $null
    )

    if ([string]::IsNullOrWhiteSpace($Letter)) {
        $Letter = Prompt-DriveLetter -Prompt 'Laufwerksbuchstabe zum Entsperren'
    }

    $mountPoint = Get-MountPoint -Letter $Letter

    if ($null -eq $Password) {
        $Password = Read-Host -AsSecureString -Prompt "Passwort fuer $mountPoint eingeben"
    }
    Unlock-BitLocker -MountPoint $mountPoint -Password $Password
    Write-Host "Laufwerk entsperrt: $mountPoint"
}

function Lock-Drive {
    param([string]$Letter)

    if ([string]::IsNullOrWhiteSpace($Letter)) {
        $Letter = Prompt-DriveLetter -Prompt 'Laufwerksbuchstabe zum Sperren'
    }

    $mountPoint = Get-MountPoint -Letter $Letter

    Lock-BitLocker -MountPoint $mountPoint
    Write-Host "Laufwerk gesperrt: $mountPoint"
}

function Decrypt-Drive {
    param([string]$Letter)

    if ([string]::IsNullOrWhiteSpace($Letter)) {
        $Letter = Prompt-DriveLetter -Prompt 'Laufwerksbuchstabe fuer Entschluesselung'
    }

    $mountPoint = Get-MountPoint -Letter $Letter

    Disable-BitLocker -MountPoint $mountPoint
    Write-Host "Entschluesselung gestartet fuer: $mountPoint"
}

function Invoke-RequestedAction {
    param(
        [string]$RequestedAction,
        [string]$RequestedDriveLetter
    )

    switch ($RequestedAction) {
        'status'   { Show-Status }
        'progress' { Watch-Progress -Letter $RequestedDriveLetter }
        'encrypt'  { Encrypt-Drive -Letter $RequestedDriveLetter }
        'unlock'   { Unlock-Drive -Letter $RequestedDriveLetter }
        'lock'     { Lock-Drive -Letter $RequestedDriveLetter }
        'decrypt'  { Decrypt-Drive -Letter $RequestedDriveLetter }
        default    { throw "Unbekannte Action: $RequestedAction" }
    }
}

function Start-InteractiveMenu {
    Write-Host ''
    Write-Host 'ENIGMA Drive Menu'
    Write-Host '1) Status anzeigen'
    Write-Host '2) Laufwerk verschluesseln'
    Write-Host '3) Laufwerk entsperren'
    Write-Host '4) Laufwerk sperren'
    Write-Host '5) Laufwerk entschluesseln'
    Write-Host '6) Verschluesselungs-Fortschritt beobachten'
    Write-Host '7) Beenden'

    $selection = Read-Host 'Auswahl (1-7)'
    switch ($selection) {
        '1' { Invoke-RequestedAction -RequestedAction 'status'   -RequestedDriveLetter $null }
        '2' { Invoke-RequestedAction -RequestedAction 'encrypt'  -RequestedDriveLetter $null }
        '3' { Invoke-RequestedAction -RequestedAction 'unlock'   -RequestedDriveLetter $null }
        '4' { Invoke-RequestedAction -RequestedAction 'lock'     -RequestedDriveLetter $null }
        '5' { Invoke-RequestedAction -RequestedAction 'decrypt'  -RequestedDriveLetter $null }
        '6' { Invoke-RequestedAction -RequestedAction 'progress' -RequestedDriveLetter $null }
        '7' { Write-Host 'Beendet.' }
        default { throw 'Ungueltige Auswahl. Bitte 1 bis 7 waehlen.' }
    }
}

function Get-PasswordStrengthInfo {
    param([string]$Password)

    $length = $Password.Length
    $score = 0
    if ($length -ge 8)  { $score++ }
    if ($length -ge 12) { $score++ }
    if ($Password -cmatch '[A-Z]')      { $score++ }
    if ($Password -cmatch '[a-z]')      { $score++ }
    if ($Password -match '\d')         { $score++ }
    if ($Password -match '[^a-zA-Z0-9]'){ $score++ }

    $label = 'Sehr schwach'
    $color = [System.Drawing.Color]::FromArgb(192, 0, 0)
    switch ($score) {
        { $_ -le 2 } { $label = 'Sehr schwach'; $color = [System.Drawing.Color]::FromArgb(192, 0, 0); break }
        3            { $label = 'Schwach';      $color = [System.Drawing.Color]::FromArgb(204, 102, 0); break }
        4            { $label = 'Mittel';       $color = [System.Drawing.Color]::FromArgb(160, 140, 0); break }
        5            { $label = 'Stark';        $color = [System.Drawing.Color]::FromArgb(0, 128, 0); break }
        default      { $label = 'Sehr stark';   $color = [System.Drawing.Color]::FromArgb(0, 90, 180) }
    }

    [PSCustomObject]@{
        Length  = $length
        Score   = $score
        Label   = $label
        Color   = $color
        IsValid = ($length -ge 8)
    }
}

function Show-PasswordDialog {
    param(
        [string]$Headline = 'Passwort eingeben',
        [string]$DriveLabel = '',
        [switch]$RequireMinLength
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "ENIGMA  -  $Headline"
    $dlg.Size            = New-Object System.Drawing.Size(420, 250)
    $dlg.StartPosition   = 'CenterScreen'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false
    $dlg.MinimizeBox     = $false
    $dlg.BackColor       = [System.Drawing.Color]::FromArgb(212, 208, 200)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text     = if ($DriveLabel) { "Passwort fuer Laufwerk ${DriveLabel}:" } else { 'Passwort:' }
    $lbl.Location = New-Object System.Drawing.Point(12, 16)
    $lbl.AutoSize = $true

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location     = New-Object System.Drawing.Point(12, 40)
    $txt.Size         = New-Object System.Drawing.Size(382, 22)
    $txt.PasswordChar = '*'

    $lblStrength = New-Object System.Windows.Forms.Label
    $lblStrength.Text     = 'Qualitaet: Sehr schwach'
    $lblStrength.Location = New-Object System.Drawing.Point(12, 68)
    $lblStrength.AutoSize = $true
    $lblStrength.ForeColor = [System.Drawing.Color]::FromArgb(192, 0, 0)

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Location = New-Object System.Drawing.Point(12, 90)
    $bar.Size     = New-Object System.Drawing.Size(382, 16)
    $bar.Minimum  = 0
    $bar.Maximum  = 6

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text     = if ($RequireMinLength) { 'Mindestens 8 Zeichen erforderlich.' } else { 'Empfohlen: mindestens 8 Zeichen.' }
    $lblHint.Location = New-Object System.Drawing.Point(12, 114)
    $lblHint.AutoSize = $true

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text         = 'OK'
    $btnOk.Location     = New-Object System.Drawing.Point(210, 160)
    $btnOk.Size         = New-Object System.Drawing.Size(84, 28)
    $btnOk.BackColor    = [System.Drawing.Color]::FromArgb(0, 0, 128)
    $btnOk.ForeColor    = [System.Drawing.Color]::White
    $btnOk.DialogResult = 'OK'
    $dlg.AcceptButton   = $btnOk

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text         = 'Abbrechen'
    $btnCancel.Location     = New-Object System.Drawing.Point(304, 160)
    $btnCancel.Size         = New-Object System.Drawing.Size(90, 28)
    $btnCancel.DialogResult = 'Cancel'
    $dlg.CancelButton       = $btnCancel

    $updateStrength = {
        $info = Get-PasswordStrengthInfo -Password $txt.Text
        $lblStrength.Text = "Qualitaet: $($info.Label)"
        $lblStrength.ForeColor = $info.Color
        $bar.Value = [math]::Max($bar.Minimum, [math]::Min($bar.Maximum, $info.Score))

        if ($RequireMinLength) {
            $btnOk.Enabled = ($txt.Text.Length -gt 0 -and $info.IsValid)
        }
        else {
            $btnOk.Enabled = ($txt.Text.Length -gt 0)
        }
    }.GetNewClosure()

    $txt.Add_TextChanged($updateStrength)
    $dlg.Controls.AddRange(@($lbl, $txt, $lblStrength, $bar, $lblHint, $btnOk, $btnCancel))
    & $updateStrength

    if ($dlg.ShowDialog() -eq 'OK' -and $txt.Text.Length -gt 0) {
        $ss = New-Object System.Security.SecureString
        foreach ($c in $txt.Text.ToCharArray()) { $ss.AppendChar($c) }
        $ss.MakeReadOnly()
        $txt.Clear()
        return $ss
    }
    return $null
}

function Start-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # ── Farb-Palette (WinXP Regierungsrechner 2003) ───────────────────────
    $clrBg       = [System.Drawing.Color]::FromArgb(212, 208, 200)   # XP-Silbergrau
    $clrNavy     = [System.Drawing.Color]::FromArgb(0, 0, 128)       # Staatsblau
    $clrNavyDark = [System.Drawing.Color]::FromArgb(0, 0, 80)
    $clrCrtBg    = [System.Drawing.Color]::FromArgb(8, 10, 8)        # Phosphor-Schwarz
    $clrCrtFg    = [System.Drawing.Color]::FromArgb(0, 204, 0)       # Gruen-Phosphor
    $clrWhite    = [System.Drawing.Color]::White
    $clrSep      = [System.Drawing.Color]::FromArgb(128, 128, 128)
    $clrSubtitle = [System.Drawing.Color]::FromArgb(160, 160, 255)

    $fontUI      = New-Object System.Drawing.Font('Tahoma', 8)
    $fontBold    = New-Object System.Drawing.Font('Tahoma', 8,  [System.Drawing.FontStyle]::Bold)
    $fontHeader  = New-Object System.Drawing.Font('Tahoma', 11, [System.Drawing.FontStyle]::Bold)
    $fontSub     = New-Object System.Drawing.Font('Tahoma', 7)
    $fontCrt     = New-Object System.Drawing.Font('Courier New', 10)
    $fontMicro   = New-Object System.Drawing.Font('Tahoma', 7)

    # ── Form ──────────────────────────────────────────────────────────────
    $form = New-Object System.Windows.Forms.Form
    $form.Text          = 'ENIGMA v2.4  //  SECURE DRIVE MANAGER'
    $form.StartPosition = 'CenterScreen'
    $form.Size          = New-Object System.Drawing.Size(760, 600)
    $form.BackColor     = $clrBg
    $form.FormBorderStyle = 'FixedSingle'
    $form.MaximizeBox   = $false
    $form.Font          = $fontUI

    # ── Header ────────────────────────────────────────────────────────────
    $pnlHeader = New-Object System.Windows.Forms.Panel
    $pnlHeader.Location  = New-Object System.Drawing.Point(0, 0)
    $pnlHeader.Size      = New-Object System.Drawing.Size(760, 60)
    $pnlHeader.BackColor = $clrNavy

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text      = 'ENIGMA  -  SECURE VOLUME MANAGER'
    $lblTitle.Font      = $fontHeader
    $lblTitle.ForeColor = $clrWhite
    $lblTitle.Location  = New-Object System.Drawing.Point(12, 7)
    $lblTitle.AutoSize  = $true

    $lblSub = New-Object System.Windows.Forms.Label
    $lblSub.Text      = 'XTS-AES-256   //   Windows BitLocker Volume Encryption'
    $lblSub.Font      = $fontSub
    $lblSub.ForeColor = $clrSubtitle
    $lblSub.Location  = New-Object System.Drawing.Point(14, 34)
    $lblSub.AutoSize  = $true

    $pnlHeader.Controls.AddRange(@($lblTitle, $lblSub))

    # ── Separator 1 ───────────────────────────────────────────────────────
    $sep1 = New-Object System.Windows.Forms.Panel
    $sep1.Location  = New-Object System.Drawing.Point(0, 60)
    $sep1.Size      = New-Object System.Drawing.Size(760, 2)
    $sep1.BackColor = $clrSep

    # ── Controls-Zeile ────────────────────────────────────────────────────
    $pnlCtrl = New-Object System.Windows.Forms.Panel
    $pnlCtrl.Location  = New-Object System.Drawing.Point(0, 62)
    $pnlCtrl.Size      = New-Object System.Drawing.Size(760, 52)
    $pnlCtrl.BackColor = $clrBg

    $lblAction = New-Object System.Windows.Forms.Label
    $lblAction.Text      = 'OPERATION:'
    $lblAction.Font      = $fontBold
    $lblAction.ForeColor = $clrNavy
    $lblAction.Location  = New-Object System.Drawing.Point(12, 6)
    $lblAction.AutoSize  = $true

    $cmbAction = New-Object System.Windows.Forms.ComboBox
    $cmbAction.Location      = New-Object System.Drawing.Point(12, 22)
    $cmbAction.Size          = New-Object System.Drawing.Size(190, 22)
    $cmbAction.DropDownStyle = 'DropDownList'
    $cmbAction.Font          = $fontUI
    $cmbAction.BackColor     = [System.Drawing.Color]::White
    [void]$cmbAction.Items.AddRange(@('status', 'encrypt', 'unlock', 'lock', 'decrypt', 'progress'))
    $cmbAction.SelectedIndex = 0

    $lblDrive = New-Object System.Windows.Forms.Label
    $lblDrive.Text      = 'TARGET DRIVE:'
    $lblDrive.Font      = $fontBold
    $lblDrive.ForeColor = $clrNavy
    $lblDrive.Location  = New-Object System.Drawing.Point(216, 6)
    $lblDrive.AutoSize  = $true

    $cmbDrive = New-Object System.Windows.Forms.ComboBox
    $cmbDrive.Location      = New-Object System.Drawing.Point(216, 22)
    $cmbDrive.Size          = New-Object System.Drawing.Size(80, 22)
    $cmbDrive.DropDownStyle = 'DropDownList'
    $cmbDrive.Font          = $fontUI
    $cmbDrive.BackColor     = [System.Drawing.Color]::White

    $makeBtn = {
        param($text, $x, $navy = $false)
        $b = New-Object System.Windows.Forms.Button
        $b.Text      = $text
        $b.Location  = New-Object System.Drawing.Point($x, 20)
        $b.Size      = New-Object System.Drawing.Size(112, 26)
        $b.Font      = $fontBold
        $b.FlatStyle = 'Standard'
        if ($navy) {
            $b.BackColor = $clrNavy
            $b.ForeColor = $clrWhite
        } else {
            $b.BackColor = $clrBg
        }
        return $b
    }

    $btnRefresh = & $makeBtn 'REFRESH DRIVES' 312
    $btnRun     = & $makeBtn 'EXECUTE'        434 $true
    $btnClose   = & $makeBtn 'CLOSE'          556

    $pnlCtrl.Controls.AddRange(@($lblAction, $cmbAction, $lblDrive, $cmbDrive, $btnRefresh, $btnRun, $btnClose))

    # ── Separator 2 ───────────────────────────────────────────────────────
    $sep2 = New-Object System.Windows.Forms.Panel
    $sep2.Location  = New-Object System.Drawing.Point(0, 114)
    $sep2.Size      = New-Object System.Drawing.Size(760, 2)
    $sep2.BackColor = $clrSep

    # ── CRT-Ausgabe ───────────────────────────────────────────────────────
    $txtOutput = New-Object System.Windows.Forms.TextBox
    $txtOutput.Location    = New-Object System.Drawing.Point(10, 122)
    $txtOutput.Size        = New-Object System.Drawing.Size(722, 416)
    $txtOutput.Multiline   = $true
    $txtOutput.ScrollBars  = 'Vertical'
    $txtOutput.ReadOnly    = $true
    $txtOutput.Font        = $fontCrt
    $txtOutput.BackColor   = $clrCrtBg
    $txtOutput.ForeColor   = $clrCrtFg
    $txtOutput.BorderStyle = 'FixedSingle'

    # ── Statusleiste ──────────────────────────────────────────────────────
    $pnlStatus = New-Object System.Windows.Forms.Panel
    $pnlStatus.Location  = New-Object System.Drawing.Point(0, 540)
    $pnlStatus.Size      = New-Object System.Drawing.Size(760, 28)
    $pnlStatus.BackColor = $clrNavyDark

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text      = 'READY'
    $lblStatus.Font      = $fontMicro
    $lblStatus.ForeColor = $clrWhite
    $lblStatus.Location  = New-Object System.Drawing.Point(10, 8)
    $lblStatus.AutoSize  = $true

    $lblClock = New-Object System.Windows.Forms.Label
    $lblClock.Text      = (Get-Date -Format 'yyyy-MM-dd   HH:mm:ss')
    $lblClock.Font      = $fontMicro
    $lblClock.ForeColor = $clrWhite
    $lblClock.Location  = New-Object System.Drawing.Point(610, 8)
    $lblClock.AutoSize  = $true

    $pnlStatus.Controls.AddRange(@($lblStatus, $lblClock))

    # ── Funktionsreferenzen als Variablen (werden von Closures eingefangen) ─
    $fnGetProgressText     = ${function:Get-ProgressText}
    $fnGetStatusText       = ${function:Get-StatusText}
    $fnGetBitLockerLetters = ${function:Get-BitLockerLetters}
    $fnInvokeAction        = ${function:Invoke-RequestedAction}

    # ── Timer: Fortschritt ────────────────────────────────────────────────
    $progressTimer = New-Object System.Windows.Forms.Timer
    $progressTimer.Interval = 3000
    $progressTimer.Add_Tick({
        try {
            $txtOutput.Text = & $fnGetProgressText
            $lblStatus.Text = 'MONITORING  //  LAST UPDATE: ' + (Get-Date -Format 'HH:mm:ss')
        } catch { }
    }.GetNewClosure())

    # ── Timer: Uhr ────────────────────────────────────────────────────────
    $clockTimer = New-Object System.Windows.Forms.Timer
    $clockTimer.Interval = 1000
    $clockTimer.Add_Tick({
        $lblClock.Text = Get-Date -Format 'yyyy-MM-dd   HH:mm:ss'
    }.GetNewClosure())
    $clockTimer.Start()

    # ── Logik ─────────────────────────────────────────────────────────────
    $refreshDrives = {
        $cmbDrive.Items.Clear()
        foreach ($letter in (& $fnGetBitLockerLetters)) {
            [void]$cmbDrive.Items.Add($letter)
        }
        if ($cmbDrive.Items.Count -gt 0) { $cmbDrive.SelectedIndex = 0 }
    }.GetNewClosure()

    $btnRefresh.Add_Click({
        & $refreshDrives
        $lblStatus.Text = 'DRIVES REFRESHED  //  ' + (Get-Date -Format 'HH:mm:ss')
    }.GetNewClosure())

    $btnClose.Add_Click({
        $progressTimer.Stop()
        $clockTimer.Stop()
        $form.Close()
    }.GetNewClosure())

    $btnRun.Add_Click({
        try {
            $selectedAction = [string]$cmbAction.SelectedItem
            $selectedDrive  = if ($cmbDrive.SelectedItem) { [string]$cmbDrive.SelectedItem } else { $null }
            $lblStatus.Text = "EXECUTING >> $($selectedAction.ToUpper())  :  $selectedDrive"

            if ($selectedAction -eq 'status') {
                $progressTimer.Stop()
                $txtOutput.Text = & $fnGetStatusText
                $lblStatus.Text = 'STATUS QUERY  //  OK  //  ' + (Get-Date -Format 'HH:mm:ss')

            } elseif ($selectedAction -eq 'progress') {
                $txtOutput.Text = & $fnGetProgressText
                $progressTimer.Start()
                $lblStatus.Text = 'MONITORING  //  AUTO-UPDATE ACTIVE'

            } elseif ($selectedAction -eq 'encrypt') {
                if ([string]::IsNullOrWhiteSpace($selectedDrive)) { throw 'Bitte zuerst ein Laufwerk auswaehlen.' }
                $pw = Show-PasswordDialog -Headline 'Verschluesselung' -DriveLabel $selectedDrive -RequireMinLength
                if ($null -eq $pw) { $lblStatus.Text = 'ABGEBROCHEN'; return }

                $mountPt  = $selectedDrive + ':'
                $recovDir = if ([System.IO.Path]::IsPathRooted($RecoveryKeyOutputDir)) {
                                $RecoveryKeyOutputDir
                            } else {
                                Join-Path (Get-Location) $RecoveryKeyOutputDir
                            }

                $rs = [runspacefactory]::CreateRunspace()
                $rs.Open()
                $rs.SessionStateProxy.SetVariable('_mp',  $mountPt)
                $rs.SessionStateProxy.SetVariable('_pw',  $pw)
                $rs.SessionStateProxy.SetVariable('_dir', $recovDir)
                $bgPs = [System.Management.Automation.PowerShell]::Create()
                $bgPs.Runspace = $rs
                [void]$bgPs.AddScript({
                    Import-Module BitLocker -ErrorAction SilentlyContinue

                    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($_pw)
                    try {
                        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                        if ($plain.Length -lt 8) {
                            throw 'Passwort zu kurz: mindestens 8 Zeichen erforderlich.'
                        }
                    }
                    finally {
                        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }

                    $vol = Get-BitLockerVolume -MountPoint $_mp
                    if ($vol.ProtectionStatus -eq 'On') { return 'ALREADY_PROTECTED' }
                    Enable-BitLocker -MountPoint $_mp -EncryptionMethod XtsAes256 -UsedSpaceOnly -PasswordProtector -Password $_pw -ErrorAction Stop

                    $check = Get-BitLockerVolume -MountPoint $_mp
                    if (-not ($check.ProtectionStatus -eq 'On' -or $check.VolumeStatus -in @('EncryptionInProgress', 'EncryptionPaused', 'FullyEncrypted'))) {
                        throw "Verschluesselung fuer $_mp wurde nicht gestartet."
                    }

                    $r   = Add-BitLockerKeyProtector -MountPoint $_mp -RecoveryPasswordProtector
                    $rec = $r.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
                    if ($rec) {
                        if (-not (Test-Path $_dir)) { New-Item $_dir -ItemType Directory | Out-Null }
                        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
                        $f  = Join-Path $_dir "Recovery-$($_mp.Replace(':',''))-$ts.txt"
                        @("MountPoint: $_mp", "CreatedAt: $(Get-Date -Format o)",
                          "RecoveryPassword: $($rec.RecoveryPassword)",
                          "KeyProtectorId: $($rec.KeyProtectorId)") | Set-Content -Path $f -Encoding UTF8
                        return "Recovery gespeichert in: $f"
                    }
                    return 'Gestartet'
                })
                $bgHandle = $bgPs.BeginInvoke()
                $script:_bgPs     = $bgPs
                $script:_bgHandle = $bgHandle
                $script:_bgRs     = $rs
                $script:_bgMount  = $mountPt

                $jobPoll = New-Object System.Windows.Forms.Timer
                $jobPoll.Interval = 1500
                $jobPoll.Add_Tick({
                    if (-not $script:_bgHandle.IsCompleted) {
                        $lblStatus.Text = "ENCRYPTING $($script:_bgMount)  //  " + (Get-Date -Format 'HH:mm:ss')
                        return
                    }
                    $jobPoll.Stop()
                    try {
                        $out = $script:_bgPs.EndInvoke($script:_bgHandle)
                        if ($script:_bgPs.HadErrors) {
                            $err = ($script:_bgPs.Streams.Error | Select-Object -First 1).ToString()
                            $lblStatus.Text = "ERROR  //  $err"
                            [System.Windows.Forms.MessageBox]::Show($err, 'ENIGMA  -  ERROR', 'OK', 'Error') | Out-Null
                        } else {
                            $txtOutput.Text = ">> VERSCHLUESSELUNG GESTARTET: $($script:_bgMount)`r`n$out`r`n`r`n" + (& $fnGetProgressText)
                            $lblStatus.Text = "ENCRYPT STARTED  //  " + (Get-Date -Format 'HH:mm:ss')
                            $progressTimer.Start()
                        }
                    } catch {
                        $lblStatus.Text = 'ERROR  //  ' + $_.Exception.Message
                    } finally {
                        $script:_bgRs.Dispose()
                        $script:_bgPs.Dispose()
                    }
                    $jobPoll.Dispose()
                }.GetNewClosure())
                $jobPoll.Start()
                $lblStatus.Text = "STARTING ENCRYPT  $mountPt  //  BITTE WARTEN..."
                $progressTimer.Stop()

            } elseif ($selectedAction -eq 'unlock') {
                if ([string]::IsNullOrWhiteSpace($selectedDrive)) { throw 'Bitte zuerst ein Laufwerk auswaehlen.' }
                $pw = Show-PasswordDialog -Headline 'Entsperren' -DriveLabel $selectedDrive
                if ($null -eq $pw) { $lblStatus.Text = 'ABGEBROCHEN'; return }
                Unlock-BitLocker -MountPoint ($selectedDrive + ':') -Password $pw
                $txtOutput.Text = ">> ENTSPERRT: $selectedDrive`r`n`r`n" + (& $fnGetStatusText)
                $lblStatus.Text = "UNLOCKED  $selectedDrive  //  " + (Get-Date -Format 'HH:mm:ss')

            } else {
                $progressTimer.Stop()
                & $fnInvokeAction -RequestedAction $selectedAction -RequestedDriveLetter $selectedDrive
                $txtOutput.Text = ">> OPERATION COMPLETE: $($selectedAction.ToUpper()) [$selectedDrive]`r`n`r`n" + (& $fnGetStatusText)
                $lblStatus.Text = "DONE: $($selectedAction.ToUpper())  $selectedDrive  //  " + (Get-Date -Format 'HH:mm:ss')
            }
        }
        catch {
            $lblStatus.Text = 'ERROR  //  ' + $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'ENIGMA  -  ERROR', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    # ── Zusammenbauen ─────────────────────────────────────────────────────
    $form.Controls.AddRange(@(
        $pnlHeader,
        $sep1,
        $pnlCtrl,
        $sep2,
        $txtOutput,
        $pnlStatus
    ))

    & $refreshDrives
    $txtOutput.Text = & $fnGetProgressText
    [void]$form.ShowDialog()
    $progressTimer.Dispose()
    $clockTimer.Dispose()
}

Assert-Admin

if ($Gui) {
    Start-Gui
    return
}

if ([string]::IsNullOrWhiteSpace($Action)) {
    Start-InteractiveMenu
    return
}

Invoke-RequestedAction -RequestedAction $Action -RequestedDriveLetter $DriveLetter
