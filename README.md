# ENIGMA

Ein sicheres Laufwerk-Verschluesselungsprogramm solltest du **nicht** mit einer selbst erfundenen Kryptografie bauen.
Dieses Projekt nutzt deshalb bewaehrte, auditierte Kryptografie ueber Windows BitLocker (XTS-AES-256) und stellt eine eigene CLI darueber bereit.

## Features

- Verschluesselungsstatus von Laufwerken anzeigen
- Laufwerke mit BitLocker verschluesseln (`XtsAes256`)
- Laufwerke entsperren und sperren
- Entschluesselung starten
- Recovery-Key lokal in eine Datei exportieren
- Interaktives Menue, wenn kein Parameter angegeben wird
- Optionale GUI (`-Gui`)

## Voraussetzungen

- Windows Pro/Enterprise/Education (BitLocker verfgbar)
- PowerShell 5.1+ oder PowerShell 7+
- Administratorrechte beim Ausfuehren

## Schnellstart

1. PowerShell als Administrator starten.
2. In den Projektordner wechseln.
3. Beispiele ausfuehren:

```powershell
# Variante A: Voller Befehl (klassisch)
.\EnigmaDrive.ps1 -Action status

# Datenlaufwerk L: verschluesseln
.\EnigmaDrive.ps1 -Action encrypt -DriveLetter L -RecoveryKeyOutputDir .\recovery

# Variante B: Kurzform mit Positionsparametern
.\EnigmaDrive.ps1 status
.\EnigmaDrive.ps1 encrypt L

# Variante C: Interaktives Menue (ohne Parameter)
.\EnigmaDrive.ps1

# Variante D: GUI starten
.\EnigmaDrive.ps1 -Gui

# Oder GUI per Doppelklick starten
.\Start-Enigma.cmd

# Weitere Beispiele
.\EnigmaDrive.ps1 -Action encrypt -DriveLetter D -RecoveryKeyOutputDir .\recovery

# Laufwerk D: entsperren
.\EnigmaDrive.ps1 -Action unlock -DriveLetter D

# Laufwerk D: sperren
.\EnigmaDrive.ps1 -Action lock -DriveLetter D

# Entschluesselung starten
.\EnigmaDrive.ps1 -Action decrypt -DriveLetter D
```

## Sicherheits-Hinweise

- Verwende fuer sensible Daten ein **starkes Passwort** und sichere den Recovery-Key offline.
- Erstelle mindestens ein zusaetzliches Backup der Recovery-Datei.
- Fuer Systemlaufwerke (`C:`) nutzt das Skript den TPM-Protector.
- Dieses Projekt ist eine Verwaltungs-CLI fuer BitLocker, kein neuer Kryptografie-Algorithmus.

## Typische Fehler

- Falsch: `EnigmaDrive.ps1 Action status`
- Richtig: `.\EnigmaDrive.ps1 -Action status`
- In PowerShell muss aus dem aktuellen Ordner mit `.\` aufgerufen werden.

## Wichtiger Hinweis

Absolute Sicherheit gibt es nicht. Praktisch erreichst du hohe Sicherheit durch:

- bewaehrte Algorithmen
- sauberes Schluesselmanagement
- sichere Backups
- aktuelles System-Patching