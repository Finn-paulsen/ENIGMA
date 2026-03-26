# ENIGMA v2.5

**Cross-Platform Enterprise Encryption Manager**

Ein professionelles, sicheres Laufwerk-Verschluesselungsprogramm basierend auf bewährter, auditierter Kryptografie:
- **Windows**: BitLocker (XTS-AES-256)
- **Linux**: LUKS2 (AES-256)

## Features

### Core Functionality
✓ Encryption-Status anzeigen  
✓ Laufwerke verschluesseln (vollautomatisch)  
✓ Volumes entsperren/sperren  
✓ Entschluesselung starten  
✓ Recovery-Keys automatisch exportiert  
✓ Audit-Logging aller Operationen  

### Security
✓ Starke Passwort-Zwangsvalidierung (12+ Zeichen, mixed case, numbers, symbols)  
✓ XTS-AES-256 Verschluesselung (militärischer Standard)  
✓ Automatische Fehlerbehandlung  
✓ Sichere Passwort-Eingabe (masked)  
✓ Bestätigungen vor kritischen Operationen  

### User Experience
✓ Moderne Terminal-UI mit Rich-Library  
✓ Progress-Anzeigen für lange Operationen  
✓ farbcodierte Status-Messages  
✓ Plattformübergreifend (Windows/Linux)  
✓ Automatische Abhängigkeits-Installation

## Voraussetzungen

### Windows
- Windows 10/11 Pro, Enterprise oder Education (BitLocker verfügbar)
- PowerShell 5.1+ oder PowerShell 7+
- Administratorrechte

### Linux
- Any Linux distribution (Ubuntu, Fedora, Arch, etc.)
- Python 3.8+
- `sudo` Zugriff
- cryptsetup wird **automatisch installiert** wenn nicht vorhanden

### Alle Plattformen
- Python 3.8+
- Internet-Verbindung beim ersten Start (zum Installieren von Abhängigkeiten)

## Schnellstart

### Installation
```bash
cd /path/to/ENIGMA

# Windows PowerShell (Admin)
python enigma.py

# Linux (sudo für Verschlüsselung notwendig)
sudo python3 enigma.py
```

### Erste Schritte

1. **Programm starten**
   ```bash
   sudo python3 enigma.py  # Linux
   python enigma.py         # Windows
   ```

2. **Hauptmenü wird angezeigt**
   - Status anzeigen
   - Laufwerk verschlüsseln
   - Volume entsperren/sperren
   - Entschlüsselung starten
   - Audit-Log ansehen

3. **Laufwerk wählen** und Aktion ausführen
   - Passwort-Validierung (mindestens 12 Zeichen mit Uppercase, Lowercase, Zahlen, Sonderzeichen)
   - Bestätigung vor kritischen Operationen
   - Progress-Anzeige bei langen Operationen

### Beispiele

**Windows - BitLocker:**
```
1. Menü starten
2. "Encrypt Drive" wählen
3. Laufwerk und Passwort eingeben
4. BitLocker Verschlüsselung startet
```

**Linux - LUKS:**
```
1. Menü starten (mit sudo!)
2. "Encrypt Drive" wählen
3. Gerät (/dev/sdX), Name und Passwort eingeben
4. LUKS2 Container wird erstellt und gemountet
```

## Sicherheits-Features

### Passwort-Validierung
- **Minimum**: 12 Zeichen
- **Erforderlich**: Uppercase + Lowercase + Zahlen + Sonderzeichen
- **Wiederholung**: Passwort muss bestätigt werden
- **Maskiert**: Eingabe wird nicht sichtbar gemacht

### Verschlüsselung
- **Windows**: XTS-AES-256 (BitLocker Industry Standard)
- **Linux**: LUKS2 mit AES-256 (Open Source Standard)
- Beide verwenden militärische Verschlüsselungsstandards

### Sicherheits-Checks
✓ Root/Admin-Privilegien erzwungen  
✓ Bestätigungen vor kritischen Operationen  
✓ Audit-Logging aller Aktionen (`enigma_audit.log`)  
✓ Keine Passwörter in Log-Dateien  
✓ Automatische Fehlerbehandlung

### Best Practices

- **Starkes Passwort**: Verwende ein zufälliges 16+ Zeichen Passwort
- **Backups**: Sichere Recovery-Keys offline
- **TPM**: Windows nutzt TPM automatisch für C: Laufwerk
- **Regelmäßige Updates**: System und enigma aktuell halten

## Wichtiger Hinweis

Absolute Sicherheit existiert nicht. Praktische Sicherheit erreicht man durch:
- ✓ Bewährte, auditierte Verschlüsselungsalgorithmen
- ✓ Starke Passwörter und sicheres Schlüsselmanagement
- ✓ Regelmäßige Backups und Offline-Storage von Recovery-Keys
- ✓ Aktuelles Patching des gesamten Systems