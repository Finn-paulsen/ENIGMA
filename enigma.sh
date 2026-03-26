#!/bin/bash

# ENIGMA - Cross-Platform Drive Encryption Manager
# Automatische Erkennung: Windows (BitLocker) oder Linux (LUKS)

set -euo pipefail

# ─── Farbcodes ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── OS-Erkennung ────────────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        MINGW64_NT*|MINGW32_NT*|MSYS_NT*)
            echo "windows"
            ;;
        Linux*)
            echo "linux"
            ;;
        Darwin*)
            echo "macos"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

OS=$(detect_os)

show_header() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║          ENIGMA - SECURE DRIVE ENCRYPTION MANAGER              ║"
    echo "║                   Erkanntes System: ${OS^^}                        ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── WINDOWS: BitLocker Menu ──────────────────────────────────────────────
run_windows() {
    # Prüfe ob PowerShell verfügbar ist
    if ! command -v pwsh &> /dev/null && ! command -v powershell &> /dev/null; then
        echo -e "${RED}[ERROR] PowerShell nicht gefunden. Bitte PowerShell installieren.${NC}"
        exit 1
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PS_SCRIPT="$SCRIPT_DIR/EnigmaDrive.ps1"

    if [ ! -f "$PS_SCRIPT" ]; then
        echo -e "${RED}[ERROR] EnigmaDrive.ps1 nicht gefunden in: $SCRIPT_DIR${NC}"
        exit 1
    fi

    # PowerShell ausführen
    pwsh -NoProfile -ExecutionPolicy Bypass -File "$PS_SCRIPT" -Gui
}

# ─── Automatische Installation von cryptsetup ────────────────────────────
ensure_cryptsetup_installed() {
    if command -v cryptsetup &> /dev/null; then
        return 0  # Bereits installiert
    fi
    
    echo -e "${YELLOW}[INFO] cryptsetup ist nicht installiert.${NC}"
    echo "Installiere automatisch..."
    echo ""
    
    # Erkenne Paketmanager
    if command -v apt-get &> /dev/null; then
        echo "Erkannt: Debian/Ubuntu (apt)"
        sudo apt-get update
        sudo apt-get install -y cryptsetup
    elif command -v dnf &> /dev/null; then
        echo "Erkannt: Fedora/RHEL (dnf)"
        sudo dnf install -y cryptsetup
    elif command -v pacman &> /dev/null; then
        echo "Erkannt: Arch Linux (pacman)"
        sudo pacman -S --noconfirm cryptsetup
    elif command -v zypper &> /dev/null; then
        echo "Erkannt: openSUSE (zypper)"
        sudo zypper install -y cryptsetup
    else
        echo -e "${RED}[ERROR] Paketmanager nicht erkannt.${NC}"
        echo "Bitte cryptsetup manuell installieren:"
        echo "  sudo apt-get install cryptsetup       # Debian/Ubuntu"
        echo "  sudo dnf install cryptsetup           # Fedora/RHEL"
        echo "  sudo pacman -S cryptsetup             # Arch"
        echo "  sudo zypper install cryptsetup        # openSUSE"
        exit 1
    fi
    
    if command -v cryptsetup &> /dev/null; then
        echo -e "${GREEN}✓ cryptsetup erfolgreich installiert!${NC}"
        sleep 2
    else
        echo -e "${RED}[ERROR] Installation fehlgeschlagen.${NC}"
        exit 1
    fi
}

# ─── LINUX: LUKS Menu ─────────────────────────────────────────────────────
run_linux() {
    # Stelle sicher, dass cryptsetup installiert ist
    ensure_cryptsetup_installed

    while true; do
        show_header
        echo -e "${BOLD}LUKS-Verschlüsselung (Linux)${NC}"
        echo ""
        echo "1) Status - Alle verschlüsselten Volumes zeigen"
        echo "2) Verschlüsseln - Neues Laufwerk verschlüsseln"
        echo "3) Entsperren - Gesperrtes Volume öffnen"
        echo "4) Sperren - Volume sperren"
        echo "5) Entschlüsseln - Verschlüsselung entfernen"
        echo "6) Beenden"
        echo ""
        read -p "Auswahl (1-6): " choice

        case $choice in
            1) show_luks_status ;;
            2) encrypt_luks_drive ;;
            3) unlock_luks_drive ;;
            4) lock_luks_drive ;;
            5) decrypt_luks_drive ;;
            6) echo -e "${GREEN}Auf Wiedersehen!${NC}"; exit 0 ;;
            *) echo -e "${RED}Ungültige Auswahl${NC}"; sleep 2 ;;
        esac
    done
}

# ─── LUKS Funktionen ──────────────────────────────────────────────────────
show_luks_status() {
    clear
    show_header
    echo -e "${BOLD}Verschlüsselte Volumes:${NC}\n"
    
    if sudo dmsetup ls --target crypt &>/dev/null; then
        sudo dmsetup ls --target crypt
        echo ""
        echo "Details:"
        sudo cryptsetup status --verbose $(sudo dmsetup ls --target crypt | awk '{print $1}') 2>/dev/null || true
    else
        echo "Keine verschlüsselten LUKS-Volumes gefunden."
    fi
    
    echo ""
    read -p "Drücke Enter zum Fortfahren..."
}

encrypt_luks_drive() {
    clear
    show_header
    echo -e "${BOLD}Neues Volume verschlüsseln${NC}\n"
    
    read -p "Geräte eingeben (z.B. /dev/sdb1, /dev/nvme0n1p2): " device
    
    if [ ! -b "$device" ]; then
        echo -e "${RED}[ERROR] Gerät $device existiert nicht.${NC}"
        sleep 2
        return
    fi
    
    # Warnung
    echo -e "${YELLOW}WARNUNG: Alle Daten auf $device werden gelöscht!${NC}"
    read -p "Wirklich fortfahren? (ja/nein): " confirm
    
    if [ "$confirm" != "ja" ]; then
        echo "Abgebrochen."
        sleep 2
        return
    fi
    
    read -p "Name für LUKS-Container eingeben (z.B. encrypted_disk): " name
    read -sp "Passwort eingeben (min. 8 Zeichen): " pw1
    echo ""
    read -sp "Passwort wiederholen: " pw2
    echo ""
    
    if [ "$pw1" != "$pw2" ]; then
        echo -e "${RED}Passwörter stimmen nicht überein!${NC}"
        sleep 2
        return
    fi
    
    if [ ${#pw1} -lt 8 ]; then
        echo -e "${RED}Passwort zu kurz (min. 8 Zeichen)${NC}"
        sleep 2
        return
    fi
    
    echo "Verschlüssele $device..."
    echo "$pw1" | sudo cryptsetup luksFormat --type luks2 "$device" -
    
    echo "Öffne verschlüsseltes Volume..."
    echo "$pw1" | sudo cryptsetup luksOpen "$device" "$name" -
    
    echo "Formatiere mit ext4..."
    sudo mkfs.ext4 "/dev/mapper/$name"
    
    echo "Erstelle Mount-Point..."
    sudo mkdir -p "/mnt/$name"
    sudo mount "/dev/mapper/$name" "/mnt/$name"
    
    echo -e "${GREEN}✓ Volume erfolgreich verschlüsselt und gemountet!${NC}"
    echo "Mount-Punkt: /mnt/$name"
    sleep 3
}

unlock_luks_drive() {
    clear
    show_header
    echo -e "${BOLD}Volume entsperren${NC}\n"
    
    read -p "Geräte eingeben (z.B. /dev/sdb1): " device
    read -p "Name für Mapper eingeben (z.B. encrypted_disk): " name
    read -sp "Passwort eingeben: " pw
    echo ""
    
    echo "$pw" | sudo cryptsetup luksOpen "$device" "$name" -
    
    echo "Mounte Volume..."
    sudo mkdir -p "/mnt/$name"
    sudo mount "/dev/mapper/$name" "/mnt/$name"
    
    echo -e "${GREEN}✓ Volume entsperrt!${NC}"
    echo "Mount-Punkt: /mnt/$name"
    sleep 3
}

lock_luks_drive() {
    clear
    show_header
    echo -e "${BOLD}Volume sperren${NC}\n"
    
    read -p "Name des Mappers eingeben (z.B. encrypted_disk): " name
    
    echo "Unmounte Volume..."
    sudo umount "/mnt/$name" || true
    
    echo "Schließe LUKS-Container..."
    sudo cryptsetup luksClose "$name"
    
    echo -e "${GREEN}✓ Volume gesperrt!${NC}"
    sleep 3
}

decrypt_luks_drive() {
    clear
    show_header
    echo -e "${BOLD}Verschlüsselung entfernen (LUKS löschen)${NC}\n"
    
    read -p "Geräte eingeben (z.B. /dev/sdb1): " device
    
    echo -e "${YELLOW}WARNUNG: LUKS-Header wird gelöscht (Daten unrettbar)!${NC}"
    read -p "Wirklich fortfahren? (ja/nein): " confirm
    
    if [ "$confirm" != "ja" ]; then
        echo "Abgebrochen."
        sleep 2
        return
    fi
    
    echo "Entferne LUKS-Header..."
    sudo cryptsetup luksErase "$device"
    
    echo -e "${GREEN}✓ LUKS-Verschlüsselung entfernt!${NC}"
    sleep 3
}

# ─── macOS: Placeholder ───────────────────────────────────────────────────
run_macos() {
    show_header
    echo -e "${YELLOW}macOS-Unterstützung ist noch nicht implementiert.${NC}"
    echo ""
    echo "Verwende FileVault 2 für Vollverschlüsselung:"
    echo "  sudo fdesetup enable"
    echo ""
    read -p "Drücke Enter zum Beenden..."
    exit 0
}

# ─── Hauptprogramm ────────────────────────────────────────────────────────
main() {
    case "$OS" in
        windows)
            run_windows
            ;;
        linux)
            run_linux
            ;;
        macos)
            run_macos
            ;;
        *)
            echo -e "${RED}[ERROR] Unbekanntes Betriebssystem: $OS${NC}"
            exit 1
            ;;
    esac
}

main "$@"
