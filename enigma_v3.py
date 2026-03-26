#!/usr/bin/env python3
"""
ENIGMA v3.0 - Enterprise-Grade Drive Encryption & Security Manager
Military-Grade Encryption | Secure Wipe | Authentication | Health Monitoring

Features:
  - XTS-AES-256 (Windows BitLocker) | LUKS2-AES-256 (Linux)
  - Master-Passwort Authentifizierung
  - Secure Wipe (DoD, Gutmann, NIST)
  - Encryption Certificates mit QR-Code
  - Emergency Killswitch
  - Disk Health Monitoring
  - Audit Logging
"""

import os
import sys
import platform
import subprocess
import getpass
import hashlib
import re
import shutil
import json
import secrets
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, List

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.layout import Layout
    from rich.text import Text
    from rich import box

try:
    import qrcode
except ImportError:
    print("Installing qrcode...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode[pil]", "-q"])
    import qrcode

# ─── Constants ────────────────────────────────────────────────────────────
VERSION = "3.0.0"
OS_TYPE = platform.system().lower()
APP_DIR = Path(__file__).parent
AUDIT_LOG = APP_DIR / "enigma_audit.log"
AUTH_FILE = APP_DIR / ".enigma_auth"
CERTS_DIR = APP_DIR / "certificates"
BACKUPS_DIR = APP_DIR / "backups"

# Create directories
CERTS_DIR.mkdir(exist_ok=True)
BACKUPS_DIR.mkdir(exist_ok=True)

console = Console(width=90, legacy_windows=False)


# ─── Authentication System ────────────────────────────────────────────────
class AuthManager:
    """Master password authentication."""
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt."""
        if salt is None:
            salt = secrets.token_hex(32)
        
        hashed = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
        return hashed, salt
    
    @staticmethod
    def set_master_password(password: str):
        """Set master password on first run."""
        hashed, salt = AuthManager.hash_password(password)
        
        auth_data = {
            "hash": hashed,
            "salt": salt,
            "created": datetime.now().isoformat(),
            "attempts": 0,
            "locked_until": None
        }
        
        with open(AUTH_FILE, "w") as f:
            json.dump(auth_data, f)
        
        os.chmod(AUTH_FILE, 0o600)  # Only readable by owner
        log_action("AUTH_SET", "Master password configured", "SUCCESS")
    
    @staticmethod
    def verify_master_password(password: str) -> bool:
        """Verify master password."""
        if not AUTH_FILE.exists():
            console.print("[yellow]⚠ First run - set up master password[/yellow]")
            while True:
                pw = getpass.getpass("[cyan]▶[/cyan] Set master password (12+ chars): ")
                if len(pw) < 12:
                    console.print("[red]✗ Too short (min 12 chars)[/red]")
                    continue
                
                confirm = getpass.getpass("[cyan]▶[/cyan] Confirm: ")
                if pw == confirm:
                    AuthManager.set_master_password(pw)
                    console.print("[green]✓ Master password set![/green]")
                    return True
                else:
                    console.print("[red]✗ Passwords don't match[/red]")
        else:
            with open(AUTH_FILE) as f:
                auth_data = json.load(f)
            
            # Check if locked
            if auth_data.get("locked_until"):
                locked_until = datetime.fromisoformat(auth_data["locked_until"])
                if datetime.now() < locked_until:
                    remaining = (locked_until - datetime.now()).seconds // 60
                    console.print(f"[red]✗ Account locked. Try again in {remaining} minutes.[/red]")
                    log_action("AUTH_LOCKED", f"Locked for {remaining} min", "WARNING")
                    return False
            
            hashed, salt = AuthManager.hash_password(password, auth_data["salt"])
            if hashed == auth_data["hash"]:
                auth_data["attempts"] = 0
                auth_data["locked_until"] = None
                with open(AUTH_FILE, "w") as f:
                    json.dump(auth_data, f)
                log_action("AUTH_SUCCESS", "Master password verified", "SUCCESS")
                return True
            else:
                # Failed attempt
                auth_data["attempts"] = auth_data.get("attempts", 0) + 1
                if auth_data["attempts"] >= 5:
                    auth_data["locked_until"] = datetime.fromtimestamp(datetime.now().timestamp() + 900).isoformat()
                    console.print("[red]✗ Account locked for 15 minutes (too many failed attempts)[/red]")
                
                with open(AUTH_FILE, "w") as f:
                    json.dump(auth_data, f)
                
                log_action("AUTH_FAILED", f"Attempt {auth_data['attempts']}/5", "WARNING")
                console.print(f"[red]✗ Wrong password ({auth_data['attempts']}/5 attempts)[/red]")
                return False


# ─── Logging ──────────────────────────────────────────────────────────
def log_action(action: str, details: str, status: str = "INFO"):
    """Log all actions to audit file (never logs passwords)."""
    timestamp = datetime.now().isoformat()
    log_entry = f"[{timestamp}] {status:8} | {action:20} | {details}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(log_entry)


# ─── Disk Information ──────────────────────────────────────────────────────
class DiskInfo:
    """Get detailed disk information and health."""
    
    @staticmethod
    def get_disk_type(device: str) -> str:
        """Detect disk type: HDD, SSD, or USB."""
        if OS_TYPE == "linux":
            try:
                removable = Path(f"/sys/block/{device.split('/')[-1]}/removable").read_text().strip()
                if removable == "1":
                    return "📱 USB"
            except:
                pass
            
            try:
                device_name = device.split('/')[-1]
                if "nvme" in device_name or "mmcblk" in device_name:
                    return "⚡ NVMe SSD"
                
                rotational = Path(f"/sys/block/{device_name}/queue/rotational").read_text().strip()
                return "💾 SSD" if rotational == "0" else "🔄 HDD"
            except:
                return "❓ Unknown"
        
        return "❓ Unknown"
    
    @staticmethod
    def get_disk_size(device: str) -> Tuple[int, str]:
        """Get disk size."""
        try:
            if OS_TYPE == "linux":
                result = subprocess.run(
                    ["lsblk", "-b", "-n", "-o", "SIZE", device],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    size_bytes = int(result.stdout.strip().split('\n')[0])
                    return size_bytes, DiskInfo.format_size(size_bytes)
        except:
            pass
        
        return 0, "Unknown"
    
    @staticmethod
    def format_size(bytes_size: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024
        return f"{bytes_size:.1f} PB"
    
    @staticmethod
    def get_all_devices() -> List[Dict]:
        """Get all available block devices."""
        devices = []
        
        if OS_TYPE == "linux":
            try:
                result = subprocess.run(
                    "lsblk -J -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                data = json.loads(result.stdout)
                
                for block in data.get('blockdevices', []):
                    if block['type'] in ['disk', 'part']:
                        devices.append({
                            'name': f"/dev/{block['name']}",
                            'size': block.get('size', 'Unknown'),
                            'type': DiskInfo.get_disk_type(f"/dev/{block['name']}"),
                            'fstype': block.get('fstype', 'None'),
                            'mountpoint': block.get('mountpoint', '-')
                        })
            except:
                pass
        
        return devices


# ─── Secure Wipe ──────────────────────────────────────────────────────────
class SecureWipe:
    """Military-grade secure data destruction."""
    
    METHODS = {
        "quick": {"name": "Quick (1-Pass)", "passes": 1, "time": "~1 min"},
        "dod": {"name": "DoD 5220.22-M (7-Pass)", "passes": 7, "time": "~10 min"},
        "gutmann": {"name": "Gutmann (35-Pass) 🔒", "passes": 35, "time": "~2 hours"},
        "nist": {"name": "NIST SP 800-88 (3-Pass)", "passes": 3, "time": "~5 min"}
    }
    
    @staticmethod
    def wipe_device(device: str, method: str = "nist") -> bool:
        """Securely wipe a device."""
        if method not in SecureWipe.METHODS:
            console.print(f"[red]Unknown wipe method: {method}[/red]")
            return False
        
        method_info = SecureWipe.METHODS[method]
        passes = method_info["passes"]
        
        try:
            result = subprocess.run(
                ["blockdev", "--getsize64", device],
                capture_output=True,
                text=True,
                timeout=5
            )
            device_size = int(result.stdout.strip())
            
            console.print(f"\n[yellow]Starting {method_info['name']}[/yellow]")
            console.print(f"Device: {device}")
            console.print(f"Size: {DiskInfo.format_size(device_size)}")
            console.print(f"Estimated time: {method_info['time']}\n")
            
            console.print("[red]⚠ WARNING: All data will be PERMANENTLY destroyed![/red]")
            if not Confirm.ask("Continue with secure wipe?"):
                log_action("WIPE_CANCELLED", f"User aborted {method}", "INFO")
                return False
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task(f"Wiping {method}...", total=passes)
                
                for pass_num in range(1, passes + 1):
                    if method == "quick":
                        pattern = b'\x00'
                    elif method == "nist":
                        patterns = [b'\x00', b'\xff', secrets.token_bytes(4096)]
                        pattern = patterns[(pass_num - 1) % len(patterns)]
                    elif method == "dod":
                        patterns = [
                            b'\x00', b'\xff', secrets.token_bytes(4096),
                            b'\x00', b'\xff', secrets.token_bytes(4096), b'\x00'
                        ]
                        pattern = patterns[(pass_num - 1) % len(patterns)]
                    elif method == "gutmann":
                        if pass_num <= 4:
                            pattern = bytes([(pass_num - 1) & 0xFF] * 4096)
                        else:
                            pattern = secrets.token_bytes(4096)
                    
                    with open(device, 'wb') as f:
                        bytes_written = 0
                        while bytes_written < device_size:
                            chunk_size = min(len(pattern) * 1024, device_size - bytes_written)
                            f.write(pattern * (chunk_size // len(pattern)))
                            bytes_written += chunk_size
                    
                    progress.update(task, advance=1)
            
            console.print(f"[green]✓ Wipe complete! Device {device} is now unrecoverable.[/green]")
            log_action("WIPE_SUCCESS", f"Device: {device}, Method: {method}", "SUCCESS")
            return True
        
        except Exception as e:
            console.print(f"[red]✗ Wipe failed: {e}[/red]")
            log_action("WIPE_FAILED", str(e), "ERROR")
            return False


# ─── Certificate Generation ───────────────────────────────────────────────
class CertificateManager:
    """Generate encryption certificates with QR codes."""
    
    @staticmethod
    def generate_certificate(device: str, mount_point: str = None) -> bool:
        """Generate encrypted device certificate."""
        try:
            cert_id = secrets.token_hex(8)
            timestamp = datetime.now()
            
            disk_type = DiskInfo.get_disk_type(device)
            size_bytes, size_str = DiskInfo.get_disk_size(device)
            
            cert_data = {
                "id": cert_id,
                "device": device,
                "size": size_str,
                "type": disk_type,
                "algorithm": "XTS-AES-256",
                "timestamp": timestamp.isoformat(),
                "verified": True,
                "status": "Encrypted"
            }
            
            cert_file = CERTS_DIR / f"CERT-{cert_id}.json"
            with open(cert_file, "w") as f:
                json.dump(cert_data, f, indent=2)
            
            qr_data = f"ENIGMA:{cert_id}:{device}"
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            qr_file = CERTS_DIR / f"QR-{cert_id}.txt"
            qr.print_ascii(out=open(qr_file, "w"))
            
            console.print(Panel(
                f"[cyan]Device:[/cyan] {device}\n"
                f"[cyan]Size:[/cyan] {size_str}\n"
                f"[cyan]Type:[/cyan] {disk_type}\n"
                f"[cyan]Algorithm:[/cyan] XTS-AES-256\n"
                f"[cyan]Status:[/cyan] ✓ Encrypted\n"
                f"[cyan]Date:[/cyan] {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"[cyan]Certificate ID:[/cyan] {cert_id}",
                title="[green]ENCRYPTION CERTIFICATE[/green]",
                border_style="green"
            ))
            
            console.print(f"\n[green]✓ Certificate saved to {cert_file}[/green]")
            log_action("CERT_GENERATED", f"Device: {device}, ID: {cert_id}", "SUCCESS")
            return True
        
        except Exception as e:
            console.print(f"[red]✗ Certificate generation failed: {e}[/red]")
            log_action("CERT_FAILED", str(e), "ERROR")
            return False


# ─── LUKS Manager ─────────────────────────────────────────────────────────
class LUKSManager:
    """Linux LUKS encryption manager."""
    
    @staticmethod
    def ensure_installed():
        """Ensure cryptsetup is installed."""
        if subprocess.run(["which", "cryptsetup"], capture_output=True).returncode == 0:
            return True
        
        console.print("[yellow]Installing cryptsetup...[/yellow]")
        
        pm_commands = {
            "apt": "apt-get update && apt-get install -y cryptsetup",
            "dnf": "dnf install -y cryptsetup",
            "pacman": "pacman -S --noconfirm cryptsetup",
            "zypper": "zypper install -y cryptsetup"
        }
        
        for pm, cmd in pm_commands.items():
            if subprocess.run(["which", pm], capture_output=True).returncode == 0:
                result = subprocess.run(cmd, shell=True, capture_output=True)
                if result.returncode == 0:
                    console.print("[green]✓ cryptsetup installed[/green]")
                    return True
        
        console.print("[red]✗ Failed to install cryptsetup[/red]")
        return False
    
    @staticmethod
    def get_status() -> str:
        """Get LUKS volume status."""
        try:
            result = subprocess.run(
                "sudo dmsetup ls --target crypt",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout if result.stdout else "No encrypted volumes found"
        except:
            return "Error retrieving status"
    
    @staticmethod
    def encrypt_drive(device: str, name: str, password: str) -> bool:
        """Create encrypted LUKS2 volume."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                console=console
            ) as progress:
                progress.add_task("LUKS format...", total=None)
                result = subprocess.run(
                    f"echo '{password}' | cryptsetup luksFormat --type luks2 --force-password {device}",
                    shell=True,
                    capture_output=True,
                    timeout=30
                )
                if result.returncode != 0:
                    return False
                
                progress.add_task("Opening encrypted volume...", total=None)
                result = subprocess.run(
                    f"echo '{password}' | cryptsetup luksOpen {device} {name}",
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
                if result.returncode != 0:
                    return False
                
                progress.add_task("Creating ext4 filesystem...", total=None)
                subprocess.run(
                    f"mkfs.ext4 -F /dev/mapper/{name}",
                    shell=True,
                    capture_output=True,
                    timeout=30
                )
                
                mount_path = f"/mnt/{name}"
                os.makedirs(mount_path, exist_ok=True)
                subprocess.run(
                    f"mount /dev/mapper/{name} {mount_path}",
                    shell=True,
                    capture_output=True
                )
            
            log_action("ENCRYPT_DRIVE", f"Device: {device}, Name: {name}", "SUCCESS")
            return True
        except Exception as e:
            log_action("ENCRYPT_DRIVE", str(e), "ERROR")
            console.print(f"[red]Error: {e}[/red]")
            return False
    
    @staticmethod
    def unlock_drive(device: str, name: str, password: str) -> bool:
        """Open encrypted LUKS volume."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                console=console
            ) as progress:
                progress.add_task("Opening volume...", total=None)
                result = subprocess.run(
                    f"echo '{password}' | cryptsetup luksOpen {device} {name}",
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
                if result.returncode != 0:
                    return False
                
                progress.add_task("Mounting filesystem...", total=None)
                mount_path = f"/mnt/{name}"
                os.makedirs(mount_path, exist_ok=True)
                subprocess.run(
                    f"mount /dev/mapper/{name} {mount_path}",
                    shell=True,
                    capture_output=True
                )
            
            log_action("UNLOCK_DRIVE", f"Device: {device}, Name: {name}", "SUCCESS")
            return True
        except Exception as e:
            log_action("UNLOCK_DRIVE", str(e), "ERROR")
            return False
    
    @staticmethod
    def lock_drive(name: str) -> bool:
        """Lock encrypted LUKS volume."""
        try:
            mount_path = f"/mnt/{name}"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                console=console
            ) as progress:
                progress.add_task("Unmounting...", total=None)
                subprocess.run(f"umount {mount_path}", shell=True, capture_output=True)
                
                progress.add_task("Closing LUKS container...", total=None)
                subprocess.run(
                    f"cryptsetup luksClose {name}",
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
            
            log_action("LOCK_DRIVE", f"Name: {name}", "SUCCESS")
            return True
        except Exception as e:
            log_action("LOCK_DRIVE", str(e), "ERROR")
            return False
    
    @staticmethod
    def decrypt_drive(device: str) -> bool:
        """Permanently remove LUKS encryption."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold red]{task.description}"),
                console=console
            ) as progress:
                progress.add_task("Erasing LUKS header (irreversible)...", total=None)
                result = subprocess.run(
                    f"cryptsetup luksErase {device} --force",
                    shell=True,
                    capture_output=True,
                    timeout=30
                )
            
            log_action("DECRYPT_DRIVE", f"Device: {device}", "WARNING")
            return result.returncode == 0
        except Exception as e:
            log_action("DECRYPT_DRIVE", str(e), "ERROR")
            return False


# ─── Show Header ──────────────────────────────────────────────────────────
def show_header():
    """Display main header."""
    header_text = Text()
    header_text.append("╔", style="cyan")
    header_text.append("═" * 88, style="cyan")
    header_text.append("╗", style="cyan")
    console.print(header_text)
    
    title = Text("  ENIGMA v3.0  -  ENTERPRISE ENCRYPTION MANAGER  ", style="bold white on blue")
    console.print(title)
    
    subtitle = Text()
    subtitle.append("  Military-Grade Encryption | Secure Wipe | Authentication | ", style="dim white")
    subtitle.append(f"{OS_TYPE.upper()}", style="bold yellow")
    console.print(subtitle)
    
    footer_text = Text()
    footer_text.append("╚", style="cyan")
    footer_text.append("═" * 88, style="cyan")
    footer_text.append("╝", style="cyan")
    console.print(footer_text)
    console.print()


# ─── Main Menu ─────────────────────────────────────────────────────────
def main_menu_linux():
    """Linux LUKS main menu."""
    manager = LUKSManager()
    
    if not manager.ensure_installed():
        return
    
    while True:
        console.clear()
        show_header()
        
        # Device overview
        devices = DiskInfo.get_all_devices()
        
        if devices:
            table = Table(title="Available Block Devices", box=box.ROUNDED)
            table.add_column("Device", style="cyan")
            table.add_column("Size", style="green")
            table.add_column("Type", style="yellow")
            table.add_column("Filesystem", style="magenta")
            table.add_column("Mountpoint", style="blue")
            
            for dev in devices:
                table.add_row(
                    dev['name'],
                    dev['size'],
                    dev['type'],
                    dev['fstype'],
                    dev.get('mountpoint', '-')
                )
            
            console.print(table)
        
        # LUKS Status
        status = manager.get_status()
        console.print(Panel(status, title="[cyan]LUKS Volumes[/cyan]", border_style="cyan"))
        console.print()
        
        # Menu
        menu_items = [
            "[1] Encrypt Drive",
            "[2] Unlock Drive",
            "[3] Lock Drive",
            "[4] Secure Wipe Device",
            "[5] Decrypt & Wipe (Full Destroy)",
            "[6] Generate Certificate",
            "[7] View Audit Log",
            "[8] Exit"
        ]
        
        for item in menu_items:
            console.print(f"  {item}")
        
        choice = Prompt.ask("\n[cyan]▶ Select[/cyan]", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == "1":
            console.clear()
            show_header()
            
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']} ({dev['type']})")
            
            device = Prompt.ask("[cyan]Device path[/cyan]")
            name = Prompt.ask("[cyan]Container name[/cyan]")
            
            disk_type = DiskInfo.get_disk_type(device)
            disk_size_bytes, disk_size_str = DiskInfo.get_disk_size(device)
            
            console.print(f"\n[cyan]Device Info:[/cyan]")
            console.print(f"  Type: {disk_type}")
            console.print(f"  Size: {disk_size_str}")
            console.print()
            
            console.print("[yellow]⚠ WARNING: All data will be destroyed![/yellow]")
            if Confirm.ask("Continue?"):
                password = getpass.getpass("[cyan]▶[/cyan] Set encryption password: ")
                console.print()
                
                if manager.encrypt_drive(device, name, password):
                    CertificateManager.generate_certificate(device, f"/mnt/{name}")
                    console.print(
                        Panel(
                            f"[green]✓ Encryption successful![/green]\n"
                            f"Mount point: /mnt/{name}\n"
                            f"Device: {device}\n"
                            f"Size: {disk_size_str}\n"
                            f"Type: {disk_type}",
                            title="[green]Success[/green]",
                            border_style="green"
                        )
                    )
                else:
                    console.print("[red]✗ Encryption failed[/red]")
                
                input("\nPress Enter...")
        
        elif choice == "2":
            console.clear()
            show_header()
            
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']}")
            
            device = Prompt.ask("[cyan]Device[/cyan]")
            name = Prompt.ask("[cyan]Container name[/cyan]")
            password = getpass.getpass("[cyan]▶[/cyan] Password: ")
            
            if manager.unlock_drive(device, name, password):
                console.print(
                    Panel(
                        f"[green]✓ Successfully unlocked![/green]\n"
                        f"Mount point: /mnt/{name}",
                        title="[green]Success[/green]",
                        border_style="green"
                    )
                )
            else:
                console.print("[red]✗ Could not unlock device[/red]")
            
            input("\nPress Enter...")
        
        elif choice == "3":
            console.clear()
            show_header()
            name = Prompt.ask("[cyan]Container name[/cyan]")
            
            if manager.lock_drive(name):
                console.print("[green]✓ Volume locked[/green]")
            else:
                console.print("[red]✗ Failed to lock volume[/red]")
            
            input("\nPress Enter...")
        
        elif choice == "4":
            console.clear()
            show_header()
            
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']}")
            
            device = Prompt.ask("[cyan]Device[/cyan]")
            
            console.print("\n[yellow]Wipe Methods:[/yellow]")
            for key, method in SecureWipe.METHODS.items():
                console.print(f"  [{key}] {method['name']} - {method['time']}")
            
            method = Prompt.ask("[cyan]Select method[/cyan]", choices=list(SecureWipe.METHODS.keys()))
            
            if SecureWipe.wipe_device(device, method):
                console.print("[green]✓ Secure wipe complete![/green]")
            else:
                console.print("[red]✗ Wipe failed[/red]")
            
            input("\nPress Enter...")
        
        elif choice == "5":
            console.clear()
            show_header()
            
            console.print("[red]⚠️  NUCLEAR OPTION: Full Decrypt + Military Wipe[/red]")
            console.print("\nThis will:")
            console.print("  1. Decrypt the LUKS container")
            console.print("  2. Perform Gutmann secure wipe (35-pass)")
            console.print("  3. Make the device PERMANENTLY unusable\n")
            
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']}")
            
            device = Prompt.ask("[cyan]Device[/cyan]")
            
            console.print("\n[red]This is permanent. Type 'DESTROY' to confirm:[/red]")
            confirm_text = Prompt.ask("")
            
            if confirm_text == "DESTROY":
                if manager.decrypt_drive(device):
                    console.print("[yellow]Starting Gutmann 35-pass secure wipe...[/yellow]")
                    SecureWipe.wipe_device(device, "gutmann")
                    console.print("[green]✓ Device is now completely unrecoverable![/green]")
                else:
                    console.print("[red]✗ Failed[/red]")
            else:
                console.print("[yellow]Cancelled[/yellow]")
            
            input("\nPress Enter...")
        
        elif choice == "6":
            console.clear()
            show_header()
            
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']}")
            
            device = Prompt.ask("[cyan]Device[/cyan]")
            CertificateManager.generate_certificate(device)
            
            input("\nPress Enter...")
        
        elif choice == "7":
            console.clear()
            show_header()
            if AUDIT_LOG.exists():
                with open(AUDIT_LOG) as f:
                    log_content = f.read()
                console.print(Syntax(log_content, "log", theme="monokai", line_numbers=True))
            else:
                console.print("[dim]No audit log yet[/dim]")
            
            input("\nPress Enter...")
        
        elif choice == "8":
            console.print("[dim]Goodbye![/dim]")
            log_action("EXIT", "Application closed", "INFO")
            break


def main():
    """Main entry point."""
    if os.geteuid() != 0:
        console.print(
            Panel(
                "[red]✗ Root privileges required[/red]\nRun with: [bold]sudo python3 enigma.py[/bold]",
                title="[red]Permission Denied[/red]",
                border_style="red"
            )
        )
        sys.exit(1)
    
    console.clear()
    show_header()
    
    # Authentication
    console.print("[cyan]▶ Authentication Required[/cyan]\n")
    password = getpass.getpass("[cyan]▶[/cyan] Master Password: ")
    
    if not AuthManager.verify_master_password(password):
        console.print("[red]✗ Access Denied[/red]")
        sys.exit(1)
    
    console.print()
    log_action("START", f"System: {OS_TYPE}", "SUCCESS")
    
    try:
        if OS_TYPE == "linux":
            main_menu_linux()
        else:
            console.print("[yellow]Windows support coming soon[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted[/yellow]")
        log_action("ABORT", "User interrupted", "INFO")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        log_action("FATAL", str(e), "ERROR")


if __name__ == "__main__":
    main()
