#!/usr/bin/env python3
"""
ENIGMA - Enterprise-Grade Cross-Platform Drive Encryption Manager
XTS-AES-256 (Windows BitLocker) | LUKS-AES-256 (Linux)

A beautiful, secure, and professional encryption management tool.
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
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, List

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
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
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.layout import Layout
    from rich.text import Text
    from rich import box

# ─── Constants ────────────────────────────────────────────────────────────
VERSION = "2.5.0"
OS_TYPE = platform.system().lower()
AUDIT_LOG = Path(__file__).parent / "enigma_audit.log"

# ─── Rich Console Setup ───────────────────────────────────────────────────
console = Console(width=90, legacy_windows=False)

# ─── Logging ──────────────────────────────────────────────────────────────
def log_action(action: str, details: str, status: str = "INFO"):
    """Log all actions to audit file."""
    timestamp = datetime.now().isoformat()
    log_entry = f"[{timestamp}] {status:8} | {action:20} | {details}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(log_entry)

# ─── Disk Information ──────────────────────────────────────────────────────
class DiskInfo:
    """Get detailed disk information."""
    
    @staticmethod
    def get_disk_type(device: str) -> str:
        """Detect disk type: HDD, SSD, or USB."""
        if OS_TYPE == "linux":
            # Check if it's a removable device (USB)
            try:
                removable = Path(f"/sys/block/{device.split('/')[-1]}/removable").read_text().strip()
                if removable == "1":
                    return "📱 USB"
            except:
                pass
            
            # Check SSD vs HDD
            try:
                device_name = device.split('/')[-1]
                if "nvme" in device_name or "mmcblk" in device_name:
                    return "⚡ NVMe SSD"
                
                rotational = Path(f"/sys/block/{device_name}/queue/rotational").read_text().strip()
                return "💾 SSD" if rotational == "0" else "🔄 HDD"
            except:
                return "❓ Unknown"
        
        elif OS_TYPE == "windows":
            try:
                disk = device.rstrip(':')
                # Check disk type via WMI
                cmd = f"""
                gwmi Win32_LogicalDisk -Filter "Name='{disk}:'" | 
                select -ExpandProperty Description
                """
                result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                desc = result.stdout.strip().lower()
                
                if "removable" in desc or "usb" in desc:
                    return "📱 USB"
                elif "ssd" in desc or "solid" in desc:
                    return "⚡ SSD"
                else:
                    return "🔄 HDD"
            except:
                return "❓ Unknown"
        
        return "❓ Unknown"
    
    @staticmethod
    def get_disk_size(device: str) -> Tuple[int, str]:
        """Get disk size in bytes and formatted string."""
        try:
            if OS_TYPE == "linux":
                # Try lsblk first
                result = subprocess.run(
                    ["lsblk", "-b", "-n", "-o", "SIZE", device],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    size_bytes = int(result.stdout.strip().split('\n')[0])
                    return size_bytes, DiskInfo.format_size(size_bytes)
            
            elif OS_TYPE == "windows":
                disk = device.rstrip(':')
                cmd = f"""
                gwmi Win32_LogicalDisk -Filter "Name='{disk}:'" | 
                select -ExpandProperty Size
                """
                result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                size_bytes = int(result.stdout.strip())
                return size_bytes, DiskInfo.format_size(size_bytes)
        except:
            pass
        
        return 0, "Unknown"
    
    @staticmethod
    def get_disk_usage(path: str) -> Tuple[int, int, int]:
        """Get disk usage (used, free, total) in bytes."""
        try:
            stat = shutil.disk_usage(path)
            return stat.used, stat.free, stat.total
        except:
            return 0, 0, 0
    
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
                            'type': block['type'],
                            'fstype': block.get('fstype', 'None'),
                            'mountpoint': block.get('mountpoint', '-')
                        })
            except:
                pass
        
        elif OS_TYPE == "windows":
            try:
                cmd = "gwmi Win32_LogicalDisk | select Name,Size,FreeSpace | ConvertTo-Json"
                result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                
                try:
                    data = json.loads(result.stdout)
                    if not isinstance(data, list):
                        data = [data]
                    
                    for disk in data:
                        devices.append({
                            'name': disk['Name'],
                            'size': DiskInfo.format_size(int(disk['Size'])),
                            'type': DiskInfo.get_disk_type(disk['Name']),
                            'fstype': 'NTFS',
                            'free': DiskInfo.format_size(int(disk['FreeSpace']))
                        })
                except:
                    pass
            except:
                pass
        
        return devices

def show_header():
    """Display main header."""
    header_text = Text()
    header_text.append("╔", style="cyan")
    header_text.append("═" * 88, style="cyan")
    header_text.append("╗", style="cyan")
    console.print(header_text)
    
    title = Text("  ENIGMA  -  ENTERPRISE ENCRYPTION MANAGER  ", style="bold white on blue")
    console.print(title)
    
    subtitle = Text()
    subtitle.append("  Secure Drive Management | ", style="dim white")
    subtitle.append(f"{OS_TYPE.upper()}", style="bold yellow")
    subtitle.append(" | ", style="dim white")
    subtitle.append(f"v{VERSION}", style="dim cyan")
    console.print(subtitle)
    
    footer_text = Text()
    footer_text.append("╚", style="cyan")
    footer_text.append("═" * 88, style="cyan")
    footer_text.append("╝", style="cyan")
    console.print(footer_text)
    console.print()


def check_root():
    """Verify root/admin privileges."""
    if os.geteuid() != 0:
        console.print(
            Panel(
                "[red]✗ Root privileges required[/red]\nRun with: [bold]sudo enigma.py[/bold]",
                title="[red]Permission Denied[/red]",
                border_style="red"
            )
        )
        log_action("CHECK_ROOT", "Failed - non-admin user", "ERROR")
        sys.exit(1)


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password strength.
    
    Requirements:
    - Minimum 12 characters
    - Uppercase, lowercase, numbers, special chars
    """
    if len(password) < 12:
        return False, "Must be at least 12 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Must contain uppercase letters"
    if not re.search(r'[a-z]', password):
        return False, "Must contain lowercase letters"
    if not re.search(r'\d', password):
        return False, "Must contain numbers"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Must contain special characters (!@#$%^&*...)"
    
    return True, "Strong password"


def show_password_strength(password: str):
    """Show password strength indicator."""
    is_valid, message = validate_password(password)
    
    if is_valid:
        console.print(f"[green]✓ {message}[/green]")
    else:
        console.print(f"[red]✗ {message}[/red]")
    
    return is_valid


def prompt_password(label: str = "Password") -> str:
    """Prompt for password with strength validation."""
    while True:
        password = getpass.getpass(f"[cyan]▶[/cyan] {label}: ")
        
        if not password:
            console.print("[red]✗ Password cannot be empty[/red]")
            continue
        
        if show_password_strength(password):
            confirm = getpass.getpass(f"[cyan]▶[/cyan] Confirm {label}: ")
            if password == confirm:
                return password
            else:
                console.print("[red]✗ Passwords don't match[/red]")
        
        console.print()


# ─── Windows BitLocker ────────────────────────────────────────────────────
class BitLockerManager:
    """Windows BitLocker encryption manager."""
    
    @staticmethod
    def check_available() -> bool:
        """Check if BitLocker is available."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-Command Get-BitLockerVolume"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def get_status() -> str:
        """Get BitLocker volume status."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-BitLockerVolume | Format-Table -AutoSize"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def encrypt_drive(drive_letter: str, password: str) -> bool:
        """Encrypt a drive with BitLocker."""
        try:
            ps_cmd = f"""
            $mnt = '{drive_letter}:'
            $pw = ConvertTo-SecureString '{password}' -AsPlainText -Force
            Enable-BitLocker -MountPoint $mnt -EncryptionMethod XtsAes256 -PasswordProtector -Password $pw
            """
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return False


# ─── Linux LUKS ──────────────────────────────────────────────────────────
class LUKSManager:
    """Linux LUKS encryption manager."""
    
    @staticmethod
    def ensure_installed():
        """Ensure cryptsetup is installed."""
        if subprocess.run(["which", "cryptsetup"], capture_output=True).returncode == 0:
            return True
        
        console.print("[yellow]Installing cryptsetup...[/yellow]")
        
        # Detect package manager
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
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def encrypt_drive(device: str, name: str, password: str) -> bool:
        """Create encrypted LUKS2 volume."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                console=console
            ) as progress:
                # Format disk
                progress.add_task("LUKS format...", total=None)
                result = subprocess.run(
                    f"echo '{password}' | cryptsetup luksFormat --type luks2 --force-password {device}",
                    shell=True,
                    capture_output=True,
                    timeout=30
                )
                if result.returncode != 0:
                    return False
                
                # Open
                progress.add_task("Opening encrypted volume...", total=None)
                result = subprocess.run(
                    f"echo '{password}' | cryptsetup luksOpen {device} {name}",
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
                if result.returncode != 0:
                    return False
                
                # Format filesystem
                progress.add_task("Creating ext4 filesystem...", total=None)
                result = subprocess.run(
                    f"mkfs.ext4 -F /dev/mapper/{name}",
                    shell=True,
                    capture_output=True,
                    timeout=30
                )
                
                # Mount
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


# ─── Main Menu ─────────────────────────────────────────────────────────
def main_menu_windows():
    """Windows BitLocker main menu."""
    manager = BitLockerManager()
    
    if not manager.check_available():
        console.print(
            Panel(
                "[red]BitLocker is not available[/red]\n"
                "Windows Pro/Enterprise/Education required",
                title="[red]Error[/red]",
                border_style="red"
            )
        )
        return
    
    while True:
        console.clear()
        show_header()
        
        # Status table
        try:
            status = manager.get_status()
            console.print(Panel(status, title="[cyan]BitLocker Status[/cyan]", border_style="cyan"))
        except:
            pass
        
        console.print()
        
        # Menu options
        menu_items = [
            "[1] Status",
            "[2] Encrypt Drive",
            "[3] Unlock Drive",
            "[4] Lock Drive",
            "[5] Decrypt Drive",
            "[6] Exit"
        ]
        
        for item in menu_items:
            console.print(f"  {item}")
        
        choice = Prompt.ask("\n[cyan]▶ Select[/cyan]", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            console.clear()
            show_header()
            console.print(manager.get_status())
            input("\nPress Enter...")
        
        elif choice == "6":
            console.print("[dim]Goodbye![/dim]")
            break


def main_menu_linux():
    """Linux LUKS main menu."""
    manager = LUKSManager()
    
    if not manager.ensure_installed():
        return
    
    while True:
        console.clear()
        show_header()
        
        # ─── Disk Overview ───────────────────────────────────────────────
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
                    dev.get('mountpoint', dev.get('free', '-'))
                )
            
            console.print(table)
        
        # ─── LUKS Status ─────────────────────────────────────────────────
        status = manager.get_status()
        console.print(Panel(status, title="[cyan]LUKS Volumes[/cyan]", border_style="cyan"))
        console.print()
        
        # ─── Menu options ────────────────────────────────────────────────
        menu_items = [
            "[1] Refresh Status",
            "[2] Encrypt Drive",
            "[3] Unlock Drive",
            "[4] Lock Drive",
            "[5] Decrypt Drive",
            "[6] Disk Info",
            "[7] Audit Log",
            "[8] Exit"
        ]
        
        for item in menu_items:
            console.print(f"  {item}")
        
        choice = Prompt.ask("\n[cyan]▶ Select[/cyan]", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == "1":
            pass  # Refresh by looping
        
        elif choice == "2":
            console.clear()
            show_header()
            
            # Show available disks
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']} ({dev['type']})")
            
            device = Prompt.ask("[cyan]Device path[/cyan]")
            name = Prompt.ask("[cyan]Container name[/cyan]")
            
            # Get disk info
            disk_type = DiskInfo.get_disk_type(device)
            disk_size_bytes, disk_size_str = DiskInfo.get_disk_size(device)
            
            console.print(f"\n[cyan]Device Info:[/cyan]")
            console.print(f"  Type: {disk_type}")
            console.print(f"  Size: {disk_size_str}")
            console.print()
            
            console.print("[yellow]⚠ WARNING: All data on this device will be lost![/yellow]")
            if Confirm.ask("Continue?"):
                password = prompt_password("Encryption password")
                console.print()
                
                if manager.encrypt_drive(device, name, password):
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
        
        elif choice == "3":
            console.clear()
            show_header()
            
            # Show available devices
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']} ({dev['type']})")
            
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
        
        elif choice == "4":
            console.clear()
            show_header()
            name = Prompt.ask("[cyan]Container name[/cyan]")
            
            if manager.lock_drive(name):
                console.print("[green]✓ Volume locked[/green]")
            else:
                console.print("[red]✗ Failed to lock volume[/red]")
            
            input("\nPress Enter...")
        
        elif choice == "5":
            console.clear()
            show_header()
            
            console.print("[yellow]Available Devices:[/yellow]")
            for idx, dev in enumerate(devices, 1):
                console.print(f"  {idx}. {dev['name']} - {dev['size']} ({dev['type']})")
            
            device = Prompt.ask("[cyan]Device[/cyan]")
            
            console.print("\n[red]⚠ WARNING: This will permanently erase all encryption![/red]")
            if Confirm.ask("Irreversible action - continue?"):
                if manager.decrypt_drive(device):
                    console.print("[green]✓ LUKS header erased[/green]")
                else:
                    console.print("[red]✗ Failed to erase[/red]")
            
            input("\nPress Enter...")
        
        elif choice == "6":
            console.clear()
            show_header()
            
            if devices:
                table = Table(title="Detailed Disk Information", box=box.DOUBLE)
                table.add_column("Device", style="cyan", width=15)
                table.add_column("Info", style="white")
                
                for dev in devices:
                    device_path = dev['name']
                    info_lines = [
                        f"Type: {dev['type']}",
                        f"Size: {dev['size']}",
                        f"FS: {dev['fstype']}",
                    ]
                    
                    if 'free' in dev:
                        info_lines.append(f"Free: {dev['free']}")
                    
                    table.add_row(device_path, "\n".join(info_lines))
                
                console.print(table)
            else:
                console.print("[dim]No devices found[/dim]")
            
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
            break


def main():
    """Main entry point."""
    check_root()
    log_action("START", f"System: {OS_TYPE}", "INFO")
    
    try:
        if OS_TYPE == "windows":
            main_menu_windows()
        elif OS_TYPE == "linux":
            main_menu_linux()
        else:
            console.print(f"[red]Unsupported OS: {OS_TYPE}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted[/yellow]")
        log_action("ABORT", "User interrupted", "INFO")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        log_action("FATAL", str(e), "ERROR")


if __name__ == "__main__":
    main()
