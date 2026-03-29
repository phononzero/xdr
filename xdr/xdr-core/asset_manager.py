#!/usr/bin/env python3
"""
XDR Asset Manager — Kernel Modules, Packages, Hardware.

Provides real-time inventory and control of system assets:
  - Kernel modules: list, unload, blacklist
  - Packages: list installed, find running
  - Hardware: USB, PCI, input devices with block/allow
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("xdr.assets")


# ═══════════════════════════════════════════════════════
# Kernel Module Management
# ═══════════════════════════════════════════════════════

def get_loaded_modules() -> list[dict]:
    """Get all loaded kernel modules with details."""
    modules = []
    kernel_ver = os.uname().release
    builtin = _get_builtin_set(kernel_ver)
    system_mods = _get_system_module_set(kernel_ver)

    try:
        for line in Path("/proc/modules").read_text().strip().splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            name = parts[0]
            size = int(parts[1])
            used_count = int(parts[2])
            used_by = parts[3].strip(",-").split(",") if parts[3] != "-" else []
            state = parts[4]  # Live, Loading, Unloading

            # Taint check
            taint = ""
            taint_path = Path(f"/sys/module/{name}/taint")
            try:
                if taint_path.exists():
                    taint = taint_path.read_text().strip()
            except (PermissionError, OSError):
                pass

            # Version
            version = ""
            ver_path = Path(f"/sys/module/{name}/version")
            try:
                if ver_path.exists():
                    version = ver_path.read_text().strip()
            except (PermissionError, OSError):
                pass

            # Safety classification
            is_system = name in system_mods or name in builtin
            is_tainted_bad = bool(taint and taint not in ("P",))

            if is_tainted_bad:
                safety = "suspicious"
            elif is_system:
                safety = "safe"
            else:
                safety = "unknown"

            modules.append({
                "name": name,
                "size": size,
                "size_kb": round(size / 1024, 1),
                "used_count": used_count,
                "used_by": used_by,
                "state": state,
                "taint": taint,
                "version": version,
                "safety": safety,
                "is_builtin": name in builtin,
                "removable": used_count == 0 and state == "Live",
            })
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read /proc/modules: {e}")

    return sorted(modules, key=lambda m: m["name"])


def unload_module(name: str) -> dict:
    """Unload a kernel module via rmmod."""
    try:
        result = subprocess.run(
            ["rmmod", name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.info(f"Module unloaded: {name}")
            return {"ok": True, "message": f"모듈 '{name}' 언로드 완료"}
        else:
            err = result.stderr.strip()
            logger.warning(f"Module unload failed: {name}: {err}")
            return {"ok": False, "message": f"언로드 실패: {err}",
                    "needs_reboot": "in use" in err.lower()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "시간 초과"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def block_module(name: str) -> dict:
    """Add module to modprobe blacklist (takes effect after reboot)."""
    blacklist_dir = Path("/etc/modprobe.d")
    blacklist_file = blacklist_dir / "xdr-blacklist.conf"

    try:
        existing = ""
        if blacklist_file.exists():
            existing = blacklist_file.read_text()

        entry = f"blacklist {name}"
        if entry in existing:
            return {"ok": True, "message": f"'{name}' 이미 블랙리스트에 존재",
                    "needs_reboot": False}

        with open(blacklist_file, "a") as f:
            f.write(f"\n# XDR blocked: {name}\n{entry}\ninstall {name} /bin/false\n")

        logger.info(f"Module blacklisted: {name}")
        return {"ok": True, "message": f"'{name}' 블랙리스트 추가 (재부팅 필요)",
                "needs_reboot": True}
    except PermissionError:
        return {"ok": False, "message": "권한 부족 (root 필요)"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def unblock_module(name: str) -> dict:
    """Remove module from modprobe blacklist."""
    blacklist_file = Path("/etc/modprobe.d/xdr-blacklist.conf")
    try:
        if not blacklist_file.exists():
            return {"ok": True, "message": "블랙리스트 파일 없음"}

        lines = blacklist_file.read_text().splitlines()
        new_lines = []
        skip_next = False
        for line in lines:
            if f"XDR blocked: {name}" in line:
                skip_next = True
                continue
            if skip_next and (f"blacklist {name}" in line or
                              f"install {name}" in line):
                skip_next = False
                continue
            skip_next = False
            new_lines.append(line)

        blacklist_file.write_text("\n".join(new_lines) + "\n")
        return {"ok": True, "message": f"'{name}' 블랙리스트 해제 (재부팅 필요)",
                "needs_reboot": True}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ═══════════════════════════════════════════════════════
# Package Management
# ═══════════════════════════════════════════════════════

def get_installed_packages() -> list[dict]:
    """Get all installed packages via dpkg."""
    packages = []
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f",
             "${Package}\t${Version}\t${Status}\t${Description}\n"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            # Get running processes to cross-reference
            running_exes = _get_running_executables()

            for line in result.stdout.splitlines():
                parts = line.split("\t", 3)
                if len(parts) < 3:
                    continue
                name = parts[0]
                version = parts[1]
                status = parts[2]
                desc = parts[3] if len(parts) > 3 else ""

                is_installed = "installed" in status.lower()
                if not is_installed:
                    continue

                # Check if any process from this package is running
                is_running = name in running_exes

                packages.append({
                    "name": name,
                    "version": version,
                    "status": status,
                    "description": desc[:100],
                    "running": is_running,
                })
    except subprocess.TimeoutExpired:
        logger.warning("dpkg-query timed out")
    except FileNotFoundError:
        # Not Debian-based, try rpm
        packages = _get_rpm_packages()
    except Exception as e:
        logger.error(f"Package query error: {e}")

    return packages


def _get_rpm_packages() -> list[dict]:
    """Fallback for RPM-based systems."""
    packages = []
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat",
             "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SUMMARY}\n"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split("\t", 2)
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "status": "installed",
                        "description": parts[2][:100] if len(parts) > 2 else "",
                        "running": False,
                    })
    except Exception:
        pass
    return packages


def _get_running_executables() -> set[str]:
    """Get set of package names that have running processes."""
    running = set()
    try:
        result = subprocess.run(
            ["ps", "axo", "comm", "--no-headers"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for comm in result.stdout.splitlines():
                running.add(comm.strip())
    except Exception:
        pass
    return running


# ═══════════════════════════════════════════════════════
# Hardware Management
# ═══════════════════════════════════════════════════════

def get_hardware_devices() -> list[dict]:
    """Get all hardware devices (USB, PCI, input)."""
    devices = []
    devices.extend(_get_usb_devices())
    devices.extend(_get_pci_devices())
    devices.extend(_get_input_devices())
    return devices


def _get_usb_devices() -> list[dict]:
    """Get USB devices from /sys/bus/usb/devices/."""
    devices = []
    usb_path = Path("/sys/bus/usb/devices")
    if not usb_path.exists():
        return devices

    for dev_dir in usb_path.iterdir():
        try:
            vendor_path = dev_dir / "idVendor"
            product_path = dev_dir / "idProduct"
            if not vendor_path.exists():
                continue

            vendor = vendor_path.read_text().strip()
            product = product_path.read_text().strip()

            manufacturer = ""
            product_name = ""
            serial = ""

            try:
                manufacturer = (dev_dir / "manufacturer").read_text().strip()
            except (FileNotFoundError, PermissionError):
                pass
            try:
                product_name = (dev_dir / "product").read_text().strip()
            except (FileNotFoundError, PermissionError):
                pass
            try:
                serial = (dev_dir / "serial").read_text().strip()
            except (FileNotFoundError, PermissionError):
                pass

            # Device class
            dev_class = ""
            try:
                dev_class = (dev_dir / "bDeviceClass").read_text().strip()
            except (FileNotFoundError, PermissionError):
                pass

            devices.append({
                "type": "usb",
                "bus_id": dev_dir.name,
                "vendor_id": vendor,
                "product_id": product,
                "manufacturer": manufacturer,
                "product_name": product_name or f"USB {vendor}:{product}",
                "serial": serial,
                "device_class": dev_class,
                "name": product_name or manufacturer or f"USB {vendor}:{product}",
            })
        except (PermissionError, OSError):
            continue

    return devices


def _get_pci_devices() -> list[dict]:
    """Get PCI devices via lspci."""
    devices = []
    try:
        result = subprocess.run(
            ["lspci", "-mm", "-nn"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                # Parse lspci -mm output
                parts = line.split('"')
                if len(parts) >= 6:
                    slot = parts[0].strip()
                    dev_class = parts[1]
                    vendor = parts[3]
                    device = parts[5]

                    devices.append({
                        "type": "pci",
                        "bus_id": slot,
                        "name": f"{vendor} {device}",
                        "device_class": dev_class,
                        "vendor_name": vendor,
                        "device_name": device,
                    })
    except Exception:
        pass
    return devices


def _get_input_devices() -> list[dict]:
    """Get input devices from /proc/bus/input/devices."""
    devices = []
    try:
        content = Path("/proc/bus/input/devices").read_text()
        current = {}

        for line in content.splitlines():
            if line.startswith("I:"):
                if current:
                    devices.append(current)
                current = {"type": "input"}
                # Parse bus/vendor/product/version
                for part in line[2:].split():
                    key, _, val = part.partition("=")
                    current[key.lower()] = val
            elif line.startswith("N:"):
                current["name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("P:"):
                current["phys"] = line.split("=", 1)[1].strip()
            elif line.startswith("H:"):
                current["handlers"] = line.split("=", 1)[1].strip()

        if current:
            devices.append(current)
    except (FileNotFoundError, PermissionError):
        pass
    return devices


def block_usb_device(vendor_id: str, product_id: str) -> dict:
    """Block a USB device via udev rule."""
    rules_dir = Path("/etc/udev/rules.d")
    rules_file = rules_dir / "99-xdr-usb-block.rules"

    try:
        existing = ""
        if rules_file.exists():
            existing = rules_file.read_text()

        rule = (f'ACTION=="add", ATTR{{idVendor}}=="{vendor_id}", '
                f'ATTR{{idProduct}}=="{product_id}", '
                f'RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'"')

        if vendor_id in existing and product_id in existing:
            return {"ok": True, "message": "이미 차단됨"}

        with open(rules_file, "a") as f:
            f.write(f"\n# XDR blocked USB: {vendor_id}:{product_id}\n{rule}\n")

        # Reload udev rules
        subprocess.run(["udevadm", "control", "--reload-rules"],
                       capture_output=True, timeout=5)

        return {"ok": True, "message": f"USB {vendor_id}:{product_id} 차단됨 (재연결 시 적용)"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def unblock_usb_device(vendor_id: str, product_id: str) -> dict:
    """Unblock a USB device."""
    rules_file = Path("/etc/udev/rules.d/99-xdr-usb-block.rules")
    try:
        if not rules_file.exists():
            return {"ok": True, "message": "차단 규칙 없음"}

        lines = rules_file.read_text().splitlines()
        new_lines = [l for l in lines
                     if not (vendor_id in l and product_id in l)]
        rules_file.write_text("\n".join(new_lines) + "\n")

        subprocess.run(["udevadm", "control", "--reload-rules"],
                       capture_output=True, timeout=5)

        return {"ok": True, "message": f"USB {vendor_id}:{product_id} 차단 해제"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ═══════════════════════════════════════════════════════
# Internal Helpers
# ═══════════════════════════════════════════════════════

def _get_builtin_set(kernel_ver: str) -> set[str]:
    """Get set of built-in module names."""
    builtins = set()
    path = Path(f"/lib/modules/{kernel_ver}/modules.builtin")
    try:
        if path.exists():
            for line in path.read_text().splitlines():
                name = line.strip().rsplit("/", 1)[-1]
                name = name.replace(".ko", "").replace("-", "_")
                builtins.add(name)
    except (PermissionError, OSError):
        pass
    return builtins


def _get_system_module_set(kernel_ver: str) -> set[str]:
    """Get set of module names from kernel module directory."""
    mods = set()
    mod_dir = Path(f"/lib/modules/{kernel_ver}/kernel")
    try:
        if mod_dir.exists():
            for ko in mod_dir.rglob("*.ko*"):
                name = ko.stem.split(".")[0].replace("-", "_")
                mods.add(name)
    except (PermissionError, OSError):
        pass
    return mods
