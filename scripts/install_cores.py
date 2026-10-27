#!/usr/bin/env python3
"""Download official Xray-core and sing-box release binaries for the current platform."""
from __future__ import annotations
import argparse
import os
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

import requests

UA = "Proxy-Harvester-Core-Installer/1.0"


def arch_names() -> tuple[str, str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
        xray_arch = "64"
    elif machine in {"aarch64", "arm64"}:
        arch = "arm64"
        xray_arch = "arm64-v8a"
    elif machine in {"i386", "i686", "x86"}:
        arch = "386"
        xray_arch = "32"
    else:
        raise RuntimeError(f"Unsupported CPU architecture: {machine}")
    if system == "windows":
        return system, "windows-" + arch, xray_arch
    if system == "darwin":
        return system, "darwin-" + arch, xray_arch
    if system == "linux":
        return system, "linux-" + arch, xray_arch
    raise RuntimeError(f"Unsupported operating system: {system}")


def api_json(url: str) -> dict:
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    token = (os.environ.get("GH_PAT", "") or os.environ.get("GITHUB_TOKEN", "")).strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


def download(url: str, dest: Path) -> None:
    headers = {"User-Agent": UA}
    with requests.get(url, headers=headers, timeout=60, stream=True) as r:
        r.raise_for_status()
        with dest.open("wb") as f:
            for chunk in r.iter_content(1024 * 256):
                if chunk:
                    f.write(chunk)


def find_asset(release: dict, predicate) -> dict:
    for asset in release.get("assets", []):
        if predicate(asset.get("name", "")):
            return asset
    raise RuntimeError("No compatible release asset found: " + str(release.get("tag_name", "latest")))


def install_xray(out: Path, os_name: str, platform_name: str, xray_arch: str) -> Path:
    release = api_json("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
    if os_name == "windows":
        wanted = f"Xray-windows-{xray_arch}.zip"
    elif os_name == "darwin":
        wanted = f"Xray-macos-{xray_arch}.zip"
    else:
        wanted = f"Xray-linux-{xray_arch}.zip"
    asset = find_asset(release, lambda name: name.lower() == wanted.lower())
    dest = out / ("xray.exe" if os_name == "windows" else "xray")
    with tempfile.TemporaryDirectory(prefix="xray-installer-") as td:
        archive = Path(td) / "xray.zip"
        download(asset["browser_download_url"], archive)
        with zipfile.ZipFile(archive) as zf:
            member = next((n for n in zf.namelist() if Path(n).name.lower() in {"xray", "xray.exe"}), None)
            if member is None:
                raise RuntimeError("Xray archive had no executable")
            dest.write_bytes(zf.read(member))
    if os_name != "windows":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def install_singbox(out: Path, os_name: str, platform_name: str) -> Path:
    release = api_json("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
    if os_name == "windows":
        endings = (platform_name + ".zip", platform_name + ".tar.gz")
    else:
        endings = (platform_name + ".tar.gz", platform_name + ".zip")
    asset = find_asset(release, lambda name: any(name.endswith(suffix) for suffix in endings) and not any(k in name.lower() for k in ("sha256", "checksum", "sig", "source")))
    dest = out / ("sing-box.exe" if os_name == "windows" else "sing-box")
    with tempfile.TemporaryDirectory(prefix="singbox-installer-") as td:
        archive = Path(td) / Path(asset["name"]).name
        download(asset["browser_download_url"], archive)
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as zf:
                member = next((n for n in zf.namelist() if Path(n).name.lower() in {"sing-box", "sing-box.exe"}), None)
                if member is None:
                    raise RuntimeError("sing-box archive had no executable")
                dest.write_bytes(zf.read(member))
        elif tarfile.is_tarfile(archive):
            with tarfile.open(archive, "r:gz") as tf:
                member = next((m for m in tf.getmembers() if m.isfile() and Path(m.name).name.lower() in {"sing-box", "sing-box.exe"}), None)
                if member is None:
                    raise RuntimeError("sing-box archive had no executable")
                source = tf.extractfile(member)
                if source is None:
                    raise RuntimeError("Unable to read sing-box executable")
                dest.write_bytes(source.read())
        else:
            raise RuntimeError("Unknown sing-box archive type")
    if os_name != "windows":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="tools", help="Folder where executables are stored")
    args = p.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    os_name, platform_name, xray_arch = arch_names()
    print(f"Platform: {os_name}/{platform_name} (Xray asset arch: {xray_arch})")
    xray = install_xray(out, os_name, platform_name, xray_arch)
    sing = install_singbox(out, os_name, platform_name)
    print(f"Installed Xray: {xray}")
    print(f"Installed sing-box: {sing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
