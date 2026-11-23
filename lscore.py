#!/usr/bin/env python3
"""Read-only Linux health check. Python 3.8+, standard library only."""
from __future__ import annotations

import argparse
import calendar
import concurrent.futures as cf
import configparser
import contextlib
import fcntl
import glob
import html
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Callable, Dict, List, Optional, Tuple

__version__ = "0.8.0"

# Marks files installed by lscore; install.sh and uninstall.sh check it.
INSTALL_MARKER = "lscore-install-marker:0d3f5a1c9b7e"

GiB = 1024 ** 3
UNICODE = (getattr(sys.stdout, "encoding", None) or "").lower().startswith("utf")


# Helpers

class Audit:
    """Collect what a run read, ran and wrote, so --audit can show it.

    Checks run in parallel, so every add takes the lock; the sets are copied
    under the same lock when the report is built.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._files_read: set = set()
        self._commands: set = set()
        self._files_written: set = set()

    def read(self, path: str) -> None:
        with self._lock:
            self._files_read.add(path)

    def ran(self, cmd: List[str]) -> None:
        line = " ".join(shlex.quote(str(part)) for part in cmd)
        with self._lock:
            self._commands.add(line)

    def wrote(self, path: str) -> None:
        with self._lock:
            self._files_written.add(path)

    def snapshot(self) -> Dict[str, List[str]]:
        with self._lock:
            return {"files_read": sorted(self._files_read),
                    "commands_run": sorted(self._commands),
                    "files_written": sorted(self._files_written)}


AUDIT = Audit()


def run(cmd: List[str], timeout: float = 8.0) -> Tuple[Optional[int], str]:
    """Run a command; never raises. Returns (returncode or None, stdout)."""
    AUDIT.ran(cmd)
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
            errors="replace",
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        return p.returncode, p.stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        return None, ""


def read(path: str) -> str:
    AUDIT.read(path)
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(s: str) -> str:
    """Replace control characters so on-disk text can't inject terminal escapes."""
    return _CTRL.sub(" ", s).strip()


def in_container() -> bool:
    """True inside Docker/Podman/Kubernetes/LXC, where /proc describes the host."""
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    cgroup = read("/proc/1/cgroup") + read("/proc/self/cgroup")
    return re.search(r"(docker|kubepods|containerd|libpod|podman|lxc)", cgroup) is not None


def human(n: float) -> str:
    """Bytes as IEC units (1024-based, so KiB/MiB/GiB are correct)."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def human2(n: float) -> str:
    """Two decimals, so disk capacity matches tools like fastfetch exactly."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TiB"


def dir_size(path: str, budget: float = 4.0) -> Tuple[int, bool]:
    """Bytes used by a folder, counted like `du`: allocated blocks, hard links once.
    Returns (bytes, finished)."""
    total, stack, seen = 0, [path], set()
    deadline = time.monotonic() + budget
    while stack:
        if time.monotonic() > deadline:
            return total, False
        d = stack.pop()
        try:
            total += os.stat(d, follow_symlinks=False).st_blocks * 512
        except OSError:
            pass
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)     # counted once, when it is popped
                            continue
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_nlink > 1:              # hard link: the inode is already counted
                        key = (st.st_dev, st.st_ino)
                        if key in seen:
                            continue
                        seen.add(key)
                    total += st.st_blocks * 512
        except OSError:
            pass
    return total, True


def index_age_days(*patterns: str) -> Optional[float]:
    mtimes = []
    for pattern in patterns:
        for f in glob.glob(pattern):
            try:
                mtimes.append(os.stat(f).st_mtime)
            except OSError:
                pass
    return (time.time() - max(mtimes)) / 86400 if mtimes else None


def meminfo() -> Dict[str, int]:
    """/proc/meminfo as {name: bytes}."""
    out: Dict[str, int] = {}
    for line in read("/proc/meminfo").splitlines():
        key, _, val = line.partition(":")
        parts = val.split()
        if parts and parts[0].isdigit():
            out[key] = int(parts[0]) * 1024
    return out


# Parsers

_TIME_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(h|min|s|ms|us)\b")
_TIME_UNIT = {"h": 3600.0, "min": 60.0, "s": 1.0, "ms": 1e-3, "us": 1e-6}


def parse_systemd_total(text: str) -> Optional[float]:
    """'Startup finished in 3.1s (kernel) + 9.2s (userspace) = 12.3s' -> 12.3"""
    line = next((l for l in text.splitlines() if l.startswith("Startup finished")), "")
    if not line:
        return None
    tail = line.split("=")[-1] if "=" in line else line
    parts = _TIME_RE.findall(tail)
    if not parts:
        return None
    return sum(float(v) * _TIME_UNIT[u] for v, u in parts)


_SYSTEMD_PHASE_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(h|min|s|ms|us)\s*\(([^)]+)\)")


def parse_systemd_breakdown(text: str) -> Dict[str, float]:
    """Startup phases from systemd-analyze -> {phase: seconds, "total": seconds}.

    Newer systemd reports firmware, loader, kernel, initrd and userspace; older
    versions only kernel and userspace. An empty dict means the line is missing
    or unreadable ("Bootup is not yet finished").
    """
    line = next((l for l in text.splitlines() if l.startswith("Startup finished")), "")
    if not line:
        return {}
    phases: Dict[str, float] = {}
    for value, unit, name in _SYSTEMD_PHASE_RE.findall(line.split("=", 1)[0]):
        key = name.strip().lower()
        if key in ("firmware", "loader", "kernel", "initrd", "userspace"):
            phases[key] = phases.get(key, 0.0) + float(value) * _TIME_UNIT[unit]
    total = parse_systemd_total(line)
    if total is None and phases:
        total = sum(phases.values())
    if total is not None:
        phases["total"] = total
    return phases


def _is_local_host(host: str) -> bool:
    host = host.strip("[]").split("%")[0].lower()
    if host.startswith("::ffff:"):
        host = host[7:]
    return host.startswith("127.") or host in ("::1", "0:0:0:0:0:0:0:1")


def parse_ss_listeners(text: str) -> List[Tuple[str, str]]:
    """`ss -H -ltnp` -> [(port, process)] for listeners reachable from the network."""
    seen, found = set(), []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 4 or cols[0] != "LISTEN":
            continue
        host, _, port = cols[3].rpartition(":")
        if not port.isdigit():
            continue
        if _is_local_host(host):
            continue
        if port in seen:
            continue
        seen.add(port)
        m = re.search(r'\(\("([^"]+)"', line)
        found.append((port, m.group(1) if m else ""))
    found.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0)
    return found


_UDP_ANNOUNCE = {"5353": "mDNS", "1900": "SSDP", "3702": "WS-Discovery", "5355": "LLMNR"}


def nft_input_filtered(text: str) -> bool:
    """True if a chain hooked to input drops or rejects traffic.
    Container FORWARD chains do not count."""
    for block in re.findall(r"chain\s+\S+\s*\{([^{}]*)\}", text, re.S):
        if re.search(r"\bhook\s+input\b", block) and re.search(r"\b(drop|reject)\b", block):
            return True
    return False


def iptables_input_filtered(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if re.match(r"^-P\s+INPUT\s+(DROP|REJECT)\b", line):
            return True
        if re.match(r"^-A\s+INPUT\b", line) and re.search(r"-j\s+(DROP|REJECT)\b", line):
            return True
    return False


def parse_zypper_updates(text: str) -> Optional[int]:
    """`zypper --xmlout list-updates` -> pending update count, or None."""
    if not text.strip():
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    status = root.find("update-status")
    if root.tag != "stream" or status is None:
        return None
    # <update-status> nests <update-list><update .../></update-list>
    return sum(1 for _ in status.iter("update"))


def parse_apk_updates(text: str) -> Optional[int]:
    """`apk version -l '<'` -> packages with a newer version."""
    n = 0
    for line in text.splitlines():
        if line.strip().startswith("Installed") or "<" not in line:
            continue
        left, _, right = line.partition("<")
        if left.strip() and right.strip():
            n += 1
    return n


def parse_rpm_ostree_status(text: str) -> Optional[Tuple[bool, Optional[float]]]:
    """`rpm-ostree status --json` -> (an update is staged, age of the booted image in days)."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("deployments"), list):
        return None
    deployments = [d for d in data["deployments"] if isinstance(d, dict)]
    staged = any(d.get("staged") is True for d in deployments)
    booted = next((d for d in deployments if d.get("booted")), None)
    age = None
    ts = booted.get("timestamp") if booted else None
    if isinstance(ts, str) and len(ts) >= 19:
        try:
            when = calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
            age = max(0.0, (time.time() - when) / 86400)
        except (ValueError, OverflowError):
            age = None
    return staged, age


def parse_xbps_updates(text: str) -> int:
    """`xbps-install -un` -> lines like `bash-5.2.021_1 update 5.2.026_1`."""
    return sum(1 for line in text.splitlines() if " update " in line)


def parse_rc_crashed(text: str) -> List[str]:
    names = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("[") or parts[0].endswith(":"):
            continue                      # bracket-only rows and "Runlevel:" headers
        names.append(parts[0])
    return names


def parse_udp_announcements(text: str) -> List[Tuple[str, str]]:
    """`ss -H -lunp` -> [(label, process)] for UDP announcement services."""
    seen, found = set(), []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 4 or cols[0] != "UNCONN":
            continue                        # listening UDP sockets show as UNCONN
        host, _, port = cols[3].rpartition(":")
        label = _UDP_ANNOUNCE.get(port)
        if label is None or _is_local_host(host):
            continue
        if label in seen:
            continue
        seen.add(label)
        m = re.search(r'\(\("([^"]+)"', line)
        found.append((label, m.group(1) if m else ""))
    return found


def parse_apt_upgradable(text: str) -> Tuple[int, int]:
    total = sec = 0
    for line in text.splitlines():
        if "[upgradable from:" not in line:
            continue
        pkg = line.split()[0] if line.split() else ""
        if "/" not in pkg:
            continue
        total += 1
        if "-security" in pkg:
            sec += 1
    return total, sec


def parse_journal_bytes(text: str) -> Optional[int]:
    """'Archived and active journals take up 3.9G in the file system.' -> bytes"""
    m = re.search(r"take up\s+(\d+(?:\.\d+)?)\s*([KMGTP]?)", text)
    if not m:
        return None
    mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": GiB, "T": 1024 ** 4, "P": 1024 ** 5}
    return int(float(m.group(1)) * mult[m.group(2)])


_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")

# Pseudo filesystems describe the kernel or devices, not storage the user can fill.
_PSEUDO_FS = frozenset({
    "apparmorfs", "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2",
    "configfs", "cramfs", "debugfs", "devpts", "devtmpfs", "efivarfs",
    "erofs", "fusectl", "fuse.gvfsd-fuse", "fuse.lxcfs", "fuse.portal",
    "hugetlbfs", "iso9660", "mqueue", "nsfs", "proc", "pstore", "ramfs",
    "romfs", "rpc_pipefs", "securityfs", "selinuxfs", "smackfs",
    "squashfs", "sysfs", "tracefs",
})

# A statvfs on a dead network mount can block forever; these belong to another machine.
_NETWORK_FS = frozenset({
    "9p", "afs", "ceph", "cifs", "davfs", "fuse.aftpfs", "fuse.ceph",
    "fuse.curlftpfs", "fuse.davfs2", "fuse.gcsfuse", "fuse.glusterfs",
    "fuse.httpdirfs", "fuse.juicefs", "fuse.moosefs", "fuse.obsfs",
    "fuse.rclone", "fuse.s3fs", "fuse.sftpfs", "fuse.smbnetfs",
    "fuse.sshfs", "glusterfs", "gpfs", "lustre", "ncpfs", "nfs", "nfs4",
    "orangefs", "pvfs2", "smb3", "smbfs",
})

# Filesystems that hold real data; a read-only one is worth reporting.
_DATA_FS = frozenset({
    "bcachefs", "btrfs", "exfat", "ext2", "ext3", "ext4", "f2fs", "hfs",
    "hfsplus", "jfs", "nilfs2", "ntfs", "ntfs3", "reiserfs", "ufs", "vfat",
    "xfs", "zfs",
})

# A read-only one of these breaks the running system, not just a data disk.
_CRITICAL_MOUNTS = {"/", "/home", "/var", "/etc", "/usr", "/boot", "/nix", "/sysroot"}


def parse_mounts(text: str) -> List[Tuple[str, str, str]]:
    """(mountpoint, fstype, options) from /proc/self/mounts; octal escapes decoded."""
    mounts = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        mount = _MOUNT_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), cols[1])
        mounts.append((mount, cols[2], cols[3]))
    return mounts


def _unescape_mount(path: str) -> str:
    return _MOUNT_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), path)


def parse_fstab_ro(text: str) -> set:
    """Mountpoints fstab asks to mount read-only on purpose."""
    ro = set()
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 4 and "ro" in fields[3].split(","):
            ro.add(_unescape_mount(fields[1]))
    return ro


def parse_ro_mounts(text: str, intentional: Optional[set] = None
                    ) -> List[Tuple[str, str, str]]:
    """Read-only data filesystems from /proc/self/mountinfo -> [(mountpoint, device, fstype)].

    Mounts whose root is not `/` are bind mounts or btrfs subvolumes. Bind mounts
    and btrfs snapshots are almost always read-only on purpose (NixOS /etc,
    snapshots), so they are skipped; a btrfs subvolume mounted at a system path
    is still judged, because that can be the real root.
    """
    intentional = intentional or set()
    found = []
    for line in text.splitlines():
        before, sep, after = line.partition(" - ")
        if not sep:
            continue
        fields, tail = before.split(), after.split()
        if len(fields) < 6 or len(tail) < 2:
            continue
        root, mountpoint, options = fields[3], _unescape_mount(fields[4]), fields[5]
        fstype, device = tail[0], tail[1]
        if fstype not in _DATA_FS:
            continue
        if root != "/" and not (fstype == "btrfs" and mountpoint in _CRITICAL_MOUNTS):
            continue
        if "ro" not in options.split(","):
            continue
        if mountpoint in intentional or device.startswith("/dev/loop"):
            continue
        found.append((mountpoint, device, fstype))
    return found


def parse_timedatectl_sync(text: str) -> Optional[bool]:
    """`timedatectl show -p NTPSynchronized --value` -> True, False or None."""
    value = text.strip().lower()
    if "=" in value:                       # older timedatectl ignores --value
        value = value.split("=", 1)[1].strip()
    if value == "yes":
        return True
    if value == "no":
        return False
    return None


def parse_chronyc_tracking(text: str) -> Optional[Tuple[float, str]]:
    """`chronyc tracking` -> (absolute offset in seconds, leap status)."""
    offset: Optional[float] = None
    leap = ""
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key == "system time":
            m = re.search(r"([\d.]+)\s+seconds", value)
            if m:
                try:
                    offset = abs(float(m.group(1)))
                except ValueError:
                    offset = None
        elif key == "leap status":
            leap = value.strip().lower()
    return (offset, leap) if offset is not None else None


def kernel_version(release: str) -> Tuple[int, ...]:
    """Numeric parts of a kernel release, so 6.10 sorts after 6.9 and 6.8.0-48 after 6.8.0-45."""
    return tuple(int(x) for x in re.findall(r"\d+", release))


def installed_kernels() -> List[str]:
    """Kernel releases with a kernel image or a module tree on disk."""
    names = set()
    for pattern in ("/boot/vmlinuz-*", "/lib/modules/*", "/usr/lib/modules/*"):
        for path in glob.glob(pattern):
            name = os.path.basename(path)
            if name.startswith("vmlinuz-"):
                name = name[len("vmlinuz-"):]
            if kernel_version(name):
                names.add(name)
    return sorted(names)


def newer_kernel(installed: List[str], running: str) -> Optional[str]:
    """The newest installed kernel, but only if it is actually newer than the running one."""
    running_v = kernel_version(running)
    if not running_v:
        return None
    best = None
    for name in installed:
        v = kernel_version(name)
        if v > running_v and (best is None or v > kernel_version(best)):
            best = name
    return best


_OOM_KILL = re.compile(r"Killed process \d+(?: \(([^)]+)\))?")


def parse_vmstat_oom(text: str) -> Optional[int]:
    """`/proc/vmstat` oom_kill counter: kills since boot, readable without root."""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "oom_kill":
            try:
                return int(fields[1])
            except ValueError:
                return None
    return None


def parse_oom_kills(text: str) -> List[str]:
    """Kernel log -> process names the OOM killer ended."""
    return [m.group(1) or "unknown" for m in _OOM_KILL.finditer(text)]


def parse_cpu_vulnerabilities(texts: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """CPU vulnerability files -> (unmitigated names, mitigated names).

    The kernel writes one file per vulnerability group. The first word is the
    overall status, so "Mitigation: ...; SMT vulnerable" still counts as mitigated.
    """
    vulnerable, mitigated = [], []
    for name in sorted(texts):
        status = texts[name].strip().lower()
        if status.startswith("vulnerable"):
            vulnerable.append(name)
        elif status.startswith(("mitigation", "not affected")):
            mitigated.append(name)
    return vulnerable, mitigated


def parse_mdstat(text: str) -> List[Tuple[str, str]]:
    """Software RAID arrays that are not healthy -> [(name, state)].

    States are "degraded", "inactive", "read-only" or "rebuilding"; healthy
    arrays are omitted.
    """
    arrays: Dict[str, str] = {}
    current = ""
    for line in text.splitlines():
        header = re.match(r"^(md\d+)\s*:\s*(.*)$", line)
        if header:
            current, line = header.group(1), header.group(2)
            arrays.setdefault(current, "ok")
            if "inactive" in line:
                arrays[current] = "inactive"
            elif "read-only" in line:
                arrays[current] = "read-only"
        elif not line.strip():
            current = ""
            continue
        elif not current:
            continue
        if arrays.get(current) == "inactive":
            continue
        if re.search(r"\(F\)", line):
            arrays[current] = "degraded"
        if re.search(r"\b(resync|recovery|reshape)\s*=", line):
            if arrays.get(current) == "ok":
                arrays[current] = "rebuilding"
        m = re.search(r"\[(\d+)/(\d+)\]", line)
        if m and m.group(1) != m.group(2):
            arrays[current] = "degraded"
        m = re.search(r"\[([U_]+)\]", line)
        if m and "_" in m.group(1):
            arrays[current] = "degraded"
    return [(name, state) for name, state in arrays.items() if state != "ok"]


def parse_sshd_config(texts: List[str]) -> Dict[str, str]:
    """First value wins (like OpenSSH). Conditional `Match` blocks are ignored."""
    cfg: Dict[str, str] = {}
    for text in texts:
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = re.split(r"[\s=]+", line, maxsplit=1)
            key = parts[0].lower()
            if key == "match":
                break
            if len(parts) == 2:
                cfg.setdefault(key, parts[1].strip().lower())
    return cfg


def sshd_config_texts(path: str = "/etc/ssh/sshd_config",
                      depth: int = 0, seen: Optional[set] = None) -> List[str]:
    """sshd_config and its Include files, in the order OpenSSH reads them."""
    if depth > 8:
        return []
    if seen is None:
        seen = set()
    real = os.path.realpath(path)
    if real in seen:
        return []
    seen.add(real)
    text = read(path)
    if not text:
        return []
    out: List[str] = []
    chunk: List[str] = []
    for line in text.splitlines():
        m = re.match(r"^\s*Include\s+(.+?)\s*$", line, re.I)
        if not m:
            chunk.append(line)
            continue
        if chunk:
            out.append("\n".join(chunk))
            chunk = []
        try:
            patterns = shlex.split(m.group(1))
        except ValueError:
            patterns = m.group(1).split()
        for pattern in patterns:
            if not os.path.isabs(pattern):
                pattern = os.path.join("/etc/ssh", pattern)   # OpenSSH's base directory
            for inc in sorted(glob.glob(pattern)):
                out.extend(sshd_config_texts(inc, depth + 1, seen))
    if chunk:
        out.append("\n".join(chunk))
    return out


def password_login_possible(cfg: Dict[str, str]) -> bool:
    """Could sshd still ask for a password, directly or through PAM keyboard-interactive?"""
    methods = cfg.get("authenticationmethods", "")
    if methods:
        allowed = {m.strip() for group in methods.split() for m in group.split(",")}
        return bool(allowed & {"password", "keyboard-interactive"})
    if cfg.get("passwordauthentication", "yes") == "yes":
        return True
    if cfg.get("usepam", "yes") == "yes":
        kbd = cfg.get("kbdinteractiveauthentication",
                      cfg.get("challengeresponseauthentication", "yes"))
        return kbd == "yes"
    return False


def autostart_entries(path: str) -> List[str]:
    names = []
    for f in sorted(glob.glob(os.path.join(path, "*.desktop"))):
        txt = read(f)
        if re.search(r"^Hidden\s*=\s*true", txt, re.M | re.I):
            continue
        if re.search(r"^X-GNOME-Autostart-enabled\s*=\s*false", txt, re.M | re.I):
            continue
        names.append(os.path.basename(f)[:-8])
    return names


def battery_health() -> Optional[Tuple[float, str]]:
    """(capacity vs. new in %, charge cycles or '') for the first battery."""
    for b in sorted(glob.glob("/sys/class/power_supply/BAT*")):
        if read(b + "/type") != "Battery":
            continue
        for full, design in (("energy_full", "energy_full_design"),
                             ("charge_full", "charge_full_design")):
            f, d = read(f"{b}/{full}"), read(f"{b}/{design}")
            if f.isdigit() and d.isdigit() and int(d) > 0:
                return min(100.0, int(f) / int(d) * 100), read(b + "/cycle_count")
    return None


def battery_charge_limit() -> Optional[int]:
    """The active charge stop threshold in percent, if the firmware exposes one."""
    for b in sorted(glob.glob("/sys/class/power_supply/BAT*")):
        if read(b + "/type") != "Battery":
            continue
        for name in ("charge_control_end_threshold", "charge_stop_threshold"):
            value = read(f"{b}/{name}")
            if value.isdigit() and 0 < int(value) <= 100:
                return int(value)
    return None


_CPU_ZONES = {"x86_pkg_temp", "cpu-thermal", "cpu_thermal", "soc_thermal"}
_CPU_HWMON = {"coretemp", "k10temp", "zenpower", "cpu_thermal", "soc_thermal"}


def cpu_temp_c() -> Optional[float]:
    files = []
    for z in glob.glob("/sys/class/thermal/thermal_zone*"):
        if read(z + "/type") in _CPU_ZONES:
            files.append(z + "/temp")
    for h in glob.glob("/sys/class/hwmon/hwmon*"):
        if read(h + "/name") in _CPU_HWMON:
            files += glob.glob(h + "/temp*_input")
    temps = []
    for f in files:
        try:
            t = int(read(f)) / 1000.0
        except ValueError:
            continue
        if 5 < t < 130:
            temps.append(t)
    return max(temps) if temps else None


def nixos_generations() -> List[Tuple[int, float]]:
    """[(generation number, creation time)] of the NixOS system profile, oldest first."""
    gens = []
    for link in glob.glob("/nix/var/nix/profiles/system-*-link"):
        m = re.search(r"system-(\d+)-link$", link)
        if not m:
            continue
        try:
            gens.append((int(m.group(1)), os.lstat(link).st_mtime))
        except OSError:
            pass
    return sorted(gens)


# Check plumbing

def nixos_update_check() -> "Out":
    """NixOS has no 'pending updates' list, so judge how long ago the system was last rebuilt."""
    gens = nixos_generations()
    if not gens:
        return skip("no NixOS system generations found")
    age = max(0.0, (time.time() - gens[-1][1]) / 86400)
    when = "today" if age < 1 else f"{age:.0f} day(s) ago"
    msg = f"NixOS has no pending-update list; the system was last rebuilt {when}"
    if age <= 45:
        return ok(msg)
    fix = ("Update your channel or flake inputs, then rebuild: `sudo nixos-rebuild switch --upgrade` "
           "(channels) or `nix flake update` + `nixos-rebuild switch` (flakes).")
    return (warn if age <= 120 else bad)(msg, fix)


def nixos_generations_check() -> "Out":
    """Old system generations keep their packages alive in /nix/store: NixOS's 'unused packages'."""
    gens = nixos_generations()
    if not gens:
        return skip("no NixOS system generations found")
    n = len(gens)
    if n <= 10:
        return ok(f"{n} system generation(s) kept")
    return (warn if n <= 40 else bad)(
        f"{n - 1} old system generation(s) (plus the current one) keep packages alive in /nix/store",
        "Delete old generations and collect garbage.",
        "sudo nix-collect-garbage --delete-older-than 14d")

@dataclass
class Out:
    status: str            # pass | warn | fail | skip
    detail: str = ""
    fix: str = ""
    cmd: str = ""          # printed by --fix only


def ok(detail: str = "") -> Out:
    return Out("pass", detail)


def warn(detail: str, fix: str = "", cmd: str = "") -> Out:
    return Out("warn", detail, fix, cmd)


def bad(detail: str, fix: str = "", cmd: str = "") -> Out:
    return Out("fail", detail, fix, cmd)


def skip(reason: str = "") -> Out:
    return Out("skip", reason)


CHECKS: List[Tuple[str, int, str, Callable]] = []


def check(category: str, weight: int, title: str):
    """Register a check; weight is its relative importance in the category."""
    def deco(fn):
        CHECKS.append((category, weight, title, fn))
        return fn
    return deco


def check_id(fn: Callable) -> str:
    name = fn.__name__
    return name[2:] if name.startswith("c_") else name


def split_tokens(values: Optional[List[str]]) -> List[str]:
    """Split repeated/comma/space-separated values; a full category name stays intact."""
    known = {c.lower() for c in CAT_ORDER}
    tokens: List[str] = []
    for value in values or []:
        whole = value.strip().lower()
        parts = [whole] if whole in known else re.split(r"[,\s]+", value)
        for token in parts:
            token = token.strip().lower()
            if token and token not in tokens:
                tokens.append(token)
    return tokens


def category_key(category: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")


def _category_keys(category: str) -> set:
    key = category_key(category)
    return {category.lower(), key, key.split("-")[0]}


def filter_checks(only: List[str], skip: List[str]
                  ) -> Tuple[List[Tuple[str, int, str, Callable]], List[str]]:
    """Select checks by id or category; returns (selected, unknown tokens)."""
    def hits(token: str) -> List[int]:
        return [i for i, (cat, _w, _t, fn) in enumerate(CHECKS)
                if token == check_id(fn) or token in _category_keys(cat)]

    chosen: List[int] = []
    if only:
        for token in only:
            if token == "all":
                chosen = list(range(len(CHECKS)))
                continue
            for i in hits(token):
                if i not in chosen:
                    chosen.append(i)
    else:
        chosen = list(range(len(CHECKS)))

    unknown: List[str] = []
    for token in only + skip:
        if token != "all" and not hits(token):
            unknown.append(token)
    for token in skip:
        if token == "all":
            chosen = []
        else:
            chosen = [i for i in chosen if i not in hits(token)]
    chosen.sort()
    return [CHECKS[i] for i in chosen], unknown


class Ctx:
    def __init__(self) -> None:
        self.home = os.path.expanduser("~")
        self.systemd = os.path.isdir("/run/systemd/system") and bool(shutil.which("systemctl"))
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        self.laptop = any(read(b + "/type") == "Battery"
                          for b in glob.glob("/sys/class/power_supply/BAT*"))
        # rpm-ostree systems also ship dnf; judging dnf would look at the wrong package set.
        self.ostree = os.path.exists("/run/ostree-booted")
        if self.ostree and shutil.which("rpm-ostree"):
            self.pm = "rpm-ostree"
        else:
            self.pm = next((m for m in ("zypper", "apk", "xbps-install",
                                        "pacman", "apt-get", "dnf", "emerge")
                            if shutil.which(m)), None)
        # /etc/NIXOS exists only on NixOS, not on other distros with plain Nix.
        self.nixos = (os.path.exists("/etc/NIXOS")
                      or re.search(r'^ID="?nixos"?$', read("/etc/os-release"), re.M) is not None)
        self.cache_home = os.environ.get("XDG_CACHE_HOME") or os.path.join(self.home, ".cache")
        self.data_home = os.environ.get("XDG_DATA_HOME") or os.path.join(self.home, ".local", "share")
        self.container = in_container()


def units_active(ctx: Ctx, names: List[str]) -> List[str]:
    if not ctx.systemd:
        return []
    _, out = run(["systemctl", "is-active", *names])
    return [n for n, s in zip(names, out.splitlines()) if s.strip() == "active"]


@lru_cache(maxsize=None)
def ss_output() -> Optional[str]:
    if not shutil.which("ss"):
        return None
    rc, out = run(["ss", "-H", "-ltnp"])
    if rc != 0:
        # iproute2 before 4.10 has no -H; the parser already skips the header.
        rc, out = run(["ss", "-ltnp"])
    return out if rc == 0 else None


@lru_cache(maxsize=None)
def ss_udp_output() -> Optional[str]:
    if not shutil.which("ss"):
        return None
    rc, out = run(["ss", "-H", "-lunp"])
    if rc != 0:
        rc, out = run(["ss", "-lunp"])
    return out if rc == 0 else None


@lru_cache(maxsize=None)
def running_processes() -> Tuple[str, ...]:
    """Running process names, so a server on a non-standard port is still seen."""
    names = []
    for d in glob.glob("/proc/[0-9]*"):
        name = read(d + "/comm")
        if name:
            names.append(name)
    return tuple(names)


@lru_cache(maxsize=None)
def resolvectl_status() -> str:
    if not shutil.which("resolvectl"):
        return ""
    rc, out = run(["resolvectl", "status"])
    return out if rc == 0 else ""


def resolved_dns_over_tls_mode() -> str:
    """Effective DNSOverTLS= mode from resolved.conf and its drop-ins, or ''.

    Read directly instead of asking systemd, so the check stays offline. Drop-ins
    are applied in lexical order, so the last setting wins, like systemd.
    """
    value = ""
    for path in ["/etc/systemd/resolved.conf"] + sorted(
            glob.glob("/etc/systemd/resolved.conf.d/*.conf")):
        for raw in read(path).splitlines():
            line = raw.split("#", 1)[0].strip()
            key, sep, val = line.partition("=")
            if sep and key.strip().lower() == "dnsovertls":
                value = val.strip().lower()
    return value if value in ("yes", "opportunistic", "no") else ""


# Speed checks

@check("Speed", 6, "Boot time")
def c_boot(ctx: Ctx) -> Out:
    if not (ctx.systemd and shutil.which("systemd-analyze")):
        return skip("needs systemd")
    _, out = run(["systemd-analyze"], 15)
    phases = parse_systemd_breakdown(out)
    secs = phases.get("total")
    if secs is None:
        secs = parse_systemd_total(out)
    if secs is None:
        return skip("boot time unavailable")
    msg = f"Boot takes {secs:.0f}s"
    if secs <= 30:
        return ok(msg)
    firmware = phases.get("firmware", 0.0) + phases.get("loader", 0.0)
    linux = max(0.0, secs - firmware)
    if firmware >= 5 and firmware > linux:
        # Blaming systemd units would send the user to the wrong layer: most
        # of this boot happens before the kernel is even loaded.
        msg += f" ({firmware:.0f}s firmware, {linux:.0f}s Linux)"
        fix = ("Enable Fast Boot in the firmware settings, update the firmware, and check the "
               f"boot device order; Linux itself takes only {linux:.0f}s.")
    else:
        if phases.get("userspace"):
            msg += f" ({phases['userspace']:.0f}s userspace)"
        fix = ("Find slow units with `systemd-analyze blame | head -15`, "
               "then disable what you don't need.")
    return (warn if secs <= 60 else bad)(msg, fix)


@check("Speed", 4, "Failed services")
def c_failed(ctx: Ctx) -> Out:
    if not ctx.systemd:
        if not shutil.which("rc-status"):
            return skip("needs systemd or OpenRC")
        rc, out = run(["rc-status", "--crashed"])
        if rc is None:
            return skip("rc-status unavailable")
        names = parse_rc_crashed(out)
        if not names:
            return ok("No crashed services (OpenRC)")
        msg = f"{len(names)} crashed: " + ", ".join(names[:4]) + ("..." if len(names) > 4 else "")
        return (warn if len(names) <= 2 else bad)(
            msg, f"See why: `rc-service {names[0]} status` and check its log in /var/log")
    rc, out = run(["systemctl", "--failed", "--no-legend", "--plain"])
    if rc is None:
        return skip("systemctl unavailable")
    names = [l.split()[0] for l in out.splitlines() if l.strip()]
    if not names:
        return ok("No failed services")
    msg = f"{len(names)} failed: " + ", ".join(names[:4]) + ("..." if len(names) > 4 else "")
    fix = f"See why: `systemctl status {names[0]}` and `journalctl -u {names[0]} -b`"
    return (warn if len(names) <= 2 else bad)(msg, fix)


@check("Speed", 5, "Available memory")
def c_memory(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("container memory limits are not host-wide")
    mi = meminfo()
    total = mi.get("MemTotal", 0)
    if not total or "MemAvailable" not in mi:
        return skip("can't read /proc/meminfo")
    avail = mi["MemAvailable"]
    pct = 100 * avail / total
    # MemAvailable, not MemFree: memory the kernel can hand out without swapping.
    msg = f"{human(avail)} available of {human(total)} ({pct:.0f}%)"
    if pct >= 20:
        return ok(msg)
    fix = "Close heavy apps. Top memory users: `ps -eo pid,comm,%mem --sort=-%mem | head -8`"
    return (warn if pct >= 10 else bad)(msg, fix)


@check("Speed", 3, "Swap")
def c_swap(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("host swap is not container-specific")
    mi = meminfo()
    ram = mi.get("MemTotal", 0)
    if not ram:
        return skip("can't read /proc/meminfo")
    total, free = mi.get("SwapTotal", 0), mi.get("SwapFree", 0)
    if total == 0:
        if ram < 8 * GiB:
            return warn(f"No swap and only {human(ram)} of RAM: when memory runs out "
                        f"a program is killed or the system hangs",
                        "Enable zram (compressed RAM swap), no disk needed.")
        return ok("No swap, but plenty of RAM")
    used = 100 * (total - free) / total
    if used > 50:
        # Swap % alone doesn't prove RAM is short now; tie the warning to MemAvailable.
        avail = mi.get("MemAvailable")
        if avail is not None and avail < 0.25 * ram:
            return warn(f"Swap is {used:.0f}% used and RAM is running short "
                        f"({human(avail)} available)", "Close heavy apps or add RAM.")
        # Idle pages in swap are normal while RAM is free.
        if avail is None:
            return ok(f"Swap is {used:.0f}% used; this kernel does not report available RAM")
        return ok(f"Swap is {used:.0f}% used, but {human(avail)} of RAM is available (idle pages in swap)")
    return ok(f"{human(total)} swap, {used:.0f}% used")


@check("Speed", 3, "Out-of-memory kills")
def c_oom(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("the host kernel log is not container-specific")
    count = parse_vmstat_oom(read("/proc/vmstat"))
    names: List[str] = []
    if ctx.systemd and shutil.which("journalctl"):
        rc, out = run(["journalctl", "-k", "--since", "7 days ago", "-g",
                       "Out of memory|oom-kill|Killed process", "--no-pager", "-o", "cat"], 10)
        if rc == 0:
            names = parse_oom_kills(out)
    if count is None and not names:
        return skip("can't read the kernel's OOM counter")
    if count:
        n, scope = count, "since boot"
    elif names:
        n, scope = len(names), "in the last 7 days"
    else:
        return ok("No out-of-memory kills since boot")
    msg = f"{n} process{'es' if n != 1 else ''} killed by the kernel {scope}"
    if names:
        msg += f", last: {names[-1]}"
    fix = ("Find the memory hog: `ps -eo pid,comm,rss --sort=-rss | head -8`, "
           "then add RAM or zram/swap, or cap the service.")
    return (warn if n < 3 else bad)(msg, fix)


@check("Speed", 3, "CPU load")
def c_load(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("host load average is not container-specific")
    try:
        l5 = os.getloadavg()[1]
    except (OSError, AttributeError):
        return skip("load average unavailable")
    cpus = os.cpu_count() or 1
    ratio = l5 / cpus
    msg = f"5-minute load {l5:.2f} on {cpus} core(s)"
    if ratio <= 0.7:
        return ok(msg)
    fix = "Find the culprit: `ps -eo pid,comm,%cpu --sort=-%cpu | head -8`"
    return (warn if ratio <= 1.5 else bad)(msg, fix)


@check("Speed", 3, "SSD TRIM")
def c_trim(ctx: Ctx) -> Out:
    ssd = False
    for d in glob.glob("/sys/block/*"):
        name = os.path.basename(d)
        if name.startswith(("loop", "ram", "zram", "dm-", "sr", "md", "nbd", "fd")):
            continue
        if read(d + "/removable") == "1":
            continue                      # USB sticks / SD cards are not the system SSD
        if read(d + "/queue/rotational") == "0":
            ssd = True
    if not ssd:
        return skip("no SSD detected")
    system_mounts = {"/", "/nix", "/home", "/var", "/boot", "/sysroot", ctx.home}
    for line in read("/proc/mounts").splitlines():
        f = line.split()
        if len(f) >= 4 and f[1] in system_mounts and "discard" in f[3].split(","):
            return ok("Continuous discard is on")
    if not ctx.systemd:
        return skip("needs systemd")
    _, out = run(["systemctl", "is-enabled", "fstrim.timer"])
    state = out.strip().splitlines()[-1] if out.strip() else ""
    if state == "enabled":
        return ok("Weekly TRIM timer is on")
    if units_active(ctx, ["fstrim.timer"]):
        return ok("TRIM timer is active")         # e.g. NixOS reports 'linked' rather than 'enabled'
    if "not-found" in state or not state:
        # No timer unit at all: some setups run fstrim from cron/anacron instead.
        cron = any("fstrim" in read(p)
                   for p in ("/etc/crontab", "/etc/cron.d/fstrim",
                             "/etc/cron.weekly/fstrim", "/etc/cron.daily/fstrim"))
        if cron:
            return ok("fstrim runs from cron")
        return skip("fstrim.timer not installed on this system")
    if state == "masked":
        return warn("SSD found but the TRIM timer is masked",
                    "TRIM keeps SSD performance from degrading.",
                    "sudo systemctl unmask fstrim.timer && sudo systemctl enable --now fstrim.timer")
    return warn("SSD found but periodic TRIM is off",
                "TRIM keeps SSD performance from degrading.",
                "sudo systemctl enable --now fstrim.timer")


@check("Speed", 2, "Startup apps")
def c_autostart(ctx: Ctx) -> Out:
    names = autostart_entries(os.path.join(ctx.home, ".config", "autostart"))
    n = len(names)
    if n == 0:
        return ok("No apps in ~/.config/autostart")
    if n <= 6:
        return ok(f"{n} app(s) start at login from ~/.config/autostart")
    msg = f"{n} apps start at login from ~/.config/autostart: " + ", ".join(names[:5]) + "..."
    fix = "Disable what you don't use (your desktop's Startup Applications, or delete the .desktop file)."
    return (warn if n <= 12 else bad)(msg, fix)


# Security checks

@check("Security", 7, "Firewall")
def c_firewall(ctx: Ctx) -> Out:
    strong = units_active(ctx, ["ufw", "firewalld", "firewall"])   # "firewall" = NixOS
    if strong:
        return ok("Active: " + ", ".join(strong))
    weak = units_active(ctx, ["nftables", "iptables"])
    cmds = {
        "apt-get": "sudo apt install ufw\nsudo ufw default deny incoming\n"
                   "# sudo ufw allow ssh   <- uncomment if you log in over SSH!\nsudo ufw enable",
        "dnf": "sudo systemctl enable --now firewalld",
        "pacman": "sudo pacman -S ufw\nsudo ufw default deny incoming\n"
                  "# sudo ufw allow ssh   <- uncomment if you log in over SSH!\n"
                  "sudo systemctl enable --now ufw\nsudo ufw enable",
        "zypper": "sudo zypper install firewalld\nsudo systemctl enable --now firewalld",
    }
    fix = ("Set `networking.firewall.enable = true;` in your NixOS configuration and rebuild."
           if ctx.nixos else "Turn on a host firewall (ufw or firewalld).")
    if ctx.is_root:
        _, nft = run(["nft", "list", "ruleset"])
        if nft_input_filtered(nft):
            return ok("nftables rules filter incoming traffic")
        _, ipt = run(["iptables", "-S"])
        if iptables_input_filtered(ipt):
            return ok("iptables rules filter incoming traffic")
        if weak:
            return warn("Active: " + ", ".join(weak) + " (no drop/reject rule found)",
                        "Load a firewall policy, or switch to ufw/firewalld.",
                        cmds.get(ctx.pm or "", ""))
    elif weak:
        # The unit is running, but reading its rules needs root: do not guess.
        return skip("Active: " + ", ".join(weak) + " (run as root to verify its rules)")
    elif not ctx.systemd:
        return skip("needs systemd or root to inspect")
    msg = "No active firewall service found" + ("" if ctx.is_root else " (run as root to inspect raw rules)")
    return warn(msg, fix, cmds.get(ctx.pm or "", ""))


@check("Security", 4, "Clock sync")
def c_timesync(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("containers use the host clock")
    synced = None
    if shutil.which("timedatectl"):
        rc, out = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], 4)
        if rc == 0:
            synced = parse_timedatectl_sync(out)
    offset, leap = None, ""
    if shutil.which("chronyc"):
        rc, out = run(["chronyc", "tracking"], 4)
        if rc == 0:
            parsed = parse_chronyc_tracking(out)
            if parsed:
                offset, leap = parsed
    if "not synchron" in leap:
        return warn(f"chrony says the clock is not synchronised ({clean(leap)})",
                    "Point chrony at a reachable NTP server, then restart it.",
                    "sudo systemctl restart chronyd")
    if offset is not None:
        if offset > 10:
            return bad(f"Clock is {offset:.0f}s off", "Step the clock before TLS, logins or updates break.",
                       "sudo chronyc makestep")
        if offset > 1:
            return warn(f"Clock is {offset:.2f}s off (chrony)",
                        "Check that the NTP server is reachable.", "sudo chronyc makestep")
        return ok(f"Clock is in sync (chrony, {offset:.3f}s off)")
    if synced is False:
        return warn("System clock is not synchronised",
                    "Turn on NTP so certificates, package signatures and logins keep working.",
                    "sudo timedatectl set-ntp true")
    if synced is True:
        return ok("System clock is synchronised")
    return skip("no NTP client found")


@check("Security", 6, "Pending updates")
def c_updates(ctx: Ctx) -> Out:
    sec, age, total = 0, None, 0
    if ctx.nixos:
        return nixos_update_check()
    if ctx.pm == "apt-get":
        age = index_age_days("/var/lib/apt/lists/*Packages*")
        if age is None:
            return skip("package list is empty: run `sudo apt update` first")
        rc, out = run(["apt", "list", "--upgradable"], 20)
        if rc != 0:
            return skip("couldn't read the apt cache")
        total, sec = parse_apt_upgradable(out)
        cmd = "sudo apt update && sudo apt upgrade"
    elif ctx.pm == "dnf":
        age = index_age_days("/var/cache/dnf/*/repodata/repomd.xml", "/var/cache/libdnf5/*/repodata/repomd.xml")
        rc, out = run(["dnf", "-q", "--cacheonly", "check-update"], 30)
        if rc not in (0, 100):
            return skip("couldn't read the dnf cache")
        total = len(re.findall(r"^\S+\.\S+\s+\S+\s+\S+\s*$", out, re.M))
        if rc == 100 and total == 0:
            return skip("couldn't parse dnf's update list")
        cmd = "sudo dnf upgrade --refresh"
    elif ctx.pm == "pacman":
        age = index_age_days("/var/lib/pacman/sync/*.db")
        if age is None:
            return skip("package list is empty: run `sudo pacman -Syu` first")
        rc, out = run(["pacman", "-Qu"], 20)
        if rc not in (0, 1):
            return skip("couldn't read the pacman database")
        total = len([l for l in out.splitlines() if l.strip()]) if rc == 0 else 0
        cmd = "sudo pacman -Syu"
    elif ctx.pm == "zypper":
        age = index_age_days("/var/cache/zypp/solv/*/solv",
                             "/var/cache/zypp/raw/*/repodata/repomd.xml")
        rc, out = run(["zypper", "--non-interactive", "--no-refresh", "--xmlout",
                       "list-updates"], 30)
        total = parse_zypper_updates(out)
        if total is None:
            return skip("couldn't read zypper's local metadata (run `sudo zypper refresh`)")
        if total == 0 and rc != 0:
            return skip("couldn't read zypper's local metadata (run `sudo zypper refresh`)")
        cmd = "sudo zypper update"
    elif ctx.pm == "apk":
        if not glob.glob("/var/cache/apk/APKINDEX.*"):
            return skip("package index is empty: run `sudo apk update` first")
        age = index_age_days("/var/cache/apk/APKINDEX.*")
        rc, out = run(["apk", "--no-network", "version", "-l", "<"], 20)
        total = parse_apk_updates(out)
        if total == 0 and rc != 0:
            return skip("couldn't read the apk index")
        cmd = "sudo apk upgrade"
    elif ctx.pm == "rpm-ostree":
        rc, out = run(["rpm-ostree", "status", "--json"], 20)
        parsed = parse_rpm_ostree_status(out) if rc == 0 else None
        if parsed is None:
            return skip("couldn't read rpm-ostree status")
        staged, built = parsed
        if staged:
            return warn("An rpm-ostree update is downloaded and waits for a reboot",
                        "Reboot to apply it.", "sudo systemctl reboot")
        if built is None:
            return skip("rpm-ostree has no offline update list")
        if built > 90:
            return warn(f"System image was built {built:.0f} days ago",
                        "Check for a newer image when you are online.",
                        "sudo rpm-ostree upgrade")
        return ok(f"System image built {built:.0f} day(s) ago "
                  "(rpm-ostree checks for updates online)")
    elif ctx.pm == "xbps-install":
        rc, out = run(["xbps-install", "-un"], 20)
        total = parse_xbps_updates(out)
        if total == 0 and rc != 0:
            return skip("couldn't read the xbps index")
        cmd = "sudo xbps-install -Su"
    elif ctx.pm == "emerge":
        return skip("Portage needs a full dependency calculation; not checked offline")
    else:
        return skip("package manager not supported")
    if total == 0:
        if age is not None and age > 14:
            return warn(f"Your package list is {age:.0f} days old, so 'up to date' can't be trusted",
                        "Refresh the list and install what's waiting.", cmd)
        return ok("Up to date (per your latest package list)")
    msg = f"{total} update(s) waiting" + (f", {sec} security" if sec else "")
    return (bad if sec or total > 50 else warn)(msg, "Install them: most are security and bug fixes.", cmd)


@check("Security", 4, "Reboot required")
def c_reboot(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("containers share the host kernel")
    for marker in ("/run/reboot-required", "/var/run/reboot-required"):
        if os.path.exists(marker):
            pkgs = read("/run/reboot-required.pkgs") or read("/var/run/reboot-required.pkgs")
            names = sorted({clean(x) for x in pkgs.splitlines() if x.strip()})
            detail = "Installed updates are waiting for a reboot"
            if names:
                detail += ": " + ", ".join(names[:3]) + ("..." if len(names) > 3 else "")
            return warn(detail, "Reboot when convenient so the new kernel and libraries are used.")
    if ctx.nixos:
        # A rebuild can change the initrd (new modules, LUKS keys) while the
        # kernel stays the same, so both must match the booted generation.
        for current_link, booted_link in (
                ("/run/current-system/kernel", "/run/booted-system/kernel"),
                ("/run/current-system/initrd", "/run/booted-system/initrd")):
            if not (os.path.exists(current_link) and os.path.exists(booted_link)):
                continue
            if os.path.realpath(current_link) != os.path.realpath(booted_link):
                return warn("The current NixOS generation has a newer kernel or boot image",
                            "Reboot to boot the generation you built.")
    if shutil.which("needs-restarting"):
        rc, _ = run(["needs-restarting", "-r"], 20)
        if rc == 1:
            return warn("Installed updates are waiting for a reboot",
                        "Reboot when convenient so the new kernel and libraries are used.")
        if rc == 0:
            return ok("Running kernel is current")
    running = platform.release()
    newest = newer_kernel(installed_kernels(), running)
    if newest:
        return warn(f"Kernel {newest} is installed but {running} is running",
                    "Reboot to boot the installed kernel.")
    return ok("No reboot pending")


@check("Security", 5, "SSH server hardening")
def c_ssh(ctx: Ctx) -> Out:
    ports = parse_ss_listeners(ss_output() or "")
    ssh_named = any(name in ("sshd", "dropbear") for _, name in ports)
    ssh_running = any(name in ("sshd", "dropbear") for name in running_processes())
    # A non-root `ss` cannot see the process behind a root-owned listener, so an
    # unnamed port 22 still counts. A named non-SSH process on port 22 does not.
    port22_ssh = any(p == "22" and (not name or name in ("sshd", "dropbear"))
                     for p, name in ports)
    if not ssh_named and not ssh_running and not port22_ssh \
            and not units_active(ctx, ["ssh", "sshd"]):
        return skip("no SSH server detected")
    texts = sshd_config_texts("/etc/ssh/sshd_config")
    if not texts:
        for f in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
            texts.extend(sshd_config_texts(f))
    if not texts:
        return skip("can't read sshd_config")
    cfg = parse_sshd_config(texts)
    if cfg.get("permitrootlogin") == "yes":
        return bad("Root can log in over SSH",
                   "Set `PermitRootLogin no` in /etc/ssh/sshd_config, then reload sshd.")
    if password_login_possible(cfg):
        return warn("SSH accepts passwords (brute-force risk)",
                    "Use keys and set `PasswordAuthentication no` and "
                    "`KbdInteractiveAuthentication no`. Test your key first!")
    return ok("SSH: password logins are off")


@check("Security", 5, "Open network ports")
def c_ports(ctx: Ctx) -> Out:
    out = ss_output()
    if out is None:
        return skip("`ss` unavailable")
    ports = parse_ss_listeners(out)
    if not ports:
        return ok("No TCP ports open beyond localhost")
    shown = ", ".join(f"{p} ({n})" if n else p for p, n in ports[:6]) + ("..." if len(ports) > 6 else "")
    msg = f"{len(ports)} TCP port(s) open to the network: {shown}"
    fix = "Bind dev servers to 127.0.0.1 and stop unused services. Inspect with `sudo ss -ltnp`."
    return (warn if len(ports) <= 3 else bad)(msg, fix)


@check("Security", 4, "AppArmor / SELinux")
def c_mac(ctx: Ctx) -> Out:
    selinux = read("/sys/fs/selinux/enforce")
    if selinux == "1":
        return ok("SELinux is enforcing")
    if read("/sys/module/apparmor/parameters/enabled") == "Y":
        return ok("AppArmor is enabled")
    if selinux == "0":
        return warn("SELinux is permissive: it logs problems but blocks nothing",
                    "Set SELinux to enforcing (`setenforce 1`, and persist it in /etc/selinux/config).")
    fix = ("Set `security.apparmor.enable = true;` in your NixOS configuration and rebuild."
           if ctx.nixos else "Enable AppArmor or SELinux (whichever your distribution ships).")
    return warn("No AppArmor or SELinux sandboxing is active", fix)


@check("Security", 4, "CPU vulnerability mitigations")
def c_cpuvuln(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("CPU mitigations are set by the host kernel")
    base = "/sys/devices/system/cpu/vulnerabilities"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return skip("kernel does not expose CPU vulnerability status")
    vulnerable, mitigated = parse_cpu_vulnerabilities(
        {name: read(os.path.join(base, name)) for name in names})
    if vulnerable:
        shown = ", ".join(vulnerable[:4]) + ("..." if len(vulnerable) > 4 else "")
        word = "vulnerability" if len(vulnerable) == 1 else "vulnerabilities"
        return bad(f"{len(vulnerable)} CPU {word} unmitigated: {shown}",
                   "Update the kernel, CPU microcode and firmware; keep SMT off if a "
                   "mitigation requires it.")
    if mitigated:
        word = "vulnerability" if len(mitigated) == 1 else "vulnerabilities"
        return ok(f"{len(mitigated)} CPU {word} mitigated or not affected")
    return skip("no readable CPU vulnerability status")


@check("Security", 3, "Disk encryption (laptops)")
def c_encryption(ctx: Ctx) -> Out:
    if not ctx.laptop:
        return skip("only checked on laptops")
    # On NixOS and live images / is a tmpfs, so judge the device that holds real data.
    targets = ((ctx.home, "your home folder"), ("/nix", "/nix"), ("/", "the root filesystem"))
    src, label = "", ""
    for path, name in targets:
        if not os.path.exists(path):
            continue
        rc, out = run(["findmnt", "-no", "SOURCE", "-T", path])
        if rc != 0 or not out:
            # very old util-linux has no -T; the plain form still works for mount points
            _, out = run(["findmnt", "-no", "SOURCE", path])
        cand = re.sub(r"\[.*\]$", "", out.strip())
        if cand.startswith("/dev/"):
            src, label = cand, name
            break
    if not src:
        return skip("no block device holds your home folder or /")
    rc, types = run(["lsblk", "-srno", "TYPE", src])
    if rc != 0 or not types:
        return skip("can't inspect the disk holding " + label)
    if "crypt" in types.split():
        return ok(f"The disk holding {label} is encrypted (LUKS)")
    return warn(f"Full-disk LUKS encryption is off for {label}: "
                "anyone with the disk can read the unencrypted parts",
                "Use full-disk LUKS at install time, or per-user encryption "
                "(fscrypt / systemd-homed) for your files.")


@check("Security", 3, "SSH key permissions")
def c_sshkeys(ctx: Ctx) -> Out:
    d = os.path.join(ctx.home, ".ssh")
    if not os.path.isdir(d):
        return skip("no ~/.ssh folder")
    loose: List[str] = []
    found_private = False
    try:
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if f.endswith(".pub") or not os.path.isfile(p):
                continue
            try:
                AUDIT.read(p)
                with open(p, "rb") as fh:
                    head = fh.read(120)
                if b"PRIVATE KEY" in head:
                    found_private = True
                    if os.stat(p).st_mode & 0o077:
                        loose.append(p)
            except OSError:
                continue
        dir_loose = bool(os.stat(d).st_mode & 0o077)
    except OSError:
        return skip("can't read ~/.ssh")
    if loose:
        names = ", ".join(clean(os.path.basename(p)) for p in loose)
        # Never put control characters in a generated script.
        safe = [p for p in loose if not _CTRL.search(p)]
        cmd = ("chmod 700 ~/.ssh\nchmod 600 " + " ".join(shlex.quote(p) for p in safe)) if safe else ""
        fix = "Tighten the permissions (SSH may refuse these keys anyway)."
        if len(safe) < len(loose):
            fix += " Some file names contain control characters: fix those by hand."
        return bad(f"Private key readable by other users: {names}", fix, cmd)
    if dir_loose:
        return warn("~/.ssh is accessible by other users", "Run `chmod 700 ~/.ssh`.", "chmod 700 ~/.ssh")
    if not found_private:
        return skip("no private SSH keys in ~/.ssh")
    return ok("Key permissions look right")


# Privacy checks

@check("Privacy", 5, "Telemetry & crash reporters")
def c_telemetry(ctx: Ctx) -> Out:
    found, cmds = [], []
    for unit, label in (("whoopsie", "whoopsie (Ubuntu crash reports)"),
                        ("abrtd", "abrtd (Fedora crash reports)")):
        if units_active(ctx, [unit]):
            found.append(label)
            cmds.append(f"sudo systemctl disable --now {unit}")
    if re.search(r'^PARTICIPATE\s*=\s*"?yes', read("/etc/popularity-contest.conf"), re.M | re.I):
        found.append("popularity-contest (package usage stats)")
        cmds.append("sudo apt remove popularity-contest")
    if not found:
        return ok("No known telemetry or crash-report uploaders found")
    return warn("Active: " + ", ".join(found), "Disable what you don't need.", "\n".join(cmds))


@check("Privacy", 3, "Encrypted DNS")
def c_dns(ctx: Ctx) -> Out:
    proxies = units_active(ctx, ["dnscrypt-proxy", "stubby"])
    status = resolvectl_status()
    if not (ctx.systemd and status):
        if proxies:
            return ok("An encrypted DNS proxy is running")
        return skip("systemd-resolved not in use")
    if "127.0.0.53" not in read("/etc/resolv.conf"):
        return skip("systemd-resolved isn't your active resolver")
    m = re.search(r"DNSOverTLS[=:]\s*(yes|opportunistic|no)", status, re.I)
    mode = (m.group(1).lower() if m else "") or resolved_dns_over_tls_mode()
    # resolvectl shows the running state: a stale config file must not override it.
    disabled = "-DNSOverTLS" in status and "+DNSOverTLS" not in status
    if not disabled and ("+DNSOverTLS" in status or mode in ("yes", "opportunistic")):
        if mode == "opportunistic":
            return ok("DNS-over-TLS is opportunistic: encrypted when the server supports it, "
                      "with a plaintext fallback")
        if mode == "yes":
            return ok("DNS-over-TLS is enforced, with no plaintext fallback")
        return ok("DNS-over-TLS is enabled")
    if proxies:
        return ok("An encrypted DNS proxy is running")
    cmd = ("# pick the DNS provider YOU trust; 'opportunistic' falls back if a network blocks port 853\n"
           "sudo mkdir -p /etc/systemd/resolved.conf.d\n"
           "printf '[Resolve]\\nDNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net\\nDNSOverTLS=opportunistic\\n'"
           " | sudo tee /etc/systemd/resolved.conf.d/lscore-dot.conf\n"
           "sudo systemctl restart systemd-resolved")
    return warn("System DNS lookups are unencrypted: the network can see every name you resolve",
                "Enable DNS-over-TLS in systemd-resolved (or DNS-over-HTTPS in your browser).", cmd)


_UDP_ANNOUNCE_PORT = {label: port for port, label in _UDP_ANNOUNCE.items()}


@check("Privacy", 3, "Network announcements")
def c_broadcast(ctx: Ctx) -> Out:
    known, raw, cmds, checked = [], [], [], set()
    avahi = units_active(ctx, ["avahi-daemon", "avahi-daemon.socket"])
    if ctx.systemd:
        checked.add("Avahi")
    if avahi:
        known.append("Avahi/mDNS")
        cmds += ["# note: printer / Chromecast auto-discovery stops working",
                 "sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket"]
    status = resolvectl_status()
    if status:
        checked.update(("mDNS", "LLMNR"))
        if re.search(r"^\s*Protocols:.*\+mDNS", status, re.M) and not avahi:
            known.append("mDNS (systemd-resolved)")
            cmds += ["sudo mkdir -p /etc/systemd/resolved.conf.d",
                     "printf '[Resolve]\\nMulticastDNS=no\\n' | sudo tee "
                     "/etc/systemd/resolved.conf.d/lscore-nomdns.conf",
                     "sudo systemctl restart systemd-resolved"]
        if re.search(r"^\s*Protocols:.*\+LLMNR", status, re.M):
            known.append("LLMNR (systemd-resolved)")
            cmds += ["sudo mkdir -p /etc/systemd/resolved.conf.d",
                     "printf '[Resolve]\\nLLMNR=no\\n' | sudo tee "
                     "/etc/systemd/resolved.conf.d/lscore-nollmnr.conf",
                     "sudo systemctl restart systemd-resolved"]
    udp = ss_udp_output()
    if udp is not None:
        checked.update(("mDNS", "LLMNR", "SSDP", "WS-Discovery"))
        for label, proc in parse_udp_announcements(udp):
            if any(label.lower() in item.lower() for item in known):
                continue                       # already reported through its service
            port = _UDP_ANNOUNCE_PORT[label]
            if proc:
                raw.append(f"{label} ({proc}, UDP {port})")
                if ctx.systemd and proc in ("miniupnpd", "wsdd", "wsdd2"):
                    cmds.append(f"sudo systemctl disable --now {proc}")
            else:
                # A bound socket proves the protocol is in use, not that this
                # machine advertises itself: say only what the evidence shows.
                raw.append(f"{label} (UDP {port})")
    if not known and not raw:
        labels = sorted(checked)
        if not labels:
            return skip("no announcement services could be inspected")
        return ok("No " + ", ".join(labels) + " announcements found")
    parts = []
    if known:
        parts.append(" + ".join(known) +
                     " announce this machine on every network, public Wi-Fi included")
    if raw:
        verb = "is" if len(raw) == 1 else "are"
        parts.append(" + ".join(raw) + f" {verb} listening for discovery traffic")
    detail = "; ".join(parts)
    fix = ("Disable what you don't need (printer and Chromecast discovery stop working)."
           if known else "Turn off discovery in the app that owns the socket, or block the port.")
    if any("UDP" in item for item in raw):
        fix += " Find the owner with `sudo ss -lunp`."
    return warn(detail, fix, "\n".join(cmds))


def group_access_others(gid: int, owner_uid: int) -> Tuple[str, bool]:
    """(group name, whether another local account can use this group).

    Reads /etc/passwd and /etc/group directly, so no NSS/LDAP network lookup is
    triggered. It only claims another member when a local account names one.
    """
    name = str(gid)
    owner = ""
    users: Dict[str, int] = {}
    members = set()
    for line in read("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        try:
            uid, pgid = int(parts[2]), int(parts[3])
        except ValueError:
            continue
        users[parts[0]] = uid
        if uid == owner_uid:
            owner = parts[0]
        if pgid == gid:
            members.add(parts[0])
    for line in read("/etc/group").splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        try:
            ggid = int(parts[2])
        except ValueError:
            continue
        if ggid == gid:
            if parts[0]:
                name = parts[0]
            members.update(m.strip() for m in parts[3].split(",") if m.strip())
    members.discard(owner)
    # Names that are not in the local passwd (LDAP, NIS) cannot be judged
    # offline; treat them as unknown rather than as another local account.
    others = [m for m in members if users.get(m, owner_uid) != owner_uid]
    return name, bool(others)


@check("Privacy", 2, "Home folder privacy")
def c_home(ctx: Ctx) -> Out:
    try:
        st = os.stat(ctx.home)
    except OSError:
        return skip("can't read home folder")
    mode = st.st_mode
    shown = mode & 0o777
    if mode & 0o007:
        return warn(f"Your home folder is accessible by other users (mode {shown:o})",
                    "Remove access for other users.", "chmod o-rwx ~")
    if mode & 0o070:
        group, others = group_access_others(st.st_gid, st.st_uid)
        if others:
            return warn(f"Your home folder is accessible to other members of group {group} "
                        f"(mode {shown:o})",
                        "Remove group access if you don't share this folder.",
                        "chmod g-rwx ~")
        return ok(f"Home folder is private (group {group} has access, "
                  "with no other local member)")
    return ok("Home folder is private")


# Storage checks

def _disk_paths(ctx: Ctx) -> List[str]:
    """Local writable filesystems from the mount table, plus the usual system paths."""
    paths = []
    text = read("/proc/self/mounts") or read("/proc/mounts")
    for mount, fstype, options in parse_mounts(text):
        if _CTRL.search(mount) or fstype in _PSEUDO_FS or fstype in _NETWORK_FS:
            continue
        if fstype in ("tmpfs", "ramfs", "overlay", "aufs") and mount != "/":
            continue
        if "ro" in options.split(","):
            continue
        paths.append(mount)
    paths.extend(("/", "/nix", "/var", "/boot", "/boot/efi", "/sysroot", ctx.home))
    return list(dict.fromkeys(p for p in paths if p and not _CTRL.search(p)))


def _is_removable(dev: int) -> bool:
    """True when st_dev is a removable block device (USB stick, card reader)."""
    try:
        node = os.path.realpath(os.path.join(
            "/sys/dev/block", f"{os.major(dev)}:{os.minor(dev)}"))
    except (OSError, ValueError):
        return False
    for _ in range(3):
        flag = read(os.path.join(node, "removable"))
        if flag:
            return flag == "1"
        parent = os.path.dirname(node)
        if parent == node:
            break
        node = parent
    return False


_HOME_PREFIXES = ("/home/", "/var/home/")


def _disk_label(path: str, home: str) -> str:
    """A mount path that never contains a user name."""
    if home not in ("", "/") and (path == home or path.startswith(home + "/")):
        return "~" + path[len(home):]
    for prefix in _HOME_PREFIXES:
        if path.startswith(prefix):
            rest = path[len(prefix):]
            _first, sep, tail = rest.partition("/")
            return prefix + "*" + (sep + tail if sep else "")
    return path


def _disk_cmd_path(path: str, home: str) -> str:
    """A shell-safe path for du, with $HOME standing in for the current home."""
    if home not in ("", "/") and path == home:
        return "$HOME"
    if home not in ("", "/") and path.startswith(home + "/"):
        return "$HOME/" + shlex.quote(path[len(home) + 1:])
    for prefix in _HOME_PREFIXES:
        if path.startswith(prefix):
            return shlex.quote(prefix.rstrip("/"))   # scan the parent, not the user name
    return shlex.quote(path)


def _scan_mounts(paths: List[str]) -> List[str]:
    """Outermost mount points of one filesystem, without duplicates or nesting."""
    out: List[str] = []
    for p in sorted(set(paths), key=lambda x: (len(x), x)):
        if any(p == q or p.startswith(q.rstrip("/") + "/") for q in out):
            continue
        out.append(p)
    return out


@check("Storage", 6, "Disk space")
def c_disk(ctx: Ctx) -> Out:
    """Judge the tightest local filesystem that holds data; / alone may be a tmpfs."""
    seen, cands, by_dev = set(), [], {}
    home = os.path.abspath(ctx.home).rstrip(os.sep) or os.sep
    for path in _disk_paths(ctx):
        try:
            st = os.statvfs(path)
            dev = os.stat(path).st_dev        # statvfs_result carries no device id
        except OSError:
            continue
        if not st.f_blocks:
            continue
        if getattr(st, "f_flag", 0) & getattr(os, "ST_RDONLY", 1):
            continue                          # read-only: 0 free is by design
        if path != "/" and _is_removable(dev) and not (
                home == path or home.startswith(path.rstrip("/") + "/")):
            continue                          # a full USB stick is not machine health
        frsize = st.f_frsize or getattr(st, "f_bsize", 0)
        total = st.f_blocks * frsize
        if total <= 0:
            continue
        # Keep every mount of this device: NixOS mounts one ext4 at /nix,
        # /home, /var, ... and the fix must scan all of them, not just one.
        by_dev.setdefault(dev, []).append(path)
        if dev in seen:
            continue
        seen.add(dev)
        avail = max(0, min(st.f_bavail * frsize, total))
        used = max(0, total - st.f_bfree * frsize)
        reserved = max(0, total - used - avail)           # root-reserved blocks
        used_pct = 100 * used / total if total else 0.0   # the same % fastfetch shows
        free_pct = 100 * avail / total if total else 0.0  # what the thresholds judge
        if st.f_files:
            inode_pct = 100 * min(max(st.f_ffree, 0), st.f_files) / st.f_files
        else:
            inode_pct = None
        effective = min(free_pct, inode_pct) if inode_pct is not None else free_pct
        cands.append((effective, avail, total, path, free_pct, inode_pct,
                      used_pct, used, reserved, dev))
    if not cands:
        return skip("can't read disk usage")
    _, avail, total, path, free_pct, inode_pct, used_pct, used, reserved, dev = min(
        cands, key=lambda c: (c[0], c[1]))
    label = _disk_label(path, home)
    msg = (f"{used_pct:.0f}% used ({human2(used)} of {human2(total)}), "
           f"{human2(avail)} free ({free_pct:.2f}%)")
    if reserved and reserved * 100 >= total:            # at least 1% of the filesystem
        msg += f", {human2(reserved)} reserved"
    if inode_pct is not None and inode_pct < 20:
        msg += f", inodes {inode_pct:.0f}% free"
    if path != "/":
        msg += f" on {label}"
    mounts = _scan_mounts(by_dev.get(dev, [path]))
    scan = " ".join(_disk_cmd_path(p, home) for p in mounts)
    fix = (f"Find the big folders: `du -xh {scan} --max-depth=2 "
           f"2>/dev/null | sort -h | tail -15`")
    effective = min(free_pct, inode_pct) if inode_pct is not None else free_pct
    # journald keeps 15% free by default (SystemKeepFree=); below 10% is critical.
    if effective < 10:
        return bad(msg, fix)
    if effective < 15:
        return warn(msg, fix)
    return ok(msg)


@check("Storage", 6, "RAID health")
def c_raid(ctx: Ctx) -> Out:
    text = read("/proc/mdstat")
    if not text or not re.search(r"^md\d+\s*:", text, re.M):
        return skip("no software RAID arrays")
    problems = parse_mdstat(text)
    if not problems:
        return ok("Software RAID arrays are healthy")
    detail = ", ".join(f"{name} ({state})" for name, state in problems[:3])
    if len(problems) > 3:
        detail += ", ..."
    if any(state in ("degraded", "inactive", "read-only") for _name, state in problems):
        return bad(f"Software RAID problem: {detail}",
                   "Inspect `cat /proc/mdstat` and `sudo mdadm --detail /dev/mdX`; "
                   "replace any failed disk and let the array rebuild.")
    return warn(f"Software RAID rebuilding: {detail}",
                "Leave the machine on until the rebuild finishes; watch `cat /proc/mdstat`.")


@check("Storage", 5, "Read-only filesystems")
def c_romount(ctx: Ctx) -> Out:
    if getattr(ctx, "container", False):
        return skip("container mounts are managed by the host")
    ro = parse_ro_mounts(read("/proc/self/mountinfo"), parse_fstab_ro(read("/etc/fstab")))
    if not ro:
        return ok("All data filesystems are writable")
    shown = ", ".join(f"{mnt} ({fstype})" for mnt, _dev, fstype in ro[:3])
    if len(ro) > 3:
        shown += f" and {len(ro) - 3} more"
    detail = ("Read-only: " if len(ro) == 1 else f"{len(ro)} read-only filesystems: ") + shown
    fix = ("Check `sudo dmesg | grep -iE 'error|read-only'` and run fsck from a rescue system; "
           "a system filesystem turns read-only when the kernel finds errors.")
    if any(mnt in _CRITICAL_MOUNTS for mnt, _dev, _fstype in ro):
        return bad(detail + " — writes will fail", fix)
    return warn(detail, "If you didn't mount it read-only yourself, check the kernel log for errors.")


@check("Storage", 3, "Package cache")
def c_pkgcache(ctx: Ctx) -> Out:
    # dnf5 keeps packages under libdnf5, so both trees must be counted or a
    # Fedora 41+ machine looks like it has an empty cache.
    spec = {"apt-get": (["/var/cache/apt/archives"], "sudo apt clean"),
            "dnf": (["/var/cache/dnf", "/var/cache/libdnf5"], "sudo dnf clean packages"),
            "pacman": (["/var/cache/pacman/pkg"],
                       "sudo paccache -rk2   # needs the pacman-contrib package"),
            "zypper": (["/var/cache/zypp/packages"], "sudo zypper clean --all"),
            "apk": (["/var/cache/apk"], "sudo apk cache clean"),
            "xbps-install": (["/var/cache/xbps"], "sudo xbps-remove -O"),
            "emerge": (["/var/cache/distfiles"],
                       "sudo eclean-dist -d   # needs app-portage/gentoolkit")}
    if ctx.nixos:
        return skip("not applicable on NixOS (see Unused packages)")
    if ctx.pm == "rpm-ostree":
        return skip("not applicable on immutable rpm-ostree systems")
    if ctx.pm not in spec:
        return skip("package manager not supported")
    paths, cmd = spec[ctx.pm]
    size, done, deadline = 0, True, time.monotonic() + 4.0
    for path in paths:
        part, finished = dir_size(path, budget=max(0.0, deadline - time.monotonic()))
        size += part
        done = done and finished
    msg = f"Package cache is {'' if done else 'at least '}{human(size)}"
    if size < GiB:
        return ok(msg)
    return (warn if size < 4 * GiB else bad)(msg, "Clear downloaded packages you no longer need.", cmd)


@check("Storage", 3, "System logs")
def c_journal(ctx: Ctx) -> Out:
    if not (ctx.systemd and shutil.which("journalctl")):
        return skip("needs systemd")
    _, out = run(["journalctl", "--disk-usage"])
    size = parse_journal_bytes(out)
    exact = True
    if not size:
        # A minimal journalctl can print 0 B when it cannot read the journal
        # files (e.g. an unsupported compression feature). Count the bytes on
        # disk instead, so a real journal is not reported as empty.
        on_disk = 0
        for path in ("/var/log/journal", "/run/log/journal"):
            if os.path.isdir(path):
                part, done = dir_size(path)
                on_disk += part
                exact = exact and done
        if on_disk:
            size = on_disk
        elif size is None or not exact:
            return skip("can't read the journal size")
    msg = f"Journal logs use {'' if exact else 'at least '}{human(size)}"
    # journald's default SystemMaxUse is 10% of the filesystem, capped at 4 GiB.
    if size <= 4 * GiB:
        return ok(msg)
    return (warn if size <= 10 * GiB else bad)(
        msg, "Trim them, and cap future growth with SystemMaxUse=500M in /etc/systemd/journald.conf.",
        "sudo journalctl --vacuum-size=500M")


@check("Storage", 3, "User cache (~/.cache)")
def c_usercache(ctx: Ctx) -> Out:
    if not os.path.isdir(ctx.cache_home):
        return ok("No cache folder")
    size, done = dir_size(ctx.cache_home)
    # XDG_CACHE_HOME may point anywhere; never print a path that contains the user name.
    default = os.path.abspath(os.path.join(ctx.home, ".cache"))
    label = "~/.cache" if os.path.abspath(ctx.cache_home) == default else "$XDG_CACHE_HOME"
    msg = f"{label} is {'' if done else 'at least '}{human(size)}"
    if size < 3 * GiB:
        return ok(msg)
    fix = (f"See what's big: `du -sh {label}/* | sort -h | tail`, "
           "then delete what you can re-download.")
    return (warn if size < 10 * GiB else bad)(msg, fix)


@check("Storage", 2, "Trash")
def c_trash(ctx: Ctx) -> Out:
    path = os.path.join(ctx.data_home, "Trash")
    if not os.path.isdir(path):
        return ok("Trash is empty")
    size, done = dir_size(path)
    msg = f"Trash holds {'' if done else 'at least '}{human(size)}"
    if size < GiB:
        return ok(msg)
    # Never fall back to rm -rf: XDG_DATA_HOME may not be ~/.local/share, and a
    # wrong glob would delete real files. No trash tool means no generated command.
    if shutil.which("gio"):
        cmd = "gio trash --empty"
    elif shutil.which("trash-empty"):
        cmd = "trash-empty"
    else:
        cmd = ""
    return (warn if size < 5 * GiB else bad)(msg, "Empty the trash.", cmd)


@check("Storage", 2, "Unused packages")
def c_unused(ctx: Ctx) -> Out:
    if ctx.nixos:
        return nixos_generations_check()
    if ctx.pm == "rpm-ostree":
        return skip("rpm-ostree has no orphan-package list")
    if ctx.pm == "zypper":
        return skip("zypper has no reliable offline unused-package list")
    if ctx.pm == "apk":
        return skip("Alpine has no orphan-package tracking")
    if ctx.pm == "xbps-install":
        return skip("Void's orphan list needs a privileged query")
    if ctx.pm == "emerge":
        return skip("Portage depclean needs a full dependency calculation")
    if ctx.pm == "apt-get":
        rc, out = run(["apt-get", "-s", "autoremove"], 20)
        if rc != 0:
            return skip("couldn't query apt")
        names = [l.split()[1] for l in out.splitlines() if l.startswith("Remv ") and len(l.split()) > 1]
        cmd = "sudo apt autoremove --purge"
    elif ctx.pm == "pacman":
        rc, out = run(["pacman", "-Qdtq"])
        if rc not in (0, 1):
            return skip("couldn't query pacman")
        names = out.splitlines() if rc == 0 else []
        cmd = "sudo pacman -Rns $(pacman -Qdtq)"
    elif ctx.pm == "dnf":
        rc, out = run(["dnf", "-q", "--cacheonly", "repoquery", "--unneeded", "--installed", "--qf", "%{name}"], 30)
        if rc != 0:
            return skip("couldn't query dnf (needs `dnf repoquery --unneeded`)")
        names = [l.strip() for l in out.splitlines() if l.strip()]
        cmd = "sudo dnf autoremove"
    else:
        return skip("package manager not supported")
    n = len(names)
    if n <= 5:
        return ok("Nothing to clean up" if n == 0 else f"{n} unused package(s), minor")
    kernels = sum(1 for x in names if x.startswith(("linux-image", "linux-headers", "linux-modules")))
    msg = f"{n} unused packages" + (f" (including {kernels} old kernel files)" if kernels else "")
    return (warn if n <= 40 else bad)(msg, "Remove what you no longer need.", cmd)


# Battery and heat checks

@check("Battery & Heat", 5, "Battery health")
def c_battery(ctx: Ctx) -> Out:
    if not ctx.laptop:
        return skip("no battery")
    health = battery_health()
    if health is None:
        return skip("battery capacity unavailable")
    pct, cycles = health
    msg = f"Battery holds {pct:.0f}% of its original capacity" + (f" ({cycles} cycles)" if cycles.isdigit() else "")
    limit = battery_charge_limit()
    if limit is not None and limit < 100:
        msg += f"; charging capped at {limit}%"
        fix = (f"Charging is already capped at {limit}%, which slows further wear. "
               "Plan a replacement if runtime is too short.")
    else:
        fix = "Cap charging at 80% if supported (TLP or a BIOS setting) to slow wear."
    if pct >= 80:
        return ok(msg)
    return (warn if pct >= 60 else bad)(msg, fix)


@check("Battery & Heat", 3, "Power management")
def c_power(ctx: Ctx) -> Out:
    if not ctx.laptop:
        return skip("no battery")
    if not ctx.systemd:
        return skip("needs systemd")
    active = units_active(ctx, ["tlp", "power-profiles-daemon", "auto-cpufreq",
                               "tuned", "laptop-mode"])
    if active:
        return ok("Active: " + ", ".join(active))
    cmds = {"apt-get": "sudo apt install tlp\nsudo systemctl enable --now tlp",
            "dnf": "sudo dnf install tlp\nsudo systemctl enable --now tlp",
            "pacman": "sudo pacman -S tlp\nsudo systemctl enable --now tlp",
            "zypper": "sudo zypper install tlp\nsudo systemctl enable --now tlp"}
    if ctx.nixos:
        cmd = ("# add to /etc/nixos/configuration.nix:\n"
               "#   services.power-profiles-daemon.enable = true;\n"
               "sudo nixos-rebuild switch")
    else:
        cmd = cmds.get(ctx.pm or "", "")
    return warn("No power-management daemon is running", "Install TLP or power-profiles-daemon.", cmd)


@check("Battery & Heat", 3, "CPU temperature")
def c_temp(ctx: Ctx) -> Out:
    t = cpu_temp_c()
    if t is None:
        return skip("no CPU temperature sensor found")
    msg = f"CPU is at {t:.0f}{chr(176) if UNICODE else chr(32)}C right now"
    # Laptop CPUs commonly run at 80-90 C under load; Intel's Tjmax is ~100 C.
    if t <= 90:
        return ok(msg)
    fix = "Clean the fans/vents, check thermal paste, and make sure nothing is pinning the CPU."
    return (warn if t <= 95 else bad)(msg, fix)


# Scoring

CAT_ORDER = ["Speed", "Security", "Privacy", "Storage", "Battery & Heat"]
CAT_WEIGHT = {"Speed": 25, "Security": 30, "Privacy": 15, "Storage": 20, "Battery & Heat": 10}
FACTOR = {"pass": 0.0, "warn": 0.5, "fail": 1.0}


@dataclass
class Result:
    id: str
    category: str
    title: str
    weight: int
    status: str
    detail: str = ""
    fix: str = ""
    cmd: str = ""
    impact: float = 0.0        # points this issue costs on the overall score


@dataclass
class Report:
    score: int
    grade: str
    cats: Dict[str, int]
    results: List[Result]
    system: Dict[str, object]


def grade_of(score: int) -> str:
    for floor, g in ((95, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= floor:
            return g
    return "F"


def system_info(ctx: Ctx) -> Dict[str, object]:
    osr: Dict[str, str] = {}
    for line in read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            osr[k] = v.strip().strip('"')
    return {"distro": clean(osr.get("PRETTY_NAME", "Linux")) or "Linux", "kernel": clean(platform.release()),
            "arch": platform.machine(), "laptop": ctx.laptop}


def run_checks(ctx: Ctx, progress: Callable[[int, int, str], None],
               checks: Optional[List[Tuple[str, int, str, Callable]]] = None,
               debug: bool = False) -> List[Result]:
    """Run checks in parallel; a crashing check becomes a skip."""
    chosen = list(CHECKS if checks is None else checks)
    results: List[Optional[Result]] = [None] * len(chosen)

    def work(i: int) -> Tuple[int, Result]:
        cat, weight, title, fn = chosen[i]
        try:
            out = fn(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken check must not break the report
            if debug:
                traceback.print_exc()
            out = Out("skip", f"internal error: {type(exc).__name__}")
        return i, Result(check_id(fn), cat, title, weight, out.status, clean(out.detail), clean(out.fix), out.cmd)

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(work, i) for i in range(len(chosen))]
        for n, fut in enumerate(cf.as_completed(futures), 1):
            i, res = fut.result()
            results[i] = res
            progress(n, len(chosen), res.title)
    return [r for r in results if r is not None]


def build_report(results: List[Result], system: Dict[str, object]) -> Optional[Report]:
    agg: Dict[str, List[float]] = {}          # category -> [total weight, weighted loss]
    for r in results:
        if r.status == "skip":
            continue
        a = agg.setdefault(r.category, [0.0, 0.0])
        a[0] += r.weight
        a[1] += r.weight * FACTOR[r.status]
    if not agg:
        return None
    total_cw = sum(CAT_WEIGHT[c] for c in agg)
    cat_scores = {c: 100 * (1 - loss / w) for c, (w, loss) in agg.items()}
    overall = sum(cat_scores[c] * CAT_WEIGHT[c] for c in agg) / total_cw
    for r in results:
        if r.status in ("warn", "fail"):
            w = agg[r.category][0]
            r.impact = round(r.weight * FACTOR[r.status] / w * CAT_WEIGHT[r.category] / total_cw * 100, 1)
    score = int(round(overall))
    if score >= 100 and any(r.status in ("warn", "fail") for r in results):
        score = 99                              # 100 is reserved for a truly clean machine
    return Report(score, grade_of(score), {c: int(round(s)) for c, s in cat_scores.items()}, results, system)


# Theme
# Rosé Pine on deep navy; accents run gold, love, foam, pine, iris.
PALETTE = {
    "base": "#0a0d15", "base2": "#191724",
    "gold": "#f6c177", "love": "#eb6f92", "foam": "#9ccfd8", "pine": "#3e8fb0", "iris": "#c4a7e7",
    "text": "#e0def4", "subtle": "#908caa", "muted": "#6e6a86",
}
STRIPES = ["gold", "love", "foam", "pine", "iris"]
ROLE = {"good": "foam", "ok": "gold", "bad": "love"}   # Rosé Pine has no green: foam stands in for "good"
CAT_COLOR = dict(zip(CAT_ORDER, STRIPES))

_BASIC16 = {"gold": "33", "love": "35", "foam": "36", "pine": "34", "iris": "95", "text": "97",
            "subtle": "37", "muted": "90", "soft": "2", "good": "32", "ok": "33", "bad": "31"}
_CUBE = (0, 95, 135, 175, 215, 255)


def hex_rgb(h: str) -> Tuple[int, int, int]:
    return int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)


def rgb_to_256(r: int, g: int, b: int) -> int:
    def near(v: int) -> int:
        return min(range(6), key=lambda i: abs(_CUBE[i] - v))
    ri, gi, bi = near(r), near(g), near(b)
    cube = (_CUBE[ri], _CUBE[gi], _CUBE[bi])
    step = min(23, max(0, round(((r + g + b) // 3 - 8) / 10)))
    gray = 8 + 10 * step
    d_cube = sum((x - y) ** 2 for x, y in zip((r, g, b), cube))
    d_gray = sum((x - gray) ** 2 for x in (r, g, b))
    return 232 + step if d_gray < d_cube else 16 + 36 * ri + 6 * gi + bi


def color_mode(theme: str = "rose") -> str:
    """How many colors the terminal supports: 'true' | '256' | '16'."""
    if theme == "basic":
        return "16"
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return "true"
    if "256" in os.environ.get("TERM", ""):
        return "256"
    return "16"


def make_painter(mode: Optional[str]) -> Callable[..., str]:
    """mode: None (no color) | 'true' | '256' | '16'. Styles: bold, soft, a palette name or a role."""
    def code(style: str) -> str:
        if style == "bold":
            return "1"
        if mode == "16":
            return _BASIC16.get(style, "")
        name = {"soft": "subtle"}.get(style) or ROLE.get(style, style)
        if name not in PALETTE:
            return ""
        r, g, b = hex_rgb(PALETTE[name])
        return f"38;2;{r};{g};{b}" if mode == "true" else f"38;5;{rgb_to_256(r, g, b)}"

    def paint(s: str, *styles: str) -> str:
        if mode is None or not s:
            return s
        codes = [c for c in map(code, styles) if c]
        return f"\033[{';'.join(codes)}m{s}\033[0m" if codes else s
    return paint


def tone(score: int) -> str:
    return "good" if score >= 85 else "ok" if score >= 70 else "bad"


# Output

BIG = {
    "0": ("███", "█ █", "█ █", "█ █", "███"), "1": (" █ ", "██ ", " █ ", " █ ", "███"),
    "2": ("███", "  █", "███", "█  ", "███"), "3": ("███", "  █", "███", "  █", "███"),
    "4": ("█ █", "█ █", "███", "  █", "  █"), "5": ("███", "█  ", "███", "  █", "███"),
    "6": ("███", "█  ", "███", "█ █", "███"), "7": ("███", "  █", "  █", "  █", "  █"),
    "8": ("███", "█ █", "███", "█ █", "███"), "9": ("███", "█ █", "███", "  █", "███"),
}


def big_number(n: int) -> List[str]:
    """Five rows of blocks; each pixel is two characters wide to offset the terminal cell aspect ratio."""
    rows = ["  ".join("".join(ch * 2 for ch in BIG[d][r]) for d in str(n)) for r in range(5)]
    return rows if UNICODE else [r.replace("█", "#") for r in rows]


_DISK_DETAIL_RE = re.compile(
    r"^(\d+)% used \((.+?) of (.+?)\), (.+?) free \([\d.]+%\)")


def disk_usage_line(detail: str, sep: str = " · ") -> str:
    """Compact '78% used · 175.5 / 224.0 GiB (37.1 GiB free)' from c_disk."""
    m = _DISK_DETAIL_RE.match(detail)
    if not m:
        return detail
    pct, used, total, free = m.groups()
    used_num = used.rsplit(" ", 1)[0] if " " in used else used
    return f"{pct}% used{sep}{used_num} / {total} ({free} free)"


def render(rep: Report, p: Callable[..., str], verbose: bool = False) -> None:
    U = UNICODE
    sym = {"pass": "✔" if U else "ok", "warn": "▲" if U else "!", "fail": "✖" if U else "x"}
    role = {"pass": "good", "warn": "ok", "fail": "bad"}
    minus, dot = ("−", " · ") if U else ("-", " | ")
    full, empty, arrow, rule = ("█", "░", "→", "━") if U else ("#", "-", "->", "=")
    s = rep.system

    print()
    print("  " + p("Linux Score", "bold", "text") + p(f"   lscore {__version__}", "soft"))
    info = dot.join(x for x in (str(s["distro"]), "kernel " + str(s["kernel"]), str(s["arch"]),
                                "laptop" if s["laptop"] else "") if x)
    print("  " + p(info, "soft"))
    print("  " + "".join(p(rule * 6, c) for c in STRIPES))
    print()

    for i, row in enumerate(big_number(rep.score)):
        tail = {1: p("   out of 100", "soft"), 3: p(f"   Grade {rep.grade}", "bold", tone(rep.score))}.get(i, "")
        print("  " + p(row, STRIPES[i]) + tail)
    print()

    for c in CAT_ORDER:
        if c in rep.cats:
            sc = rep.cats[c]
            n = round(sc / 100 * 20)
            label = "Storage (health)" if c == "Storage" else c
            print(f"  {label:<17}" + p(full * n, CAT_COLOR[c]) + p(empty * (20 - n), "muted")
                  + "  " + p(f"{sc:>3}", tone(sc)))
            if c == "Storage":
                disk = next((r for r in rep.results
                             if r.id == "disk" and r.status != "skip"), None)
                if disk and disk.detail:
                    branch = "    └─ Disk        " if U else "    `- Disk        "
                    print(p(branch, "soft") + p(disk_usage_line(disk.detail, dot), "text"))
    print()

    issues = sorted((r for r in rep.results if r.status in ("warn", "fail")), key=lambda r: -r.impact)
    if issues:
        print("  " + p("What to improve", "bold", "text") + p("  (biggest wins first)", "soft"))
        shown = issues if verbose else issues[:8]
        for r in shown:
            print(f"  {p(sym[r.status], role[r.status])} {p(r.title, 'bold')}  "
                  f"{p(minus + format(r.impact, '.1f'), 'soft')}")
            if r.detail:
                print(f"      {r.detail}")
            if r.fix:
                print("      " + p(f"{arrow} {r.fix}", "iris"))
        if len(issues) > len(shown):
            print(p(f"  ... and {len(issues) - len(shown)} more (use -v to see all)", "soft"))
        top = issues[:3]
        reach = min(100, int(round(rep.score + sum(r.impact for r in top))))
        if reach > rep.score:
            what = "the top issue" if len(top) == 1 else f"the top {len(top)}"
            print(f"\n  Fix {what} and you'd reach about " + p(f"{reach}/100", "bold", tone(reach)))
        print()
    else:
        print("  " + p("Nothing to improve. Nice machine.", "good"))
        print()

    passed = [r for r in rep.results if r.status == "pass"]
    skipped = [r for r in rep.results if r.status == "skip"]
    line = f"  {p(sym['pass'], 'good')} {len(passed)} checks passed"
    if skipped:
        line += p(f"   ({len(skipped)} not applicable here)", "soft")
    print(line)
    if verbose:
        for r in passed:
            print(p(f"      {r.title}: {r.detail}", "soft"))
        for r in skipped:
            print(p(f"      {r.title}: skipped ({r.detail})", "soft"))
    print()
    print(p("  Share it:  lscore --card   |   lscore --share   |   lscore --badge", "soft"))
    print(p("  Fix plan:  lscore --fix    (prints commands to review; runs nothing)", "soft"))
    print()


def redact_audit(snapshot: Dict[str, List[str]], home: str) -> Dict[str, List[str]]:
    """Replace the user's home path with $HOME so --audit output can be shared."""
    home = home.rstrip(os.sep)
    if not home or home == os.sep:
        return snapshot
    # Redact on a path boundary: home may be followed by "/", the end of
    # the string, or punctuation such as a quote or ":", but not by another
    # file-name character ("/home/anabel" must stay untouched).
    pattern = re.compile(re.escape(home) + r"(?![\w.+\-~@%])")
    return {key: [pattern.sub("$HOME", value) for value in values]
            for key, values in snapshot.items()}


def render_audit(snapshot: Dict[str, List[str]], p: Callable[..., str],
                 stream: Optional[object] = None) -> None:
    """Print every path and command the run touched; this is the --audit proof."""
    stream = stream or sys.stdout
    print(file=stream)
    print("  " + p("Audit", "bold", "text")
          + p("   every file and command this run touched", "soft"), file=stream)
    for title, items in (("Commands run", snapshot["commands_run"]),
                         ("Files read", snapshot["files_read"]),
                         ("Files written", snapshot["files_written"])):
        if not items:
            print("  " + p(title + ": none", "soft"), file=stream)
            continue
        print("  " + p(f"{title} ({len(items)})", "bold"), file=stream)
        for item in items:
            print("    " + clean(str(item)), file=stream)
    print(file=stream)


def to_json(rep: Report, audit: Optional[Dict[str, List[str]]] = None) -> str:
    data: Dict[str, object] = {"version": __version__, "score": rep.score, "grade": rep.grade,
                               "categories": rep.cats, "system": rep.system,
                               "checks": [asdict(r) for r in rep.results]}
    if audit is not None:
        data["audit"] = audit
    return json.dumps(data, indent=2, ensure_ascii=False)


def prometheus_text(rep: Report) -> str:
    """node_exporter textfile metrics. One file, no network, no daemon."""
    counts = {status: sum(1 for r in rep.results if r.status == status)
              for status in ("warn", "fail")}
    lines = [
        "# HELP lscore_score Overall Linux health score, 0-100.",
        "# TYPE lscore_score gauge",
        f"lscore_score {rep.score}",
        "# HELP lscore_grade_info Letter grade as a label; the value is always 1.",
        "# TYPE lscore_grade_info gauge",
        f'lscore_grade_info{{grade="{rep.grade}"}} 1',
        "# HELP lscore_category_score Health score per category, 0-100.",
        "# TYPE lscore_category_score gauge",
    ]
    for category in CAT_ORDER:
        if category in rep.cats:
            lines.append(f'lscore_category_score{{category="{category_key(category)}"}} '
                         f"{rep.cats[category]}")
    lines += [
        "# HELP lscore_check_score Health of one check: 1 pass, 0.5 warn, 0 fail.",
        "# TYPE lscore_check_score gauge",
    ]
    for result in rep.results:
        if result.status == "skip":
            continue
        lines.append(f'lscore_check_score{{id="{result.id}",'
                     f'category="{category_key(result.category)}"}} '
                     f"{1 - FACTOR[result.status]:g}")
    lines += [
        "# HELP lscore_issues Checks that need attention.",
        "# TYPE lscore_issues gauge",
    ]
    for status in ("warn", "fail"):
        lines.append(f'lscore_issues{{status="{status}"}} {counts[status]}')
    lines += [
        "# HELP lscore_last_run_timestamp_seconds Unix time of this run.",
        "# TYPE lscore_last_run_timestamp_seconds gauge",
        f"lscore_last_run_timestamp_seconds {int(time.time())}",
    ]
    return "\n".join(lines) + "\n"


def write_atomic(path: str, text: str) -> None:
    """Write a small file atomically and world-readable, so a collector never sees half of it."""
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o644)          # node_exporter often runs as another user
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def fix_script(rep: Report) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# lscore fix plan. Nothing has been executed.",
        "# Review every line, delete what you don't want, then run: bash <this-file>",
        "# Tip: take a snapshot first (Timeshift / Snapper).",
        "",
    ]
    todo = [r for r in sorted(rep.results, key=lambda r: -r.impact)
            if r.status in ("warn", "fail") and r.cmd]
    if not todo:
        lines.append("# Nothing here can be fixed automatically; run `lscore` for manual suggestions.")
    for r in todo:
        lines.append(f"# [{r.category}] {r.title}: {r.detail} (-{r.impact})")
        lines.extend(r.cmd.splitlines())
        lines.append("")
    return "\n".join(lines)


def share_text(rep: Report) -> str:
    """Plain text to paste into a post. No hostname, username or IP."""
    s = rep.system
    cats = " | ".join(f"{c} {rep.cats[c]}" for c in CAT_ORDER if c in rep.cats)
    return (f"Linux Score: {rep.score}/100 ({rep.grade})\n{s['distro']} | {s['arch']}\n{cats}\n"
            f"scored with lscore {__version__}")


def badge_md(rep: Report) -> str:
    color = PALETTE[ROLE[tone(rep.score)]].lstrip("#")
    label = PALETTE["base2"].lstrip("#")
    return (f"![Linux Score](https://img.shields.io/badge/Linux%20Score-{rep.score}-{color}"
            f"?labelColor={label}&style=flat-square)")


def make_card(rep: Report) -> str:
    """A 1200x630 SVG share card in the lscore palette. Contains no hostname, username or IP."""
    esc, P = html.escape, PALETTE

    def txt(x, y, s, size, fill, weight=400, anchor="start") -> str:
        return (f'<text x="{x}" y="{y}" font-family="Inter, \'DejaVu Sans\', Verdana, sans-serif" '
                f'font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">'
                f'{esc(str(s))}</text>')

    def role_hex(score: int) -> str:
        return P[ROLE[tone(score)]]

    stripes = [P[n] for n in STRIPES]
    bands = "".join(f'<stop offset="{i / 5:g}" stop-color="{c}"/><stop offset="{(i + 1) / 5:g}" stop-color="{c}"/>'
                    for i, c in enumerate(stripes))
    sysi = rep.system
    sub = f'{sysi["distro"]} \u00b7 {sysi["arch"]}'[:44]
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" '
        f'role="img" aria-label="Linux Score {rep.score} out of 100">',
        f'<title>Linux Score {rep.score}/100 ({rep.grade})</title>',
        '<defs>'
        f'<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{P["base"]}"/>'
        f'<stop offset="1" stop-color="{P["base2"]}"/></linearGradient>'
        f'<linearGradient id="bands" gradientUnits="userSpaceOnUse" x1="0" y1="238" x2="0" y2="420">{bands}</linearGradient>'
        '<clipPath id="mark"><rect x="80" y="62" width="48" height="48" rx="12"/></clipPath>'
        '</defs>',
        '<rect width="1200" height="630" fill="url(#bg)"/>',
    ]
    parts += [f'<rect x="0" y="{i * 3}" width="1200" height="3" fill="{c}"/>' for i, c in enumerate(stripes)]
    parts.append('<g clip-path="url(#mark)">' + "".join(
        f'<rect x="80" y="{62 + i * 9.6:g}" width="48" height="10" fill="{c}"/>'
        for i, c in enumerate(stripes)) + '</g>')
    parts += [
        txt(144, 100, "Linux Score", 44, P["text"], 700),
        txt(144, 142, sub, 26, P["subtle"]),
        txt(70, 420, rep.score, 250, "url(#bands)", 800),
        txt(86, 478, "out of 100", 30, P["subtle"]),
        f'<rect x="80" y="498" width="210" height="64" rx="32" fill="{role_hex(rep.score)}"/>',
        txt(185, 543, f"Grade {rep.grade}", 34, P["base"], 700, "middle"),
    ]
    y = 200
    for name in CAT_ORDER:
        if name not in rep.cats:
            continue
        s = rep.cats[name]
        w = max(10, round(440 * s / 100))
        parts += [
            txt(660, y, name, 28, P["text"]),
            txt(1100, y, s, 28, role_hex(s), 700, "end"),
            f'<rect x="660" y="{y + 16}" width="440" height="16" rx="8" fill="#ffffff" fill-opacity="0.08"/>',
            f'<rect x="660" y="{y + 16}" width="{w}" height="16" rx="8" fill="{P[CAT_COLOR[name]]}"/>',
        ]
        y += 76
    parts += [txt(80, 600, f"lscore {__version__}  \u00b7  run it on your own machine", 22, P["muted"]), "</svg>"]
    return "\n".join(parts)


# History

HISTORY_KEEP = 400
_MAX_TS = 4102444800            # 2100-01-01 UTC, safe for time_t
_GRADES = ("A+", "A", "B", "C", "D", "F")


def history_path() -> str:
    """Where past scores live: $XDG_STATE_HOME/lscore/history.jsonl (else ~/.local/state/...)."""
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.environ.get("HOME") or os.path.expanduser("~"), ".local", "state")
    return os.path.join(state, "lscore", "history.jsonl")


@contextlib.contextmanager
def history_lock(path: str):
    """Serialize append+prune across concurrent runs. If locking fails, still write."""
    fd = None
    try:
        fd = os.open(path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        AUDIT.wrote(path + ".lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            fd = None
    try:
        yield
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass


def _prune_history(path: str) -> None:
    try:
        AUDIT.read(path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if len(lines) <= HISTORY_KEEP + 50:
            return
        tmp = f"{path}.{os.getpid()}.tmp"
        try:
            # O_CREAT with 0600 keeps the pruned file private; a plain open()
            # would create it 0644 and os.replace() would publish that mode.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.writelines(lines[-HISTORY_KEEP:])
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
    except OSError:
        pass


def record_score(rep: Report) -> str:
    """Append this run to the history file; return its path, or '' if nothing was written.
    Root runs are skipped: a preserved $HOME would leave a root-owned file. Never raises."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ""
    path = history_path()
    line = json.dumps({"t": int(time.time()), "score": rep.score, "grade": rep.grade,
                       "cats": rep.cats, "n": len(rep.results)}) + "\n"
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(os.path.dirname(path), 0o700)   # tighten folders created by older versions
        with history_lock(path):
            # O_CREAT with 0600 means the file is never world-readable, not even for a moment.
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)                # repair a file left at 0644 by older versions
            _prune_history(path)
    except OSError:
        return ""
    AUDIT.wrote(path)
    return path


def load_history() -> List[Dict[str, object]]:
    """Recorded runs, oldest first. Corrupt, foreign or out-of-range lines are ignored."""
    entries: List[Dict[str, object]] = []
    for raw in read(history_path()).splitlines():
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        score, t = e.get("score"), e.get("t")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            continue
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not 0 <= t <= _MAX_TS:
            continue
        entries.append(e)
    entries.sort(key=lambda e: float(e["t"]))
    return entries


def load_last_history_report() -> Dict[str, object]:
    """The newest recorded run, shaped like a --json report (no per-check data)."""
    entries = load_history()
    if not entries:
        raise ValueError("no recorded runs yet; run `lscore --history` first")
    last = entries[-1]
    score = int(last["score"])
    cats: Dict[str, int] = {}
    raw_cats = last.get("cats")
    if isinstance(raw_cats, dict):
        for name, value in raw_cats.items():
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100:
                cats[str(name)] = value
    grade = last.get("grade")
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(last["t"])))
    checks_run = last.get("n")
    if isinstance(checks_run, bool) or not isinstance(checks_run, int) or checks_run < 0:
        checks_run = 0
    return {"score": score,
            "grade": clean(grade) if isinstance(grade, str) else grade_of(score),
            "categories": cats,
            "checks": {},
            "checks_run": checks_run,
            "version": "history",
            "source_label": f"recorded {when}",
            "system": {}}


def arrow_of(a: int, b: int) -> str:
    if b > a:
        return "→" if UNICODE else "->"
    if b < a:
        return "↓" if UNICODE else "v"
    return "=" if UNICODE else "=="


def format_age(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def render_history(entries: List[Dict[str, object]], p: Callable[..., str],
                   recorded: bool, verbose: bool = False, is_root: bool = False) -> None:
    full, empty = ("█", "░") if UNICODE else ("#", "-")
    print()
    print("  " + p("History", "bold", "text") + p("   score over time, stored only on this machine", "soft"))
    if not entries:
        print("  " + p("No runs recorded yet.", "soft"))
        if is_root:
            print("  " + p("(runs as root are not recorded: run lscore as your normal user)", "soft"))
        print()
        return

    shown = entries[-14:]
    if len(entries) > len(shown):
        print(p(f"  showing the newest {len(shown)} of {len(entries)} runs", "soft"))
    for i, e in enumerate(shown):
        idx = len(entries) - len(shown) + i
        t = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(e["t"])))
        score = int(e["score"])
        delta = score - int(entries[idx - 1]["score"]) if idx else None
        change = "   -" if delta is None else (f"{delta:+4d}" if delta else "   0")
        n = round(score / 100 * 16)
        note = p("  <- this run", "soft") if recorded and idx == len(entries) - 1 else ""
        grade = str(e.get("grade", ""))
        label = grade if grade in _GRADES else ""
        print(f"    {t}   {score:>3} {label:<2} {change}   "
              + p(full * n, tone(score)) + p(empty * (16 - n), "muted") + note)

    first, now = int(entries[0]["score"]), int(entries[-1]["score"])
    scores = [int(e["score"]) for e in entries]
    dot = " · " if UNICODE else " | "
    last_age = format_age(time.time() - float(entries[-1]["t"]))
    summary = (f"  {len(entries)} runs{dot}best {max(scores)}{dot}average {sum(scores) / len(scores):.1f}"
               f"{dot}latest {scores[-1]}{dot}last run {last_age}")
    print(p(summary, "soft"))
    since = time.strftime("%Y-%m-%d", time.localtime(float(entries[0]["t"])))
    trend = "good" if now > first else "bad" if now < first else "soft"
    print("  " + p(f"  since {since}: {first} {arrow_of(first, now)} {now}", trend))
    if is_root:
        print("  " + p("  (this run was not recorded: running as root)", "soft"))
    if verbose:
        print("  " + p(f"  file: {history_path()}", "soft"))
    print()


# CLI helpers

def env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


CONFIG_KEYS = ("only", "skip", "min", "fail_on", "theme", "color", "ascii", "no_history")


def config_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.environ.get("HOME") or os.path.expanduser("~"), ".config")
    return os.path.join(base, "lscore", "config.ini")


def parse_bool(value: str) -> Optional[bool]:
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return None


def load_config(path: str, strict: bool = False) -> Tuple[Dict[str, object], List[str]]:
    """Read the optional INI file; returns (settings, warnings). Strict mode raises."""
    cfg: Dict[str, object] = {}
    warnings: List[str] = []
    if not os.path.isfile(path):
        if strict:
            raise OSError("file not found")
        return cfg, warnings

    AUDIT.read(path)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, "r", encoding="utf-8") as f:
            parser.read_file(f)
    except (OSError, configparser.Error, UnicodeError) as exc:
        msg = f"couldn't read {path}: {exc}"
        if strict:
            raise ValueError(str(exc)) from exc
        warnings.append(msg + "; ignoring it")
        return cfg, warnings

    if not parser.has_section("lscore"):
        msg = f"{path} has no [lscore] section; ignoring the file"
        if strict:
            raise ValueError("no [lscore] section")
        warnings.append(msg)
        return cfg, warnings

    section = parser["lscore"]
    for key in section:
        if key not in CONFIG_KEYS:
            warnings.append(f"{path}: unknown key {key!r}; ignoring it")

    def invalid(key: str, value: str, expected: str) -> None:
        warnings.append(f"{path}: {key} = {value!r} is not {expected}; ignoring it")

    for key in ("only", "skip"):
        if key in section:
            cfg[key] = split_tokens([section.get(key, "")])

    if "min" in section:
        try:
            cfg["min"] = int(section["min"].strip())
        except ValueError:
            invalid("min", section["min"], "an integer")

    for key, choices in (("fail_on", ("warn", "fail")),
                         ("theme", ("rose", "basic")),
                         ("color", ("auto", "always", "never"))):
        if key in section:
            value = section[key].strip().lower()
            if value in choices:
                cfg[key] = value
            else:
                invalid(key, section[key], "one of " + ", ".join(choices))

    for key in ("ascii", "no_history"):
        if key in section:
            value = parse_bool(section[key])
            if value is None:
                invalid(key, section[key], "true or false")
            else:
                cfg[key] = value

    return cfg, warnings


def list_checks_text(checks: List[Tuple[str, int, str, Callable]]) -> str:
    lines = [f"  {len(checks)} check(s)", "",
             f"  {'id':<12} {'category':<16} {'weight':>6}  title"]
    for cat, weight, title, fn in checks:
        lines.append(f"  {check_id(fn):<12} {cat:<16} {weight:>6}  {title}")
    lines += ["", "  Use --only or --skip with an ID or CATEGORY (comma-separated).",
              "  Category keys: speed, security, privacy, storage, battery."]
    return "\n".join(lines)


def list_checks_json(checks: List[Tuple[str, int, str, Callable]]) -> str:
    return json.dumps([{"id": check_id(fn), "category": cat, "weight": weight, "title": title}
                       for cat, weight, title, fn in checks], indent=2, ensure_ascii=False)


def load_report_file(path: str) -> Dict[str, object]:
    """Read a --json report; raises OSError or ValueError if it isn't one."""
    AUDIT.read(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("not an lscore JSON report")
    score = data.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("no valid score in this file")
    cats: Dict[str, int] = {}
    raw_cats = data.get("categories")
    if isinstance(raw_cats, dict):
        for name, value in raw_cats.items():
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100:
                cats[str(name)] = value
    checks: Dict[str, Dict[str, object]] = {}
    raw_checks = data.get("checks")
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if not isinstance(item, dict):
                continue
            cid, status = item.get("id"), item.get("status")
            if not isinstance(cid, str) or status not in ("pass", "warn", "fail", "skip"):
                continue
            impact = item.get("impact")
            checks[cid] = {
                "status": status,
                "title": clean(item["title"]) if isinstance(item.get("title"), str) else cid,
                "detail": clean(item["detail"]) if isinstance(item.get("detail"), str) else "",
                "impact": float(impact) if isinstance(impact, (int, float))
                and not isinstance(impact, bool) else 0.0,
            }
    system = data.get("system") if isinstance(data.get("system"), dict) else {}
    version = clean(data["version"]) if isinstance(data.get("version"), str) else "?"
    grade = clean(data["grade"]) if isinstance(data.get("grade"), str) else grade_of(score)
    return {"score": score,
            "grade": grade,
            "categories": cats,
            "checks": checks,
            "version": version,
            "source_label": f"lscore {version}",
            "system": {str(k): clean(v) if isinstance(v, str) else v
                       for k, v in system.items()}}


def _status_rank(status: object) -> int:
    return {"skip": -1, "pass": 0, "warn": 1, "fail": 2}.get(str(status), -1)


def new_issues(rep: Report, old: Dict[str, object]) -> List[Result]:
    """Checks that are warn/fail now and were healthier in the old report.

    Only checks present in both reports are compared: a check added by a newer
    lscore must not fail a CI job that used an older baseline.
    """
    old_checks = old.get("checks") if isinstance(old.get("checks"), dict) else {}
    found: List[Result] = []
    for result in rep.results:
        before = old_checks.get(result.id)
        if not isinstance(before, dict) or result.status not in ("warn", "fail"):
            continue
        if _status_rank(result.status) > _status_rank(before.get("status")):
            found.append(result)
    return found


def compare_lines(rep: Report, old: Dict[str, object], source: str) -> str:
    arrow = "→" if UNICODE else "->"
    old_cats = old["categories"] if isinstance(old["categories"], dict) else {}
    label = clean(str(old.get("source_label") or f"lscore {old.get('version', '?')}"))

    def delta(now: int, before: Optional[int]) -> str:
        if before is None:
            return f"{now}  (not in that report)"
        diff = now - before
        if diff == 0:
            return f"{now}  (same)"
        return f"{before} {arrow} {now}  ({diff:+d})"

    lines = [f"  Compared with {clean(str(source))}  ({label})"]
    old_system = old.get("system") if isinstance(old.get("system"), dict) else {}
    old_distro = old_system.get("distro") if isinstance(old_system.get("distro"), str) else ""
    now_distro = rep.system.get("distro") if isinstance(rep.system.get("distro"), str) else ""
    if old_distro and now_distro and old_distro != now_distro:
        lines.append(f"  Note: that report is from {clean(old_distro)}; "
                     f"this run is {clean(now_distro)}.")

    lines.append(f"  {'Score':<15}{delta(rep.score, int(old['score']))}"
                 f"   Grade {clean(str(old['grade']))} {arrow} {rep.grade}")
    for c in CAT_ORDER:
        now = rep.cats.get(c)
        before = old_cats.get(c)
        if now is None and before is None:
            continue
        value = f"{before}  (not scored this run)" if now is None else delta(now, before)
        lines.append(f"  {c:<15}{value}")

    old_checks = old.get("checks") if isinstance(old.get("checks"), dict) else {}
    old_n = old.get("checks_run")
    if isinstance(old_n, bool) or not isinstance(old_n, int) or old_n < 0:
        old_n = len(old_checks)
    if old_n and old_n != len(rep.results):
        lines.append(f"  Note: that run covered {old_n} checks; this one covers "
                     f"{len(rep.results)}; scores from different selections are not "
                     "directly comparable.")
    if old_checks:
        changes: List[Tuple[int, Result, Optional[str], str]] = []
        for r in rep.results:
            before = old_checks.get(r.id)
            if not isinstance(before, dict):
                if r.status in ("warn", "fail"):
                    changes.append((0, r, None, "new issue"))
                continue
            old_status = before.get("status")
            if old_status == r.status:
                continue
            if old_status == "skip":
                if r.status in ("warn", "fail"):
                    changes.append((0, r, "skip", "new issue (was skipped)"))
                else:
                    changes.append((2, r, "skip", "now checked"))
            elif r.status == "skip":
                changes.append((3, r, str(old_status), "not checked now"))
            elif _status_rank(r.status) > _status_rank(old_status):
                changes.append((0, r, str(old_status), "worse"))
            else:
                changes.append((1, r, str(old_status), "better"))

        order = {c: i for i, c in enumerate(CAT_ORDER)}
        changes.sort(key=lambda item: (item[0], order.get(item[1].category, 99), item[1].id))
        lines.append("")
        if changes:
            lines.append("  Check changes:")
            for _group, r, old_status, kind in changes[:25]:
                sym = {"better": "↓", "worse": "↑", "new issue": "✖",
                       "new issue (was skipped)": "✖", "now checked": "·",
                       "not checked now": "·"}.get(kind, "·")
                if not UNICODE:
                    sym = {"better": "v", "worse": "^", "new issue": "x",
                           "new issue (was skipped)": "x"}.get(kind, "-")
                transition = r.status if old_status is None else f"{old_status} {arrow} {r.status}"
                extra = ""
                if kind in ("worse", "new issue", "new issue (was skipped)") and r.detail:
                    detail = r.detail if len(r.detail) <= 90 else r.detail[:87] + "..."
                    extra = f": {detail}"
                lines.append(f"  {sym} {r.title} ({r.id})  {transition}  ({kind}){extra}")
            if len(changes) > 25:
                lines.append(f"  ... and {len(changes) - 25} more check change(s)")
        else:
            lines.append("  No check changed status.")
    elif old.get("checks") is not None:
        lines.append("")
        lines.append("  (that report has no per-check data; save one with --json to compare checks)")
    return "\n".join(lines)


def completion_script(shell: str) -> str:
    ids = " ".join(check_id(fn) for _c, _w, _t, fn in CHECKS)
    cats = " ".join(category_key(c).split("-")[0] for c in CAT_ORDER)
    checks = f"{ids} {cats} all"
    options = ("--json --audit --redact --prometheus --card --share --badge --fix --history "
               "--no-history --quiet --verbose --min --theme --no-color --color --version "
               "--debug --list-checks --only --skip --compare --fail-on --fail-on-new --ascii "
               "--completion --config --no-config --help -q -v -h")

    if shell == "bash":
        return """# bash completion for lscore
# Install: lscore --completion bash > ~/.local/share/bash-completion/completions/lscore
_lscore() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    case "$prev" in
        --card|--compare|--config|--prometheus)
            COMPREPLY=( $(compgen -f -- "$cur") ); return 0 ;;
        --min)
            COMPREPLY=(); return 0 ;;
        --only|--skip)
            COMPREPLY=( $(compgen -W "__CHECKS__" -- "$cur") ); return 0 ;;
        --fail-on)
            COMPREPLY=( $(compgen -W "warn fail" -- "$cur") ); return 0 ;;
        --color)
            COMPREPLY=( $(compgen -W "auto always never" -- "$cur") ); return 0 ;;
        --theme)
            COMPREPLY=( $(compgen -W "rose basic" -- "$cur") ); return 0 ;;
        --completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ); return 0 ;;
    esac
    COMPREPLY=( $(compgen -W "__OPTIONS__" -- "$cur") )
}
complete -F _lscore lscore
""".replace("__CHECKS__", checks).replace("__OPTIONS__", options)

    if shell == "zsh":
        return """#compdef lscore
# Install: lscore --completion zsh > "${fpath[1]}/_lscore"
_lscore() {
  _arguments -s \\
    '--json[machine-readable output]' \\
    '--audit[show every file read and command run]' \\
    '--redact[replace your home path with $HOME in --audit]' \\
    '--prometheus=[write node_exporter metrics]:file:_files' \\
    '--card=-[save a shareable SVG card]:file:_files' \\
    '--share[print a plain-text summary to paste in a post]' \\
    '--badge[print a Markdown badge for your README]' \\
    '--fix[print a fix script to review (nothing is executed)]' \\
    '--history[show your score over time]' \\
    '--no-history[do not record this run]' \\
    '(-q --quiet)'{-q,--quiet}'[print only the score]' \\
    '(-v --verbose)'{-v,--verbose}'[show every check]' \\
    '--min=[exit 1 below this score]:score:' \\
    '--theme=[color palette]:palette:(rose basic)' \\
    '--no-color[disable colors]' \\
    '--color=[when to use color]:when:(auto always never)' \\
    '--version[print the version]' \\
    '--debug[print tracebacks for crashing checks]' \\
    '--list-checks[list every check and exit]' \\
    '*--only=[run only these checks]:check:(__CHECKS__)' \\
    '*--skip=[skip these checks]:check:(__CHECKS__)' \\
    '--compare=[compare with a saved JSON report]:file:_files' \\
    '--fail-on-new[exit 1 if a compared check got worse]' \\
    '--config=[read defaults from this INI file]:file:_files' \\
    '--no-config[ignore the config file for this run]' \\
    '--fail-on=[exit 1 on this severity]:severity:(warn fail)' \\
    '--ascii[use ASCII symbols instead of Unicode]' \\
    '--completion=[print a shell completion script]:shell:(bash zsh fish)' \\
    '(-h --help)'{-h,--help}'[show help]'
}
_lscore "$@"
""".replace("__CHECKS__", checks)

    if shell == "fish":
        lines = ["# fish completion for lscore",
                 "# Install: lscore --completion fish > ~/.config/fish/completions/lscore.fish",
                 "complete -c lscore -f"]
        for flag, desc in (("json", "machine-readable output"),
                           ("audit", "show every file read and command run"),
                           ("redact", "replace your home path with $HOME in --audit"),
                           ("share", "print a plain-text summary to paste in a post"),
                           ("badge", "print a Markdown badge for your README"),
                           ("fix", "print a fix script to review (nothing is executed)"),
                           ("history", "show your score over time"),
                           ("no-history", "do not record this run"),
                           ("no-color", "disable colors"),
                           ("version", "print the version"),
                           ("debug", "print tracebacks for crashing checks"),
                           ("list-checks", "list every check and exit"),
                           ("ascii", "use ASCII symbols instead of Unicode")):
            lines.append(f"complete -c lscore -l {flag} -d '{desc}'")
        lines += [
            "complete -c lscore -s q -l quiet -d 'print only the score'",
            "complete -c lscore -s v -l verbose -d 'show every check'",
            "complete -c lscore -s h -l help -d 'show help'",
            "complete -c lscore -l card -r -F -d 'save a shareable SVG card'",
            "complete -c lscore -l prometheus -r -F -d 'write node_exporter metrics'",
            "complete -c lscore -l compare -r -F -d 'compare with a saved JSON report'",
            "complete -c lscore -l fail-on-new -d 'exit 1 if a compared check got worse'",
            "complete -c lscore -l config -r -F -d 'read defaults from this INI file'",
            "complete -c lscore -l no-config -d 'ignore the config file for this run'",
            "complete -c lscore -l min -x -d 'exit 1 below this score'",
            "complete -c lscore -l theme -x -a 'rose basic' -d 'color palette'",
            "complete -c lscore -l color -x -a 'auto always never' -d 'when to use color'",
            "complete -c lscore -l fail-on -x -a 'warn fail' -d 'exit 1 on this severity'",
            "complete -c lscore -l completion -x -a 'bash zsh fish' -d 'print a completion script'",
            f"complete -c lscore -l only -x -a '{checks}' -d 'run only these checks'",
            f"complete -c lscore -l skip -x -a '{checks}' -d 'skip these checks'",
        ]
        return "\n".join(lines) + "\n"

    raise ValueError(f"unsupported shell: {shell}")


# CLI

def main(argv: Optional[List[str]] = None) -> int:
    global UNICODE, AUDIT
    ap = argparse.ArgumentParser(
        prog="lscore", description="Linux Score: a one-command health check for your Linux machine.",
        epilog="Read-only and offline. History stays in ~/.local/state/lscore/history.jsonl "
               "unless --no-history is used. Config: ~/.config/lscore/config.ini. "
               "Exit codes: 0 ok, 1 threshold, 2 error. Manual: man lscore.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--audit", action="store_true",
                    help="show every file read and command run (proof it is read-only)")
    ap.add_argument("--redact", action="store_true",
                    help="with --audit, replace your home path with $HOME")
    ap.add_argument("--prometheus", metavar="FILE",
                    help="write node_exporter textfile metrics to FILE")
    ap.add_argument("--card", nargs="?", const="lscore-card.svg", metavar="FILE",
                    help="save a shareable SVG card (default: lscore-card.svg)")
    ap.add_argument("--share", action="store_true", help="print a plain-text summary to paste in a post")
    ap.add_argument("--badge", action="store_true", help="print a Markdown badge for your README")
    ap.add_argument("--fix", action="store_true", help="print a fix script to review (nothing is executed)")
    ap.add_argument("--history", action="store_true",
                    help="show score history (recorded locally unless --no-history)")
    ap.add_argument("--no-history", action="store_true",
                    help="don't record this run in history")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only the score")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show every check, including passed and skipped")
    ap.add_argument("--min", type=int, metavar="N", help="exit 1 if the score is below N (for CI)")
    ap.add_argument("--fail-on", choices=("warn", "fail"), metavar="LEVEL",
                    help="exit 1 on a warning or failure (for CI)")
    ap.add_argument("--only", action="append", metavar="ID",
                    help="run only these checks or categories (repeatable, comma-separated)")
    ap.add_argument("--skip", action="append", metavar="ID",
                    help="skip these checks or categories (repeatable, comma-separated)")
    ap.add_argument("--list-checks", action="store_true",
                    help="list every check and exit (JSON with --json)")
    ap.add_argument("--compare", nargs="?", const="@last", metavar="FILE",
                    help="compare with a saved --json report (no value: your last recorded run)")
    ap.add_argument("--fail-on-new", action="store_true",
                    help="exit 1 if any check got worse than the --compare report")
    config_group = ap.add_mutually_exclusive_group()
    config_group.add_argument("--config", metavar="FILE",
                              help="read defaults from this INI file (default: ~/.config/lscore/config.ini)")
    config_group.add_argument("--no-config", action="store_true",
                              help="ignore the config file for this run")
    ap.add_argument("--theme", choices=("rose", "basic"),
                    help="color palette: rose (default) or basic for light terminals")
    ap.add_argument("--color", choices=("auto", "always", "never"), metavar="WHEN",
                    help="when to use colors: auto (default), always, never")
    ap.add_argument("--no-color", action="store_true", help="disable colors (same as --color never)")
    ap.add_argument("--ascii", action="store_true", help="use ASCII symbols and rules instead of Unicode")
    ap.add_argument("--debug", action="store_true", help="print tracebacks for checks that crash")
    ap.add_argument("--completion", choices=("bash", "zsh", "fish"), metavar="SHELL",
                    help="print a shell completion script and exit")
    ap.add_argument("--version", action="version", version=f"lscore {__version__}")
    args = ap.parse_args(argv)
    AUDIT = Audit()          # a fresh proof for this run, even if main() is called twice
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")      # never crash on exotic terminal encodings

    old_unicode = UNICODE
    if args.ascii:
        UNICODE = False
    try:
        if args.completion:
            print(completion_script(args.completion))
            return 0

        cfg: Dict[str, object] = {}
        if not args.no_config:
            cfg_file = args.config or config_path()
            try:
                cfg, cfg_warnings = load_config(cfg_file, strict=bool(args.config))
            except (OSError, ValueError) as exc:
                print(f"lscore: couldn't read config {cfg_file}: {exc}", file=sys.stderr)
                return 2
            for warning in cfg_warnings:
                print(f"lscore: config: {warning}", file=sys.stderr)

        only_values = args.only if args.only else cfg.get("only") or []
        skip_values = args.skip if args.skip else cfg.get("skip") or []

        if args.list_checks:
            # --list-checks ignores the config's only/skip, but honors explicit CLI filters.
            listed, unknown = filter_checks(split_tokens(args.only), split_tokens(args.skip))
            if unknown:
                print("lscore: unknown check or category: " + ", ".join(unknown), file=sys.stderr)
                print("lscore: run `lscore --list-checks` to see every id.", file=sys.stderr)
                return 2
            print(list_checks_json(listed) if args.json else list_checks_text(listed))
            return 0

        selected, unknown = filter_checks(split_tokens(only_values), split_tokens(skip_values))
        if unknown:
            print("lscore: unknown check or category: " + ", ".join(unknown), file=sys.stderr)
            print("lscore: run `lscore --list-checks` to see every id.", file=sys.stderr)
            return 2

        min_score = args.min if args.min is not None else cfg.get("min")
        fail_on = args.fail_on if args.fail_on is not None else cfg.get("fail_on")
        theme = args.theme or cfg.get("theme") or os.environ.get("LSCORE_THEME", "rose")
        ascii_mode = args.ascii or bool(cfg.get("ascii", False))
        if ascii_mode:
            UNICODE = False
        no_history = (args.no_history or bool(cfg.get("no_history", False))
                      or env_truthy("LSCORE_NO_HISTORY"))

        old_report = None
        compare_source = ""
        if args.compare is not None:
            if args.compare == "@last":
                try:
                    old_report = load_last_history_report()
                except ValueError as exc:
                    print(f"lscore: {exc}", file=sys.stderr)
                    return 2
                compare_source = "your last recorded run"
            else:
                try:
                    old_report = load_report_file(args.compare)
                except (OSError, ValueError) as exc:
                    print(f"lscore: couldn't read {args.compare}: {exc}", file=sys.stderr)
                    return 2
                compare_source = args.compare

        if args.fail_on_new:
            if old_report is None:
                print("lscore: --fail-on-new needs --compare FILE (a saved --json report)",
                      file=sys.stderr)
                return 2
            if not old_report.get("checks"):
                print("lscore: --fail-on-new needs a --json report with per-check results",
                      file=sys.stderr)
                return 2
        if args.redact and not args.audit:
            print("lscore: --redact needs --audit", file=sys.stderr)
            return 2

        if not selected:
            print("lscore: no checks selected.", file=sys.stderr)
            return 2

        color_when = "never" if args.no_color else (
            args.color or cfg.get("color") or "auto")
        use_color = (color_when == "always" or (
            color_when == "auto" and sys.stdout.isatty()
            and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"))
        p = make_painter(color_mode(theme) if use_color else None)
        show_progress = sys.stderr.isatty() and not (args.json or args.quiet)

        def progress(n: int, total: int, title: str) -> None:
            if show_progress:
                sys.stderr.write(f"\r\033[K  scanning... {n}/{total}  {title}")
                sys.stderr.flush()

        ctx = Ctx()
        results = run_checks(ctx, progress, selected, args.debug)
        if show_progress:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

        rep = build_report(results, system_info(ctx))
        if rep is None:
            print("lscore: couldn't run any checks on this system.", file=sys.stderr)
            return 2

        recorded = not no_history and bool(record_score(rep))
        regressed = new_issues(rep, old_report) if args.fail_on_new and old_report else []

        if args.json:
            if not args.audit:
                print(to_json(rep))
        elif args.quiet:
            print(rep.score)
        elif args.fix:
            print(fix_script(rep))
        elif args.share:
            print(share_text(rep))
        else:
            render(rep, p, args.verbose)
            if args.history:
                render_history(load_history(), p, recorded, args.verbose, ctx.is_root)

        # keep add-ons off stdout when another flag owns it
        extras = sys.stderr if (args.json or args.fix or args.quiet or args.share) else sys.stdout
        failed = False
        if args.card:
            try:
                with open(args.card, "w", encoding="utf-8") as f:
                    f.write(make_card(rep))
                AUDIT.wrote(args.card)
                print(f"  Card saved to {args.card}  (open it in a browser and screenshot it)", file=extras)
            except OSError as exc:
                print(f"lscore: couldn't write the card: {exc}", file=sys.stderr)
                failed = True
        if args.prometheus:
            try:
                write_atomic(args.prometheus, prometheus_text(rep))
                AUDIT.wrote(args.prometheus)
                print(f"  Metrics saved to {args.prometheus}", file=extras)
            except OSError as exc:
                print(f"lscore: couldn't write metrics: {exc}", file=sys.stderr)
                failed = True
        if args.badge:
            print(badge_md(rep), file=extras)
        if old_report is not None:
            print(file=extras)
            comparison = compare_lines(rep, old_report, compare_source)
            if args.fail_on_new:
                comparison += "\n" + (
                    f"  New issues: {len(regressed)}  (--fail-on-new)"
                    if regressed else "  New issues: none")
            print(comparison, file=extras)
        if args.audit:
            snapshot = AUDIT.snapshot()
            if args.redact:
                snapshot = redact_audit(snapshot, os.path.expanduser("~"))
            if args.json:
                print(to_json(rep, snapshot))
            else:
                render_audit(snapshot, p, extras)

        if failed:
            return 2
        tripped = (fail_on == "warn" and any(r.status in ("warn", "fail") for r in rep.results)) \
            or (fail_on == "fail" and any(r.status == "fail" for r in rep.results))
        return 1 if tripped or regressed or (
            min_score is not None and rep.score < min_score) else 0
    finally:
        UNICODE = old_unicode


def cli_main() -> None:
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    cli_main()
