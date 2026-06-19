from __future__ import annotations

import ctypes
import ipaddress
import os
import platform
import re
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import psutil
except ImportError:  # pragma: no cover - exercised when optional dependency is absent.
    psutil = None


IS_WINDOWS = platform.system() == "Windows"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    path: str = ""
    command_line: str = ""
    username: str = ""
    create_time: float | None = None
    signer_status: str = "UNKNOWN"
    signer_subject: str = ""


@dataclass(frozen=True)
class MemoryRegion:
    base_address: int
    size: int
    protection: int
    region_type: int
    state: int

    @property
    def key(self) -> tuple[int, int, int]:
        return (self.base_address, self.size, self.protection)


@dataclass(frozen=True)
class ThreadInfo:
    tid: int
    owner_pid: int
    start_address: int | None = None
    start_region: MemoryRegion | None = None


@dataclass(frozen=True)
class NetworkPortInfo:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str = ""
    remote_port: int = 0
    status: str = ""
    pid: int = 0
    process_name: str = ""
    process_path: str = ""

    @property
    def key(self) -> tuple[str, str, int, str, int, str, int]:
        return (
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port,
            self.status,
            self.pid,
        )

    @property
    def direction(self) -> str:
        if self.status.upper() == "LISTEN":
            return "listening"
        if self.remote_address:
            return "connected"
        return "open"

    def as_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "remote_scope": network_address_scope(self.remote_address),
            "status": self.status,
            "direction": self.direction,
            "pid": self.pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "listener_exposure": listener_exposure(self.local_address, self.status),
        }


@dataclass(frozen=True)
class ProcessMemorySample:
    pid: int
    rss_bytes: int
    memory_percent: float
    status: str

    @property
    def rss_mb(self) -> float:
        return round(self.rss_bytes / (1024 * 1024), 2)


@dataclass
class MemorySurgeRecord:
    pid: int
    process_name: str
    process_path: str
    first_seen: str
    last_seen: str
    baseline_rss_bytes: int
    peak_rss_bytes: int
    latest_rss_bytes: int
    peak_growth_percent: float
    latest_growth_percent: float
    peak_memory_percent: float
    latest_memory_percent: float
    status: str
    persistence_cycles: int = 0
    sleeping_after_surge: bool = False
    alive: bool = True
    sleep_event_emitted: bool = False

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "baseline_rss_mb": round(self.baseline_rss_bytes / (1024 * 1024), 2),
            "peak_rss_mb": round(self.peak_rss_bytes / (1024 * 1024), 2),
            "latest_rss_mb": round(self.latest_rss_bytes / (1024 * 1024), 2),
            "peak_growth_percent": round(self.peak_growth_percent, 2),
            "latest_growth_percent": round(self.latest_growth_percent, 2),
            "peak_memory_percent": round(self.peak_memory_percent, 3),
            "latest_memory_percent": round(self.latest_memory_percent, 3),
            "status": self.status,
            "persistence_cycles": self.persistence_cycles,
            "sleeping_after_surge": self.sleeping_after_surge,
            "alive": self.alive,
        }


@dataclass
class WatchedRegion:
    pid: int
    base_address: int
    size: int
    previous_protection: int
    first_seen: float
    last_seen: float
    source: str
    thread_id: int | None = None
    alerted: bool = False


@dataclass
class MonitorEvent:
    timestamp: str
    severity: str
    category: str
    pid: int
    process_name: str
    message: str
    score: int
    process_path: str = ""
    parent_pid: int | None = None
    parent_name: str = ""
    thread_id: int | None = None
    evidence: dict[str, str | int | float | bool | None] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "pid": self.pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "thread_id": self.thread_id,
            "score": self.score,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class MonitorConfig:
    duration_seconds: int = 20
    interval_seconds: float = 1.0
    inspect_thread_starts: bool = True
    inspect_memory_regions: bool = True
    inspect_page_transitions: bool = True
    transition_watch_seconds: int = 30
    max_processes_per_cycle: int = 80
    max_regions_per_process: int = 2048
    max_events: int = 500
    include_process_starts: bool = True
    inspect_network_ports: bool = True
    max_network_connections: int = 500
    inspect_memory_growth: bool = True
    memory_growth_percent_threshold: float = 35.0
    memory_growth_min_mb: int = 8
    memory_persistence_cycles: int = 2


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def network_address_scope(address: str) -> str:
    if not address:
        return ""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "name"
    if ip.is_unspecified:
        return "all_interfaces"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    return "public"


def listener_exposure(address: str, status: str) -> str:
    if status.upper() != "LISTEN":
        return ""
    scope = network_address_scope(address)
    if scope == "all_interfaces":
        return "all_interfaces"
    if scope in {"public", "private"}:
        return scope
    return "local_only"


def collect_demo_system_telemetry() -> dict[str, str | bool]:
    """Collect intentionally low-sensitivity host facts for the local demo."""
    desktop_path = Path.home() / "Desktop"
    return {
        "device_name": platform.node() or "unknown",
        "os_name": platform.system() or "unknown",
        "os_release": platform.release() or "unknown",
        "os_version": platform.version() or "unknown",
        "architecture": platform.machine() or "unknown",
        "desktop_folder_present": desktop_path.exists(),
        "desktop_probe_scope": "existence check only; no desktop files are read",
        "destination": "local Streamlit session state",
    }


class WindowsApiProbe:
    TH32CS_SNAPPROCESS = 0x00000002
    TH32CS_SNAPTHREAD = 0x00000004
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    THREAD_QUERY_INFORMATION = 0x0040
    THREAD_QUERY_LIMITED_INFORMATION = 0x0800
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    MEM_IMAGE = 0x1000000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100
    EXECUTE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    ThreadQuerySetWin32StartAddress = 9

    def __init__(self) -> None:
        if not IS_WINDOWS:
            raise OSError("Live monitoring is available on Windows only.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        self._signature_cache: dict[str, tuple[str, str]] = {}
        self._configure_prototypes()
        self.max_application_address = self._max_application_address()

    def _configure_prototypes(self) -> None:
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self.kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_int
        self.kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel32.OpenProcess.restype = ctypes.c_void_p
        self.kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel32.OpenThread.restype = ctypes.c_void_p
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        self.kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel32.Process32FirstW.restype = ctypes.c_int
        self.kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel32.Process32NextW.restype = ctypes.c_int
        self.kernel32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel32.Thread32First.restype = ctypes.c_int
        self.kernel32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel32.Thread32Next.restype = ctypes.c_int
        self.kernel32.GetNativeSystemInfo.argtypes = [ctypes.c_void_p]
        self.kernel32.GetNativeSystemInfo.restype = None
        self.kernel32.VirtualQueryEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.ntdll.NtQueryInformationThread.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        self.ntdll.NtQueryInformationThread.restype = ctypes.c_long

    def _max_application_address(self) -> int:
        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", ctypes.c_ushort),
                ("wReserved", ctypes.c_ushort),
                ("dwPageSize", ctypes.c_uint32),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_size_t),
                ("dwNumberOfProcessors", ctypes.c_uint32),
                ("dwProcessorType", ctypes.c_uint32),
                ("dwAllocationGranularity", ctypes.c_uint32),
                ("wProcessorLevel", ctypes.c_ushort),
                ("wProcessorRevision", ctypes.c_ushort),
            ]

        info = SYSTEM_INFO()
        self.kernel32.GetNativeSystemInfo(ctypes.byref(info))
        return int(info.lpMaximumApplicationAddress or 0x7FFFFFFF)

    def _close(self, handle: int | None) -> None:
        if handle and handle != self.INVALID_HANDLE_VALUE:
            self.kernel32.CloseHandle(handle)

    @staticmethod
    def is_executable_protection(protection: int) -> bool:
        if protection & WindowsApiProbe.PAGE_GUARD:
            return False
        base_protection = protection & 0xFF
        return base_protection in WindowsApiProbe.EXECUTE_PROTECTIONS

    @staticmethod
    def protection_name(protection: int) -> str:
        names = {
            0x01: "NOACCESS",
            0x02: "READONLY",
            0x04: "READWRITE",
            0x08: "WRITECOPY",
            0x10: "EXECUTE",
            0x20: "EXECUTE_READ",
            0x40: "EXECUTE_READWRITE",
            0x80: "EXECUTE_WRITECOPY",
        }
        suffix = "|GUARD" if protection & WindowsApiProbe.PAGE_GUARD else ""
        return names.get(protection & 0xFF, f"0x{protection:x}") + suffix

    @staticmethod
    def region_type_name(region_type: int) -> str:
        if region_type == WindowsApiProbe.MEM_PRIVATE:
            return "MEM_PRIVATE"
        if region_type == WindowsApiProbe.MEM_IMAGE:
            return "MEM_IMAGE"
        if region_type == WindowsApiProbe.MEM_MAPPED:
            return "MEM_MAPPED"
        return f"0x{region_type:x}"

    def open_process(self, pid: int, access: int | None = None) -> int | None:
        access = access or (self.PROCESS_QUERY_INFORMATION | self.PROCESS_QUERY_LIMITED_INFORMATION)
        handle = self.kernel32.OpenProcess(access, False, pid)
        return int(handle) if handle else None

    def query_process_path(self, pid: int) -> str:
        handle = self.open_process(pid, self.PROCESS_QUERY_LIMITED_INFORMATION)
        if not handle:
            return ""
        try:
            size = ctypes.c_uint32(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            ok = self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
            if ok:
                return buffer.value
            return ""
        finally:
            self._close(handle)

    def iter_processes(self) -> list[ProcessInfo]:
        if psutil is not None:
            processes: list[ProcessInfo] = []
            attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
            for process in psutil.process_iter(attrs):
                try:
                    info = process.info
                    cmdline = info.get("cmdline") or []
                    processes.append(
                        ProcessInfo(
                            pid=int(info.get("pid") or 0),
                            parent_pid=int(info.get("ppid") or 0),
                            name=info.get("name") or "",
                            path=info.get("exe") or "",
                            command_line=subprocess.list2cmdline(cmdline) if isinstance(cmdline, list) else str(cmdline),
                            username=info.get("username") or "",
                            create_time=info.get("create_time"),
                        )
                    )
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
            if processes:
                return processes

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_uint32),
                ("cntUsage", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_uint32),
                ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        snapshot = self.kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        if snapshot == self.INVALID_HANDLE_VALUE:
            return []

        processes: list[ProcessInfo] = []
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        try:
            if not self.kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return []
            while True:
                pid = int(entry.th32ProcessID)
                processes.append(
                    ProcessInfo(
                        pid=pid,
                        parent_pid=int(entry.th32ParentProcessID),
                        name=entry.szExeFile,
                        path=self.query_process_path(pid),
                    )
                )
                if not self.kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
        finally:
            self._close(snapshot)
        return processes

    def enrich_signature(self, process: ProcessInfo) -> ProcessInfo:
        if not process.path:
            return process
        status, subject = self._signature_for_path(process.path)
        return replace(process, signer_status=status, signer_subject=subject)

    def _signature_for_path(self, path: str) -> tuple[str, str]:
        normalized = path.lower()
        if normalized in self._signature_cache:
            return self._signature_cache[normalized]
        if not os.path.exists(path):
            result = ("MISSING", "")
            self._signature_cache[normalized] = result
            return result

        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$s = Get-AuthenticodeSignature -LiteralPath $args[0]; "
            "($s.Status.ToString() + '|' + ($s.SignerCertificate.Subject -replace '\\r|\\n',' '))",
            path,
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            output = (completed.stdout or "").strip().splitlines()[-1] if completed.stdout.strip() else ""
            status, _, subject = output.partition("|")
            result = ((status or "UNKNOWN").upper(), subject.strip())
        except (OSError, subprocess.SubprocessError):
            result = ("UNKNOWN", "")
        self._signature_cache[normalized] = result
        return result

    def iter_threads(self) -> list[ThreadInfo]:
        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_uint32),
                ("cntUsage", ctypes.c_uint32),
                ("th32ThreadID", ctypes.c_uint32),
                ("th32OwnerProcessID", ctypes.c_uint32),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32),
            ]

        snapshot = self.kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPTHREAD, 0)
        if snapshot == self.INVALID_HANDLE_VALUE:
            return []

        threads: list[ThreadInfo] = []
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        try:
            if not self.kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                return []
            while True:
                threads.append(
                    ThreadInfo(
                        tid=int(entry.th32ThreadID),
                        owner_pid=int(entry.th32OwnerProcessID),
                    )
                )
                if not self.kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                    break
        finally:
            self._close(snapshot)
        return threads

    def thread_start_info(self, thread: ThreadInfo) -> ThreadInfo:
        thread_handle = self.kernel32.OpenThread(
            self.THREAD_QUERY_LIMITED_INFORMATION | self.THREAD_QUERY_INFORMATION,
            False,
            thread.tid,
        )
        if not thread_handle:
            return thread

        process_handle = None
        try:
            start_address = ctypes.c_void_p()
            return_length = ctypes.c_ulong()
            status = self.ntdll.NtQueryInformationThread(
                thread_handle,
                self.ThreadQuerySetWin32StartAddress,
                ctypes.byref(start_address),
                ctypes.sizeof(start_address),
                ctypes.byref(return_length),
            )
            if status != 0 or not start_address.value:
                return thread

            process_handle = self.open_process(thread.owner_pid)
            region = self.query_region(process_handle, int(start_address.value)) if process_handle else None
            return ThreadInfo(
                tid=thread.tid,
                owner_pid=thread.owner_pid,
                start_address=int(start_address.value),
                start_region=region,
            )
        finally:
            self._close(process_handle)
            self._close(thread_handle)

    def query_region(self, process_handle: int, address: int) -> MemoryRegion | None:
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_uint32),
                ("PartitionId", ctypes.c_ushort),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_uint32),
                ("Protect", ctypes.c_uint32),
                ("Type", ctypes.c_uint32),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        result = self.kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not result:
            return None
        return MemoryRegion(
            base_address=int(mbi.BaseAddress or 0),
            size=int(mbi.RegionSize),
            protection=int(mbi.Protect),
            region_type=int(mbi.Type),
            state=int(mbi.State),
        )

    def query_process_region(self, pid: int, address: int) -> MemoryRegion | None:
        handle = self.open_process(pid)
        if not handle:
            return None
        try:
            return self.query_region(handle, address)
        finally:
            self._close(handle)

    def private_executable_regions(self, pid: int, max_regions: int) -> list[MemoryRegion]:
        handle = self.open_process(pid)
        if not handle:
            return []

        regions: list[MemoryRegion] = []
        address = 0
        queried = 0
        try:
            while address < self.max_application_address and queried < max_regions:
                region = self.query_region(handle, address)
                if region is None or region.size <= 0:
                    address += 0x10000
                    continue
                queried += 1
                if (
                    region.state == self.MEM_COMMIT
                    and region.region_type == self.MEM_PRIVATE
                    and self.is_executable_protection(region.protection)
                ):
                    regions.append(region)
                address = region.base_address + region.size
        finally:
            self._close(handle)
        return regions


class BehaviorRuleEngine:
    REMOTE_CONTROL_OR_FILE_PORTS = {
        20: "FTP data",
        21: "FTP control",
        22: "SSH/SFTP",
        445: "SMB file sharing",
        548: "AFP file sharing",
        873: "rsync",
        3389: "Remote Desktop",
        5900: "VNC remote screen",
        5938: "TeamViewer",
        6568: "AnyDesk",
        7070: "Real-time media",
        9001: "Tor relay/control-adjacent",
    }
    SCRIPT_OR_LOLBIN_NAMES = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "msiexec.exe",
        "schtasks.exe",
    }
    EXPLOIT_PRONE_PARENTS = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "teams.exe",
        "slack.exe",
        "discord.exe",
        "acrord32.exe",
    }
    SYSTEM_NAMES = {
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "winlogon.exe",
        "csrss.exe",
        "spoolsv.exe",
        "smss.exe",
    }
    SENSITIVE_TARGETS = {
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "outlook.exe",
        "teams.exe",
        "slack.exe",
        "discord.exe",
    }
    JIT_HEAVY_PROCESSES = {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
    }
    USER_WRITABLE_MARKERS = (
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\downloads\\",
        "\\users\\public\\",
        "\\programdata\\",
        "\\temp\\",
    )
    USER_INITIATED_PARENTS = {
        "explorer.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "windowsterminal.exe",
        "conhost.exe",
        "wt.exe",
    }
    BACKGROUND_OR_AUTOMATION_PARENTS = {
        "services.exe",
        "svchost.exe",
        "taskeng.exe",
        "taskhostw.exe",
        "wmiprvse.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
    }
    COMMANDLINE_PATTERNS = (
        (re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\b"), "encoded PowerShell command"),
        (re.compile(r"(?i)\b(?:iex|invoke-expression)\b"), "Invoke-Expression execution"),
        (re.compile(r"(?i)\bdownloadstring\b|\binvoke-webrequest\b|\biwr\b|\bcurl\s+https?://"), "scripted network download"),
        (re.compile(r"(?i)\bfrombase64string\b"), "base64 decoding"),
        (re.compile(r"(?i)(?:^|\s)-(?:w\s+hidden|windowstyle\s+hidden)\b"), "hidden script window"),
        (re.compile(r"(?i)(?:^|\s)-executionpolicy\s+bypass\b"), "PowerShell execution policy bypass"),
    )
    TRUSTED_UPDATER_PARENTS = {
        "code.exe",
        "code - insiders.exe",
    }
    SLEEP_LIKE_STATUSES = {
        "sleeping",
        "disk-sleep",
        "stopped",
        "parked",
        "idle",
    }

    def process_start_events(self, process: ProcessInfo, parent: ProcessInfo | None) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        name = process.name.lower()
        parent_name = (parent.name if parent else "").lower()
        path = process.path.lower()

        if parent_name in self.EXPLOIT_PRONE_PARENTS and name in self.SCRIPT_OR_LOLBIN_NAMES:
            events.append(
                self._event(
                    "HIGH",
                    "suspicious_process_tree",
                    process,
                    f"{parent_name} spawned {name}, a common post-exploitation child process",
                    35,
                    parent=parent,
                )
            )

        if name in self.SYSTEM_NAMES and path and "\\windows\\system32\\" not in path:
            events.append(
                self._event(
                    "HIGH",
                    "process_masquerading",
                    process,
                    f"{process.name} is running outside the expected Windows system directory",
                    40,
                    parent=parent,
                    evidence={"path": process.path},
                )
            )

        if name in self.SCRIPT_OR_LOLBIN_NAMES and self._is_user_writable_path(path):
            events.append(
                self._event(
                    "MEDIUM",
                    "user_writable_execution",
                    process,
                    f"{process.name} started from a user-writable location",
                    20,
                    parent=parent,
                    evidence={"path": process.path},
                )
            )

        if name in self.SCRIPT_OR_LOLBIN_NAMES and self._command_references_user_writable_path(process.command_line):
            events.append(
                self._event(
                    "MEDIUM",
                    "user_writable_script_argument",
                    process,
                    f"{process.name} references a script or payload from a user-writable path",
                    25,
                    parent=parent,
                    evidence={"command_line": self._redact_command_line(process.command_line)},
                )
            )

        command_findings = self._suspicious_command_line_findings(process.command_line)
        if command_findings:
            events.append(
                self._event(
                    "HIGH",
                    "suspicious_command_line",
                    process,
                    f"{process.name} started with suspicious command-line content",
                    35,
                    parent=parent,
                    evidence={
                        "command_line": self._redact_command_line(process.command_line),
                        "findings": ", ".join(command_findings),
                    },
                )
            )

        if parent_name in self.BACKGROUND_OR_AUTOMATION_PARENTS and name in self.SCRIPT_OR_LOLBIN_NAMES:
            events.append(
                self._event(
                    "MEDIUM",
                    "background_lolbin_launch",
                    process,
                    f"{parent_name} launched {name}; background LOLBin launches deserve review",
                    25,
                    parent=parent,
                    evidence={"parent_name": parent.name if parent else ""},
                )
            )

        if parent_name and parent_name not in self.USER_INITIATED_PARENTS and name in self.SCRIPT_OR_LOLBIN_NAMES:
            events.append(
                self._event(
                    "LOW",
                    "non_interactive_parent",
                    process,
                    f"{process.name} was not launched by a common interactive shell parent",
                    10,
                    parent=parent,
                    evidence={"parent_name": parent.name if parent else ""},
                )
            )

        reputation_events = self.reputation_events(process, parent)
        events.extend(reputation_events)

        return events

    def reputation_events(self, process: ProcessInfo, parent: ProcessInfo | None = None) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        path = process.path.lower()
        signer_status = process.signer_status.upper()
        user_writable = self._is_user_writable_path(path)

        if self._is_known_trusted_updater(process, parent):
            return []

        if process.path and user_writable and signer_status not in {"VALID", "UNKNOWN"}:
            events.append(
                self._event(
                    "HIGH",
                    "unsigned_user_writable_process",
                    process,
                    f"{process.name} is unsigned or untrusted and running from a user-writable path",
                    35,
                    parent=parent,
                    evidence={
                        "path": process.path,
                        "signer_status": process.signer_status,
                        "signer_subject": process.signer_subject,
                    },
                )
            )

        if signer_status not in {"VALID", "UNKNOWN"} and path and not self._is_windows_system_path(path):
            events.append(
                self._event(
                    "MEDIUM",
                    "untrusted_process_signature",
                    process,
                    f"{process.name} has an untrusted or missing Authenticode signature",
                    20,
                    parent=parent,
                    evidence={
                        "path": process.path,
                        "signer_status": process.signer_status,
                        "signer_subject": process.signer_subject,
                    },
                )
            )

        return events

    def reconnaissance_sleep_event(
        self,
        process: ProcessInfo,
        telemetry: dict[str, str | bool],
        sleep_seconds: float,
    ) -> MonitorEvent:
        return self._event(
            "MEDIUM",
            "demo_reconnaissance_then_sleep",
            process,
            f"{process.name} collected local host-profile telemetry and entered a demo sleep interval",
            25,
            evidence={
                "device_name": telemetry.get("device_name", "unknown"),
                "os_name": telemetry.get("os_name", "unknown"),
                "os_release": telemetry.get("os_release", "unknown"),
                "desktop_folder_present": telemetry.get("desktop_folder_present", False),
                "sleep_seconds": round(float(sleep_seconds), 3),
                "destination": telemetry.get("destination", "local Streamlit session state"),
                "scope": telemetry.get("desktop_probe_scope", "local demo telemetry"),
            },
        )

    def network_port_events(self, port: NetworkPortInfo) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        process = ProcessInfo(
            pid=port.pid,
            parent_pid=0,
            name=port.process_name or "unknown",
            path=port.process_path,
        )
        exposure = listener_exposure(port.local_address, port.status)

        if exposure == "all_interfaces":
            events.append(
                self._event(
                    "LOW",
                    "network_listener_all_interfaces",
                    process,
                    f"{process.name} is listening on {port.protocol}/{port.local_port} across all interfaces",
                    10,
                    evidence=port.as_dict(),
                )
            )
        elif exposure in {"public", "private"}:
            events.append(
                self._event(
                    "LOW",
                    "network_listener_reachable_interface",
                    process,
                    f"{process.name} is listening on {port.protocol}/{port.local_port} on a {exposure} address",
                    10,
                    evidence=port.as_dict(),
                )
            )

        remote_scope = network_address_scope(port.remote_address)
        watched_service = self.REMOTE_CONTROL_OR_FILE_PORTS.get(port.remote_port)
        if port.remote_address and remote_scope == "public" and watched_service:
            events.append(
                self._event(
                    "MEDIUM",
                    "public_remote_control_or_file_port",
                    process,
                    f"{process.name} has a public connection to {watched_service} port {port.remote_port}",
                    25,
                    evidence=port.as_dict(),
                )
            )

        return events

    def memory_growth_events(
        self,
        process: ProcessInfo,
        previous: ProcessMemorySample,
        current: ProcessMemorySample,
    ) -> list[MonitorEvent]:
        growth_percent = ((current.rss_bytes - previous.rss_bytes) / max(previous.rss_bytes, 1)) * 100
        delta_mb = (current.rss_bytes - previous.rss_bytes) / (1024 * 1024)
        severity = "HIGH" if growth_percent >= 200 or current.memory_percent >= 5.0 else "MEDIUM"
        score = 45 if severity == "HIGH" else 30
        return [
            self._event(
                severity,
                "sudden_memory_growth",
                process,
                f"{process.name} increased memory by {growth_percent:.1f}% in one interval",
                score,
                evidence={
                    "previous_rss_mb": round(previous.rss_mb, 2),
                    "current_rss_mb": round(current.rss_mb, 2),
                    "delta_mb": round(delta_mb, 2),
                    "growth_percent": round(growth_percent, 2),
                    "memory_percent": round(current.memory_percent, 3),
                    "status": current.status,
                },
            )
        ]

    def memory_surge_sleep_events(
        self,
        process: ProcessInfo,
        record: MemorySurgeRecord,
    ) -> list[MonitorEvent]:
        if not self._is_sleep_like_status(record.status):
            return []
        return [
            self._event(
                "MEDIUM",
                "memory_surge_then_sleep",
                process,
                f"{process.name} stayed alive after a sharp memory increase and moved into a sleep-like state",
                25,
                evidence={
                    "peak_growth_percent": round(record.peak_growth_percent, 2),
                    "peak_rss_mb": round(record.peak_rss_bytes / (1024 * 1024), 2),
                    "latest_rss_mb": round(record.latest_rss_bytes / (1024 * 1024), 2),
                    "memory_percent": round(record.latest_memory_percent, 3),
                    "status": record.status,
                    "persistence_cycles": record.persistence_cycles,
                },
            )
        ]

    @classmethod
    def should_track_memory_growth(cls, process: ProcessInfo) -> bool:
        process_name = process.name.lower()
        if process_name in cls.JIT_HEAVY_PROCESSES:
            return False
        if process.signer_status.upper() == "VALID" and not cls._is_user_writable_path(process.path.lower()):
            return False
        return True

    def thread_start_events(self, thread: ThreadInfo, owner: ProcessInfo | None) -> list[MonitorEvent]:
        if not owner or not thread.start_region:
            return []
        region = thread.start_region
        if (
            region.region_type == WindowsApiProbe.MEM_PRIVATE
            and WindowsApiProbe.is_executable_protection(region.protection)
        ):
            severity = "CRITICAL" if owner.name.lower() in self.SENSITIVE_TARGETS else "HIGH"
            score = 65 if severity == "CRITICAL" else 45
            return [
                self._event(
                    severity,
                    "private_executable_thread_start",
                    owner,
                    f"Thread {thread.tid} starts in private executable memory",
                    score,
                    thread_id=thread.tid,
                    evidence={
                        "start_address": self._hex(thread.start_address),
                        "region_base": self._hex(region.base_address),
                        "region_size": region.size,
                        "protection": WindowsApiProbe.protection_name(region.protection),
                        "region_type": WindowsApiProbe.region_type_name(region.region_type),
                    },
                )
            ]
        return []

    def memory_region_events(self, process: ProcessInfo, region: MemoryRegion) -> list[MonitorEvent]:
        process_name = process.name.lower()
        if process_name in self.JIT_HEAVY_PROCESSES:
            return []

        if process_name in self.SENSITIVE_TARGETS:
            return [
                self._event(
                    "HIGH",
                    "private_executable_memory",
                    process,
                    f"{process.name} has newly observed private executable memory",
                    35,
                    evidence={
                        "region_base": self._hex(region.base_address),
                        "region_size": region.size,
                        "protection": WindowsApiProbe.protection_name(region.protection),
                        "region_type": WindowsApiProbe.region_type_name(region.region_type),
                    },
                )
            ]
        return []

    def page_transition_events(
        self,
        process: ProcessInfo,
        watched: WatchedRegion,
        current_region: MemoryRegion,
    ) -> list[MonitorEvent]:
        if watched.alerted:
            return []
        if not self._is_sleep_obfuscation_transition(watched.previous_protection, current_region.protection):
            return []

        return [
            self._event(
                "CRITICAL",
                "sleep_obfuscation_page_transition",
                process,
                f"{process.name} changed watched executable memory to {WindowsApiProbe.protection_name(current_region.protection)}",
                70,
                thread_id=watched.thread_id,
                evidence={
                    "source": watched.source,
                    "region_base": self._hex(current_region.base_address),
                    "region_size": current_region.size,
                    "previous_protection": WindowsApiProbe.protection_name(watched.previous_protection),
                    "current_protection": WindowsApiProbe.protection_name(current_region.protection),
                    "region_type": WindowsApiProbe.region_type_name(current_region.region_type),
                    "age_seconds": round(time.monotonic() - watched.first_seen, 3),
                },
            )
        ]

    @classmethod
    def should_memory_scan(cls, process: ProcessInfo, is_new_process: bool) -> bool:
        process_name = process.name.lower()
        if process_name in cls.JIT_HEAVY_PROCESSES:
            return False
        return is_new_process or process_name in cls.SENSITIVE_TARGETS

    @staticmethod
    def _is_sleep_obfuscation_transition(previous_protection: int, current_protection: int) -> bool:
        if not WindowsApiProbe.is_executable_protection(previous_protection):
            return False
        current_base = current_protection & 0xFF
        return current_base in {
            WindowsApiProbe.PAGE_NOACCESS,
            0x04,  # PAGE_READWRITE
            0x08,  # PAGE_WRITECOPY
        }

    @staticmethod
    def _is_user_writable_path(path: str) -> bool:
        return any(marker in path for marker in BehaviorRuleEngine.USER_WRITABLE_MARKERS)

    @classmethod
    def _command_references_user_writable_path(cls, command_line: str) -> bool:
        return cls._is_user_writable_path(command_line.lower())

    @classmethod
    def _is_known_trusted_updater(cls, process: ProcessInfo, parent: ProcessInfo | None) -> bool:
        name = process.name.lower()
        path = process.path.lower()
        parent_name = (parent.name if parent else "").lower()

        if parent_name in cls.TRUSTED_UPDATER_PARENTS:
            return name.startswith("codesetup-") and "\\temp\\vscode-" in path

        if parent_name.startswith("codesetup-"):
            return name.startswith("codesetup-") and "\\temp\\is-" in path

        return False

    @staticmethod
    def _is_windows_system_path(path: str) -> bool:
        return "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path

    @classmethod
    def _suspicious_command_line_findings(cls, command_line: str) -> list[str]:
        if not command_line:
            return []
        findings = [description for pattern, description in cls.COMMANDLINE_PATTERNS if pattern.search(command_line)]
        try:
            parts = shlex.split(command_line, posix=False)
        except ValueError:
            parts = command_line.split()
        long_tokens = [part for part in parts if len(part) >= 120 and re.fullmatch(r"[A-Za-z0-9+/=]+", part)]
        if long_tokens:
            findings.append("long base64-like token")
        return findings

    @staticmethod
    def _redact_command_line(command_line: str) -> str:
        if len(command_line) <= 500:
            return command_line
        return command_line[:500] + "...<truncated>"

    @classmethod
    def _is_sleep_like_status(cls, status: str) -> bool:
        return status.lower() in cls.SLEEP_LIKE_STATUSES

    @staticmethod
    def _hex(value: int | None) -> str:
        return f"0x{value:x}" if value is not None else ""

    def _event(
        self,
        severity: str,
        category: str,
        process: ProcessInfo,
        message: str,
        score: int,
        parent: ProcessInfo | None = None,
        thread_id: int | None = None,
        evidence: dict | None = None,
    ) -> MonitorEvent:
        return MonitorEvent(
            timestamp=utc_now(),
            severity=severity,
            category=category,
            pid=process.pid,
            process_name=process.name,
            process_path=process.path,
            parent_pid=process.parent_pid,
            parent_name=parent.name if parent else "",
            thread_id=thread_id,
            score=score,
            message=message,
            evidence=evidence or {},
        )


class WindowsBehaviorMonitor:
    """Bounded Windows user-mode behavior monitor for anti-injection signals."""

    def __init__(self, config: MonitorConfig | None = None) -> None:
        self.config = config or MonitorConfig()
        self.rule_engine = BehaviorRuleEngine()
        self.current_pid = os.getpid()
        self.probe = WindowsApiProbe() if IS_WINDOWS else None

    @property
    def is_supported(self) -> bool:
        return IS_WINDOWS and self.probe is not None

    def run(self, progress_callback=None) -> dict:
        if not self.is_supported:
            return {
                "supported": False,
                "started_at": utc_now(),
                "ended_at": utc_now(),
                "events": [],
                "summary": {"risk_score": 0, "event_count": 0},
                "configuration": self._configuration_dict(),
                "message": "Live monitoring is available on Windows only.",
            }

        started = time.monotonic()
        started_at = utc_now()
        events: list[MonitorEvent] = []
        baseline_processes = self._process_map()
        seen_pids = set(baseline_processes)
        seen_threads = {thread.tid for thread in self.probe.iter_threads()}
        seen_regions: dict[int, set[tuple[int, int, int]]] = {}
        watched_regions: dict[tuple[int, int], WatchedRegion] = {}
        network_ports: list[NetworkPortInfo] = []
        seen_network_ports: set[tuple[str, str, int, str, int, str, int]] = set()
        previous_memory_samples: dict[int, ProcessMemorySample] = {}
        memory_surges: dict[int, MemorySurgeRecord] = {}

        if self.config.inspect_network_ports:
            network_ports = self.collect_live_ports(baseline_processes)
            seen_network_ports = {port.key for port in network_ports}
        if self.config.inspect_memory_growth:
            previous_memory_samples = self.collect_process_memory_samples(baseline_processes)

        if self.config.inspect_memory_regions:
            for process in self._memory_scan_candidates(baseline_processes, set()):
                seen_regions[process.pid] = {
                    region.key
                    for region in self.probe.private_executable_regions(
                        process.pid,
                        self.config.max_regions_per_process,
                    )
                }

        while time.monotonic() - started < self.config.duration_seconds:
            elapsed = time.monotonic() - started
            if progress_callback:
                progress_callback(min(1.0, elapsed / max(1, self.config.duration_seconds)))

            processes = self._process_map()
            new_pids = set(processes) - seen_pids

            if self.config.inspect_memory_growth:
                current_memory_samples = self.collect_process_memory_samples(processes)
                events.extend(
                    self._memory_growth_cycle_events(
                        processes,
                        previous_memory_samples,
                        current_memory_samples,
                        memory_surges,
                    )
                )
                previous_memory_samples = current_memory_samples

            if self.config.inspect_network_ports:
                network_ports = self.collect_live_ports(processes)
                for port in network_ports:
                    if port.key in seen_network_ports:
                        continue
                    seen_network_ports.add(port.key)
                    events.extend(self.rule_engine.network_port_events(port))

            if self.config.include_process_starts:
                for pid in sorted(new_pids):
                    if self._is_own_process(pid, processes):
                        continue
                    process = self._with_signature(processes[pid])
                    parent = processes.get(process.parent_pid) or baseline_processes.get(process.parent_pid)
                    parent = self._with_signature(parent) if parent else None
                    processes[pid] = process
                    events.extend(self.rule_engine.process_start_events(process, parent))

            if self.config.inspect_thread_starts:
                current_threads = self.probe.iter_threads()
                for thread in current_threads:
                    if thread.tid in seen_threads:
                        continue
                    seen_threads.add(thread.tid)
                    if thread.owner_pid == self.current_pid:
                        continue
                    if thread.owner_pid not in processes:
                        continue
                    enriched = self.probe.thread_start_info(thread)
                    events.extend(self.rule_engine.thread_start_events(enriched, processes.get(thread.owner_pid)))
                    if self.config.inspect_page_transitions and enriched.start_region:
                        self._watch_region(
                            watched_regions,
                            process=processes[thread.owner_pid],
                            region=enriched.start_region,
                            source="private executable thread start",
                            thread_id=enriched.tid,
                        )

            if self.config.inspect_memory_regions:
                for process in self._memory_scan_candidates(processes, new_pids):
                    if self._is_own_process(process.pid, processes):
                        continue
                    known = seen_regions.setdefault(process.pid, set())
                    for region in self.probe.private_executable_regions(
                        process.pid,
                        self.config.max_regions_per_process,
                    ):
                        if region.key in known:
                            continue
                        known.add(region.key)
                        events.extend(self.rule_engine.memory_region_events(process, region))
                        if self.config.inspect_page_transitions:
                            self._watch_region(
                                watched_regions,
                                process=process,
                                region=region,
                                source="private executable memory",
                            )

            if self.config.inspect_page_transitions:
                events.extend(self._page_transition_events(watched_regions, processes))

            if len(events) > self.config.max_events:
                events = events[-self.config.max_events:]

            seen_pids.update(new_pids)
            baseline_processes = processes
            time.sleep(max(0.25, self.config.interval_seconds))

        if progress_callback:
            progress_callback(1.0)

        return {
            "supported": True,
            "started_at": started_at,
            "ended_at": utc_now(),
            "events": [event.as_dict() for event in events],
            "summary": self._summary(events, network_ports),
            "configuration": self._configuration_dict(),
            "network_ports": [port.as_dict() for port in network_ports],
            "network_summary": self._network_summary(network_ports),
            "memory_surges": self._memory_surge_rows(memory_surges),
            "memory_surge_summary": self._memory_surge_summary(memory_surges),
            "message": "Monitoring session completed.",
        }

    def port_check_report(self) -> dict:
        started_at = utc_now()
        if psutil is None:
            return {
                "supported": False,
                "started_at": started_at,
                "ended_at": utc_now(),
                "events": [],
                "summary": self._port_check_summary([], []),
                "configuration": self._configuration_dict(),
                "network_ports": [],
                "network_summary": self._network_summary([]),
                "message": "Port checking requires psutil. Install dependencies with requirements.txt.",
            }

        processes = self._process_map() if self.is_supported else {}
        ports = self.collect_live_ports(processes)
        events: list[MonitorEvent] = []
        for port in ports:
            events.extend(self.rule_engine.network_port_events(port))

        return {
            "supported": True,
            "port_check": True,
            "started_at": started_at,
            "ended_at": utc_now(),
            "events": [event.as_dict() for event in events],
            "summary": self._port_check_summary(events, ports),
            "configuration": self._configuration_dict(),
            "network_ports": [port.as_dict() for port in ports],
            "network_summary": self._network_summary(ports),
            "message": "Live port check completed. Port state indicates possible communication paths, not proof of file or screen data transfer.",
        }

    def _watch_region(
        self,
        watched_regions: dict[tuple[int, int], WatchedRegion],
        process: ProcessInfo,
        region: MemoryRegion,
        source: str,
        thread_id: int | None = None,
    ) -> None:
        if not WindowsApiProbe.is_executable_protection(region.protection):
            return
        if region.region_type != WindowsApiProbe.MEM_PRIVATE:
            return
        if process.name.lower() in BehaviorRuleEngine.JIT_HEAVY_PROCESSES:
            return

        key = (process.pid, region.base_address)
        now = time.monotonic()
        existing = watched_regions.get(key)
        if existing:
            existing.previous_protection = region.protection
            existing.last_seen = now
            if thread_id is not None:
                existing.thread_id = thread_id
            return

        watched_regions[key] = WatchedRegion(
            pid=process.pid,
            base_address=region.base_address,
            size=region.size,
            previous_protection=region.protection,
            first_seen=now,
            last_seen=now,
            source=source,
            thread_id=thread_id,
        )

    def _page_transition_events(
        self,
        watched_regions: dict[tuple[int, int], WatchedRegion],
        processes: dict[int, ProcessInfo],
    ) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        now = time.monotonic()

        for key, watched in list(watched_regions.items()):
            if now - watched.first_seen > self.config.transition_watch_seconds:
                watched_regions.pop(key, None)
                continue

            process = processes.get(watched.pid)
            if process is None:
                watched_regions.pop(key, None)
                continue

            current_region = self.probe.query_process_region(watched.pid, watched.base_address)
            if current_region is None:
                watched_regions.pop(key, None)
                continue

            transition_events = self.rule_engine.page_transition_events(process, watched, current_region)
            if transition_events:
                watched.alerted = True
                events.extend(transition_events)
                continue

            if WindowsApiProbe.is_executable_protection(current_region.protection):
                watched.previous_protection = current_region.protection
            watched.last_seen = now

        return events

    def self_test_report(self) -> dict:
        """Return a synthetic report proving the behavior rules can fire."""
        parent = ProcessInfo(
            pid=4100,
            parent_pid=900,
            name="WINWORD.EXE",
            path=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        )
        child = ProcessInfo(
            pid=4108,
            parent_pid=4100,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        owner = ProcessInfo(
            pid=500,
            parent_pid=4,
            name="lsass.exe",
            path=r"C:\Windows\System32\lsass.exe",
        )
        region = MemoryRegion(
            base_address=0x100000,
            size=4096,
            protection=0x40,
            region_type=WindowsApiProbe.MEM_PRIVATE,
            state=WindowsApiProbe.MEM_COMMIT,
        )
        hidden_region = MemoryRegion(
            base_address=0x100000,
            size=4096,
            protection=WindowsApiProbe.PAGE_NOACCESS,
            region_type=WindowsApiProbe.MEM_PRIVATE,
            state=WindowsApiProbe.MEM_COMMIT,
        )
        thread = ThreadInfo(
            tid=900,
            owner_pid=owner.pid,
            start_address=0x100100,
            start_region=region,
        )
        watched = WatchedRegion(
            pid=owner.pid,
            base_address=region.base_address,
            size=region.size,
            previous_protection=region.protection,
            first_seen=time.monotonic(),
            last_seen=time.monotonic(),
            source="self-test private executable thread start",
            thread_id=thread.tid,
        )

        events = []
        events.extend(self.rule_engine.process_start_events(child, parent))
        events.extend(self.rule_engine.thread_start_events(thread, owner))
        events.extend(self.rule_engine.page_transition_events(owner, watched, hidden_region))

        return {
            "supported": True,
            "self_test": True,
            "started_at": utc_now(),
            "ended_at": utc_now(),
            "events": [event.as_dict() for event in events],
            "summary": self._summary(events),
            "configuration": self._configuration_dict(),
            "message": "Self-test report generated from synthetic anti-injection rule events.",
        }

    def demo_recon_sleep_report(self, sleep_seconds: float = 3.0, progress_callback=None) -> dict:
        """Run a local telemetry-and-sleep demonstration and return a monitor report."""
        started_at = utc_now()
        sleep_seconds = max(0.0, float(sleep_seconds))
        if progress_callback:
            progress_callback(0.1)

        telemetry = collect_demo_system_telemetry()
        current_process = ProcessInfo(
            pid=self.current_pid,
            parent_pid=os.getppid(),
            name=Path(os.path.basename(__file__)).stem,
            path=__file__,
        )
        event = self.rule_engine.reconnaissance_sleep_event(current_process, telemetry, sleep_seconds)

        if progress_callback:
            progress_callback(0.45)
        if sleep_seconds:
            time.sleep(sleep_seconds)
        if progress_callback:
            progress_callback(1.0)

        events = [event]
        return {
            "supported": True,
            "self_test": True,
            "demo_type": "local_reconnaissance_sleep",
            "started_at": started_at,
            "ended_at": utc_now(),
            "events": [event.as_dict() for event in events],
            "summary": self._summary(events),
            "configuration": {
                **self._configuration_dict(),
                "demo_sleep_seconds": sleep_seconds,
            },
            "demo_telemetry": telemetry,
            "message": "Local demo collected low-sensitivity host telemetry, displayed it in Streamlit, and emitted a sleep-pattern detection event.",
        }

    def collect_live_ports(self, processes: dict[int, ProcessInfo] | None = None) -> list[NetworkPortInfo]:
        if psutil is None:
            return []

        process_map = processes or {}
        ports: list[NetworkPortInfo] = []
        for connection in psutil.net_connections(kind="inet"):
            if len(ports) >= self.config.max_network_connections:
                break
            local_address, local_port = self._socket_address_parts(connection.laddr)
            remote_address, remote_port = self._socket_address_parts(connection.raddr)
            pid = int(connection.pid or 0)
            process = process_map.get(pid) or self._psutil_process_info(pid)
            protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
            ports.append(
                NetworkPortInfo(
                    protocol=protocol,
                    local_address=local_address,
                    local_port=local_port,
                    remote_address=remote_address,
                    remote_port=remote_port,
                    status=connection.status or ("OPEN" if protocol == "UDP" else ""),
                    pid=pid,
                    process_name=process.name if process else "",
                    process_path=process.path if process else "",
                )
            )

        ports.sort(
            key=lambda port: (
                port.direction != "listening",
                port.protocol,
                port.local_port,
                port.process_name.lower(),
                port.remote_address,
                port.remote_port,
            )
        )
        return ports

    def collect_process_memory_samples(self, processes: dict[int, ProcessInfo]) -> dict[int, ProcessMemorySample]:
        if psutil is None:
            return {}
        samples: dict[int, ProcessMemorySample] = {}
        for pid in processes:
            if self._is_own_process(pid, processes):
                continue
            try:
                process = psutil.Process(pid)
                info = process.memory_info()
                samples[pid] = ProcessMemorySample(
                    pid=pid,
                    rss_bytes=int(info.rss),
                    memory_percent=float(process.memory_percent() or 0.0),
                    status=process.status() or "unknown",
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                continue
        return samples

    def _process_map(self) -> dict[int, ProcessInfo]:
        if not self.probe:
            return {}
        return {process.pid: process for process in self.probe.iter_processes()}

    def _with_signature(self, process: ProcessInfo) -> ProcessInfo:
        if not self.probe or process.signer_status != "UNKNOWN":
            return process
        return self.probe.enrich_signature(process)

    def _memory_scan_candidates(self, processes: dict[int, ProcessInfo], new_pids: Iterable[int]) -> list[ProcessInfo]:
        new_pid_set = set(new_pids)
        candidates = [
            process
            for process in processes.values()
            if self.rule_engine.should_memory_scan(process, process.pid in new_pid_set)
        ]
        candidates.sort(key=lambda process: (process.pid not in new_pid_set, process.name.lower(), process.pid))
        return candidates[: self.config.max_processes_per_cycle]

    def _is_own_process(self, pid: int, processes: dict[int, ProcessInfo]) -> bool:
        if pid == self.current_pid:
            return True
        process = processes.get(pid)
        return bool(process and process.parent_pid == self.current_pid)

    def _memory_growth_cycle_events(
        self,
        processes: dict[int, ProcessInfo],
        previous_samples: dict[int, ProcessMemorySample],
        current_samples: dict[int, ProcessMemorySample],
        memory_surges: dict[int, MemorySurgeRecord],
    ) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        threshold_bytes = int(self.config.memory_growth_min_mb * 1024 * 1024)

        for pid, sample in current_samples.items():
            previous = previous_samples.get(pid)
            process = processes.get(pid)
            if process is None or previous is None:
                continue

            delta_bytes = sample.rss_bytes - previous.rss_bytes
            growth_percent = (delta_bytes / max(previous.rss_bytes, 1)) * 100 if previous.rss_bytes > 0 else 0.0
            record = memory_surges.get(pid)

            if delta_bytes >= threshold_bytes and growth_percent >= self.config.memory_growth_percent_threshold:
                process = self._with_signature(process)
                processes[pid] = process
                if not self.rule_engine.should_track_memory_growth(process):
                    continue
                if record is None:
                    record = MemorySurgeRecord(
                        pid=pid,
                        process_name=process.name,
                        process_path=process.path,
                        first_seen=utc_now(),
                        last_seen=utc_now(),
                        baseline_rss_bytes=previous.rss_bytes,
                        peak_rss_bytes=sample.rss_bytes,
                        latest_rss_bytes=sample.rss_bytes,
                        peak_growth_percent=growth_percent,
                        latest_growth_percent=growth_percent,
                        peak_memory_percent=sample.memory_percent,
                        latest_memory_percent=sample.memory_percent,
                        status=sample.status,
                    )
                    memory_surges[pid] = record
                    events.extend(self.rule_engine.memory_growth_events(process, previous, sample))
                else:
                    record.last_seen = utc_now()
                    record.latest_rss_bytes = sample.rss_bytes
                    record.latest_growth_percent = growth_percent
                    record.latest_memory_percent = sample.memory_percent
                    record.status = sample.status
                    record.alive = True
                    if growth_percent > record.peak_growth_percent:
                        record.peak_growth_percent = growth_percent
                        record.peak_rss_bytes = sample.rss_bytes
                    if sample.memory_percent > record.peak_memory_percent:
                        record.peak_memory_percent = sample.memory_percent

            if record is not None:
                record.last_seen = utc_now()
                record.latest_rss_bytes = sample.rss_bytes
                record.latest_growth_percent = max(growth_percent, 0.0)
                record.latest_memory_percent = sample.memory_percent
                record.status = sample.status
                record.alive = True
                record.persistence_cycles += 1
                record.sleeping_after_surge = self.rule_engine._is_sleep_like_status(sample.status)
                if (
                    record.sleeping_after_surge
                    and not record.sleep_event_emitted
                    and record.persistence_cycles >= self.config.memory_persistence_cycles
                ):
                    events.extend(self.rule_engine.memory_surge_sleep_events(process, record))
                    record.sleep_event_emitted = True

        current_pids = set(current_samples)
        for pid, record in memory_surges.items():
            if pid not in current_pids:
                record.alive = False

        return events

    @staticmethod
    def _socket_address_parts(address) -> tuple[str, int]:
        if not address:
            return "", 0
        try:
            return str(address.ip), int(address.port)
        except AttributeError:
            if isinstance(address, tuple) and len(address) >= 2:
                return str(address[0]), int(address[1])
        return "", 0

    @staticmethod
    def _psutil_process_info(pid: int) -> ProcessInfo | None:
        if not pid or psutil is None:
            return None
        try:
            process = psutil.Process(pid)
            return ProcessInfo(
                pid=pid,
                parent_pid=int(process.ppid() or 0),
                name=process.name() or "",
                path=process.exe() or "",
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            return ProcessInfo(pid=pid, parent_pid=0, name="", path="")

    @staticmethod
    def _summary(events: list[MonitorEvent], ports: list[NetworkPortInfo] | None = None) -> dict:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts: dict[str, int] = {}
        risk_score = 0
        for event in events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
            category_counts[event.category] = category_counts.get(event.category, 0) + 1
            risk_score += event.score
        return {
            "risk_score": risk_score,
            "event_count": len(events),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "network": WindowsBehaviorMonitor._network_summary(ports or []),
        }

    @staticmethod
    def _memory_surge_rows(memory_surges: dict[int, MemorySurgeRecord]) -> list[dict]:
        rows = [record.as_dict() for record in memory_surges.values()]
        rows.sort(key=lambda row: (-row["peak_growth_percent"], -row["peak_rss_mb"], row["process_name"].lower(), row["pid"]))
        return rows

    @staticmethod
    def _memory_surge_summary(memory_surges: dict[int, MemorySurgeRecord]) -> dict:
        rows = WindowsBehaviorMonitor._memory_surge_rows(memory_surges)
        return {
            "tracked_processes": len(rows),
            "sleeping_after_surge": sum(1 for row in rows if row["sleeping_after_surge"]),
            "alive_after_surge": sum(1 for row in rows if row["alive"]),
            "max_growth_percent": round(max((row["peak_growth_percent"] for row in rows), default=0.0), 2),
        }

    @staticmethod
    def _network_summary(ports: list[NetworkPortInfo]) -> dict:
        public_connections = [
            port
            for port in ports
            if port.remote_address and network_address_scope(port.remote_address) == "public"
        ]
        listeners = [port for port in ports if port.direction == "listening"]
        exposed_listeners = [
            port
            for port in listeners
            if listener_exposure(port.local_address, port.status) in {"all_interfaces", "public", "private"}
        ]
        return {
            "total_ports": len(ports),
            "listeners": len(listeners),
            "established_public_connections": len(public_connections),
            "exposed_listeners": len(exposed_listeners),
            "unknown_process_ports": sum(1 for port in ports if not port.process_name),
            "truncated": len(ports) > 0 and len(ports) >= MonitorConfig().max_network_connections,
        }

    @staticmethod
    def _port_check_summary(events: list[MonitorEvent], ports: list[NetworkPortInfo]) -> dict:
        summary = WindowsBehaviorMonitor._summary(events, ports)
        summary["risk_score"] = max((event.score for event in events), default=0)
        summary["score_model"] = "max_single_port_exposure"
        return summary

    def _configuration_dict(self) -> dict:
        return {
            "duration_seconds": self.config.duration_seconds,
            "interval_seconds": self.config.interval_seconds,
            "inspect_thread_starts": self.config.inspect_thread_starts,
            "inspect_memory_regions": self.config.inspect_memory_regions,
            "inspect_page_transitions": self.config.inspect_page_transitions,
            "transition_watch_seconds": self.config.transition_watch_seconds,
            "max_processes_per_cycle": self.config.max_processes_per_cycle,
            "max_regions_per_process": self.config.max_regions_per_process,
            "include_process_starts": self.config.include_process_starts,
            "inspect_network_ports": self.config.inspect_network_ports,
            "max_network_connections": self.config.max_network_connections,
            "inspect_memory_growth": self.config.inspect_memory_growth,
            "memory_growth_percent_threshold": self.config.memory_growth_percent_threshold,
            "memory_growth_min_mb": self.config.memory_growth_min_mb,
            "memory_persistence_cycles": self.config.memory_persistence_cycles,
        }
