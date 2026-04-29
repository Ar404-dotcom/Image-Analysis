from __future__ import annotations

import ctypes
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


IS_WINDOWS = platform.system() == "Windows"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    path: str = ""


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
    max_processes_per_cycle: int = 80
    max_regions_per_process: int = 2048
    max_events: int = 500
    include_process_starts: bool = True


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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

        return events

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

    @classmethod
    def should_memory_scan(cls, process: ProcessInfo, is_new_process: bool) -> bool:
        process_name = process.name.lower()
        if process_name in cls.JIT_HEAVY_PROCESSES:
            return False
        return is_new_process or process_name in cls.SENSITIVE_TARGETS

    @staticmethod
    def _is_user_writable_path(path: str) -> bool:
        return any(marker in path for marker in BehaviorRuleEngine.USER_WRITABLE_MARKERS)

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

            if self.config.include_process_starts:
                for pid in sorted(new_pids):
                    if self._is_own_process(pid, processes):
                        continue
                    process = processes[pid]
                    parent = processes.get(process.parent_pid) or baseline_processes.get(process.parent_pid)
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
            "summary": self._summary(events),
            "configuration": self._configuration_dict(),
            "message": "Monitoring session completed.",
        }

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
        thread = ThreadInfo(
            tid=900,
            owner_pid=owner.pid,
            start_address=0x100100,
            start_region=region,
        )

        events = []
        events.extend(self.rule_engine.process_start_events(child, parent))
        events.extend(self.rule_engine.thread_start_events(thread, owner))

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

    def _process_map(self) -> dict[int, ProcessInfo]:
        return {process.pid: process for process in self.probe.iter_processes()}

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

    @staticmethod
    def _summary(events: list[MonitorEvent]) -> dict:
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
        }

    def _configuration_dict(self) -> dict:
        return {
            "duration_seconds": self.config.duration_seconds,
            "interval_seconds": self.config.interval_seconds,
            "inspect_thread_starts": self.config.inspect_thread_starts,
            "inspect_memory_regions": self.config.inspect_memory_regions,
            "max_processes_per_cycle": self.config.max_processes_per_cycle,
            "max_regions_per_process": self.config.max_regions_per_process,
            "include_process_starts": self.config.include_process_starts,
        }
