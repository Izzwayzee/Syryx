# -*- coding: utf-8 -*-
"""
Syryx — минималистичный аналог AIDA64.

Только стандартная библиотека Python (tkinter + ctypes + powershell-запросы).
Ничего не устанавливает, ничего не пишет в систему, работает без прав администратора.

Запуск:      python sysinfo.py            (или Запуск.bat)
Отчёт в CLI: python sysinfo.py --report
"""

import ctypes
from ctypes import wintypes
import datetime as dt
import getpass
import hashlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

APP_NAME = "Syryx"
APP_VER = "1.0"
CACHE_VER = 5
IS_WIN = os.name == "nt"

# Пиктограммы верхней полосы, взятые из эталонного скриншота (белое на
# прозрачном фоне). Встроены в EXE, чтобы не требовать отдельные файлы.
_BLOCK = None  # буфер для теста процессора (создаётся при первом тесте)


def _block():
    global _BLOCK
    if _BLOCK is None:
        _BLOCK = os.urandom(8 << 20)
    return _BLOCK

# --------------------------------------------------------------------------
# Win32 через ctypes — «живые» показатели без запуска процессов
# --------------------------------------------------------------------------

if IS_WIN:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_uint32),
                    ("dwHighDateTime", ctypes.c_uint32)]

    class _MEMSTAT(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    def _ft(v):
        return (v.dwHighDateTime << 32) | v.dwLowDateTime

    def cpu_times():
        idle, kern, user = _FILETIME(), _FILETIME(), _FILETIME()
        _k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
        return _ft(idle), _ft(kern), _ft(user)

    def cpu_load(prev, cur):
        di = cur[0] - prev[0]
        dk = cur[1] - prev[1]
        du = cur[2] - prev[2]
        total = dk + du
        if total <= 0:
            return 0.0
        return max(0.0, min(100.0, (total - di) * 100.0 / total))

    def memory():
        m = _MEMSTAT()
        m.dwLength = ctypes.sizeof(m)
        _k32.GlobalMemoryStatusEx(ctypes.byref(m))
        return m

    def uptime_seconds():
        return _k32.GetTickCount64() / 1000.0

    def screen_info():
        u = ctypes.windll.user32
        try:
            dpi = u.GetDpiForSystem()
        except Exception:
            dpi = 96
        return (u.GetSystemMetrics(0), u.GetSystemMetrics(1),
                max(1, u.GetSystemMetrics(80)), dpi)
else:  # запасной вариант — программа всё равно откроется
    def cpu_times():
        return (0, 0, 0)

    def cpu_load(prev, cur):
        return 0.0

    def memory():
        return None

    def uptime_seconds():
        return 0.0

    def screen_info():
        return (0, 0, 1, 96)


# --------------------------------------------------------------------------
# Живые счётчики GPU и диска через PDH — в том же процессе, без PowerShell
# --------------------------------------------------------------------------

class _Pdh:
    """Минимальная обёртка над pdh.dll (только то, что нужно Syryx)."""

    FMT_DOUBLE = 0x00000200

    class Value(ctypes.Structure):
        _fields_ = [("status", ctypes.c_ulong), ("value", ctypes.c_double)]

    def __init__(self):
        api = ctypes.WinDLL("pdh.dll")
        self.api = api
        api.PdhOpenQueryW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
        api.PdhOpenQueryW.restype = ctypes.c_long
        api.PdhAddEnglishCounterW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_void_p)]
        api.PdhAddEnglishCounterW.restype = ctypes.c_long
        api.PdhCollectQueryData.argtypes = [ctypes.c_void_p]
        api.PdhCollectQueryData.restype = ctypes.c_long
        api.PdhGetFormattedCounterValue.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(self.Value)]
        api.PdhGetFormattedCounterValue.restype = ctypes.c_long
        api.PdhExpandWildCardPathW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong)]
        api.PdhExpandWildCardPathW.restype = ctypes.c_long
        self.query = ctypes.c_void_p()
        if api.PdhOpenQueryW(None, 0, ctypes.byref(self.query)) != 0:
            raise OSError("PdhOpenQuery")

    def add(self, path):
        h = ctypes.c_void_p()
        if self.api.PdhAddEnglishCounterW(self.query, path, 0,
                                          ctypes.byref(h)) != 0:
            return None
        return h

    def expand(self, path):
        size = ctypes.c_ulong(0)
        self.api.PdhExpandWildCardPathW(None, path, None, ctypes.byref(size))
        if not size.value:
            return []
        buf = ctypes.create_unicode_buffer(size.value + 2)
        if self.api.PdhExpandWildCardPathW(None, path, buf,
                                           ctypes.byref(size)) != 0:
            return []
        return [p for p in buf[:size.value].split("\x00") if p]

    def collect(self):
        self.api.PdhCollectQueryData(self.query)

    def value(self, handle):
        val = self.Value()
        if self.api.PdhGetFormattedCounterValue(
                handle, self.FMT_DOUBLE, None, ctypes.byref(val)) != 0:
            return None
        if val.status not in (0, 1):  # VALID_DATA / NEW_DATA
            return None
        return val.value


class LiveCounters:
    """Загрузка видеокарты и активность дисков в процентах (0..100)."""

    GPU_PATH = r"\GPU Engine(*)\Utilization Percentage"
    DISK_PATH = r"\PhysicalDisk(_Total)\% Idle Time"
    CPU_CLK_PATH = r"\Processor Information(_Total)\% Processor Performance"

    def __init__(self):
        self.available = False
        self._pdh = None
        self._disk = None
        self._cpuclk = None
        self._gpu = []
        self._gpu_refresh = 0.0
        if not IS_WIN:
            return
        try:
            self._pdh = _Pdh()
            self._disk = self._pdh.add(self.DISK_PATH)
            self._cpuclk = self._pdh.add(self.CPU_CLK_PATH)
            self.refresh_gpu()
            self._pdh.collect()
            self.available = True
        except Exception:
            self._pdh = None

    def cpu_clock(self, base_mhz):
        """Текущая частота процессора из PDH, МГц."""
        if not self._pdh or not self._cpuclk or not base_mhz:
            return None
        perf = self._pdh.value(self._cpuclk)
        return base_mhz * perf / 100.0 if perf is not None else None

    def refresh_gpu(self):
        self._gpu = []
        self._gpu_refresh = time.time()
        try:
            for path in self._pdh.expand(self.GPU_PATH):
                if "_engtype_3D)" not in path:
                    continue
                h = self._pdh.add(path)
                if h is not None:
                    self._gpu.append(h)
        except Exception:
            self._gpu = []

    def update(self):
        """Возвращает (GPU %, диск %) или (None, None), если недоступно."""
        if not self._pdh:
            return None, None
        try:
            if time.time() - self._gpu_refresh > 20:
                self.refresh_gpu()
            self._pdh.collect()
            gpu = 0.0
            for h in self._gpu:
                v = self._pdh.value(h)
                if v is not None:
                    gpu += v
            idle = self._pdh.value(self._disk) if self._disk else None
            return (min(100.0, gpu) if self._gpu else None,
                    max(0.0, min(100.0, 100.0 - idle)) if idle is not None
                    else None)
        except Exception:
            return None, None


class NvmlSensors:
    """Температура, мощность, частота и VRAM видеокарты через nvml.dll.

    Работает в том же процессе, без прав администратора и сторонних программ.
    """

    class Mem(ctypes.Structure):
        _fields_ = [("total", ctypes.c_ulonglong),
                    ("free", ctypes.c_ulonglong),
                    ("used", ctypes.c_ulonglong)]

    class Util(ctypes.Structure):
        _fields_ = [("gpu", ctypes.c_uint), ("memory", ctypes.c_uint)]

    def __init__(self):
        self.available = False
        self.api = None
        self.handle = None
        if not IS_WIN:
            return
        try:
            api = ctypes.CDLL("nvml.dll")
            if api.nvmlInit_v2() != 0:
                return
            count = ctypes.c_uint()
            if api.nvmlDeviceGetCount_v2(ctypes.byref(count)) != 0 or not count.value:
                return
            handle = ctypes.c_void_p()
            if api.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(handle)) != 0:
                return
            self.api = api
            self.handle = handle
            self.available = True
        except Exception:
            self.api = None

    def _uint(self, name, *extra):
        try:
            value = ctypes.c_uint()
            fn = getattr(self.api, name)
            if fn(self.handle, *extra, ctypes.byref(value)) == 0:
                return value.value
        except Exception:
            pass
        return None

    def read(self):
        if not self.available:
            return {}
        out = {}
        temp = self._uint("nvmlDeviceGetTemperature", ctypes.c_int(0))
        if temp is not None:
            out["temp"] = float(temp)
        power = self._uint("nvmlDeviceGetPowerUsage")
        if power is not None:
            out["power"] = power / 1000.0
        clock = self._uint("nvmlDeviceGetClockInfo", ctypes.c_int(0))
        if clock is not None:
            out["clock"] = clock
        try:
            mem = self.Mem()
            if self.api.nvmlDeviceGetMemoryInfo(
                    self.handle, ctypes.byref(mem)) == 0:
                out["mem_used"] = mem.used / 1048576.0
                out["mem_total"] = mem.total / 1048576.0
        except Exception:
            pass
        try:
            util = self.Util()
            if self.api.nvmlDeviceGetUtilizationRates(
                    self.handle, ctypes.byref(util)) == 0:
                out["util"] = float(util.gpu)
        except Exception:
            pass
        return out


# --------------------------------------------------------------------------
# Сбор «железа» одним запросом PowerShell (CIM) + кэш
# --------------------------------------------------------------------------

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$cs     = Get-CimInstance Win32_ComputerSystem
$os     = Get-CimInstance Win32_OperatingSystem
$cpu    = @(Get-CimInstance Win32_Processor)[0]
$board  = Get-CimInstance Win32_BaseBoard
$bios   = Get-CimInstance Win32_BIOS
$gpus   = @(Get-CimInstance Win32_VideoController)
$rams   = @(Get-CimInstance Win32_PhysicalMemory)
$disks  = @(Get-CimInstance Win32_DiskDrive)
$vols   = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')
$nets   = @(Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=True')
$snd    = @(Get-CimInstance Win32_SoundDevice)
$phys   = @(Get-PhysicalDisk)
$parts  = @(Get-Partition | Where-Object { $_.DriveLetter })
$thermal = @(Get-CimInstance -Namespace root\wmi `
    -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue)
$cputemp = $null
if ($thermal.Count -gt 0 -and $thermal[0].CurrentTemperature) {
  $cputemp = [math]::Round(($thermal[0].CurrentTemperature / 10.0 - 273.15), 1)
}

# ревизия процессора: CPUID-подпись из реестра ( там же, где и имя CPU )
$cpureg = Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
$cpuident = $cpureg.Identifier
$ucode = $null
if ($cpureg.'Update Revision') {
  $ucode = '0x' + ([BitConverter]::ToUInt32([byte[]]$cpureg.'Update Revision', 0)).ToString('X')
}

# реальный объём видеопамяти (AdapterRAM в WMI ограничен 4 ГБ)
$vramMap = @{}
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
Get-ChildItem $cls | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath
  if ($p.DriverDesc -and $p.'HardwareInformation.qwMemorySize') {
    $vramMap[[string]$p.DriverDesc] = [int64]$p.'HardwareInformation.qwMemorySize'
  }
}

$out = [ordered]@{
  system = [ordered]@{
    manufacturer = $cs.Manufacturer
    model        = $cs.Model
    systemtype   = $cs.SystemType
    domain       = $cs.Domain
    workgroup    = $cs.Workgroup
    partofdomain = $cs.PartOfDomain
    totalphys    = $cs.TotalPhysicalMemory
  }
  os = [ordered]@{
    caption      = $os.Caption
    version      = $os.Version
    build        = $os.BuildNumber
    arch         = $os.OSArchitecture
    install      = $os.InstallDate
    boot         = $os.LastBootUpTime
    serial       = $os.SerialNumber
    user         = $os.RegisteredUser
    locale       = $os.Locale
    sysdrive     = $os.SystemDrive
    windir       = $os.WindowsDirectory
  }
  cpu = [ordered]@{
    name        = $cpu.Name
    cores       = $cpu.NumberOfCores
    threads     = $cpu.NumberOfLogicalProcessors
    maxclock    = $cpu.MaxClockSpeed
    curclock    = $cpu.CurrentClockSpeed
    temp        = $cputemp
    l2          = $cpu.L2CacheSize
    l3          = $cpu.L3CacheSize
    socket      = $cpu.SocketDesignation
    width       = $cpu.AddressWidth
    manuf       = $cpu.Manufacturer
    id          = $cpu.ProcessorId
    virtfirmware= $cpu.VirtualizationFirmwareEnabled
    vmmonitor   = $cpu.VMMonitorModeExtensions
    ident       = $cpuident
    ucode       = $ucode
  }
  board = [ordered]@{
    manufacturer = $board.Manufacturer
    product      = $board.Product
    version      = $board.Version
    serial       = $board.SerialNumber
  }
  bios = [ordered]@{
    manufacturer = $bios.Manufacturer
    version      = $bios.SMBIOSBIOSVersion
    release      = $bios.ReleaseDate
    serial       = $bios.SerialNumber
  }
  gpus = @($gpus | ForEach-Object {
    # PCI-ревизия (REV_xx) из аппаратного ID — то, что показывает GPU-Z
    $rev = $null
    if ($_.PNPDeviceID -match 'REV_([0-9A-Fa-f]+)') {
      $rev = $Matches[1].ToUpperInvariant()
    }
    [ordered]@{
      name     = $_.Name
      vram     = $(if ($vramMap[[string]$_.Name]) { $vramMap[[string]$_.Name] } else { $_.AdapterRAM })
      driver   = $_.DriverVersion
      drvdate  = $_.DriverDate
      processor= $_.VideoProcessor
      mode     = $_.VideoModeDescription
      status   = $_.Status
      pnp      = $_.PNPDeviceID
      rev      = $rev
    }
  })
  ram = @($rams | ForEach-Object {
    [ordered]@{
      slot     = if ($_.DeviceLocator) { $_.DeviceLocator } else { $_.BankLabel }
      size     = $_.Capacity
      speed    = $_.Speed
      cspeed   = $_.ConfiguredClockSpeed
      manuf    = $_.Manufacturer
      part     = $_.PartNumber
      fmt      = $_.FormFactor
      memtype  = $_.SMBIOSMemoryType
    }
  })
  disks = @($disks | ForEach-Object {
    [ordered]@{
      model    = $_.Model
      index    = $_.Index
      size     = $_.Size
      iface    = $_.InterfaceType
      media    = $_.MediaType
      serial   = $_.SerialNumber
      parts    = $_.Partitions
      status   = $_.Status
      fw       = $_.FirmwareRevision
    }
  })
  partitions = @($parts | ForEach-Object {
    [ordered]@{
      disknumber  = $_.DiskNumber
      driveletter = "$($_.DriveLetter)"
      size        = $_.Size
      offset      = $_.Offset
    }
  })
  volumes = @($vols | ForEach-Object {
    [ordered]@{
      letter   = $_.DeviceID
      label    = $_.VolumeName
      fs       = $_.FileSystem
      size     = $_.Size
      free     = $_.FreeSpace
    }
  })
  nets = @($nets | ForEach-Object {
    [ordered]@{
      name     = $_.Name
      conn     = $_.NetConnectionID
      mac      = $_.MACAddress
      speed    = $_.Speed
      manuf    = $_.Manufacturer
    }
  })
  sound = @($snd | ForEach-Object { [ordered]@{ name = $_.Name } })
  phys  = @($phys | ForEach-Object {
    $rc = $_ | Get-StorageReliabilityCounter
    [ordered]@{
      name     = $_.FriendlyName
      deviceid = "$($_.DeviceId)"
      media    = "$($_.MediaType)"
      bus      = "$($_.BusType)"
      health   = "$($_.HealthStatus)"
      size     = $_.Size
      wear     = $rc.Wear
      temp     = $rc.Temperature
      hours    = $rc.PowerOnHours
      readerr  = $rc.ReadErrorsTotal
      writeerr = $rc.WriteErrorsTotal
    }
  })
}

$out | ConvertTo-Json -Depth 6 -Compress
"""


def _cache_path():
    """В exe кэш лежит в %LOCALAPPDATA%\\Syryx, в скрипте — рядом с файлом."""
    if getattr(sys, "frozen", False):
        base = os.path.join(os.environ.get("LOCALAPPDATA")
                            or os.path.expanduser("~"), APP_NAME)
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            base = tempfile.gettempdir()
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "hardware-cache.json")


def _run_powershell(script, timeout=120):
    fd, path = tempfile.mkstemp(suffix=".ps1", prefix="pcinfo_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
            f.write(script)
        flags = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, timeout=timeout, creationflags=flags)
        raw = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end < 0:
        raise RuntimeError("PowerShell не вернул данные.\n" + (err or raw)[:600])
    return json.loads(raw[start:end + 1])


def _clean(obj):
    """Убирает пробелы по краям во всех строках."""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return obj.strip()
    return obj


def collect_hardware(use_cache=True):
    """Возвращает dict с железом. Из кэша — если он свежий (< 1 сут)."""
    path = _cache_path()
    if use_cache and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if (time.time() - cached.get("_ts", 0) < 86400
                    and cached.get("_ver") == CACHE_VER):
                return cached
        except Exception:
            pass

    data = _run_powershell(PS_SCRIPT)
    data = _clean(data)
    data["_ts"] = time.time()
    data["_ver"] = CACHE_VER
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except OSError:
        pass
    return data


# --------------------------------------------------------------------------
# Форматирование
# --------------------------------------------------------------------------

def fmt_bytes(v, digits=1):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "—"
    if v <= 0:
        return "—"
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"]
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    if i == 0:
        return f"{v:.0f} {units[i]}"
    return f"{v:.{digits}f} {units[i]}".replace(".", ",")


def fmt_num(v, suffix=""):
    if v is None or v == "" or v == 0:
        return "—"
    try:
        v = int(v)
    except (TypeError, ValueError):
        return str(v)
    return f"{v:,}".replace(",", " ") + (f" {suffix}" if suffix else "")


def fmt_date(v):
    if not v:
        return "—"
    s = str(v)
    if s.startswith("/Date(") and s.endswith(")/"):
        try:
            ms = int(s[6:-2].split("+")[0].split("-", 1)[0])
            return dt.datetime.fromtimestamp(ms / 1000.0).strftime("%d.%m.%Y")
        except Exception:
            return s
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return f"{m.group(3)}.{m.group(2)}.{m.group(1)}"
    return s


def join(a, b):
    a = (a or "").strip()
    b = (b or "").strip()
    if a and b and a.lower() != b.lower():
        return f"{a} {b}"
    return a or b


MEM_TYPES = {20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3",
             26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3",
             30: "LPDDR4", 34: "DDR5", 35: "LPDDR5", 0: "—"}
FORM_FACTORS = {8: "DIMM", 12: "SODIMM"}
MEDIA_RU = {"external hard disk media": "внешний HDD",
            "fixed hard disk media": "HDD",
            "removable media": "съёмный носитель"}
HEALTH_RU = {"healthy": "норма", "warning": "внимание",
             "unhealthy": "проблема", "ok": "работает"}


def fmt_uptime(sec):
    sec = int(sec or 0)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} д {h} ч {m} мин"
    if h:
        return f"{h} ч {m} мин"
    return f"{m} мин"


def fmt_speed(bits):
    try:
        bits = float(bits)
    except (TypeError, ValueError):
        return "—"
    if bits <= 0:
        return "—"
    if bits >= 1e9:
        return f"{bits / 1e9:.0f} Гбит/с"
    return f"{bits / 1e6:.0f} Мбит/с"


def cpu_revision(c):
    """Ревизия CPU из CPUID-подписи реестра: Stepping / Family / Model."""
    ident = str(c.get("ident") or "")
    step = re.search(r"Stepping\s+(\d+)", ident, re.I)
    if not step:
        return ""
    parts = [f"Stepping {step.group(1)}"]
    for label in ("Family", "Model"):
        m = re.search(rf"{label}\s+(\d+)", ident, re.I)
        if m:
            parts.append(f"{label} {m.group(1)}")
    return ", ".join(parts)


def gpu_revision(g):
    """PCI-ревизия видеокарты (REV_xx в аппаратном ID), например A1."""
    return str(g.get("rev") or "").strip().upper()


# --------------------------------------------------------------------------
# Построение «страниц» с параметрами
# --------------------------------------------------------------------------

def page_system(d, live):
    s = d.get("system") or {}
    o = d.get("os") or {}
    return [
        ("Компьютер", join(s.get("manufacturer"), s.get("model")) or "—"),
        ("Имя в сети", socket.gethostname()),
        ("Пользователь", getpass.getuser()),
        ("Тип системы", s.get("systemtype") or "—"),
        ("Операционная система", o.get("caption") or "—"),
        ("Версия / сборка", f"{o.get('version') or '—'}  (build {o.get('build') or '—'})"),
        ("Разрядность", o.get("arch") or "—"),
        ("Установлена", fmt_date(o.get("install"))),
        ("Последняя загрузка", fmt_date(o.get("boot"))),
        ("Время работы", fmt_uptime(live.get("uptime", 0))),
        ("Рабочая группа / домен", s.get("domain") or s.get("workgroup") or "—"),
        ("Серийный номер ОС", o.get("serial") or "—"),
        ("Каталог Windows", o.get("windir") or "—"),
    ]


def page_cpu(d, live):
    c = d.get("cpu") or {}
    rows = [
        ("Модель", (c.get("name") or "—").strip()),
        ("Производитель", c.get("manuf") or "—"),
        ("Ядра / потоки", f"{c.get('cores') or '—'} / {c.get('threads') or '—'}"),
        ("Базовая частота", fmt_num(c.get("maxclock"), "МГц")),
        ("Текущая частота", fmt_num(c.get("curclock"), "МГц")),
        ("Кэш L2", fmt_bytes((c.get("l2") or 0) * 1024) if c.get("l2") else "—"),
        ("Кэш L3", fmt_bytes((c.get("l3") or 0) * 1024) if c.get("l3") else "—"),
        ("Сокет", c.get("socket") or "—"),
        ("Разрядность", f"{c.get('width') or '—'}-бит"),
        ("ID процессора", c.get("id") or "—"),
        ("Ревизия (CPUID)", cpu_revision(c) or "—"),
        ("Ревизия микрокода", c.get("ucode") or "—"),
        ("Загрузка сейчас", f"{live.get('cpu', 0):.0f} %"),
    ]
    if c.get("virtfirmware") is not None:
        rows.append(("Виртуализация (VT-x/AMD-V)",
                     "включена" if c.get("virtfirmware") else "выключена"))
    return rows


def page_memory(d, live):
    rows = []
    m = memory()
    if m is not None:
        used = m.ullTotalPhys - m.ullAvailPhys
        rows += [
            ("Всего ОЗУ", fmt_bytes(m.ullTotalPhys)),
            ("Использовано", f"{fmt_bytes(used)}  ({m.dwMemoryLoad} %)"),
            ("Свободно", fmt_bytes(m.ullAvailPhys)),
            ("Файл подкачки (всего)", fmt_bytes(m.ullTotalPageFile)),
            ("Файл подкачки (свободно)", fmt_bytes(m.ullAvailPageFile)),
        ]
    rows.append(("", ""))
    mods = d.get("ram") or []
    if mods:
        rows.append(("МОДУЛИ ПАМЯТИ", ""))
        for i, mod in enumerate(mods, 1):
            mt = MEM_TYPES.get(mod.get("memtype"), "—")
            ff = FORM_FACTORS.get(mod.get("fmt"), "")
            speed = mod.get("cspeed") or mod.get("speed")
            title = f"{mod.get('slot') or f'Слот {i}'} — {fmt_bytes(mod.get('size'), 0)}"
            info = " · ".join(x for x in [
                f"{mt}" if mt != "—" else "",
                ff,
                f"{speed} МГц" if speed else "",
                (mod.get("manuf") or "").strip(),
                (mod.get("part") or "").strip(),
            ] if x)
            rows.append((title, info or "—"))
    else:
        rows.append(("Модули", "нет данных"))
    return rows


def page_disks(d, live):
    rows = []
    ph = {str(p.get("name") or "").lower(): p for p in (d.get("phys") or [])}

    disks = d.get("disks") or []
    rows.append(("ФИЗИЧЕСКИЕ ДИСКИ", ""))
    if not disks:
        rows.append(("—", "нет данных"))
    for i, dk in enumerate(disks, 1):
        model = (dk.get("model") or f"Диск {i}").strip()
        extra = ph.get(model.lower(), {})
        bus = extra.get("bus")
        media = MEDIA_RU.get(str(extra.get("media") or "").lower(),
                             extra.get("media"))
        health = HEALTH_RU.get(str(extra.get("health") or "").lower(), "")
        info = " · ".join(x for x in [
            fmt_bytes(dk.get("size")),
            (bus if bus not in (None, "", "0", "Unspecified", "Unknown") else dk.get("iface")),
            (media if media not in (None, "", "0", "Unspecified", "Unknown") else ""),
            (f"состояние: {health}" if health else ""),
        ] if x)
        rows.append((model, info))
        sub = []
        if dk.get("serial"):
            sub.append(f"S/N {dk['serial'].strip()}")
        if dk.get("fw"):
            sub.append(f"прошивка {dk['fw'].strip()}")
        if dk.get("parts"):
            sub.append(f"разделов: {dk['parts']}")
        if sub:
            rows.append(("", " · ".join(sub)))

    rows.append(("", ""))
    rows.append(("ЛОГИЧЕСКИЕ ДИСКИ", ""))
    for v in d.get("volumes") or []:
        size = v.get("size") or 0
        free = v.get("free") or 0
        pct = (free / size * 100) if size else 0
        name = (v.get("label") or "").strip()
        letter = v.get("letter") or "?"
        title = f"{letter} «{name}»" if name else letter
        rows.append((title, f"{v.get('fs') or '—'} · {fmt_bytes(size)} · "
                            f"свободно {fmt_bytes(free)} ({pct:.0f} %)"))
    return rows


def page_gpu(d, live):
    """Только видеокарта: экран и звук открываются своими плитками."""
    rows = []
    gpus = d.get("gpus") or []
    if not gpus:
        rows.append(("Видеокарта", "нет данных"))
    for g in gpus:
        rows.append(("Модель", (g.get("name") or "—").strip()))
        rows.append(("Видеопамять", fmt_bytes(g.get("vram"))))
        rows.append(("Ревизия (PCI)", gpu_revision(g) or "—"))
        rows.append(("Драйвер",
                     f"{g.get('driver') or '—'} от {fmt_date(g.get('drvdate'))}"))
        if g.get("processor"):
            rows.append(("Видеопроцессор", g.get("processor")))
        if g.get("status"):
            status = HEALTH_RU.get(str(g["status"]).lower(), g["status"])
            rows.append(("Состояние", status))
        rows.append(("Загрузка сейчас", f"{float(live.get('gpu') or 0):.0f} %"))
    return rows


def page_screen(d, live):
    """Только монитор: разрешение, число мониторов и масштабирование."""
    w, h, count, dpi = screen_info()
    return [
        ("Разрешение", f"{w} × {h}" if w else "—"),
        ("Мониторов", str(count)),
        ("DPI", f"{dpi} ({round(dpi / 96 * 100)} %)"),
    ]


def page_sound(d, live):
    sound = d.get("sound") or []
    names = [(s.get("name") or "").strip() for s in sound if s.get("name")]
    return [("Устройства", "\n".join(names) if names else "—")]


def page_board(d, live):
    """Только материнская плата и BIOS."""
    b = d.get("board") or {}
    bio = d.get("bios") or {}
    return [
        ("Материнская плата", join(b.get("manufacturer"), b.get("product")) or "—"),
        ("Версия платы", b.get("version") or "—"),
        ("Серийный номер платы", b.get("serial") or "—"),
        ("BIOS", join(bio.get("manufacturer"), bio.get("version")) or "—"),
        ("Дата BIOS", fmt_date(bio.get("release"))),
    ]


def page_network(d, live):
    rows = [("Имя компьютера", socket.gethostname()),
            ("Локальный IPv4", ", ".join(local_ips()) or "—"), ("", "")]
    nets = d.get("nets") or []
    if not nets:
        rows.append(("Адаптеры", "нет данных"))
    for n in nets:
        title = (n.get("conn") or n.get("name") or "—").strip()
        rows.append((title, ""))
        rows.append(("  Описание", (n.get("name") or "—").strip()))
        rows.append(("  MAC-адрес", n.get("mac") or "—"))
        rows.append(("  Скорость", fmt_speed(n.get("speed"))))
        if n.get("manuf"):
            rows.append(("  Производитель", n.get("manuf")))
    return rows


def build_report(d, live):
    """Текстовый отчёт для сохранения/CLI."""
    lines = [f"{APP_NAME} {APP_VER} — отчёт о системе",
             f"Сформирован: {dt.datetime.now():%d.%m.%Y %H:%M:%S}",
             "=" * 62, ""]
    for title, fn in (("СИСТЕМА", page_system), ("ПЛАТА", page_board),
                      ("ПРОЦЕССОР", page_cpu),
                      ("ПАМЯТЬ", page_memory), ("ДИСКИ", page_disks),
                      ("ВИДЕО", page_gpu), ("ЭКРАН", page_screen),
                      ("ЗВУК", page_sound), ("СЕТЬ", page_network)):
        lines.append(f"[ {title} ]")
        for k, v in fn(d, live):
            if not k and not v:
                lines.append("")
            elif k and not v:
                lines.append(f"  {k}:")
            elif k:
                line = f"{k} {v}" if k.endswith(":") else f"{k}: {v}"
                lines.append("  " + line)
            else:
                lines.append(f"    {v}")
        lines.append("")
        lines.append("-" * 62)
        lines.append("")
    if live.get("bench"):
        lines.append("[ ТЕСТЫ ]")
        for k, v in live["bench"]:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


def local_ips():
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith(("127.", "169.254.")):
                ips.append(ip)
    except OSError:
        pass

    def private(ip):
        p = ip.split(".")
        return (p[0] == "10" or (p[0] == "192" and p[1] == "168")
                or (p[0] == "172" and 16 <= int(p[1] or 0) <= 31))

    priv = [ip for ip in ips if private(ip)]
    return priv or ips


# --------------------------------------------------------------------------
# Тесты производительности (экономные: ~1-2 секунды)
# --------------------------------------------------------------------------

def bench_cpu(threads=1, mb=512):
    """Скорость SHA-256 в МБ/с. hashlib отпускает GIL — потоки реально параллельны."""
    threads = max(1, int(threads or 1))
    per = max(8, mb // threads)
    count = per // 8
    blk = _block()

    def work():
        h = hashlib.sha256
        for _ in range(count):
            h(blk).digest()

    ts = [threading.Thread(target=work) for _ in range(threads)]
    t = time.perf_counter()
    for th in ts:
        th.start()
    for th in ts:
        th.join()
    dt_ = time.perf_counter() - t
    return (per * threads) / dt_, dt_


def bench_cpu_multi(threads):
    """То же на всех потоках: (МБ/с, секунды)."""
    return bench_cpu(threads, mb=2048)


def bench_memory(mb=128):
    size = (mb << 20)
    src = bytes(size)
    dst = bytearray(size)
    best = None
    for _ in range(3):
        t = time.perf_counter()
        dst[:] = src
        d = time.perf_counter() - t
        best = d if best is None else min(best, d)
    return size / best / (1 << 20)  # МБ/с


def bench_disk(mb=64):
    size = mb << 20
    chunk = os.urandom(1 << 20)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcinfo")
    path = tmp.name
    tmp.close()
    try:
        t = time.perf_counter()
        with open(path, "wb") as f:
            for _ in range(mb):
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        w = time.perf_counter() - t

        t = time.perf_counter()
        with open(path, "rb") as f:
            while f.read(1 << 20):
                pass
        r = time.perf_counter() - t
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return size / w / (1 << 20), size / r / (1 << 20)


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Данные для плиток дашборда
# --------------------------------------------------------------------------

def plural(n, one, few, many):
    n = abs(int(n)) % 100
    if 11 <= n <= 19:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many


def cpu_brand(name):
    n = (name or "").lower()
    if "intel" in n:
        return "Intel"
    if "amd" in n or "ryzen" in n or "athlon" in n:
        return "AMD"
    return ""


def short_cpu_name(name):
    s = (name or "").strip()
    s = re.sub(r"\(R\)|\(TM\)|\(tm\)|CPU|Processor", " ", s, flags=re.I)
    s = re.sub(r"\b\d+(st|nd|rd|th)\s+Gen\b", " ", s, flags=re.I)
    s = re.sub(r"\s+", " ", s).strip(" -")
    return s or "Процессор"


def gb(v):
    try:
        return int(round(float(v) / (1 << 30)))
    except (TypeError, ValueError):
        return 0


def cpu_caption(d, live):
    c = d.get("cpu") or {}
    parts = []
    brand = cpu_brand(c.get("name") or "")
    if brand:
        parts.append(brand)
    if c.get("cores") and c.get("threads"):
        parts.append(f"{c['cores']} ядер / {c['threads']} потоков")
    if c.get("maxclock"):
        parts.append(fmt_num(c["maxclock"], "МГц"))
    parts.append(f"загрузка {float(live.get('cpu') or 0):.0f} %")
    return " · ".join(parts)


def mem_caption(d, m):
    mods = d.get("ram") or []
    parts = []
    if mods:
        parts.append(f"{len(mods)} {plural(len(mods), 'модуль', 'модуля', 'модулей')}")
    if m is not None:
        parts.append(f"занято {m.dwMemoryLoad} %")
        parts.append(f"свободно {fmt_bytes(m.ullAvailPhys)}")
    return " · ".join(parts)


def disk_usage(d):
    """Сколько места занято на всех разделах: всего, свободно, процент."""
    vols = d.get("volumes") or []
    total = sum(int(v.get("size") or 0) for v in vols)
    free = sum(int(v.get("free") or 0) for v in vols)
    pct = (100.0 - free * 100.0 / total) if total else 0.0
    return total, free, max(0.0, min(100.0, pct))


def gpu_caption(d, live):
    g = (d.get("gpus") or [{}])[0]
    name = (g.get("name") or "").lower()
    vendor = ("NVIDIA" if "nvidia" in name else
              "AMD" if ("amd" in name or "radeon" in name) else
              "Intel" if "intel" in name else "")
    parts = [x for x in (
        vendor,
        fmt_bytes(g.get("vram")) if g.get("vram") else "",
        (f"драйвер {g['driver']}" if g.get("driver") else ""),
        (f"загрузка {float(live.get('gpu') or 0):.0f} %"
         if live.get("gpu") is not None else "")) if x]
    return " · ".join(parts)


def disks_caption(d, live):
    disks = d.get("disks") or []
    ph = {str(p.get("name") or "").strip().lower(): p
          for p in (d.get("phys") or [])}
    buses = []
    for x in disks:
        info = ph.get((x.get("model") or "").strip().lower(), {})
        bus = (info.get("bus") or "").strip()
        if bus in ("", "0", "Unspecified", "Unknown"):
            bus = (x.get("iface") or "").strip()
        if bus and bus not in buses:
            buses.append(bus)
    parts = [x for x in (
        " · ".join(buses[:3]),
        (f"{len(disks)} {plural(len(disks), 'накопитель', 'накопителя', 'накопителей')}"
         if disks else ""),
        f"занято {disk_usage(d)[2]:.0f} %" if disks else "") if x]
    return " · ".join(parts)


def build_cards(d, live):
    """Плитки дашборда: key, подпись, крупное значение, мелкая подпись, цвет, полоса, страница."""
    s = d.get("system") or {}
    o = d.get("os") or {}
    c = d.get("cpu") or {}
    b = d.get("board") or {}
    bio = d.get("bios") or {}
    gpus = d.get("gpus") or []
    mods = d.get("ram") or []
    disks = d.get("disks") or []
    nets = d.get("nets") or []

    m = memory()
    total_ram = m.ullTotalPhys if m else int(s.get("totalphys") or 0)
    mt = MEM_TYPES.get(mods[0].get("memtype"), "") if mods else ""
    sp = (mods[0].get("cspeed") or mods[0].get("speed")) if mods else None
    mem_value = f"{gb(total_ram)} ГБ" if total_ram else "—"
    if mt:
        mem_value += f" {mt}" + (f"-{sp}" if sp else "")

    g = gpus[0] if gpus else {}
    gname = (g.get("name") or "—").strip()

    os_name = (o.get("caption") or "Операционная система")
    for junk in ("Майкрософт ", "Microsoft "):
        os_name = os_name.replace(junk, "")

    active = {}
    for n in nets:
        conn = (n.get("conn") or "").lower()
        if conn in ("ethernet", "wi-fi", "wifi", "ethernet 2"):
            active = n
            break
    if not active and nets:
        active = nets[0]

    w_, h_, count, dpi = screen_info()

    bench = live.get("bench") or []
    bench_caption = (" · ".join(t for _, t in bench[:2]) if bench
                     else "F5 · ~1 секунда · CPU, память, диск")
    disk_pct = disk_usage(d)[2] if disks else 0.0

    return [
        dict(key="cpu", title="Процессор", value=short_cpu_name(c.get("name")),
             caption=cpu_caption(d, live), accent="#4d9bff",
             bar=float(live.get("cpu") or 0), details=page_cpu),
        dict(key="gpu", title="Видеокарта", value=gname,
             caption=gpu_caption(d, live), accent="#a78bfa",
             bar=float(live.get("gpu") or 0),
             barstyle="Card.Horizontal.TProgressbar", details=page_gpu),
        dict(key="mem", title="Оперативная память", value=mem_value,
             caption=mem_caption(d, m), accent="#34d399",
             bar=float(m.dwMemoryLoad) if m is not None else None,
             details=page_memory),
        dict(key="disks", title="Накопители",
             value=fmt_bytes(sum(int(x.get("size") or 0) for x in disks)) if disks else "—",
             caption=disks_caption(d, live), accent="#2dd4bf",
             bar=disk_pct,
             barstyle=("DiskAlert.Horizontal.TProgressbar" if disk_pct >= 85
                       else "Card.Horizontal.TProgressbar"),
             details=page_disks),
        dict(key="system", title="Система", value=os_name,
             caption=" · ".join(x for x in [
                 f"build {o['build']}" if o.get("build") else "",
                 o.get("arch") or "", fmt_uptime(live.get("uptime", 0))] if x),
             accent="#38bdf8", bar=None, details=page_system),
        dict(key="board", title="Материнская плата",
             value=(b.get("product") or "—").strip(),
             caption=" · ".join(x for x in [
                 (b.get("manufacturer") or "").strip(),
                 f"BIOS {bio['version']}" if bio.get("version") else "",
                 fmt_date(bio.get("release")) if bio.get("release") else ""] if x),
             accent="#fbbf24", bar=None, details=page_board),
        dict(key="network", title="Сеть",
             value=", ".join(local_ips()) or "—",
             caption=" · ".join(x for x in [
                 (active.get("conn") or active.get("name") or "").strip(),
                 fmt_speed(active.get("speed")) if active.get("speed") else "",
                 f"MAC {active['mac']}" if active.get("mac") else ""] if x),
             accent="#5eead4", bar=None, details=page_network),
        dict(key="screen", title="Экран", value=f"{w_} × {h_}" if w_ else "—",
             caption=(f"{count} {plural(count, 'монитор', 'монитора', 'мониторов')} · "
                      f"{dpi} DPI ({round(dpi / 96 * 100)} %)") if w_ else "—",
             accent="#f472b6", bar=None, details=page_screen),
        dict(key="tests", title="Тесты", value="Проверить скорость",
             caption=bench_caption, accent="#ef4444", bar=None, details=None),
    ]


def is_admin():
    if not IS_WIN:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def disk_models(d):
    """Собирает диски: модель, тип, состояние, разделы с занятостью и SMART."""
    disks = d.get("disks") or []
    phys = d.get("phys") or []
    partitions = d.get("partitions") or []
    vols = {(v.get("letter") or "").upper().rstrip(":"): v
            for v in (d.get("volumes") or [])}

    by_index, by_name = {}, {}
    for x in disks:
        try:
            by_index[int(x.get("index"))] = x
        except (TypeError, ValueError):
            pass
        by_name[(x.get("model") or "").strip().lower()] = x

    def volumes_for(idx):
        out = []
        for pt in partitions:
            if str(pt.get("disknumber")) != str(idx):
                continue
            letter = (pt.get("driveletter") or "").upper().rstrip(":")
            if not letter:
                continue
            v = vols.get(letter)
            if v is None:
                v = {"letter": letter + ":", "size": pt.get("size"),
                     "free": 0, "fs": ""}
            out.append(v)
        return out

    models, seen = [], set()
    for p in phys:
        name = (p.get("name") or "").strip()
        did = str(p.get("deviceid") or "")
        md = by_index.get(int(did)) if did.isdigit() else None
        md = md or by_name.get(name.lower()) or {}
        models.append({
            "name": name or (md.get("model") or "Накопитель"),
            "size": p.get("size") or md.get("size"),
            "bus": p.get("bus") or md.get("iface"),
            "media": p.get("media") or md.get("media"),
            "health": (p.get("health") or "").strip(),
            "serial": (md.get("serial") or "").strip(),
            "firmware": (md.get("fw") or "").strip(),
            "volumes": volumes_for(did),
            "smart": {k: p.get(k) for k in
                      ("wear", "temp", "hours", "readerr", "writeerr")},
        })
        seen.add(name.lower())
        if did:
            seen.add("#" + did)

    for x in disks:
        name = (x.get("model") or "").strip()
        idx = str(x.get("index") or "")
        if name.lower() in seen or (idx and "#" + idx in seen):
            continue
        models.append({
            "name": name or "Накопитель", "size": x.get("size"),
            "bus": x.get("iface"), "media": x.get("media"),
            "health": "", "serial": (x.get("serial") or "").strip(),
            "firmware": (x.get("fw") or "").strip(),
            "volumes": volumes_for(x.get("index")), "smart": {},
        })
    return models


# --------------------------------------------------------------------------
# GUI: плитки
# --------------------------------------------------------------------------

def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter import font as tkfont

    # Светлая тема: светло-серое окно, белые плитки, синие акценты.
    BG = "#eef1f6"
    CARD = "#ffffff"
    BORDER = "#dde3ea"
    ACCENT = "#1f6feb"
    ACCENT_HOVER = "#1a63c8"
    TEXT = "#16202c"
    MUTED = "#5b6573"
    TROUGH = "#dde3ea"
    GOOD = "#1a7f37"
    WARN = "#9a6700"
    CRIT = "#c62828"

    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VER} — характеристики компьютера")
    root.configure(bg=BG)
    if IS_WIN:
        try:
            root.state("zoomed")
        except tk.TclError:
            root.geometry("1280x800")
    else:
        root.geometry("1280x800")
    root.minsize(820, 560)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    for _name, _color, _thick in (
            ("Card", ACCENT, 6), ("Ok", GOOD, 8), ("Warn", WARN, 8),
            ("Crit", CRIT, 8), ("Info", ACCENT, 8), ("DiskAlert", CRIT, 6),
            ("Splash", ACCENT, 6)):
        style.configure(f"{_name}.Horizontal.TProgressbar",
                        troughcolor=TROUGH, background=_color,
                        bordercolor=TROUGH, lightcolor=_color,
                        darkcolor=_color, thickness=_thick)
    style.configure("Vertical.TScrollbar", background="#d7dce3",
                    troughcolor="#f3f5f8", arrowcolor=MUTED,
                    bordercolor=BORDER)

    # ---------- экран загрузки ----------
    # Главное окно скрыто, пока данные не собраны: пустые плитки не мелькают.
    splash = None
    splash_bar = None
    splash_label = None
    splash_started = 0.0
    splash_finishing = False

    def show_splash():
        nonlocal splash, splash_bar, splash_label, splash_started
        splash_started = time.monotonic()
        win = tk.Toplevel(root, bg=CARD)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        w, h = 430, 196
        x = (win.winfo_screenwidth() - w) // 2
        y = (win.winfo_screenheight() - h) // 3
        win.geometry(f"{w}x{h}+{x}+{y}")

        card = tk.Frame(win, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True)
        tk.Frame(card, bg=ACCENT, height=4).pack(fill="x")
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill="both", expand=True, padx=28, pady=(22, 20))

        tk.Label(inner, text=APP_NAME, bg=CARD, fg=TEXT,
                 font=("Segoe UI Semibold", 26)).pack(anchor="w")
        tk.Label(inner, text="характеристики компьютера", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 22))
        bar = ttk.Progressbar(inner, mode="indeterminate", length=360,
                              style="Splash.Horizontal.TProgressbar")
        bar.pack(fill="x")
        bar.start(12)
        label = tk.Label(inner, text="собираем данные о железе…", bg=CARD,
                         fg=MUTED, font=("Segoe UI", 9))
        label.pack(anchor="w", pady=(14, 0))
        splash, splash_bar, splash_label = win, bar, label

    splash_steps = ("собираем данные о железе…", "опрашиваем Windows…",
                    "почти готово…")

    def splash_step(i=0):
        if splash is None or splash_label is None:
            return
        try:
            if not splash.winfo_exists():
                return
            splash_label.configure(text=splash_steps[i % len(splash_steps)])
            splash.after(900, lambda: splash_step(i + 1))
        except tk.TclError:
            return

    def hide_splash():
        nonlocal splash, splash_bar, splash_label
        if splash is None:
            return
        try:
            splash_bar.stop()
        except (tk.TclError, AttributeError):
            pass
        try:
            splash.destroy()
        except tk.TclError:
            pass
        splash, splash_bar, splash_label = None, None, None
        try:
            root.deiconify()
            root.lift()
            if IS_WIN:
                root.state("zoomed")
        except tk.TclError:
            pass

    def finish_splash():
        nonlocal splash_finishing
        if splash is None or splash_finishing:
            return
        splash_finishing = True
        # Небольшая задержка, чтобы экран не мигал при тёплом кэше.
        delay = max(0, int(600 - (time.monotonic() - splash_started) * 1000))
        root.after(delay, hide_splash)

    root.withdraw()
    show_splash()
    splash.after(900, splash_step)
    root.after(30000, finish_splash)  # на случай, если сбор данных завис

    data = {}
    live = {"cpu": 0.0, "gpu": 0.0, "uptime": uptime_seconds(),
            "bench": []}
    counters = LiveCounters()
    gpu_sensors = NvmlSensors()
    q = queue.Queue()
    status_var = tk.StringVar(value="сбор данных…")

    # ---------- шапка ----------
    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", side="top")

    head_text = tk.Frame(header, bg=BG)
    head_text.pack(side="left", padx=(22, 0), pady=(14, 8))
    tk.Label(head_text, text=APP_NAME, bg=BG, fg=TEXT,
             font=("Segoe UI Semibold", 18)).pack(anchor="w")
    tk.Label(head_text, text="характеристики компьютера", bg=BG, fg=MUTED,
             font=("Segoe UI", 9)).pack(anchor="w")
    tk.Label(head_text, textvariable=status_var, bg=BG, fg=MUTED,
             font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 0))

    actions = tk.Frame(header, bg=BG)
    actions.pack(side="right", padx=22)

    def header_button(text, command, primary=False):
        btn = tk.Button(actions, text=text, command=command, relief="flat",
                        bd=0, padx=14, pady=7, cursor="hand2",
                        font=("Segoe UI", 9),
                        bg=ACCENT if primary else CARD,
                        fg="white" if primary else TEXT,
                        activebackground=ACCENT_HOVER if primary else BORDER,
                        activeforeground="white" if primary else TEXT,
                        highlightthickness=1,
                        highlightbackground=ACCENT if primary else BORDER)
        btn.pack(side="left", padx=4)
        return btn

    btn_run = header_button("Тесты", lambda: start_bench(), primary=True)
    header_button("Обновить", lambda: on_refresh())
    header_button("Отчёт", lambda: on_save())

    # ---------- сетка плиток: без прокрутки, плитки тянутся на всё окно ----------
    board = tk.Frame(root, bg=BG)
    board.pack(fill="both", expand=True, padx=12, pady=(4, 8))

    scroll_target = {"cv": None}

    def wheel(event):
        cv = scroll_target["cv"]
        if cv is not None:
            try:
                cv.yview_scroll(int(-event.delta / 120), "units")
            except tk.TclError:
                pass

    def scrollable(cv):
        cv.bind("<Enter>", lambda e: scroll_target.update(cv=cv))
        cv.bind("<Leave>", lambda e: scroll_target.update(cv=None))

    cards = {}
    order = []

    def reflow(_event=None):
        if not order:
            return
        width = board.winfo_width() or 1060
        cols = 3
        rows = (len(order) + cols - 1) // cols
        for i, key in enumerate(order):
            cards[key].grid(row=i // cols, column=i % cols, sticky="nsew",
                            padx=7, pady=7)
        for col in range(cols):
            board.columnconfigure(col, weight=1, uniform="cards")
        for row in range(6):
            board.rowconfigure(row, weight=1 if row < rows else 0,
                               uniform="rows" if row < rows else "")
        wrap_len = max(150, int((width - cols * 14) / cols) - 40)
        cell_h = (board.winfo_height() or 660) / max(1, rows)
        vsize = max(15, min(30, int(cell_h / 9)))
        csize = 11 if cell_h >= 250 else 10 if cell_h >= 190 else 9
        for card in cards.values():
            card.value.configure(font=("Segoe UI Semibold", vsize),
                                 wraplength=wrap_len)
            card.caption.configure(font=("Segoe UI", csize),
                                   wraplength=wrap_len)

    # ---------- подробности ----------
    def show_details(title, rows):
        win = tk.Toplevel(root)
        win.title(f"{title} — {APP_NAME}")
        win.geometry("660x600")
        win.minsize(460, 340)
        win.configure(bg=BG)
        win.transient(root)
        win.geometry(f"+{root.winfo_x() + 60}+{root.winfo_y() + 40}")

        top = tk.Frame(win, bg=BG)
        top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text=title, bg=BG, fg=TEXT,
                 font=("Segoe UI Semibold", 14)).pack(side="left")
        tk.Button(top, text="Закрыть", command=win.destroy, relief="flat", bd=0,
                  padx=10, pady=4, cursor="hand2", font=("Segoe UI", 9),
                  bg=CARD, fg=TEXT, highlightthickness=1,
                  highlightbackground=BORDER).pack(side="right")

        holder = tk.Frame(win, bg=BG)
        holder.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        cv = tk.Canvas(holder, bg=CARD, highlightthickness=0)
        sb = ttk.Scrollbar(holder, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(cv, bg=CARD)
        iwin = cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfigure(iwin, width=e.width))
        scrollable(cv)

        inner.columnconfigure(1, weight=1)
        for i, (k, v) in enumerate(rows):
            if k and not v:
                tk.Label(inner, text=k, bg=CARD, fg=ACCENT,
                         font=("Segoe UI Semibold", 9)).grid(
                    row=i, column=0, columnspan=2, sticky="w",
                    padx=14, pady=(12, 2))
            elif k:
                tk.Label(inner, text=k, bg=CARD, fg=MUTED,
                         font=("Segoe UI", 9), anchor="w").grid(
                    row=i, column=0, sticky="nw", padx=(14, 18), pady=2)
                tk.Label(inner, text=str(v), bg=CARD, fg=TEXT,
                         font=("Segoe UI", 9), anchor="w", justify="left",
                         wraplength=430).grid(row=i, column=1, sticky="w",
                                              padx=(0, 14), pady=2)
            else:
                tk.Label(inner, text=str(v), bg=CARD, fg=MUTED,
                         font=("Segoe UI", 9), anchor="w", justify="left",
                         wraplength=430).grid(row=i, column=1, sticky="w",
                                              padx=(0, 14), pady=2)
        return win

    def bar_style(pct):
        return "Crit" if pct >= 90 else "Warn" if pct >= 75 else "Ok"

    def close_button(parent, command):
        tk.Button(parent, text="Закрыть", command=command, relief="flat", bd=0,
                  padx=10, pady=4, cursor="hand2", font=("Segoe UI", 9),
                  bg=CARD, fg=TEXT, highlightthickness=1,
                  highlightbackground=BORDER).pack(side="right")

    disks_windows = []

    def open_disks_window():
        win = tk.Toplevel(root)
        win.title(f"Накопители — {APP_NAME}")
        win.geometry("900x700")
        win.minsize(560, 420)
        win.configure(bg=BG)
        win.transient(root)
        win.geometry(f"+{max(0, root.winfo_x() + 40)}+{max(0, root.winfo_y() + 30)}")

        top = tk.Frame(win, bg=BG)
        top.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(top, text="Накопители", bg=BG, fg=TEXT,
                 font=("Segoe UI Semibold", 15)).pack(side="left")
        close_button(top, win.destroy)

        holder = tk.Frame(win, bg=BG)
        holder.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        cv = tk.Canvas(holder, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(holder, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(cv, bg=BG)
        iwin = cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfigure(iwin, width=e.width))
        scrollable(cv)

        def fill():
            for _c in inner.winfo_children():
                _c.destroy()
            models = disk_models(data)
            total = sum(int(m.get("size") or 0) for m in models)
            free = sum(int(v.get("free") or 0)
                       for m in models for v in m["volumes"])
            used = max(0, total - free)
            pct = used * 100 / total if total else 0

            summ = tk.Frame(inner, bg=CARD, highlightbackground=BORDER,
                            highlightthickness=1)
            summ.pack(fill="x", pady=(0, 8))

            def stat(parent, title, value, color=TEXT, size=16):
                box = tk.Frame(parent, bg=CARD)
                tk.Label(box, text=title.upper(), bg=CARD, fg=MUTED,
                         font=("Segoe UI", 8)).pack(anchor="w")
                tk.Label(box, text=value, bg=CARD, fg=color,
                         font=("Segoe UI Semibold", size)).pack(anchor="w")
                return box

            row = tk.Frame(summ, bg=CARD)
            row.pack(fill="x", padx=16, pady=(14, 8))
            stat(row, "Всего", fmt_bytes(total)).pack(side="left", padx=(0, 40))
            stat(row, "Занято", fmt_bytes(used)).pack(side="left", padx=(0, 40))
            stat(row, "Свободно", fmt_bytes(free), GOOD).pack(side="left",
                                                              padx=(0, 40))
            stat(row, "Заполнено", f"{pct:.0f} %").pack(side="left")
            stat(row, "Накопителей", str(len(models))).pack(side="right")

            ttk.Progressbar(summ, style="Card.Horizontal.TProgressbar",
                            maximum=100, value=pct).pack(fill="x", padx=16,
                                                         pady=(0, 14))

            def disk_card(model):
                card = tk.Frame(inner, bg=CARD, highlightbackground=BORDER,
                                highlightthickness=1)
                card.pack(fill="x", pady=(0, 8))

                head = tk.Frame(card, bg=CARD)
                head.pack(fill="x", padx=16, pady=(14, 0))
                tk.Label(head, text=model["name"], bg=CARD, fg=TEXT,
                         font=("Segoe UI Semibold", 12),
                         anchor="w").pack(side="left")

                media = model.get("media") or ""
                if media.lower() in ("unspecified", "unknown", "0"):
                    media = ""
                bus = model.get("bus") or ""
                if bus.lower() in ("unspecified", "unknown", "0"):
                    bus = ""
                meta = " · ".join(x for x in (media, bus,
                                              fmt_bytes(model.get("size"))) if x)
                tk.Label(card, text=meta, bg=CARD, fg=MUTED,
                         font=("Segoe UI", 9), anchor="w").pack(
                    fill="x", padx=16, pady=(2, 0))

                if model["volumes"]:
                    for v in model["volumes"]:
                        size = int(v.get("size") or 0)
                        free_v = int(v.get("free") or 0)
                        used_pct = 100.0 - free_v * 100.0 / size if size else 0.0
                        letter = (v.get("letter") or "?").strip()
                        label = (v.get("label") or "").strip() or "Локальный диск"

                        row = tk.Frame(card, bg=CARD)
                        row.pack(fill="x", padx=16, pady=(12, 0))
                        head2 = tk.Frame(row, bg=CARD)
                        head2.pack(fill="x")
                        tk.Label(head2, text=letter, bg=CARD, fg=ACCENT,
                                 font=("Segoe UI Semibold", 11)).pack(side="left")
                        tk.Label(head2, text=label, bg=CARD, fg=TEXT,
                                 font=("Segoe UI", 9)).pack(side="left",
                                                            padx=(8, 0))
                        tk.Label(head2, text=f"{used_pct:.0f} %", bg=CARD,
                                 fg=(CRIT if used_pct >= 90 else
                                     WARN if used_pct >= 75 else GOOD),
                                 font=("Segoe UI Semibold", 11)).pack(side="right")
                        ttk.Progressbar(row,
                                        style=f"{bar_style(used_pct)}.Horizontal.TProgressbar",
                                        maximum=100, value=used_pct).pack(
                            fill="x", pady=(4, 2))
                        foot = tk.Frame(row, bg=CARD)
                        foot.pack(fill="x")
                        tk.Label(foot, text=f"занято {fmt_bytes(size - free_v)} "
                                            f"из {fmt_bytes(size)}",
                                 bg=CARD, fg=MUTED,
                                 font=("Segoe UI", 8)).pack(side="left")
                        tk.Label(foot, text=f"свободно {fmt_bytes(free_v)}",
                                 bg=CARD, fg=GOOD,
                                 font=("Segoe UI", 8)).pack(side="right")
                else:
                    tk.Label(card, text="Разделы не найдены (не размечен)", bg=CARD,
                             fg=MUTED, font=("Segoe UI", 9)).pack(
                        anchor="w", padx=16, pady=(10, 0))

                sm = model.get("smart") or {}
                bits = []
                if sm.get("temp") is not None:
                    bits.append(f"температура {sm['temp']} °C")
                if sm.get("wear") is not None:
                    bits.append(f"износ {sm['wear']} %")
                if sm.get("hours") is not None:
                    bits.append(f"наработка {fmt_num(sm['hours'], 'ч')}")
                if sm.get("readerr"):
                    bits.append(f"ошибок чтения {sm['readerr']}")
                smart_text = "SMART: " + " · ".join(bits) if bits else ""
                extra = " · ".join(x for x in (
                    (f"S/N {model['serial']}" if model.get("serial") else ""),
                    (f"прошивка {model['firmware']}"
                     if model.get("firmware") else "")) if x)
                if smart_text or extra:
                    tail = tk.Frame(card, bg=CARD)
                    tail.pack(fill="x", padx=16, pady=(10, 14))
                    if smart_text:
                        tk.Label(tail, text=smart_text, bg=CARD, fg=MUTED,
                                 font=("Segoe UI", 8),
                                 anchor="w").pack(anchor="w")
                    if extra:
                        tk.Label(tail, text=extra, bg=CARD, fg=MUTED,
                                 font=("Segoe UI", 8), anchor="w").pack(
                            anchor="w", pady=(2, 0) if smart_text else 0)

            for model in models:
                disk_card(model)

            if not models:
                text = ("Собираю данные о накопителях…" if not data
                        else "Накопители не найдены")
                tk.Label(inner, text=text, bg=BG, fg=MUTED,
                         font=("Segoe UI", 10)).pack(pady=30)

        filled_ok = [False]

        def fill_and_keep_top():
            fill()
            if not filled_ok[0] and disk_models(data):
                filled_ok[0] = True
                cv.update_idletasks()
                cv.yview_moveto(0)

        fill_and_keep_top()
        disks_windows.append((win, fill_and_keep_top))

    # ---------- плитка ----------
    class Tile(tk.Frame):
        def __init__(self, master, tile):
            super().__init__(master, bg=CARD, highlightbackground=BORDER,
                             highlightthickness=1, cursor="hand2")
            self.tile = tile
            self.accent = tile.get("accent") or ACCENT
            head = tk.Frame(self, bg=CARD)
            head.pack(fill="x", padx=14, pady=(12, 0))
            stripe = tk.Frame(head, bg=self.accent, width=3, height=13)
            stripe.pack(side="left")
            stripe.pack_propagate(False)
            tk.Label(head, text=tile["title"].upper(), bg=CARD, fg=MUTED,
                     font=("Segoe UI", 8)).pack(side="left", padx=(8, 0))

            self.body = tk.Frame(self, bg=CARD)
            self.body.pack(fill="both", expand=True, padx=14)
            self.body.columnconfigure(0, weight=1)
            self.body.grid_rowconfigure(0, weight=1)
            self.body.grid_rowconfigure(3, weight=1)

            self.value = tk.Label(self.body, text=tile["value"], bg=CARD,
                                  fg=TEXT,
                                  font=("Segoe UI Semibold", 15), anchor="w",
                                  justify="left", wraplength=300)
            self.value.grid(row=1, column=0, sticky="w")

            self.caption = tk.Label(self, text=tile["caption"], bg=CARD,
                                    fg=MUTED, font=("Segoe UI", 9), anchor="w",
                                    justify="left", wraplength=300)
            self.caption.pack(side="bottom", fill="x", padx=14, pady=(6, 12))

            self.bar = None
            if tile.get("bar") is not None:
                self.bar = ttk.Progressbar(
                    self.body,
                    style=tile.get("barstyle") or "Card.Horizontal.TProgressbar",
                    maximum=100, value=float(tile["bar"] or 0))
                self.bar.grid(row=2, column=0, sticky="ew", pady=(8, 0))

            self._bind_all(self)

        def _bind_all(self, widget):
            widget.bind("<Enter>", self._enter)
            widget.bind("<Leave>", self._leave)
            widget.bind("<Button-1>", self._click)
            for child in widget.winfo_children():
                self._bind_all(child)

        def _enter(self, _e):
            self.configure(highlightbackground=self.accent)

        def _leave(self, _e):
            self.configure(highlightbackground=BORDER)

        def _click(self, _e):
            tile = self.tile
            if tile["key"] == "tests":
                start_bench()
            elif tile["key"] == "disks":
                open_disks_window()
            else:
                rows = tile["details"](data, live)
                show_details(tile["title"], rows)

    def render():
        nonlocal order
        for child in board.winfo_children():
            child.destroy()
        cards.clear()
        tiles = build_cards(data, live)
        order = [t["key"] for t in tiles]
        for tile in tiles:
            cards[tile["key"]] = Tile(board, tile)
        reflow()

    # ---------- окно тестов ----------
    tests_win = {"win": None, "labels": {}}

    def open_tests():
        win = tests_win["win"]
        if win is not None and win.winfo_exists():
            win.lift()
            win.focus_force()
            return
        win = tk.Toplevel(root)
        win.title(f"Тесты — {APP_NAME}")
        win.geometry("540x400")
        win.minsize(420, 320)
        win.configure(bg=BG)
        win.transient(root)
        win.geometry(f"+{root.winfo_x() + 120}+{root.winfo_y() + 90}")
        tests_win["win"] = win
        tests_win["labels"] = {}

        tk.Label(win, text="ТЕСТЫ ПРОИЗВОДИТЕЛЬНОСТИ", bg=BG, fg=ACCENT,
                 font=("Segoe UI Semibold", 10)).pack(anchor="w", padx=20,
                                                      pady=(16, 2))
        tk.Label(win, text="Короткие замеры (1–2 с). Показывают реальную "
                           "скорость именно этой машины.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9),
                 wraplength=480, justify="left").pack(anchor="w", padx=20,
                                                      pady=(0, 10))

        body = tk.Frame(win, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        body.pack(fill="both", expand=True, padx=20)
        body.columnconfigure(1, weight=1)
        rows = [("cpu1", "Процессор, 1 поток"),
                ("cpun", "Процессор, все потоки"),
                ("mem", "Память (копирование)"),
                ("write", "Диск — запись"),
                ("read", "Диск — чтение")]
        for i, (key, title) in enumerate(rows):
            tk.Label(body, text=title, bg=CARD, fg=MUTED,
                     font=("Segoe UI", 9)).grid(row=i, column=0, sticky="w",
                                                padx=14, pady=8)
            lbl = tk.Label(body, text="—", bg=CARD, fg=TEXT,
                           font=("Segoe UI", 10))
            lbl.grid(row=i, column=1, sticky="w", pady=8)
            tests_win["labels"][key] = lbl

        bottom = tk.Frame(win, bg=BG)
        bottom.pack(fill="x", padx=20, pady=12)
        tk.Button(bottom, text="Прогнать тесты", command=start_bench,
                  relief="flat", bd=0, padx=14, pady=7, cursor="hand2",
                  font=("Segoe UI", 9), bg=ACCENT, fg="white",
                  activebackground=ACCENT_HOVER, activeforeground="white"
                  ).pack(side="left")
        tk.Button(bottom, text="Закрыть", command=win.destroy, relief="flat",
                  bd=0, padx=12, pady=7, cursor="hand2", font=("Segoe UI", 9),
                  bg=CARD, fg=TEXT, highlightthickness=1,
                  highlightbackground=BORDER).pack(side="right")
        tk.Label(bottom, text="F5", bg=BG, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="right", padx=8)

    # ---------- фоновые задачи ----------
    def worker_collect():
        try:
            q.put(("data", collect_hardware(use_cache=True)))
        except Exception as e:
            q.put(("error", str(e)))

    def worker_refresh():
        try:
            q.put(("data", collect_hardware(use_cache=False)))
        except Exception as e:
            q.put(("error", str(e)))

    def worker_bench():
        q.put(("bench_status", "идёт тест процессора…"))
        try:
            c1, _ = bench_cpu(1)
            q.put(("bench", ("cpu1", f"{c1:,.0f} МБ/с (SHA-256)".replace(",", " "))))
            threads = os.cpu_count() or 1
            q.put(("bench_status", f"тест процессора на {threads} потоках…"))
            cn, _ = bench_cpu_multi(threads)
            speedup = cn / c1 if c1 else 0
            q.put(("bench", ("cpun", f"{cn:,.0f} МБ/с · {threads} потоков, "
                                     f"ускорение ×{speedup:.1f}".replace(",", " "))))
            q.put(("bench_status", "тест памяти…"))
            mem = bench_memory()
            q.put(("bench", ("mem", f"{mem:,.0f} МБ/с".replace(",", " "))))
            q.put(("bench_status", "тест диска…"))
            w, r = bench_disk()
            q.put(("bench", ("write", f"{w:,.0f} МБ/с".replace(",", " "))))
            q.put(("bench", ("read", f"{r:,.0f} МБ/с (с кэшем)".replace(",", " "))))
            q.put(("bench_status", "готово"))
        except Exception as e:
            q.put(("error", f"Ошибка теста: {e}"))

    def start_bench():
        open_tests()
        for lbl in tests_win["labels"].values():
            lbl.configure(text="—")
        live["bench"] = []
        threading.Thread(target=worker_bench, daemon=True).start()

    def poll():
        changed = False
        try:
            while True:
                kind, payload = q.get_nowait()
                if kind == "data":
                    data.clear()
                    data.update(payload)
                    data.pop("_pending", None)
                    changed = True
                    finish_splash()
                elif kind == "error":
                    status_var.set("ошибка")
                    finish_splash()
                    messagebox.showerror(APP_NAME, payload)
                elif kind == "bench":
                    key, text = payload
                    live["bench"].append(payload)
                    lbl = tests_win["labels"].get(key)
                    if lbl is not None and lbl.winfo_exists():
                        lbl.configure(text=text)
                elif kind == "bench_status":
                    status_var.set(payload)
                    btn_run.configure(state="disabled" if payload != "готово"
                                              else "normal")
        except queue.Empty:
            pass
        if changed:
            status_var.set(f"данные получены · {dt.datetime.now():%H:%M}")
            render()
            alive = []
            for w, refill in disks_windows:
                try:
                    if w.winfo_exists():
                        refill()
                        alive.append((w, refill))
                except tk.TclError:
                    pass
            disks_windows[:] = alive
        root.after(120, poll)

    # ---------- живые показатели ----------
    prev_times = cpu_times()

    def tick():
        nonlocal prev_times
        cur = cpu_times()
        load = cpu_load(prev_times, cur)
        prev_times = cur
        live["cpu"] = load
        live["uptime"] = uptime_seconds()
        gpu_pct, _disk_busy = counters.update()
        if gpu_pct is not None:
            live["gpu"] = gpu_pct
        m = memory()

        card = cards.get("cpu")
        if card is not None:
            if card.bar is not None:
                card.bar.configure(value=load)
            card.caption.configure(text=cpu_caption(data, live))
        card = cards.get("mem")
        if card is not None and m is not None:
            if card.bar is not None:
                card.bar.configure(value=m.dwMemoryLoad)
            card.caption.configure(text=mem_caption(data, m))
        card = cards.get("gpu")
        if card is not None:
            if card.bar is not None and gpu_pct is not None:
                card.bar.configure(value=gpu_pct)
            card.caption.configure(text=gpu_caption(data, live))
        root.after(1000, tick)

    # ---------- действия ----------
    def on_refresh():
        status_var.set("обновляю данные…")
        threading.Thread(target=worker_refresh, daemon=True).start()

    def on_save():
        path = filedialog.asksaveasfilename(
            title="Сохранить отчёт", defaultextension=".txt",
            initialfile=f"Syryx-отчёт-{dt.datetime.now():%Y-%m-%d}.txt",
            filetypes=[("Текстовый файл", "*.txt"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write(build_report(data, live))
            status_var.set("отчёт сохранён")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить: {e}")

    # ---------- нижняя строка ----------
    bar = tk.Frame(root, bg="#f3f3f3", height=26)
    bar.pack(fill="x", side="bottom")
    bar.pack_propagate(False)
    tk.Label(bar, text="F5 — тесты · Ctrl+R — обновить · Ctrl+S — отчёт",
             bg="#f3f3f3", fg=MUTED, font=("Segoe UI", 8)).pack(
        side="left", padx=18)
    tk.Label(bar, text=f"{APP_NAME} {APP_VER}", bg="#f3f3f3", fg=MUTED,
             font=("Segoe UI", 8)).pack(side="right", padx=18)

    root.bind("<F5>", lambda e: start_bench())
    root.bind("<Control-r>", lambda e: on_refresh())
    root.bind("<Control-s>", lambda e: on_save())
    root.bind("<MouseWheel>", wheel)
    board.bind("<Configure>", reflow)

    render()
    root.after(120, poll)
    root.after(1000, tick)

    def _debug_view():
        what = os.environ.get("SYRYX_DEBUG")
        if what == "disks":
            open_disks_window()
        elif what == "bench":
            start_bench()
        root.after(1500, _debug_dump)

    def _debug_dump():
        import ctypes as ct
        u = ct.windll.user32
        found = []

        @ct.WINFUNCTYPE(ct.c_bool, ct.c_void_p, ct.c_void_p)
        def _cb(h, _l):
            p = ct.c_ulong()
            u.GetWindowThreadProcessId(h, ct.byref(p))
            if p.value == os.getpid():
                buf = ct.create_unicode_buffer(256)
                u.GetWindowTextW(h, buf, 256)
                found.append([int(h), buf.value, bool(u.IsWindowVisible(h))])
            return True

        u.EnumWindows(_cb, 0)
        with open(os.path.join(tempfile.gettempdir(), "syryx-dbg.txt"),
                  "a", encoding="utf-8") as f:
            f.write(repr(found) + "\n")

    if os.environ.get("SYRYX_DEBUG"):
        root.after(3000, _debug_view)

    threading.Thread(target=worker_collect, daemon=True).start()
    root.mainloop()

def run_cli():
    """
    Отчёт без окна.
    Из исходников — печать в консоль. В exe консоли нет, поэтому отчёт
    сохраняется в текущую папку и открывается в блокноте.
    """
    frozen = getattr(sys, "frozen", False)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    try:
        d = collect_hardware(use_cache=True)
    except Exception as e:
        if frozen:
            import tkinter.messagebox as mb
            mb.showerror(APP_NAME, f"Ошибка сбора данных:\n{e}")
        else:
            print("Ошибка сбора данных:", e)
        return 1

    live = {"cpu": 0.0, "uptime": uptime_seconds(), "bench": []}
    text = build_report(d, live)

    if frozen:
        path = os.path.join(os.getcwd(), "Syryx-отчёт.txt")
        try:
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write(text)
            os.startfile(path)  # noqa: S606 — открыть отчёт в блокноте
        except OSError as e:
            import tkinter.messagebox as mb
            mb.showerror(APP_NAME, f"Не удалось сохранить отчёт:\n{e}")
            return 1
    else:
        print(text)
    return 0


if __name__ == "__main__":
    if "--report" in sys.argv:
        sys.exit(run_cli())
    run_gui()
