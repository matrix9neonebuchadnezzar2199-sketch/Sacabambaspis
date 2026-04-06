# -*- coding: utf-8 -*-
"""P26: Memory Dump & Analysis Module"""
import os
import time
import sys
import ctypes
import ctypes.wintypes
import struct
from datetime import datetime

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ALL_ACCESS = 0x1F0FFF
MiniDumpWithFullMemory = 0x00000002
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]

PROTECT_LABELS = {
    0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WRITECOPY",
    0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "X-WRITECOPY",
}

REGION_TYPES = {0x20000: "Private", 0x40000: "Mapped", 0x1000000: "Image"}


class MemoryDumper:
    """Process memory dump and analysis."""

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.dbghelp = ctypes.windll.dbghelp
        self.psapi = ctypes.windll.psapi
        # F1-b: exe環境ではexe隣接、通常環境ではプロジェクトルート
        if getattr(sys, 'frozen', False):
            _base = os.path.dirname(sys.executable)
        else:
            _base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.dump_dir = os.path.join(_base, "dumps")
        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir)

    # ==========================================
    # 1. Process listing
    # ==========================================
    def list_processes(self):
        """Return list of running processes with basic info."""
        import psutil
        results = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'cpu_percent', 'status', 'username']):
            try:
                info = proc.info
                mem = info.get('memory_info')
                results.append({
                    'pid': info['pid'],
                    'name': info.get('name', ''),
                    'exe': info.get('exe', '') or '',
                    'memory_mb': round(mem.rss / 1048576, 1) if mem else 0,
                    'cpu': info.get('cpu_percent', 0),
                    'status': info.get('status', ''),
                    'username': info.get('username', '') or '',
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(results, key=lambda x: x['memory_mb'], reverse=True)

    # ==========================================
    # 2. Full memory dump
    # ==========================================
    def dump_process(self, pid, output_dir=None):
        """Create a full memory dump of the specified process."""
        if output_dir is None:
            output_dir = self.dump_dir

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Get process name
        try:
            import psutil
            proc = psutil.Process(pid)
            pname = proc.name().replace('.exe', '')
        except Exception:
            pname = 'unknown'

        # F1-c: サブフォルダ形式 YYYYMMDD_HHMMSS_プロセス名/
        dump_subdir = os.path.join(output_dir, f"{ts}_{pname}")
        os.makedirs(dump_subdir, exist_ok=True)

        filename = f"{pname}_{pid}.dmp"
        filepath = os.path.join(dump_subdir, filename)


        handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle:
            return {'success': False, 'error': f'OpenProcess failed (PID={pid}). Admin rights required.'}

        try:
            with open(filepath, 'wb') as f:
                ctypes.c_uint(f.fileno())
                import msvcrt
                h_file = msvcrt.get_osfhandle(f.fileno())
                result = self.dbghelp.MiniDumpWriteDump(
                    handle, pid, h_file,
                    MiniDumpWithFullMemory, None, None, None
                )
                if not result:
                    return {'success': False, 'error': 'MiniDumpWriteDump failed.'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            self.kernel32.CloseHandle(handle)

        size_mb = round(os.path.getsize(filepath) / 1048576, 2)
        return {
            'success': True,
            'filepath': filepath,
            'filename': filename,
            'size_mb': size_mb,
        }

    # ==========================================
    # 3. String extraction
    # ==========================================
    def extract_strings(self, pid, min_len=4, max_results=5000):
        """Extract ASCII/Unicode strings from process memory."""
        handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not handle:
            return {'success': False, 'error': 'OpenProcess failed.'}

        results = []
        try:
            regions = self._enum_regions(handle)
            for region in regions:
                if region['state'] != MEM_COMMIT:
                    continue
                data = self._read_region(handle, region['base'], region['size'])
                if not data:
                    continue
                # ASCII
                results.extend(self._find_strings(data, region['base'], min_len, 'ASCII'))
                # Unicode (UTF-16LE)
                results.extend(self._find_strings_unicode(data, region['base'], min_len))
                if len(results) >= max_results:
                    results = results[:max_results]
                    break
        finally:
            self.kernel32.CloseHandle(handle)

        return {'success': True, 'count': len(results), 'strings': results}

    def _find_strings(self, data, base_addr, min_len, encoding='ASCII'):
        """Find printable ASCII strings."""
        result = []
        current = []
        start = 0
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                if not current:
                    start = i
                current.append(chr(b))
            else:
                if len(current) >= min_len:
                    result.append({
                        'offset': hex(base_addr + start),
                        'type': encoding,
                        'value': ''.join(current)[:512],
                    })
                current = []
        if len(current) >= min_len:
            result.append({
                'offset': hex(base_addr + start),
                'type': encoding,
                'value': ''.join(current)[:512],
            })
        return result

    def _find_strings_unicode(self, data, base_addr, min_len):
        """Find UTF-16LE strings."""
        result = []
        try:
            i = 0
            while i < len(data) - 1:
                start = i
                chars = []
                while i < len(data) - 1:
                    c = data[i] | (data[i+1] << 8)
                    if 0x20 <= c <= 0x7E or c in (0x3000, 0x30FC) or (0x3040 <= c <= 0x9FFF):
                        chars.append(chr(c))
                        i += 2
                    else:
                        break
                if len(chars) >= min_len:
                    result.append({
                        'offset': hex(base_addr + start),
                        'type': 'Unicode',
                        'value': ''.join(chars)[:512],
                    })
                i += 2
        except Exception:
            pass
        return result

    # ==========================================
    # 4. DLL list
    # ==========================================
    def list_dlls(self, pid):
        """List loaded DLLs for a process."""
        handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not handle:
            return {'success': False, 'error': 'OpenProcess failed.'}

        try:
            hMods = (ctypes.c_void_p * 1024)()
            cbNeeded = ctypes.wintypes.DWORD()
            if not self.psapi.EnumProcessModulesEx(
                handle, ctypes.byref(hMods), ctypes.sizeof(hMods),
                ctypes.byref(cbNeeded), 0x03
            ):
                return {'success': False, 'error': 'EnumProcessModulesEx failed.'}

            count = cbNeeded.value // ctypes.sizeof(ctypes.c_void_p)
            dlls = []
            sys_root = os.environ.get('SystemRoot', 'C:\\Windows').lower()
            prog_files = os.environ.get('ProgramFiles', 'C:\\Program Files').lower()
            prog_x86 = os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').lower()

            for i in range(count):
                mod_name = ctypes.create_unicode_buffer(260)
                mod_path = ctypes.create_unicode_buffer(260)
                self.psapi.GetModuleBaseNameW(handle, hMods[i], mod_name, 260)
                self.psapi.GetModuleFileNameExW(handle, hMods[i], mod_path, 260)

                path_lower = mod_path.value.lower()
                is_system = path_lower.startswith(sys_root) or \
                            path_lower.startswith(prog_files) or \
                            path_lower.startswith(prog_x86)

                size = 0
                try:
                    if os.path.exists(mod_path.value):
                        size = os.path.getsize(mod_path.value)
                except Exception:
                    pass

                dlls.append({
                    'name': mod_name.value,
                    'path': mod_path.value,
                    'base': hex(hMods[i] or 0),
                    'size_kb': round(size / 1024, 1),
                    'is_system': is_system,
                    'suspicious': not is_system and i > 0,
                })
            return {'success': True, 'count': len(dlls), 'dlls': dlls}
        finally:
            self.kernel32.CloseHandle(handle)

    # ==========================================
    # 5. Memory map (VAD)
    # ==========================================
    def memory_map(self, pid):
        """Enumerate virtual memory regions."""
        handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not handle:
            return {'success': False, 'error': 'OpenProcess failed.'}

        try:
            regions = self._enum_regions(handle)
            result = []
            for r in regions:
                if r['state'] != MEM_COMMIT:
                    continue
                prot = r['protect']
                prot_label = PROTECT_LABELS.get(prot, f'0x{prot:02X}')
                is_rwx = prot in (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
                is_exec = prot in (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                                   PAGE_EXECUTE_WRITECOPY, 0x10)
                result.append({
                    'base': hex(r['base']),
                    'size': r['size'],
                    'size_display': self._format_size(r['size']),
                    'protect': prot_label,
                    'type': REGION_TYPES.get(r['type'], f"0x{r['type']:X}"),
                    'is_rwx': is_rwx,
                    'is_exec': is_exec,
                })
            return {'success': True, 'count': len(result), 'regions': result}
        finally:
            self.kernel32.CloseHandle(handle)

    # ==========================================
    # 6. PE header detection
    # ==========================================
    def scan_pe_headers(self, pid):
        """Scan for PE signatures (MZ+PE) in process memory."""
        handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not handle:
            return {'success': False, 'error': 'OpenProcess failed.'}

        findings = []
        try:
            regions = self._enum_regions(handle)
            for r in regions:
                if r['state'] != MEM_COMMIT or r['size'] < 64:
                    continue
                data = self._read_region(handle, r['base'], min(r['size'], 0x100000))
                if not data:
                    continue
                offset = 0
                while offset < len(data) - 64:
                    idx = data.find(b'MZ', offset)
                    if idx == -1:
                        break
                    if idx + 0x3C + 4 <= len(data):
                        pe_offset = struct.unpack_from('<I', data, idx + 0x3C)[0]
                        if idx + pe_offset + 4 <= len(data):
                            if data[idx + pe_offset:idx + pe_offset + 4] == b'PE\x00\x00':
                                addr = r['base'] + idx
                                pe_size = self._estimate_pe_size(data, idx)
                                findings.append({
                                    'address': hex(addr),
                                    'region_base': hex(r['base']),
                                    'region_protect': PROTECT_LABELS.get(r['protect'], '?'),
                                    'estimated_size': self._format_size(pe_size),
                                    'estimated_bytes': pe_size,
                                })
                    offset = idx + 2
        finally:
            self.kernel32.CloseHandle(handle)

        return {'success': True, 'count': len(findings), 'pe_headers': findings}

    def export_pe(self, pid, address_hex, output_dir=None):
        """Export a PE image from memory to .bin file."""
        if output_dir is None:
            output_dir = self.dump_dir
        # F1-c: サブフォルダ形式
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_subdir = os.path.join(output_dir, f"{ts}_pe_export")
        os.makedirs(dump_subdir, exist_ok=True)


        address = int(address_hex, 16)
        handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not handle:
            return {'success': False, 'error': 'OpenProcess failed.'}

        try:
            data = self._read_region(handle, address, 0x200000)
            if not data or len(data) < 64:
                return {'success': False, 'error': 'Cannot read memory at address.'}
            pe_size = self._estimate_pe_size(data, 0)
            pe_data = data[:pe_size]
            filename = f"pe_dump_{address_hex}.bin"
            filepath = os.path.join(dump_subdir, filename)
            with open(filepath, 'wb') as f:

                f.write(pe_data)

            return {
                'success': True,
                'filepath': filepath,
                'filename': filename,
                'size_kb': round(len(pe_data) / 1024, 1),
            }
        finally:
            self.kernel32.CloseHandle(handle)

    def _estimate_pe_size(self, data, offset):
        """Estimate PE file size from headers."""
        try:
            pe_off = struct.unpack_from('<I', data, offset + 0x3C)[0]
            size_of_image = struct.unpack_from('<I', data, offset + pe_off + 0x50)[0]
            return min(size_of_image, 0x2000000)
        except Exception:
            return 0x10000

    # ==========================================
    # 7. Hex viewer
    # ==========================================
    def read_hex(self, pid, address_hex, size=256):
        """Read memory region and return hex + ASCII view."""
        address = int(address_hex, 16)
        size = min(size, 4096)
        handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not handle:
            return {'success': False, 'error': 'OpenProcess failed.'}

        try:
            data = self._read_region(handle, address, size)
            if not data:
                return {'success': False, 'error': 'Cannot read memory.'}

            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02X}' for b in chunk)
                ascii_part = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk)
                lines.append({
                    'address': f'{address + i:016X}',
                    'hex': hex_part,
                    'ascii': ascii_part,
                })
            return {'success': True, 'address': address_hex, 'size': len(data), 'lines': lines}
        finally:
            self.kernel32.CloseHandle(handle)

    # ==========================================
    # Shared helpers
    # ==========================================
    def _enum_regions(self, handle):
        """Enumerate virtual memory regions."""
        regions = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        while self.kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(addr),
            ctypes.byref(mbi), ctypes.sizeof(mbi)
        ):
            regions.append({
                'base': mbi.BaseAddress or 0,
                'size': mbi.RegionSize,
                'state': mbi.State,
                'protect': mbi.Protect,
                'type': mbi.Type,
            })
            addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            if addr >= 0x7FFFFFFFFFFF:
                break
        return regions

    def _read_region(self, handle, base, size):
        """Read memory from a process."""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        result = self.kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(base),
            buf, size, ctypes.byref(bytes_read)
        )
        if result:
            return buf.raw[:bytes_read.value]
        return None

    def _format_size(self, size):
        """Format byte size to human readable."""
        if size >= 1048576:
            return f"{size / 1048576:.1f} MB"
        elif size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"

    # ==========================================
    # 10. System memory info
    # ==========================================
    def get_system_memory_info(self):
        """Get physical memory information."""
        try:
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            total = stat.ullTotalPhys
            avail = stat.ullAvailPhys
            used = total - avail
            # Check output dir free space
            import shutil
            output_dir = self.dump_dir
            disk = shutil.disk_usage(os.path.splitdrive(output_dir)[0] or output_dir)
            return {
                "total_bytes": total,
                "total": self._format_size(total),
                "used_bytes": used,
                "used": self._format_size(used),
                "used_percent": round(used / total * 100, 1) if total else 0,
                "available_bytes": avail,
                "available": self._format_size(avail),
                "available_percent": round(avail / total * 100, 1) if total else 0,
                "estimated_dump_size": self._format_size(total),
                "output_dir": output_dir,
                "output_dir_free_bytes": disk.free,
                "output_dir_free": self._format_size(disk.free),
                "can_dump": disk.free > total
            }
        except Exception as e:
            return {"error": str(e)}

    # ==========================================
    # 11. Dump all processes
    # ==========================================
    def dump_all_processes(self, output_dir=None):
        """Dump all accessible processes."""
        out = output_dir or self.dump_dir
        os.makedirs(out, exist_ok=True)
        procs = self.list_processes()
        results = []
        success = 0
        failed = 0
        for p in procs:
            pid = p.get("pid", 0)
            name = p.get("name", "unknown")
            if pid <= 4:
                continue
            try:
                r = self.dump_process(pid, out)
                if r.get("success"):
                    success += 1
                    results.append({"pid": pid, "name": name, "status": "OK", "path": r.get("path", ""), "size": r.get("size", "")})
                else:
                    failed += 1
                    results.append({"pid": pid, "name": name, "status": "FAIL", "error": r.get("error", "unknown")})
            except Exception as e:
                failed += 1
                results.append({"pid": pid, "name": name, "status": "FAIL", "error": str(e)})
        return {"success_count": success, "failed_count": failed, "total": success + failed, "output_dir": out, "results": results}

    # ==========================================
    # 12. Process selective dump (by region type)
    # ==========================================
    def dump_process_selective(self, pid, output_dir=None, include_heap=True, include_stack=True, include_executable=True, include_mapped=False, include_all=False):
        """Dump selected memory region types of a process."""
        out = output_dir or self.dump_dir
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        try:
            import psutil
            proc = psutil.Process(pid)
            pname = proc.name().replace('.exe', '')
        except Exception:
            pname = 'unknown'
        # F1-c: サブフォルダ形式
        dump_subdir = os.path.join(out, f"{ts}_{pname}_selective")
        os.makedirs(dump_subdir, exist_ok=True)

        PROCESS_ALL_ACCESS = 0x1F0FFF
        handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle:
            return {"error": f"Cannot open process {pid}"}
        try:
            regions = self._enum_regions(handle)
            results = []
            total_size = 0
            for r in regions:
                base = r["base"]
                size = r["size"]
                state = r.get("state", 0)
                protect = r.get("protect", 0)
                mtype = r.get("type", 0)
                # Skip non-committed regions
                MEM_COMMIT = 0x1000
                if state != MEM_COMMIT:
                    continue
                # Decode protect flags
                PAGE_EXECUTE = 0x10
                PAGE_EXECUTE_READ = 0x20
                PAGE_EXECUTE_READWRITE = 0x40
                PAGE_EXECUTE_WRITECOPY = 0x80
                PAGE_READWRITE = 0x04
                PAGE_WRITECOPY = 0x08
                is_exec = protect in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
                is_rw = protect in (PAGE_READWRITE, PAGE_WRITECOPY) and not is_exec
                # Decode type
                MEM_PRIVATE = 0x20000
                MEM_MAPPED = 0x40000
                MEM_IMAGE = 0x1000000
                is_mapped = mtype in (MEM_MAPPED, MEM_IMAGE)
                is_private = mtype == MEM_PRIVATE
                # Build protection string for display
                prot_map = {0x02:"R", 0x04:"RW", 0x08:"WC", 0x10:"X", 0x20:"RX", 0x40:"RWX", 0x80:"XWC"}
                prot = prot_map.get(protect, f"0x{protect:X}")

                # Determine region category
                category = "other"
                if is_exec:
                    category = "executable"
                elif is_private and is_rw:
                    category = "heap"
                elif is_mapped:
                    category = "mapped"
                # Simple stack heuristic: private RW near thread stack range
                if is_private and is_rw and size <= 1048576 * 4:
                    if any(keyword in r.get("info", "") for keyword in ["Stack", "stack", "Thread"]):
                        category = "stack"
                should_dump = include_all
                if not should_dump:
                    if category == "heap" and include_heap:
                        should_dump = True
                    elif category == "stack" and include_stack:
                        should_dump = True
                    elif category == "executable" and include_executable:
                        should_dump = True
                    elif category == "mapped" and include_mapped:
                        should_dump = True
                if not should_dump:
                    continue
                data = self._read_region(handle, base, size)
                if data and len(data) > 0:
                    fname = f"{category}_0x{base:016X}_{size}.bin"
                    fpath = os.path.join(dump_subdir, fname)
                    with open(fpath, "wb") as f:
                        f.write(data)
                    total_size += len(data)
                    results.append({
                        "category": category,
                        "address": f"0x{base:016X}",
                        "size": self._format_size(size),
                        "size_bytes": size,
                        "protection": prot,
                        "filename": os.path.basename(fpath)
                    })
            return {
                "pid": pid,
                "region_count": len(results),
                "total_size": self._format_size(total_size),
                "output_dir": dump_subdir,
                "regions": results
            }
        finally:
            self.kernel32.CloseHandle(handle)

    # ==========================================
    # 13. Full physical memory dump (via MiniDumpWriteDump of all processes)
    # ==========================================
    def dump_full_memory(self, output_dir=None):
        """Create a combined dump of all process memory (best-effort physical memory approximation)."""
        import time
        out = output_dir or self.dump_dir
        os.makedirs(out, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        dump_subdir = os.path.join(out, f"full_memdump_{timestamp}")
        os.makedirs(dump_subdir, exist_ok=True)
        procs = self.list_processes()
        results = []
        total_size = 0
        success = 0
        failed = 0
        skipped = 0
        for p in procs:
            pid = p.get("pid", 0)
            name = p.get("name", "unknown")
            if pid <= 4:
                skipped += 1
                continue
            try:
                r = self.dump_process(pid, dump_subdir)
                if r.get("success"):
                    fsize = os.path.getsize(r["path"]) if os.path.exists(r.get("path", "")) else 0
                    total_size += fsize
                    success += 1
                    results.append({"pid": pid, "name": name, "status": "OK", "size": self._format_size(fsize)})
                else:
                    failed += 1
                    results.append({"pid": pid, "name": name, "status": "FAIL", "error": r.get("error", "")})
            except Exception as e:
                failed += 1
                results.append({"pid": pid, "name": name, "status": "FAIL", "error": str(e)})
        return {
            "output_dir": dump_subdir,
            "total_size": self._format_size(total_size),
            "total_size_bytes": total_size,
            "success_count": success,
            "failed_count": failed,
            "skipped_count": skipped,
            "process_count": len(procs),
            "results": results
        }

    # ==========================================
    # 14. Dump file analysis
    # ==========================================
    def analyze_dump_file(self, filepath, analysis_type="strings", min_len=4, max_results=5000, hex_offset=0, hex_size=1024):
        """Analyze a dump file offline."""
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}"}
        fsize = os.path.getsize(filepath)
        base_info = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "size": self._format_size(fsize),
            "size_bytes": fsize
        }
        if analysis_type == "strings":
            return self._analyze_dump_strings(filepath, fsize, base_info, min_len, max_results)
        elif analysis_type == "pe":
            return self._analyze_dump_pe(filepath, fsize, base_info)
        elif analysis_type == "hex":
            return self._analyze_dump_hex(filepath, fsize, base_info, hex_offset, hex_size)
        elif analysis_type == "ioc":
            return self._analyze_dump_ioc(filepath, fsize, base_info, max_results)
        elif analysis_type == "yara":
            return self._analyze_dump_yara(filepath, base_info)
        else:
            return {"error": f"Unknown analysis type: {analysis_type}"}

    def _analyze_dump_strings(self, filepath, fsize, base_info, min_len, max_results):
        """Extract strings from dump file."""
        strings = []
        chunk_size = 10 * 1024 * 1024  # 10MB chunks
        try:
            with open(filepath, "rb") as f:
                offset = 0
                while offset < fsize and len(strings) < max_results:
                    f.seek(offset)
                    data = f.read(chunk_size)
                    if not data:
                        break
                    # ASCII strings
                    current = []
                    for i, b in enumerate(data):
                        if 32 <= b < 127:
                            current.append(chr(b))
                        else:
                            if len(current) >= min_len:
                                s = "".join(current)
                                strings.append({"offset": f"0x{offset + i - len(current):X}", "type": "ASCII", "value": s[:200]})
                                if len(strings) >= max_results:
                                    break
                            current = []
                    if current and len(current) >= min_len and len(strings) < max_results:
                        strings.append({"offset": f"0x{offset + len(data) - len(current):X}", "type": "ASCII", "value": "".join(current)[:200]})
                    # Unicode strings (UTF-16LE)
                    if len(strings) < max_results:
                        i = 0
                        ucurrent = []
                        while i < len(data) - 1:
                            c = data[i] | (data[i+1] << 8)
                            if 32 <= c < 127:
                                ucurrent.append(chr(c))
                            else:
                                if len(ucurrent) >= min_len:
                                    s = "".join(ucurrent)
                                    strings.append({"offset": f"0x{offset + i - len(ucurrent)*2:X}", "type": "Unicode", "value": s[:200]})
                                    if len(strings) >= max_results:
                                        break
                                ucurrent = []
                            i += 2
                    offset += chunk_size
            base_info["strings"] = strings[:max_results]
            base_info["total_found"] = len(strings)
            return base_info
        except Exception as e:
            base_info["error"] = str(e)
            return base_info

    def _analyze_dump_pe(self, filepath, fsize, base_info):
        """Scan for PE headers in dump file."""
        pe_headers = []
        chunk_size = 10 * 1024 * 1024
        try:
            with open(filepath, "rb") as f:
                offset = 0
                while offset < fsize:
                    f.seek(offset)
                    data = f.read(chunk_size + 4096)  # overlap for boundary
                    if not data:
                        break
                    pos = 0
                    while pos < len(data) - 64:
                        idx = data.find(b"MZ", pos)
                        if idx == -1:
                            break
                        # Verify PE signature
                        if idx + 64 <= len(data):
                            try:
                                pe_offset_bytes = data[idx+60:idx+64]
                                pe_offset = int.from_bytes(pe_offset_bytes, "little")
                                if 0 < pe_offset < 1024 and idx + pe_offset + 4 <= len(data):
                                    sig = data[idx+pe_offset:idx+pe_offset+4]
                                    if sig == b"PE\x00\x00":
                                        est_size = self._estimate_pe_size(data, idx) if idx + 512 <= len(data) else 0
                                        pe_headers.append({
                                            "offset": f"0x{offset + idx:X}",
                                            "offset_int": offset + idx,
                                            "pe_offset": pe_offset,
                                            "estimated_size": self._format_size(est_size) if est_size else "unknown"
                                        })
                            except Exception:
                                pass
                        pos = idx + 2
                    offset += chunk_size
            base_info["pe_headers"] = pe_headers
            base_info["pe_count"] = len(pe_headers)
            return base_info
        except Exception as e:
            base_info["error"] = str(e)
            return base_info

    def _analyze_dump_hex(self, filepath, fsize, base_info, hex_offset, hex_size):
        """Read hex from dump file at given offset."""
        try:
            hex_size = min(hex_size, 65536)
            with open(filepath, "rb") as f:
                f.seek(hex_offset)
                data = f.read(hex_size)
            lines = []
            for i in range(0, len(data), 16):
                row = data[i:i+16]
                addr = f"0x{hex_offset + i:08X}"
                hex_str = " ".join(f"{b:02X}" for b in row)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
                lines.append({"address": addr, "hex": hex_str, "ascii": ascii_str})
            base_info["hex_lines"] = lines
            base_info["hex_offset"] = hex_offset
            base_info["hex_size"] = len(data)
            base_info["file_size"] = fsize
            return base_info
        except Exception as e:
            base_info["error"] = str(e)
            return base_info

    def _analyze_dump_ioc(self, filepath, fsize, base_info, max_results):
        """Extract IOCs (URLs, IPs, emails, registry keys, domains) from dump file."""
        import re
        patterns = {
            "URL": re.compile(rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,500}', re.IGNORECASE),
            "IPv4": re.compile(rb'(?:^|[^\d])((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(?:[^\d]|$)'),
            "Email": re.compile(rb'[a-zA-Z0-9._%+\-]{2,40}@[a-zA-Z0-9.\-]{2,40}\.[a-zA-Z]{2,10}'),
            "Registry": re.compile(rb'(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[a-zA-Z0-9\\_ \-]{5,200}', re.IGNORECASE),
            "Domain": re.compile(rb'(?:[a-zA-Z0-9\-]{2,63}\.){1,5}(?:com|net|org|info|biz|ru|cn|tk|xyz|top|pw|cc|io|me|co)(?:[^a-zA-Z]|$)', re.IGNORECASE),
        }
        iocs = {k: {} for k in patterns}
        chunk_size = 10 * 1024 * 1024
        try:
            with open(filepath, "rb") as f:
                offset = 0
                while offset < fsize:
                    f.seek(offset)
                    data = f.read(chunk_size + 1024)
                    if not data:
                        break
                    for cat, pat in patterns.items():
                        for m in pat.finditer(data):
                            val = m.group(0) if cat != "IPv4" else m.group(1)
                            try:
                                val_str = val.decode("utf-8", errors="ignore").strip()
                            except Exception:
                                continue
                            if len(val_str) < 4:
                                continue
                            # Skip common false positives
                            if cat == "IPv4" and (val_str.startswith("0.") or val_str.startswith("255.") or val_str == "127.0.0.1"):
                                continue
                            if val_str in iocs[cat]:
                                iocs[cat][val_str] += 1
                            else:
                                iocs[cat][val_str] = 1
                    offset += chunk_size
            result_list = []
            for cat in patterns:
                sorted_items = sorted(iocs[cat].items(), key=lambda x: -x[1])[:max_results]
                for val, count in sorted_items:
                    result_list.append({"category": cat, "value": val, "count": count})
            base_info["iocs"] = result_list
            base_info["ioc_summary"] = {cat: len(iocs[cat]) for cat in patterns}
            return base_info
        except Exception as e:
            base_info["error"] = str(e)
            return base_info

    def _analyze_dump_yara(self, filepath, base_info):
        """Scan dump file with YARA rules."""
        try:
            from utils.yara_manager import YaraManager
            ym = YaraManager()
            result = ym.scan_file(filepath, timeout=120)
            base_info["yara_matches"] = result.get("matches", [])
            base_info["yara_match_count"] = len(result.get("matches", []))
            base_info["yara_error"] = result.get("error", None)
            return base_info
        except ImportError:
            base_info["yara_error"] = "yara-python is not installed"
            base_info["yara_matches"] = []
            return base_info
        except Exception as e:
            base_info["yara_error"] = str(e)
            base_info["yara_matches"] = []
            return base_info

    # ==========================================
    # 15. List dump files
    # ==========================================
    def list_dump_files(self, directory=None):
        """List dump files in the specified directory."""
        target = directory or self.dump_dir
        if not os.path.exists(target):
            return {"files": [], "directory": target}
        files = []
        try:
            for entry in os.scandir(target):
                if entry.is_file() and entry.name.endswith((".dmp", ".bin", ".raw", ".mem")):
                    stat = entry.stat()
                    files.append({
                        "filename": entry.name,
                        "filepath": entry.path,
                        "size": self._format_size(stat.st_size),
                        "size_bytes": stat.st_size,
                        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
                    })
                elif entry.is_dir():
                    # Check subdirectories (full_memdump_xxx)
                    subfiles = []
                    sub_total = 0
                    for sub in os.scandir(entry.path):
                        if sub.is_file() and sub.name.endswith((".dmp", ".bin", ".raw", ".mem")):
                            sub_total += sub.stat().st_size
                            subfiles.append(sub.name)
                    if subfiles:
                        files.append({
                            "filename": entry.name + "/",
                            "filepath": entry.path,
                            "size": self._format_size(sub_total),
                            "size_bytes": sub_total,
                            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.stat().st_mtime)),
                            "is_dir": True,
                            "file_count": len(subfiles)
                        })
            files.sort(key=lambda x: x.get("mtime", ""), reverse=True)
        except Exception as e:
            return {"files": [], "directory": target, "error": str(e)}
        return {"files": files, "directory": target}

    # ==========================================
    # 16. Get/set output directory
    # ==========================================
    def get_output_dir(self):
        """Return current output directory."""
        return self.dump_dir

    def set_output_dir(self, new_dir):
        """Set output directory."""
        os.makedirs(new_dir, exist_ok=True)
        self.dump_dir = new_dir
        return {"output_dir": self.dump_dir}
