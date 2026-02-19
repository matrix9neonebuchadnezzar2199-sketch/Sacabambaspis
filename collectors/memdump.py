# -*- coding: utf-8 -*-
"""P26: Memory Dump & Analysis Module"""
import os
import sys
import ctypes
import ctypes.wintypes
import struct
import tempfile
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
        self.dump_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "dumps"
        )
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

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Get process name
        try:
            import psutil
            proc = psutil.Process(pid)
            pname = proc.name().replace('.exe', '')
        except Exception:
            pname = 'unknown'

        filename = f"{pname}_{pid}_{ts}.dmp"
        filepath = os.path.join(output_dir, filename)

        handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle:
            return {'success': False, 'error': f'OpenProcess failed (PID={pid}). Admin rights required.'}

        try:
            with open(filepath, 'wb') as f:
                fd = ctypes.c_uint(f.fileno())
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
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

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

            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"pe_dump_{address_hex}_{ts}.bin"
            filepath = os.path.join(output_dir, filename)
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
