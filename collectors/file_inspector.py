# -*- coding: utf-8 -*-
"""P27: File Inspector Module - Folder listing and file analysis."""
import os
import sys
import math
import hashlib
import struct
from datetime import datetime

# Magic bytes for file type detection
MAGIC_SIGNATURES = {
    b'\xd0\xcf\x11\xe0': 'OLE',
    b'PK\x03\x04': 'ZIP/OOXML',
    b'%PDF': 'PDF',
    b'\xff\xd8\xff': 'JPEG',
    b'\x89PNG': 'PNG',
    b'GIF87a': 'GIF',
    b'GIF89a': 'GIF',
    b'BM': 'BMP',
    b'MZ': 'PE',
    b'\x7fELF': 'ELF',
    b'Rar!': 'RAR',
    b'\x1f\x8b': 'GZIP',
    b'7z\xbc\xaf': '7Z',
}

# File category mapping
CATEGORY_MAP = {
    'OLE': {'icon': '\U0001f4c4', 'label': 'OLE\u6587\u66f8'},
    'ZIP/OOXML': {'icon': '\U0001f4c4', 'label': 'OOXML/ZIP'},
    'PDF': {'icon': '\U0001f4d5', 'label': 'PDF'},
    'JPEG': {'icon': '\U0001f5bc\ufe0f', 'label': '\u753b\u50cf'},
    'PNG': {'icon': '\U0001f5bc\ufe0f', 'label': '\u753b\u50cf'},
    'GIF': {'icon': '\U0001f5bc\ufe0f', 'label': '\u753b\u50cf'},
    'BMP': {'icon': '\U0001f5bc\ufe0f', 'label': '\u753b\u50cf'},
    'PE': {'icon': '\u2699\ufe0f', 'label': '\u5b9f\u884c'},
    'RAR': {'icon': '\U0001f4e6', 'label': '\u5727\u7e2e'},
    'GZIP': {'icon': '\U0001f4e6', 'label': '\u5727\u7e2e'},
    '7Z': {'icon': '\U0001f4e6', 'label': '\u5727\u7e2e'},
    'ELF': {'icon': '\u2699\ufe0f', 'label': '\u5b9f\u884c'},
}

# Extension to expected type
EXT_TYPE_MAP = {
    '.doc': 'OLE', '.xls': 'OLE', '.ppt': 'OLE',
    '.docx': 'ZIP/OOXML', '.xlsx': 'ZIP/OOXML', '.pptx': 'ZIP/OOXML',
    '.pdf': 'PDF',
    '.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG', '.gif': 'GIF', '.bmp': 'BMP',
    '.svg': 'SVG',
    '.exe': 'PE', '.dll': 'PE', '.sys': 'PE', '.scr': 'PE',
    '.zip': 'ZIP/OOXML', '.rar': 'RAR', '.7z': '7Z', '.gz': 'GZIP',
    '.js': 'SCRIPT', '.vbs': 'SCRIPT', '.ps1': 'SCRIPT', '.bat': 'SCRIPT',
    '.cmd': 'SCRIPT', '.wsf': 'SCRIPT', '.hta': 'SCRIPT',
    '.html': 'HTML', '.htm': 'HTML', '.mht': 'HTML',
    '.txt': 'TEXT', '.csv': 'TEXT', '.log': 'TEXT', '.xml': 'TEXT', '.json': 'TEXT',
}

SCRIPT_EXTENSIONS = {'.js', '.vbs', '.ps1', '.bat', '.cmd', '.wsf', '.hta', '.py', '.rb', '.sh'}
HTML_EXTENSIONS = {'.html', '.htm', '.mht', '.mhtml'}
TEXT_EXTENSIONS = {'.txt', '.csv', '.log', '.xml', '.json', '.ini', '.cfg', '.yaml', '.yml', '.md'}
SVG_EXTENSIONS = {'.svg'}


class FileInspector:
    """Folder listing and file metadata analysis."""

    def __init__(self):
        pass

    def list_folder(self, folder_path, include_subfolders=False):
        """List all files in a folder with metadata."""
        if not os.path.exists(folder_path):
            return {'success': False, 'error': 'Folder not found: ' + folder_path}
        if not os.path.isdir(folder_path):
            return {'success': False, 'error': 'Not a folder: ' + folder_path}

        files = []
        folder_count = 0
        total_size = 0
        idx = 0

        try:
            if include_subfolders:
                for root, dirs, filenames in os.walk(folder_path):
                    folder_count += len(dirs)
                    for fname in filenames:
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, folder_path)
                        entry = self._build_file_entry(idx, fpath, rel_path)
                        if entry:
                            files.append(entry)
                            total_size += entry['size_bytes']
                            idx += 1
            else:
                for fname in os.listdir(folder_path):
                    fpath = os.path.join(folder_path, fname)
                    if os.path.isdir(fpath):
                        folder_count += 1
                        continue
                    entry = self._build_file_entry(idx, fpath, fname)
                    if entry:
                        files.append(entry)
                        total_size += entry['size_bytes']
                        idx += 1
        except PermissionError as e:
            return {'success': False, 'error': 'Permission denied: ' + str(e)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

        return {
            'success': True,
            'folder': folder_path,
            'file_count': len(files),
            'folder_count': folder_count,
            'total_size': self._format_size(total_size),
            'total_size_bytes': total_size,
            'files': files,
        }

    def _build_file_entry(self, idx, filepath, display_name):
        """Build metadata entry for a single file."""
        try:
            stat = os.stat(filepath)
        except (PermissionError, OSError):
            return None

        size = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')

        ext = os.path.splitext(filepath)[1].lower()
        magic_type = self._detect_magic(filepath)
        expected_type = EXT_TYPE_MAP.get(ext, 'UNKNOWN')

        # Determine display type
        if magic_type:
            display_type = magic_type
        elif ext in SVG_EXTENSIONS:
            display_type = 'SVG'
        elif ext in SCRIPT_EXTENSIONS:
            display_type = 'SCRIPT'
        elif ext in HTML_EXTENSIONS:
            display_type = 'HTML'
        elif ext in TEXT_EXTENSIONS:
            display_type = 'TEXT'
        else:
            display_type = 'UNKNOWN'

        # Extension match check
        ext_match = True
        if magic_type and expected_type != 'UNKNOWN':
            if magic_type == 'ZIP/OOXML' and expected_type in ('ZIP/OOXML',):
                ext_match = True
            elif magic_type != expected_type:
                ext_match = False

        # Category info
        cat = CATEGORY_MAP.get(display_type, {'icon': '\u2753', 'label': display_type})

        # Entropy (quick, first 64KB)
        entropy = self._quick_entropy(filepath)

        return {
            'idx': idx,
            'filename': display_name,
            'filepath': filepath,
            'ext': ext,
            'size_bytes': size,
            'size': self._format_size(size),
            'mtime': mtime,
            'type': display_type,
            'type_icon': cat['icon'],
            'type_label': cat['label'],
            'entropy': round(entropy, 2),
            'ext_match': ext_match,
            'status': 'pending',
            'result': None,
        }

    def _detect_magic(self, filepath):
        """Detect file type from magic bytes."""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
        except (PermissionError, OSError):
            return None

        if len(header) < 2:
            return None

        for sig, ftype in MAGIC_SIGNATURES.items():
            if header[:len(sig)] == sig:
                return ftype
        return None

    def _quick_entropy(self, filepath, max_bytes=65536):
        """Calculate Shannon entropy on first N bytes."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(max_bytes)
        except (PermissionError, OSError):
            return 0.0

        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        length = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def get_file_hashes(self, filepath):
        """Calculate MD5 and SHA256 hashes."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha256.update(chunk)
            return {
                'md5': md5.hexdigest(),
                'sha256': sha256.hexdigest(),
            }
        except (PermissionError, OSError):
            return {'md5': 'N/A', 'sha256': 'N/A'}

    def _format_size(self, size):
        """Format byte size to human readable."""
        if size >= 1073741824:
            return f"{size / 1073741824:.1f} GB"
        elif size >= 1048576:
            return f"{size / 1048576:.1f} MB"
        elif size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"

    # ==========================================
    # P27-B: File Analysis Engine
    # ==========================================
    def analyze_file(self, filepath):
        """Analyze a file based on its type. Returns detailed result dict."""
        if not os.path.exists(filepath):
            return {'success': False, 'error': 'File not found'}

        ext = os.path.splitext(filepath)[1].lower()
        magic = self._detect_magic(filepath)
        hashes = self.get_file_hashes(filepath)
        entropy = self._quick_entropy(filepath)
        size = os.path.getsize(filepath)

        base_info = {
            'success': True,
            'filepath': filepath,
            'filename': os.path.basename(filepath),
            'size': self._format_size(size),
            'size_bytes': size,
            'ext': ext,
            'magic_type': magic or 'UNKNOWN',
            'entropy': round(entropy, 2),
            'hashes': hashes,
            'ext_match': True,
            'findings': [],
            'extracted_code': [],
            'status': 'SAFE',
            'reason': '',
            'mitre': [],
        }

        try:
            if magic == 'OLE':
                self._analyze_ole(filepath, base_info)
            elif magic == 'ZIP/OOXML' and ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm'):
                self._analyze_ooxml(filepath, base_info)
            elif magic == 'ZIP/OOXML' and ext in ('.zip',):
                self._analyze_zip(filepath, base_info)
            elif magic == 'PDF' or ext == '.pdf':
                self._analyze_pdf(filepath, base_info)
            elif magic in ('JPEG', 'PNG', 'GIF', 'BMP') or ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp'):
                self._analyze_image(filepath, base_info)
            elif ext == '.svg':
                self._analyze_svg(filepath, base_info)
            elif magic == 'PE' or ext in ('.exe', '.dll', '.sys', '.scr'):
                self._analyze_pe(filepath, base_info)
            elif ext in ('.js', '.vbs', '.ps1', '.bat', '.cmd', '.wsf', '.hta'):
                self._analyze_script(filepath, base_info)
            elif ext in ('.html', '.htm', '.mht', '.mhtml'):
                self._analyze_html(filepath, base_info)
            else:
                self._analyze_generic(filepath, base_info)
        except Exception as e:
            base_info['findings'].append({'type': 'ERROR', 'detail': f'Analysis error: {str(e)}'})

        # Check extension mismatch
        expected = EXT_TYPE_MAP.get(ext, 'UNKNOWN')
        if magic and expected != 'UNKNOWN' and magic != expected:
            if not (magic == 'ZIP/OOXML' and expected == 'ZIP/OOXML'):
                base_info['ext_match'] = False
                base_info['findings'].append({
                    'type': 'WARNING',
                    'detail': f'Extension mismatch: ext={ext} but magic={magic}',
                })
                if base_info['status'] == 'SAFE':
                    base_info['status'] = 'WARNING'
                    base_info['reason'] = 'Extension mismatch'

        # High entropy check
        if entropy >= 7.5 and base_info['status'] == 'SAFE':
            base_info['status'] = 'WARNING'
            base_info['reason'] = 'High entropy (possible packing/encryption)'
            base_info['findings'].append({'type': 'WARNING', 'detail': f'High entropy: {entropy:.2f}'})

        return base_info

    # --- OLE Analysis (.doc, .xls, .ppt) ---
    def _analyze_ole(self, filepath, info):
        """Analyze OLE compound files for VBA macros."""
        try:
            import olefile
        except ImportError:
            info['findings'].append({'type': 'INFO', 'detail': 'olefile not installed - OLE analysis skipped'})
            return

        try:
            ole = olefile.OleFileIO(filepath)
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'OLE parse error: {e}'})
            return

        # List streams
        streams = ole.listdir()
        stream_names = ['/'.join(s) for s in streams]
        info['findings'].append({
            'type': 'INFO',
            'detail': f'OLE streams: {len(stream_names)}',
            'streams': stream_names[:50],
        })

        # Check for VBA macros
        vba_streams = [s for s in stream_names if 'vba' in s.lower() or 'macro' in s.lower()]
        has_macros = len(vba_streams) > 0

        if has_macros:
            info['findings'].append({
                'type': 'WARNING',
                'detail': f'VBAマクロストリーム検出: {len(vba_streams)}件',
                'vba_streams': vba_streams,
            })

            # Extract and analyze VBA code
            for vs in vba_streams:
                try:
                    parts = vs.split('/')
                    stream_data = ole.openstream(parts).read()
                    code_text = self._extract_vba_text(stream_data)
                    if code_text:
                        dangers = self._check_vba_dangers(code_text)
                        info['extracted_code'].append({
                            'module': vs,
                            'code': code_text[:10000],
                            'dangers': dangers,
                        })
                        if dangers:
                            info['status'] = 'DANGER'
                            info['reason'] = '悪意あるVBAマクロを検出'
                            info['mitre'].extend(['T1059.005', 'T1204.002'])
                            for d in dangers:
                                info['findings'].append({'type': 'DANGER', 'detail': d})
                except Exception:
                    pass

            if has_macros and info['status'] == 'SAFE':
                info['status'] = 'WARNING'
                info['reason'] = 'VBAマクロが含まれています'
                info['mitre'].append('T1059.005')

        ole.close()

    def _extract_vba_text(self, data):
        """Extract readable text from VBA stream data."""
        # Try to find readable strings
        result = []
        current = []
        for b in data:
            if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09):
                current.append(chr(b))
            else:
                if len(current) >= 4:
                    result.append(''.join(current))
                current = []
        if len(current) >= 4:
            result.append(''.join(current))
        text = '\n'.join(result)
        # Filter for VBA-like content
        vba_keywords = ['Sub ', 'Function ', 'Dim ', 'Set ', 'End Sub', 'End Function',
                        'Private ', 'Public ', 'Shell', 'CreateObject', 'WScript']
        if any(kw in text for kw in vba_keywords):
            return text
        return text if len(text) > 20 else ''

    def _check_vba_dangers(self, code):
        """Check VBA code for dangerous patterns."""
        dangers = []
        code_lower = code.lower()

        checks = [
            ('AutoOpen', 'Auto-execute trigger: AutoOpen'),
            ('Document_Open', 'Auto-execute trigger: Document_Open'),
            ('Workbook_Open', 'Auto-execute trigger: Workbook_Open'),
            ('Auto_Open', 'Auto-execute trigger: Auto_Open'),
            ('Shell', 'Shell command execution'),
            ('WScript.Shell', 'WScript.Shell object creation'),
            ('CreateObject', 'COM object creation (CreateObject)'),
            ('PowerShell', 'PowerShell invocation'),
            ('cmd /c', 'Command prompt execution'),
            ('cmd.exe', 'Command prompt execution'),
            ('Environ', 'Environment variable access'),
            ('XMLHTTP', 'HTTP request (possible download)'),
            ('ADODB.Stream', 'Binary stream manipulation'),
            ('SaveToFile', 'File write operation'),
            ('base64', 'Base64 encoding/decoding'),
            ('-enc', 'Encoded command parameter'),
            ('DownloadFile', 'File download'),
            ('Invoke-Expression', 'PowerShell Invoke-Expression'),
            ('IEX', 'PowerShell IEX (Invoke-Expression)'),
            ('Net.WebClient', '.NET WebClient'),
            ('FromBase64String', 'Base64 decode'),
            ('vbHide', 'Hidden window execution'),
        ]

        for pattern, desc in checks:
            if pattern.lower() in code_lower:
                dangers.append(desc)

        return dangers

    # --- OOXML Analysis (.docx, .xlsx, .pptx) ---
    def _analyze_ooxml(self, filepath, info):
        """Analyze OOXML (Office Open XML) files."""
        import zipfile

        try:
            zf = zipfile.ZipFile(filepath, 'r')
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'ZIP parse error: {e}'})
            return

        entries = zf.namelist()
        info['findings'].append({
            'type': 'INFO',
            'detail': f'OOXML entries: {len(entries)}',
            'entries': entries[:50],
        })

        # Check for vbaProject.bin
        vba_files = [e for e in entries if 'vbaproject' in e.lower()]
        if vba_files:
            info['findings'].append({
                'type': 'WARNING',
                'detail': f'VBAプロジェクト検出: {", ".join(vba_files)} - マクロ埋め込みOOXMLファイルです',
            })
            info['status'] = 'WARNING'
            info['reason'] = 'OOXML内にVBAマクロを検出'
            info['mitre'].append('T1059.005')

            for vf in vba_files:
                try:
                    data = zf.read(vf)
                    code_text = self._extract_vba_text(data)
                    if code_text:
                        dangers = self._check_vba_dangers(code_text)
                        info['extracted_code'].append({
                            'module': vf,
                            'code': code_text[:10000],
                            'dangers': dangers,
                        })
                        if dangers:
                            info['status'] = 'DANGER'
                            info['reason'] = 'OOXML内に悪意あるVBAマクロを検出'
                            info['mitre'].append('T1204.002')
                            for d in dangers:
                                info['findings'].append({'type': 'DANGER', 'detail': d})
                except Exception:
                    pass

        # Check for ActiveX
        activex = [e for e in entries if 'activex' in e.lower()]
        if activex:
            info['findings'].append({'type': 'WARNING', 'detail': f'ActiveX controls: {len(activex)}'})
            if info['status'] == 'SAFE':
                info['status'] = 'WARNING'
                info['reason'] = 'ActiveX controls detected'

        # Check for external references (template injection)
        for entry in entries:
            if entry.endswith('.rels'):
                try:
                    rels_data = zf.read(entry).decode('utf-8', errors='ignore')
                    if 'http://' in rels_data or 'https://' in rels_data:
                        import re
                        urls = re.findall(r'Target="(https?://[^"]+)"', rels_data)
                        if urls:
                            info['status'] = 'DANGER'
                            info['reason'] = f'外部テンプレートインジェクション検出（{len(urls)}件）'
                            if 'T1221' not in info.get('mitre', []):
                                info['mitre'].append('T1221')
                            for url in urls:
                                info['findings'].append({
                                    'type': 'DANGER',
                                    'detail': f'外部参照（テンプレートインジェクション）: {self._defang_url(url)}',
                                })
                except Exception:
                    pass

        zf.close()

    # --- PDF Analysis ---
    def _analyze_pdf(self, filepath, info):
        """Analyze PDF files for dangerous elements."""
        try:
            with open(filepath, 'rb') as f:
                raw = f.read(min(os.path.getsize(filepath), 5242880))  # max 5MB
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'PDF読み取りエラー: {e}'})
            return

        raw_str = raw.decode('latin-1', errors='ignore')

        # PDF version
        import re
        ver_match = re.search(r'%PDF-(\d+\.\d+)', raw_str[:100])
        if ver_match:
            info['findings'].append({'type': 'INFO', 'detail': f'PDF version: {ver_match.group(1)}'})

        # Dangerous keywords
        pdf_checks = [
            ('/JavaScript', 'DANGER', 'JavaScript code in PDF', 'T1059.007'),
            ('/JS', 'WARNING', 'JS reference in PDF', 'T1059.007'),
            ('/OpenAction', 'WARNING', 'Auto-execute on open (OpenAction)', 'T1204.002'),
            ('/AA', 'WARNING', 'Additional Actions (AA) trigger', 'T1204.002'),
            ('/Launch', 'DANGER', 'Launch action (execute external program)', 'T1204.002'),
            ('/EmbeddedFile', 'WARNING', 'Embedded file detected', 'T1027.001'),
            ('/AcroForm', 'INFO', 'AcroForm (interactive form)'),
            ('/XFA', 'WARNING', 'XFA form (potential exploit vector)'),
            ('/RichMedia', 'WARNING', 'Rich media content (Flash/video)'),
            ('/ObjStm', 'INFO', 'Object streams present'),
        ]

        for check in pdf_checks:
            keyword = check[0]
            level = check[1]
            desc = check[2]
            mitre = check[3] if len(check) > 3 else None

            count = raw_str.count(keyword)
            if count > 0:
                info['findings'].append({
                    'type': level,
                    'detail': f'{desc} ({count} occurrences)',
                })
                if level == 'DANGER' and info['status'] != 'DANGER':
                    info['status'] = 'DANGER'
                    info['reason'] = desc
                elif level == 'WARNING' and info['status'] == 'SAFE':
                    info['status'] = 'WARNING'
                    info['reason'] = desc
                if mitre:
                    info['mitre'].append(mitre)

        # Extract JavaScript code
        js_pattern = re.compile(r'/JavaScript\s*<<.*?/JS\s*\((.*?)\)', re.DOTALL)
        js_matches = js_pattern.findall(raw_str)
        for js in js_matches[:5]:
            info['extracted_code'].append({
                'module': 'PDF JavaScript',
                'code': js[:5000],
                'dangers': self._check_js_dangers(js),
            })

        # Check for streams with suspicious content
        stream_pattern = re.compile(r'stream\r?\n(.*?)\r?\nendstream', re.DOTALL)
        for m in stream_pattern.finditer(raw_str[:2000000]):
            stream_data = m.group(1)[:10000]
            if 'eval' in stream_data or 'unescape' in stream_data or 'String.fromCharCode' in stream_data:
                info['findings'].append({
                    'type': 'DANGER',
                    'detail': 'Suspicious JavaScript in PDF stream',
                })
                info['extracted_code'].append({
                    'module': 'PDF Stream',
                    'code': stream_data[:5000],
                    'dangers': ['eval/unescape in PDF stream'],
                })
                info['status'] = 'DANGER'
                info['reason'] = 'Obfuscated JavaScript in PDF'
                break

    def _check_js_dangers(self, code):
        """Check JavaScript code for dangerous patterns."""
        dangers = []
        code_lower = code.lower()
        checks = [
            ('eval', 'eval() execution'),
            ('unescape', 'unescape() (possible obfuscation)'),
            ('String.fromCharCode', 'String.fromCharCode (obfuscation)'),
            ('document.write', 'document.write (DOM manipulation)'),
            ('exportDataObject', 'exportDataObject (file extraction)'),
            ('nLaunch', 'nLaunch parameter (auto-launch)'),
            ('submitForm', 'submitForm (data exfiltration)'),
            ('this.getURL', 'getURL (URL access)'),
            ('app.launchURL', 'launchURL (URL launch)'),
            ('atob', 'atob (Base64 decode)'),
            ('ActiveXObject', 'ActiveX object creation'),
            ('XMLHttpRequest', 'HTTP request'),
            ('fetch(', 'Fetch API call'),
        ]
        for pattern, desc in checks:
            if pattern.lower() in code_lower:
                dangers.append(desc)
        return dangers

    # --- Image Analysis ---
    def _analyze_image(self, filepath, info):
        """Analyze image files for embedded code."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'Read error: {e}'})
            return

        data_str = data.decode('latin-1', errors='ignore')
        size = len(data)

        # Find image end marker
        end_offset = None
        if data[:2] == b'\xff\xd8':  # JPEG
            idx = data.rfind(b'\xff\xd9')
            if idx > 0:
                end_offset = idx + 2
        elif data[:4] == b'\x89PNG':
            idx = data.rfind(b'IEND')
            if idx > 0:
                end_offset = idx + 8

        # Trailer data check
        if end_offset and end_offset < size - 10:
            trailer_size = size - end_offset
            trailer = data[end_offset:]
            info['findings'].append({
                'type': 'WARNING',
                'detail': f'Trailing data after image end: {trailer_size} bytes',
            })
            # Check trailer for code
            trailer_str = trailer.decode('latin-1', errors='ignore')
            self._check_embedded_code(trailer_str, info, 'Trailer')

        # Check entire file for embedded code
        self._check_embedded_code(data_str, info, 'Image body')

        # EXIF check for suspicious content
        self._check_exif_dangers(data_str, info)

    def _check_embedded_code(self, text, info, location):
        """Check text for embedded malicious code."""
        checks = [
            ('<?php', 'PHP code', 'T1505.003'),
            ('eval(', 'eval() call', 'T1059'),
            ('base64_decode', 'PHP base64_decode', 'T1027'),
            ('system(', 'PHP system() call', 'T1059'),
            ('exec(', 'exec() call', 'T1059'),
            ('passthru(', 'PHP passthru()', 'T1059'),
            ('shell_exec', 'PHP shell_exec()', 'T1059'),
            ('<script', 'JavaScript tag', 'T1059.007'),
            ('document.cookie', 'Cookie access', 'T1539'),
            ('cmd.exe', 'Command prompt reference', 'T1059.003'),
            ('powershell', 'PowerShell reference', 'T1059.001'),
        ]

        for pattern, desc, mitre in checks:
            if pattern.lower() in text.lower():
                info['findings'].append({
                    'type': 'DANGER',
                    'detail': f'{desc} detected in {location}',
                })
                info['status'] = 'DANGER'
                info['reason'] = f'{desc} embedded in image'
                info['mitre'].append(mitre)

                # Extract surrounding code
                idx = text.lower().find(pattern.lower())
                start = max(0, idx - 100)
                end = min(len(text), idx + 500)
                info['extracted_code'].append({
                    'module': f'{location} @ offset {idx}',
                    'code': text[start:end],
                    'dangers': [desc],
                })

    def _check_exif_dangers(self, data_str, info):
        """Check EXIF/metadata for suspicious content."""
        danger_patterns = ['<?php', '<script', 'eval(', 'system(', 'cmd.exe']
        for p in danger_patterns:
            if p.lower() in data_str.lower():
                # Already caught by _check_embedded_code, skip duplicate
                pass

    # --- SVG Analysis ---
    def _analyze_svg(self, filepath, info):
        """Analyze SVG files for embedded scripts."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1048576)  # max 1MB
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'Read error: {e}'})
            return

        import re
        content_lower = content.lower()

        # Script tags
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
        if scripts:
            info['findings'].append({'type': 'WARNING', 'detail': f'<script> tags: {len(scripts)}'})
            for s in scripts[:5]:
                dangers = self._check_js_dangers(s)
                info['extracted_code'].append({
                    'module': 'SVG <script>',
                    'code': s[:5000],
                    'dangers': dangers,
                })
                if dangers:
                    info['status'] = 'DANGER'
                    info['reason'] = 'Malicious script in SVG'
                    info['mitre'].append('T1059.007')
                elif info['status'] == 'SAFE':
                    info['status'] = 'WARNING'
                    info['reason'] = 'Script in SVG'

        # Event handlers
        events = re.findall(r'(on\w+)\s*=\s*"([^"]*)"', content, re.IGNORECASE)
        for evt_name, evt_code in events:
            info['findings'].append({
                'type': 'WARNING',
                'detail': f'Event handler: {evt_name}="{evt_code[:100]}"',
            })
            if info['status'] == 'SAFE':
                info['status'] = 'WARNING'
                info['reason'] = 'Event handlers in SVG'

        # foreignObject
        if '<foreignobject' in content_lower:
            info['findings'].append({'type': 'WARNING', 'detail': 'foreignObject element (HTML embedding)'})

        # javascript: URLs
        js_urls = re.findall(r'javascript:[^"\']+', content, re.IGNORECASE)
        if js_urls:
            info['findings'].append({'type': 'DANGER', 'detail': f'javascript: URLs: {len(js_urls)}'})
            info['status'] = 'DANGER'
            info['reason'] = 'javascript: URL in SVG'
            info['mitre'].append('T1059.007')

    # --- PE Analysis (.exe, .dll) ---
    def _analyze_pe(self, filepath, info):
        """Analyze PE executable files."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(min(os.path.getsize(filepath), 2097152))  # max 2MB header
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'Read error: {e}'})
            return

        if len(data) < 64:
            return

        # PE header
        try:
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                info['findings'].append({'type': 'WARNING', 'detail': 'Invalid PE signature'})
                return

            machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
            arch = {0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM'}.get(machine, f'0x{machine:X}')
            info['findings'].append({'type': 'INFO', 'detail': f'Architecture: {arch}'})

            # Timestamp
            timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
            try:
                compile_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
                info['findings'].append({'type': 'INFO', 'detail': f'Compile time: {compile_time}'})
            except Exception:
                pass

            # Sections
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
            section_offset = pe_offset + 24 + opt_header_size

            sections = []
            packer_hints = []
            for i in range(min(num_sections, 20)):
                s_off = section_offset + i * 40
                if s_off + 40 > len(data):
                    break
                name = data[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                vsize = struct.unpack_from('<I', data, s_off + 8)[0]
                rsize = struct.unpack_from('<I', data, s_off + 16)[0]
                sections.append({'name': name, 'virtual_size': vsize, 'raw_size': rsize})

                # Packer detection
                if name.upper() in ('UPX0', 'UPX1', 'UPX2', '.ASPACK', '.ADATA'):
                    packer_hints.append(name)

            info['findings'].append({
                'type': 'INFO',
                'detail': f'Sections ({num_sections}): {", ".join(s["name"] for s in sections)}',
                'sections': sections,
            })

            if packer_hints:
                info['findings'].append({
                    'type': 'WARNING',
                    'detail': f'Packer detected: {", ".join(packer_hints)}',
                })
                info['status'] = 'WARNING'
                info['reason'] = 'Packed executable'
                info['mitre'].append('T1027.002')

        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'PE parse error: {e}'})

        # Suspicious imports (string search)
        data_str = data.decode('latin-1', errors='ignore')
        suspicious_imports = [
            ('VirtualAllocEx', 'Remote memory allocation', 'T1055'),
            ('WriteProcessMemory', 'Process memory write', 'T1055'),
            ('CreateRemoteThread', 'Remote thread creation', 'T1055'),
            ('NtUnmapViewOfSection', 'Process hollowing', 'T1055.012'),
            ('SetWindowsHookEx', 'Hooking', 'T1056.004'),
            ('IsDebuggerPresent', 'Anti-debug check', 'T1622'),
            ('GetAsyncKeyState', 'Keylogger indicator', 'T1056.001'),
        ]

        for func, desc, mitre in suspicious_imports:
            if func in data_str:
                info['findings'].append({'type': 'WARNING', 'detail': f'Suspicious import: {func} ({desc})'})
                if info['status'] == 'SAFE':
                    info['status'] = 'WARNING'
                    info['reason'] = 'Suspicious API imports'
                info['mitre'].append(mitre)

        # Suspicious strings
        sus_strings = ['cmd.exe /c', 'powershell', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                       'http://', 'https://', '.onion', 'bitcoin', 'ransom']
        found_sus = []
        for s in sus_strings:
            if s.lower() in data_str.lower():
                found_sus.append(s)
        if found_sus:
            info['findings'].append({
                'type': 'WARNING',
                'detail': f'Suspicious strings: {", ".join(found_sus[:10])}',
            })

    # --- Script Analysis ---
    def _analyze_script(self, filepath, info):
        """Analyze script files for malicious patterns."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1048576)
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'Read error: {e}'})
            return

        ext = os.path.splitext(filepath)[1].lower()
        lines = content.count('\n') + 1
        info['findings'].append({'type': 'INFO', 'detail': f'Script lines: {lines}'})

        content_lower = content.lower()

        # Common dangerous patterns
        script_checks = [
            ('invoke-expression', 'PowerShell Invoke-Expression', 'T1059.001'),
            ('invoke-webrequest', 'PowerShell web request', 'T1105'),
            ('downloadfile', 'File download', 'T1105'),
            ('downloadstring', 'String download', 'T1105'),
            ('net.webclient', '.NET WebClient', 'T1105'),
            ('-encodedcommand', 'Encoded PowerShell command', 'T1027'),
            ('-enc ', 'Encoded command shorthand', 'T1027'),
            ('frombase64string', 'Base64 decode', 'T1027'),
            ('convertto-securestring', 'Credential manipulation', 'T1003'),
            ('new-object system.net', 'Network object creation', 'T1071'),
            ('wscript.shell', 'WScript Shell', 'T1059.005'),
            ('cmd /c', 'Command execution', 'T1059.003'),
            ('reg add', 'Registry modification', 'T1547.001'),
            ('schtasks', 'Scheduled task', 'T1053.005'),
            ('certutil -decode', 'Certutil decode (LOLBin)', 'T1140'),
            ('bitsadmin', 'BITS transfer (LOLBin)', 'T1197'),
        ]

        found_dangers = []
        for pattern, desc, mitre in script_checks:
            if pattern in content_lower:
                found_dangers.append(desc)
                info['findings'].append({'type': 'DANGER', 'detail': desc})
                info['mitre'].append(mitre)

        if found_dangers:
            info['status'] = 'DANGER'
            info['reason'] = f'Dangerous script patterns: {", ".join(found_dangers[:3])}'

        # Store full code for review
        info['extracted_code'].append({
            'module': os.path.basename(filepath),
            'code': content[:10000],
            'dangers': found_dangers,
        })

    # --- HTML Analysis ---
    def _analyze_html(self, filepath, info):
        """Analyze HTML files for embedded threats."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1048576)
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'Read error: {e}'})
            return

        import re
        content_lower = content.lower()

        # Script tags
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
        info['findings'].append({'type': 'INFO', 'detail': f'<script> tags: {len(scripts)}'})

        # External scripts
        ext_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for src in ext_scripts:
            level = 'WARNING' if 'http://' in src else 'INFO'
            info['findings'].append({'type': level, 'detail': f'External script: {src}'})

        # iframes
        iframes = re.findall(r'<iframe[^>]*>', content, re.IGNORECASE)
        for iframe in iframes:
            hidden = 'hidden' in iframe.lower() or 'display:none' in iframe.lower() or 'width="0"' in iframe
            level = 'DANGER' if hidden else 'WARNING'
            info['findings'].append({'type': level, 'detail': f'iframe: {iframe[:200]}'})
            if hidden:
                info['status'] = 'DANGER'
                info['reason'] = 'Hidden iframe detected'
                info['mitre'].append('T1189')

        # Dangerous JS patterns in inline scripts
        for s in scripts[:10]:
            dangers = self._check_js_dangers(s)
            if dangers:
                info['extracted_code'].append({
                    'module': 'HTML <script>',
                    'code': s[:5000],
                    'dangers': dangers,
                })
                if info['status'] != 'DANGER':
                    info['status'] = 'WARNING'
                    info['reason'] = 'Suspicious JavaScript'

        # object/embed tags
        if '<object' in content_lower or '<embed' in content_lower:
            info['findings'].append({'type': 'WARNING', 'detail': 'object/embed tags detected'})

    # --- ZIP Analysis ---
    def _analyze_zip(self, filepath, info):
        """Analyze ZIP archive contents."""
        import zipfile

        try:
            zf = zipfile.ZipFile(filepath, 'r')
        except Exception as e:
            info['findings'].append({'type': 'ERROR', 'detail': f'ZIP error: {e}'})
            return

        entries = zf.namelist()
        info['findings'].append({'type': 'INFO', 'detail': f'Archive entries: {len(entries)}'})

        # Check for dangerous content
        exe_exts = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.wsf'}
        for entry in entries:
            ext = os.path.splitext(entry)[1].lower()
            name_lower = entry.lower()

            if ext in exe_exts:
                info['findings'].append({
                    'type': 'WARNING',
                    'detail': f'Executable in archive: {entry}',
                })
                if info['status'] == 'SAFE':
                    info['status'] = 'WARNING'
                    info['reason'] = 'Executable file in archive'

            # Double extension
            parts = entry.rsplit('.', 2)
            if len(parts) >= 3 and parts[-2].lower() in ('pdf', 'doc', 'jpg', 'txt'):
                info['findings'].append({
                    'type': 'DANGER',
                    'detail': f'Double extension: {entry}',
                })
                info['status'] = 'DANGER'
                info['reason'] = 'Double file extension (disguise)'
                info['mitre'].append('T1036.007')

            # Path traversal
            if '..' in entry:
                info['findings'].append({
                    'type': 'DANGER',
                    'detail': f'Path traversal: {entry}',
                })
                info['status'] = 'DANGER'
                info['reason'] = 'Path traversal in archive'

        # ZIP bomb check
        total_uncompressed = sum(z.file_size for z in zf.infolist())
        total_compressed = sum(z.compress_size for z in zf.infolist())
        if total_compressed > 0 and total_uncompressed / total_compressed > 100:
            info['findings'].append({
                'type': 'DANGER',
                'detail': f'ZIP bomb suspected: ratio {total_uncompressed/total_compressed:.0f}:1',
            })
            info['status'] = 'DANGER'
            info['reason'] = 'ZIP bomb detected'

        zf.close()

    # --- Generic / Unknown file ---
    def _analyze_generic(self, filepath, info):
        """Basic analysis for unknown file types."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(65536)
        except Exception:
            return

        # Check for MZ header in non-exe extension
        if data[:2] == b'MZ':
            info['findings'].append({
                'type': 'DANGER',
                'detail': 'PE実行ファイルの拡張子偽装 - 実際は実行可能ファイルです',
            })
            info['status'] = 'DANGER'
            info['reason'] = '実行ファイルの偽装（拡張子詐称）'
            info['mitre'].append('T1036.007')
            info['ext_match'] = False
            return

        # Check for embedded code in text-like files
        text = data.decode('utf-8', errors='ignore')
        self._check_embedded_code(text, info, 'File content')

    # =========================================================
    # P27-B: OLE / OOXML / PDF Deep Structure Analysis
    # =========================================================


    @staticmethod
    def _defang_url(url):
        """Defang URL for safe display: http->hXXp, dots->[.]"""
        if not url:
            return url
        r = url.replace('http://', 'hXXp://').replace('https://', 'hXXps://')
        parts = r.split('/', 3)
        if len(parts) >= 3:
            parts[2] = parts[2].replace('.', '[.]')
            r = '/'.join(parts)
        return r

    def analyze_ole(self, filepath):
        """Analyze OLE2 files (.doc, .xls, .ppt) for macros and suspicious content."""
        result = {
            'type': 'OLE',
            'ole_version': '',
            'streams': [],
            'macros': [],
            'suspicious_keywords': [],
            'auto_exec': [],
            'external_links': [],
            'status': 'SAFE',
            'risk_score': 0,
            'findings': [],
            'mitre': []
        }
        try:
            import olefile
        except ImportError:
            result['findings'].append({'type': 'INFO', 'detail': 'olefile not installed - OLE analysis skipped'})
            return result

        if not olefile.isOleFile(filepath):
            result['findings'].append({'type': 'INFO', 'detail': '有効なOLEファイルではありません'})
            return result

        try:
            ole = olefile.OleFileIO(filepath)
        except Exception as e:
            result['findings'].append({'type': 'WARNING', 'detail': f'OLE open error: {e}'})
            return result

        try:
            meta = ole.get_metadata()
            if meta:
                result['ole_version'] = f"OLE2 (CodePage: {getattr(meta, 'codepage', 'N/A')})"

            # Enumerate streams
            for stream_path in ole.listdir(streams=True, storages=False):
                stream_name = '/'.join(stream_path)
                try:
                    size = ole.get_size(stream_name)
                except:
                    size = 0
                result['streams'].append({'name': stream_name, 'size': size})

            # VBA macro detection
            vba_streams = [s for s in result['streams']
                           if any(k in s['name'].lower() for k in ['vba', 'macro', '_vba_project', 'vbaproject'])]

            if vba_streams:
                result['findings'].append({'type': 'WARNING', 'detail': f'VBAプロジェクト検出（{len(vba_streams)}ストリーム）- マクロが埋め込まれています'})
                result['risk_score'] += 30
                result['mitre'].append('T1059.005')

            # Extract and analyze VBA code
            dangerous_keywords = {
                'Shell': ('シェルコマンド実行 - 外部プログラムを起動する危険な関数', 'T1059'),
                'WScript.Shell': ('Windows Script Host経由の実行 - スクリプトからOSコマンドを実行', 'T1059.005'),
                'PowerShell': ('PowerShell呼び出し - 高度なスクリプト実行環境を利用', 'T1059.001'),
                'cmd.exe': ('コマンドプロンプト呼び出し - OSコマンドの直接実行', 'T1059.003'),
                'CreateObject': ('COMオブジェクト生成 - 外部コンポーネントを動的に生成', 'T1559.001'),
                'XMLHTTP': ('HTTP通信 - 外部サーバーとの通信（C2通信の可能性）', 'T1071.001'),
                'ADODB.Stream': ('バイナリストリーム操作 - ファイル書き込みやデータ変換に悪用', 'T1027'),
                'Environ': ('環境変数アクセス - システム情報の窃取に利用', 'T1082'),
                'URLDownloadToFile': ('ファイルダウンロード - 外部から追加のマルウェアを取得', 'T1105'),
                'RegWrite': ('レジストリ書き込み - 永続化（起動時の自動実行登録）', 'T1547.001'),
                'CallByName': ('動的関数呼び出し - 検知回避のため関数名を動的に指定', 'T1059.005'),
                'GetObject': ('オブジェクトアクセス - 既存プロセスへの接続や操作', 'T1559.001'),
                'Lib "kernel32"': ('Win32 API直接呼び出し - OS低レベル機能の悪用', 'T1106'),
                'Lib "user32"': ('Win32 API直接呼び出し - OS低レベル機能の悪用', 'T1106'),
                'Chr(': ('文字コード変換による難読化 - 検知回避のためコードを隠蔽', 'T1027'),
                'Base64': ('Base64エンコード - ペイロードの隠蔽に使用', 'T1132.001'),
                'FromBase64': ('Base64デコード - 隠蔽されたペイロードの復元', 'T1140'),
            }

            auto_exec_triggers = [
                'AutoOpen', 'AutoClose', 'AutoExec', 'AutoExit', 'AutoNew',
                'Document_Open', 'Document_Close', 'Workbook_Open', 'Workbook_Close',
                'Auto_Open', 'Auto_Close', 'Workbook_Activate', 'Workbook_BeforeClose',
            ]

            for vs in vba_streams:
                try:
                    raw = ole.openstream(vs['name']).read()
                    text = raw.decode('utf-8', errors='ignore')

                    # Auto-exec triggers
                    for trigger in auto_exec_triggers:
                        if trigger.lower() in text.lower():
                            result['auto_exec'].append(trigger)
                            result['findings'].append({
                                'type': 'DANGER',
                                'detail': f'自動実行トリガー検出: {trigger} - ファイルを開くだけでマクロが自動実行されます'
                            })
                            result['risk_score'] += 40
                            result['mitre'].append('T1204.002')

                    # Dangerous keywords
                    for kw, (desc, mitre) in dangerous_keywords.items():
                        if kw.lower() in text.lower():
                            result['suspicious_keywords'].append({'keyword': kw, 'description': desc})
                            result['findings'].append({
                                'type': 'WARNING',
                                'detail': f'危険キーワード検出: {kw} - {desc}'
                            })
                            result['risk_score'] += 15
                            if mitre not in result['mitre']:
                                result['mitre'].append(mitre)

                    # Extract macro code for display
                    result['macros'].append({
                        'stream': vs['name'],
                        'size': vs['size'],
                        'code_preview': text[:5000]
                    })
                except Exception:
                    pass

            # External links in non-VBA streams
            for stream_info in result['streams']:
                if 'vba' not in stream_info['name'].lower():
                    try:
                        raw = ole.openstream(stream_info['name']).read()
                        text = raw.decode('utf-8', errors='ignore')
                        import re
                        urls = re.findall(r'https?://[^\s\x00"\'<>\)]{5,200}', text)
                        for url in urls:
                            result['external_links'].append(self._defang_url(url))
                    except:
                        pass

            if result['external_links']:
                result['findings'].append({
                    'type': 'WARNING',
                    'detail': f'外部リンク検出: {len(result["external_links"])}件 - ドキュメント内に外部URLへの参照があります'
                })
                result['risk_score'] += 20
                if 'T1071.001' not in result['mitre']:
                    result['mitre'].append('T1071.001')

            # Determine status
            if result['risk_score'] >= 60:
                result['status'] = 'DANGER'
            elif result['risk_score'] >= 20:
                result['status'] = 'WARNING'

            result['auto_exec'] = list(set(result['auto_exec']))
            result['mitre'] = list(set(result['mitre']))

        except Exception as e:
            result['findings'].append({'type': 'WARNING', 'detail': f'OLE analysis error: {e}'})
        finally:
            try:
                ole.close()
            except:
                pass

        return result

    def analyze_ooxml(self, filepath):
        """Analyze OOXML files (.docx, .xlsx, .pptx) for embedded macros and external references."""
        result = {
            'type': 'OOXML',
            'entries': [],
            'relationships': [],
            'macros': [],
            'external_links': [],
            'activex': False,
            'status': 'SAFE',
            'risk_score': 0,
            'findings': [],
            'mitre': []
        }
        import zipfile
        if not zipfile.is_zipfile(filepath):
            result['findings'].append({'type': 'INFO', 'detail': '有効なZIP/OOXMLファイルではありません'})
            return result

        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                namelist = zf.namelist()
                result['entries'] = [{'name': n, 'size': zf.getinfo(n).file_size} for n in namelist]

                # Check for VBA project
                vba_files = [n for n in namelist if 'vbaproject' in n.lower()]
                if vba_files:
                    result['findings'].append({
                        'type': 'WARNING',
                        'detail': f'VBAプロジェクト検出: {", ".join(vba_files)} - マクロ埋め込みOOXMLファイルです'
                    })
                    result['risk_score'] += 30
                    result['mitre'].append('T1059.005')

                    for vf in vba_files:
                        try:
                            raw = zf.read(vf)
                            text = raw.decode('utf-8', errors='ignore')
                            result['macros'].append({
                                'file': vf,
                                'size': len(raw),
                                'code_preview': text[:5000]
                            })
                        except:
                            pass

                # Check for ActiveX
                activex_files = [n for n in namelist if 'activex' in n.lower()]
                if activex_files:
                    result['activex'] = True
                    result['findings'].append({
                        'type': 'WARNING',
                        'detail': f'ActiveXコントロール検出: {len(activex_files)}件 - コード実行に悪用される可能性があります'
                    })
                    result['risk_score'] += 25
                    result['mitre'].append('T1559.001')

                # Parse .rels files for external references
                import re
                rels_files = [n for n in namelist if n.endswith('.rels')]
                for rf in rels_files:
                    try:
                        rels_content = zf.read(rf).decode('utf-8', errors='ignore')
                        # External targets
                        ext_targets = re.findall(
                            r'Target\s*=\s*"(https?://[^"]+)".*?TargetMode\s*=\s*"External"',
                            rels_content, re.IGNORECASE | re.DOTALL
                        )
                        if not ext_targets:
                            ext_targets = re.findall(
                                r'TargetMode\s*=\s*"External".*?Target\s*=\s*"(https?://[^"]+)"',
                                rels_content, re.IGNORECASE | re.DOTALL
                            )
                        for t in ext_targets:
                            result['external_links'].append(self._defang_url(t))
                            result['relationships'].append({'file': rf, 'target': t, 'mode': 'External'})
                    except:
                        pass

                if result['external_links']:
                    result['findings'].append({
                        'type': 'DANGER',
                        'detail': f'外部テンプレート/リンクインジェクション検出: {len(result["external_links"])}件 - 外部サーバーからテンプレートを読み込む手法で、マクロ無効化を回避して悪意あるコードを実行する攻撃に利用されます'
                    })
                    result['risk_score'] += 40
                    if 'T1221' not in result['mitre']:
                        result['mitre'].append('T1221')


                # Embedded executables
                exe_entries = [n for n in namelist
                               if any(n.lower().endswith(ext) for ext in ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1'])]
                if exe_entries:
                    result['findings'].append({
                        'type': 'DANGER',
                        'detail': f'実行ファイル埋め込み検出: {", ".join(exe_entries)} - ドキュメント内に実行可能ファイルが隠されています'
                    })
                    result['risk_score'] += 50
                    result['mitre'].append('T1204.002')

                if result['risk_score'] >= 50:
                    result['status'] = 'DANGER'
                elif result['risk_score'] >= 20:
                    result['status'] = 'WARNING'

                result['mitre'] = list(set(result['mitre']))

        except Exception as e:
            result['findings'].append({'type': 'WARNING', 'detail': f'OOXML analysis error: {e}'})

        return result

    def analyze_pdf(self, filepath):
        """Analyze PDF files for JavaScript, auto-actions, embedded files, and suspicious objects."""
        result = {
            'type': 'PDF',
            'version': '',
            'pages': 0,
            'objects': 0,
            'javascript': [],
            'auto_actions': [],
            'embedded_files': [],
            'uris': [],
            'suspicious_objects': [],
            'status': 'SAFE',
            'risk_score': 0,
            'findings': [],
            'mitre': []
        }

        # Phase 1: Raw text scan for dangerous keywords
        try:
            with open(filepath, 'rb') as f:
                raw = f.read()
            text = raw.decode('latin-1', errors='ignore')

            import re
            # PDF version
            ver_match = re.search(r'%PDF-(\d+\.\d+)', text)
            if ver_match:
                result['version'] = ver_match.group(1)

            # Dangerous PDF keywords
            pdf_keywords = {
                '/JavaScript': ('JavaScriptコード検出 - PDFを開くとスクリプトが実行される危険性', 'T1059.007', 40),
                '/JS': ('JavaScript省略形 - スクリプト実行の危険性', 'T1059.007', 40),
                '/OpenAction': ('自動実行アクション - PDF開封時に自動でアクションを実行', 'T1204.002', 30),
                '/AA': ('追加アクション定義 - ページ表示時等にアクションを実行', 'T1204.002', 25),
                '/Launch': ('起動アクション - 外部プログラムを直接実行する最も危険な機能', 'T1204.002', 50),
                '/SubmitForm': ('フォーム送信 - 入力データを外部に送信（情報漏洩の手段）', 'T1048', 30),
                '/ImportData': ('データインポート - 外部データの取り込み', 'T1105', 20),
                '/RichMedia': ('リッチメディア（Flash等） - 脆弱性を悪用する攻撃の温床', 'T1203', 25),
                '/EmbeddedFile': ('埋め込みファイル - PDF内にファイルが隠されています', 'T1027.001', 30),
                '/XFA': ('XFAフォーム - 複雑なスクリプト実行が可能', 'T1059.007', 25),
                '/ObjStm': ('オブジェクトストリーム - オブジェクトの隠蔽に使用', 'T1027', 15),
                '/Encrypt': ('暗号化 - 解析妨害のためコンテンツを暗号化', 'T1027', 10),
                '/AcroForm': ('インタラクティブフォーム - ユーザー操作を誘導', 'T1204.002', 10),
            }

            for kw, (desc, mitre, score) in pdf_keywords.items():
                count = text.count(kw)
                if count > 0:
                    result['suspicious_objects'].append({'keyword': kw, 'count': count, 'description': desc})
                    result['findings'].append({
                        'type': 'DANGER' if score >= 30 else 'WARNING',
                        'detail': f'{kw} を{count}箇所で検出 - {desc}'
                    })
                    result['risk_score'] += score
                    if mitre not in result['mitre']:
                        result['mitre'].append(mitre)

            # Extract URIs
            uris = re.findall(r'/URI\s*\(([^)]+)\)', text)
            uris += re.findall(r'/URI\s*<([^>]+)>', text)
            for uri in uris:
                decoded = uri.replace('\\/', '/')
                result['uris'].append(decoded)
            if result['uris']:
                result['findings'].append({
                    'type': 'INFO',
                    'detail': f'URI検出: {len(result["uris"])}件 - 外部へのリンクが含まれています'
                })

            # Extract JavaScript blocks
            js_blocks = re.findall(r'/JavaScript\s*<<[^>]*>>\s*stream\s*(.*?)\s*endstream', text, re.DOTALL)
            js_blocks += re.findall(r'/JS\s*\(([^)]{1,10000})\)', text)
            for js in js_blocks:
                result['javascript'].append(js[:3000])

            if result['javascript']:
                result['findings'].append({
                    'type': 'DANGER',
                    'detail': f'JavaScriptコード抽出: {len(result["javascript"])}ブロック - 悪意あるスクリプトの可能性があります'
                })

        except Exception as e:
            result['findings'].append({'type': 'WARNING', 'detail': f'Raw PDF scan error: {e}'})

        # Phase 2: PyPDF2 analysis
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(filepath)
            result['pages'] = len(reader.pages)

            # Count objects
            if hasattr(reader, '_objects'):
                result['objects'] = len(reader._objects)

            # Check for embedded files in catalog
            if reader.trailer and '/Root' in reader.trailer:
                root = reader.trailer['/Root']
                if hasattr(root, 'get_object'):
                    root = root.get_object()
                if isinstance(root, dict):
                    if '/Names' in root:
                        names = root['/Names']
                        if hasattr(names, 'get_object'):
                            names = names.get_object()
                        if isinstance(names, dict) and '/EmbeddedFiles' in names:
                            result['findings'].append({
                                'type': 'WARNING',
                                'detail': '埋め込みファイルカタログ検出 - PDF内にファイルが格納されています'
                            })
                            result['risk_score'] += 20

        except Exception as e:
            result['findings'].append({'type': 'INFO', 'detail': f'PyPDF2 parse note: {e}'})

        # Determine status
        if result['risk_score'] >= 50:
            result['status'] = 'DANGER'
        elif result['risk_score'] >= 15:
            result['status'] = 'WARNING'

        result['mitre'] = list(set(result['mitre']))
        return result

    def analyze_file_deep(self, filepath):
        """Run deep analysis on a single file based on its type. Returns detailed result dict."""
        import os
        result = {'filepath': filepath, 'analysis': None, 'error': None}

        if not os.path.isfile(filepath):
            result['error'] = 'File not found'
            return result

        ext = os.path.splitext(filepath)[1].lower()

        try:
            if ext in ('.doc', '.xls', '.ppt', '.dot', '.xlt'):
                result['analysis'] = self.analyze_ole(filepath)
            elif ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.dotx', '.xltx'):
                result['analysis'] = self.analyze_ooxml(filepath)
            elif ext == '.pdf':
                result['analysis'] = self.analyze_pdf(filepath)
            else:
                result['analysis'] = {'type': 'UNSUPPORTED', 'findings': [
                    {'type': 'INFO', 'detail': f'Deep analysis not yet implemented for {ext}'}
                ], 'status': 'INFO', 'mitre': []}
        except Exception as e:
            result['error'] = str(e)

        return result
