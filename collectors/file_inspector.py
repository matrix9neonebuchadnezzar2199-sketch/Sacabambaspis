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
