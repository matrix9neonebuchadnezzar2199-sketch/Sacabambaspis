import os
import json
import hashlib
import shutil
import time

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraManager:
    """YARA rule manager: load, compile, scan, import, deduplicate."""

    def __init__(self, rules_dir=None):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rules_dir = rules_dir or os.path.join(base, 'yara_rules')
        self.compiled_rules = None
        self._rule_index = {}  # hash -> filepath
        self._ensure_dirs()

    def _ensure_dirs(self):
        for d in [self.rules_dir, os.path.join(self.rules_dir, 'custom'), os.path.join(self.rules_dir, 'imported')]:
            if not os.path.exists(d):
                os.makedirs(d)

    def is_available(self):
        return YARA_AVAILABLE

    def get_status(self):
        """Return current YARA status."""
        rule_files = self._list_rule_files()
        return {
            'available': YARA_AVAILABLE,
            'version': yara.YARA_VERSION if YARA_AVAILABLE else None,
            'rules_dir': self.rules_dir,
            'rule_files': len(rule_files),
            'compiled': self.compiled_rules is not None,
            'categories': self._get_categories()
        }

    def _list_rule_files(self):
        """List all .yar/.yara files recursively."""
        files = []
        for root, dirs, filenames in os.walk(self.rules_dir):
            for fn in filenames:
                if fn.lower().endswith(('.yar', '.yara')):
                    files.append(os.path.join(root, fn))
        return files

    def _get_categories(self):
        """Get rule categories (subdirectories)."""
        cats = {}
        for root, dirs, filenames in os.walk(self.rules_dir):
            rel = os.path.relpath(root, self.rules_dir)
            if rel == '.':
                rel = 'root'
            count = sum(1 for f in filenames if f.lower().endswith(('.yar', '.yara')))
            if count > 0:
                cats[rel] = count
        return cats

    def list_rules(self):
        """List all rule files with metadata."""
        files = self._list_rule_files()
        rules = []
        for fp in files:
            rel = os.path.relpath(fp, self.rules_dir)
            try:
                stat = os.stat(fp)
                size = stat.st_size
                mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
            except:
                size = 0
                mtime = ''

            # Count rules in file
            rule_count = 0
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith('rule ') and '{' in stripped:
                            rule_count += 1
            except:
                pass

            rules.append({
                'filepath': fp,
                'relative': rel,
                'filename': os.path.basename(fp),
                'size': size,
                'mtime': mtime,
                'rule_count': rule_count
            })
        return rules

    def compile_rules(self):
        """Compile all YARA rules. Returns success status and any errors."""
        if not YARA_AVAILABLE:
            return {'success': False, 'error': 'yara-python がインストールされていません'}

        files = self._list_rule_files()
        if not files:
            self.compiled_rules = None
            return {'success': False, 'error': 'YARAルールファイルがありません。ルールをインポートしてください。'}

        # Build filepaths dict for yara.compile
        filepaths = {}
        errors = []
        for i, fp in enumerate(files):
            ns = os.path.relpath(fp, self.rules_dir).replace(os.sep, '_').replace('.yar', '').replace('.yara', '')
            try:
                # Test compile individually first
                yara.compile(filepath=fp)
                filepaths[ns] = fp
            except yara.SyntaxError as e:
                errors.append({'file': os.path.relpath(fp, self.rules_dir), 'error': str(e)})
            except Exception as e:
                errors.append({'file': os.path.relpath(fp, self.rules_dir), 'error': str(e)})

        if not filepaths:
            self.compiled_rules = None
            return {'success': False, 'error': '有効なルールファイルがありません', 'compile_errors': errors}

        try:
            self.compiled_rules = yara.compile(filepaths=filepaths)
            return {
                'success': True,
                'compiled_files': len(filepaths),
                'skipped_files': len(errors),
                'compile_errors': errors
            }
        except Exception as e:
            self.compiled_rules = None
            return {'success': False, 'error': str(e), 'compile_errors': errors}

    def scan_file(self, filepath, timeout=60):
        """Scan a single file with compiled YARA rules."""
        if not YARA_AVAILABLE:
            return {'error': 'yara-python がインストールされていません', 'matches': []}

        if not self.compiled_rules:
            compile_result = self.compile_rules()
            if not compile_result.get('success'):
                return {'error': compile_result.get('error', 'コンパイル失敗'), 'matches': []}

        try:
            matches = self.compiled_rules.match(filepath, timeout=timeout)
            results = []
            for m in matches:
                match_info = {
                    'rule': m.rule,
                    'namespace': m.namespace,
                    'tags': list(m.tags) if m.tags else [],
                    'meta': dict(m.meta) if m.meta else {},
                    'strings': []
                }
                if m.strings:
                    for s in m.strings[:50]:  # Limit to 50 string matches
                        for instance in s.instances[:10]:
                            match_info['strings'].append({
                                'identifier': s.identifier,
                                'offset': instance.offset,
                                'data': instance.matched_data[:200].hex() if instance.matched_data else ''
                            })
                results.append(match_info)
            return {'matches': results, 'scanned': True}
        except yara.TimeoutError:
            return {'error': f'スキャンタイムアウト（{timeout}秒超過）', 'matches': []}
        except Exception as e:
            return {'error': str(e), 'matches': []}

    def import_rules(self, source_path, category='imported'):
        """Import YARA rules from a file or directory, with deduplication."""
        dest_dir = os.path.join(self.rules_dir, category)
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        imported = 0
        skipped = 0
        errors = []

        # Build hash index of existing rules
        self._build_rule_index()

        if os.path.isfile(source_path):
            result = self._import_single_file(source_path, dest_dir)
            if result == 'imported':
                imported += 1
            elif result == 'duplicate':
                skipped += 1
            else:
                errors.append(result)
        elif os.path.isdir(source_path):
            for root, dirs, filenames in os.walk(source_path):
                for fn in filenames:
                    if fn.lower().endswith(('.yar', '.yara')):
                        fp = os.path.join(root, fn)
                        result = self._import_single_file(fp, dest_dir)
                        if result == 'imported':
                            imported += 1
                        elif result == 'duplicate':
                            skipped += 1
                        else:
                            errors.append(result)
        else:
            return {'success': False, 'error': 'パスが見つかりません'}

        # Recompile after import
        if imported > 0:
            self.compile_rules()

        return {
            'success': True,
            'imported': imported,
            'skipped_duplicates': skipped,
            'errors': errors
        }

    def _build_rule_index(self):
        """Build hash index of existing rule files for dedup."""
        self._rule_index = {}
        for fp in self._list_rule_files():
            try:
                h = self._file_hash(fp)
                self._rule_index[h] = fp
            except:
                pass

    def _file_hash(self, filepath):
        """Calculate SHA256 hash of file content (normalized)."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Normalize: strip whitespace, lowercase for dedup
            normalized = '\n'.join(line.strip() for line in content.splitlines() if line.strip())
            return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
        except:
            # Fallback to binary hash
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()

    def _import_single_file(self, source, dest_dir):
        """Import a single YARA file with dedup check."""
        try:
            h = self._file_hash(source)
            if h in self._rule_index:
                return 'duplicate'

            # Validate YARA syntax
            if YARA_AVAILABLE:
                try:
                    yara.compile(filepath=source)
                except yara.SyntaxError as e:
                    return f'{os.path.basename(source)}: 構文エラー - {e}'

            dest = os.path.join(dest_dir, os.path.basename(source))
            # Handle name conflicts
            if os.path.exists(dest):
                base, ext = os.path.splitext(dest)
                counter = 1
                while os.path.exists(f'{base}_{counter}{ext}'):
                    counter += 1
                dest = f'{base}_{counter}{ext}'

            shutil.copy2(source, dest)
            self._rule_index[h] = dest
            return 'imported'
        except Exception as e:
            return f'{os.path.basename(source)}: {e}'

    def delete_rule(self, filepath):
        """Delete a YARA rule file."""
        # Security: only allow deletion within rules_dir
        real_path = os.path.realpath(filepath)
        real_rules = os.path.realpath(self.rules_dir)
        if not real_path.startswith(real_rules):
            return {'success': False, 'error': '不正なパスです'}
        try:
            os.remove(filepath)
            self.compiled_rules = None  # Force recompile
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def download_ruleset(self, url, name='downloaded'):
        """Download YARA rules from a URL (git clone or file download)."""
        import tempfile
        import subprocess

        temp_dir = tempfile.mkdtemp(prefix='yara_dl_')
        try:
            if url.endswith('.git') or 'github.com' in url:
                # Git clone
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', url, temp_dir],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    return {'success': False, 'error': f'git clone 失敗: {result.stderr[:500]}'}
            else:
                # Direct file download
                import urllib.request
                dest_file = os.path.join(temp_dir, 'downloaded.yar')
                urllib.request.urlretrieve(url, dest_file)

            # Import from temp dir
            import_result = self.import_rules(temp_dir, category=name)
            return import_result
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'ダウンロードタイムアウト（120秒）'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
