import os
import sys
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
        # PyInstaller exe: sys.executable の隣を優先
        # 通常実行: __file__ ベース
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(sys.executable)
        else:
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
            except Exception:
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
            except Exception:
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
            except Exception:
                pass

    def _file_hash(self, filepath):
        """Calculate SHA256 hash of file content (normalized)."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Normalize: strip whitespace, lowercase for dedup
            normalized = '\n'.join(line.strip() for line in content.splitlines() if line.strip())
            return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
        except Exception:
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
            except Exception:
                pass

    # ================================================================
    # P28-A: YARA管理・検査タブ用 拡張メソッド
    # ================================================================

    def get_rule_tree(self):
        """カテゴリ/ファイル/ルール名の階層ツリーを返す"""
        tree = []
        for root, dirs, filenames in os.walk(self.rules_dir):
            rel_dir = os.path.relpath(root, self.rules_dir)
            if rel_dir == '.':
                rel_dir = 'root'
            yar_files = [f for f in sorted(filenames) if f.lower().endswith(('.yar', '.yara'))]
            if not yar_files and rel_dir != 'root':
                continue
            category_node = {
                'category': rel_dir,
                'path': root,
                'files': []
            }
            for fn in yar_files:
                fp = os.path.join(root, fn)
                rule_names = []
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            stripped = line.strip()
                            if stripped.startswith('rule ') and '{' in stripped:
                                rname = stripped.split('{')[0].replace('rule ', '').strip().rstrip(':').strip()
                                if rname:
                                    rule_names.append(rname)
                except Exception:
                    pass
                category_node['files'].append({
                    'filename': fn,
                    'filepath': fp,
                    'relative': os.path.relpath(fp, self.rules_dir),
                    'rule_names': rule_names,
                    'rule_count': len(rule_names)
                })
            tree.append(category_node)
        return tree

    def get_rule_content(self, filepath):
        """ルールファイルの内容を取得"""
        real_path = os.path.realpath(filepath)
        real_rules = os.path.realpath(self.rules_dir)
        if not real_path.startswith(real_rules):
            return {'success': False, 'error': '不正なパスです'}
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return {'success': True, 'content': content, 'filepath': filepath, 'filename': os.path.basename(filepath)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def save_rule_content(self, filepath, content):
        """ルールファイルを編集保存（構文チェック付き）"""
        real_path = os.path.realpath(filepath)
        real_rules = os.path.realpath(self.rules_dir)
        if not real_path.startswith(real_rules):
            return {'success': False, 'error': '不正なパスです'}
        # 構文チェック
        if YARA_AVAILABLE:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False, encoding='utf-8') as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                try:
                    yara.compile(filepath=tmp_path)
                except yara.SyntaxError as e:
                    return {'success': False, 'error': f'構文エラー: {e}'}
                finally:
                    os.remove(tmp_path)
            except yara.SyntaxError as e:
                return {'success': False, 'error': f'構文エラー: {e}'}
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            self.compiled_rules = None  # 再コンパイル必要
            return {'success': True, 'filepath': filepath}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_rule(self, category, name, content=None):
        """新規ルールファイルを作成"""
        if not name.lower().endswith(('.yar', '.yara')):
            name = name + '.yar'
        cat_dir = os.path.join(self.rules_dir, category)
        if not os.path.exists(cat_dir):
            os.makedirs(cat_dir)
        filepath = os.path.join(cat_dir, name)
        if os.path.exists(filepath):
            return {'success': False, 'error': '同名のファイルが既に存在します'}
        if content is None:
            rule_name = name.replace('.yar', '').replace('.yara', '').replace(' ', '_')
            content = f"""rule {rule_name}
{{
    meta:
        author = "custom"
        description = ""
        date = "{time.strftime('%Y-%m-%d')}"
    strings:
        $s1 = "example" ascii
    condition:
        $s1
}}
"""
        # 構文チェック
        if YARA_AVAILABLE and content.strip():
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False, encoding='utf-8') as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                try:
                    yara.compile(filepath=tmp_path)
                except yara.SyntaxError as e:
                    return {'success': False, 'error': f'構文エラー: {e}'}
                finally:
                    os.remove(tmp_path)
            except Exception:
                pass
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            self.compiled_rules = None
            return {'success': True, 'filepath': filepath, 'relative': os.path.relpath(filepath, self.rules_dir)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def search_rules(self, query):
        """ルール名、タグ、meta内テキストで検索"""
        if not query:
            return []
        query_lower = query.lower()
        results = []
        for fp in self._list_rule_files():
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                lines = content.splitlines()
                file_matches = []
                current_rule = None
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped.startswith('rule ') and '{' in stripped:
                        current_rule = stripped.split('{')[0].replace('rule ', '').strip().rstrip(':').strip()
                    if query_lower in stripped.lower():
                        file_matches.append({
                            'line_number': i + 1,
                            'line': stripped[:200],
                            'rule_name': current_rule or ''
                        })
                if file_matches:
                    results.append({
                        'filepath': fp,
                        'relative': os.path.relpath(fp, self.rules_dir),
                        'filename': os.path.basename(fp),
                        'matches': file_matches[:20],
                        'match_count': len(file_matches)
                    })
            except Exception:
                continue
        return results

    def scan_directory(self, dirpath, timeout=60):
        """フォルダ内の全ファイルを一括スキャン"""
        if not YARA_AVAILABLE:
            return {'error': 'yara-python がインストールされていません', 'results': []}
        if not self.compiled_rules:
            compile_result = self.compile_rules()
            if not compile_result.get('success'):
                return {'error': compile_result.get('error', 'コンパイル失敗'), 'results': []}
        if not os.path.isdir(dirpath):
            return {'error': 'フォルダが見つかりません', 'results': []}
        results = []
        scanned = 0
        matched = 0
        errors = 0
        for root, dirs, filenames in os.walk(dirpath):
            for fn in filenames:
                fp = os.path.join(root, fn)
                try:
                    scan_result = self.scan_file(fp, timeout=timeout)
                    scanned += 1
                    if scan_result.get('matches'):
                        matched += 1
                        results.append({
                            'filepath': fp,
                            'filename': fn,
                            'relative': os.path.relpath(fp, dirpath),
                            'matches': scan_result['matches']
                        })
                except Exception:
                    errors += 1
        return {
            'scanned': scanned,
            'matched': matched,
            'errors': errors,
            'results': results
        }

    def get_presets(self):
        """プリセットYARAルールリポジトリ一覧"""
        return [
            {
                'name': 'Neo23x0/signature-base',
                'url': 'https://github.com/Neo23x0/signature-base.git',
                'description': 'Florian Roth による包括的なYARAルールセット（APT、マルウェア、Webシェル等）',
                'recommended': True
            },
            {
                'name': 'YARA-Rules/rules',
                'url': 'https://github.com/Yara-Rules/rules.git',
                'description': 'コミュニティ管理のYARAルール集（マルウェア分類、CVE検出等）',
                'recommended': False
            },
            {
                'name': 'InQuest/yara-rules',
                'url': 'https://github.com/InQuest/yara-rules.git',
                'description': 'InQuest Labs提供のYARAルール（ドキュメント解析特化）',
                'recommended': False
            },
            {
                'name': 'ReversingLabs/reversinglabs-yara-rules',
                'url': 'https://github.com/reversinglabs/reversinglabs-yara-rules.git',
                'description': 'ReversingLabs提供のYARAルール（脅威分類）',
                'recommended': False
            }
        ]
