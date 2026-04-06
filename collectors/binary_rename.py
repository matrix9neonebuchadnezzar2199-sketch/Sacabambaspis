# -*- coding: utf-8 -*-
# collectors/binary_rename.py - P43: バイナリリネーム検知 (Velociraptor BinaryRename移植)
# 実行中プロセスのファイル名とPEヘッダのOriginalFilename/InternalNameを比較し、
# リネームされた攻撃ツール・LOLBinを検出する
import os
import psutil

try:
    from utils.tutor_template import build_tutor_desc
except ImportError:
    def build_tutor_desc(**kwargs):
        return kwargs.get('detection', '')

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

from utils import threat_lists as _tl
from utils.binary_rename_table import RENAME_TABLE, TRUSTED_PREFIX_DIRS


class BinaryRenameCollector:
    def __init__(self):
        self.rename_table = RENAME_TABLE
        self.hardcore_tools = _tl.BINARY_RENAME_HARDCORE_SUBSTRINGS
        self._trusted_dirs = TRUSTED_PREFIX_DIRS

    def scan(self):
        if not HAS_PEFILE:
            return [{
                'status': 'INFO',
                'exe_name': '-',
                'exe_path': '-',
                'original_name': '-',
                'internal_name': '-',
                'current_name': '-',
                'description': '-',
                'reason': 'pefile未インストール: pip install pefile',
                'desc': 'PEヘッダ解析ライブラリが見つかりません',
                'source': 'BinaryRename',
                'pid': 0,
            }]

        results = []
        seen_paths = set()

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info['name'] or ''
                exe_path = proc.info['exe'] or ''

                if not exe_path or not os.path.isfile(exe_path):
                    continue
                if exe_path.lower() in seen_paths:
                    continue
                seen_paths.add(exe_path.lower())

                pe_info = self._read_pe_version(exe_path)
                if not pe_info:
                    continue

                match = self._check_rename(name, exe_path, pe_info)
                if match:
                    results.append(match)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return results

    def _read_pe_version(self, exe_path):
        """PEヘッダからVersionInformationを読み取る"""
        try:
            pe = pefile.PE(exe_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
            )

            info = {}
            if hasattr(pe, 'FileInfo'):
                for fi_list in pe.FileInfo:
                    for fi in fi_list:
                        if hasattr(fi, 'StringTable'):
                            for st in fi.StringTable:
                                for k, v in st.entries.items():
                                    info[k.decode('utf-8', errors='replace')] = v.decode('utf-8', errors='replace')
            pe.close()
            return info if info else None
        except Exception:
            return None

    def _check_rename(self, current_name, exe_path, pe_info):
        """リネーム検知ロジック"""
        current_lower = current_name.lower()
        path_lower = exe_path.lower()

        orig = pe_info.get('OriginalFilename', '').strip()
        internal = pe_info.get('InternalName', '').strip()
        company = pe_info.get('CompanyName', '').strip()
        description = pe_info.get('FileDescription', '').strip()

        orig_lower = orig.lower()
        internal_lower = internal.lower()

        for expected_fn, exp_internal, exp_original, desc_note in self.rename_table:
            exp_fn_l = expected_fn.lower()
            exp_int_l = exp_internal.lower() if exp_internal else ''
            exp_orig_l = exp_original.lower() if exp_original else ''

            matched_pe = False
            # 完全一致 or 拡張子除去後の完全一致（部分一致による誤検知防止）
            orig_base = orig_lower.replace('.exe', '').replace('.dll', '')
            internal_base = internal_lower.replace('.exe', '').replace('.dll', '')
            exp_orig_base = exp_orig_l.replace('.exe', '').replace('.dll', '').replace('.c', '')
            exp_int_base = exp_int_l.replace('.exe', '').replace('.dll', '')

            if exp_orig_base and (exp_orig_base == orig_base or exp_orig_l == orig_lower):
                matched_pe = True
            elif exp_int_base and (exp_int_base == internal_base or exp_int_l == internal_lower):
                matched_pe = True

            if not matched_pe:
                continue

            # ANY = 攻撃ツール → ファイル名問わず報告
            if exp_fn_l == 'any':
                is_hardcore = any(h in internal_lower or h in orig_lower
                                 for h in self.hardcore_tools)
                status = 'DANGER' if is_hardcore else 'WARNING'
                reason = f'攻撃ツール検知: {desc_note} (PE: {orig or internal})'

                return self._build_result(
                    status=status,
                    current_name=current_name,
                    exe_path=exe_path,
                    original=orig,
                    internal=internal,
                    description=description,
                    company=company,
                    reason=reason,
                    desc_note=desc_note,
                    rename_type='攻撃ツール',
                    mitre_key='binrename_attack_tool',
                    pid=0,
                )

            # システムツールのリネーム検知
            if exp_fn_l != current_lower:
                # 信頼パスにある場合はスキップ（正規のWindowsコンポーネント）
                if any(path_lower.startswith(d) for d in self._trusted_dirs):
                    continue

                reason = f'バイナリリネーム: {desc_note} が "{current_name}" にリネーム (本来: {expected_fn})'

                return self._build_result(
                    status='DANGER',
                    current_name=current_name,
                    exe_path=exe_path,
                    original=orig,
                    internal=internal,
                    description=description,
                    company=company,
                    reason=reason,
                    desc_note=desc_note,
                    rename_type='LOLBinリネーム',
                    mitre_key='binrename_lolbin',
                    pid=0,
                )

        return None

    def _build_result(self, status, current_name, exe_path, original, internal,
                      description, company, reason, desc_note, rename_type, mitre_key, pid):
        detection_text = f'{rename_type}検知: "{current_name}" (元: {original or internal})'
        if rename_type == '攻撃ツール':
            why_text = (
                f'{desc_note} のPEヘッダ情報が検出されました。'
                f'攻撃者がファイル名を変更して正規ツールに偽装している可能性があります。'
                f'T1036.003 (Masquerading: Rename System Utilities) に該当します。'
            )
        else:
            why_text = (
                f'Windows標準ツール "{original or internal}" が "{current_name}" にリネームされています。'
                f'攻撃者はEDR/ログ監視を回避するためにシステムツールをリネームして実行します。'
                f'T1036.003 (Masquerading: Rename System Utilities) に該当します。'
            )

        normal_text = f'正規の {original or internal} は本来のファイル名で実行される'
        abnormal_text = f'"{current_name}" という名前で {desc_note} が実行されている'

        next_steps = [
            f'ファイルパス "{exe_path}" を確認し、正規の場所か検証',
            'ファイルハッシュを VirusTotal で検索',
            'プロセスの親プロセスと起動コマンドラインを確認',
            '同時期のイベントログ (Event ID 4688) を確認',
        ]

        normal_vs = f'正常: {normal_text} / 異常: {abnormal_text}'
        full_desc = build_tutor_desc(
            detection=detection_text,
            why_dangerous=why_text,
            mitre_key=mitre_key,
            normal_vs_abnormal=normal_vs,
            next_steps=next_steps,
        )

        return {
            'status': status,
            'exe_name': current_name,
            'exe_path': exe_path,
            'original_name': original or '-',
            'internal_name': internal or '-',
            'current_name': current_name,
            'description': description or '-',
            'company': company or '-',
            'rename_type': rename_type,
            'reason': reason,
            'desc': full_desc,
            'source': 'BinaryRename',
            'pid': pid,
            'artifact': exe_path,
            'mitre': 'T1036.003',
        }