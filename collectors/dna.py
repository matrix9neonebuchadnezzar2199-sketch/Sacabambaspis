# -*- coding: utf-8 -*-
# collectors/dna.py - P17: MITRE ATT&CK + Tutor Mode 統合版
import math
import os

try:
    from utils.tutor_template import build_tutor_desc, MITRE_MAP
except ImportError:
    from tutor_template import build_tutor_desc, MITRE_MAP


class DNACollector:
    """P12: シャノンエントロピー解析 - ファイルの暗号化/パック検知"""

    def analyze_file(self, filepath):
        """単一ファイルのエントロピー解析"""
        try:
            if not os.path.exists(filepath):
                return {
                    "entropy": 0,
                    "verdict": "ファイル不在",
                    "status": "WARNING",
                    "reason": "指定ファイルが存在しない",
                    "desc": build_tutor_desc(
                        detection=(
                            f'指定されたファイルが存在しません。\n'
                            f'パス: {filepath}'
                        ),
                        why_dangerous=(
                            '解析対象ファイルが見つからない場合、'
                            '攻撃者がマルウェアを実行後に証拠隠滅のため削除した可能性があります。'
                            'またはファイルパスの指定が誤っている可能性もあります。'
                        ),
                        mitre_key=None,
                        normal_vs_abnormal=(
                            '正常: 指定パスにファイルが存在する\n'
                            '異常: 最近まで存在していたファイルが突然消えている'
                        ),
                        next_steps=[
                            'Prefetch/PCA/CAM DBで当該ファイルの実行痕跡を確認する',
                            'ごみ箱（$Recycle.Bin）にファイルが移動されていないか確認する',
                            'Volume Shadow Copyからファイルの復元を試みる',
                        ],
                        status='WARNING',
                    ),
                }

            file_size = os.path.getsize(filepath)
            if file_size > 10 * 1024 * 1024:
                return {
                    "entropy": 0,
                    "verdict": "スキップ (10MB超)",
                    "status": "INFO",
                    "reason": f"ファイルサイズが大きいためスキップ ({file_size // (1024*1024)}MB)",
                    "desc": build_tutor_desc(
                        detection=(
                            f'ファイルサイズが10MBを超えるためエントロピー解析をスキップしました。\n'
                            f'ファイルサイズ: {file_size // (1024*1024)}MB'
                        ),
                        why_dangerous=(
                            '大きなファイルの場合、先頭部分のみの解析や'
                            'ハッシュ値によるVirusTotal照合を推奨します。'
                        ),
                        mitre_key=None,
                        status='INFO',
                    ),
                }

            if file_size == 0:
                return {
                    "entropy": 0,
                    "verdict": "空ファイル",
                    "status": "INFO",
                    "reason": "ファイルサイズが0バイト",
                    "desc": build_tutor_desc(
                        detection='空のファイルです。エントロピー解析の対象外です。',
                        why_dangerous='空ファイルは解析対象になりません。',
                        mitre_key=None,
                        status='INFO',
                    ),
                }

            with open(filepath, 'rb') as f:
                data = f.read()

            entropy = self._shannon_entropy(data)
            filename = os.path.basename(filepath)
            file_ext = os.path.splitext(filename)[1].lower()

            status, reason, verdict, desc = self._analyze_entropy(
                entropy, filename, file_ext, file_size
            )

            return {
                "entropy": round(entropy, 3),
                "verdict": verdict,
                "status": status,
                "reason": reason,
                "desc": desc,
            }
        except PermissionError:
            return {
                "entropy": 0,
                "verdict": "アクセス拒否",
                "status": "WARNING",
                "reason": "ファイルへのアクセスが拒否された",
                "desc": build_tutor_desc(
                    detection=(
                        f'ファイルへのアクセス権限がありません。\n'
                        f'パス: {filepath}'
                    ),
                    why_dangerous=(
                        'システムファイルや他ユーザーのファイルは'
                        '権限不足で読み取れない場合があります。'
                        '管理者権限での再実行を検討してください。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 自分のユーザーフォルダ内のファイルはアクセス可能\n'
                        '異常: 通常アクセスできるファイルが突然アクセス拒否になった'
                    ),
                    next_steps=[
                        '管理者として実行して再解析する',
                        'ファイルの所有者とACLを確認する',
                    ],
                    status='WARNING',
                ),
            }
        except Exception as e:
            return {
                "entropy": 0,
                "verdict": f"解析エラー: {str(e)[:50]}",
                "status": "WARNING",
                "reason": f"エントロピー解析中にエラーが発生",
                "desc": f"ファイル解析中にエラーが発生しました: {str(e)[:100]}",
            }


    def _analyze_entropy(self, entropy, filename, file_ext, file_size):
        """エントロピー値に基づく危険度判定と統一フォーマット解説を生成"""

        size_str = f"{file_size / 1024:.1f}KB" if file_size < 1024 * 1024 else f"{file_size / (1024*1024):.1f}MB"

        # --- 高エントロピー圧縮ファイルの除外 ---
        compressed_exts = {'.zip', '.7z', '.rar', '.gz', '.bz2', '.xz',
                          '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4',
                          '.avi', '.mkv', '.pdf', '.docx', '.xlsx', '.pptx'}
        if file_ext in compressed_exts and entropy > 7.0:
            return (
                "INFO",
                f"圧縮/メディアファイル (エントロピー: {entropy:.3f})",
                f"高エントロピー (圧縮形式: {file_ext})",
                build_tutor_desc(
                    detection=(
                        f'ファイル「{filename}」のエントロピーは{entropy:.3f}です。\n'
                        f'サイズ: {size_str}'
                    ),
                    why_dangerous=(
                        f'圧縮ファイルやメディアファイル（{file_ext}）は元々データが圧縮されているため、'
                        f'高いエントロピー値を示すのは正常です。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        f'正常: {file_ext}形式のファイルはエントロピー7.0以上が一般的\n'
                        '異常: 拡張子が偽装されている場合（例: .jpg だが中身はEXE）'
                    ),
                    status='INFO',
                ),
            )

        # --- 非常に高いエントロピー（7.5以上）: 暗号化の疑い ---
        if entropy >= 7.5:
            return (
                "DANGER",
                f"極高エントロピー: {entropy:.3f} (暗号化の疑い)",
                "極高エントロピー (暗号化/ランサムウェア疑い)",
                build_tutor_desc(
                    detection=(
                        f'ファイル「{filename}」のエントロピーが{entropy:.3f}と'
                        f'極めて高い値を示しています。\n'
                        f'サイズ: {size_str}'
                    ),
                    why_dangerous=(
                        'シャノンエントロピーが7.5を超えるファイルは、'
                        'データがほぼ完全にランダム化されており、以下の可能性があります：\n'
                        '・ランサムウェアによって暗号化されたファイル\n'
                        '・パッカー（UPX、Themida等）で難読化されたマルウェア\n'
                        '・カスタム暗号化で保護された攻撃ツール\n'
                        '理論上の最大値は8.0で、正規のテキストファイルや'
                        '一般的なEXEファイルは通常4.0〜6.5の範囲に収まります。'
                    ),
                    mitre_key='dna_high_entropy',
                    normal_vs_abnormal=(
                        '正常: テキストファイルは2.0〜5.0、一般的なEXEは4.0〜6.5\n'
                        '異常: 7.5以上はほぼ確実に暗号化・パック・圧縮されたデータ'
                    ),
                    next_steps=[
                        'ファイルのハッシュ値（SHA256）を取得し、VirusTotalで検索する',
                        'ファイルのデジタル署名を確認する（署名なし=要注意）',
                        '同一フォルダ内の他のファイルも暗号化されていないか確認する'
                        '（ランサムウェアの場合、複数ファイルが同時に暗号化される）',
                        'ファイルの拡張子が変更されていないか確認する',
                    ],
                    status='DANGER',
                ),
            )

        # --- 高エントロピー（7.0〜7.5）: パック/圧縮の疑い ---
        if entropy >= 7.0:
            return (
                "WARNING",
                f"高エントロピー: {entropy:.3f} (パック疑い)",
                "高エントロピー (パック/圧縮の疑い)",
                build_tutor_desc(
                    detection=(
                        f'ファイル「{filename}」のエントロピーが{entropy:.3f}と'
                        f'高い値を示しています。\n'
                        f'サイズ: {size_str}'
                    ),
                    why_dangerous=(
                        'エントロピー7.0以上のファイルは、'
                        'パッカー（UPX、ASPack等）で圧縮・難読化されている可能性があります。'
                        'マルウェアの約70%はパッキングされており、'
                        'セキュリティソフトの静的解析を回避する目的で使用されます。'
                        'ただし、正規のソフトウェアでもインストーラ等がパックされている場合があります。'
                    ),
                    mitre_key='dna_packed',
                    normal_vs_abnormal=(
                        '正常: インストーラやSFX形式の自己解凍書庫は7.0前後になることがある\n'
                        '異常: 小さなEXEファイル（数百KB）でエントロピーが7.0以上は要注意'
                    ),
                    next_steps=[
                        'ファイルのハッシュ値をVirusTotalで検索する',
                        'ファイルのデジタル署名を確認する',
                        'Detect It Easy等のツールでパッカーの種類を特定する',
                        '正規のソフトウェアでない場合、サンドボックスで動的解析を実施する',
                    ],
                    status='WARNING',
                ),
            )

        # --- やや高いエントロピー（6.5〜7.0）---
        if entropy >= 6.5:
            return (
                "INFO",
                f"やや高エントロピー: {entropy:.3f}",
                "やや高エントロピー (コンパイル済みバイナリの範囲)",
                build_tutor_desc(
                    detection=(
                        f'ファイル「{filename}」のエントロピーは{entropy:.3f}です。\n'
                        f'サイズ: {size_str}'
                    ),
                    why_dangerous=(
                        'コンパイル済みの実行ファイル（.exe/.dll）では'
                        '6.0〜7.0のエントロピーは一般的な範囲です。'
                        'ただし他の不審な兆候（不審なパス、未署名等）と'
                        '組み合わさっている場合は追加調査を推奨します。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: C/C++でコンパイルされたEXEは6.0〜7.0が一般的\n'
                        '異常: テキストファイルやスクリプトでこの値が出る場合は難読化の疑い'
                    ),
                    status='INFO',
                ),
            )

        # --- 低エントロピー（1.0未満）---
        if entropy < 1.0:
            return (
                "INFO",
                f"低エントロピー: {entropy:.3f}",
                "低エントロピー (ほぼ同一データ)",
                build_tutor_desc(
                    detection=(
                        f'ファイル「{filename}」のエントロピーが{entropy:.3f}と'
                        f'非常に低い値を示しています。\n'
                        f'サイズ: {size_str}'
                    ),
                    why_dangerous=(
                        'エントロピーが1.0未満のファイルは、ほぼ同一のバイトで構成されています。'
                        'NULLパディングされたファイル、空のログファイル、'
                        'または特定パターンで埋められたテストファイルの可能性があります。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: ログファイルや初期化直後のDBファイルは低エントロピーになる\n'
                        '異常: 実行ファイルでエントロピーが極端に低い場合はデータ破損の可能性'
                    ),
                    status='INFO',
                ),
            )

        # --- 正常範囲（1.0〜6.5）---
        return (
            "SAFE",
            "",
            "正常",
            build_tutor_desc(
                detection=(
                    f'ファイル「{filename}」のエントロピーは{entropy:.3f}で正常範囲内です。\n'
                    f'サイズ: {size_str}'
                ),
                why_dangerous='',
                mitre_key=None,
                normal_vs_abnormal=(
                    'テキストファイルは2.0〜5.0、一般的なEXE/DLLは4.0〜6.5が正常範囲です。'
                ),
                status='SAFE',
            ),
        )


    def _shannon_entropy(self, data):
        """シャノンエントロピーの計算（最適化版）"""
        if not data:
            return 0.0

        length = len(data)
        # バイト出現頻度をカウント（bytearrayを使った高速化）
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy