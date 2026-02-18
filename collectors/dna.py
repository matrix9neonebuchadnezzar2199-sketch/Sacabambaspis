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
                    "desc": (
                        "【検知内容】指定されたファイルが存在しません。\n"
                        f"パス: {filepath}\n\n"
                        "【なぜ危険か】解析対象ファイルが見つからない場合、"
                        "攻撃者がマルウェアを実行後に証拠隠滅のため削除した可能性があります。"
                        "またはファイルパスの指定が誤っている可能性もあります。\n\n"
                        "【次の調査手順】\n"
                        "① Prefetch/PCA/CAM DBで当該ファイルの実行痕跡を確認する\n"
                        "② ごみ箱（$Recycle.Bin）にファイルが移動されていないか確認する\n"
                        "③ Volume Shadow Copyからファイルの復元を試みる"
                    ),
                }

            file_size = os.path.getsize(filepath)
            if file_size > 10 * 1024 * 1024:
                return {
                    "entropy": 0,
                    "verdict": "スキップ (10MB超)",
                    "status": "INFO",
                    "reason": f"ファイルサイズが大きいためスキップ ({file_size // (1024*1024)}MB)",
                    "desc": (
                        "【検知内容】ファイルサイズが10MBを超えるためエントロピー解析をスキップしました。\n"
                        f"ファイルサイズ: {file_size // (1024*1024)}MB\n\n"
                        "大きなファイルの場合、先頭部分のみの解析や"
                        "ハッシュ値によるVirusTotal照合を推奨します。"
                    ),
                }

            if file_size == 0:
                return {
                    "entropy": 0,
                    "verdict": "空ファイル",
                    "status": "INFO",
                    "reason": "ファイルサイズが0バイト",
                    "desc": "空のファイルです。エントロピー解析の対象外です。",
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
                "desc": (
                    "【検知内容】ファイルへのアクセス権限がありません。\n"
                    f"パス: {filepath}\n\n"
                    "【なぜ危険か】システムファイルや他ユーザーのファイルは"
                    "権限不足で読み取れない場合があります。"
                    "管理者権限での再実行を検討してください。\n\n"
                    "【次の調査手順】\n"
                    "① 管理者として実行して再解析する\n"
                    "② ファイルの所有者とACLを確認する"
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
        """エントロピー値に基づく危険度判定と3段構成解説を生成"""

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
                f"【検知内容】ファイル「{filename}」のエントロピーは{entropy:.3f}です。\n"
                f"サイズ: {size_str}\n\n"
                f"圧縮ファイルやメディアファイル（{file_ext}）は元々データが圧縮されているため、"
                f"高いエントロピー値を示すのは正常です。"
            )

        # --- 非常に高いエントロピー（7.5以上）: 暗号化の疑い ---
        if entropy >= 7.5:
            return (
                "DANGER",
                f"極高エントロピー: {entropy:.3f} (暗号化の疑い)",
                "極高エントロピー (暗号化/ランサムウェア疑い)",
                f"【検知内容】ファイル「{filename}」のエントロピーが{entropy:.3f}と"
                f"極めて高い値を示しています。\n"
                f"サイズ: {size_str}\n\n"
                f"【なぜ危険か】シャノンエントロピーが7.5を超えるファイルは、"
                f"データがほぼ完全にランダム化されており、以下の可能性があります：\n"
                f"・ランサムウェアによって暗号化されたファイル\n"
                f"・パッカー（UPX、Themida等）で難読化されたマルウェア\n"
                f"・カスタム暗号化で保護された攻撃ツール\n"
                f"理論上の最大値は8.0で、正規のテキストファイルや"
                f"一般的なEXEファイルは通常4.0〜6.5の範囲に収まります。\n\n"
                f"【次の調査手順】\n"
                f"① ファイルのハッシュ値（SHA256）を取得し、VirusTotalで検索する\n"
                f"② ファイルのデジタル署名を確認する（署名なし=要注意）\n"
                f"③ 同一フォルダ内の他のファイルも暗号化されていないか確認する"
                f"（ランサムウェアの場合、複数ファイルが同時に暗号化される）\n"
                f"④ ファイルの拡張子が変更されていないか確認する\n\n"
                f"【MITRE ATT&CK】{MITRE_MAP.get('dna_high_entropy', ('','',''))[0]} - "
                f"{MITRE_MAP.get('dna_high_entropy', ('','',''))[1]}\n"
                f"{MITRE_MAP.get('dna_high_entropy', ('','',''))[2]}"
            )

        # --- 高エントロピー（7.0〜7.5）: パック/圧縮の疑い ---
        if entropy >= 7.0:
            return (
                "WARNING",
                f"高エントロピー: {entropy:.3f} (パック疑い)",
                "高エントロピー (パック/圧縮の疑い)",
                f"【検知内容】ファイル「{filename}」のエントロピーが{entropy:.3f}と"
                f"高い値を示しています。\n"
                f"サイズ: {size_str}\n\n"
                f"【なぜ危険か】エントロピー7.0以上のファイルは、"
                f"パッカー（UPX、ASPack等）で圧縮・難読化されている可能性があります。"
                f"マルウェアの約70%はパッキングされており、"
                f"セキュリティソフトの静的解析を回避する目的で使用されます。"
                f"ただし、正規のソフトウェアでもインストーラ等がパックされている場合があります。\n\n"
                f"【次の調査手順】\n"
                f"① ファイルのハッシュ値をVirusTotalで検索する\n"
                f"② ファイルのデジタル署名を確認する\n"
                f"③ Detect It Easy等のツールでパッカーの種類を特定する\n"
                f"④ 正規のソフトウェアでない場合、サンドボックスで動的解析を実施する\n\n"
                f"【MITRE ATT&CK】{MITRE_MAP.get('dna_packed', ('','',''))[0]} - "
                f"{MITRE_MAP.get('dna_packed', ('','',''))[1]}\n"
                f"{MITRE_MAP.get('dna_packed', ('','',''))[2]}"
            )

        # --- やや高いエントロピー（6.5〜7.0）---
        if entropy >= 6.5:
            return (
                "INFO",
                f"やや高エントロピー: {entropy:.3f}",
                "やや高エントロピー (コンパイル済みバイナリの範囲)",
                f"【検知内容】ファイル「{filename}」のエントロピーは{entropy:.3f}です。\n"
                f"サイズ: {size_str}\n\n"
                f"コンパイル済みの実行ファイル（.exe/.dll）では"
                f"6.0〜7.0のエントロピーは一般的な範囲です。"
                f"ただし他の不審な兆候（不審なパス、未署名等）と"
                f"組み合わさっている場合は追加調査を推奨します。"
            )

        # --- 低エントロピー（1.0未満）---
        if entropy < 1.0:
            return (
                "INFO",
                f"低エントロピー: {entropy:.3f}",
                "低エントロピー (ほぼ同一データ)",
                f"【検知内容】ファイル「{filename}」のエントロピーが{entropy:.3f}と"
                f"非常に低い値を示しています。\n"
                f"サイズ: {size_str}\n\n"
                f"エントロピーが1.0未満のファイルは、ほぼ同一のバイトで構成されています。"
                f"NULLパディングされたファイル、空のログファイル、"
                f"または特定パターンで埋められたテストファイルの可能性があります。"
            )

        # --- 正常範囲（1.0〜6.5）---
        return (
            "SAFE",
            "",
            "正常",
            f"ファイル「{filename}」のエントロピーは{entropy:.3f}で正常範囲内です。\n"
            f"サイズ: {size_str}"
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