# -*- coding: utf-8 -*-
"""
ホスト上のセキュリティ製品の表面チェック（WMI SecurityCenter2）。
カーネル深部・商用 EDR の内部テレメトリは取得しないが、
「何が入っているか」の把握とガイダンス用の INFO を返す。
"""
import json
import subprocess

from utils.tutor_template import build_tutor_desc


class SecuritySurfaceCollector:
    """Windows セキュリティセンター経由の AV 製品列挙（ユーザー空間・読み取りのみ）。"""

    def scan(self):
        results = []
        results.extend(self._antivirus_products())
        results.append(self._kernel_scope_note())
        results.append(self._edr_scope_note())
        return results

    def _antivirus_products(self):
        out = []
        ps = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
  $p = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
    Select-Object displayName, productState, instanceGuid
  $p | ConvertTo-Json -Compress -Depth 3
} catch {
  '[]'
}
"""
        try:
            raw = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=0x08000000,
                timeout=45,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            out.append(
                {
                    "source": "SecurityCenter2",
                    "artifact": "AntiVirusProduct",
                    "status": "INFO",
                    "reason": "セキュリティ製品一覧を取得できませんでした（権限・WMI）",
                    "desc": build_tutor_desc(
                        detection="WMI SecurityCenter2 への問い合わせに失敗しました。",
                        why_dangerous="",
                        normal_vs_abnormal="管理者権限・セキュリティソフトの自己防護でブロックされる場合があります。",
                        status="INFO",
                    ),
                }
            )
            return out

        raw = (raw or "").strip()
        if not raw or raw == "[]":
            out.append(
                {
                    "source": "SecurityCenter2",
                    "artifact": "AntiVirusProduct",
                    "status": "INFO",
                    "reason": "登録された AV 製品が報告されませんでした",
                    "desc": build_tutor_desc(
                        detection="Security Center に AV 製品が見つかりませんでした。",
                        why_dangerous="無効化・未導入の可能性があります。組織ポリシーを確認してください。",
                        status="INFO",
                    ),
                }
            )
            return out

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = []
        if isinstance(data, dict):
            data = [data]

        for row in data:
            name = (row.get("displayName") or "Unknown").strip()
            state = row.get("productState")
            out.append(
                {
                    "source": "SecurityCenter2",
                    "artifact": name,
                    "detail": f"productState={state}",
                    "status": "INFO",
                    "reason": f"セキュリティ製品: {name}",
                    "desc": build_tutor_desc(
                        detection=f"報告されたセキュリティ製品: {name}",
                        why_dangerous="",
                        normal_vs_abnormal="productState はベンダー固有ビットマスクです。詳細は各製品コンソールで確認してください。",
                        status="INFO",
                    ),
                }
            )
        return out

    def _kernel_scope_note(self):
        return {
            "source": "スキャン範囲",
            "artifact": "カーネル／ドライバ深層",
            "status": "INFO",
            "reason": "本ツールはユーザーモード API 中心のため、カーネルメモリ・未公開コールバックの網羅解析は対象外です",
            "desc": build_tutor_desc(
                detection=(
                    "ルートキットのコールバック、ドライバオブジェクトの完全列挙、"
                    "物理メモリの解析には専用カーネルドライバまたは Velociraptor / 商用 EDR が一般的です。"
                ),
                why_dangerous="高度な侵害ではカーネル層に潜むことがあります。",
                normal_vs_abnormal="本スキャンでクリーンでも、疑わしい場合はメモリフォレンジック・別メディア調査を検討してください。",
                mitre_key=None,
                status="INFO",
            ),
        }

    def _edr_scope_note(self):
        return {
            "source": "スキャン範囲",
            "artifact": "商用 EDR テレメトリ",
            "status": "INFO",
            "reason": "CrowdStrike / SentinelOne 等の独自イベント・テレメ API は統合していません",
            "desc": build_tutor_desc(
                detection=(
                    "EDR のプロセス樹・ネットワーク・レジストリの相関は各ベンダー API または "
                    "Microsoft 365 Defender ポータルで参照するのが確実です。"
                    "本アプリはオフライン単体ホスト向けのヒューリスティックに特化しています。"
                ),
                why_dangerous="",
                normal_vs_abnormal="組織運用では EDR と SIEM を正とし、本ツールは補助・初動用として位置づけてください。",
                status="INFO",
            ),
        }
