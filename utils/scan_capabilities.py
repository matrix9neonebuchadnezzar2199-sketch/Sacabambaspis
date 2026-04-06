# -*- coding: utf-8 -*-
"""
本プロダクトのスキャン範囲と、エンタープライズフォレンジック製品との差分の要約（API/UI 向け）。
"""


def build_scan_capability_report(security_surface_count=0):
    """
    security_surface_count: スキャン結果に含まれた security_surface 行数（任意）。
    """
    gaps = [
        {
            "topic": "ディスクイメージ・死体解剖",
            "gap": "物理ディスクのセクタ単位イメージ、VSC 全列挙、未割当クラスタ解析は未実装。",
        },
        {
            "topic": "タイムライン統合 DB",
            "gap": "Plaso / Timesketch 級の全アーティファクト時系列マージは未実装（同一パス相関は軽量版）。",
        },
        {
            "topic": "カーネル・ハイパーバイザ",
            "gap": "IDT / SSDT / コールバック / 隠しドライバの網羅は要専用ドライバまたは外部ツール。",
        },
        {
            "topic": "商用 EDR",
            "gap": "ベンダー独自テレメトリ（生プロセスイベントのクラウド相関等）は API 未統合。",
        },
        {
            "topic": "クラウド ID",
            "gap": "Entra / AWS / GCP のログ相関は未対象（エンドポイント単体スコープ）。",
        },
    ]

    strengths = [
        "複数 Windows アーティファクト（痕跡・永続化・メモリ・ネットワーク等）の単体ホスト集約",
        "IOC / 署名 / ヒューリスティック / Sysmon（導入時）の併用",
        "同一パス横断相関・脅威サマリー",
    ]

    return {
        "product_tier": "endpoint_triage",
        "summary_ja": (
            "本スキャンは「管理者端末の初動・健診」向けであり、"
            "法執行・大規模インシデント向けのフルディスクイメージ解析や "
            "EDR/SIEM クラウド相関の代替にはなりません。"
        ),
        "strengths": strengths,
        "gaps_vs_enterprise_forensic": gaps,
        "security_surface_rows": security_surface_count,
    }
