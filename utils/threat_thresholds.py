# -*- coding: utf-8 -*-
"""脅威レベル・相関メッセージ用の閾値（魔法数の単一ソース）。"""

# DANGER が出たカテゴリ数 → CRITICAL / HIGH / MEDIUM
THREAT_DC_CRITICAL_MIN = 5
THREAT_DC_HIGH_MIN = 3

# 「複数カテゴリで DANGER」相関コメント用
THREAT_CORR_MULTI_SEVERE_MIN = 5
THREAT_CORR_MULTI_MODERATE_MIN = 3
