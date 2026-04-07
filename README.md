# Sacabambaspis

**Windows フォレンジック・アーティファクト収集・解析ツール**

Sacabambaspis は、Windows 端末上でインシデント対応に必要なフォレンジック・アーティファクトを収集・解析するためのローカル動作型ツールです。Flask ベースの Web UI を通じて、プロセス、メモリ、ネットワーク、レジストリ、イベントログなど多角的な観点から調査を行えます。

---

## 特徴

- **完全オフライン動作** — インターネット接続不要。現場端末で即座に実行可能
- **単一 exe 配布** — PyInstaller による exe 化対応。USB メモリで持ち込み可能
- **Web UI** — ブラウザベースの日本語 UI。専用ソフトのインストール不要
- **MITRE ATT&CK マッピング** — 全検出項目に MITRE ATT&CK ID を紐付け
- **YARA スキャン** — Neo23x0/signature-base（700+ ルール）対応
- **アルゴリズム解説 Wiki** — 各検出ロジックの業務フロー付き解説を内蔵

---

## 解析機能一覧

| タブ | 機能 | 主な検出項目 |
|------|------|-------------|
| プロセス解析 | プロセス列挙・偽プロセス検出 | マスカレード、インジェクション、ホロウイング |
| メモリ抽出 | メモリダンプ・PE 抽出・文字列解析 | RWX 領域、IOC、YARA マッチ |
| ネットワーク | TCP/UDP 接続一覧・C2 通信検出 | 不審な外部通信、既知 C2 ポート |
| ファイル検査 | OLE/OOXML/PDF/PE 構造解析 | マクロ、JavaScript、パッキング |
| 永続化 | レジストリ・タスク・サービス・WMI | AutoRun、スケジュールタスク、WMI サブスクリプション |
| イベントログ | セキュリティログ・PowerShell ログ | ブルートフォース、不審なプロセス生成 |
| SRUM | ネットワーク使用量・実行履歴 | データ窃取の痕跡、削除済みプログラムの実行証拠 |
| PCA | プログラム互換性アシスタント解析 | 過去の実行履歴復元 |
| ADS | 代替データストリーム検出 | 隠蔽されたデータ |
| Recall | Windows Recall 解析 | スクリーンショット履歴 |
| WSL | WSL 環境検出 | Linux サブシステムの存在確認 |
| DNA | ファイルハッシュ・類似度解析 | マルウェアファミリー推定 |
| YARA 管理 | ルール管理・手動スキャン・GitHub 取込 | カスタムルール運用 |

---

## 環境要件

| 項目 | 要件 |
|------|------|
| OS | Windows 10 / 11（64bit） |
| Python | 3.11 以上（ソース実行時） |
| 権限 | 管理者権限推奨（メモリダンプ等に必要） |
| ブラウザ | Chrome / Edge / Firefox（最新版） |

---

## インストール・起動

### exe 版（推奨）

1. `Sacabambaspis.exe` を対象端末にコピー
2. YARA ルールを使用する場合は `yara_rules/` フォルダを exe と同じ階層に配置
3. `Sacabambaspis.exe` を管理者として実行
4. ブラウザが自動で開きます（デフォルトは `http://127.0.0.1:` + 空きポート。5000 付近を使用）

#### セキュリティ製品（McAfee 等）に削除・隔離される場合

PyInstaller の単一 EXE と、プロセス／メモリ／レジストリを読む挙動は、**ヒューリスティックに「疑わしい」と判定されやすい**です。悪意のあるコードではなく、**誤検知（false positive）**で起きがちです。

**対処の例：**

- **除外（推奨）**: McAfee の「除外リスト」に、`Sacabambaspis.exe` を置いたフォルダ、または exe 本体のパスを追加する。
- **隔離から復元**後、上記の除外を設定してから再実行する。
- **再ビルド**: リポジトリの `Sacabambaspis.spec` は **UPX 圧縮を無効**（`upx=False`）にしてあり、パッカー検知を抑えやすくしています。古い exe の場合は `build.bat` で作り直す。
- **配布用**に誤検知を減らすには、**コード署名証明書**で EXE に署名する方法があります（有償・手続きあり）。

### ソースから実行

```bash
git clone https://github.com/matrix9neonebuchadnezzar2199-sketch/Sacabambaspis.git
cd Sacabambaspis

pip install -r requirements.txt

python main.py
```

### exe を自前ビルドする場合

```bash
pip install -r requirements-dev.txt
build.bat
```

**PyInstaller** は `requirements-dev.txt` にのみ含めています（実行時の `pip install -r requirements.txt` だけでは exe 化できません）。**Sigma**（`sigma-rule-matcher` / `pySigma`）は `collectors/sigma_engine.py` のイベントログ連携用です。未インストール時は Sigma 照合のみスキップされます。

### 自動テスト（開発者向け）

```bash
pip install -r requirements-dev.txt
pytest
```

`tests/` 配下の単体テストは `pytest` で実行（件数はテスト追加により変動）。

---

## YARA ルール

YARA ルールは exe に同梱せず、外部フォルダとして管理します（Windows Defender 誤検知回避のため）。

### セットアップ

1. YARA 管理タブから「GitHub から取込」をクリック
2. Neo23x0/signature-base が自動ダウンロードされます
3. または手動で `yara_rules/` フォルダに `.yar` / `.yara` ファイルを配置

### フォルダ構成

```
Sacabambaspis.exe（または main.py）
├── yara_rules/
│   ├── apt_*.yar
│   ├── crime_*.yar
│   ├── exploit_*.yar
│   └── ...（700+ ルール）
└── dumps/（メモリダンプ出力先）
```

### PE-sieve（任意）

プロセス解析でのメモリインジェクション検知を強化するには、[PE-sieve](https://github.com/hasherezade/pe-sieve) の `pe-sieve64.exe`（および任意で HollowsHunter）を、プロジェクト直下の `tools/` フォルダに配置してください。配置がない場合、該当検知はスキップされます。

---

## ビルド（exe 化）

```bash
python -m PyInstaller Sacabambaspis.spec --noconfirm
```

出力先: `dist/Sacabambaspis/Sacabambaspis.exe`

### ビルド時の注意

- `Sacabambaspis.spec` に全設定が定義済み
- `web/` フォルダ（テンプレート・静的ファイル）は自動同梱
- `yara_rules/` は同梱しない（Defender 誤検知回避）
- `console=False` でコンソールウィンドウ非表示

---

## プロジェクト構成

```
Sacabambaspis/
├── main.py                    # エントリーポイント
├── web/
│   ├── app.py                 # Flask ルーティング（全 API）
│   ├── templates/
│   │   └── index.html         # SPA（単一 HTML）
│   └── static/
│       └── wiki/
│           ├── wiki-data.js   # アルゴリズム解説データ（25 記事）
│           └── wiki-loader.js # Wiki UI 制御
├── collectors/                # コレクタモジュール
├── utils/
│   ├── yara_manager.py        # YARA ルール管理
│   └── path_helper.py         # パス解決（exe/通常実行対応）
├── yara_rules/                # YARA ルール（exe 非同梱）
├── Sacabambaspis.spec         # PyInstaller 設定
├── requirements.txt           # Python 依存関係
├── build.bat                  # ビルドスクリプト
└── start.bat                  # 起動スクリプト
```

---

## MITRE ATT&CK カバレッジ

本ツールは以下の戦術・技術を検出対象としています。

| 戦術 | 主な技術 ID |
|------|------------|
| 初期アクセス | T1566.001（フィッシング添付） |
| 実行 | T1059（スクリプト実行）、T1204（ユーザー実行） |
| 永続化 | T1547.001（レジストリ Run）、T1053.005（タスク）、T1543.003（サービス）、T1546.003（WMI） |
| 権限昇格 | T1055（プロセスインジェクション） |
| 防御回避 | T1036.005（マスカレード）、T1027（難読化）、T1070.001（ログ消去） |
| 探索 | T1057（プロセス探索） |
| C2 | T1071（アプリケーション層プロトコル）、T1573（暗号化チャネル） |
| データ窃取 | T1041（C2 チャネル経由） |

---

## アルゴリズム解説 Wiki

ツール内蔵の Wiki 機能で、各検出アルゴリズムの詳細を確認できます。

- ヘッダー右上の 📖 ボタンをクリック
- 8 カテゴリ・25 記事を収録
- 各記事には「異常判定の業務フロー」「正常判定の業務フロー」を掲載
- 検索バーでキーワード検索可能

---

## ライセンス

### 使用ライブラリ

| ライブラリ | ライセンス | 用途 |
|-----------|-----------|------|
| Flask | BSD-3 | Web フレームワーク |
| psutil | BSD-3 | プロセス・ネットワーク情報 |
| olefile | BSD-2 | OLE ファイル解析 |
| PyPDF2 | BSD-3 | PDF 解析 |
| yara-python | Apache-2.0 | YARA ルールエンジン |

### YARA ルール

Neo23x0/signature-base は CC BY-NC 4.0 ライセンスです。商用利用時は条件を確認してください。

---

## トラブルシューティング

| 症状 | 原因 | 対処法 |
|------|------|--------|
| exe が起動しない | Defender がブロック | 除外設定に追加 |
| メモリダンプ失敗 | 管理者権限不足 | 管理者として実行 |
| YARA スキャンでマッチなし | ルール未配置 | `yara_rules/` フォルダを配置 |
| ブラウザが開かない | ポート競合 | アプリが 5000〜 付近の空きポートを自動選択 |
| 文字化け | エンコーディング | ブラウザの文字コードを UTF-8 に設定 |
