var WIKI_DATA = [
  // ========================================
  // Category 1: 概要 (overview)
  // ========================================
  {
    id: "overview-purpose",
    category: "概要",
    categoryId: "overview",
    title: "このツールの目的と設計思想",
    content: {
      summary: "Sacabambaspis は、Windows 端末上でフォレンジック・アーティファクトを収集・解析するためのローカル動作型ツールです。Flask ベースの Web UI を通じて、プロセス、メモリ、ネットワーク、レジストリ、イベントログなど多角的な観点からインシデントの痕跡を調査できます。\n\nPyInstaller による単一 exe 化に対応しており、USB メモリ等で現場端末に持ち込んで即座に実行できるポータビリティを重視しています。インターネット接続を必要とせず、完全オフラインで動作します。",
      points: "・管理者権限で実行することで、メモリダンプやレジストリの深い解析が可能になります\n・YARA ルールは exe に同梱せず、隣接フォルダから読み込む設計です（Defender 誤検知回避）\n・検出結果には MITRE ATT&CK ID を紐付け、脅威の文脈を把握できます\n・全 UI は日本語で提供され、初学者にも扱いやすい設計です",
      logic: null,
      flow_danger: null,
      flow_safe: null,
      mitre: null,
      references: "・MITRE ATT&CK: https://attack.mitre.org/\n・NIST SP 800-86 (Guide to Integrating Forensic Techniques): https://csrc.nist.gov/publications/detail/sp/800-86/final\n・SANS Digital Forensics: https://www.sans.org/digital-forensics-incident-response/"
    }
  },
  {
    id: "overview-flow",
    category: "概要",
    categoryId: "overview",
    title: "フォレンジック解析の基本フロー",
    content: {
      summary: "デジタルフォレンジックにおける解析は、一般的に「収集（Collection）→ 検査（Examination）→ 分析（Analysis）→ 報告（Reporting）」の4段階で進行します。\n\nSacabambaspis はこのうち「収集」と「検査」を自動化し、「分析」を支援するツールです。最終的な判断（報告）はアナリストが行いますが、各検出項目に業務フローと MITRE マッピングを付与することで、分析の精度と速度を高めます。",
      points: "・揮発性の高いデータ（メモリ、ネットワーク接続）から先に収集するのが原則です\n・収集したアーティファクトは改変せず保全することが重要です\n・各タブは独立して動作するため、必要な解析から着手できます\n・解析結果はブラウザ上で確認でき、CSV エクスポートにも対応しています",
      logic: "Sacabambaspis の解析フローは以下の順序を推奨します：\n\n1. プロセス解析タブ → 実行中プロセスの全体像把握\n2. ネットワークタブ → 外部通信の確認\n3. メモリ抽出タブ → 不審プロセスのメモリダンプ取得\n4. ファイル検査タブ → 不審ファイルの構造解析\n5. 永続化タブ → AutoRun / タスク / サービスの確認\n6. イベントログタブ → 時系列での行動追跡\n7. YARA 管理タブ → カスタムルールでの横断スキャン",
      flow_danger: null,
      flow_safe: null,
      mitre: null,
      references: "・NIST SP 800-86: https://csrc.nist.gov/publications/detail/sp/800-86/final\n・RFC 3227 (Evidence Collection): https://datatracker.ietf.org/doc/html/rfc3227\n・JPCERT/CC インシデント対応マニュアル: https://www.jpcert.or.jp/"
    }
  },

  // ========================================
  // Category 2: プロセス解析 (process)
  // ========================================
  {
    id: "process-enumeration",
    category: "プロセス解析",
    categoryId: "process",
    title: "プロセス列挙の仕組み",
    content: {
      summary: "Windows 上で動作する全プロセスを psutil ライブラリを用いて列挙し、PID、プロセス名、実行パス、親プロセス（PPID）、コマンドライン引数、起動ユーザーなどの属性情報を収集します。\n\nこの情報は後続の偽プロセス検出やインジェクション検出の基盤データとなります。",
      points: "・System（PID 4）や Idle（PID 0）など、正常なシステムプロセスの特徴を把握しておくことが重要です\n・実行パスが空白やアクセス拒否のプロセスは、権限不足またはカーネルプロセスの可能性があります\n・同名プロセスが複数存在すること自体は正常ですが、実行パスの違いに注目します",
      logic: "psutil.process_iter() で全プロセスを走査し、各プロセスから以下を取得します：\n・pid, name, exe, ppid, cmdline, username, create_time\n・アクセス拒否（AccessDenied）の場合は N/A として記録\n・取得結果をJSON形式でフロントエンドに返却",
      flow_danger: null,
      flow_safe: null,
      mitre: "T1057 Process Discovery\n攻撃者は侵入後、標的システムで動作中のプロセスを列挙して環境を把握します。防御側も同じ手法でプロセス一覧を取得し、不審なプロセスを特定します。",
      references: "・psutil documentation: https://psutil.readthedocs.io/\n・MITRE T1057: https://attack.mitre.org/techniques/T1057/"
    }
  },
  {
    id: "process-masquerade",
    category: "プロセス解析",
    categoryId: "process",
    title: "偽プロセス検出アルゴリズム",
    content: {
      summary: "攻撃者はマルウェアを svchost.exe や explorer.exe など正規プロセスに偽装して実行することがあります（プロセス・マスカレード）。本ツールは、既知の正規プロセスについて「正しい実行パス」「正しい親プロセス」「正しい実行ユーザー」のルールセットを保持し、逸脱を検出します。",
      points: "・svchost.exe は必ず C:\\Windows\\System32\\ から起動し、親は services.exe（PID は起動ごとに異なる）です\n・csrss.exe、wininit.exe、winlogon.exe なども検査対象です\n・正規パスから起動しているが引数が異常なケースにも注意が必要です\n・ファイル名の類似（svch0st.exe など）による偽装も対象です",
      logic: "1. 既知の正規プロセス名リスト（約15種）を定義\n2. 各プロセスに対して以下を検査：\n   a. 実行パスが正規パスと一致するか\n   b. 親プロセスが期待される親と一致するか\n   c. 実行ユーザーが期待されるユーザー（SYSTEM等）と一致するか\n3. いずれかが不一致の場合、異常フラグを立てて理由を記録\n4. 類似名検出: レーベンシュタイン距離による typosquatting 検知",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: svchost.exe が C:\\Users\\Public\\ から起動していることを検出\n  ↓\n確認: 該当プロセスの PID・起動時刻・コマンドライン引数を記録\n  ↓\n確認: 親プロセス（PPID）を追跡し、起動チェーンを確認\n  ↓\n結論: 正規パス外からの svchost.exe 起動はマルウェアの可能性が高い\n  ↓\n対応: メモリダンプを取得し、YARA スキャンを実施。ネットワーク接続も確認。インシデント対応プロセスへエスカレーション",
      flow_safe: "【正常判定の業務フロー】\n\n検知: svchost.exe が C:\\Windows\\System32\\svchost.exe から起動\n  ↓\n確認: 親プロセスが services.exe であることを確認\n  ↓\n確認: 実行ユーザーが SYSTEM / LOCAL SERVICE / NETWORK SERVICE のいずれか\n  ↓\n結論: 正規のサービスホストプロセスと判定。対応不要",
      mitre: "T1036.005 Masquerading: Match Legitimate Name or Location\n攻撃者は正規の Windows プロセス名や配置場所を模倣してマルウェアを偽装します。防御側はパスと親プロセスの整合性チェックで検出できます。",
      references: "・MITRE T1036.005: https://attack.mitre.org/techniques/T1036/005/\n・SANS Hunt Evil Poster: https://www.sans.org/posters/hunt-evil/\n・ECC-CERT プロセス正規化ガイド"
    }
  },
  {
    id: "process-injection",
    category: "プロセス解析",
    categoryId: "process",
    title: "プロセスインジェクション検出",
    content: {
      summary: "プロセスインジェクションは、攻撃者が正規プロセスのメモリ空間に悪意あるコードを注入して実行する手法です。これにより、セキュリティ製品の検出を回避しつつ、正規プロセスの権限で悪意ある活動を行えます。\n\n本ツールでは、プロセスのメモリ領域の権限属性（特に RWX: 読み書き実行可能）を検査し、インジェクションの痕跡を検出します。",
      points: "・RWX（PAGE_EXECUTE_READWRITE）権限を持つメモリ領域は、通常のアプリケーションではほとんど使用されません\n・.NET アプリケーションや JIT コンパイラは正当な理由で RWX を使用する場合があります\n・検出されたプロセスが正規プロセス（explorer.exe 等）の場合、インジェクションの可能性が高まります\n・VirtualAllocEx + WriteProcessMemory + CreateRemoteThread は典型的なインジェクションパターンです",
      logic: "1. 対象プロセスのメモリリージョンを VirtualQueryEx で走査\n2. PAGE_EXECUTE_READWRITE（RWX）権限を持つリージョンを特定\n3. リージョンのサイズと数をカウント\n4. 閾値（RWX リージョン数 > 3 またはサイズ > 1MB）を超える場合に警告\n5. 該当プロセスの他の異常指標（偽プロセス判定結果等）と複合評価",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: explorer.exe に大量の RWX メモリリージョン（8個、合計 4.2MB）を検出\n  ↓\n確認: 当該プロセスの起動時刻と通常の explorer.exe の挙動を比較\n  ↓\n確認: ネットワーク接続タブで当該 PID の外部通信を確認\n  ↓\n結論: 正規プロセスへのコードインジェクションの可能性が高い\n  ↓\n対応: メモリダンプを取得し、RWX 領域を抽出して YARA スキャン。PE ヘッダの有無を確認。C2 通信のIOC を抽出",
      flow_safe: "【正常判定の業務フロー】\n\n検知: java.exe に RWX メモリリージョン（2個、合計 512KB）を検出\n  ↓\n確認: Java/JIT コンパイラは動的コード生成のため RWX を正当に使用\n  ↓\n確認: リージョン数・サイズが JIT の一般的な範囲内\n  ↓\n結論: JIT コンパイラによる正当な RWX 使用と判定。対応不要",
      mitre: "T1055 Process Injection\n攻撃者は別プロセスのアドレス空間にコードを注入し、そのプロセスのコンテキストで実行します。検出回避・権限昇格・永続化に使用されます。\n\nサブテクニック例：\n・T1055.001 DLL Injection\n・T1055.003 Thread Execution Hijacking\n・T1055.012 Process Hollowing",
      references: "・MITRE T1055: https://attack.mitre.org/techniques/T1055/\n・Elastic Security: Process Injection detection: https://www.elastic.co/security-labs\n・Red Canary Threat Detection Report"
    }
  },
  {
    id: "process-hollowing",
    category: "プロセス解析",
    categoryId: "process",
    title: "プロセスホロウイング検出",
    content: {
      summary: "プロセスホロウイング（Process Hollowing）は、正規プロセスをサスペンド状態で起動し、そのメモリ内容を悪意あるコードで置き換えてから再開する手法です。外見上は正規プロセスとして動作するため、タスクマネージャーやプロセス一覧では発見が困難です。\n\n本ツールでは、プロセスのメモリイメージとディスク上の実行ファイルの不一致を検出することで、ホロウイングの痕跡を特定します。",
      points: "・ホロウイングされたプロセスは、ディスク上のファイルとメモリ上のコードが一致しません\n・PEB（Process Environment Block）の ImageBaseAddress がディスク上の PE ヘッダと異なる場合があります\n・CREATE_SUSPENDED フラグで起動されたプロセスの履歴は、イベントログからも追跡可能です\n・svchost.exe や rundll32.exe が頻繁にターゲットにされます",
      logic: "1. プロセスの実行パス（exe）を取得\n2. ディスク上の PE ファイルのエントリポイントとベースアドレスを解析\n3. メモリ上のプロセスイメージのベースアドレスを取得\n4. 両者を比較し、不一致がある場合にホロウイングの疑いとして報告\n5. 追加検査: メモリ内 PE ヘッダの存在確認と RWX リージョンとの相関分析",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: svchost.exe のメモリイメージがディスク上のファイルと不一致\n  ↓\n確認: メモリ上のベースアドレスとディスク上の PE ヘッダを比較\n  ↓\n確認: メモリ内に本来の svchost.exe とは異なる PE ヘッダが存在\n  ↓\n結論: プロセスホロウイングの可能性が極めて高い\n  ↓\n対応: 即座にメモリダンプを取得。抽出した PE を YARA スキャン。ネットワーク接続を確認し、C2 の特定を試みる。端末の隔離を検討",
      flow_safe: "【正常判定の業務フロー】\n\n検知: プロセスのメモリイメージとディスクファイルが一致\n  ↓\n確認: ベースアドレス、エントリポイントともに正常範囲\n  ↓\n確認: RWX リージョンも通常範囲内\n  ↓\n結論: ホロウイングの兆候なし。正常なプロセスと判定",
      mitre: "T1055.012 Process Hollowing\n攻撃者は正規プロセスのメモリ内容を悪意あるコードで置換し、正規プロセスを装って活動します。NtUnmapViewOfSection でメモリを解放し、新たなコードをマッピングします。",
      references: "・MITRE T1055.012: https://attack.mitre.org/techniques/T1055/012/\n・Elastic: Detecting Process Hollowing: https://www.elastic.co/security-labs\n・hasherezade - Process Hollowing explained"
    }
  },

  // ========================================
  // Category 3: メモリ解析 (memory)
  // ========================================
  {
    id: "memory-dump",
    category: "メモリ解析",
    categoryId: "memory",
    title: "メモリダンプ取得の仕組み",
    content: {
      summary: "メモリダンプとは、プロセスの仮想メモリ空間の内容をファイルとして保存する操作です。実行中のマルウェアがディスク上では暗号化されていても、メモリ上では復号された状態で存在するため、メモリダンプはフォレンジック解析において極めて重要です。\n\n本ツールでは、Windows API（MiniDumpWriteDump）を ctypes 経由で呼び出し、指定プロセスのフルメモリダンプを取得します。",
      points: "・メモリダンプ取得には管理者権限が必要です\n・保護されたプロセス（csrss.exe、lsass.exe 等）は特別な権限が必要な場合があります\n・ダンプファイルは数百 MB に達する場合があります\n・ダンプ取得中はプロセスが一時的にサスペンドされます",
      logic: "1. OpenProcess() で PROCESS_ALL_ACCESS 権限のハンドルを取得\n2. MiniDumpWriteDump() でフルメモリダンプを dumps/ フォルダに保存\n3. ファイル名は PID_プロセス名_タイムスタンプ.dmp 形式\n4. 取得完了後、ダンプファイルのサイズとパスを返却\n5. エラー発生時は GetLastError() でWindows エラーコードを取得して表示",
      flow_danger: null,
      flow_safe: null,
      mitre: "T1003 OS Credential Dumping\nメモリダンプ技術は攻撃者も防御者も使用します。攻撃者は lsass.exe のダンプから認証情報を抽出し、防御者は不審プロセスのダンプからマルウェアの挙動を解析します。",
      references: "・Microsoft MiniDumpWriteDump: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump\n・Volatility Framework: https://www.volatilityfoundation.org/\n・MITRE T1003: https://attack.mitre.org/techniques/T1003/"
    }
  },
  {
    id: "memory-pe-extraction",
    category: "メモリ解析",
    categoryId: "memory",
    title: "PE抽出とインジェクション検出",
    content: {
      summary: "メモリダンプから PE（Portable Executable）ヘッダを検索し、プロセスのメモリ空間に読み込まれた実行ファイルや DLL を抽出します。正規プロセスのメモリ内に予期しない PE イメージが存在する場合、DLL インジェクションやプロセスホロウイングの痕跡である可能性があります。\n\n本ツールでは、MZ/PE シグネチャをスキャンし、検出された PE のセクション情報やインポートテーブルを解析します。",
      points: "・MZ ヘッダ（0x4D5A）は PE ファイルの先頭シグネチャです\n・1つのプロセスに複数の PE イメージが存在するのは正常です（本体 + DLL群）\n・ただし、RWX 領域内の PE イメージはインジェクションの強い指標です\n・抽出した PE はそのまま YARA スキャンの入力として使用できます",
      logic: "1. ダンプファイルをバイナリモードで読み込み\n2. MZ シグネチャ（0x4D5A）を全域検索\n3. 各 MZ 位置から PE ヘッダ（0x5045）のオフセットを確認\n4. PE ヘッダが有効な場合、セクション数・エントリポイント・イメージサイズを解析\n5. 抽出した PE メタデータを一覧として返却\n6. オプション: PE イメージをファイルとして書き出し（後続の YARA スキャン用）",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: explorer.exe のダンプ内 RWX 領域に未知の PE イメージを検出\n  ↓\n確認: 当該 PE のセクション構成とインポートテーブルを解析\n  ↓\n確認: ネットワーク関連 API（WinINet, WinHTTP）のインポートを確認\n  ↓\n結論: インジェクションされたマルウェア本体の可能性が高い\n  ↓\n対応: PE イメージを抽出・保存し、YARA スキャンを実施。ハッシュ値を算出し、VirusTotal 等で照合",
      flow_safe: "【正常判定の業務フロー】\n\n検知: chrome.exe のダンプ内に複数の PE イメージを検出\n  ↓\n確認: 検出された PE は全て既知の Chrome DLL（chrome.dll, v8.dll 等）\n  ↓\n確認: RWX 領域内の PE は V8 JIT コンパイラによるもの\n  ↓\n結論: ブラウザの正常動作に伴う PE イメージと判定",
      mitre: "T1055.001 DLL Injection\n攻撃者は LoadLibrary を使用して悪意ある DLL を正規プロセスに読み込ませます。メモリ内の PE 検索により、注入された DLL を検出できます。",
      references: "・PE Format Specification: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format\n・MITRE T1055.001: https://attack.mitre.org/techniques/T1055/001/\n・Hasherezade PE-sieve: https://github.com/hasherezade/pe-sieve"
    }
  },
  {
    id: "memory-strings",
    category: "メモリ解析",
    categoryId: "memory",
    title: "文字列解析によるIOC抽出",
    content: {
      summary: "メモリダンプから ASCII および Unicode 文字列を抽出し、IOC（Indicator of Compromise: 侵害指標）を検出します。マルウェアがメモリ上で復号した C2 サーバーの URL、IP アドレス、レジストリキー、ファイルパスなどが抽出対象です。\n\n通信先の特定やマルウェアファミリーの推定に役立つ重要な解析手法です。",
      points: "・最小4文字以上の印字可能文字列を抽出対象とします\n・URL、IP アドレス、ドメイン名は正規表現でフィルタリングします\n・Base64 エンコードされた文字列も検出対象です\n・抽出結果には大量のノイズ（正規文字列）が含まれるため、フィルタリングが重要です",
      logic: "1. ダンプファイルを読み込み、ASCII 文字列（4文字以上）を正規表現で抽出\n2. Unicode（UTF-16LE）文字列も同様に抽出\n3. 抽出文字列に対して IOC パターンマッチング：\n   a. URL: https?://のパターン\n   b. IP: 数字.数字.数字.数字 のパターン\n   c. ドメイン: FQDN パターン\n   d. レジストリ: HKLM / HKCU で始まるパス\n   e. ファイルパス: ドライブレターで始まるパス\n4. 検出した URL は無害化（defang）して表示\n5. 統計情報（種類別カウント）を生成",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: svchost.exe のメモリから不審な URL を検出\n  ↓\n確認: 当該 URL のドメインを WHOIS / PassiveDNS で調査\n  ↓\n確認: ネットワークタブで同一ドメインへの通信履歴を確認\n  ↓\n結論: C2 通信の痕跡。当該プロセスはマルウェアに感染している可能性が高い\n  ↓\n対応: IOC リスト（URL、IP、ドメイン）を作成。ファイアウォールでブロック。横展開の確認",
      flow_safe: "【正常判定の業務フロー】\n\n検知: chrome.exe のメモリから多数の URL を検出\n  ↓\n確認: 検出された URL は全てブラウザのアクセス履歴に対応する一般サイト\n  ↓\n確認: 不審なドメインや既知の C2 パターンに一致するものなし\n  ↓\n結論: ブラウザの正常なメモリ内容と判定",
      mitre: "T1132 Data Encoding\nマルウェアは C2 通信データを Base64 等でエンコードしますが、メモリ上では復号された状態で存在することがあります。文字列解析により、エンコード前後のデータを検出できます。",
      references: "・Sysinternals Strings: https://learn.microsoft.com/en-us/sysinternals/downloads/strings\n・MITRE T1132: https://attack.mitre.org/techniques/T1132/\n・SANS DFIR: Memory Forensics Cheat Sheet"
    }
  },
  {
    id: "memory-yara",
    category: "メモリ解析",
    categoryId: "memory",
    title: "YARAスキャンの仕組み",
    content: {
      summary: "YARA は、バイナリパターンやテキストパターンに基づいてマルウェアを識別するためのルールベースのツールです。メモリダンプに対して YARA ルールを適用することで、既知のマルウェアファミリーやハッキングツールの痕跡を検出できます。\n\n本ツールでは yara-python ライブラリを使用し、yara_rules/ フォルダ内の全ルールを一括コンパイルしてスキャンします。",
      points: "・YARA ルールは文字列パターン（strings）と条件（condition）で構成されます\n・Neo23x0/signature-base には 700 以上のルールが含まれます\n・メモリスキャンはファイルスキャンより多くのマッチを返す傾向があります\n・ルールのコンパイルは初回のみ行い、キャッシュして再利用します",
      logic: "1. yara_rules/ フォルダ内の .yar/.yara ファイルを再帰的に列挙\n2. yara.compile() で全ルールを一括コンパイル\n3. コンパイル済みルールオブジェクトを使用してダンプファイルをスキャン\n4. マッチしたルール名、文字列オフセット、マッチ内容を収集\n5. 結果をルール名でグループ化し、重要度でソート\n6. Web UI にマッチ結果と該当ルールの説明を表示",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: メモリダンプから YARA ルール Cobalt_Strike_Beacon がマッチ\n  ↓\n確認: マッチした文字列オフセットとパターンを確認\n  ↓\n確認: 該当プロセスのネットワーク接続を確認（定期的なビーコン通信）\n  ↓\n結論: Cobalt Strike ビーコンによる C2 通信が確認された\n  ↓\n対応: 即座に端末をネットワークから隔離。メモリダンプとネットワークログを保全。SOC / CSIRT へエスカレーション",
      flow_safe: "【正常判定の業務フロー】\n\n検知: メモリスキャンで YARA マッチなし\n  ↓\n確認: 使用ルールセットが最新版であることを確認\n  ↓\n確認: ルールコンパイルが正常に完了していることを確認\n  ↓\n結論: 既知のマルウェアシグネチャには合致せず。ただし未知のマルウェアの可能性は排除できない",
      mitre: "TA0005 Defense Evasion\nYARA スキャンは防御回避技術（パッキング、難読化）を検出するための重要な手段です。メモリスキャンはアンパックされた状態のコードを検査できるため、ファイルスキャンより検出率が高い場合があります。",
      references: "・YARA Documentation: https://yara.readthedocs.io/\n・Neo23x0/signature-base: https://github.com/Neo23x0/signature-base\n・VirusTotal YARA: https://virustotal.github.io/yara/\n・MITRE TA0005: https://attack.mitre.org/tactics/TA0005/"
    }
  },

  // ========================================
  // Category 4: ネットワーク解析 (network)
  // ========================================
  {
    id: "network-connections",
    category: "ネットワーク解析",
    categoryId: "network",
    title: "接続情報の収集方法",
    content: {
      summary: "Windows 端末のネットワーク接続情報を psutil ライブラリで収集します。TCP/UDP の接続状態、ローカル/リモートのアドレスとポート、接続に紐付くプロセス ID を一覧化し、不審な外部通信を可視化します。\n\nnetstat コマンドと同等の情報をプログラマティックに取得し、プロセス情報と紐付けることで、どのプロセスがどこに通信しているかを即座に把握できます。",
      points: "・ESTABLISHED 状態の外部接続が最も重要な調査対象です\n・LISTENING 状態のポートは、バックドアやリモートアクセスツールの指標になり得ます\n・ループバック（127.0.0.1）への接続はローカル通信のため通常は問題ありません\n・よく知られたポート（80, 443, 53）でも不審なプロセスが使用している場合は要注意です",
      logic: "1. psutil.net_connections(kind=inet) で全 TCP/UDP 接続を取得\n2. 各接続の laddr、raddr、status、pid を記録\n3. pid からプロセス名を逆引き\n4. リモートアドレスがプライベート IP か外部 IP かを判定\n5. 既知の危険ポート（4444, 5555, 8080 等）への接続をハイライト\n6. 結果をプロセス別・接続状態別に整理して返却",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: svchost.exe が外部 IP の 443 番ポートに ESTABLISHED 接続\n  ↓\n確認: 当該 svchost.exe の起動パスと親プロセスをプロセス解析タブで確認\n  ↓\n確認: 接続先 IP の Whois / 地理情報を確認\n  ↓\n結論: svchost.exe が直接外部 IP に HTTPS 接続するのは異常。C2 通信の疑い\n  ↓\n対応: メモリダンプを取得し IOC 抽出。ファイアウォールログで通信履歴を確認。IP をブロックリストに追加",
      flow_safe: "【正常判定の業務フロー】\n\n検知: chrome.exe が複数の外部 IP にポート 443 で ESTABLISHED 接続\n  ↓\n確認: 接続先は Google、Cloudflare 等の既知 CDN\n  ↓\n確認: chrome.exe の起動パスが正規\n  ↓\n結論: ブラウザの正常な HTTPS 通信と判定",
      mitre: "T1071.001 Application Layer Protocol: Web Protocols\n攻撃者は HTTP/HTTPS を使用して C2 通信を行い、通常の Web トラフィックに紛れ込ませます。プロセスと通信先の紐付けにより、正規通信と不審通信を判別できます。",
      references: "・psutil net_connections: https://psutil.readthedocs.io/en/latest/\n・MITRE T1071.001: https://attack.mitre.org/techniques/T1071/001/\n・SANS: Network Forensics Poster"
    }
  },
  {
    id: "network-c2",
    category: "ネットワーク解析",
    categoryId: "network",
    title: "C2通信の特徴と検出",
    content: {
      summary: "C2（Command and Control）通信とは、マルウェアが攻撃者のサーバーと通信して命令を受け取り、結果を送信する仕組みです。検出を回避するために、一般的な Web 通信に偽装したり、DNS トンネリングを使用したりします。\n\n本ツールでは、通信パターンの異常（定期的なビーコニング、異常な通信先、不審なプロセスによる通信）を検出して C2 の疑いを報告します。",
      points: "・定期的な間隔での通信はビーコニングの典型的パターンです\n・高番号ポートへの直接接続は要注意です\n・DNS の TXT レコードを使った通信も検出対象です\n・通信量が極端に少ない定期通信はハートビート通信の可能性があります\n・正規プロセスが通常接続しない宛先への通信は異常指標です",
      logic: "1. ESTABLISHED 状態の全外部接続を抽出\n2. 各接続のプロセスが正規に外部通信するプロセスかを判定\n   a. ブラウザ → 通常は正常\n   b. svchost.exe → Windows Update 等の既知サービス以外は疑わしい\n   c. cmd.exe / powershell.exe → 外部通信は高リスク\n3. 接続先ポートの異常判定（4444, 8888, 1337 等の既知C2ポート）\n4. プライベート IP 範囲外への接続をリスクスコアリング\n5. 複合スコア（プロセス異常度 + ポート異常度 + 接続先異常度）で判定",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: powershell.exe が外部 IP の高番号ポートに接続中\n  ↓\n確認: PowerShell のコマンドライン引数を確認（Base64 エンコードされたコマンド）\n  ↓\n確認: 接続先 IP は既知の VPS プロバイダ。正規業務との関連なし\n  ↓\n結論: リバースシェルまたは C2 エージェントが PowerShell 経由で動作している\n  ↓\n対応: 即座にネットワーク隔離。プロセスツリー全体を調査。メモリダンプ取得。イベントログで PowerShell 実行履歴を確認",
      flow_safe: "【正常判定の業務フロー】\n\n検知: Windows Update 関連プロセスが Microsoft IP レンジに接続\n  ↓\n確認: 接続先が Microsoft の既知 IP レンジ内\n  ↓\n確認: 通信パターンが Windows Update の典型的挙動と一致\n  ↓\n結論: 正常な Windows Update 通信と判定",
      mitre: "T1071 Application Layer Protocol\n攻撃者は一般的なアプリケーションプロトコルを使用して C2 通信を行います。\n\nサブテクニック：\n・T1071.001 Web Protocols\n・T1071.004 DNS\n・T1573 Encrypted Channel",
      references: "・MITRE T1071: https://attack.mitre.org/techniques/T1071/\n・MITRE T1573: https://attack.mitre.org/techniques/T1573/\n・JPCERT/CC C2 通信検知ガイド: https://www.jpcert.or.jp/\n・Palo Alto Unit42 C2 Matrix: https://howto.thec2matrix.com/"
    }
  },

  // ========================================
  // Category 5: ファイル検査 (fileinspect)
  // ========================================
  {
    id: "file-ole",
    category: "ファイル検査",
    categoryId: "fileinspect",
    title: "OLE/OOXML構造解析",
    content: {
      summary: "Microsoft Office ドキュメント（.doc, .xls, .ppt 等の OLE 形式、および .docx, .xlsx 等の OOXML 形式）の内部構造を解析し、埋め込みマクロ、外部リンク、不審なストリームを検出します。\n\nOLE（Object Linking and Embedding）はバイナリ形式の複合ドキュメントで、内部に複数のストリーム（VBA マクロ、メタデータ等）を格納します。OOXML は ZIP 圧縮された XML ベースの形式で、内部に .rels ファイルや vbaProject.bin を含む場合があります。",
      points: "・VBA マクロを含むドキュメントは AutoOpen / Document_Open で自動実行される可能性があります\n・OLE ストリーム名に Macros / VBA / _VBA_PROJECT が含まれる場合はマクロ存在の指標です\n・OOXML の .rels ファイルに外部 URL への参照がある場合、テンプレートインジェクションの疑いがあります\n・olefile ライブラリで OLE 構造を解析し、zipfile で OOXML を展開します",
      logic: "1. ファイルのマジックバイトで OLE（D0CF11E0）か OOXML（504B0304=ZIP）かを判定\n2. OLE の場合：\n   a. olefile.OleFileIO でストリーム一覧を取得\n   b. Macros/VBA ストリームの存在を確認\n   c. メタデータ（作成者、最終更新者、作成日時）を抽出\n   d. 各ストリームのサイズと内容プレビューを表示\n3. OOXML の場合：\n   a. ZIP として展開し、内部ファイル一覧を取得\n   b. [Content_Types].xml からコンテンツタイプを解析\n   c. .rels ファイルから外部参照 URL を抽出\n   d. vbaProject.bin の存在を確認\n4. 検出結果をリスクレベル付きで返却",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: .docx ファイルの .rels に外部 URL への Template 参照を検出\n  ↓\n確認: 参照先 URL を無害化して記録（hXXps://evil[.]com/template.dotm）\n  ↓\n確認: テンプレートファイル（.dotm）にはマクロが含まれる可能性が高い\n  ↓\n結論: テンプレートインジェクション攻撃の疑い（T1221）\n  ↓\n対応: ファイルを隔離。参照先 URL をブロックリストに追加。送信元メールを調査。同一ファイルの受信者を特定",
      flow_safe: "【正常判定の業務フロー】\n\n検知: .xlsx ファイルの内部構造を解析\n  ↓\n確認: マクロ（vbaProject.bin）なし、外部参照なし\n  ↓\n確認: メタデータは社内ユーザーによる作成\n  ↓\n結論: 正常な Office ドキュメントと判定",
      mitre: "T1221 Template Injection\n攻撃者は Office ドキュメントのテンプレート参照機能を悪用し、外部サーバーからマクロ付きテンプレートをダウンロード・実行させます。ドキュメント本体にはマクロが含まれないため、静的解析を回避できます。\n\nT1137 Office Application Startup\nVBA マクロによる自動実行（AutoOpen 等）で、ドキュメントを開いた時点でコードが実行されます。",
      references: "・olefile documentation: https://olefile.readthedocs.io/\n・MITRE T1221: https://attack.mitre.org/techniques/T1221/\n・MITRE T1137: https://attack.mitre.org/techniques/T1137/\n・OASIS OOXML Standard: https://www.ecma-international.org/publications-and-standards/standards/ecma-376/"
    }
  },
  {
    id: "file-pdf",
    category: "ファイル検査",
    categoryId: "fileinspect",
    title: "PDF構造とJavaScript検出",
    content: {
      summary: "PDF ファイルの内部構造を解析し、埋め込み JavaScript、自動実行アクション（OpenAction）、外部 URL リンク、添付ファイルなどの不審な要素を検出します。\n\nPDF はオブジェクトベースの構造を持ち、テキスト・画像だけでなく、JavaScript コードやフォームアクションを内包できます。これらの機能はマルウェアの配布や脆弱性攻撃に悪用されることがあります。",
      points: "・/JavaScript や /JS オブジェクトは PDF 内の JavaScript コードを示します\n・/OpenAction は PDF を開いた時に自動実行されるアクションです\n・/Launch は外部プログラムの起動を指示するアクションです\n・/EmbeddedFile は PDF 内に添付されたファイルを示します\n・難読化された JavaScript（eval, unescape, String.fromCharCode）に注意が必要です",
      logic: "1. PyPDF2 で PDF ファイルを読み込み\n2. ページ数、メタデータ（作成者、作成ツール、作成日時）を取得\n3. 全オブジェクトを走査し、以下のキーワードを検索：\n   a. /JavaScript, /JS → JavaScript コードの存在\n   b. /OpenAction → 自動実行アクション\n   c. /Launch → 外部プログラム起動\n   d. /EmbeddedFile → 添付ファイル\n   e. /URI → 外部 URL リンク\n4. 検出された要素の内容をプレビュー表示\n5. リスクスコア（JavaScript + OpenAction = 高リスク）を算出",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: PDF に /OpenAction + /JavaScript の組み合わせを検出\n  ↓\n確認: JavaScript コードの内容を確認（難読化された eval 呼び出し）\n  ↓\n確認: PDF の作成ツールが不審（通常の Office や Acrobat ではない）\n  ↓\n結論: PDF を利用した悪意あるコード実行の試み\n  ↓\n対応: ファイルを隔離。JavaScript コードをデコードして IOC を抽出。配布経路（メール、Web）を調査",
      flow_safe: "【正常判定の業務フロー】\n\n検知: PDF にフォーム用の /JavaScript を検出\n  ↓\n確認: JavaScript はフォームの入力値チェック（日付形式、必須項目）のみ\n  ↓\n確認: 作成ツールが Adobe Acrobat で、メタデータに不審な点なし\n  ↓\n結論: 業務用フォーム PDF の正常な機能と判定",
      mitre: "T1566.001 Phishing: Spearphishing Attachment\n攻撃者は悪意ある PDF をメール添付で送信し、開封時に JavaScript を実行させます。\n\nT1203 Exploitation for Client Execution\nPDF リーダーの脆弱性を悪用して任意コード実行を行う手法です。",
      references: "・PyPDF2 documentation: https://pypdf2.readthedocs.io/\n・MITRE T1566.001: https://attack.mitre.org/techniques/T1566/001/\n・PDF Reference (Adobe): https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf\n・Didier Stevens PDF Tools: https://blog.didierstevens.com/programs/pdf-tools/"
    }
  },
  {
    id: "file-pe",
    category: "ファイル検査",
    categoryId: "fileinspect",
    title: "PE実行ファイル解析",
    content: {
      summary: "Windows の実行ファイル（.exe, .dll）の PE（Portable Executable）構造を解析し、セクション情報、インポートテーブル、エントリポイント、コンパイルタイムスタンプ、デジタル署名の有無などを検査します。\n\nこれらの属性は、マルウェアの特徴（パッキング、異常なセクション名、疑わしいインポート関数）を検出するための重要な手がかりとなります。",
      points: "・セクション名が .text / .data / .rsrc 以外（.UPX0 等）の場合はパッカーの使用を示唆します\n・エントロピーが 7.0 以上のセクションは暗号化またはパッキングの指標です\n・VirtualAllocEx / WriteProcessMemory / CreateRemoteThread のインポートはインジェクション能力を示します\n・コンパイルタイムスタンプが未来日や 2000 年以前の場合は改ざんの可能性があります\n・デジタル署名がないか、無効な署名は要注意です",
      logic: "1. PE ファイルのヘッダを解析（MZ シグネチャ確認、PE ヘッダオフセット取得）\n2. セクション情報を列挙：名前、仮想サイズ、RAW サイズ、特性フラグ\n3. 各セクションのエントロピーを計算（Shannon entropy）\n4. インポートテーブルから DLL 名と関数名を抽出\n5. 不審なインポート関数（VirtualAllocEx 等）の存在を検査\n6. コンパイルタイムスタンプの妥当性チェック\n7. ファイルハッシュ（MD5, SHA256）を算出\n8. 総合リスクスコアを算出して返却",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: .exe ファイルに UPX パッキングの痕跡（.UPX0, .UPX1 セクション）とエントロピー 7.8 を検出\n  ↓\n確認: インポートテーブルに VirtualAllocEx, WriteProcessMemory を確認\n  ↓\n確認: デジタル署名なし、コンパイルタイムスタンプが改ざんされている\n  ↓\n結論: パッキングされたマルウェアの可能性が高い\n  ↓\n対応: SHA256 ハッシュで VirusTotal 等を照合。YARA スキャンを実施。実行履歴をイベントログで確認",
      flow_safe: "【正常判定の業務フロー】\n\n検知: .exe ファイルを解析\n  ↓\n確認: セクション構成が標準的（.text, .data, .rsrc, .reloc）\n  ↓\n確認: Microsoft の有効なデジタル署名あり\n  ↓\n結論: 正規の署名付き実行ファイルと判定",
      mitre: "T1027 Obfuscated Files or Information\n攻撃者はマルウェアをパッキング・暗号化して静的解析を回避します。PE 構造解析により、パッキングの痕跡を検出できます。\n\nT1027.002 Software Packing\nUPX、Themida 等のパッカーを使用してマルウェアを圧縮・暗号化します。",
      references: "・PE Format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format\n・MITRE T1027: https://attack.mitre.org/techniques/T1027/\n・pefile (Python): https://github.com/erocarrera/pefile\n・Practical Malware Analysis (Book)"
    }
  },

  // ========================================
  // Category 6: 永続化メカニズム (persistence)
  // ========================================
  {
    id: "persist-registry",
    category: "永続化メカニズム",
    categoryId: "persistence",
    title: "レジストリAutoRun検出",
    content: {
      summary: "Windows レジストリの自動起動（AutoRun）キーを検査し、OS 起動時やユーザーログオン時に自動実行されるプログラムを一覧化します。攻撃者はこれらのキーにマルウェアのパスを登録することで、永続化（再起動後も動作を継続）を実現します。\n\n本ツールでは、HKLM および HKCU の主要な AutoRun キー（約15箇所）を検査し、不審なエントリを検出します。",
      points: "・Run / RunOnce キーが最も一般的な永続化ポイントです\n・Winlogon の Shell / Userinit 値の改ざんも検出対象です\n・レジストリ値がファイルパスを含む場合、そのファイルの存在確認も行います\n・正規のソフトウェアも AutoRun を使用するため、正常/異常の判別が重要です\n・コマンドラインに powershell -enc や cmd /c が含まれる場合は高リスクです",
      logic: "1. 検査対象レジストリキーのリスト（約15箇所）を定義\n   a. HKLM/HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n   b. HKLM/HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n   c. HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon (Shell, Userinit)\n   d. HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n   等\n2. 各キーの値を列挙（名前、データ、型）\n3. データに含まれるファイルパスの存在確認\n4. 既知の正規エントリ（SecurityHealth, VMware Tools 等）をホワイトリスト判定\n5. ホワイトリスト外のエントリを不審として報告\n6. パスに %TEMP% や %APPDATA% が含まれる場合にリスクスコアを加算",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: HKCU\\Run に不審なエントリ sysupdate = powershell -windowstyle hidden -enc BASE64... を検出\n  ↓\n確認: Base64 をデコードしてコマンド内容を確認\n  ↓\n確認: 当該エントリの登録日時をレジストリのタイムスタンプから推定\n  ↓\n結論: PowerShell による隠蔽された自動起動 = 典型的なマルウェアの永続化\n  ↓\n対応: レジストリエントリを記録。関連ファイルを YARA スキャン。プロセス解析で実行中かを確認",
      flow_safe: "【正常判定の業務フロー】\n\n検知: HKLM\\Run に SecurityHealth = C:\\Windows\\System32\\SecurityHealthSystray.exe を検出\n  ↓\n確認: Windows Security の正規コンポーネント\n  ↓\n確認: ファイルパスが正規、デジタル署名あり\n  ↓\n結論: 正規の AutoRun エントリと判定",
      mitre: "T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder\n攻撃者はレジストリの Run キーにエントリを追加して、システム起動時またはユーザーログオン時にマルウェアを自動実行させます。",
      references: "・MITRE T1547.001: https://attack.mitre.org/techniques/T1547/001/\n・Microsoft: Run and RunOnce Registry Keys: https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys\n・SANS: Windows Registry Forensics"
    }
  },
  {
    id: "persist-tasks",
    category: "永続化メカニズム",
    categoryId: "persistence",
    title: "スケジュールタスク解析",
    content: {
      summary: "Windows タスクスケジューラに登録されたタスクを列挙し、不審な定期実行タスクを検出します。攻撃者はスケジュールタスクを作成して、定期的にマルウェアを実行させたり、特定のイベント発生時にコードを実行させたりします。\n\nschtasks コマンドの出力を解析し、タスク名、実行パス、トリガー（起動条件）、作成者、最終実行日時などを確認します。",
      points: "・Microsoft 以外の作成者によるタスクは重点的に検査します\n・実行パスが %TEMP% や %APPDATA% のタスクは高リスクです\n・トリガーが BOOT / LOGON / 短間隔（5分以下）のタスクは C2 ビーコンの可能性があります\n・タスク名が正規タスクに偽装（GoogleUpdate 等）されている場合があります\n・XML 定義ファイル内の Hidden 属性が True のタスクは隠蔽の意図があります",
      logic: "1. schtasks /query /fo CSV /v で全タスクを CSV 形式で取得\n2. CSV をパースし、各タスクの属性を構造化\n3. 作成者が Microsoft Corporation 以外のタスクをフィルタリング\n4. 実行パスのリスク判定：\n   a. システムディレクトリ外 → リスク中\n   b. %TEMP% / %APPDATA% → リスク高\n   c. powershell / cmd 経由 → リスク高\n5. トリガー間隔の分析（短間隔は C2 ビーコンの指標）\n6. 結果をリスクスコア順にソートして返却",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: タスク ChromeUpdater が 5分間隔で powershell.exe を実行。作成者不明\n  ↓\n確認: 実行コマンドの内容を確認（外部サーバーからスクリプトをダウンロード）\n  ↓\n確認: タスクの作成日時とインシデントタイムラインを照合\n  ↓\n結論: C2 ビーコン用のスケジュールタスクによる永続化\n  ↓\n対応: タスク定義を保全（XML エクスポート）。関連ファイルを調査。タスクを無効化。イベントログで作成タイミングを特定",
      flow_safe: "【正常判定の業務フロー】\n\n検知: タスク GoogleUpdateTaskMachineUA を検出\n  ↓\n確認: 実行パスが C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\n  ↓\n確認: 作成者が Google、デジタル署名あり\n  ↓\n結論: 正規の Google Update タスクと判定",
      mitre: "T1053.005 Scheduled Task/Job: Scheduled Task\n攻撃者は schtasks コマンドや Task Scheduler API を使用して悪意あるタスクを登録し、定期的または特定条件下でコードを実行させます。",
      references: "・MITRE T1053.005: https://attack.mitre.org/techniques/T1053/005/\n・Microsoft: schtasks: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks\n・SANS: Detecting Persistence with Task Scheduler"
    }
  },
  {
    id: "persist-services",
    category: "永続化メカニズム",
    categoryId: "persistence",
    title: "サービス登録検出",
    content: {
      summary: "Windows サービスとして登録されたプログラムを列挙し、不審なサービスを検出します。攻撃者は SYSTEM 権限で動作するサービスを作成して、高権限での永続的なコード実行を実現します。\n\nsc query コマンドおよびレジストリの Services キーから、サービス名、表示名、実行パス、起動タイプ、実行ユーザーを取得して検査します。",
      points: "・実行パスが System32 外のサービスは重点的に検査します\n・表示名や説明が空白のサービスは不審です\n・起動タイプが AUTO_START（自動）で、作成日が最近のサービスに注目します\n・サービスの実行パスに cmd.exe /c や powershell が含まれる場合は高リスクです\n・DLL を使用する svchost ベースのサービスは serviceDll レジストリ値を確認します",
      logic: "1. sc query state=all で全サービスを列挙\n2. 各サービスの詳細を sc qc で取得（BINARY_PATH_NAME, START_TYPE, SERVICE_START_NAME）\n3. レジストリ HKLM\\SYSTEM\\CurrentControlSet\\Services から追加情報を取得\n4. 実行パスのリスク判定（System32 外、TEMP パス、PowerShell 使用）\n5. svchost.exe ベースのサービスは ServiceDll 値を確認\n6. 既知の正規サービスをホワイトリストで除外\n7. 残りのサービスをリスクスコア順にソート",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: サービス WinSvcHelper（表示名: Windows Service Helper）が C:\\ProgramData\\svc.exe を実行\n  ↓\n確認: サービスの作成日時が直近（インシデント発生時刻付近）\n  ↓\n確認: svc.exe にデジタル署名なし。YARA スキャンでマルウェア検出\n  ↓\n結論: マルウェアが SYSTEM 権限で永続化するために作成したサービス\n  ↓\n対応: サービスを停止・無効化。実行ファイルを隔離・解析。イベントログで作成者を特定",
      flow_safe: "【正常判定の業務フロー】\n\n検知: サービス Spooler（Print Spooler）を検出\n  ↓\n確認: 実行パスが C:\\Windows\\System32\\spoolsv.exe\n  ↓\n確認: Microsoft の正規サービスでデジタル署名あり\n  ↓\n結論: 正規の Windows サービスと判定",
      mitre: "T1543.003 Create or Modify System Process: Windows Service\n攻撃者は sc create コマンドや API を使用して悪意あるサービスを登録し、SYSTEM 権限での永続的なコード実行を実現します。",
      references: "・MITRE T1543.003: https://attack.mitre.org/techniques/T1543/003/\n・Microsoft: sc create: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create\n・SANS: Detecting Malicious Services"
    }
  },
  {
    id: "persist-wmi",
    category: "永続化メカニズム",
    categoryId: "persistence",
    title: "WMIイベント監視",
    content: {
      summary: "WMI（Windows Management Instrumentation）のイベントサブスクリプションを検査し、不審な永続化メカニズムを検出します。攻撃者は WMI イベントフィルター、コンシューマー、バインディングの3要素を組み合わせて、特定のシステムイベント発生時にコードを自動実行させます。\n\nこの手法はファイルレス攻撃の代表例で、レジストリやファイルシステムに痕跡が残りにくいため、検出が困難です。",
      points: "・WMI イベントサブスクリプションは3つの要素で構成されます：\n  - EventFilter: 監視するイベント（例: OS 起動後60秒経過）\n  - EventConsumer: 実行するアクション（例: PowerShell コマンド）\n  - FilterToConsumerBinding: フィルターとコンシューマーの紐付け\n・CommandLineEventConsumer と ActiveScriptEventConsumer が特に危険です\n・正規の WMI サブスクリプションはほとんど存在しないため、検出された場合は要注意です",
      logic: "1. WMI クエリで __EventFilter クラスの全インスタンスを取得\n2. CommandLineEventConsumer と ActiveScriptEventConsumer を列挙\n3. __FilterToConsumerBinding で紐付け関係を確認\n4. 各コンシューマーの実行コマンド/スクリプト内容を取得\n5. 正規の WMI サブスクリプション（BVTFilter 等）をホワイトリストで除外\n6. 残りのサブスクリプションを全て不審として報告",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: WMI EventFilter SCM Event Log Filter が OS 起動後60秒で CommandLineEventConsumer を起動\n  ↓\n確認: コンシューマーの実行コマンドが powershell -enc で始まる Base64 エンコードされたスクリプト\n  ↓\n確認: 正規の WMI サブスクリプションリストに該当なし\n  ↓\n結論: WMI を利用したファイルレス永続化。高度な攻撃手法\n  ↓\n対応: WMI サブスクリプションを記録・削除。Base64 をデコードして IOC を抽出。イベントログ（Microsoft-Windows-WMI-Activity）で作成タイミングを特定",
      flow_safe: "【正常判定の業務フロー】\n\n検知: WMI サブスクリプションのクエリ結果が空\n  ↓\n確認: EventFilter、EventConsumer、Binding のいずれも検出されず\n  ↓\n結論: WMI を利用した永続化は確認されず",
      mitre: "T1546.003 Event Triggered Execution: Windows Management Instrumentation Event Subscription\n攻撃者は WMI イベントサブスクリプションを作成して、特定のシステムイベント発生時に悪意あるコードを実行させます。ファイルレスかつ高権限での永続化が可能です。",
      references: "・MITRE T1546.003: https://attack.mitre.org/techniques/T1546/003/\n・FireEye: WMI Attacks: https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf\n・Microsoft WMI documentation: https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page"
    }
  },

  // ========================================
  // Category 7: システムアーティファクト (artifacts)
  // ========================================
  {
    id: "artifact-eventlog",
    category: "システムアーティファクト",
    categoryId: "artifacts",
    title: "イベントログ解析",
    content: {
      summary: "Windows イベントログは、OS やアプリケーションの動作を時系列で記録するシステムです。セキュリティログ、システムログ、アプリケーションログ、および PowerShell 実行ログなどから、攻撃者の行動痕跡を追跡できます。\n\n本ツールでは、セキュリティ上重要なイベント ID（ログオン成功/失敗、プロセス生成、サービス登録等）を重点的に収集・表示します。",
      points: "・Event ID 4624/4625: ログオン成功/失敗。ブルートフォース攻撃の検出に有効\n・Event ID 4688: プロセス生成。コマンドライン引数の記録が有効な場合、実行されたコマンドを追跡可能\n・Event ID 7045: サービス登録。マルウェアによるサービス作成を検出\n・Event ID 4104: PowerShell スクリプトブロックログ。実行されたスクリプト内容を記録\n・Event ID 1102: セキュリティログの消去。証拠隠滅の指標",
      logic: "1. wevtutil または Python の win32evtlog で対象ログを取得\n2. 重点イベント ID リストに基づきフィルタリング\n3. 各イベントから時刻、ソース、イベント ID、メッセージを抽出\n4. ログオン失敗の連続発生（5分以内に10回以上）をブルートフォース指標として検出\n5. プロセス生成ログから不審なコマンドライン（powershell -enc、certutil -urlcache 等）を抽出\n6. 時系列順にソートし、タイムラインビューで表示",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: Event ID 4625（ログオン失敗）が5分間に47回記録。ソース IP は外部\n  ↓\n確認: 対象アカウント名を確認（Administrator、admin 等の一般名）\n  ↓\n確認: 最終的にEvent ID 4624（ログオン成功）があるか確認\n  ↓\n結論: ブルートフォース攻撃が実行され、成功している場合は侵入済み\n  ↓\n対応: 該当アカウントのパスワード即時変更。ソース IP をブロック。成功ログオン以降のアクティビティを全て調査",
      flow_safe: "【正常判定の業務フロー】\n\n検知: Event ID 4624 のログオン成功イベントを検出\n  ↓\n確認: ログオンタイプが 2（対話型）で、業務時間内のローカルログオン\n  ↓\n確認: ユーザーアカウントは正規の業務ユーザー\n  ↓\n結論: 正常なユーザーログオンと判定",
      mitre: "T1070.001 Indicator Removal: Clear Windows Event Logs\n攻撃者は wevtutil cl コマンドでイベントログを消去して痕跡を隠滅します。Event ID 1102 で消去操作自体が記録されます。\n\nT1110 Brute Force\nログオン失敗の大量発生はブルートフォース攻撃の指標です。",
      references: "・MITRE T1070.001: https://attack.mitre.org/techniques/T1070/001/\n・MITRE T1110: https://attack.mitre.org/techniques/T1110/\n・JPCERT/CC ログ分析ガイド: https://www.jpcert.or.jp/\n・SANS: Windows Event Log Analysis"
    }
  },
  {
    id: "artifact-srum",
    category: "システムアーティファクト",
    categoryId: "artifacts",
    title: "SRUM解析",
    content: {
      summary: "SRUM（System Resource Usage Monitor）は、Windows 8 以降に搭載されたシステムリソース使用状況の記録機能です。アプリケーションごとのネットワーク使用量、CPU 使用時間、メモリ使用量などが最大30日間記録されます。\n\nSRUM データベース（SRUDB.dat）は ESE（Extensible Storage Engine）形式で保存され、プロセスが削除された後も実行履歴として残るため、フォレンジック解析で非常に有用です。",
      points: "・SRUDB.dat は C:\\Windows\\System32\\sru\\ に保存されています\n・削除されたマルウェアの実行証拠が SRUM に残っている場合があります\n・ネットワーク使用量から、大量のデータ送信（データ窃取）の痕跡を検出できます\n・アプリケーション名とユーザー SID の組み合わせで、誰がいつ何を実行したかを特定できます\n・ESE データベースのロックを回避するため、VSS（ボリュームシャドウコピー）経由でアクセスする場合があります",
      logic: "1. SRUDB.dat ファイルの存在確認とコピー（ロック回避）\n2. ESE データベースを解析し、以下のテーブルを読み取り：\n   a. NetworkUsage: アプリケーション別ネットワーク送受信量\n   b. ApplicationResourceUsage: CPU/メモリ使用量\n   c. NetworkConnections: ネットワーク接続プロファイル\n3. SID からユーザーアカウント名を逆引き\n4. ネットワーク送信量が異常に大きいアプリケーションを検出（データ窃取の指標）\n5. 実行履歴のタイムラインを生成",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: SRUM に記録された unknown.exe が過去7日間で 2.3GB のデータを外部送信\n  ↓\n確認: 当該 exe は現在ディスク上に存在しない（削除済み）\n  ↓\n確認: 送信先ネットワークプロファイルと時間帯を確認\n  ↓\n結論: マルウェアによるデータ窃取（Exfiltration）の痕跡\n  ↓\n対応: SRUM の完全なタイムラインを保全。送信先 IP をネットワークログから特定。窃取されたデータの範囲を評価",
      flow_safe: "【正常判定の業務フロー】\n\n検知: SRUM に chrome.exe の大量ネットワーク使用を検出\n  ↓\n確認: 業務時間内のブラウジングによる通常の通信量\n  ↓\n確認: 送受信比率が通常範囲内（受信 > 送信）\n  ↓\n結論: 正常なブラウザ使用と判定",
      mitre: "T1041 Exfiltration Over C2 Channel\nSRUM のネットワーク使用量解析により、C2 チャネルを通じた大量データ送信を検出できます。\n\nT1070.004 File Deletion\nマルウェアが自身を削除しても、SRUM にプロセス実行の記録が残ります。",
      references: "・SANS: SRUM Forensics: https://www.sans.org/blog/digital-forensics-srum/\n・Velociraptor SRUM Parser: https://docs.velociraptor.app/\n・MITRE T1041: https://attack.mitre.org/techniques/T1041/\n・Mark Baggett - SRUM Dump: https://github.com/MarkBaggett/srum-dump"
    }
  },
  {
    id: "artifact-pca",
    category: "システムアーティファクト",
    categoryId: "artifacts",
    title: "PCA解析",
    content: {
      summary: "PCA（Program Compatibility Assistant）は、Windows がアプリケーションの互換性問題を追跡するためのサービスです。PCA データベースには、実行されたプログラムのパス、実行日時、互換性フラグなどが記録されます。\n\nフォレンジック解析では、PCA の記録を利用して過去に実行されたプログラムの履歴を復元できます。特に、Prefetch が無効化されている環境でも PCA は動作するため、補完的な証拠として有用です。",
      points: "・PcaAppLaunchDic.txt / PcaGeneralDb0.txt 等にプログラム実行履歴が記録されます\n・ファイルパスと最終実行日時が含まれます\n・Prefetch と異なり、PCA は Windows の全エディションで有効です\n・%SystemRoot%\\appcompat\\pca\\ に格納されています\n・攻撃者がこのアーティファクトを消去することは稀なため、信頼性が高い証拠です",
      logic: "1. PCA 関連ファイル（PcaAppLaunchDic.txt 等）の存在確認\n2. テキストファイルを解析し、実行パスとタイムスタンプを抽出\n3. パスが TEMP / Downloads / AppData を含むエントリをハイライト\n4. 実行されたが現在ディスクに存在しないプログラムを検出\n5. タイムラインを生成し、他のアーティファクト（SRUM、イベントログ）と時刻を照合",
      flow_danger: "【異常検知時の業務フロー】\n\n検知: PCA に C:\\Users\\user\\Downloads\\invoice.exe の実行記録。ファイルは現在存在しない\n  ↓\n確認: 実行日時がインシデント疑惑の時刻と一致\n  ↓\n確認: SRUM にも同一ファイルのネットワーク使用記録あり\n  ↓\n結論: フィッシングメール経由でダウンロード・実行された実行ファイル。実行後に自己削除\n  ↓\n対応: ファイル名で検索し、メール添付/ダウンロード元を特定。SRUM のネットワーク記録から C2 通信先を推定",
      flow_safe: "【正常判定の業務フロー】\n\n検知: PCA に Visual Studio インストーラーの実行記録\n  ↓\n確認: 正規のソフトウェアインストール作業に対応\n  ↓\n確認: IT 部門による承認済みのインストール\n  ↓\n結論: 正常なソフトウェアインストールと判定",
      mitre: "T1059 Command and Scripting Interpreter\nPCA はスクリプトや実行ファイルの実行履歴を記録するため、攻撃者が使用したコマンドインタープリターの証拠として活用できます。\n\nT1070.004 File Deletion\n実行後に削除されたマルウェアの痕跡が PCA に残ります。",
      references: "・Andrew Rathbun: PCA Forensics: https://github.com/AndrewRathworthy/PCA-Research\n・13Cubed: PCA Analysis: https://www.youtube.com/c/13Cubed\n・MITRE T1059: https://attack.mitre.org/techniques/T1059/"
    }
  },

  // ========================================
  // Category 8: 参考資料・出典一覧 (references)
  // ========================================
  {
    id: "ref-mitre",
    category: "参考資料",
    categoryId: "references",
    title: "MITRE ATT&CKフレームワーク",
    content: {
      summary: "MITRE ATT&CK（Adversarial Tactics, Techniques, and Common Knowledge）は、実際のサイバー攻撃の観察に基づいて体系化された、攻撃者の戦術・技術のナレッジベースです。\n\n本ツールの全ての検出項目は MITRE ATT&CK の技術 ID に紐付けられており、検出結果がどのような攻撃手法に対応するかを即座に理解できるようになっています。",
      points: "・ATT&CK は14の戦術（Tactics）と数百の技術（Techniques）で構成されます\n・戦術: 初期アクセス、実行、永続化、権限昇格、防御回避、認証情報アクセス、探索、横移動、収集、C2、データ窃取、影響\n・各技術には固有の ID（例: T1055）が割り当てられています\n・サブテクニック（例: T1055.001）でより詳細な手法を分類\n・ATT&CK Navigator でカバレッジの可視化が可能です",
      logic: null,
      flow_danger: null,
      flow_safe: null,
      mitre: null,
      references: "・MITRE ATT&CK 公式: https://attack.mitre.org/\n・ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/\n・ATT&CK for Enterprise: https://attack.mitre.org/matrices/enterprise/\n・MITRE ATT&CK 日本語参考: https://www.intellilink.co.jp/column/security/2020/060200.aspx"
    }
  },
  {
    id: "ref-nsa-cisa",
    category: "参考資料",
    categoryId: "references",
    title: "NSA/CISAガイダンス",
    content: {
      summary: "NSA（National Security Agency）と CISA（Cybersecurity and Infrastructure Security Agency）は、サイバーセキュリティに関する技術的なガイダンスやアドバイザリーを定期的に公開しています。\n\nこれらのガイダンスには、具体的な検出手法、緩和策、設定推奨が含まれており、本ツールの検出ロジックの参考にしています。",
      points: "・NSA/CISA Joint Advisories は APT（国家支援攻撃グループ）の最新手法を解説\n・CIS Benchmarks と連携した Windows セキュリティ設定ガイド\n・PowerShell のセキュアな設定に関するガイダンス\n・イベントログの推奨設定と監視項目\n・ネットワーク防御のベストプラクティス",
      logic: null,
      flow_danger: null,
      flow_safe: null,
      mitre: null,
      references: "・CISA 公式: https://www.cisa.gov/\n・NSA Cybersecurity Advisories: https://www.nsa.gov/cybersecurity-advisories/\n・CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n・CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks\n・NIST Cybersecurity Framework: https://www.nist.gov/cyberframework"
    }
  },
  {
    id: "ref-oss",
    category: "参考資料",
    categoryId: "references",
    title: "GitHub OSSプロジェクト",
    content: {
      summary: "本ツールの開発に際して参考にした、または内部で使用しているオープンソースプロジェクトの一覧です。\n\nこれらのプロジェクトはセキュリティコミュニティによって開発・維持されており、フォレンジック解析やマルウェア検出の分野で広く活用されています。",
      points: "・Neo23x0/signature-base: YARA ルールの包括的なコレクション（本ツールで使用）\n・hasherezade/pe-sieve: プロセスメモリ内の PE 検出ツール\n・Volatility Foundation: メモリフォレンジックフレームワーク\n・Eric Zimmerman Tools: Windows フォレンジックツール群\n・SANS DFIR: デジタルフォレンジックの教育・ツール\n・Sysinternals: Microsoft 公式の高度なシステムユーティリティ",
      logic: null,
      flow_danger: null,
      flow_safe: null,
      mitre: null,
      references: "・Neo23x0/signature-base: https://github.com/Neo23x0/signature-base\n・hasherezade/pe-sieve: https://github.com/hasherezade/pe-sieve\n・Volatility3: https://github.com/volatilityfoundation/volatility3\n・Eric Zimmerman Tools: https://ericzimmerman.github.io/\n・Sysinternals: https://learn.microsoft.com/en-us/sysinternals/\n・SANS DFIR: https://www.sans.org/digital-forensics-incident-response/\n・psutil: https://github.com/giampaolo/psutil\n・olefile: https://github.com/decalage2/olefile\n・yara-python: https://github.com/VirusTotal/yara-python\n・PyPDF2: https://github.com/py-pdf/pypdf"
    }
  }
];
