# -*- mode: python ; coding: utf-8 -*-
# Sacabambaspis.spec - PyInstaller Build Configuration
# Version: v3.2
# ERR-SPEC-001: specファイル読み込みエラー時はパスを確認

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('web', 'web'),
        ('collectors', 'collectors'),
        ('utils', 'utils'),
    ],
    hiddenimports=[
        'flask',
        'psutil',
        'collectors.memory',
        'collectors.network',
        'collectors.process',
        'collectors.persistence',
        'collectors.registry',
        'collectors.eventlog',
        'collectors.evidence',
        'collectors.dna',
        'collectors.ads',
        'collectors.pca',
        'collectors.recall',
        'collectors.wsl',
        'collectors.cam',
        'collectors.srum',
        'utils.path_helper',
        'utils.tutor_template',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Sacabambaspis',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
