# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'Crypto.Cipher.AES',
        'Crypto.Cipher._mode_gcm',
        'Crypto.Hash.SHA256',
        'Crypto.Protocol.KDF',
        'Crypto.Random',
        'Crypto.Math',
        'Crypto.Util',
        'Crypto.Util._cpuid_c',
        'Crypto.Util._file_system',
        'Crypto.Util.strxor',
        'Crypto.Util.padding',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MD5-AES加密解密工具',
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
