"""MD5 + AES 加密解密工具 — Tkinter 桌面应用"""

import hashlib
import os
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


class AESEngine:
    """AES-256-GCM 加解密引擎"""

    SALT_SIZE = 16
    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    ITERATIONS = 100_000

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        return PBKDF2(password, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)

    @staticmethod
    def encrypt_text(plaintext: str, password: str) -> str:
        """加密文本，返回 Base64 编码的密文"""
        salt = get_random_bytes(16)
        key = AESEngine._derive_key(password, salt)
        nonce = get_random_bytes(AESEngine.NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        combined = salt + nonce + tag + ciphertext
        return base64.b64encode(combined).decode('ascii')

    @staticmethod
    def decrypt_text(encrypted_b64: str, password: str) -> str:
        """解密 Base64 密文，密码错误时抛出 ValueError"""
        raw = base64.b64decode(encrypted_b64)
        salt = raw[:16]
        nonce = raw[16:28]
        tag = raw[28:44]
        ciphertext = raw[44:]
        key = AESEngine._derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt_file(filepath: str, password: str) -> tuple:
        """加密文件，返回 (输出路径, MD5值)"""
        salt = get_random_bytes(16)
        key = AESEngine._derive_key(password, salt)
        nonce = get_random_bytes(AESEngine.NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        outpath = filepath + '.enc'
        with open(filepath, 'rb') as fin, open(outpath, 'wb') as fout:
            fout.write(salt)
            fout.write(nonce)
            data = fin.read()
            ciphertext, tag = cipher.encrypt_and_digest(data)
            fout.write(tag)
            fout.write(ciphertext)

        md5_val = MD5Engine.file_md5(outpath)
        return outpath, md5_val

    @staticmethod
    def decrypt_file(filepath: str, password: str) -> tuple:
        """解密文件，返回 (输出路径, MD5值)，密码错误时抛出 ValueError"""
        with open(filepath, 'rb') as fin:
            salt = fin.read(16)
            nonce = fin.read(12)
            tag = fin.read(16)
            ciphertext = fin.read()

        key = AESEngine._derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        outpath = filepath[:-4] if filepath.endswith('.enc') else filepath + '.dec'
        with open(outpath, 'wb') as fout:
            fout.write(plaintext)

        md5_val = MD5Engine.file_md5(outpath)
        return outpath, md5_val


class MD5Engine:
    """MD5 哈希计算引擎"""

    @staticmethod
    def text_md5(text: str) -> str:
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    @staticmethod
    def file_md5(filepath: str) -> str:
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()


class App(tk.Tk):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.title("MD5 + AES 加密解密工具")
        self.geometry("600x500")
        self.resizable(True, True)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        notebook.add(TextTab(notebook), text="文本加解密")
        notebook.add(FileTab(notebook), text="文件加解密")
        notebook.add(MD5Tab(notebook), text="MD5 计算")


class TextTab(ttk.Frame):
    """文本加解密标签页"""

    def __init__(self, parent):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="密码:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.pwd_entry = ttk.Entry(self, show='*', width=60)
        self.pwd_entry.pack(fill=tk.X, padx=5)

        ttk.Label(self, text="输入文本:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.input_text = tk.Text(self, height=6)
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="加密", command=self._encrypt).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="解密", command=self._decrypt).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="复制结果", command=self._copy).pack(side=tk.LEFT)

        ttk.Label(self, text="输出结果:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.output_text = tk.Text(self, height=6)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 10))

    def _encrypt(self):
        text = self.input_text.get('1.0', tk.END).strip()
        pwd = self.pwd_entry.get()
        if not text or not pwd:
            messagebox.showwarning("提示", "请输入文本和密码")
            return
        try:
            result = AESEngine.encrypt_text(text, pwd)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("加密失败", str(e))

    def _decrypt(self):
        text = self.input_text.get('1.0', tk.END).strip()
        pwd = self.pwd_entry.get()
        if not text or not pwd:
            messagebox.showwarning("提示", "请输入密文和密码")
            return
        try:
            result = AESEngine.decrypt_text(text, pwd)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except (ValueError, Exception):
            messagebox.showerror("解密失败", "密码错误或密文损坏")

    def _copy(self):
        result = self.output_text.get('1.0', tk.END).strip()
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)


class FileTab(ttk.Frame):
    """文件加解密标签页"""

    def __init__(self, parent):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="选择文件:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, padx=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="浏览...", command=self._browse).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Label(self, text="密码:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.pwd_entry = ttk.Entry(self, show='*', width=60)
        self.pwd_entry.pack(fill=tk.X, padx=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="加密", command=self._encrypt).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="解密", command=self._decrypt).pack(side=tk.LEFT)

        ttk.Label(self, text="输出信息:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.info_text = tk.Text(self, height=6, state=tk.DISABLED)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 10))

    def _browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def _log(self, msg):
        self.info_text.configure(state=tk.NORMAL)
        self.info_text.insert(tk.END, msg + '\n')
        self.info_text.configure(state=tk.DISABLED)

    def _encrypt(self):
        path = self.file_path.get()
        pwd = self.pwd_entry.get()
        if not path or not pwd:
            messagebox.showwarning("提示", "请选择文件并输入密码")
            return
        try:
            outpath, md5_val = AESEngine.encrypt_file(path, pwd)
            self._log(f"加密成功: {outpath}")
            self._log(f"MD5: {md5_val}")
        except Exception as e:
            messagebox.showerror("加密失败", str(e))

    def _decrypt(self):
        path = self.file_path.get()
        pwd = self.pwd_entry.get()
        if not path or not pwd:
            messagebox.showwarning("提示", "请选择文件并输入密码")
            return
        try:
            outpath, md5_val = AESEngine.decrypt_file(path, pwd)
            self._log(f"解密成功: {outpath}")
            self._log(f"MD5: {md5_val}")
        except (ValueError, Exception):
            messagebox.showerror("解密失败", "密码错误或文件损坏")


class MD5Tab(ttk.Frame):
    """MD5 计算标签页"""

    def __init__(self, parent):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="输入文本:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.text_input = tk.Text(self, height=3)
        self.text_input.pack(fill=tk.X, padx=5)

        text_btn_frame = ttk.Frame(self)
        text_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(text_btn_frame, text="计算 MD5", command=self._text_md5).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(text_btn_frame, text="复制", command=self._copy_text_md5).pack(side=tk.LEFT)

        self.text_result = tk.StringVar(value="MD5 值将显示在此处")
        ttk.Label(self, textvariable=self.text_result, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, padx=5, ipady=3)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5, pady=10)

        ttk.Label(self, text="选择文件:").pack(anchor=tk.W, padx=5)
        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, padx=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="浏览...", command=self._browse).pack(side=tk.LEFT, padx=(5, 0))

        file_btn_frame = ttk.Frame(self)
        file_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(file_btn_frame, text="计算 MD5", command=self._file_md5).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_btn_frame, text="复制", command=self._copy_file_md5).pack(side=tk.LEFT)

        self.file_result = tk.StringVar(value="MD5 值将显示在此处")
        ttk.Label(self, textvariable=self.file_result, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, padx=5, ipady=3)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5, pady=10)

        ttk.Label(self, text="MD5 对比校验（粘贴两个 MD5 值比对）:").pack(anchor=tk.W, padx=5)

        comp_frame = ttk.Frame(self)
        comp_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(comp_frame, text="MD5-1:").grid(row=0, column=0, sticky=tk.W, pady=(0, 2))
        self.compare1 = tk.StringVar()
        ttk.Entry(comp_frame, textvariable=self.compare1, width=55).grid(row=0, column=1, padx=(5, 0), pady=(0, 2))

        ttk.Label(comp_frame, text="MD5-2:").grid(row=1, column=0, sticky=tk.W, pady=(0, 2))
        self.compare2 = tk.StringVar()
        ttk.Entry(comp_frame, textvariable=self.compare2, width=55).grid(row=1, column=1, padx=(5, 0), pady=(0, 2))

        ttk.Button(comp_frame, text="比对", command=self._compare).grid(row=2, column=1, sticky=tk.W, pady=5)
        self.compare_result = tk.StringVar()
        ttk.Label(comp_frame, textvariable=self.compare_result).grid(row=2, column=1, pady=5)

    def _browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def _text_md5(self):
        text = self.text_input.get('1.0', tk.END).strip()
        if not text:
            messagebox.showwarning("提示", "请输入文本")
            return
        self.text_result.set(MD5Engine.text_md5(text))

    def _copy_text_md5(self):
        val = self.text_result.get()
        if val != "MD5 值将显示在此处":
            self.clipboard_clear()
            self.clipboard_append(val)

    def _file_md5(self):
        path = self.file_path.get()
        if not path:
            messagebox.showwarning("提示", "请选择文件")
            return
        self.file_result.set(MD5Engine.file_md5(path))

    def _copy_file_md5(self):
        val = self.file_result.get()
        if val != "MD5 值将显示在此处":
            self.clipboard_clear()
            self.clipboard_append(val)

    def _compare(self):
        v1 = self.compare1.get().strip().lower()
        v2 = self.compare2.get().strip().lower()
        if not v1 or not v2:
            messagebox.showwarning("提示", "请输入两个 MD5 值")
            return
        if v1 == v2:
            self.compare_result.set("✓ 匹配一致")
        else:
            self.compare_result.set("✗ 不匹配")


if __name__ == '__main__':
    app = App()
    app.mainloop()
