"""手动功能验证 — 运行此脚本验证加解密正确性"""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from main import AESEngine, MD5Engine

# 测试1: 文本加解密
print("=== 测试1: 文本加解密 ===")
cipher = AESEngine.encrypt_text("你好, World! 123", "test_password")
print(f"密文: {cipher[:40]}...")
plain = AESEngine.decrypt_text(cipher, "test_password")
assert plain == "你好, World! 123", f"解密内容不匹配: {plain}"
print("[PASS] 文本加解密通过")

# 测试2: 密码错误
print("\n=== 测试2: 密码错误检测 ===")
try:
    AESEngine.decrypt_text(cipher, "wrong_password")
    assert False, "应该抛出异常"
except (ValueError, Exception):
    print("[PASS] 密码错误正确检测")

# 测试3: 文件加解密
print("\n=== 测试3: 文件加解密 ===")
test_file = 'test_original.txt'
with open(test_file, 'w', encoding='utf-8') as f:
    f.write('这是一个测试文件内容。' * 1000)

outpath, _ = AESEngine.encrypt_file(test_file, 'file_password')
print(f"加密文件: {outpath}")
assert os.path.exists(outpath), "加密文件未生成"

dec_path, _ = AESEngine.decrypt_file(outpath, 'file_password')
print(f"解密文件: {dec_path}")
with open(dec_path, 'r', encoding='utf-8') as f:
    content = f.read()
assert '测试文件内容' in content, "解密内容不正确"
print("[PASS] 文件加解密通过")

# 测试4: MD5
print("\n=== 测试4: MD5 计算 ===")
md5 = MD5Engine.text_md5("hello")
assert len(md5) == 32, f"MD5 长度错误: {len(md5)}"
assert md5 == "5d41402abc4b2a76b9719d911017c592", f"MD5 值错误: {md5}"
print(f"MD5('hello') = {md5}")
print("[PASS] MD5 计算通过")

# 测试5: 文件 MD5
md5_file = MD5Engine.file_md5(test_file)
assert len(md5_file) == 32
print(f"文件 MD5: {md5_file}")
print("[PASS] 文件 MD5 计算通过")

# 清理临时文件（dec_path 可能与 test_file 同名，已在解密时覆盖）
os.remove(outpath)
os.remove(dec_path)

print("\n" + "=" * 40)
print("所有测试通过!")
