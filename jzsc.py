# -*- coding: utf-8 -*-
# Author: Litre WU
# E-mail: litre-wu@tutanota.com
# Software: PyCharm
# File: jzsc.py
from Cryptodome.Cipher import AES
from binascii import a2b_hex
from time import time
from random import randint
from json import dumps, loads
from js2py import eval_js
from base64 import decodebytes,b64encode
import re


# 四库一(web)
async def jzsc_web(text):
    try:
        iv = '0123456789ABCDEF'.encode()  # 偏移量
        key = 'jo8j9wGw%6HbxfFn'.encode()  # 密钥
        cipher = AES.new(key, AES.MODE_CBC, iv)  # 创建一个AES对象（密钥，模式，偏移量）
        decrypt_bytes = cipher.decrypt(bytes.fromhex(text))  # 解密
        result = decrypt_bytes.decode().strip()  # 编码转换
        print(result)
        if result[0] == "[":
            result = re.compile(r'[.*]').findall(result)
        elif result[0] == "{":
            result = re.compile(r'{.*}').findall(result)
        return result
    except Exception as e:
        print(e)
        return None


# 四库一(小程序-不定周期更换key)
async def jzsc_lit(text):
    try:
        # 秘钥
        key = 'cd3b2e6d63473cadda38a9106b6b4e07'
        # 初始化加密器
        aes = AES.new(a2b_hex(key), AES.MODE_ECB)
        # 优先逆向解密base64成bytes
        base64_decrypted = decodebytes(text.encode())
        # 执行解密密并转码返回str
        result = str(aes.decrypt(base64_decrypted).decode()).strip()
        print(result)
        if result[0] == "[":
            result = re.compile(r'[.*]').findall(result)
        elif result[0] == "{":
            result = re.compile(r'{.*}').findall(result)
        return result
    except Exception as e:
        print(e)
        return None


# 企查查-建筑查查 newrelic
async def qcc_newrelic():
    a = """
            function a(t) {
                        function e() {
                            return n ? 15 & n[r++] : 16 * Math.random() | 0
                        }
                        var n = null, r = 0, o = window.crypto || window.msCrypto;
                        o && o.getRandomValues && Uint8Array && (n = o.getRandomValues(new Uint8Array(31)));
                        for (var i = [], a = 0; a < t; a++) i.push(e().toString(16));
                        return i.join("")
                    }
            """
    a = eval_js(a)
    h = a(16)
    m = a(32)
    v = str(int(time() * 1000))
    accountID = str(randint(1000000, 3000000))
    agentID = str(int(time()))
    NREUM = {"accountID": accountID, "trustKey": accountID, "agentID": agentID,
             "licenseKey": "NRJS-a6860bd2d258d985bd2", "applicationID": agentID}
    data = dumps({'d': {'ac': NREUM["trustKey"], 'ap': NREUM["agentID"], 'id': h, 'ti': v, 'tr': m, 'ty': 'Browser'},
                  'v': [0, 1]})
    result = b64encode(data.encode()).decode()
    return result


# 浙江建设厅 token
async def jzsc_zj_token(**kwargs):
    pad = lambda s: s + (AES.block_size - len(s.encode()) % AES.block_size) * chr(
        AES.block_size - len(s.encode()) % AES.block_size)
    t = str(int(time() * 1000))
    t = pad(t).encode()
    key = '255B675CDF21B04F923992E0E9F4A498'.encode()  # 密钥
    iv = '255B675CDF21B04F'.encode()  # 偏移量
    cipher = AES.new(key, AES.MODE_CBC, iv)  # 创建一个AES对象（密钥，模式，偏移量）
    encrypt_bytes = cipher.encrypt(t)
    token = b64encode(encrypt_bytes).decode()
    print(token)
    return token


# 浙江建设厅 idcard
async def jzsc_zj_idcard_decrypt(text):
    try:
        iv = 'ABCDEF1234123412'  # 偏移量
        key = '1234123412ABCDEF'  # 密钥
    
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())  # 创建一个AES对象（密钥，模式，偏移量）
        decrypt_bytes = cipher.decrypt(bytes.fromhex(text))  # 解密
        result = str(decrypt_bytes, encoding='UTF-8')
        print(result)
        return re.findall('\d+',result)
    except Exception as e:
        print(e)
        return None


