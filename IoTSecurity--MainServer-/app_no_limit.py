from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
from ECCOperator import ECC_P256
import os

app = Flask(__name__)

# --- 配置 ---
PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

# --- 加載密鑰 ---
def load_private_key(filename):
    """從 PEM 文件加載私鑰"""
    try:
        with open(filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # 如果你的私鑰有密碼保護，請在這裡提供
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        app.logger.error(f"錯誤：私鑰文件 '{filename}' 未找到。")
        return None
    except Exception as e:
        app.logger.error(f"加載私鑰時出錯: {e}")
        return None

def load_public_key(filename):
    """從 PEM 文件加載公鑰"""
    try:
        with open(filename, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except FileNotFoundError:
        app.logger.error(f"錯誤：公鑰文件 '{filename}' 未找到。")
        return None
    except Exception as e:
        app.logger.error(f"加載公鑰時出錯: {e}")
        return None

private_key = load_private_key(PRIVATE_KEY_FILE)
public_key = load_public_key(PUBLIC_KEY_FILE)

if not private_key or not public_key:
    app.logger.error("密鑰加載失敗，應用程序可能無法正常工作。")
    # 你可以在這裡決定是否要退出應用
    # exit(1)

# --- 加密/解密輔助函數 ---
def decrypt_message_rsa(encrypted_message_b64, priv_key):
    """使用 RSA 私鑰解密 Base64 編碼的消息"""
    if not priv_key:
        raise ValueError("私鑰未加載")
    try:
        encrypted_message_bytes = base64.b64decode(encrypted_message_b64)
        decrypted_bytes = priv_key.decrypt(
            encrypted_message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        app.logger.error(f"解密失敗: {e}")
        raise

def encrypt_message_rsa(message_str, pub_key):
    """使用 RSA 公鑰加密消息並返回 Base64 編碼的字符串"""
    if not pub_key:
        raise ValueError("公鑰未加載")
    try:
        message_bytes = message_str.encode('utf-8')
        encrypted_bytes = pub_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        app.logger.error(f"加密失敗: {e}")
        raise

# --- API 端點 ---
@app.route('/decrypt', methods=['POST'])
def decrypt_packet():
    '''
    if not private_key or not public_key:
        return jsonify({"error": "伺服器密鑰配置錯誤"}), 500
    '''

    data = request.get_json()
    if not data or 'encrypted_packet' not in data:
        return jsonify({"error": "請求中缺少 'encrypted_packet'"}), 400

    b64_encrypted_pkg = data['encrypted_packet']
    encrypted_message = {
        "temp_key": base64.b64decode(b64_encrypted_pkg["temp_key"]),
        "nonce"   : base64.b64decode(b64_encrypted_pkg["nonce"]),
        "secret"  : base64.b64decode(b64_encrypted_pkg["secret"]),}
    ecc1 = ECC_P256()
    print(ecc1.asymmetric_decryption(encrypted_message))
    return jsonify({"status": "success", "encrypted_response": True}), 200
    '''
    try:
        decrypted_message = decrypt_message_rsa(encrypted_packet_b64, private_key)
        print(f"收到的解密後訊息: {decrypted_message}") # 打印解密後的訊息

        # 回傳加密的 "OK"
        response_message = "OK"
        encrypted_ok_b64 = encrypt_message_rsa(response_message, public_key)
        
        return jsonify({"status": "success", "encrypted_response": encrypted_ok_b64}), 200

    except ValueError as ve: # 通常是密鑰未加載
        app.logger.error(f"處理請求時出錯 (ValueError): {ve}")
        return jsonify({"error": "伺服器內部錯誤"}), 500
    except Exception as e:
        app.logger.error(f"處理請求時出錯: {e}")
        # 通常解密失敗會是 cryptography.exceptions.InvalidTag 或類似的
        # 或者 base64.binascii.Error: Incorrect padding
        return jsonify({"error": f"解密或加密失敗: {str(e)}"}), 500
    '''

@app.route('/test', methods=['GET'])
def test():
    return "王裕誠同學你好"


if __name__ == '__main__':
    # 確保在生產環境中不要使用 debug=True
    app.run(host='0.0.0.0', port=5000, debug=True)