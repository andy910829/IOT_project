from flask import Flask, request, jsonify
# ... (其他 imports 保持不變) ...
import base64
from ECCOperator import ECC_P256
import os
import time
import threading
from collections import defaultdict

app = Flask(__name__)

# --- 配置 ---
PUBLIC_KEY_FILE = "public_key.pem" # 假設 ECCOperator 會自己讀取
PRIVATE_KEY_FILE = "private_key.pem" # 假設 ECCOperator 會自己讀取

# --- 應用級配置 ---
# 限制請求體的大小，例如 1MB。這有助於防止惡意的大型請求。
# 需要注意的是，這個配置是針對整個請求體的，包括文件上傳等。
# 對於你的 /decrypt API，如果 payload 很小，可以設置得更小。
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

# --- Rate Limiting 配置 ---
# 允許每個 IP 在 RATE_LIMIT_WINDOW_SECONDS 秒內最多 RATE_LIMIT_REQUESTS 次請求 /decrypt
DECRYPT_RATE_LIMIT_REQUESTS = 10
DECRYPT_RATE_LIMIT_WINDOW_SECONDS = 60

# 針對其他未知或高頻請求的更嚴格的全局限制 (可選)
# GLOBAL_RATE_LIMIT_REQUESTS = 100 # 例如每分鐘100次
# GLOBAL_RATE_LIMIT_WINDOW_SECONDS = 60

# 用於存儲 IP 請求時間戳的字典
# 結構: { "ip_address": {"endpoint_name": [timestamp1, ...], "global": [timestamp1,...]}, ... }
# 使用 defaultdict 可以簡化初始化
ip_request_tracker = defaultdict(lambda: defaultdict(list))
ip_data_lock = threading.Lock()


# --- 加載密鑰 (你的原始邏輯) ---
# 你的 /decrypt 路由直接使用了 ECCOperator，所以這些 RSA 密鑰和函數
# 對 /decrypt 而言可能並非活躍。確保 ECCOperator 能正確加載它需要的密鑰。
# ... (load_private_key, load_public_key, private_key_rsa, public_key_rsa 保持不變) ...
# ... (decrypt_message_rsa, encrypt_message_rsa 保持不變) ...


# --- Rate Limiter 和基礎請求檢查 ---
@app.before_request
def basic_security_checks():
    # 1. 獲取真實 IP (考慮反向代理)
    if request.headers.getlist("X-Forwarded-For"):
        client_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        client_ip = request.remote_addr

    current_time = time.time()

    with ip_data_lock:
        # 2. 特定端點的速率限制 (/decrypt)
        if request.endpoint == 'decrypt_packet':
            request_times = ip_request_tracker[client_ip]['decrypt_packet']
            # 清理過期時間戳
            valid_request_times = [t for t in request_times if t > current_time - DECRYPT_RATE_LIMIT_WINDOW_SECONDS]
            if len(valid_request_times) >= DECRYPT_RATE_LIMIT_REQUESTS:
                app.logger.warning(f"IP {client_ip} for /decrypt reached rate limit.")
                retry_after = (valid_request_times[0] + DECRYPT_RATE_LIMIT_WINDOW_SECONDS) - current_time
                return jsonify({"error": "請求過於頻繁 (decrypt)"}), 429 # Too Many Requests
            valid_request_times.append(current_time)
            ip_request_tracker[client_ip]['decrypt_packet'] = valid_request_times

        # 3. (可選) 全局速率限制 (針對所有請求或特定 API 組)
        # request_times_global = ip_request_tracker[client_ip]['global']
        # valid_request_times_global = [t for t in request_times_global if t > current_time - GLOBAL_RATE_LIMIT_WINDOW_SECONDS]
        # if len(valid_request_times_global) >= GLOBAL_RATE_LIMIT_REQUESTS:
        #     app.logger.warning(f"IP {client_ip} reached global rate limit.")
        #     return jsonify({"error": "請求過於頻繁 (global)"}), 429
        # valid_request_times_global.append(current_time)
        # ip_request_tracker[client_ip]['global'] = valid_request_times_global

    # 4. 檢查 User-Agent (非常基礎的檢查)
    # user_agent = request.headers.get('User-Agent')
    # if not user_agent or "bot" in user_agent.lower() or "spider" in user_agent.lower(): # 過於簡單，易被繞過
    #     # app.logger.info(f"Suspicious User-Agent from {client_ip}: {user_agent}")
    #     # pass # 可以選擇記錄或直接拒絕，但此方法誤判率高
    #     pass

    return None # 繼續處理請求

# Flask 會在請求體過大時自動返回 413 Request Entity Too Large
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify(error="請求體過大"), 413

# --- API 端點 ---
@app.route('/decrypt', methods=['POST'])
def decrypt_packet():
    # 速率限制已由 @app.before_request 處理

    # 5. 輸入驗證 (更早地檢查請求結構)
    data = request.get_json(silent=True) # silent=True 避免在非 JSON 時直接拋出 400
    if data is None:
        return jsonify({"error": "請求體不是有效的 JSON"}), 400
    if 'encrypted_packet' not in data or not isinstance(data['encrypted_packet'], dict):
        return jsonify({"error": "請求中缺少 'encrypted_packet' 或格式錯誤"}), 400

    b64_encrypted_pkg = data['encrypted_packet']
    required_keys = ["temp_key", "nonce", "secret"]
    for key in required_keys:
        if key not in b64_encrypted_pkg or not isinstance(b64_encrypted_pkg[key], str):
            return jsonify({"error": f"encrypted_packet 中缺少 '{key}' 或其值不是字符串"}), 400

    try:
        encrypted_message = {
            "temp_key": base64.b64decode(b64_encrypted_pkg["temp_key"]),
            "nonce"   : base64.b64decode(b64_encrypted_pkg["nonce"]),
            "secret"  : base64.b64decode(b64_encrypted_pkg["secret"]),
        }
    except (TypeError, base64.binascii.Error) as e:
        app.logger.warning(f"Base64 解碼失敗來自 IP {request.remote_addr}: {e}")
        return jsonify({"error": "無效的 Base64 編碼數據"}), 400

    try:
        ecc1 = ECC_P256() # 確保 ECCOperator 正確處理其密鑰
    except Exception as e:
        app.logger.error(f"初始化 ECCOperator 失敗: {e}")
        return jsonify({"error": "伺服器內部加密組件錯誤"}), 500

    try:
        decrypted_content = ecc1.asymmetric_decryption(encrypted_message)
        app.logger.info(f"成功解密來自 IP {request.remote_addr} 的數據。")
        return jsonify({"status": "success", "message": "數據已成功解密處理。"}), 200
    except ValueError as ve:
        app.logger.warning(f"ECC 解密 ValueError 來自 IP {request.remote_addr}: {ve}")
        return jsonify({"error": "解密失敗，數據可能已損壞或密鑰不匹配"}), 400
    except Exception as e:
        app.logger.error(f"ECC 解密時發生未知錯誤: {e}")
        return jsonify({"error": "解密過程中發生伺服器內部錯誤"}), 500


@app.route('/test', methods=['GET'])
def test():
    return "王裕誠同學你好"


if __name__ == '__main__':
    # 使用 threaded=True 進行本地測試
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)