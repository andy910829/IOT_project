import requests
import json
import base64
import threading
import time
import argparse
from ECCOperator import ECC_P256 # 確保 ECCOperator.py 在同目錄或PYTHONPATH

# 全局統計
success_count = 0
failure_count = 0
count_lock = threading.Lock()

# 假設 ECCOperator.py 中的 ECC_P256 實例化和方法調用如下
# 你可能需要根據你的 ECCOperator.py 進行調整
ecc_operator = ECC_P256()
SERVER_PUBLIC_KEY_PEM_PATH = "public_key.pem" # 伺服器公鑰

# 加載伺服器公鑰 (PEM 格式)
# ECCOperator 應該有一個方法來加載 PEM 公鑰，或者直接接受 PEM 字串
# 這裡假設 read_pk_pem() 返回的是可以直接用於加密的公鑰對象或 PEM 字串
# 或者 asymmetric_encryption 直接接受 PEM 字串作為公鑰
try:
    # 方式一：如果 ECCOperator.read_pk_pem() 返回的是 PEM 字串
    # with open(SERVER_PUBLIC_KEY_PEM_PATH, 'rb') as f:
    #     server_pk_pem_bytes = f.read()
    # server_public_key_for_encryption = server_pk_pem_bytes

    # 方式二：如果 ECCOperator.read_pk_pem() 返回的是內部公鑰對象
    # server_public_key_for_encryption = ecc_operator.read_pk_pem(filename=SERVER_PUBLIC_KEY_PEM_PATH)
    
    # 根據 HttpHandler.py, read_pk_pem() 似乎不需要參數，並且返回 PEM 字串
    # 而 asymmetric_encryption 接受 PEM 字串作為公鑰
    # 所以我們直接讀取文件內容
    with open(SERVER_PUBLIC_KEY_PEM_PATH, 'rb') as f:
        server_pk_pem_content = f.read()
    
    if not server_pk_pem_content:
        raise FileNotFoundError("公鑰文件為空或加載失敗")
    print(f"成功從 {SERVER_PUBLIC_KEY_PEM_PATH} 加載伺服器公鑰。")

except FileNotFoundError:
    print(f"錯誤：伺服器公鑰文件 '{SERVER_PUBLIC_KEY_PEM_PATH}' 未找到。請先生成密鑰。")
    exit(1)
except Exception as e:
    print(f"加載伺服器公鑰時出錯: {e}")
    exit(1)


def generate_encrypted_payload():
    """
    生成用於發送到 /decrypt 端點的加密數據包。
    """
    message_to_encrypt = b"This is a test payload for DDoS script " + base64.b64encode(str(time.time()).encode())
    
    # 使用 ECCOperator 加密消息
    # 假設 asymmetric_encryption 返回一個包含 temp_key, nonce, secret (都是 bytes) 的字典
    encrypted_message_dict = ecc_operator.asymmetric_encryption(message_to_encrypt, server_pk_pem_content)
    
    b64_encrypted_pkg = {
        "temp_key": base64.b64encode(encrypted_message_dict["temp_key"]).decode("utf-8"),
        "nonce": base64.b64encode(encrypted_message_dict["nonce"]).decode("utf-8"),
        "secret": base64.b64encode(encrypted_message_dict["secret"]).decode("utf-8"),
    }
    return {"encrypted_packet": b64_encrypted_pkg}

def send_request(target_url, session):
    global success_count, failure_count
    payload = generate_encrypted_payload()
    try:
        # 使用 session 可以重用 TCP 連接，效率更高
        response = session.post(target_url, json=payload, timeout=10)
        response.raise_for_status() # 如果狀態碼是 4xx 或 5xx，則拋出異常
        # print(f"Response: {response.status_code} - {response.text[:50]}")
        with count_lock:
            success_count += 1
        return True
    except requests.exceptions.Timeout:
        # print("請求超時")
        with count_lock:
            failure_count += 1
    except requests.exceptions.ConnectionError:
        # print("連接錯誤")
        with count_lock:
            failure_count += 1
    except requests.exceptions.HTTPError as e:
        # print(f"HTTP 錯誤: {e.response.status_code} - {e.response.text[:100]}")
        with count_lock:
            failure_count += 1
    except Exception as e:
        # print(f"發送請求時發生未知錯誤: {e}")
        with count_lock:
            failure_count += 1
    return False

def worker(target_url, num_requests):
    """
    每個線程執行的工作函數。
    """
    # print(f"線程 {threading.get_ident()} 開始執行 {num_requests} 次請求")
    # 為每個線程創建一個 Session 對象
    with requests.Session() as session:
        for _ in range(num_requests):
            send_request(target_url, session)
            # time.sleep(0.01) # 可選：在請求之間添加微小延遲，以避免瞬間打垮本地網絡接口

    # print(f"線程 {threading.get_ident()} 完成")


def main():
    parser = argparse.ArgumentParser(description="針對 Flask /decrypt 端點的壓力測試腳本")
    parser.add_argument("url", help="目標伺服器 URL (例如 http://127.0.0.1:5000)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="併發線程數 (預設: 10)")
    parser.add_argument("-r", "--requests", type=int, default=100, help="每個線程發送的請求數 (預設: 100)")
    
    args = parser.parse_args()

    target_decrypt_url = args.url.rstrip('/') + "/decrypt"
    num_threads = args.threads
    requests_per_thread = args.requests
    total_requests = num_threads * requests_per_thread

    print(f"開始壓力測試...")
    print(f"目標 URL: {target_decrypt_url}")
    print(f"線程數: {num_threads}")
    print(f"每個線程請求數: {requests_per_thread}")
    print(f"總請求數: {total_requests}")
    print("-" * 30)

    threads = []
    start_time = time.time()

    for i in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_decrypt_url, requests_per_thread))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    duration = end_time - start_time

    print("-" * 30)
    print("壓力測試完成！")
    print(f"總耗時: {duration:.2f} 秒")
    print(f"總請求數: {total_requests}")
    print(f"成功請求: {success_count}")
    print(f"失敗請求: {failure_count}")
    if duration > 0:
        print(f"平均 RPS (每秒請求數): {total_requests / duration:.2f}")
        print(f"平均成功 RPS: {success_count / duration:.2f}")
    else:
        print("執行時間過短，無法計算 RPS。")

if __name__ == "__main__":
    main()