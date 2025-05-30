import socket

HOST = '192.168.0.20'       # 空字串代表監聽所有介面（含 eth0）
PORT = 5000     # 可自行指定未被佔用的埠號

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"TCP 伺服器啟動，監聽埠號 {PORT}")
    conn, addr = s.accept()
    with conn:
        print('已連線來自', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                print("連線關閉")
                break
            print("收到資料：", data)
            # 若要回傳，可以：
            # conn.sendall(b"ACK")
