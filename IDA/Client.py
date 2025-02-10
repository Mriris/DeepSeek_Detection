import socket
import json

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # 连接到 IDA 中的服务器
        client_socket.connect(('localhost', 65432))

        # 向服务器发送请求
        client_socket.sendall(b'Request function information')

        # 接收来自服务器的响应数据
        data = b''  # 初始化一个空的字节串来接收数据
        while True:
            chunk = client_socket.recv(1024)  # 接收1024字节
            if not chunk:
                break
            data += chunk  # 将接收到的块拼接起来

        if data:
            print("Received data from IDA:")
            try:
                # 将接收到的数据解析为 JSON 格式
                functions = json.loads(data.decode())
                print(functions)

                # 读取保存的 JSON 文件
                with open(r'C:\0Program\Python\DeepSeek_Detection\example\test3\extracted_functions.json', 'r') as json_file:
                    saved_functions = json.load(json_file)
                    print("Functions saved to file:")
                    print(saved_functions)

            except json.JSONDecodeError as e:
                print(f"JSON decoding error: {e}")
                print("Raw data received:")
                print(data.decode())

# 启动客户端
start_client()
