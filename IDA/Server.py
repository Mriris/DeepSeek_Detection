import socket
import idaapi
import idautils
import idc
import json
import time


def extract_function_info():
    functions = []
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        func_start = func_ea
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

        function_info = {
            'function_name': func_name,
            'start_address': hex(func_start),
            'end_address': hex(func_end),
            'instructions': extract_instructions(func_start, func_end)
        }

        functions.append(function_info)
    return functions


def extract_instructions(func_start, func_end):
    instructions = []
    for head in idautils.Heads(func_start, func_end):
        instruction = idc.GetDisasm(head)
        instructions.append({
            'address': hex(head),
            'instruction': instruction
        })
    return instructions


def save_as_json(functions, file_path):
    with open(file_path, 'w') as json_file:
        json.dump(functions, json_file, indent=4)
    print(f"Functions saved to {file_path}")


def start_server():
    # 设置服务器，监听来自PyCharm的请求
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))  # 绑定本地地址和端口
    server_socket.listen(1)  # 设置最多允许一个客户端连接

    server_socket.setblocking(0)  # 设置为非阻塞模式
    print("Waiting for client connection...")

    while True:
        try:
            conn, addr = server_socket.accept()  # 非阻塞等待连接
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024)
                if data:
                    print(f"Received: {data.decode()}")
                    functions = extract_function_info()
                    json_data = json.dumps(functions, indent=4)

                    # 保存为 JSON 文件
                    file_path = r'C:\0Program\Python\DeepSeek_Detection\example\test3\extracted_functions.json'
                    save_as_json(functions, file_path)

                    # 发送 JSON 数据到客户端
                    conn.sendall(json_data.encode())
                    print("Sent data to client.")
        except BlockingIOError:
            # 如果没有连接，可以继续进行其他任务
            time.sleep(1)  # 等待一秒钟，然后重试


# 启动服务器
start_server()
