import csv
import os
import subprocess
import sys
import logging
from io import StringIO

from flask import Flask, render_template, request, jsonify, Response
import ollama
import json
import requests  # 添加requests库用于调用RAGFlow API

from process_vulfi import read_vulfi_file, read_extracted_functions, extract_vulfi_data, save_to_json

app = Flask(__name__)

# 定义关键路径变量
PROJECT_PATH = r'C:\0Program\Python\DeepSeek_Detection'
IDA_PATH = r'C:\Application\IDA Professional 9.0'

# 其他路径变量
UPLOAD_FOLDER = os.path.join(PROJECT_PATH, 'example', 'Web')
FEATURES_FILE_PATH = os.path.join(UPLOAD_FOLDER, 'vulfi_extracted_data.json')
VULFI_FILE_PATH = os.path.join(UPLOAD_FOLDER, 'scan_results.csv')
EXTRACTED_FUNCTIONS_FILE_PATH = os.path.join(UPLOAD_FOLDER, 'extracted_functions.json')
OUTPUT_FILE_PATH = os.path.join(UPLOAD_FOLDER, 'vulfi_extracted_data.json')
EXTRACT_FEATURES_SCRIPT_PATH = os.path.join(PROJECT_PATH, 'IDA', 'extract_features.py')
VULFI_SCRIPT_PATH = os.path.join(PROJECT_PATH, 'IDA', 'VulFi.py')
IDA_EXECUTABLE = os.path.join(IDA_PATH, 'ida.exe')
PLUGINS_FOLDER = os.path.join(IDA_PATH, 'plugins')

# RAGFlow API配置
RAGFLOW_API_URL = "http://127.0.0.1"  # 使用本地主机地址，端口80是默认的，不需要指定
# RAGFlow API Key
RAGFLOW_API_KEY = "ragflow-AzNjBkMzMyZWVkOTExZWY5MjM2MDI0Mm"
# 如果上面的API路径无效，可以尝试以下替代路径之一
RAGFLOW_API_ALTERNATIVES = [
    "http://localhost",
    "http://127.0.0.1:9380"
]

ALLOWED_EXTENSIONS = {'bin', 'exe', 'elf'}

# 检查项目路径是否存在，不存在则终止程序
if not os.path.exists(PROJECT_PATH):
    print(f"错误：项目路径 {PROJECT_PATH} 不存在！")
    sys.exit(1)

# 检查 IDA 路径是否有效，不存在则终止程序
if not os.path.exists(IDA_PATH):
    print(f"错误：IDA 可执行文件 {IDA_PATH} 不存在！")
    sys.exit(1)

# 定义 plugins 文件夹路径


# 检查 plugins 文件夹是否齐全
required_files = ['vulfi.py', 'vulfi_prototypes.json', 'vulfi_rules.json']
missing_files = [file for file in required_files if not os.path.exists(os.path.join(PLUGINS_FOLDER, file))]

if missing_files:
    print(
        f"错误：以下文件缺失：{', '.join(missing_files)}\n请从 {PROJECT_PATH}\\IDA\\plugins 中找到并复制这些文件到 {PLUGINS_FOLDER} 文件夹中。")
    sys.exit(1)

# 确保上传文件夹存在，如果不存在则创建
if not os.path.exists(UPLOAD_FOLDER):
    print(f"上传文件夹 {UPLOAD_FOLDER} 不存在，正在创建...")
    os.makedirs(UPLOAD_FOLDER)


# 确保上传的文件符合格式
def allowed_file(filename):
    if '.' in filename:
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in ALLOWED_EXTENSIONS
    return False


# 加载 DeepSeek 模型并获取漏洞检测结果
def load_model(features_file):
    with open(features_file, 'r') as f:
        features = json.load(f)

    highest_priority_instruction = None
    instruction_index = -1

    for i, instruction in enumerate(features['all_instructions']):
        if instruction['address'] == features['priority_instructions'][0]['address']:
            highest_priority_instruction = features['priority_instructions'][0]
            instruction_index = i
            break

    if highest_priority_instruction is None:
        print("没有找到匹配的风险指令！")
        return None

    previous_instructions, next_instructions = get_context_instructions(instruction_index, features['all_instructions'],
                                                                        context_range=10)

    previous_instructions = [instr['instruction'] for instr in previous_instructions]
    next_instructions = [instr['instruction'] for instr in next_instructions]

    message_content = f"请检测以下特征(汇编指令)的潜在漏洞，进行描述并提出解决方案。特征数据：\n风险指令：{{\"instruction\": \"{highest_priority_instruction['instruction']}\", \"issue_name\": \"{highest_priority_instruction['issue_name']}\", \"priority\": \"{highest_priority_instruction['priority']}\"}}\n上文指令：{json.dumps(previous_instructions)}\n下文指令：{json.dumps(next_instructions)}"

    response = ollama.chat(model='deepseek-r1:14b', messages=[{'role': 'user', 'content': message_content}])

    if 'message' in response:
        return response['message']['content']
    return None


# 获取上下文指令（前文和后文）
def get_context_instructions(instruction_index, all_instructions, context_range=1):
    start_index = max(0, instruction_index - context_range)
    end_index = min(len(all_instructions), instruction_index + context_range + 1)

    previous_instructions = all_instructions[start_index:instruction_index]
    next_instructions = all_instructions[instruction_index + 1:end_index]

    return previous_instructions, next_instructions


# 文件保存时重命名为 'Application' 并保留扩展名
def save_file(file):
    try:
        # 遍历文件夹中的文件并删除
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"已删除文件: {file_path}")
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
                print(f"已删除文件夹: {file_path}")
    except Exception as e:
        print(f"清空文件夹时出错: {str(e)}")

    file_ext = file.filename.rsplit('.', 1)[1].lower()
    new_filename = 'Application.' + file_ext  # 重命名为 Application + 扩展名
    file_path = os.path.join(UPLOAD_FOLDER, new_filename)
    file.save(file_path)
    return file_path


# 读取 CSV 文件并将其转换为字典数组
def read_csv_to_array(csv_file_path):
    data = []
    with open(csv_file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data.append(row)
    return data


def load_features():
    """
    从 JSON 文件加载特征数据，遍历所有函数，提取所有指令以及带优先级的指令
    """
    with open(FEATURES_FILE_PATH, 'r') as f:
        features = json.load(f)

    all_instructions = []
    priority_instructions = []

    # 遍历 JSON 文件中所有的函数数据
    for func in features:
        if 'instructions' in func:
            # 将该函数的所有指令添加到 all_instructions 列表中
            all_instructions.extend(func['instructions'])
            # 筛选带有优先级的指令
            for instr in func['instructions']:
                if instr.get('priority'):
                    priority_instructions.append({
                        'address': instr['address'],
                        'instruction': instr['instruction'],
                        'issue_name': instr.get('issue_name', ''),
                        'priority': instr['priority']
                    })
    return {
        'all_instructions': all_instructions,
        'priority_instructions': priority_instructions
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register_user', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # 简单的输入验证
        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400
            
        # 这里应该添加用户名和密码的存储逻辑
        # 在实际应用中，应该使用数据库存储，并对密码进行加密
        # 这里为了简单演示，我们只返回成功信息
        
        return jsonify({'success': True, 'message': '注册成功！'})
    except Exception as e:
        print(f"注册过程中出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/check_login', methods=['POST'])
def check_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # 简单的硬编码验证，实际应用中应该查询数据库
        if username == "sharkiceee" and password == "123456":
            return jsonify({'success': True, 'username': username})
        else:
            return jsonify({'success': False, 'message': '用户名或密码错误'})
    except Exception as e:
        print(f"登录验证过程中出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/houtai')
def houtai():
    # 获取URL参数中的用户名
    username = request.args.get('username', '')
    return render_template('houtai.html', username=username)


@app.route('/detective')
def portfolio_details():
    return render_template('detective.html')


@app.route('/model_training')
def model_training():
    return render_template('model_training.html')


@app.route('/knowledge_base')
def knowledge_base():
    return render_template('knowledge_base.html')


@app.route('/vulnerability_management')
def vulnerability_management():
    return render_template('vulnerability_management.html')


@app.route('/project-details')
def service_details():
    return render_template('project-details.html')


@app.route('/detect', methods=['POST'])
def detect():
    try:
        # 获取上传的文件
        file = request.files['bin_file']

        # 调试：输出文件的名称和扩展名
        print(f"上传的文件名是: {file.filename}")

        if file and allowed_file(file.filename):
            # 保存文件并获取新路径
            file_path = save_file(file)

            # 执行第一个 IDA 命令提取特征
            ida_command_1 = f'"{IDA_EXECUTABLE}" -A -S"{EXTRACT_FEATURES_SCRIPT_PATH}" "{file_path}"'
            print("执行的 IDA 命令1是:", ida_command_1)  # 输出执行的 IDA 命令
            result_1 = subprocess.run(ida_command_1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result_1.stderr:
                print("IDA 执行错误:", result_1.stderr.decode())
                return jsonify({'error': 'IDA 执行失败'}), 500

            # # 执行第二个 IDA 命令运行 VulFi 脚本
            # ida_command_2 = f'"{IDA_EXECUTABLE}" -A -S"{VULFI_SCRIPT_PATH}" "{file_path}"'
            # print("执行的 IDA 命令2是:", ida_command_2)  # 输出执行的 IDA 命令
            # result_2 = subprocess.run(ida_command_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #
            # if result_2.stderr:
            #     print("IDA 执行错误:", result_2.stderr.decode())
            #     return jsonify({'error': 'IDA 执行失败'}), 500

            # 获取并处理 VulFi 数据
            vulfi_data = read_vulfi_file(VULFI_FILE_PATH)
            extracted_functions = read_extracted_functions(EXTRACTED_FUNCTIONS_FILE_PATH)

            # 调试：输出读取的 VulFi 数据和函数数据
            print("VulFi 数据读取成功:", vulfi_data[:2])  # 输出前两行数据
            print("函数数据读取成功:", extracted_functions[:2])  # 输出前两行数据

            # 生成最终的数据
            extracted_data = extract_vulfi_data(vulfi_data, extracted_functions)

            # 保存处理后的数据到 JSON 文件
            save_to_json(extracted_data, OUTPUT_FILE_PATH)

            # 读取并解析 scan_results.csv 文件
            if os.path.exists(VULFI_FILE_PATH):
                csv_content = read_csv_to_array(VULFI_FILE_PATH)

            return jsonify({'result': extracted_data, 'csv': csv_content})

        return jsonify({'error': '文件类型不支持'}), 400

    except Exception as e:
        print(f"处理文件时出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze/<address>', methods=['GET'])
def analyze_vulnerability(address):
    try:
        # 加载 feature 数据
        features = load_features()

        # 查找风险指令
        highest_priority_instruction = None
        for instruction in features['priority_instructions']:
            if instruction['address'] == address:
                highest_priority_instruction = instruction
                break
        print(f"找到的风险指令: {highest_priority_instruction}")  # 输出找到的风险指令
        if not highest_priority_instruction:
            return jsonify({'error': '未找到匹配的风险指令'}), 404

        # 获取上下文指令
        instruction_index = next(
            i for i, instr in enumerate(features['all_instructions']) if instr['address'] == address)
        previous_instructions, next_instructions = get_context_instructions(instruction_index,
                                                                            features['all_instructions'],
                                                                            context_range=10)

        # 生成消息内容
        previous_instructions = [instr['instruction'] for instr in previous_instructions]
        next_instructions = [instr['instruction'] for instr in next_instructions]
        message_content = f"请检测以下特征(汇编指令)的潜在漏洞，进行描述并提出解决方案。特征数据：\n风险指令：{{\"instruction\": \"{highest_priority_instruction['instruction']}\", \"issue_name\": \"{highest_priority_instruction['issue_name']}\", \"priority\": \"{highest_priority_instruction['priority']}\"}}\n上文指令：{json.dumps(previous_instructions)}\n下文指令：{json.dumps(next_instructions)}"
        # message_content = f"你好"

        print(f"生成的消息内容: {message_content}")  # 输出生成的消息内容

        # 调用模型进行分析
        response = ollama.chat(model='deepseek-r1:14b', messages=[{'role': 'user', 'content': message_content}])

        if 'message' in response:
            result_content = response['message']['content']
            print(result_content)
            return jsonify({'result': result_content})

        return jsonify({'error': '未获取到分析结果'}), 500
    except Exception as e:
        print(f"分析过程中出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


# RAGFlow API工具函数
def get_ragflow_knowledge_bases():
    """获取RAGFlow所有知识库"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        response = requests.get(f"{RAGFLOW_API_URL}/api/v1/datasets", headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"获取知识库列表 - 原始响应: {data}")
            
            # 检查各种可能的响应格式
            if isinstance(data, list):
                # 直接返回知识库列表
                return data
            elif isinstance(data, dict):
                # 可能是包含数据的响应对象
                if "data" in data and isinstance(data["data"], list):
                    return data["data"]
                elif "result" in data and isinstance(data["result"], list):
                    return data["result"] 
                elif "code" in data and data["code"] == 0 and "data" in data:
                    # RAGFlow标准格式
                    return data["data"]
                elif "code" in data and data["code"] == 100:
                    # 特殊情况，可能是一种API格式需要特殊处理
                    # 对于这种情况，我们返回空列表并记录
                    print(f"特殊API响应格式: {data}")
                    return []
                else:
                    print(f"未知的知识库响应格式: {data}")
                    return {"error": f"未知的知识库响应格式: {data}"}
            else:
                print(f"不支持的响应类型: {type(data)}")
                return {"error": f"不支持的响应类型: {type(data)}"}
        else:
            print(f"获取知识库列表失败: {response.status_code}, 响应: {response.text}")
            return {"error": f"获取知识库列表失败: {response.status_code}, 响应: {response.text}"}
    except Exception as e:
        print(f"连接RAGFlow API出错: {str(e)}")
        return {"error": f"连接RAGFlow API出错: {str(e)}"}

# 创建一个内存日志处理器
class MemoryLogHandler(logging.Handler):
    def __init__(self, max_entries=1000):
        super().__init__()
        self.log_records = []
        self.max_entries = max_entries
        
    def emit(self, record):
        if len(self.log_records) >= self.max_entries:
            self.log_records.pop(0)  # 删除最旧的记录
        self.log_records.append({
            'level': record.levelname,
            'message': self.format(record),
            'timestamp': record.created
        })

# 设置日志记录器
memory_handler = MemoryLogHandler()
memory_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
memory_handler.setFormatter(formatter)

# 配置根日志记录器
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(memory_handler)

# 创建一个专门的日志记录器用于API请求
api_logger = logging.getLogger('api_requests')
api_logger.setLevel(logging.DEBUG)

@app.route('/debug/logs', methods=['GET'])
def view_logs():
    """查看应用程序日志"""
    # 创建HTML页面
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>应用程序日志</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .log-debug { color: #6c757d; }
            .log-info { color: #0d6efd; }
            .log-warning { color: #ffc107; }
            .log-error { color: #dc3545; }
            .log-critical { color: #dc3545; font-weight: bold; }
            pre { white-space: pre-wrap; word-break: break-all; }
        </style>
    </head>
    <body>
        <div class="container mt-4">
            <h1>应用程序日志</h1>
            <div class="mb-3">
                <button id="refreshBtn" class="btn btn-primary">刷新日志</button>
                <button id="clearBtn" class="btn btn-warning">清空日志</button>
                <select id="filterLevel" class="form-select d-inline-block w-auto ms-2">
                    <option value="ALL">所有级别</option>
                    <option value="DEBUG">DEBUG</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                    <option value="CRITICAL">CRITICAL</option>
                </select>
                <input type="text" id="searchText" class="form-control d-inline-block w-auto ms-2" placeholder="搜索日志...">
            </div>
            <div class="card">
                <div class="card-body">
                    <pre id="logContent" class="mb-0"></pre>
                </div>
            </div>
        </div>

        <script>
            function fetchLogs() {
                const filterLevel = document.getElementById('filterLevel').value;
                const searchText = document.getElementById('searchText').value;
                
                fetch(`/debug/api_logs?level=${filterLevel}&search=${encodeURIComponent(searchText)}`)
                    .then(response => response.json())
                    .then(data => {
                        const logContent = document.getElementById('logContent');
                        logContent.innerHTML = '';
                        
                        data.logs.forEach(log => {
                            const logLine = document.createElement('div');
                            logLine.className = 'log-' + log.level.toLowerCase();
                            logLine.textContent = log.message;
                            logContent.appendChild(logLine);
                        });
                    })
                    .catch(error => {
                        console.error('获取日志失败:', error);
                    });
            }
            
            document.getElementById('refreshBtn').addEventListener('click', fetchLogs);
            document.getElementById('filterLevel').addEventListener('change', fetchLogs);
            document.getElementById('searchText').addEventListener('input', fetchLogs);
            
            document.getElementById('clearBtn').addEventListener('click', () => {
                fetch('/debug/clear_logs', { method: 'POST' })
                    .then(() => fetchLogs());
            });
            
            // 初始加载日志
            fetchLogs();
            
            // 每10秒自动刷新
            setInterval(fetchLogs, 10000);
        </script>
    </body>
    </html>
    """
    return html

@app.route('/debug/api_logs', methods=['GET'])
def get_api_logs():
    """API端点：获取日志数据"""
    filter_level = request.args.get('level', 'ALL')
    search_text = request.args.get('search', '').lower()
    
    filtered_logs = memory_handler.log_records
    
    # 应用级别过滤
    if filter_level != 'ALL':
        filtered_logs = [log for log in filtered_logs if log['level'] == filter_level]
    
    # 应用搜索文本过滤
    if search_text:
        filtered_logs = [log for log in filtered_logs if search_text in log['message'].lower()]
    
    # 按时间戳倒序排序
    filtered_logs = sorted(filtered_logs, key=lambda log: log['timestamp'], reverse=True)
    
    return jsonify({"logs": filtered_logs})

@app.route('/debug/clear_logs', methods=['POST'])
def clear_logs():
    """清空日志记录"""
    memory_handler.log_records.clear()
    return jsonify({"status": "success"})

@app.route('/api/knowledge_bases', methods=['GET'])
def api_get_knowledge_bases():
    """获取所有知识库列表的API"""
    kbs = get_ragflow_knowledge_bases()
    return jsonify(kbs)

@app.route('/api/knowledge_bases/<kb_id>/datasets', methods=['GET'])
def api_get_kb_datasets(kb_id):
    """API: 获取知识库的数据集列表"""
    datasets = get_ragflow_kb_datasets(kb_id)
    
    if 'error' in datasets:
        return jsonify({"error": datasets['error']}), 500
    
    # 处理RAGFlow API的响应格式 - 预期格式: {"code": 0, "data": {"docs": [...], "total": number}}
    try:
        # 检查是否为RAGFlow格式
        if isinstance(datasets, dict) and 'code' in datasets and datasets.get('code') == 0:
            # 从RAGFlow格式提取文档列表
            if 'data' in datasets and 'docs' in datasets['data']:
                return jsonify(datasets['data']['docs'])
        
        # 如果不是预期的格式，返回原始数据
        return jsonify(datasets)
    except Exception as e:
        print(f"处理知识库数据集响应时出错: {str(e)}")
        return jsonify({"error": f"处理响应时出错: {str(e)}"}), 500

@app.route('/api/knowledge_bases/create', methods=['POST'])
def api_create_knowledge_base():
    """创建新知识库的API"""
    data = request.get_json()
    name = data.get('name')
    description = data.get('description', '')
    if not name:
        return jsonify({"error": "知识库名称不能为空"}), 400
    result = create_ragflow_kb(name, description)
    return jsonify(result)

@app.route('/api/knowledge_bases/<kb_id>/query', methods=['POST'])
def api_query_knowledge_base(kb_id):
    """查询知识库的API"""
    data = request.get_json()
    query = data.get('query')
    if not query:
        return jsonify({"error": "查询内容不能为空"}), 400
    result = query_ragflow_kb(kb_id, query)
    return jsonify(result)

@app.route('/api/ragflow/test_all_paths', methods=['GET'])
def test_all_ragflow_paths():
    """尝试所有可能的RAGFlow API路径"""
    results = {}
    headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
    
    # 先测试默认路径
    try:
        response = requests.get(f"{RAGFLOW_API_URL}/api/v1/datasets", headers=headers, timeout=3)
        results["default"] = {
            "url": f"{RAGFLOW_API_URL}/api/v1/datasets",
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "content_type": response.headers.get('Content-Type'),
            "response": response.json() if response.status_code == 200 else None
        }
    except Exception as e:
        results["default"] = {
            "url": f"{RAGFLOW_API_URL}/api/v1/datasets",
            "error": str(e),
            "success": False
        }
    
    # 测试替代路径
    for i, api_url in enumerate(RAGFLOW_API_ALTERNATIVES):
        try:
            response = requests.get(f"{api_url}/api/v1/datasets", headers=headers, timeout=3)
            results[f"alt_{i}"] = {
                "url": f"{api_url}/api/v1/datasets",
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "content_type": response.headers.get('Content-Type'),
                "response": response.json() if response.status_code == 200 else None
            }
        except Exception as e:
            results[f"alt_{i}"] = {
                "url": f"{api_url}/api/v1/datasets",
                "error": str(e),
                "success": False
            }
    
    return jsonify(results)

@app.route('/api/ragflow/debug_kb', methods=['GET'])
def debug_ragflow_kb():
    """调试用：获取RAGFlow知识库API的原始响应"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        print(f"调试RAGFlow连接 - API URL: {RAGFLOW_API_URL}/api/v1/datasets")
        print(f"调试RAGFlow连接 - Headers: {headers}")
        response = requests.get(f"{RAGFLOW_API_URL}/api/v1/datasets", headers=headers, timeout=5)
        print(f"调试RAGFlow连接 - 状态码: {response.status_code}")
        print(f"调试RAGFlow连接 - 响应头: {response.headers}")
        
        if response.status_code == 200:
            response_data = response.json()
            print(f"调试RAGFlow连接 - 响应内容: {response_data}")
            return jsonify({
                "success": True,
                "raw_response": response_data,
                "content_type": response.headers.get('Content-Type'),
                "headers_sent": headers,
                "api_key_used": RAGFLOW_API_KEY[:10] + "..." # 只显示部分API key以保护安全
            })
        else:
            return jsonify({
                "success": False,
                "status_code": response.status_code,
                "reason": response.reason,
                "content": response.text
            })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

@app.route('/api/ragflow/test_connection', methods=['GET'])
def test_ragflow_connection():
    """测试RAGFlow连接状态"""
    try:
        # 尝试获取知识库列表作为连接测试
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        
        print(f"测试RAGFlow连接 - 使用基础URL: {RAGFLOW_API_URL}")
        print(f"测试RAGFlow连接 - 使用头信息: {headers}")
        
        # 直接测试API路径
        api_tests = [
            {"name": "获取知识库列表", "url": f"{RAGFLOW_API_URL}/api/v1/datasets", "method": "GET"},
            {"name": "测试检索API", "url": f"{RAGFLOW_API_URL}/api/v1/retrieval", "method": "POST", 
             "data": {"query": "测试查询", "top_k": 3}},
        ]
        
        # 首先获取知识库列表，用于测试文档列表API
        try:
            kb_response = requests.get(f"{RAGFLOW_API_URL}/api/v1/datasets", headers=headers, timeout=3)
            if kb_response.status_code == 200:
                kb_data = kb_response.json()
                # 从返回的数据结构中获取第一个知识库ID
                first_kb_id = None
                if "data" in kb_data and isinstance(kb_data["data"], list) and len(kb_data["data"]) > 0:
                    first_kb_id = kb_data["data"][0].get("id")
                
                if first_kb_id:
                    print(f"找到知识库ID: {first_kb_id}，开始测试文档列表API")
                    api_tests.append({
                        "name": "获取文档列表", 
                        "url": f"{RAGFLOW_API_URL}/api/v1/datasets/{first_kb_id}/documents", 
                        "method": "GET"
                    })
        except Exception as e:
            print(f"获取知识库ID失败: {str(e)}")
        
        results = {}
        for test in api_tests:
            try:
                if test["method"] == "GET":
                    response = requests.get(test["url"], headers=headers, timeout=5)
                else:
                    response = requests.post(test["url"], json=test.get("data"), headers=headers, timeout=5)
                
                content_type = response.headers.get('Content-Type', '')
                print(f"测试RAGFlow {test['name']} - 状态码: {response.status_code}")
                print(f"测试RAGFlow {test['name']} - 内容类型: {content_type}")
                
                results[test["name"]] = {
                    "success": response.status_code == 200,
                    "status_code": response.status_code,
                    "content_type": content_type
                }
                
                if response.status_code == 200:
                    try:
                        results[test["name"]]["response"] = response.json()
                    except:
                        results[test["name"]]["response_text"] = response.text[:100]
            except Exception as e:
                results[test["name"]] = {
                    "success": False,
                    "error": str(e)
                }
        
        # 检查是否有任何一个测试成功
        any_success = any(test.get("success", False) for test in results.values())
        
        return jsonify({
            "success": any_success,
            "message": "成功连接到RAGFlow服务" if any_success else "无法连接到RAGFlow服务",
            "test_results": results
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"无法连接到RAGFlow服务: {str(e)}",
            "status": None
        })

@app.route('/api/ragflow/detect_api_format', methods=['GET'])
def detect_api_format():
    """自动检测RAGFlow API的正确格式"""
    results = {}
    headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
    
    # 尝试多种不同的路径格式组合
    api_formats = [
        # 测试知识库列表API
        {"base": "http://127.0.0.1", "path": "/api/v1/datasets", "method": "GET", "data": None, "name": "获取知识库列表"},
        {"base": "http://127.0.0.1:9380", "path": "/api/v1/datasets", "method": "GET", "data": None, "name": "获取知识库列表(9380端口)"},
        
        # 测试检索API
        {"base": "http://127.0.0.1", "path": "/api/v1/retrieval", "method": "POST", 
         "data": {"query": "测试查询", "top_k": 3}, "name": "检索API"},
         
        # 测试知识库详情API
        {"base": "http://127.0.0.1", "path": "/api/v1/datasets/1", "method": "GET", "data": None, "name": "知识库详情"},
        
        # 测试知识库文档列表API - 修正路径
        {"base": "http://127.0.0.1", "path": "/api/v1/datasets/1/documents", "method": "GET", "data": None, "name": "知识库文档列表"}
    ]
    
    for i, format_info in enumerate(api_formats):
        base = format_info["base"]
        path = format_info["path"]
        method = format_info["method"]
        data = format_info["data"]
        name = format_info["name"]
        full_url = f"{base}{path}"
        
        try:
            if method == "GET":
                response = requests.get(full_url, headers=headers, timeout=3)
            else:
                response = requests.post(full_url, json=data, headers=headers, timeout=3)
                
            results[f"format_{i}"] = {
                "name": name,
                "base_url": base,
                "path": path,
                "method": method,
                "full_url": full_url,
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "content_type": response.headers.get('Content-Type', ''),
                "response": response.json() if response.status_code == 200 else None
            }
        except Exception as e:
            results[f"format_{i}"] = {
                "name": name,
                "base_url": base,
                "path": path,
                "method": method,
                "full_url": full_url,
                "error": str(e),
                "success": False
            }
    
    # 检查是否有成功的路径
    successful_formats = [f for f in results.values() if f.get("success", False)]
    if successful_formats:
        results["successful_paths"] = [
            {"name": f["name"], "full_url": f["full_url"], "method": f["method"]} 
            for f in successful_formats
        ]
    
    return jsonify(results)

def upload_file_to_ragflow(kb_id, file_path, file_name=None):
    """上传文件到知识库"""
    try:
        if not file_name:
            file_name = os.path.basename(file_path)
            
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        
        # 打开文件并准备上传
        with open(file_path, 'rb') as f:
            files = {'file': (file_name, f)}
            
            request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents"
            api_logger.info(f"上传文件 - URL: {request_url}")
            api_logger.info(f"上传文件 - 文件名: {file_name}")
            
            response = requests.post(
                request_url,
                files=files,
                headers=headers,
                timeout=30  # 上传可能需要更长时间
            )
            
            if response.status_code == 200:
                api_logger.info(f"文件上传成功 - 状态码: {response.status_code}")
                return response.json()
            else:
                error_msg = f"文件上传失败: {response.status_code}, 响应: {response.text}"
                api_logger.error(error_msg)
                return {"error": error_msg}
    except Exception as e:
        error_msg = f"文件上传出错: {str(e)}"
        api_logger.error(error_msg)
        return {"error": error_msg}

# 添加文件上传API路由
@app.route('/api/knowledge_bases/<kb_id>/upload', methods=['POST'])
def api_upload_file_to_kb(kb_id):
    """上传文件到知识库的API"""
    try:
        # 检查是否有文件上传
        if 'file' not in request.files:
            return jsonify({"error": "没有选择文件"}), 400
            
        file = request.files['file']
        
        # 检查文件名是否为空
        if file.filename == '':
            return jsonify({"error": "没有选择文件"}), 400
            
        # 保存文件到临时路径
        temp_dir = os.path.join(PROJECT_PATH, 'temp')
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
            
        temp_file_path = os.path.join(temp_dir, file.filename)
        file.save(temp_file_path)
        
        # 上传文件到RAGFlow
        result = upload_file_to_ragflow(kb_id, temp_file_path)
        
        # 删除临时文件
        try:
            os.remove(temp_file_path)
        except:
            pass
            
        return jsonify(result)
    except Exception as e:
        print(f"上传文件处理过程中出错: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/test_documents/<kb_id>', methods=['GET'])
def test_documents_format(kb_id):
    """测试路由：获取原始的文档列表响应格式"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        params = {
            "page": 1,
            "page_size": 30,
            "orderby": "create_time",
            "desc": True
        }
        
        # 打印完整的请求URL和参数
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents"
        print(f"测试文档格式 - 请求URL: {request_url}")
        
        # 发送请求
        response = requests.get(
            request_url,
            headers=headers,
            params=params,
            timeout=5
        )
        
        print(f"测试文档格式 - 状态码: {response.status_code}")
        
        response_data = {
            "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type'),
            "raw_response": response.json() if response.status_code == 200 else response.text
        }
        
        return jsonify(response_data)
    except Exception as e:
        return jsonify({
            "error": str(e)
        })

@app.route('/debug/api/<path:api_path>', methods=['GET'])
def debug_api_response(api_path):
    """调试端点：直接查看特定API路径的响应"""
    try:
        # 从查询参数中获取HTTP方法，默认为GET
        method = request.args.get('method', 'GET').upper()
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        
        # 构建完整的API URL
        full_url = f"{RAGFLOW_API_URL}/{api_path}"
        
        # 获取所有查询参数（除了method）
        params = {k: v for k, v in request.args.items() if k != 'method'}
        
        print(f"调试API - 方法: {method}, URL: {full_url}")
        print(f"调试API - 参数: {params}")
        
        if method == 'GET':
            response = requests.get(full_url, headers=headers, params=params, timeout=10)
        else:
            return jsonify({"error": f"不支持的HTTP方法: {method}"}), 400
        
        # 返回原始响应
        try:
            data = response.json()
            return jsonify({
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "data": data
            })
        except ValueError:
            # 不是JSON格式
            return jsonify({
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "raw_content": response.text
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 更新get_ragflow_kb_datasets函数以使用日志记录
def get_ragflow_kb_datasets(kb_id):
    """获取指定知识库的所有数据集"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        # 添加分页和排序参数
        params = {
            "page": 1,
            "page_size": 50,
            "orderby": "create_time",
            "desc": True
        }
        
        # 使用日志记录器
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents"
        api_logger.info(f"请求文档列表 - URL: {request_url}")
        api_logger.info(f"请求文档列表 - 参数: {params}")
        api_logger.info(f"请求文档列表 - 头信息: Authorization Bearer {RAGFLOW_API_KEY[:5]}...")
        
        # 发送请求
        response = requests.get(
            request_url,
            headers=headers,
            params=params,
            timeout=5
        )
        
        if response.status_code == 200:
            api_logger.info(f"获取文档列表成功 - 状态码: {response.status_code}")
            data = response.json()
            api_logger.info(f"响应数据结构: {list(data.keys()) if isinstance(data, dict) else '非字典类型'}")
            return data
        else:
            error_msg = f"获取知识库数据集失败: {response.status_code}, 响应: {response.text}"
            api_logger.error(error_msg)
            return {"error": error_msg}
    except Exception as e:
        error_msg = f"连接RAGFlow API出错: {str(e)}"
        api_logger.error(error_msg)
        return {"error": error_msg}

def create_ragflow_kb(name, description=""):
    """创建新的知识库"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        data = {
            "name": name,
            "description": description
        }
        
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets"
        api_logger.info(f"创建知识库 - URL: {request_url}")
        api_logger.info(f"创建知识库 - 数据: {data}")
        
        response = requests.post(
            request_url, 
            json=data, 
            headers=headers, 
            timeout=5
        )
        
        if response.status_code == 200:
            api_logger.info(f"创建知识库成功 - 状态码: {response.status_code}")
            return response.json()
        else:
            error_msg = f"创建知识库失败: {response.status_code}, 响应: {response.text}"
            api_logger.error(error_msg)
            return {"error": error_msg}
    except Exception as e:
        error_msg = f"连接RAGFlow API出错: {str(e)}"
        api_logger.error(error_msg)
        return {"error": error_msg}

def query_ragflow_kb(kb_id, query_text):
    """对知识库执行查询"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        data = {
            "query": query_text,
            "top_k": 3,
            "dataset_ids": [kb_id]  # 添加dataset_ids参数
        }
        
        request_url = f"{RAGFLOW_API_URL}/api/v1/retrieval"
        api_logger.info(f"知识库查询 - URL: {request_url}")
        api_logger.info(f"知识库查询 - 数据: {data}")
        
        response = requests.post(
            request_url, 
            json=data, 
            headers=headers, 
            timeout=5
        )
        
        if response.status_code == 200:
            api_logger.info(f"知识库查询成功 - 状态码: {response.status_code}")
            return response.json()
        else:
            error_msg = f"知识库查询失败: {response.status_code}, 响应: {response.text}"
            api_logger.error(error_msg)
            return {"error": error_msg}
    except Exception as e:
        error_msg = f"连接RAGFlow API出错: {str(e)}"
        api_logger.error(error_msg)
        return {"error": error_msg}

@app.route('/api/knowledge_bases/<kb_id>/documents/<doc_id>/preview', methods=['GET'])
def api_preview_document(kb_id, doc_id):
    """获取文档预览内容"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        
        # 记录请求信息
        api_logger.info(f"文档预览请求 - 知识库ID: {kb_id}, 文档ID: {doc_id}")
        
        # 获取查询参数
        keywords = request.args.get('keywords', '')
        
        # 构建请求URL - 使用chunks API获取文档内容
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents/{doc_id}/chunks"
        
        # 准备查询参数
        params = {}
        if keywords:
            params['keywords'] = keywords
        
        # 发送请求获取文档块内容
        api_logger.info(f"请求文档块内容 - URL: {request_url}, 参数: {params}")
        response = requests.get(
            request_url,
            headers=headers,
            params=params,
            timeout=10  # 增加超时时间，因为文档可能较大
        )
        
        # 检查响应状态
        if response.status_code == 200:
            api_logger.info(f"获取文档块内容成功 - 状态码: {response.status_code}")
            data = response.json()
            
            # 检查响应格式
            if isinstance(data, dict) and data.get('code') == 0 and 'data' in data:
                # 返回标准化的响应格式
                return jsonify({
                    "success": True,
                    "chunks": data['data'].get('chunks', []),
                    "doc_info": data['data'].get('doc', {}),
                    "total_chunks": data['data'].get('total', 0),
                    "keywords": keywords  # 返回搜索的关键词
                })
            else:
                # 如果响应格式不符合预期，返回原始数据
                api_logger.warning(f"文档块内容响应格式不符合预期: {data}")
                return jsonify(data)
        else:
            error_msg = f"获取文档块内容失败: {response.status_code}, 响应: {response.text}"
            api_logger.error(error_msg)
            return jsonify({"error": error_msg}), 500
    except Exception as e:
        error_msg = f"文档预览请求处理出错: {str(e)}"
        api_logger.error(error_msg)
        return jsonify({"error": error_msg}), 500

# 文档删除API端点
@app.route('/api/knowledge_bases/<kb_id>/documents/<doc_id>', methods=['DELETE'])
def api_delete_document(kb_id, doc_id):
    """删除文档"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        
        # 记录请求信息
        api_logger.info(f"文档删除请求 - 知识库ID: {kb_id}, 文档ID: {doc_id}")
        
        # 构建请求URL
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents/{doc_id}"
        
        # 发送删除请求
        response = requests.delete(
            request_url,
            headers=headers,
            timeout=10
        )
        
        # 检查响应状态
        if response.status_code == 200:
            api_logger.info(f"删除文档成功 - 状态码: {response.status_code}")
            
            try:
                return jsonify(response.json())
            except:
                return jsonify({"success": True, "message": "文档已成功删除"})
        else:
            error_msg = f"删除文档失败: {response.status_code}, 响应: {response.text}"
            api_logger.error(error_msg)
            return jsonify({"error": error_msg}), 500
    except Exception as e:
        error_msg = f"文档删除请求处理出错: {str(e)}"
        api_logger.error(error_msg)
        return jsonify({"error": error_msg}), 500

@app.route('/api/knowledge_bases/<kb_id>/documents/<doc_id>/download', methods=['GET'])
def api_download_document(kb_id, doc_id):
    """下载文档"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        
        # 记录请求信息
        api_logger.info(f"文档下载请求 - 知识库ID: {kb_id}, 文档ID: {doc_id}")
        
        # 先获取文档列表，从中找到匹配的文档名称
        filename = None
        try:
            # 获取知识库的文档列表
            datasets = get_ragflow_kb_datasets(kb_id)
            if isinstance(datasets, dict) and 'code' in datasets and datasets.get('code') == 0:
                if 'data' in datasets and 'docs' in datasets['data']:
                    # 在文档列表中查找匹配的文档
                    for doc in datasets['data']['docs']:
                        # 确保ID比较正确，将两者都转为字符串再比较
                        doc_id_str = str(doc.get('id'))
                        if doc_id_str == doc_id:
                            filename = doc.get('name')
                            api_logger.info(f"从文档列表中找到文件名: {filename}")
                            break
        except Exception as e:
            api_logger.warning(f"从文档列表获取文件名失败: {str(e)}")
        
        # 构建请求URL - 使用文档下载API
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents/{doc_id}"
        api_logger.info(f"请求文档下载 - URL: {request_url}")
        
        try:
            # 发送请求获取文档内容
            response = requests.get(
                request_url,
                headers=headers,
                stream=True,  # 使用流式传输
                timeout=30    # 增加超时时间，因为文档可能较大
            )
            
            # 检查响应状态
            if response.status_code == 200:
                api_logger.info(f"文档下载请求成功 - 状态码: {response.status_code}")
                
                # 如果之前未找到文件名，尝试从响应中获取
                if not filename:
                    # 先从Content-Disposition头获取文件名
                    if 'Content-Disposition' in response.headers:
                        content_disposition = response.headers['Content-Disposition']
                        if 'filename=' in content_disposition:
                            try:
                                # 处理引号和编码问题
                                if '"' in content_disposition:
                                    filename = content_disposition.split('filename="')[1].split('"')[0]
                                else:
                                    filename = content_disposition.split('filename=')[1].split(';')[0].strip()
                                api_logger.info(f"从响应头获取到文件名: {filename}")
                            except Exception as e:
                                api_logger.warning(f"从Content-Disposition解析文件名失败: {str(e)}")
                
                # 如果仍然无法获取文件名，使用文档ID作为文件名
                if not filename:
                    filename = f"document_{doc_id}"
                    api_logger.warning(f"无法获取文件名，使用文档ID作为文件名: {filename}")
                
                # 检查Content-Type是否为JSON（可能是API返回了错误而不是文件）
                content_type = response.headers.get('Content-Type', '')
                api_logger.info(f"下载响应的Content-Type: {content_type}")
                
                if 'application/json' in content_type.lower():
                    try:
                        # 仅读取一部分来判断是否为JSON错误
                        content_start = next(response.iter_content(chunk_size=1024))
                        try:
                            error_data = json.loads(content_start)
                            api_logger.error(f"API返回了JSON而不是文件: {error_data}")
                            return jsonify({"error": "服务器返回了JSON而不是文件内容"}), 500
                        except json.JSONDecodeError:
                            # 如果不是有效的JSON，可能是二进制文件，继续处理
                            api_logger.info("Content-Type声明为JSON但不是有效JSON，继续处理文件下载")
                    except Exception as content_err:
                        api_logger.error(f"检查内容类型时出错: {str(content_err)}")
                
                # 创建响应，使用Flask的响应对象来流式传输数据
                def generate():
                    try:
                        # 如果之前已经读取了内容的开始部分，先返回它
                        if 'content_start' in locals() and content_start:
                            yield content_start
                        
                        # 然后继续读取剩余内容
                        for chunk in response.iter_content(chunk_size=4096):
                            if chunk:  # 过滤掉保持连接活跃的空块
                                yield chunk
                    except Exception as stream_err:
                        api_logger.error(f"流式传输文件时出错: {str(stream_err)}")
                
                # 对文件名进行URL编码以处理特殊字符
                encoded_filename = requests.utils.quote(filename)
                
                # 创建响应并设置适当的头信息
                flask_response = Response(
                    generate(), 
                    content_type=response.headers.get('Content-Type', 'application/octet-stream')
                )
                
                # 设置Content-Disposition头，确保文件名编码正确
                if ',' in filename or ';' in filename or '"' in filename or "'" in filename:
                    # 如果文件名包含特殊字符，使用引号并编码
                    flask_response.headers['Content-Disposition'] = f'attachment; filename="{encoded_filename}"; filename*=UTF-8\'\'{encoded_filename}'
                else:
                    # 否则使用简单格式
                    flask_response.headers['Content-Disposition'] = f'attachment; filename={encoded_filename}'
                
                # 添加其他有用的头信息
                if 'Content-Length' in response.headers:
                    flask_response.headers['Content-Length'] = response.headers['Content-Length']
                
                api_logger.info(f"开始文档下载 - 文件名: {filename}, 编码后: {encoded_filename}")
                return flask_response
            else:
                # 捕获常见错误响应
                error_msg = f"文档下载失败: 状态码 {response.status_code}"
                try:
                    if response.headers.get('Content-Type', '').startswith('application/json'):
                        error_json = response.json()
                        if isinstance(error_json, dict) and 'error' in error_json:
                            error_msg = f"文档下载失败: {error_json['error']}"
                    else:
                        error_msg = f"文档下载失败: {response.text[:200]}"
                except Exception:
                    pass  # 保持原始错误消息
                
                api_logger.error(error_msg)
                return jsonify({"error": error_msg}), response.status_code
                
        except requests.exceptions.RequestException as req_err:
            error_msg = f"发送下载请求失败: {str(req_err)}"
            api_logger.error(error_msg)
            return jsonify({"error": error_msg}), 500
            
    except Exception as e:
        error_msg = f"文档下载请求处理出错: {str(e)}"
        api_logger.error(error_msg)
        return jsonify({"error": error_msg}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
