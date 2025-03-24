import csv
import os
import subprocess
import sys

from flask import Flask, render_template, request, jsonify
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

def get_ragflow_kb_datasets(kb_id):
    """获取指定知识库的所有数据集"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        response = requests.get(f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/files", headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"获取知识库数据集失败: {response.status_code}, 响应: {response.text}")
            return {"error": f"获取知识库数据集失败: {response.status_code}, 响应: {response.text}"}
    except Exception as e:
        print(f"连接RAGFlow API出错: {str(e)}")
        return {"error": f"连接RAGFlow API出错: {str(e)}"}

def create_ragflow_kb(name, description=""):
    """创建新的知识库"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        data = {
            "name": name,
            "description": description
        }
        response = requests.post(f"{RAGFLOW_API_URL}/api/v1/datasets", json=data, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"创建知识库失败: {response.status_code}, 响应: {response.text}")
            return {"error": f"创建知识库失败: {response.status_code}, 响应: {response.text}"}
    except Exception as e:
        print(f"连接RAGFlow API出错: {str(e)}")
        return {"error": f"连接RAGFlow API出错: {str(e)}"}

def query_ragflow_kb(kb_id, query_text):
    """对知识库执行查询"""
    try:
        headers = {"Authorization": f"Bearer {RAGFLOW_API_KEY}"}
        data = {
            "query": query_text,
            "top_k": 3
        }
        response = requests.post(f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/search", json=data, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"知识库查询失败: {response.status_code}, 响应: {response.text}")
            return {"error": f"知识库查询失败: {response.status_code}, 响应: {response.text}"}
    except Exception as e:
        print(f"连接RAGFlow API出错: {str(e)}")
        return {"error": f"连接RAGFlow API出错: {str(e)}"}

# 知识库相关API路由
@app.route('/api/knowledge_bases', methods=['GET'])
def api_get_knowledge_bases():
    """获取所有知识库列表的API"""
    kbs = get_ragflow_knowledge_bases()
    return jsonify(kbs)

@app.route('/api/knowledge_bases/<kb_id>/datasets', methods=['GET'])
def api_get_kb_datasets(kb_id):
    """获取知识库数据集的API"""
    datasets = get_ragflow_kb_datasets(kb_id)
    return jsonify(datasets)

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
        
        # 首先尝试不带路径直接访问
        print(f"测试RAGFlow连接 - 使用基础URL: {RAGFLOW_API_URL}")
        print(f"测试RAGFlow连接 - 使用头信息: {headers}")
        
        # 直接测试正确的API路径
        response = requests.get(f"{RAGFLOW_API_URL}/api/v1/datasets", headers=headers, timeout=5)
        content_type = response.headers.get('Content-Type', '')
        
        print(f"测试RAGFlow连接 - 状态码: {response.status_code}")
        print(f"测试RAGFlow连接 - 内容类型: {content_type}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"测试RAGFlow连接 - 响应内容: {data}")
                
                return jsonify({
                    "success": True,
                    "message": "成功连接到RAGFlow服务",
                    "status": data
                })
            except:
                return jsonify({
                    "success": True,
                    "message": "成功连接到RAGFlow服务，但响应不是JSON格式",
                    "content_type": content_type,
                    "status": response.text[:100]
                })
        else:
            return jsonify({
                "success": False,
                "message": f"RAGFlow服务返回错误: {response.status_code}",
                "content_type": content_type,
                "status": None
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
        # 根据Postman测试结果，这是正确的基础URL格式
        {"base": "http://127.0.0.1", "kb_path": "/api/v1/datasets"},
        {"base": "http://localhost", "kb_path": "/api/v1/datasets"},
        {"base": "http://127.0.0.1:9380", "kb_path": "/api/v1/datasets"},
        {"base": "http://localhost:9380", "kb_path": "/api/v1/datasets"},
        # 尝试旧的kb路径作为对比
        {"base": "http://127.0.0.1", "kb_path": "/api/v1/kb"},
        {"base": "http://localhost:9380", "kb_path": "/api/v1/kb"}
    ]
    
    for i, format_info in enumerate(api_formats):
        base = format_info["base"]
        kb_path = format_info["kb_path"]
        full_url = f"{base}{kb_path}"
        
        try:
            response = requests.get(full_url, headers=headers, timeout=3)
            results[f"format_{i}"] = {
                "base_url": base,
                "kb_path": kb_path,
                "full_url": full_url,
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "content_type": response.headers.get('Content-Type', ''),
                "response": response.json() if response.status_code == 200 else None
            }
        except Exception as e:
            results[f"format_{i}"] = {
                "base_url": base,
                "kb_path": kb_path,
                "full_url": full_url,
                "error": str(e),
                "success": False
            }
    
    # 检查是否有成功的路径
    successful_formats = [f for f in results.values() if f.get("success", False)]
    if successful_formats:
        recommended = successful_formats[0]
        results["recommendation"] = {
            "base_url": recommended["base_url"],
            "kb_path": recommended["kb_path"],
            "full_url": recommended["full_url"],
            "message": "建议使用此API格式"
        }
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
