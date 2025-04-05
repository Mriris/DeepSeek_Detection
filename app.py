import csv
import json
import logging
import os
import subprocess
import sys
from dotenv import load_dotenv
from functools import wraps
import gzip

import ollama
import requests
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for

from process_vulfi import read_vulfi_file, read_extracted_functions, extract_vulfi_data, save_to_json

# 加载环境变量
load_dotenv()

# =============== 基础配置 ===============
# Flask应用配置
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')  # 添加密钥用于session加密

# 允许的文件扩展名
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'bin,exe,elf').split(','))

# 漏洞名称映射（英文到中文）
VULNERABILITY_NAME_MAP = {
    "Format String": "格式化字符串漏洞",
    "Buffer Overflow": "缓冲区溢出",
    "Command Injection": "命令注入",
    "Unchecked Return Value of *scanf": "未检查的scanf返回值",
    "Possible Dangling Pointer": "可能的悬垂指针",
    "Possible Null Pointer Dereference": "可能的空指针解引用",
    "Memory Leak": "内存泄漏",
    "Comparison with Dynamic Count": "动态计数比较问题",
    "Signed Comparison Issue": "有符号比较问题", 
    "Unbound Loop": "无界循环"
}

# 函数名称映射（英文到中文）
FUNCTION_NAME_MAP = {
    "Loop Check": "循环检查",
    "Array Access": "数组访问",
    "memcpy": "内存复制",
    "memmove": "内存移动",
    "strcpy": "字符串复制",
    "strncpy": "字符串长度复制",
    "strcat": "字符串连接",
    "strncat": "字符串长度连接",
    "memset": "内存设置",
    "memchr": "内存查找字符",
    "memrchr": "内存反向查找字符",
    "read": "读取",
    "write": "写入",
    "printf": "打印格式化字符串",
    "scanf": "扫描输入",
    "malloc": "内存分配",
    "free": "内存释放",
    "snprintf": "安全打印格式化字符串",
    "vsnprintf": "可变参数安全打印格式化字符串",
    "gets": "获取字符串",
    "system": "系统命令执行",
    "popen": "进程打开"
}

# =============== 路径配置 ===============
# 项目根路径
PROJECT_PATH = os.getenv('PROJECT_PATH', r'C:\0Program\Python\DeepSeek_Detection')
# IDA Pro路径
IDA_PATH = os.getenv('IDA_PATH', r'C:\Application\IDA Professional 9.0')

# 上传文件夹路径
UPLOAD_FOLDER = os.path.join(PROJECT_PATH, os.getenv('UPLOAD_FOLDER', 'example/Web'))

# 文件路径配置
FEATURES_FILENAME = os.getenv('FEATURES_FILENAME', 'vulfi_extracted_data.json')
VULFI_FILENAME = os.getenv('VULFI_FILENAME', 'scan_results.csv')
EXTRACTED_FUNCTIONS_FILENAME = os.getenv('EXTRACTED_FUNCTIONS_FILENAME', 'extracted_functions.json')

FEATURES_FILE_PATH = os.path.join(UPLOAD_FOLDER, FEATURES_FILENAME)
VULFI_FILE_PATH = os.path.join(UPLOAD_FOLDER, VULFI_FILENAME)
EXTRACTED_FUNCTIONS_FILE_PATH = os.path.join(UPLOAD_FOLDER, EXTRACTED_FUNCTIONS_FILENAME)
OUTPUT_FILE_PATH = os.path.join(UPLOAD_FOLDER, FEATURES_FILENAME)  # 与FEATURES_FILE_PATH相同

EXTRACT_FEATURES_SCRIPT_PATH = os.path.join(PROJECT_PATH, os.getenv('EXTRACT_FEATURES_SCRIPT_PATH', 'IDA/extract_features.py'))
VULFI_SCRIPT_PATH = os.path.join(PROJECT_PATH, os.getenv('VULFI_SCRIPT_PATH', 'IDA/VulFi.py'))
IDA_EXECUTABLE = os.path.join(IDA_PATH, os.getenv('IDA_EXECUTABLE', 'ida.exe'))
PLUGINS_FOLDER = os.path.join(IDA_PATH, os.getenv('PLUGINS_FOLDER', 'plugins'))

# 训练模型存储路径
TRAINED_MODELS_FILE = os.path.join(PROJECT_PATH, os.getenv('TRAINED_MODELS_FILENAME', 'trained_models.json'))

# =============== API配置 ===============
# Ollama API配置
OLLAMA_API_URL = os.getenv('OLLAMA_API_URL', 'http://localhost:11434')
DEFAULT_MODEL = os.getenv('DEFAULT_MODEL', 'deepseek-r1:14b')

# RAGFlow API配置
RAGFLOW_API_URL = os.getenv('RAGFLOW_API_URL', 'http://127.0.0.1')
RAGFLOW_API_KEY = os.getenv('RAGFLOW_API_KEY', 'ragflow-AzNjBkMzMyZWVkOTExZWY5MjM2MDI0Mm')

# RAGFlow API替代路径
RAGFLOW_API_ALTERNATIVES = [
    "http://localhost",
    "http://127.0.0.1:9380"
]

# =============== 插件配置 ===============
# 必需的插件文件
required_files = ['vulfi.py', 'vulfi_prototypes.json', 'vulfi_rules.json']

# =============== 环境检查 ===============
# 检查项目路径是否存在
if not os.path.exists(PROJECT_PATH):
    print(f"错误：项目路径 {PROJECT_PATH} 不存在！")
    sys.exit(1)

# 检查 IDA 路径是否有效
if not os.path.exists(IDA_PATH):
    print(f"错误：IDA 可执行文件 {IDA_PATH} 不存在！")
    sys.exit(1)

# 检查 plugins 文件夹是否齐全
missing_files = [file for file in required_files if not os.path.exists(os.path.join(PLUGINS_FOLDER, file))]
if missing_files:
    print(f"错误：以下文件缺失：{', '.join(missing_files)}\n请从 {PROJECT_PATH}\\IDA\\plugins 中找到并复制这些文件到 {PLUGINS_FOLDER} 文件夹中。")
    sys.exit(1)

# 确保上传文件夹存在
if not os.path.exists(UPLOAD_FOLDER):
    print(f"上传文件夹 {UPLOAD_FOLDER} 不存在，正在创建...")
    os.makedirs(UPLOAD_FOLDER)


# 确保上传的文件符合格式
def allowed_file(filename):
    if '.' in filename:
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in ALLOWED_EXTENSIONS
    return False


# 获取Ollama可用模型列表
def get_ollama_models():
    try:
        response = requests.get(f"{OLLAMA_API_URL}/api/tags")
        if response.status_code == 200:
            models = response.json().get('models', [])
            return models
        else:
            return []
    except Exception as e:
        print(f"获取模型列表时出错: {str(e)}")
        return []


# 获取已训练的模型列表
def get_trained_models():
    if not os.path.exists(TRAINED_MODELS_FILE):
        return []

    try:
        with open(TRAINED_MODELS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"读取训练模型列表时出错: {str(e)}")
        return []


# 保存训练模型信息
def save_trained_model(model_info):
    try:
        models = get_trained_models()
        models.append(model_info)

        with open(TRAINED_MODELS_FILE, 'w', encoding='utf-8') as f:
            json.dump(models, f, ensure_ascii=False, indent=2)

        return True
    except Exception as e:
        print(f"保存训练模型信息时出错: {str(e)}")
        return False


# 获取所有可用模型（包括基础模型和训练好的模型）
def get_all_available_models():
    base_models = get_ollama_models()
    trained_models = get_trained_models()

    # 创建基础模型列表（添加类型标识）
    base_model_list = [
        {
            "name": model["name"],
            "type": "base",
            "details": model.get("details", {}),
            "size": model.get("size", 0)
        }
        for model in base_models
    ]

    # 创建训练模型列表（添加类型标识）
    trained_model_list = [
        {
            "name": model["model_name"],
            "type": "trained",
            "base_model": model["base_model"],
            "created_at": model["created_at"],
            "id": model.get("id", "")
        }
        for model in trained_models
    ]

    # 合并两个列表
    return base_model_list + trained_model_list


# 核心漏洞分析函数
def analyze_vulnerability_core(features, address=None, model_name=DEFAULT_MODEL, stream=False):
    """
    执行漏洞分析的核心逻辑
    
    Args:
        features (dict): 包含all_instructions和priority_instructions的特征数据
        address (str, optional): 特定指令的地址。如果为None，使用第一个优先级指令
        model_name (str, optional): 使用的模型名称
        stream (bool, optional): 是否使用流式输出，默认为False
    
    Returns:
        如果stream=False, 返回str: 分析结果文本，或者None如果分析失败
        如果stream=True, 返回generator: 生成分析结果文本的流式生成器
    """
    try:
        # 查找风险指令
        highest_priority_instruction = None
        instruction_index = -1
        
        if address:
            # 如果提供了特定地址，查找对应的指令
            for instruction in features['priority_instructions']:
                if instruction['address'] == address:
                    highest_priority_instruction = instruction
                    break
                    
            if not highest_priority_instruction:
                print(f"未找到地址为 {address} 的风险指令")
                return None
                
            # 获取指令在all_instructions中的索引
            instruction_index = next(
                (i for i, instr in enumerate(features['all_instructions']) if instr['address'] == address),
                -1
            )
        else:
            # 使用第一个优先级指令
            if features['priority_instructions']:
                highest_priority_instruction = features['priority_instructions'][0]
                # 找到这个指令在all_instructions中的索引
                for i, instruction in enumerate(features['all_instructions']):
                    if instruction['address'] == highest_priority_instruction['address']:
                        instruction_index = i
                        break
        
        if highest_priority_instruction is None or instruction_index == -1:
            print("没有找到匹配的风险指令！")
            return None
            
        # 获取上下文指令
        previous_instructions, next_instructions = get_context_instructions(
            instruction_index, 
            features['all_instructions'],
            context_range=10
        )

        # 转换指令格式
        previous_instructions = [instr['instruction'] for instr in previous_instructions]
        next_instructions = [instr['instruction'] for instr in next_instructions]
        
        # 生成提示词
        message_content = build_vulnerability_prompt(
            highest_priority_instruction, 
            previous_instructions, 
            next_instructions
        )

        print(f"使用模型: {model_name} 进行分析")
        
        # 调用模型进行分析，根据stream参数决定是否使用流式输出
        if stream:
            # 返回流式生成器
            return ollama.chat(
                model=model_name, 
                messages=[{'role': 'user', 'content': message_content}],
                stream=True
            )
        else:
            # 返回完整响应
            response = ollama.chat(model=model_name, messages=[{'role': 'user', 'content': message_content}])
            if 'message' in response:
                result_content = response['message']['content']
                print(result_content)
                return result_content
        
        return None
    except Exception as e:
        print(f"分析过程中出错: {str(e)}")
        return None


# 加载 DeepSeek 模型并获取漏洞检测结果
def load_model(features_file, model_name=None):
    """
    加载特征文件并分析其中的漏洞
    """
    if not model_name:
        model_name = DEFAULT_MODEL

    # 读取特征文件
    try:
        with open(features_file, 'r') as f:
            features = json.load(f)
            
        # 使用核心分析函数
        return analyze_vulnerability_core(features, address=None, model_name=model_name)
    except Exception as e:
        print(f"加载模型时出错: {str(e)}")
        return None


# 获取上下文指令（前文和后文）
def get_context_instructions(instruction_index, all_instructions, context_range=1):
    start_index = max(0, instruction_index - context_range)
    end_index = min(len(all_instructions), instruction_index + context_range + 1)

    previous_instructions = all_instructions[start_index:instruction_index]
    next_instructions = all_instructions[instruction_index + 1:end_index]

    return previous_instructions, next_instructions


# 构建漏洞检测提示词
def build_vulnerability_prompt(instruction, previous_instructions, next_instructions):
    """构建用于漏洞检测的提示词"""
    # 确保使用中文漏洞名称
    issue_name = instruction['issue_name']
    
    return f"""# 汇编代码漏洞分析报告

## 分析对象
- 风险指令: {{"instruction": "{instruction['instruction']}", "issue_name": "{issue_name}", "priority": "{instruction['priority']}"}}

## 上下文
- 前序指令: {json.dumps(previous_instructions, ensure_ascii=False, indent=2)}
- 后续指令: {json.dumps(next_instructions, ensure_ascii=False, indent=2)}

请基于以上数据，生成完整的漏洞分析报告，包含以下内容：

1. 漏洞类型和风险等级
2. 漏洞详细描述和原理
3. 漏洞可能造成的影响
4. 可行的修复方案或缓解措施
5. 针对此类漏洞的最佳安全实践建议

请保持专业、严谨的技术语言，清晰地用中文阐述问题和解决方案。"""


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


# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# 用户数据存储（实际应用中应该使用数据库）
users = {
    "sharkiceee": "123456"
}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/register')
def register():
    if 'username' in session:
        return redirect(url_for('index'))
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

        # 检查用户名是否已存在
        if username in users:
            return jsonify({'error': '用户名已存在'}), 400

        # 保存用户信息（实际应用中应该使用数据库）
        users[username] = password

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

        # 验证用户名和密码
        if username in users and users[username] == password:
            session['username'] = username
            return jsonify({'success': True, 'username': username})
        else:
            return jsonify({'success': False, 'message': '用户名或密码错误'})
    except Exception as e:
        print(f"登录验证过程中出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/logout')
def logout():
    # 清除所有会话数据
    session.clear()
    # 重定向到首页
    return redirect(url_for('index'))


@app.route('/backend')
@login_required
def backend():
    return render_template('backend.html', username=session.get('username'))


@app.route('/detective')
@login_required
def portfolio_details():
    models = get_all_available_models()
    return render_template('detective.html', models=models)


@app.route('/model_training')
@login_required
def model_training():
    models = get_ollama_models()
    trained_models = get_trained_models()
    return render_template('model_training.html', models=models, trained_models=trained_models)


@app.route('/knowledge_base')
@login_required
def knowledge_base():
    return render_template('knowledge_base.html')


@app.route('/vulnerability_management')
@login_required
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
        # 获取用户选择的模型
        model_name = request.form.get('model_name', DEFAULT_MODEL)

        # 调试：输出文件的名称和扩展名
        print(f"上传的文件名是: {file.filename}")
        print(f"选择的模型是: {model_name}")

        if file and allowed_file(file.filename):
            # 保存文件并获取新路径
            file_path = save_file(file)

            # 设置环境变量
            env = os.environ.copy()
            env['EXTRACTED_FUNCTIONS_FILE_PATH'] = EXTRACTED_FUNCTIONS_FILE_PATH

            # 执行第一个 IDA 命令提取特征
            ida_command_1 = f'"{IDA_EXECUTABLE}" -A -S"{EXTRACT_FEATURES_SCRIPT_PATH}" "{file_path}"'
            print("执行的 IDA 命令1是:", ida_command_1)  # 输出执行的 IDA 命令
            result_1 = subprocess.run(ida_command_1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

            if result_1.stderr:
                print("IDA 执行错误:", result_1.stderr.decode())
                return jsonify({'error': 'IDA 执行失败'}), 500

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

            # 返回提取的函数数据，不再返回CSV内容
            # 前端将分两步处理：1. 显示函数数据 2. 通过get_vulfi_results获取CSV数据进行漏洞分析
            return jsonify({'result': extracted_functions})

        return jsonify({'error': '文件类型不支持'}), 400

    except Exception as e:
        print(f"处理文件时出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze/<address>', methods=['GET'])
def analyze_vulnerability(address):
    try:
        # 获取用户选择的模型
        model_name = request.args.get('model_name', DEFAULT_MODEL)
        # 获取是否使用流式输出的参数
        stream = request.args.get('stream', 'false').lower() == 'true'

        # 如果选择的是训练模型，找到对应的基础模型
        if ':' not in model_name:  # 训练模型通常没有冒号
            trained_models = get_trained_models()
            for trained_model in trained_models:
                if trained_model["model_name"] == model_name:
                    model_name = trained_model["base_model"]
                    print(f"使用训练模型 {trained_model['model_name']} 的基础模型: {model_name}")
                    break

        # 加载 feature 数据
        features = load_features()
        
        # 根据stream参数决定返回方式
        if stream:
            # 流式输出
            def generate():
                try:
                    # 使用流式核心分析函数
                    response_stream = analyze_vulnerability_core(
                        features, 
                        address=address, 
                        model_name=model_name, 
                        stream=True
                    )
                    
                    # 对流式输出进行处理
                    if response_stream:
                        # 第一个事件
                        yield 'data: {"event": "start"}\n\n'
                        
                        # 输出内容
                        for chunk in response_stream:
                            if 'message' in chunk and 'content' in chunk['message']:
                                content = chunk['message']['content']
                                if content:
                                    # 使用Server-Sent Events格式
                                    yield f'data: {json.dumps({"content": content})}\n\n'
                        
                        # 结束事件
                        yield 'data: {"event": "end"}\n\n'
                    else:
                        yield 'data: {"error": "未获取到分析结果"}\n\n'
                        
                except Exception as e:
                    print(f"流式分析过程中出错: {str(e)}")
                    yield f'data: {{"error": "{str(e)}"}}\n\n'
            
            # 返回流式响应
            return Response(
                generate(),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'X-Accel-Buffering': 'no'  # 禁用Nginx缓冲
                }
            )
        else:
            # 非流式输出 - 原有的实现方式
            result_content = analyze_vulnerability_core(features, address=address, model_name=model_name)
            
            if result_content:
                return jsonify({'result': result_content})
            else:
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
                "api_key_used": RAGFLOW_API_KEY[:10] + "..."  # 只显示部分API key以保护安全
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
        {"base": "http://127.0.0.1", "path": "/api/v1/datasets", "method": "GET", "data": None,
         "name": "获取知识库列表"},
        {"base": "http://127.0.0.1:9380", "path": "/api/v1/datasets", "method": "GET", "data": None,
         "name": "获取知识库列表(9380端口)"},

        # 测试检索API
        {"base": "http://127.0.0.1", "path": "/api/v1/retrieval", "method": "POST",
         "data": {"query": "测试查询", "top_k": 3}, "name": "检索API"},

        # 测试知识库详情API
        {"base": "http://127.0.0.1", "path": "/api/v1/datasets/1", "method": "GET", "data": None, "name": "知识库详情"},

        # 测试知识库文档列表API - 修正路径
        {"base": "http://127.0.0.1", "path": "/api/v1/datasets/1/documents", "method": "GET", "data": None,
         "name": "知识库文档列表"}
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

        # 先获取文档名称
        filename = None
        try:
            datasets = get_ragflow_kb_datasets(kb_id)
            if isinstance(datasets, dict) and datasets.get('code') == 0 and 'data' in datasets and 'docs' in datasets[
                'data']:
                for doc in datasets['data']['docs']:
                    if str(doc.get('id')) == doc_id:
                        filename = doc.get('name')
                        api_logger.info(f"从文档列表找到文件名: {filename}")
                        break
        except Exception as e:
            api_logger.warning(f"获取文件名失败: {str(e)}")

        # 构建请求URL
        request_url = f"{RAGFLOW_API_URL}/api/v1/datasets/{kb_id}/documents/{doc_id}"
        api_logger.info(f"请求文档下载 - URL: {request_url}")

        # 发送请求获取文档内容
        response = requests.get(
            request_url,
            headers=headers,
            stream=True,
            timeout=30
        )

        # 检查响应状态
        if response.status_code == 200:
            api_logger.info(f"下载请求成功 - 状态码: {response.status_code}")

            # 如果未找到文件名，尝试从响应头获取
            if not filename and 'Content-Disposition' in response.headers:
                try:
                    cd = response.headers['Content-Disposition']
                    if '"' in cd:
                        filename = cd.split('filename="')[1].split('"')[0]
                    else:
                        filename = cd.split('filename=')[1].split(';')[0].strip()
                except Exception:
                    pass

            # 如果仍然没有文件名，使用文档ID
            if not filename:
                filename = f"document_{doc_id}"

            # 检查内容类型，避免返回JSON错误
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type.lower():
                try:
                    content_start = next(response.iter_content(chunk_size=1024))
                    json.loads(content_start)  # 如果能解析为JSON，则是错误响应
                    return jsonify({"error": "服务器返回了JSON而不是文件内容"}), 500
                except (json.JSONDecodeError, StopIteration):
                    pass

            # 创建响应
            def generate():
                if 'content_start' in locals() and content_start:
                    yield content_start
                for chunk in response.iter_content(chunk_size=4096):
                    if chunk:
                        yield chunk

            # 设置响应头
            encoded_filename = requests.utils.quote(filename)
            flask_response = Response(
                generate(),
                content_type=response.headers.get('Content-Type', 'application/octet-stream')
            )

            # 设置Content-Disposition头
            if any(c in filename for c in ',;\'\"'):
                flask_response.headers[
                    'Content-Disposition'] = f'attachment; filename="{encoded_filename}"; filename*=UTF-8\'\'{encoded_filename}'
            else:
                flask_response.headers['Content-Disposition'] = f'attachment; filename={encoded_filename}'

            # 复制Content-Length头
            if 'Content-Length' in response.headers:
                flask_response.headers['Content-Length'] = response.headers['Content-Length']

            return flask_response
        else:
            error_msg = f"文档下载失败: 状态码 {response.status_code}"
            if response.headers.get('Content-Type', '').startswith('application/json'):
                try:
                    error_json = response.json()
                    if 'error' in error_json:
                        error_msg = f"下载失败: {error_json['error']}"
                except:
                    pass

            api_logger.error(error_msg)
            return jsonify({"error": error_msg}), response.status_code

    except requests.exceptions.RequestException as req_err:
        error_msg = f"下载请求失败: {str(req_err)}"
        api_logger.error(error_msg)
        return jsonify({"error": error_msg}), 500
    except Exception as e:
        error_msg = f"下载处理出错: {str(e)}"
        api_logger.error(error_msg)
        return jsonify({"error": error_msg}), 500


# 获取可用的Ollama模型列表
@app.route('/api/ollama/models', methods=['GET'])
def api_get_ollama_models():
    try:
        include_trained = request.args.get('include_trained', 'false').lower() == 'true'

        if include_trained:
            models = get_all_available_models()
        else:
            models = get_ollama_models()

        return jsonify({'models': models})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 保存训练模型信息
@app.route('/api/models/trained', methods=['POST'])
def api_save_trained_model():
    try:
        data = request.get_json()
        if not data or 'model_name' not in data or 'base_model' not in data:
            return jsonify({'error': '缺少必要的模型信息'}), 400

        # 确保有创建日期
        if 'created_at' not in data:
            from datetime import datetime
            data['created_at'] = datetime.now().strftime('%Y-%m-%d')

        # 添加唯一ID
        import uuid
        data['id'] = str(uuid.uuid4())

        success = save_trained_model(data)
        if success:
            return jsonify({'success': True, 'message': '模型信息保存成功', 'model': data})
        else:
            return jsonify({'error': '保存模型信息失败'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 获取已训练模型列表
@app.route('/api/models/trained', methods=['GET'])
def api_get_trained_models():
    try:
        models = get_trained_models()
        return jsonify({'models': models})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 删除训练模型
@app.route('/api/models/trained/<model_id>', methods=['DELETE'])
def api_delete_trained_model(model_id):
    try:
        models = get_trained_models()
        filtered_models = [model for model in models if model.get('id') != model_id]

        if len(filtered_models) == len(models):
            return jsonify({'error': '未找到指定模型'}), 404

        with open(TRAINED_MODELS_FILE, 'w', encoding='utf-8') as f:
            json.dump(filtered_models, f, ensure_ascii=False, indent=2)

        return jsonify({'success': True, 'message': '模型删除成功'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 添加模拟漏洞数据API
@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """获取漏洞列表API"""
    # 获取分页参数
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 15))
    
    # 获取过滤参数
    risk_level = request.args.get('risk_level', None)
    search_term = request.args.get('search', '').lower()
    
    # 获取语言偏好参数
    use_chinese = request.args.get('use_chinese', 'true').lower() == 'true'

    # 加载所有漏洞数据
    vulnerabilities_file = os.path.join(PROJECT_PATH, 'data', 'cve_vulnerabilities_raw.json')
    try:
        with open(vulnerabilities_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            ALL_VULNERABILITIES = data.get('vulnerabilities', [])
    except FileNotFoundError:
        return jsonify({
            "error": f"漏洞数据文件不存在: {vulnerabilities_file}",
            "vulnerabilities": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "total_pages": 0,
            "filtered": False
        }), 404
    except Exception as e:
        return jsonify({
            "error": f"读取漏洞数据失败: {str(e)}",
            "vulnerabilities": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "total_pages": 0,
            "filtered": False
        }), 500
    
    # 应用过滤条件
    filtered_vulnerabilities = ALL_VULNERABILITIES
    
    # 按风险等级过滤
    if risk_level:
        filtered_vulnerabilities = [v for v in filtered_vulnerabilities if v['risk_level'] == risk_level]
    
    # 按搜索词过滤
    if search_term:
        filtered_vulnerabilities = [
            v for v in filtered_vulnerabilities 
            if search_term in v.get('id', '').lower() or 
               search_term in v.get('type', '').lower() or 
               search_term in v.get('function', '').lower() or 
               search_term in (v.get('description_zh' if use_chinese and 'description_zh' in v else 'description', '') or '').lower() or
               search_term in (v.get('details_zh' if use_chinese and 'details_zh' in v else 'details', '') or '').lower()
        ]

    # 处理中文翻译显示
    processed_vulnerabilities = []
    for vuln in filtered_vulnerabilities:
        # 复制漏洞数据
        processed_vuln = vuln.copy()
        
        # 如果请求中文并且有中文翻译，则替换英文内容
        if use_chinese:
            if 'description_zh' in vuln and vuln['description_zh']:
                processed_vuln['description'] = vuln['description_zh']
            if 'details_zh' in vuln and vuln['details_zh']:
                processed_vuln['details'] = vuln['details_zh']
        
        processed_vulnerabilities.append(processed_vuln)
    
    # 计算总页数和当前页数据
    total_items = len(processed_vulnerabilities)
    total_pages = max(1, (total_items + page_size - 1) // page_size)
    
    # 确保请求的页码有效
    if page > total_pages:
        page = total_pages
    
    # 计算分页的起始和结束索引
    start_idx = (page - 1) * page_size
    end_idx = min(start_idx + page_size, total_items)
    
    # 获取当前页的数据
    current_page_data = processed_vulnerabilities[start_idx:end_idx]

    return jsonify({
        "vulnerabilities": current_page_data,
        "total": total_items,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "filtered": bool(risk_level or search_term),  # 指示是否应用了过滤
        "using_chinese": use_chinese  # 指示是否使用了中文翻译
    })


# 获取漏洞详情API
@app.route('/api/vulnerabilities/<vuln_id>', methods=['GET'])
def get_vulnerability_details(vuln_id):
    """获取指定漏洞的详细信息"""
    # 获取语言偏好参数
    use_chinese = request.args.get('use_chinese', 'true').lower() == 'true'
    
    # 从数据文件中查找漏洞
    vulnerabilities_file = os.path.join(PROJECT_PATH, 'data', 'all_vulnerabilities.json')
    try:
        with open(vulnerabilities_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            all_vulnerabilities = data.get('vulnerabilities', [])
            
            # 查找匹配的漏洞
            vuln = None
            for v in all_vulnerabilities:
                if v.get('id') == vuln_id:
                    vuln = v.copy()
                    break
            
            # 如果找到漏洞且要使用中文翻译
            if vuln and use_chinese:
                if 'description_zh' in vuln and vuln['description_zh']:
                    vuln['description'] = vuln['description_zh']
                if 'details_zh' in vuln and vuln['details_zh']:
                    vuln['details'] = vuln['details_zh']
            
            # 如果找到漏洞，返回详情
            if vuln:
                return jsonify(vuln)
                
    except Exception as e:
        return jsonify({"error": f"获取漏洞详情失败: {str(e)}"}), 500
    
    # 如果未找到漏洞或出现错误，生成一个模拟数据
    risk_levels = ["高危", "中危", "低危"]
    types = ["缓冲区溢出", "SQL注入", "XSS攻击", "命令注入", "权限提升", "拒绝服务"]
    import random

    vuln = {
        "id": vuln_id,
        "risk_level": random.choice(risk_levels),
        "type": random.choice(types),
        "function": f"function_{vuln_id.split('-')[-1].lower()}",
        "description": f"这是{vuln_id}的漏洞描述信息，通常描述漏洞可能造成的影响和产生的原因。",
        "details": f"这是{vuln_id}的详细信息，包含漏洞的技术细节、利用方法和影响范围等。攻击者可能利用此漏洞执行未授权操作或获取敏感信息。",
        "affected_versions": "受影响的版本范围: 1.0.0 - 2.3.5",
        "cve_reference": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}",
        "discovered_date": "2023-01-15"
    }

    return jsonify(vuln)


# 翻译漏洞描述
@app.route('/api/translate', methods=['POST'])
def translate_text():
    try:
        data = request.get_json()
        text = data.get('text', '')
        target_lang = data.get('target_lang', 'zh')
        
        if not text:
            return jsonify({'error': '没有提供要翻译的文本'}), 400
            
        # 使用transformers进行翻译
        try:
            from transformers import MarianMTModel, MarianTokenizer
        except ImportError:
            # 如果未安装transformers，给出提示
            return jsonify({
                'error': '服务器未安装必要的翻译库，请先安装：pip install transformers sentencepiece'
            }), 500
        
        # 加载模型和分词器（首次加载会下载模型，确保服务器有网络连接）
        model_name = "Helsinki-NLP/opus-mt-en-zh"
        
        # 创建全局变量以便模型只加载一次
        if not hasattr(app, 'translator_model') or not hasattr(app, 'translator_tokenizer'):
            try:
                app.translator_tokenizer = MarianTokenizer.from_pretrained(model_name)
                app.translator_model = MarianMTModel.from_pretrained(model_name)
                print("翻译模型加载成功")
            except Exception as e:
                print(f"加载翻译模型失败: {str(e)}")
                return jsonify({'error': f'加载翻译模型失败: {str(e)}'}), 500
        
        # 执行翻译
        try:
            # 分词
            inputs = app.translator_tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
            
            # 生成翻译
            translated = app.translator_model.generate(**inputs)
            translated_text = app.translator_tokenizer.batch_decode(translated, skip_special_tokens=True)[0]
            
            return jsonify({
                'original_text': text,
                'translated_text': translated_text,
                'target_lang': target_lang,
                'model': model_name
            })
        except Exception as e:
            print(f"翻译过程中出错: {str(e)}")
            return jsonify({'error': f'翻译过程中出错: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_vulfi_results', methods=['GET'])
def get_vulfi_results():
    """获取已经分析的VulFi结果，供前端显示漏洞检测结果使用"""
    try:
        # 读取并解析 scan_results.csv 文件
        csv_content = []
        if os.path.exists(VULFI_FILE_PATH):
            csv_content = read_csv_to_array(VULFI_FILE_PATH)
            # 应用漏洞名称翻译
            for item in csv_content:
                if 'IssueName' in item and item['IssueName'] in VULNERABILITY_NAME_MAP:
                    item['IssueName'] = VULNERABILITY_NAME_MAP[item['IssueName']]
                # 应用函数名称翻译（保留原名）
                if 'FunctionName' in item and item['FunctionName'] in FUNCTION_NAME_MAP:
                    item['FunctionName'] = f"{FUNCTION_NAME_MAP[item['FunctionName']]} ({item['FunctionName']})"
            
            return jsonify({'csv': csv_content})
        else:
            return jsonify({'error': 'VulFi分析结果文件不存在，请先上传文件进行分析'}), 404
    except Exception as e:
        print(f"获取VulFi结果时出错: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
