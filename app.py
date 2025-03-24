import csv
import os
import subprocess
import sys

from flask import Flask, render_template, request, jsonify
import ollama
import json

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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
