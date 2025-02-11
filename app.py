import csv
import os
import subprocess
from flask import Flask, render_template, request, jsonify
import ollama
import json

from process_vulfi import read_vulfi_file, read_extracted_functions, extract_vulfi_data, save_to_json

app = Flask(__name__)

UPLOAD_FOLDER = r'C:\0Program\Python\DeepSeek_Detection\example\Web'
ALLOWED_EXTENSIONS = {'bin', 'exe', 'elf'}


# 确保上传的文件符合格式
def allowed_file(filename):
    if '.' in filename:
        extension = filename.rsplit('.', 1)[1].lower()
        # print(f"上传文件的扩展名是: {extension}")  # 调试：输出扩展名
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
    从 JSON 文件加载特征数据。
    包括所有指令和带优先级的指令。
    """
    # 特征文件路径
    features_file_path = r'C:\0Program\Python\DeepSeek_Detection\example\Web\vulfi_extracted_data.json'

    # 打开并加载 JSON 文件
    with open(features_file_path, 'r') as f:
        features = json.load(f)

    # 获取第一个函数的所有指令
    first_function = features[0]  # 假设每个文件包含多个函数
    all_instructions = [instruction for instruction in first_function['instructions']]

    # 提取带有优先级的指令
    priority_instructions = [
        {
            'address': instruction['address'],
            'instruction': instruction['instruction'],
            'issue_name': instruction.get('issue_name', ''),  # 获取 issue_name，若无则为空
            'priority': instruction['priority']  # 获取优先级
        }
        for instruction in first_function['instructions'] if instruction['priority']
    ]
    print(f"提取的优先级指令: {priority_instructions}")  # 打印提取的优先级指令
    # 返回所有指令和带优先级的指令
    return {
        'all_instructions': all_instructions,
        'priority_instructions': priority_instructions
    }


@app.route('/')
def index():
    return render_template('index.html')


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

            # 执行 IDA 命令提取特征
            ida_command = f'"C:\\Application\\IDA Professional 9.0\\ida.exe" -A -S"C:\\0Program\\Python\\DeepSeek_Detection\\IDA\\extract_features.py" "{file_path}"'
            result = subprocess.run(ida_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.stderr:
                print("IDA 执行错误:", result.stderr.decode())
                return jsonify({'error': 'IDA 执行失败'}), 500

            # 获取并处理 VulFi 数据
            vulfi_file_path = r'C:\0Program\Python\DeepSeek_Detection\example\Web\scan_results.csv'
            extracted_functions_file_path = r'C:\0Program\Python\DeepSeek_Detection\example\Web\extracted_functions.json'

            # 读取 VulFi 结果和提取的函数数据

            vulfi_data = read_vulfi_file(vulfi_file_path)
            extracted_functions = read_extracted_functions(extracted_functions_file_path)

            # 调试：输出读取的 VulFi 数据和函数数据
            # print("VulFi 数据读取成功:", vulfi_data[:2])  # 输出前两行数据
            # print("函数数据读取成功:", extracted_functions[:2])  # 输出前两行数据

            # 生成最终的数据
            extracted_data = extract_vulfi_data(vulfi_data, extracted_functions)

            # 调试：输出提取的数据
            # print("提取的数据:", extracted_data[:2])  # 输出前两条提取的数据

            # 保存处理后的数据到 JSON 文件
            output_file_path = r'C:\0Program\Python\DeepSeek_Detection\example\Web\vulfi_extracted_data.json'
            save_to_json(extracted_data, output_file_path)
            # 读取并解析 scan_results.csv 文件
            if os.path.exists(vulfi_file_path):
                csv_content = read_csv_to_array(vulfi_file_path)

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
    app.run(debug=True)
