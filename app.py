from flask import Flask, render_template, request, jsonify
import ollama
import json

app = Flask(__name__)

# 全局变量，存储对话历史
messages = []

def load_model():
    """
    加载 DeepSeek 模型，并维护对话上下文
    """
    features = load_features()  # 加载特征内容

    # 查找风险指令及其在 all_instructions 中的位置
    highest_priority_instruction = None
    instruction_index = -1

    # 通过 address 来匹配风险指令
    for i, instruction in enumerate(features['all_instructions']):
        if instruction['address'] == features['priority_instructions'][0]['address']:  # 根据 address 匹配
            highest_priority_instruction = features['priority_instructions'][0]
            instruction_index = i
            break

    if highest_priority_instruction is None:
        print("没有找到匹配的风险指令！")
        return None

    # 获取上下文指令（前文和后文）
    previous_instructions, next_instructions = get_context_instructions(instruction_index, features['all_instructions'],
                                                                        context_range=10)

    # 只保留 instruction 字段
    previous_instructions = [instr['instruction'] for instr in previous_instructions]
    next_instructions = [instr['instruction'] for instr in next_instructions]

    # 生成消息内容：包括风险指令，上文指令，下文指令
    message_content = f"请检测以下特征(汇编指令)的潜在漏洞，进行描述并提出解决方案。特征数据：\n风险指令：{{\"instruction\": \"{highest_priority_instruction['instruction']}\", \"issue_name\": \"{highest_priority_instruction['issue_name']}\", \"priority\": \"{highest_priority_instruction['priority']}\"}}\n上文指令：{json.dumps(previous_instructions)}\n下文指令：{json.dumps(next_instructions)}"
    # message_content = f"你好，请思考，你是谁"

    # 打印用户输入内容
    print("输入内容：")
    print(message_content)  # 打印输入的内容

    # 记录用户输入
    messages.append({'role': 'user', 'content': message_content})

    # 调用模型，并传递完整的对话历史
    response = ollama.chat(model='deepseek-r1:14b', messages=messages)

    # 在控制台输出模型的响应
    print("模型响应：")
    print(response)

    # 记录模型的响应
    if 'message' in response:
        messages.append({'role': 'assistant', 'content': response['message']['content']})

    return response


def load_features():
    """
    从 JSON 文件加载特征
    """
    with open(r'example/test1/vulfi_extracted_data.json', 'r') as f:
        features = json.load(f)

    # 获取第一个函数
    first_function = features[0]

    # 所有指令
    all_instructions = [instruction for instruction in first_function['instructions']]

    # 仅提取带有优先级的指令，同时提取对应的 issue_name
    priority_instructions = [
        {
            'address': instruction['address'],
            'instruction': instruction['instruction'],
            'issue_name': instruction.get('issue_name', ''),  # 获取 issue_name，如果没有则为空
            'priority': instruction['priority']  # 取 priority 字段
        }
        for instruction in first_function['instructions'] if instruction['priority']
    ]

    # 返回两个特征集：所有指令和带优先级的指令
    return {
        'all_instructions': all_instructions,
        'priority_instructions': priority_instructions
    }

def get_context_instructions(instruction_index, all_instructions, context_range=1):
    """
    获取给定指令的上下文指令，防止越界
    :param instruction_index: 当前优先级最高指令的索引
    :param all_instructions: 所有指令
    :param context_range: 上下文范围，正值为后文，负值为上文
    :return: 包含上下文指令的列表
    """
    # 获取上文指令范围
    start_index = max(0, instruction_index - context_range)  # 防止越界，确保从0开始
    # 获取下文指令范围
    end_index = min(len(all_instructions), instruction_index + context_range + 1)  # 防止超出总长度

    # 上文指令是从当前指令索引向前提取
    previous_instructions = all_instructions[start_index:instruction_index]
    # 下文指令是从当前指令索引向后提取
    next_instructions = all_instructions[instruction_index + 1:end_index]

    return previous_instructions, next_instructions

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detective')
def portfolio_details():
    return render_template('detective.html')

@app.route('/service-details')
def service_details():
    return render_template('service-details.html')

@app.route('/detect', methods=['POST'])
def detect():
    try:
        # 执行漏洞检测
        response = load_model()

        if response and 'message' in response:
            result_content = response['message']['content']
            return jsonify({'result': result_content})  # 确保返回的数据结构包含 result 字段
        else:
            return jsonify({'error': '未找到检测结果'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
