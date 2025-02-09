import ollama
import json

# 全局变量，存储对话历史
messages = []

def load_model():
    """
    加载 DeepSeek 模型，并维护对话上下文
    """
    features = load_features()  # 加载特征内容

    # 先传递优先级指令，再传递所有指令
    # message_content = f"请检测以下特征(汇编指令)的潜在漏洞。特征数据：\n风险优先级指令：{json.dumps(features['priority_instructions'])}\n优先级指令所在函数全部指令：{json.dumps(features['all_instructions'])}"
    message_content = f"请检测以下特征(汇编指令)的潜在漏洞。特征数据：\n风险指令：{json.dumps(features['priority_instructions'])}"

    # 打印用户输入内容
    print("用户输入的内容：")
    print(message_content)  # 打印输入的内容

    # 记录用户输入
    messages.append({'role': 'user', 'content': message_content})

    # 调用模型，并传递完整的对话历史
    response = ollama.chat(model='deepseek-r1:14b', messages=messages)

    # 记录模型的响应
    if 'message' in response:
        messages.append({'role': 'assistant', 'content': response['message']['content']})

    return response


def detect_vulnerability():
    """
    让模型分析漏洞，并且在对话历史中存储其回答
    """
    response = load_model()
    print("漏洞检测结果：")
    if 'message' in response:
        print(response['message']['content'])
    else:
        print("未找到漏洞检测结果。")


def load_features():
    """
    从 JSON 文件加载特征
    """
    with open(r'example/test2/vulfi_extracted_data.json', 'r') as f:
        features = json.load(f)

    # 获取第一个函数
    first_function = features[0]

    # 所有指令
    all_instructions = [instruction['instruction'] for instruction in first_function['instructions']]

    # 仅提取带有优先级的指令
    priority_instructions = [instruction['instruction'] for instruction in first_function['instructions'] if instruction['priority']]

    # 返回两个特征集：所有指令和带优先级的指令
    return {
        'all_instructions': all_instructions,
        'priority_instructions': priority_instructions
    }


# 运行漏洞检测
detect_vulnerability()
