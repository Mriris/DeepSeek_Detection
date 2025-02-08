import ollama
import json


def load_model():
    """
    加载 DeepSeek 模型
    """
    features = load_features()  # 加载特征内容
    # 先传递优先级指令，再传递所有指令
    message_content = f"请检测以下特征中的潜在漏洞，特征数据：\n风险优先级指令：{json.dumps(features['priority_instructions'])}\n优先级指令所在函数全部指令：{json.dumps(features['all_instructions'])}"

    model = ollama.chat(
        model='deepseek-r1:14b',  # 请根据实际模型名称调整
        messages=[{
            'role': 'user',
            'content': message_content
        }]
    )
    return model


def detect_vulnerability(model, features):
    """
    将提取的特征输入 DeepSeek 模型进行漏洞检测
    """
    # 通过模型进行漏洞检测
    response = model  # 获取模型响应

    print("漏洞检测结果：")
    if 'message' in response:
        print(response['message']['content'])  # 输出模型返回的内容
    else:
        print("未找到漏洞检测结果。")


def load_features():
    """
    从 JSON 文件加载特征
    """
    with open(r'example/vulfi_extracted_data.json', 'r') as f:
        features = json.load(f)

    # 获取第一个函数
    first_function = features[0]

    # 所有指令
    all_instructions = [instruction['instruction'] for instruction in first_function['instructions']]

    # 仅提取带有优先级的指令
    priority_instructions = []
    for instruction in first_function['instructions']:
        if instruction['priority']:  # 检查指令是否有优先级
            priority_instructions.append(instruction)

    # 返回两个特征集：所有指令和带优先级的指令
    return {
        'all_instructions': all_instructions,
        'priority_instructions': priority_instructions
    }


# 加载模型
model = load_model()

# 加载特征
features = load_features()

# 检测漏洞
detect_vulnerability(model, features)
