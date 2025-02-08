import ollama
import json


def load_model():
    """
    加载 DeepSeek 模型
    """
    features = load_features()  # 加载特征内容
    message_content = f"请检测以下特征中的潜在漏洞，特征数据：{json.dumps(features)}"

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

    print("完整的模型响应：")
    print(response)

    print("漏洞检测结果：")
    if 'message' in response:
        print(response['message']['content'])  # 输出模型返回的内容
    else:
        print("未找到漏洞检测结果。")


def load_features():
    """
    从 JSON 文件加载特征
    """
    with open(r'IDA/test.json', 'r') as f:
        features = json.load(f)
    return features


# 加载模型
model = load_model()

# 加载特征
features = load_features()

# 检测漏洞
detect_vulnerability(model, features)
