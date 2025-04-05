import json
import csv
import re

import csv
import json

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

# 读取VulFi结果文件
def read_vulfi_file(vulfi_file_path):
    vulfi_data = []
    try:
        with open(vulfi_file_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # 处理 None 值，将其替换为空字符串
                row = {k: (v if v is not None else '') for k, v in row.items()}
                # 翻译漏洞名称
                if 'IssueName' in row and row['IssueName'] in VULNERABILITY_NAME_MAP:
                    row['IssueName'] = VULNERABILITY_NAME_MAP[row['IssueName']]
                
                # 翻译函数名称（保留原名）
                if 'FunctionName' in row and row['FunctionName'] in FUNCTION_NAME_MAP:
                    row['FunctionName'] = f"{FUNCTION_NAME_MAP[row['FunctionName']]} ({row['FunctionName']})"
                
                vulfi_data.append(row)
        # 调试：输出读取的部分数据
        # print(f"读取的 VulFi 数据: {vulfi_data[:5]}")  # 输出前5行数据（可根据实际情况调整）
    except Exception as e:
        print(f"读取 VulFi 文件时出错: {str(e)}")

    return vulfi_data


# 读取extracted_functions.json文件
def read_extracted_functions(file_path):
    try:
        with open(file_path, 'r') as file:
            extracted_functions = json.load(file)

            # 确保没有 None 值，替换或处理它们
            extracted_functions = [f for f in extracted_functions if f is not None]
        # 调试：输出读取的部分数据
        # print(f"读取的 extracted_functions 数据: {extracted_functions[:5]}")  # 输出前5个函数数据
    except Exception as e:
        print(f"读取 extracted_functions 文件时出错: {str(e)}")

    return extracted_functions


# 格式化指令，去除多余的空格
def format_instruction(instruction_text):
    formatted_instruction = re.sub(r'\s+', ' ', instruction_text).strip()
    return formatted_instruction


# 获取函数的最高优先级
def get_highest_priority(instructions, vulfi_data):
    highest_priority = None
    for instruction in instructions:
        instruction_address = instruction['address']
        matching_vulfi_entry = next((vulfi for vulfi in vulfi_data if vulfi['Address'] == instruction_address), None)
        if matching_vulfi_entry:
            priority = matching_vulfi_entry['Priority']
            if highest_priority is None or priority > highest_priority:
                highest_priority = priority
    return highest_priority if highest_priority else ''


def extract_vulfi_data(vulfi_data, extracted_functions):
    vulfi_extracted_data = []

    # 创建一个地址到指令映射，以便更快匹配
    address_to_instruction = {}

    # 遍历提取的函数数据，生成地址到指令的映射
    for function in extracted_functions:
        # 确保函数中包含 'instructions'，并且每条指令都包含 'address' 和 'instruction'
        if 'instructions' in function:
            for instruction in function['instructions']:
                address = instruction.get('address')
                if address:
                    address_to_instruction[address] = {
                        'instruction': instruction.get('instruction', ''),
                        'function_name': function.get('function_name', '未知函数')  # 使用默认函数名
                    }

    # 遍历 VulFi 数据，匹配指令
    for vulfi_item in vulfi_data:
        address = vulfi_item.get('Address', '')
        issue_name = vulfi_item.get('IssueName', '未知问题')
        priority = vulfi_item.get('Priority', 'Low')

        # 如果缺少必要字段，跳过该条记录
        if not address or not issue_name or not priority:
            continue

        # 如果该地址有对应的指令数据
        if address in address_to_instruction:
            instruction_data = address_to_instruction[address]
            formatted_instruction = format_instruction(instruction_data['instruction'])

            # 构建匹配数据
            instruction_entry = {
                'address': address,
                'instruction': formatted_instruction,
                'priority': priority,
                'issue_name': issue_name  # 此处的issue_name已在read_vulfi_file函数中翻译为中文
            }

            # 获取该地址所在的函数名（如果可用）
            function_name = instruction_data['function_name']

            # 组装结果，若已有相同函数的记录，则更新优先级较高的项
            existing_entry = next((entry for entry in vulfi_extracted_data if entry['function_name'] == function_name),
                                  None)
            if existing_entry:
                # 更新现有条目，优先级较高的替代
                existing_entry['instructions'].append(instruction_entry)
                existing_entry['highest_priority'] = max(existing_entry['highest_priority'], priority)
            else:
                # 否则创建新的条目
                vulfi_extracted_data.append({
                    'function_name': function_name,
                    'instructions': [instruction_entry],
                    'highest_priority': priority
                })

    # 按优先级排序，优先级越高越排前
    vulfi_extracted_data.sort(key=lambda x: priority_to_numeric(x['highest_priority']), reverse=True)

    # 打印前5条数据，供调试使用
    # print(f"提取的 VulFi 数据: {vulfi_extracted_data[:5]}")

    return vulfi_extracted_data


def save_to_json(data, output_file_path):
    print(f"保存到文件: {output_file_path}")  # 调试：输出保存文件的路径
    with open(output_file_path, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"数据已成功保存到 {output_file_path}")  # 确保数据成功保存


def priority_to_numeric(priority):
    priority_map = {'High': 3, 'Medium': 2, 'Low': 1, '': 0}
    return priority_map.get(priority, 0)
