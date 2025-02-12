import json
import csv
import re

import csv
import json


# 读取VulFi结果文件
def read_vulfi_file(vulfi_file_path):
    vulfi_data = []
    try:
        with open(vulfi_file_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # 处理 None 值，将其替换为空字符串
                row = {k: (v if v is not None else '') for k, v in row.items()}
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
        # 检查 VulFi 数据中必需的字段是否存在
        address = vulfi_item.get('Address')
        issue_name = vulfi_item.get('IssueName')
        priority = vulfi_item.get('Priority')

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
                'issue_name': issue_name
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
