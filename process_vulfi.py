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

    for function in extracted_functions:
        for instruction in function['instructions']:
            address_to_instruction[instruction['address']] = {
                'instruction': instruction['instruction'],
                'function_name': function['function_name']  # 仍然保留函数名，供参考
            }

    for vulfi_item in vulfi_data:
        address = vulfi_item['Address']
        issue_name = vulfi_item['IssueName']

        if address in address_to_instruction:
            # 获取指令信息
            instruction_data = address_to_instruction[address]
            formatted_instruction = format_instruction(instruction_data['instruction'])

            # 构建匹配数据
            instruction_entry = {
                'address': address,
                'instruction': formatted_instruction,
                'priority': vulfi_item['Priority'],
                'issue_name': issue_name
            }

            # 获取该地址所在的函数（如果可用）
            function_name = instruction_data['function_name']

            # 组装结果
            vulfi_extracted_data.append({
                'function_name': function_name,
                'instructions': [instruction_entry],
                'highest_priority': vulfi_item['Priority']
            })

    # 按优先级排序
    vulfi_extracted_data.sort(key=lambda x: priority_to_numeric(x['highest_priority']), reverse=True)

    return vulfi_extracted_data


def save_to_json(data, output_file_path):
    print(f"保存到文件: {output_file_path}")  # 调试：输出保存文件的路径
    with open(output_file_path, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"数据已成功保存到 {output_file_path}")  # 确保数据成功保存


def priority_to_numeric(priority):
    priority_map = {'High': 3, 'Medium': 2, 'Low': 1, '': 0}
    return priority_map.get(priority, 0)
