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

# 匹配并生成最终的JSON数据
def extract_vulfi_data(vulfi_data, extracted_functions):
    vulfi_extracted_data = []
    for vulfi_item in vulfi_data:
        function_name = vulfi_item['FoundIn']
        address = vulfi_item['Address']
        issue_name = vulfi_item['IssueName']
        function_data = next((func for func in extracted_functions if func['function_name'] == function_name), None)

        if function_data:
            instructions_with_priority = []
            for instruction in function_data['instructions']:
                instruction_address = instruction['address']
                instruction_text = instruction['instruction']

                formatted_instruction = format_instruction(instruction_text)

                if address == instruction_address:
                    instructions_with_priority.append({
                        'address': instruction_address,
                        'instruction': formatted_instruction,
                        'priority': vulfi_item['Priority'],
                        'issue_name': issue_name
                    })
                else:
                    instructions_with_priority.append({
                        'address': instruction_address,
                        'instruction': formatted_instruction,
                        'priority': '',
                        'issue_name': ''
                    })

            highest_priority = get_highest_priority(instructions_with_priority, vulfi_data)

            vulfi_extracted_data.append({
                'function_name': function_name,
                'instructions': instructions_with_priority,
                'highest_priority': highest_priority
            })

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
