import json
import csv
import re


# 读取VulFi结果文件
def read_vulfi_file(vulfi_file_path):
    vulfi_data = []
    with open(vulfi_file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            vulfi_data.append(row)
    return vulfi_data


# 读取extracted_functions.json文件
def read_extracted_functions(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


# 格式化指令，去除多余的空格
def format_instruction(instruction_text):
    # 移除多余的空格
    formatted_instruction = re.sub(r'\s+', ' ', instruction_text).strip()
    return formatted_instruction


# 获取函数的最高优先级
def get_highest_priority(instructions, vulfi_data):
    # 默认优先级为None
    highest_priority = None
    for instruction in instructions:
        instruction_address = instruction['address']
        # 查找VulFi数据中是否有对应地址的优先级
        matching_vulfi_entry = next((vulfi for vulfi in vulfi_data if vulfi['Address'] == instruction_address), None)
        if matching_vulfi_entry:
            priority = matching_vulfi_entry['Priority']
            if highest_priority is None or priority > highest_priority:
                highest_priority = priority
    return highest_priority if highest_priority else ''


# 将优先级转换为数字，以便排序
def priority_to_numeric(priority):
    priority_map = {'High': 3, 'Medium': 2, 'Low': 1, '': 0}  # 定义优先级对应的数值
    return priority_map.get(priority, 0)  # 默认为0


# 匹配并生成最终的JSON数据
def extract_vulfi_data(vulfi_data, extracted_functions):
    vulfi_extracted_data = []

    # 遍历 VulFi 数据
    for vulfi_item in vulfi_data:
        function_name = vulfi_item['FoundIn']
        address = vulfi_item['Address']
        issue_name = vulfi_item['IssueName']  # 提取 IssueName
        # 查找对应的函数数据
        function_data = next((func for func in extracted_functions if func['function_name'] == function_name), None)

        if function_data:
            instructions_with_priority = []
            for instruction in function_data['instructions']:
                instruction_address = instruction['address']
                instruction_text = instruction['instruction']

                # 格式化指令
                formatted_instruction = format_instruction(instruction_text)

                # 判断指令地址是否与VulFi中的地址匹配
                if address == instruction_address:
                    instructions_with_priority.append({
                        'address': instruction_address,
                        'instruction': formatted_instruction,
                        'priority': vulfi_item['Priority'],
                        'issue_name': issue_name  # 添加 IssueName 字段
                    })
                else:
                    instructions_with_priority.append({
                        'address': instruction_address,
                        'instruction': formatted_instruction,
                        'priority': '',
                        'issue_name': ''  # 如果没有匹配的优先级，保留空值
                    })

            # 获取该函数的最高优先级
            highest_priority = get_highest_priority(instructions_with_priority, vulfi_data)

            vulfi_extracted_data.append({
                'function_name': function_name,
                'instructions': instructions_with_priority,
                'highest_priority': highest_priority
            })

    # 按照最高优先级排序
    vulfi_extracted_data.sort(key=lambda x: priority_to_numeric(x['highest_priority']), reverse=True)

    return vulfi_extracted_data


# 将结果输出为JSON文件
def save_to_json(data, output_file_path):
    with open(output_file_path, 'w') as file:
        json.dump(data, file, indent=4)


# 主函数
def main():
    vulfi_file_path = r'example/test2/test2.386'  # VulFi结果文件路径
    extracted_functions_file_path = r'example/test2/extracted_functions.json'  # extracted_functions.json文件路径
    output_file_path = r'example/test2/vulfi_extracted_data.json'  # 输出的JSON文件路径

    vulfi_data = read_vulfi_file(vulfi_file_path)
    extracted_functions = read_extracted_functions(extracted_functions_file_path)

    extracted_data = extract_vulfi_data(vulfi_data, extracted_functions)
    save_to_json(extracted_data, output_file_path)

    print(f"数据已成功提取并保存至 {output_file_path}")


if __name__ == "__main__":
    main()
