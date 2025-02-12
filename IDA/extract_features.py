#"C:\Application\IDA Professional 9.0\ida.exe" -A -S"C:\0Program\Python\DeepSeek_Detection\IDA\extract_features.py" "C:\0Program\Python\DeepSeek_Detection\example\test1\ConsoleApplication1.exe"
import idaapi
import idautils
import idc
import json


def extract_function_info():
    functions = []
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        func_start = func_ea
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

        function_info = {
            'function_name': func_name,
            'start_address': hex(func_start),
            'end_address': hex(func_end),
            'instructions': extract_instructions(func_start, func_end)
        }

        functions.append(function_info)
    return functions


def extract_instructions(func_start, func_end):
    instructions = []
    for head in idautils.Heads(func_start, func_end):
        instruction = idc.GetDisasm(head)
        instructions.append({
            'address': hex(head),
            'instruction': instruction
        })
    return instructions


def save_as_json(functions):
    with open(r'C:\0Program\Python\DeepSeek_Detection\example\Web\extracted_functions.json', 'w') as json_file:
        json.dump(functions, json_file, indent=4)

idaapi.auto_wait()

# 提取函数信息
functions = extract_function_info()

# 保存为JSON文件
save_as_json(functions)

print("Exported functions to 'extracted_functions.json'")

# 漏洞检测
plugin_name = "vulfi"
arg = 0
idc.load_and_run_plugin(plugin_name, arg)

idc.qexit(0)
