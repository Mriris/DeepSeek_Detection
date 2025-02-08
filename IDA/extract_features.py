import idautils
import idaapi
import idc
import json

def extract_functions():
    """
    提取二进制文件中的函数列表
    """
    functions = []
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        functions.append(func_name)
    return functions

def extract_strings():
    """
    提取二进制文件中的字符串
    """
    strings = []
    for string_ea in idautils.Strings():
        strings.append(str(string_ea))
    return strings

def extract_calls():
    """
    提取函数调用关系
    """
    calls = []
    for func_ea in idautils.Functions():
        for head in idautils.FuncItems(func_ea):
            # 使用 idaapi.print_insn_mnem 代替 idc.GetMnem
            mnem = idaapi.print_insn_mnem(head)
            if mnem == "call":
                # 使用 idautils.DecodeInstruction 获取操作数
                instruction = idautils.DecodeInstruction(head)
                # 获取操作数值
                target_func = instruction[1].value  # 获取操作数的值
                calls.append((head, target_func))
    return calls

def save_features():
    """
    提取函数、字符串和调用关系，并保存到 IDA 文件
    """
    functions = extract_functions()
    strings = extract_strings()
    calls = extract_calls()

    # 组织特征为字典格式
    features = {
        "functions": functions,
        "strings": strings,
        "calls": calls
    }

    # 保存到 IDA 文件
    with open(r"C:\0Program\Python\DeepSeek_Detection\IDA\features.json", "w") as f:
        json.dump(features, f, indent=4)

# 调用函数提取特征并保存
save_features()
