#"C:\Application\IDA Professional 9.0\ida.exe" -A -S"C:\0Program\Python\DeepSeek_Detection\IDA\plugin.py" "C:\0Program\Python\DeepSeek_Detection\example\test1\ConsoleApplication1.exe"
import idc

# 使用 IDC 方法加载并运行插件
plugin_name = "vulfi"
arg = 0
idc.load_and_run_plugin(plugin_name, arg)
idc.qexit(0)
