#"C:\Application\IDA Professional 9.0\ida.exe" -A -S"C:\0Program\Python\DeepSeek_Detection\IDA\VulFi.py" "C:\0Program\Python\DeepSeek_Detection\example\Web\Application.exe"
#"C:\Application\IDA Professional 9.0\ida.exe" -A "C:\0Program\Python\DeepSeek_Detection\example\Web\Application.exe" -S"C:\0Program\Python\DeepSeek_Detection\IDA\VulFi.py"
import idc
import idaapi

# 等待自动分析完成
# idaapi.auto_wait()

# 执行插件加载和运行
plugin_name = "vulfi"
arg = 0
idc.load_and_run_plugin(plugin_name, arg)

# 退出 IDA
idc.qexit(0)
