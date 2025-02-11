import markdown2
import pdfkit
import tempfile
import re

# 读取Markdown文件并转换为HTML
with open(r"example/test2/result.md", "r", encoding="utf-8") as md_file:
    markdown_content = md_file.read()

# 打印原始Markdown内容
print("原始的Markdown内容：")
print(markdown_content)

code_blocks = re.findall(r'```[a-zA-Z]?\s*\n(.*?)\n```', markdown_content, re.DOTALL)

# 打印提取的代码块内容
print("\n提取的代码块内容：")
for block in code_blocks:
    print(f"---\n{block}\n---")

# 2. 替换代码块部分为占位符
markdown_content_without_code = re.sub(r'```[a-zA-Z]\n.*?\n```', '<<<CODEBLOCK>>>', markdown_content, flags=re.DOTALL)

# # 打印替换占位符后的Markdown内容
# print("\n替换占位符后的Markdown内容：")
# print(markdown_content_without_code)

# 3. 强制换行：将所有的换行符（除了代码块内容）替换为两个换行符
markdown_content_without_code = re.sub(r'([^\n])\n([^\n])', r'\1\n\n\2', markdown_content_without_code)

# 4. 还原代码块到内容中
for code_block in code_blocks:
    markdown_content_without_code = markdown_content_without_code.replace('<<<CODEBLOCK>>>', f'```\n{code_block}\n```', 1)

# # 打印处理后的Markdown内容
# print("\n经过处理后的Markdown内容：")
# print(markdown_content_without_code)

# 使用markdown2的gfm扩展，启用换行支持
html_content = markdown2.markdown(markdown_content_without_code, extras=["gfm"])

# 定义CSS样式
css = """
body {
    font-family: "Microsoft YaHei", "SimSun", sans-serif;
}

h1, h2, h3, h4, h5, h6 {
    font-weight: bold;
}

code, pre {
    font-family: "Courier New", monospace;
    background-color: #f4f4f4;
    padding: 3px;
    border-radius: 3px;
    font-size: 0.95em;
}

pre {
    white-space: pre-wrap;
    word-wrap: break-word;
}

ul {
    list-style-type: disc;  /* 无序列表符号 */
    padding-left: 20px;
}

p {
    margin-bottom: 10px;  /* 添加段落间距 */
}
"""

# 将CSS内容写入临时文件
with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as temp_css_file:
    temp_css_file.write(css)
    css_file_path = temp_css_file.name  # 获取临时CSS文件路径

# 设置pdfkit的选项
options = {
    'encoding': 'UTF-8',  # 设置编码
    'no-outline': None,  # 去除PDF的目录
    'custom-header': [('Accept-Encoding', 'gzip')],
    'quiet': None
}

# 将HTML转换为PDF，传入CSS文件路径
pdfkit.from_string(html_content, r"example/test2/result13.pdf", options=options, css=css_file_path)

# 删除临时CSS文件
import os
os.remove(css_file_path)
