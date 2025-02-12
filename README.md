# VULNEX - 漏洞检测系统

VULNEX 是一个基于深度学习的漏洞检测系统，结合了机器学习和静态代码分析，能够有效地识别和修复代码中的潜在安全漏洞。该系统支持对各种二进制文件进行分析，检测可能的漏洞并提供详细的修复方案。

## 项目结构
```
.
├── app.py                          # 主应用程序文件，使用 Flask 构建 Web 服务
├── deepseek_detection.py           # 深度学习模型的加载和漏洞检测
├── process_vulfi.py                # 处理 VulFi 扫描结果
├── example/                        # 示例文件，包含测试数据和结果
│   └── test1/
│       ├── ConsoleApplication1.cpp # 测试代码文件
│       ├── ConsoleApplication1.exe # 编译后的二进制文件
│       ├── extracted_functions.json # 提取的完整函数数据
│       ├── vulfi_extracted_data.json # VulFi 扫描提取的数据
│       └── result.md               # 漏洞扫描结果
│   └── Web/                        # 浏览器文件存储
│       └── ...
├── IDA/                            # IDA Pro 插件和脚本
│   ├── extract_features.py         # 提取特征的脚本
│   ├── vulfi/                      # VulFi 插件
│   └── ...                         # 其他 IDA Pro 插件相关文件
├── reference/                      # 旧代码和参考资料
│   └── ...                         
├── static/                         # 前端静态文件，包括样式、图像和前端脚本
│   └── assets/
│       └── img/                    # 图像文件
│       └── css/                    # CSS 文件
│       └── js/                     # JavaScript 文件
│       └── video/                  # 视频文件
├── templates/                      # 前端页面文件
│   ├── base.html                   # 基本 HTML 模板
│   ├── detective.html              # 漏洞检测界面
│   ├── index.html                  # 首页
│   └── ...                         
└── requirements.txt                # Python 依赖包
```

## 安装和配置

1. **克隆项目到本地**：
   ```bash
   git clone https://github.com/Mriris/DeepSeek_Detection.git
   ```

2. **创建并激活 conda 环境**：
   - 安装 Python 3.13.2 版本的 conda 环境：
     ```bash
     conda create -n muaDSD python=3.13.2
     ```
   - 激活 conda 环境：
     ```bash
     conda activate muaDSD
     ```

3. **安装所需的依赖包**：
   在激活的 conda 环境中，安装项目的依赖：
   ```bash
   pip install -r requirements.txt
   ```

4. **确保您已安装并配置了 IDA Pro**，并正确设置了 `ida.exe` 的路径。

5. **启动 Flask 应用**：
   运行python：
   ```bash
   python app.py
   ```

6. **打开浏览器并访问 `http://127.0.0.1:5000` 来使用 VULNEX**。

## 使用方法

1. **上传二进制文件**：
   在首页，点击“开始”按钮，上传 `.bin`、`.exe` 或 `.elf` 格式的二进制文件。

2. **漏洞检测**：
   上传文件后，系统会开始对文件进行漏洞扫描。您可以查看漏洞检测结果，并进一步分析每个漏洞。

3. **查看分析结果**：
   点击漏洞的地址，系统会显示该漏洞的详细分析和修复建议。

## 功能说明

- **DeepSeek 漏洞检测**：结合深度学习和静态分析，自动识别代码中的漏洞。
- **VulFi 扫描**：通过 VulFi 扫描工具提取二进制文件的函数和指令信息。
- **漏洞分析**：根据提取的特征数据和漏洞扫描结果，提供针对漏洞的修复方案。

## 文件说明

- `app.py`：Flask Web 服务的主逻辑，负责文件上传、漏洞检测及结果展示。
- `deepseek_detection.py`：深度学习模型的加载和漏洞检测逻辑。
- `process_vulfi.py`：处理 VulFi 扫描结果，生成漏洞报告。
- `app.py`：启动项目的入口脚本，负责初始化和运行 Flask 应用。
- `IDA/`：包含用于 IDA Pro 的插件和脚本。
- `static/`：包含静态资源，如图像、样式和前端脚本。
- `templates/`：HTML 模板文件，包含项目的前端页面。
