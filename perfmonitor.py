import os
import json
import time
import threading
import logging
from datetime import datetime
from flask import Flask, render_template, Response, jsonify
import psutil

# 尝试导入GPU监控模块
try:
    import pynvml
    has_gpu = True
except ImportError:
    has_gpu = False

# 配置日志
logger = logging.getLogger("perf_monitor")

class PerformanceData:
    """存储性能数据的类"""
    
    def __init__(self):
        self.data = {
            "timestamp": time.time(),
            "gpu_info": {},
            "system_info": {},
            "translation_stats": {
                "total_texts": 0,
                "processed_texts": 0,
                "avg_time_per_text": 0,
                "total_time": 0,
                "current_batch": 0,
                "total_batches": 0,
                "remaining_time": 0,   # 预计剩余时间（秒）
                "progress_percent": 0  # 总体进度百分比
            },
            "current_translation": {
                "source_text": "",
                "translated_text": "",
                "processing_time": 0,
                "batch_index": 0,
                "text_index": 0
            }
        }
        self.clients = []
        self.lock = threading.Lock()
    
    def update(self, key, value):
        """更新性能数据"""
        with self.lock:
            if key == "gpu_info":
                self.data["gpu_info"] = value
            elif key == "system_info":
                self.data["system_info"] = value
            elif key == "translation_stats":
                # 保存当前的批次信息
                current_batch = self.data["translation_stats"].get("current_batch", 0)
                total_batches = self.data["translation_stats"].get("total_batches", 0)
                
                # 更新统计信息
                self.data["translation_stats"].update(value)
                
                # 如果没有指定批次信息，恢复原有的批次信息
                if "current_batch" not in value:
                    self.data["translation_stats"]["current_batch"] = current_batch
                if "total_batches" not in value:
                    self.data["translation_stats"]["total_batches"] = total_batches
                
            elif key == "current_translation":
                self.data["current_translation"].update(value)
            
            # 更新时间戳
            self.data["timestamp"] = time.time()
    
    def get_data(self):
        """获取当前性能数据"""
        with self.lock:
            return self.data.copy()
    
    def add_client(self, client):
        """添加客户端"""
        with self.lock:
            self.clients.append(client)
    
    def remove_client(self, client):
        """移除客户端"""
        with self.lock:
            if client in self.clients:
                self.clients.remove(client)
    
    def broadcast(self):
        """向所有客户端广播性能数据"""
        with self.lock:
            data_json = json.dumps(self.data)
            clients_to_remove = []
            
            for client in self.clients:
                try:
                    client.send(data_json)
                except Exception:
                    clients_to_remove.append(client)
            
            # 移除断开连接的客户端
            for client in clients_to_remove:
                self.clients.remove(client)

# 创建全局性能数据对象
performance_data = PerformanceData()

# 获取GPU信息函数
def get_gpu_info():
    """获取GPU性能信息"""
    if not has_gpu:
        return {"error": "没有可用的GPU"}
    
    try:
        import torch
        
        # 初始化NVML
        pynvml.nvmlInit()
        
        # 获取设备数量
        device_count = pynvml.nvmlDeviceGetCount()
        
        # 如果没有GPU，则返回空字典
        if device_count == 0 or not torch.cuda.is_available():
            return {"error": "没有可用的GPU"}
        
        # 获取GPU信息（默认使用第一个GPU）
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        
        # 获取GPU名称
        name = pynvml.nvmlDeviceGetName(handle)
        
        # 获取GPU使用率
        utilization = pynvml.nvmlDeviceGetUtilizationRates(handle)
        gpu_util = utilization.gpu
        
        # 获取GPU内存信息
        memory = pynvml.nvmlDeviceGetMemoryInfo(handle)
        total_memory = memory.total / (1024 ** 2)  # MB
        used_memory = memory.used / (1024 ** 2)    # MB
        memory_percent = (used_memory / total_memory) * 100
        
        # 获取GPU温度
        temperature = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        
        # 获取GPU功率使用情况
        power_usage = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0  # W
        
        # 关闭NVML
        pynvml.nvmlShutdown()
        
        return {
            "name": name,
            "utilization": gpu_util,
            "memory_used_mb": used_memory,
            "memory_total_mb": total_memory,
            "memory_percent": memory_percent,
            "temperature": temperature,
            "power_usage": power_usage
        }
    except Exception as e:
        return {"error": f"获取GPU信息失败: {str(e)}"}

# 获取系统信息函数
def get_system_info():
    """获取系统CPU和内存使用情况"""
    try:
        # 获取CPU使用率
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # 获取内存使用情况
        memory = psutil.virtual_memory()
        
        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": memory.used / (1024 ** 3),
            "memory_total_gb": memory.total / (1024 ** 3)
        }
    except Exception as e:
        return {"error": f"获取系统信息失败: {str(e)}"}

# 创建性能监控线程类
class PerformanceMonitorThread(threading.Thread):
    """性能监控线程，定期收集系统和GPU性能数据"""
    
    def __init__(self, interval=1.0, log_file=None):
        """
        初始化性能监控线程
        
        Args:
            interval: 监控间隔（秒）
            log_file: 性能日志文件路径，如果提供则记录性能数据
        """
        super().__init__()
        self.interval = interval
        self.log_file = log_file
        self.daemon = True  # 设置为守护线程
        self.running = False
        self.start_time = time.time()
        
        # 初始化性能日志文件
        if self.log_file:
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write("timestamp,gpu_util,gpu_mem_used,gpu_mem_total,gpu_mem_percent,gpu_temp,gpu_power,cpu_percent,mem_used_gb,mem_total_gb,mem_percent,texts_processed,avg_time_per_text\n")
    
    def run(self):
        """线程运行函数"""
        self.running = True
        self.start_time = time.time()
        
        while self.running:
            # 收集GPU和系统信息
            gpu_info = get_gpu_info()
            sys_info = get_system_info()
            
            # 更新性能数据
            performance_data.update("gpu_info", gpu_info)
            performance_data.update("system_info", sys_info)
            
            # 广播性能数据到客户端
            performance_data.broadcast()
            
            # 记录性能数据到日志文件
            if self.log_file:
                self._log_performance(gpu_info, sys_info)
            
            # 等待下一次更新
            time.sleep(self.interval)
    
    def stop(self):
        """停止监控线程"""
        self.running = False
        
    def _log_performance(self, gpu_info, sys_info):
        """记录性能数据到日志文件"""
        if not self.log_file:
            return
            
        try:
            translation_stats = performance_data.get_data()["translation_stats"]
            
            if "error" not in gpu_info and "error" not in sys_info:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    elapsed = time.time() - self.start_time
                    f.write(f"{elapsed:.2f},{gpu_info['utilization']},{gpu_info['memory_used_mb']:.1f},{gpu_info['memory_total_mb']:.1f},{gpu_info['memory_percent']:.1f},{gpu_info['temperature']},{gpu_info['power_usage']:.2f},{sys_info['cpu_percent']},{sys_info['memory_used_gb']:.2f},{sys_info['memory_total_gb']:.2f},{sys_info['memory_percent']},{translation_stats['processed_texts']},{translation_stats['avg_time_per_text']:.4f}\n")
        except Exception as e:
            # 如果记录失败，不应该影响主程序运行
            logger.error(f"记录性能数据失败: {str(e)}")

# 创建Flask应用
app = Flask(__name__)

@app.route('/')
def index():
    """返回性能监控页面"""
    # 检查模板目录是否存在
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
    
    # 创建monitor.html模板文件
    monitor_html = """
<!DOCTYPE html>
<html>
<head>
    <title>翻译性能监控</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .panel {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 4px;
            background-color: #f9f9f9;
            border: 1px solid #ddd;
        }
        .panel-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #444;
        }
        .stat-item {
            margin: 8px 0;
        }
        .progress-container {
            width: 100%;
            background-color: #ddd;
            border-radius: 4px;
            margin: 10px 0;
        }
        .progress-bar {
            height: 20px;
            background-color: #4CAF50;
            border-radius: 4px;
            text-align: center;
            color: white;
            line-height: 20px;
        }
        .translation-panel {
            background-color: #f0f8ff;
            border: 1px solid #b8d6f9;
        }
        .translation-content {
            max-height: 150px;
            overflow-y: auto;
            padding: 8px;
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-top: 5px;
        }
        .gpu-info, .system-info {
            display: flex;
            flex-wrap: wrap;
        }
        .info-block {
            flex: 1;
            min-width: 250px;
            margin: 5px;
        }
        .meter {
            height: 20px;
            position: relative;
            background: #f3f3f3;
            border-radius: 4px;
            padding: 3px;
            box-shadow: inset 0 -1px 1px rgba(255,255,255,0.3);
            margin-top: 5px;
        }
        .meter > span {
            display: block;
            height: 100%;
            border-radius: 4px;
            position: relative;
            overflow: hidden;
            text-align: center;
            color: white;
            font-size: 12px;
            line-height: 20px;
        }
        .green span { background-color: #4CAF50; }
        .orange span { background-color: #FF9800; }
        .red span { background-color: #F44336; }
        .blue span { background-color: #2196F3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>翻译性能监控</h1>
        
        <div class="panel translation-panel">
            <div class="panel-title">翻译进度</div>
            <div class="progress-container">
                <div class="progress-bar" id="translation-progress" style="width: 0%">0%</div>
            </div>
            <div class="stat-item">翻译进度: <span id="processed-texts">0</span>/<span id="total-texts">0</span> 文本 (<span id="progress-percent">0.0</span>%)</div>
            <div class="stat-item">大批次进度: <span id="current-batch">0</span>/<span id="total-batches">0</span></div>
            <div class="stat-item">平均翻译时间: <span id="avg-time">0.00</span> 秒/条</div>
            <div class="stat-item">总翻译时间: <span id="total-time">0</span> 秒</div>
            <div class="stat-item">预计剩余时间: <span id="remaining-time">计算中...</span></div>
        </div>
        
        <div class="panel translation-panel">
            <div class="panel-title">当前翻译内容</div>
            <div class="stat-item">当前批次: <span id="current-batch-idx">0</span>, 当前索引: <span id="current-text-idx">0</span>, 处理时间: <span id="processing-time">0.00</span>秒</div>
            <div class="stat-item">源文本:</div>
            <div class="translation-content" id="source-text"></div>
            <div class="stat-item">翻译结果:</div>
            <div class="translation-content" id="translated-text"></div>
        </div>
        
        <div class="panel">
            <div class="panel-title">GPU 信息</div>
            <div class="gpu-info">
                <div class="info-block">
                    <div class="stat-item">GPU: <span id="gpu-name">未检测到</span></div>
                    <div class="stat-item">GPU 利用率:</div>
                    <div class="meter green">
                        <span id="gpu-util-meter" style="width: 0%">0%</span>
                    </div>
                </div>
                <div class="info-block">
                    <div class="stat-item">GPU 内存:</div>
                    <div class="meter blue">
                        <span id="gpu-memory-meter" style="width: 0%">0%</span>
                    </div>
                    <div class="stat-item">使用: <span id="gpu-memory-used">0</span> MB / <span id="gpu-memory-total">0</span> MB</div>
                </div>
                <div class="info-block">
                    <div class="stat-item">GPU 温度: <span id="gpu-temp">0</span>°C</div>
                    <div class="stat-item">功耗: <span id="gpu-power">0</span> W</div>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-title">系统信息</div>
            <div class="system-info">
                <div class="info-block">
                    <div class="stat-item">CPU 利用率:</div>
                    <div class="meter orange">
                        <span id="cpu-util-meter" style="width: 0%">0%</span>
                    </div>
                </div>
                <div class="info-block">
                    <div class="stat-item">内存:</div>
                    <div class="meter red">
                        <span id="memory-meter" style="width: 0%">0%</span>
                    </div>
                    <div class="stat-item">使用: <span id="memory-used">0</span> GB / <span id="memory-total">0</span> GB</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // 格式化时间（秒转为时:分:秒）
        function formatTime(seconds) {
            seconds = Math.round(seconds);
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            
            const parts = [];
            if (hours > 0) parts.push(hours + '小时');
            if (minutes > 0) parts.push(minutes + '分钟');
            if (secs > 0 || parts.length === 0) parts.push(secs + '秒');
            
            return parts.join(' ');
        }
        
        // 使用EventSource接收服务器发送的事件
        const eventSource = new EventSource('/api/stream');
        
        eventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            // 更新翻译统计信息
            const translationStats = data.translation_stats;
            document.getElementById('processed-texts').textContent = translationStats.processed_texts;
            document.getElementById('total-texts').textContent = translationStats.total_texts;
            document.getElementById('current-batch').textContent = translationStats.current_batch;
            document.getElementById('total-batches').textContent = translationStats.total_batches;
            document.getElementById('avg-time').textContent = translationStats.avg_time_per_text.toFixed(3);
            document.getElementById('total-time').textContent = Math.round(translationStats.total_time);
            
            // 更新进度条
            let progressPercent = 0;
            if (translationStats.total_texts > 0) {
                progressPercent = translationStats.processed_texts / translationStats.total_texts * 100;
            } else if (translationStats.progress_percent) {
                // 如果提供了直接的进度百分比，使用它
                progressPercent = translationStats.progress_percent;
            }
            
            const progressBar = document.getElementById('translation-progress');
            progressBar.style.width = progressPercent.toFixed(1) + '%';
            progressBar.textContent = progressPercent.toFixed(1) + '%';
            document.getElementById('progress-percent').textContent = progressPercent.toFixed(1);
            
            // 更新剩余时间
            if (translationStats.remaining_time !== undefined) {
                document.getElementById('remaining-time').textContent = formatTime(translationStats.remaining_time);
            } else if (translationStats.processed_texts > 0 && translationStats.total_texts > 0) {
                const remaining = (translationStats.total_texts - translationStats.processed_texts) * 
                                  translationStats.avg_time_per_text;
                document.getElementById('remaining-time').textContent = formatTime(remaining);
            }
            
            // 更新当前翻译内容
            const currentTranslation = data.current_translation;
            document.getElementById('current-batch-idx').textContent = currentTranslation.batch_index;
            document.getElementById('current-text-idx').textContent = currentTranslation.text_index;
            document.getElementById('processing-time').textContent = currentTranslation.processing_time.toFixed(3);
            document.getElementById('source-text').textContent = currentTranslation.source_text;
            document.getElementById('translated-text').textContent = currentTranslation.translated_text;
            
            // 更新GPU信息
            const gpuInfo = data.gpu_info;
            if (!gpuInfo.error) {
                document.getElementById('gpu-name').textContent = gpuInfo.name;
                
                const gpuUtilMeter = document.getElementById('gpu-util-meter');
                gpuUtilMeter.style.width = gpuInfo.utilization + '%';
                gpuUtilMeter.textContent = gpuInfo.utilization + '%';
                
                const gpuMemMeter = document.getElementById('gpu-memory-meter');
                gpuMemMeter.style.width = gpuInfo.memory_percent.toFixed(1) + '%';
                gpuMemMeter.textContent = gpuInfo.memory_percent.toFixed(1) + '%';
                
                document.getElementById('gpu-memory-used').textContent = Math.round(gpuInfo.memory_used_mb);
                document.getElementById('gpu-memory-total').textContent = Math.round(gpuInfo.memory_total_mb);
                document.getElementById('gpu-temp').textContent = gpuInfo.temperature;
                document.getElementById('gpu-power').textContent = gpuInfo.power_usage.toFixed(1);
            }
            
            // 更新系统信息
            const sysInfo = data.system_info;
            if (!sysInfo.error) {
                const cpuMeter = document.getElementById('cpu-util-meter');
                cpuMeter.style.width = sysInfo.cpu_percent + '%';
                cpuMeter.textContent = sysInfo.cpu_percent + '%';
                
                const memoryMeter = document.getElementById('memory-meter');
                memoryMeter.style.width = sysInfo.memory_percent + '%';
                memoryMeter.textContent = sysInfo.memory_percent + '%';
                
                document.getElementById('memory-used').textContent = sysInfo.memory_used_gb.toFixed(1);
                document.getElementById('memory-total').textContent = sysInfo.memory_total_gb.toFixed(1);
            }
        };
        
        eventSource.onerror = function(event) {
            console.error('EventSource error:', event);
        };
    </script>
</body>
</html>
    """
    
    # 写入模板文件
    template_path = os.path.join(template_dir, "monitor.html")
    with open(template_path, "w", encoding="utf-8") as f:
        f.write(monitor_html)
    
    return render_template('monitor.html')

@app.route('/api/data')
def get_data():
    """返回当前性能数据"""
    return jsonify(performance_data.get_data())

def event_stream():
    """事件流，用于Server-Sent Events (SSE)"""
    while True:
        # 获取最新数据
        data = performance_data.get_data()
        # 发送数据
        yield f"data: {json.dumps(data)}\n\n"
        time.sleep(0.5)

@app.route('/api/stream')
def stream():
    """SSE流端点"""
    return Response(event_stream(), mimetype="text/event-stream")

# 启动Web服务器的函数
def start_web_monitor(host='127.0.0.1', port=5001, interval=0.5):
    """
    启动Web性能监控服务
    
    Args:
        host: 监听地址
        port: 监听端口
        interval: 性能数据更新间隔（秒）
    """
    # 创建性能日志文件
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"perf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    
    # 启动性能监控线程
    monitor_thread = PerformanceMonitorThread(interval=interval, log_file=log_file)
    monitor_thread.start()
    
    logger.info(f"性能监控Web服务已启动: http://{host}:{port}")
    logger.info(f"性能数据将记录到: {log_file}")
    
    # 启动Flask应用
    app.run(host=host, port=port, debug=False, threaded=True)
    
    return monitor_thread

# 更新翻译统计信息的函数
def update_translation_stats(stats):
    """
    更新翻译统计信息
    
    Args:
        stats: 要更新的统计信息字典
    """
    with performance_data.lock:
        # 保存当前的批次信息，防止被覆盖
        current_batch = performance_data.data["translation_stats"]["current_batch"] 
        total_batches = performance_data.data["translation_stats"]["total_batches"]
        
        # 更新提供的统计信息
        performance_data.data["translation_stats"].update(stats)
        
        # 如果没有指定批次信息，恢复原有的批次信息
        if "current_batch" not in stats:
            performance_data.data["translation_stats"]["current_batch"] = current_batch
        if "total_batches" not in stats:
            performance_data.data["translation_stats"]["total_batches"] = total_batches
        
        # 更新时间戳
        performance_data.data["timestamp"] = time.time()

# 增加更新当前翻译内容的函数
def update_current_translation(source_text, translated_text=None, processing_time=0, batch_index=0, text_index=0):
    """
    更新当前翻译的文本内容
    
    Args:
        source_text: 源文本
        translated_text: 翻译后的文本
        processing_time: 处理时间（秒）
        batch_index: 当前批次索引
        text_index: 当前文本在批次中的索引
    """
    # 如果源文本过长，截断显示
    if source_text and len(source_text) > 300:
        source_text = source_text[:300] + "..."
    
    # 如果翻译文本过长，截断显示
    if translated_text and len(translated_text) > 300:
        translated_text = translated_text[:300] + "..."
    
    performance_data.update("current_translation", {
        "source_text": source_text,
        "translated_text": translated_text or "",
        "processing_time": processing_time,
        "batch_index": batch_index,
        "text_index": text_index
    })

if __name__ == "__main__":
    # 当直接运行该模块时，启动Web监控服务
    logging.basicConfig(level=logging.INFO)
    print("正在启动Web性能监控服务...")
    print("提示: 此模块通常不需要单独运行，而是由vulnerability_data_crawler.py调用")
    print("访问 http://127.0.0.1:5001 查看性能监控页面")
    start_web_monitor() 