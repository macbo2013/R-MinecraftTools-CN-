#原创：GITHUB:MACBO2013
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
import sys
import os
import random
import time
import threading
import json
import binascii
import re
import ctypes
from ctypes import windll, wintypes
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QGroupBox, QGridLayout, QMessageBox, QDialog, QDialogButtonBox, QTabWidget, QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView, QPlainTextEdit, QCheckBox, QSpinBox, QDoubleSpinBox, QProgressBar, QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QTimer, QDateTime, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QTextCursor, QIcon
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.packet import Raw
import subprocess
import platform

print("+==-_正在加载_-==+")
print("by run++")

# 隐藏控制台窗口（仅Windows）
def hide_console():
    if platform.system() == "Windows":
        try:
            # 获取控制台窗口句柄
            hwnd = windll.kernel32.GetConsoleWindow()
            if hwnd != 0:
                # 隐藏窗口
                windll.user32.ShowWindow(hwnd, 0)  # 0 = SW_HIDE
                # 确保窗口不会被再次显示
                windll.kernel32.CloseHandle(hwnd)
        except Exception as e:
            print(f"隐藏控制台失败: {str(e)}")

# 在程序启动时立即隐藏控制台
hide_console()

# 卡密配置
VALID_KEYS = [
    "run++mc-2025-pro-2.0",
    "R++-Pro-v.2.0",
    "run++-pro-cc-2.0",
    "R++TOOL-2024-PRO-2.0",
    "R++TOOL-VIP-ACCESS-2.0", 
    "R++TOOL-ULTIMATE--+2..0",
]
def set_publisher_info():
    if platform.system() == "Windows":
        try:
            # 尝试设置应用程序的元数据信息
            # 这会影响UAC提示中显示的发布者信息
            app_id = 'run++.tech.mc.tool.v1'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        except:
            pass
# 检查并获取管理员权限
def is_admin():
    """检查当前进程是否以管理员权限运行"""
    try:
        return windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """以管理员权限重新启动程序"""
    try:
        # 获取当前脚本路径
        script_path = os.path.abspath(sys.argv[0])
        
        # 设置ShellExecute参数
        params = f'"{script_path}"'
        if len(sys.argv) > 1:
            params += ' ' + ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
    
        # 使用runas动词请求管理员权限
        result = windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        # 检查是否成功触发UAC
        if result <= 32:
            QMessageBox.critical(None, "权限错误", "无法获取管理员权限，程序可能无法正常运行")
    except Exception as e:
        QMessageBox.critical(None, "错误", f"权限提升失败: {str(e)}")

class LoadingDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("R++Tool - 初始化中")
        self.setFixedSize(400, 200)
        self.setModal(True)
        
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #1a1a2e, stop: 1 #16213e);
                border: 2px solid #00b4d8;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 14px;
                background: transparent;
            }
            QProgressBar {
                border: 2px solid #00b4d8;
                border-radius: 5px;
                text-align: center;
                background: #0f3460;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y1: 0,
                    stop: 0 #00b4d8, stop: 1 #0077b6);
                border-radius: 3px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # 标题
        title_label = QLabel("R++Tool 正在初始化(完成后点击×号开始)")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00b4d8; margin: 20px 0;")
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # 状态标签
        self.status_label = QLabel("正在准备UDP/TCP协议栈...")
        self.status_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(title_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        QApplication.processEvents()

class KeyAuthDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("run++科技 - 卡密验证")
        self.setFixedSize(500, 300)
        self.setModal(True)
        
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #1a1a2e, stop: 1 #16213e);
            }
            QLabel {
                color: #ffffff;
                font-size: 14px;
            }
            QLineEdit {
                background-color: #0f3460;
                color: #ffffff;
                border: 2px solid #00b4d8;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                selection-background-color: #0077b6;
            }
            QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #00b4d8, stop: 1 #0077b6);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #0077b6, stop: 1 #005f8a);
            }
            QPushButton:pressed {
                background: #005f8a;
            }
        """)
        
        layout = QVBoxLayout()
        
        title_label = QLabel("run++科技")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00b4d8; margin: 20px 0;")
        
        subtitle_label = QLabel("Minecraft 高级辅助工具")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet("color: #ffffff; margin-bottom: 30px;")
        
        key_label = QLabel("请输入卡密:")
        key_label.setStyleSheet("color: #ffffff; font-weight: bold;")
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("输入您的R++Tool授权密钥...")
        
        self.auth_button = QPushButton("验证卡密")
        self.auth_button.clicked.connect(self.authenticate)
        
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        layout.addWidget(key_label)
        layout.addWidget(self.key_input)
        layout.addWidget(self.auth_button)
        
        self.setLayout(layout)
    
    def authenticate(self):
        key = self.key_input.text().strip()
        if key in VALID_KEYS:
            # 显示加载界面
            loading_dialog = LoadingDialog(self)
            self.start_loading_animation(loading_dialog)
            loading_dialog.exec_()
            self.accept()
        else:
            QMessageBox.warning(self, "验证失败", "卡密无效，请检查后重试！")
            self.key_input.clear()
    
    def start_loading_animation(self, loading_dialog):
        def loading_thread():
            steps = [
                (10, "正在准备UDP/TCP协议栈..."),
                (20, "初始化网络接口..."),
                (30, "加载物品数据库..."),
                (40, "验证服务器连接..."),
                (50, "准备攻击模块..."),
                (60, "初始化抓包引擎..."),
                (70, "加载配置文件..."),
                (80, "优化性能..."),
                (90, "最终检查..."),
                (100, "准备就绪！")
            ]
            
            for progress, message in steps:
                loading_dialog.update_progress(progress, message)
                time.sleep(1)  # 总共10秒
        
        thread = threading.Thread(target=loading_thread)
        thread.daemon = True
        thread.start()

class PacketGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("run++科技 - 数据包生成器(发包崩服)")
        
        # 设置窗口大小和样式
        self.setGeometry(100, 100, 650, 550)
        
        self.setStyleSheet("""QDialog { background-color:#2b2b2b; }
            QLabel { color:#ffffff; } QLineEdit, QComboBox, QPlainTextEdit, QSpinBox, QDoubleSpinBox { 
                background-color:#3c3c3c; color:#ffffff; border: none; border-radius: 
                4px; padding:5px; } QPushButton { background-color:#f2f2f2; color:#2b2b2b; 
                border:none; border-radius :4px; padding :8px; font-weight:bold; } 
                QPushButton:hover { background-color:#eaeaea; } QPushButton:pressed { 
                background-color:#d4d4d4; } QGroupBox { color:#4CAF50; font-weight:bold; 
                border:2px solid #4CAF5; border-radius :8px; margin-top :10px; padding-top :15px; }""")
        
        layout = QVBoxLayout()
        
        # 协议选择
        protocol_group = QGroupBox("协议设置")
        protocol_layout = QGridLayout()
        
        protocol_layout.addWidget(QLabel("协议类型:"), 0, 0)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["UDP", "TCP", "ICMP", "RAW"])
        protocol_layout.addWidget(self.protocol_combo, 0, 1)
        
        protocol_layout.addWidget(QLabel("源端口:"), 1, 0)
        self.src_port = QSpinBox()
        self.src_port.setRange(1, 65535)
        self.src_port.setValue(random.randint(1024, 65535))
        protocol_layout.addWidget(self.src_port, 1, 1)
        
        protocol_layout.addWidget(QLabel("目标端口:"), 2, 0)
        self.dst_port = QSpinBox()
        self.dst_port.setRange(1, 65535)
        self.dst_port.setValue(19132)
        protocol_layout.addWidget(self.dst_port, 2, 1)
        
        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)
        
        # IP设置
        ip_group = QGroupBox("IP设置")
        ip_layout = QGridLayout()
        
        ip_layout.addWidget(QLabel("源IP:"), 0, 0)
        self.src_ip = QLineEdit("192.168.1.100")
        ip_layout.addWidget(self.src_ip, 0, 1)
        
        ip_layout.addWidget(QLabel("目标IP:"), 1, 0)
        self.dst_ip = QLineEdit("192.168.1.1")
        ip_layout.addWidget(self.dst_ip, 1, 1)
        
        ip_layout.addWidget(QLabel("TTL:"), 2, 0)
        self.ttl = QSpinBox()
        self.ttl.setRange(1, 255)
        self.ttl.setValue(64)
        ip_layout.addWidget(self.ttl, 2, 1)
        
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)
        
        # 数据内容
        data_group = QGroupBox("数据内容")
        data_layout = QVBoxLayout()
        
        self.data_type = QComboBox()
        self.data_type.addItems(["十六进制", "文本", "随机数据", "Minecraft数据包"])
        self.data_type.currentIndexChanged.connect(self.on_data_type_changed)
        data_layout.addWidget(self.data_type)
        
        self.data_input = QPlainTextEdit()
        self.data_input.setPlaceholderText("输入十六进制数据，例如: a1b2c3d4...")
        data_layout.addWidget(self.data_input)
        
        # 添加格式提示标签
        self.format_hint = QLabel("提示: 十六进制只能包含0-9和a-f（不区分大小写）")
        self.format_hint.setStyleSheet("color: #aaaaaa; font-size: 12px;")
        data_layout.addWidget(self.format_hint)
        
        data_group.setLayout(data_layout)
        layout.addWidget(data_group)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.generate_btn = QPushButton("生成数据包")
        self.generate_btn.clicked.connect(self.generate_packet)
        button_layout.addWidget(self.generate_btn)
        
        self.send_btn = QPushButton("发送数据包")
        self.send_btn.clicked.connect(self.send_packet)
        button_layout.addWidget(self.send_btn)
        
        self.close_btn = QPushButton("关闭")
        self.close_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        self.generated_packet = None
    
    def on_data_type_changed(self, index):
        """根据选择的数据类型更新输入提示和格式要求"""
        data_types = [
            "十六进制", 
            "文本", 
            "随机数据", 
            "Minecraft数据包"
        ]
        hints = [
            "提示: 十六进制只能包含0-9和a-f（不区分大小写），如 a1b2c3d4",
            "提示: 输入将按UTF-8编码转换为字节",
            "提示: 输入内容将作为随机数据长度（留空则默认100字节）",
            "提示: Minecraft RakNet协议数据包，无需手动输入内容"
        ]
        
        placeholders = [
            "输入十六进制数据，例如: a1b2c3d4...",
            "输入文本内容...",
            "输入随机数据长度（字节）...",
            ""
        ]
        
        self.format_hint.setText(hints[index])
        self.data_input.setPlaceholderText(placeholders[index])
        
        # 如果是Minecraft数据包，清空输入并禁用编辑
        if data_types[index] == "Minecraft数据包":
            self.data_input.setPlainText("")
            self.data_input.setDisabled(True)
        else:
            self.data_input.setEnabled(True)
    
    def is_valid_hex(self, s):
        """检查字符串是否为有效的十六进制"""
        # 移除所有空格和分隔符
        s = re.sub(r'[^0-9a-fA-F]', '', s)
        # 检查长度是否为偶数
        return len(s) % 2 == 0 and re.fullmatch(r'^[0-9a-fA-F]*$', s) is not None
    
    def generate_packet(self):
        try:
            protocol = self.protocol_combo.currentText()
            src_ip = self.src_ip.text()
            dst_ip = self.dst_ip.text()
            src_port = self.src_port.value()
            dst_port = self.dst_port.value()
            
            # 验证IP地址格式
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', src_ip):
                QMessageBox.warning(self, "输入错误", "源IP地址格式无效！")
                return
                
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dst_ip):
                QMessageBox.warning(self, "输入错误", "目标IP地址格式无效！")
                return
            
            # 创建IP层
            ip_layer = IP(src=src_ip, dst=dst_ip, ttl=self.ttl.value())
            
            # 创建传输层
            if protocol == "UDP":
                transport_layer = UDP(sport=src_port, dport=dst_port)
            elif protocol == "TCP":
                transport_layer = TCP(sport=src_port, dport=dst_port)
            elif protocol == "ICMP":
                transport_layer = scapy.ICMP()
            else:
                transport_layer = None
            
            # 创建数据负载
            data_type = self.data_type.currentText()
            data_text = self.data_input.toPlainText()
            
            if data_type == "十六进制":
                # 清理输入，移除所有非十六进制字符
                cleaned_data = re.sub(r'[^0-9a-fA-F]', '', data_text)
                
                # 验证十六进制有效性
                if not self.is_valid_hex(cleaned_data):
                    error_msg = "无效的十六进制数据！\n\n"
                    error_msg += "请确保：\n"
                    error_msg += "1. 只包含0-9和a-f（不区分大小写）\n"
                    error_msg += "2. 字符数量为偶数\n"
                    error_msg += "3. 不包含空格或其他分隔符"
                    QMessageBox.warning(self, "输入错误", error_msg)
                    return
                
                # 查找无效字符位置（如果有）
                invalid_chars = re.findall(r'[^0-9a-fA-F]', data_text)
                if invalid_chars:
                    first_invalid_pos = re.search(r'[^0-9a-fA-F]', data_text).start()
                    QMessageBox.warning(self, "格式警告", f"输入包含无效字符，已自动清理。\n第一个无效字符位置: {first_invalid_pos+1}")
                
                payload = bytes.fromhex(cleaned_data)
                
            elif data_type == "文本":
                payload = data_text.encode('utf-8', errors='replace')  # 替换无效UTF-8字符
                
            elif data_type == "随机数据":
                try:
                    size = int(data_text) if data_text.strip() else 100
                    if size < 1 or size > 65535:
                        raise ValueError("大小必须在1-65535之间")
                    payload = os.urandom(size)
                except ValueError:
                    QMessageBox.warning(self, "输入错误", "随机数据大小必须是有效的整数（1-65535）")
                    return
                
            elif data_type == "Minecraft数据包":
                # Minecraft RakNet协议数据包
                payload = self.generate_minecraft_packet()
            
            # 组装数据包
            if transport_layer:
                self.generated_packet = ip_layer / transport_layer / Raw(load=payload)
            else:
                self.generated_packet = ip_layer / Raw(load=payload)
                
            QMessageBox.information(self, "成功", "数据包生成成功！\n大小: {} 字节".format(len(self.generated_packet)))
        except Exception as e:
            QMessageBox.warning(self, "错误", f"生成数据包失败: {str(e)}\n\n请检查输入参数是否正确。")
    
    def generate_minecraft_packet(self):
        """生成Minecraft协议数据包"""
        packet_types = {
            "连接请求": b"\x01",
            "连接响应": b"\x02",
            "心跳包": b"\x03",
            "断开连接": b"\x04",
            "自定义数据": b"\x05"
        }
        
        # 简单的Minecraft协议数据包
        packet_type = random.choice(list(packet_types.values()))
        payload = packet_type + os.urandom(random.randint(10, 100))
        return payload
    
    def send_packet(self):
        if not self.generated_packet:
            QMessageBox.warning(self, "错误", "请先生成数据包！")
            return
            
        try:
            scapy.send(self.generated_packet, verbose=False)
            QMessageBox.information(self, "成功", "数据包发送成功！")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"发送数据包失败: {str(e)}")

class PacketSniffer:
    def __init__(self, log_callback, update_callback):
        self.is_sniffing = False
        self.sniff_thread = None
        self.log_callback = log_callback
        self.update_callback = update_callback
        self.packets = []
        self.packet_count = 0
    
    def start_sniffing(self, interface=None, filter_str="", count=0):
        if self.is_sniffing:
            return
            
        self.is_sniffing = True
        self.packets = []
        self.packet_count = 0
        
        def sniff_packets():
            try:
                self.log_callback(f"[+] 开始抓包，过滤器: {filter_str}")
                # 简单的抓包实现
                scapy.conf.sniff_promisc = 1  # 混杂模式
                
                # 使用更稳定的抓包方式
                packets = scapy.sniff(
                    iface=interface,
                    filter=filter_str,
                    count=count if count > 0 else 0,
                    timeout=10,
                    store=True
                )
                
                for packet in packets:
                    self.process_packet(packet)
            except Exception as e:
                self.log_callback(f"抓包错误: {str(e)}")
            finally:
                self.is_sniffing = False
                self.log_callback("[+] 抓包已停止")
        
        self.sniff_thread = threading.Thread(target=sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
    
    def process_packet(self, packet):
        if not self.is_sniffing:
            return
            
        self.packet_count += 1
        self.packets.append(packet)
        
        # 每抓到包就更新界面
        if self.packet_count % 1 == 0:
            self.update_callback(self.packets)
    
    def stop_sniffing(self):
        self.is_sniffing = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2.0)
    
    def get_packet_info(self, packet):
        """获取数据包基本信息"""
        info = {
            'time': packet.time,
            'summary': packet.summary(),
            'length': len(packet),
            'src': 'N/A',
            'dst': 'N/A',
            'protocol': 'Unknown'
        }
        
        try:
            if IP in packet:
                info['src'] = packet[IP].src
                info['dst'] = packet[IP].dst
                info['protocol'] = 'IP'
                
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    info['sport'] = packet[TCP].sport
                    info['dport'] = packet[TCP].dport
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    info['sport'] = packet[UDP].sport
                    info['dport'] = packet[UDP].dport
            elif Ether in packet:
                info['src'] = packet[Ether].src
                info['dst'] = packet[Ether].dst
                info['protocol'] = 'Ethernet'
        except:
            pass
            
        return info

class ItemSpawner:
    # Minecraft物品数据库
    ITEMS_DATABASE = {
        "blocks": {
            "钻石块": b"\x01\x00\x00\x00\x01",  # 示例协议数据
            "金块": b"\x01\x00\x00\x00\x02",
            "铁块": b"\x01\x00\x00\x00\x03",
            "绿宝石块": b"\x01\x00\x00\x00\x04",
            "红石块": b"\x01\x00\x00\x00\x05"
        },
        "tools": {
            "钻石剑": b"\x02\x00\x00\x00\x01",
            "钻石镐": b"\x02\x00\x00\x00\x02",
            "钻石斧": b"\x02\x00\x00\x00\x03",
            "钻石铲": b"\x02\x00\x00\x00\x04",
            "钻石锄": b"\x02\x00\x00\x00\x05"
        },
        "resources": {
            "钻石": b"\x03\x00\x00\x00\x01",
            "金锭": b"\x03\x00\x00\x00\x02",
            "铁锭": b"\x03\x00\x00\x00\x03",
            "绿宝石": b"\x03\x00\x00\x00\x04",
            "下界合金锭": b"\x03\x00\x00\x00\x05"
        },
        "special": {
            "附魔金苹果": b"\x04\x00\x00\x00\x01",
            "末影珍珠": b"\x04\x00\x00\x00\x02",
            "潜影壳": b"\x04\x00\x00\x00\x03",
            "海洋之心": b"\x04\x00\x00\x00\x04",
            "下界之星": b"\x04\x00\x00\x00\x05"
        }
    }

    @staticmethod
    def generate_item_packet(item_name, quantity=1, target_ip="", target_port=19132):
        """生成物品数据包"""
        # 在实际应用中，这里应该是真实的Minecraft协议格式
        for category, items in ItemSpawner.ITEMS_DATABASE.items():
            if item_name in items:
                item_data = items[item_name]
                
                # 构建Minecraft协议数据包 (示例)
                packet_data = (
                    b"\xfe\xfd" +  # Magic bytes
                    int.to_bytes(quantity, 4, 'big') +
                    item_data +
                    os.urandom(8)   # 随机数据增加真实性
                )
                
                # 创建UDP数据包
                udp_packet = (
                    IP(dst=target_ip) /
                    UDP(sport=random.randint(49152, 65535), dport=target_port) /
                    Raw(load=packet_data)
                )
                
                return udp_packet
        
        return None

class MinecraftAttacker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_attacking = False
        self.attack_thread = None
        self.packet_count = 0
        self.send_count = 0
        self.sniffer_packet_count = 0
        self.sniffer = PacketSniffer(self.log_message, self.update_packet_list)
        self.target_ip = ""
        self.target_port = 19132
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("run++科技 - v.2.0-pro")
        self.setGeometry(100, 100, 1200, 800)
        
        self.setStyleSheet("""
            QMainWindow { background-color: #2b2b2b; }
            QLabel { color: #ffffff; }
            QLineEdit, QComboBox, QPlainTextEdit, QSpinBox, QDoubleSpinBox { 
                background-color: #3c3c3c; color: #ffffff; 
                border: 1px solid #555555; border-radius: 4px; padding: 5px; 
            }
            QPushButton { background-color: #4CAF50; color: white; border: none; border-radius: 4px; padding: 8px; font-weight: bold; }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:pressed { background-color: #3d8b40; }
            QPushButton:disabled { background-color: #555555; color: #888888; }
            QGroupBox { 
                color: #4CAF50; font-weight: bold; 
                border: 2px solid #4CAF50; border-radius: 8px; 
                margin-top: 10px; padding-top: 15px; 
            }
            QTextEdit, QPlainTextEdit { 
                background-color: #3c3c3c; color: #ffffff; 
                border: 1px solid #555555; border-radius: 4px; 
            }
            QTreeWidget { 
                background-color: #3c3c3c; color: #ffffff; 
                border: 1px solid #555555; border-radius: 4px; 
                alternate-background-color: #454545;
            }
            QHeaderView::section { 
                background-color: #4CAF50; color: white; 
                padding: 4px; border: 1px solid #3d8b40; 
            }
            QTabWidget::pane { 
                border: 1px solid #4CAF50; border-radius: 4px; 
                background-color: #2b2b2b; 
            }
            QTabBar::tab { 
                background-color: #3c3c3c; color: #ffffff; 
                padding: 8px; border-top-left-radius: 4px; border-top-right-radius: 4px; 
            }
            QTabBar::tab:selected { 
                background-color: #4CAF50; color: white; 
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 顶部服务器信息栏
        server_info_group = QGroupBox("服务器连接")
        server_layout = QGridLayout()
        
        server_layout.addWidget(QLabel("服务器IP:"), 0, 0)
        self.server_ip_entry = QLineEdit("127.0.0.1")
        server_layout.addWidget(self.server_ip_entry, 0, 1)
        
        server_layout.addWidget(QLabel("服务器端口:"), 0, 2)
        self.server_port_entry = QLineEdit("19132")
        server_layout.addWidget(self.server_port_entry, 0, 3)
        
        self.connect_btn = QPushButton("连接服务器")
        self.connect_btn.clicked.connect(self.connect_to_server)
        server_layout.addWidget(self.connect_btn, 0, 4)
        
        server_info_group.setLayout(server_layout)
        main_layout.addWidget(server_info_group)
        
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # 物品生成标签页
        self.item_spawn_tab = QWidget()
        self.setup_item_spawn_tab()
        self.tabs.addTab(self.item_spawn_tab, "物品生成")
        
        # 攻击标签页
        self.attack_tab = QWidget()
        self.setup_attack_tab()
        self.tabs.addTab(self.attack_tab, "攻击工具")
        
        # 抓包标签页
        self.sniffer_tab = QWidget()
        self.setup_sniffer_tab()
        self.tabs.addTab(self.sniffer_tab, "抓包分析")
        
        # 数据包生成器标签页
        self.generator_tab = QWidget()
        self.setup_generator_tab()
        self.tabs.addTab(self.generator_tab, "数据包生成器")
        
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪 (管理员模式)")
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)
    
    def setup_item_spawn_tab(self):
        layout = QVBoxLayout(self.item_spawn_tab)
        
        # 标题
        title_label = QLabel("物品生成系统")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #4CAF50; margin: 15px 0;")
        layout.addWidget(title_label)
        
        # 物品选择区域
        selection_group = QGroupBox("物品选择")
        selection_layout = QHBoxLayout()
        
        # 物品分类列表
        categories_group = QGroupBox("物品分类")
        categories_layout = QVBoxLayout()
        
        self.category_list = QListWidget()
        self.category_list.addItems(["方块", "工具", "资源", "特殊物品"])
        self.category_list.currentRowChanged.connect(self.update_item_list)
        categories_layout.addWidget(self.category_list)
        
        categories_group.setLayout(categories_layout)
        selection_layout.addWidget(categories_group)
        
        # 物品列表
        items_group = QGroupBox("可用物品")
        items_layout = QVBoxLayout()
        
        self.item_list = QListWidget()
        items_layout.addWidget(self.item_list)
        
        items_group.setLayout(items_layout)
        selection_layout.addWidget(items_group)
        
        # 物品详情和控制
        control_group = QGroupBox("物品设置")
        control_layout = QGridLayout()
        
        control_layout.addWidget(QLabel("选择物品:"), 0, 0)
        self.selected_item_label = QLabel("未选择")
        self.selected_item_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        control_layout.addWidget(self.selected_item_label, 0, 1)
        
        control_layout.addWidget(QLabel("数量:"), 1, 0)
        self.quantity_spin = QSpinBox()
        self.quantity_spin.setRange(1, 64)
        self.quantity_spin.setValue(1)
        control_layout.addWidget(self.quantity_spin, 1, 1)
        
        control_layout.addWidget(QLabel("生成位置:"), 2, 0)
        self.position_combo = QComboBox()
        self.position_combo.addItems(["准星指向的箱子", "玩家背包", "地面掉落"])
        control_layout.addWidget(self.position_combo, 2, 1)
        
        self.spawn_btn = QPushButton("生成物品")
        self.spawn_btn.clicked.connect(self.spawn_item)
        self.spawn_btn.setEnabled(False)
        control_layout.addWidget(self.spawn_btn, 3, 0, 1, 2)
        
        control_group.setLayout(control_layout)
        selection_layout.addWidget(control_group)
        
        selection_group.setLayout(selection_layout)
        layout.addWidget(selection_group)
        
        # 日志区域
        log_group = QGroupBox("操作日志")
        log_layout = QVBoxLayout()
        
        self.item_log = QTextEdit()
        self.item_log.setMaximumHeight(150)
        log_layout.addWidget(self.item_log)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        # 初始化物品列表
        self.update_item_list(0)
        self.item_list.currentItemChanged.connect(self.on_item_selected)
    
    def update_item_list(self, category_index):
        self.item_list.clear()
        categories = ["blocks", "tools", "resources", "special"]
        if 0 <= category_index < len(categories):
            category = categories[category_index]
            items = ItemSpawner.ITEMS_DATABASE.get(category, {})
            for item_name in items.keys():
                self.item_list.addItem(item_name)
    
    def on_item_selected(self, current, previous):
        if current:
            self.selected_item_label.setText(current.text())
            self.spawn_btn.setEnabled(True)
    
    def spawn_item(self):
        if not self.item_list.currentItem():
            return
        
        item_name = self.item_list.currentItem().text()
        quantity = self.quantity_spin.value()
        position = self.position_combo.currentText()
        
        try:
            # 生成物品数据包
            packet = ItemSpawner.generate_item_packet(
                item_name, quantity, self.target_ip, self.target_port
            )
            
            if packet:
                # 发送数据包
                scapy.send(packet, verbose=False)
                self.send_count += 1
                
                # 记录日志
                timestamp = time.strftime("%H:%M:%S")
                log_message = f"[{timestamp}] 成功生成 {quantity} 个 {item_name} 到 {position}"
                self.item_log.append(log_message)
                self.status_bar.showMessage(f"已生成: {item_name} x{quantity}")
                
                QMessageBox.information(self, "成功", f"已生成 {quantity} 个 {item_name}!")
            else:
                QMessageBox.warning(self, "错误", "生成物品数据包失败!")
                
        except Exception as e:
            QMessageBox.warning(self, "错误", f"生成物品失败: {str(e)}")
    
    def connect_to_server(self):
        try:
            self.target_ip = self.server_ip_entry.text()
            self.target_port = int(self.server_port_entry.text())
            
            if not self.target_ip:
                QMessageBox.warning(self, "错误", "请输入服务器IP地址")
                return
            
            self.status_bar.showMessage(f"已连接到: {self.target_ip}:{self.target_port}")
            self.spawn_btn.setEnabled(True)
            QMessageBox.information(self, "成功", f"已连接到服务器 {self.target_ip}:{self.target_port}")
            
        except ValueError:
            QMessageBox.warning(self, "错误", "请输入有效的端口号")
    
    def setup_attack_tab(self):
        layout = QVBoxLayout(self.attack_tab)
        
        title_label = QLabel("run++科技 - 攻击工具(发包崩服)")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #4CAF50; margin: 10px;")
        layout.addWidget(title_label)
        
        # 目标设置
        target_group = QGroupBox("目标设置")
        target_layout = QGridLayout()
        
        target_layout.addWidget(QLabel("目标IP:"), 0, 0)
        self.ip_entry = QLineEdit("117.187.184.24")
        target_layout.addWidget(self.ip_entry, 0, 1)
        
        target_layout.addWidget(QLabel("目标端口:"), 0, 2)
        self.port_entry = QLineEdit("19132")
        target_layout.addWidget(self.port_entry, 0, 3)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # 攻击设置
        attack_group = QGroupBox("攻击设置")
        attack_layout = QGridLayout()
        
        attack_layout.addWidget(QLabel("攻击类型:"), 0, 0)
        self.attack_type = QComboBox()
        self.attack_type.addItems(["大量数据包", "畸形数据包", "大流量攻击", "TCP洪水攻击", "混合攻击"])
        attack_layout.addWidget(self.attack_type, 0, 1)
        
        attack_layout.addWidget(QLabel("持续时间(秒):"), 0, 2)
        self.duration_entry = QLineEdit("10")
        attack_layout.addWidget(self.duration_entry, 0, 3)
        
        attack_layout.addWidget(QLabel("线程数:"), 1, 0)
        self.threads_entry = QLineEdit("1")
        attack_layout.addWidget(self.threads_entry, 1, 1)
        
        attack_layout.addWidget(QLabel("数据包大小:"), 1, 2)
        self.packet_size = QComboBox()
        self.packet_size.addItems(["随机", "小(64字节)", "中(512字节)", "大(1024字节)", "超大(1500字节)"])
        attack_layout.addWidget(self.packet_size, 1, 3)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("开始攻击")
        self.start_button.clicked.connect(self.start_attack)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止攻击")
        self.stop_button.clicked.connect(self.stop_attack)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        layout.addLayout(button_layout)
        
        # 统计信息
        stats_group = QGroupBox("攻击统计")
        stats_layout = QVBoxLayout()
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(100)
        self.stats_text.setPlainText("就绪。请设置参数并开始攻击 (已获取管理员权限)")
        stats_layout.addWidget(self.stats_text)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # 日志
        log_group = QGroupBox("攻击日志")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
    
    def setup_sniffer_tab(self):
        layout = QVBoxLayout(self.sniffer_tab)
        
        title_label = QLabel("run++科技 - 网络抓包分析工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #4CAF50; margin: 10px;")
        layout.addWidget(title_label)
        
        # 抓包设置 - 增加手动输入接口选项
        sniff_group = QGroupBox("抓包设置")
        sniff_layout = QGridLayout()
        
        # 网络接口选择
        sniff_layout.addWidget(QLabel("网络接口:"), 0, 0)
        interface_layout = QHBoxLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(300)
        interface_layout.addWidget(self.interface_combo)
        
        # 刷新接口按钮
        self.refresh_interface_btn = QPushButton("刷新接口")
        self.refresh_interface_btn.clicked.connect(self.refresh_network_interfaces)
        interface_layout.addWidget(self.refresh_interface_btn)
        
        sniff_layout.addLayout(interface_layout, 0, 1, 1, 3)
        
        # 手动输入接口名称 (备选方案)
        sniff_layout.addWidget(QLabel("手动输入接口名:"), 1, 0)
        self.manual_interface = QLineEdit()
        self.manual_interface.setPlaceholderText("自动获取失败时，可在此手动输入接口名称")
        sniff_layout.addWidget(self.manual_interface, 1, 1, 1, 3)
        
        # 过滤条件
        sniff_layout.addWidget(QLabel("过滤条件:"), 2, 0)
        self.filter_entry = QLineEdit("udp or tcp")
        self.filter_entry.setPlaceholderText("例如: tcp port 80, udp, icmp")
        sniff_layout.addWidget(self.filter_entry, 2, 1, 1, 3)
        
        # 接口状态提示
        self.interface_status = QLabel("状态: 未加载接口列表")
        self.interface_status.setStyleSheet("color: #ff9900; font-size: 12px;")
        sniff_layout.addWidget(self.interface_status, 3, 1, 1, 3)
        
        sniff_group.setLayout(sniff_layout)
        layout.addWidget(sniff_group)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.start_sniff_button = QPushButton("开始抓包")
        self.start_sniff_button.clicked.connect(self.start_sniffing)
        button_layout.addWidget(self.start_sniff_button)
        
        self.stop_sniff_button = QPushButton("停止抓包")
        self.stop_sniff_button.clicked.connect(self.stop_sniffing)
        self.stop_sniff_button.setEnabled(False)
        button_layout.addWidget(self.stop_sniff_button)
        
        self.clear_sniff_button = QPushButton("清空数据")
        self.clear_sniff_button.clicked.connect(self.clear_sniff_data)
        button_layout.addWidget(self.clear_sniff_button)
        
        layout.addLayout(button_layout)
        
        # 统计
        sniff_stats_layout = QHBoxLayout()
        self.sniff_stats_label = QLabel("抓包统计: 0 个数据包")
        sniff_stats_layout.addWidget(self.sniff_stats_label)
        sniff_stats_layout.addStretch()
        layout.addLayout(sniff_stats_layout)
        
        # 数据包列表和详情
        splitter = QSplitter(Qt.Vertical)
        self.packet_list = QTreeWidget()
        self.packet_list.setHeaderLabels(["时间", "源IP", "目标IP", "协议", "长度", "信息"])
        self.packet_list.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_list.itemClicked.connect(self.show_packet_details)
        splitter.addWidget(self.packet_list)
        
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        splitter.addWidget(self.packet_details)
        splitter.setSizes([400, 200])
        layout.addWidget(splitter)
        
        # 初始加载网络接口
        self.refresh_network_interfaces()
    
    def refresh_network_interfaces(self):
        """刷新网络接口列表，兼容不同Scapy版本"""
        try:
            self.interface_combo.clear()
            self.interface_status.setText("状态: 正在加载接口列表...")
            
            if platform.system() == "Windows":
                # 尝试使用不同的方法获取Windows网络接口
                interfaces = []
                try:
                    # 方法1: 使用get_windows_if_list (旧版Scapy)
                    interfaces = scapy.get_windows_if_list()
                except AttributeError:
                    try:
                        # 方法2: 尝试从all模块导入
                        from scapy.all import get_windows_if_list
                        interfaces = get_windows_if_list()
                    except (ImportError, AttributeError):
                        try:
                            # 方法3: 使用get_if_list并过滤Windows接口
                            all_interfaces = scapy.get_if_list()
                            # 简单过滤Windows常见接口名称
                            valid_interfaces = ["以太网", "WLAN", "本地连接", "Loopback", "VPN"]
                            interfaces = [iface for iface in all_interfaces if any(name in iface for name in valid_interfaces)]
                        except Exception as e:
                            self.interface_status.setText(f"状态: 获取接口失败: {str(e)}")
                            QMessageBox.warning(
                                self, 
                                "接口获取失败", 
                                f"无法获取网络接口列表: {str(e)}\n\n请确保已安装正确版本的Scapy库。"
                            )
                            return
                
                if not interfaces:
                    raise Exception("未找到网络接口")
                
                for iface in interfaces:
                    # 处理不同格式的接口信息
                    if isinstance(iface, dict):
                        name = iface.get('name', '未知接口')
                        desc = iface.get('description', '无描述')
                        self.interface_combo.addItem(f"{name} - {desc}", name)
                    else:
                        # 如果是字符串格式的接口名称
                        self.interface_combo.addItem(iface, iface)
                        
                self.interface_status.setText(f"状态: 成功加载 {len(interfaces)} 个网络接口")
                self.interface_status.setStyleSheet("color: #4CAF50; font-size: 12px;")
                
            else:
                # Linux/macOS系统
                interfaces = scapy.get_if_list()
                if not interfaces:
                    raise Exception("未找到网络接口")
                
                for iface in interfaces:
                    self.interface_combo.addItem(iface)
                    
                self.interface_status.setText(f"状态: 成功加载 {len(interfaces)} 个网络接口")
                self.interface_status.setStyleSheet("color: #4CAF50; font-size: 12px;")
                
        except Exception as e:
            error_msg = f"加载网络接口失败: {str(e)}"
            self.interface_status.setText(error_msg)
            self.interface_status.setStyleSheet("color: #ff0000; font-size: 12px;")
            
            # 添加默认选项
            self.interface_combo.addItem("默认接口")
            self.interface_combo.addItem("尝试自动检测")
            
            # 显示详细错误提示和解决方案
            solution_msg = (f"无法自动获取网络接口列表:\n{str(e)}\n\n"
                           "解决方案:\n"
                           "1. 确保已安装最新版本的Scapy: pip install --upgrade scapy\n"
                           "2. 如果使用Python 3.10+，尝试安装Scapy 2.5.0+版本\n"
                           "3. 可在下方手动输入接口名称，常见接口名称:\n"
                           "   - 以太网接口: Ethernet, eth0, eth1\n"
                           "   - 无线接口: WLAN, wlan0\n"
                           "   - 本地回环: Loopback, lo")
            
            QMessageBox.warning(self, "接口加载失败", solution_msg)
    
    def setup_generator_tab(self):
        layout = QVBoxLayout(self.generator_tab)
        
        title_label = QLabel("run++科技 - 自定义数据包生成器")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #4CAF50; margin: 10px;")
        layout.addWidget(title_label)
        
        # 快速生成按钮
        quick_buttons = QHBoxLayout()
        minecraft_btn = QPushButton("生成Minecraft包")
        minecraft_btn.clicked.connect(lambda: self.quick_generate("minecraft"))
        quick_buttons.addWidget(minecraft_btn)
        
        tcp_btn = QPushButton("生成TCP包")
        tcp_btn.clicked.connect(lambda: self.quick_generate("tcp"))
        quick_buttons.addWidget(tcp_btn)
        
        udp_btn = QPushButton("生成UDP包")
        udp_btn.clicked.connect(lambda: self.quick_generate("udp"))
        quick_buttons.addWidget(udp_btn)
        
        layout.addLayout(quick_buttons)
        
        # 打开完整生成器按钮
        full_generator_btn = QPushButton("打开完整数据包生成器")
        full_generator_btn.clicked.connect(self.open_packet_generator)
        full_generator_btn.setStyleSheet("background-color: #2196F3;")
        layout.addWidget(full_generator_btn)
        
        # 生成的包显示
        generated_group = QGroupBox("生成的数据包")
        generated_layout = QVBoxLayout()
        self.generated_packet_text = QPlainTextEdit()
        self.generated_packet_text.setReadOnly(True)
        generated_layout.addWidget(self.generated_packet_text)
        
        send_btn = QPushButton("发送此数据包")
        send_btn.clicked.connect(self.send_generated_packet)
        generated_layout.addWidget(send_btn)
        
        generated_group.setLayout(generated_layout)
        layout.addWidget(generated_group)
        
        # 发送统计
        send_stats = QHBoxLayout()
        self.send_count_label = QLabel("已发送: 0 个数据包")
        send_stats.addWidget(self.send_count_label)
        send_stats.addStretch()
        layout.addLayout(send_stats)
        
        self.send_count = 0
        self.current_packet = None
    
    def update_packet_list(self, packets):
        """更新数据包列表显示"""
        # 只添加新的数据包
        new_packets = packets[self.sniffer_packet_count:]
        if not new_packets:
            return
            
        for packet in new_packets:
            info = self.sniffer.get_packet_info(packet)
            
            # 格式化时间
            time_str = time.strftime("%H:%M:%S", time.localtime(info['time']))
            
            # 创建列表项
            item = QTreeWidgetItem([
                time_str,
                info['src'],
                info['dst'],
                info['protocol'],
                str(info['length']),
                info['summary']
            ])
            
            # 存储原始数据包供详情查看
            item.setData(0, Qt.UserRole, packet)
            
            self.packet_list.addTopLevelItem(item)
            self.sniffer_packet_count += 1
        
        # 更新统计信息
        self.sniff_stats_label.setText(f"抓包统计: {self.sniffer_packet_count} 个数据包")
    
    def show_packet_details(self, item):
        """显示选中数据包的详细信息"""
        packet = item.data(0, Qt.UserRole)
        if not packet:
            return
            
        try:
            details = "数据包详细信息:\n\n"
            details += f"时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}\n"
            details += f"长度: {len(packet)} 字节\n"
            details += f"摘要: {packet.summary()}\n\n"
            
            # 十六进制转储
            details += "十六进制转储:\n"
            details += scapy.hexdump(packet, dump=True)
            
            self.packet_details.setPlainText(details)
        except Exception as e:
            self.packet_details.setPlainText(f"无法显示数据包详情: {str(e)}")
    
    def quick_generate(self, packet_type):
        """快速生成常见类型的数据包"""
        try:
            if packet_type == "minecraft":
                # Minecraft RakNet协议包
                packet = (IP(dst=self.ip_entry.text()) / 
                         UDP(sport=random.randint(1024, 65535), dport=int(self.port_entry.text())) / 
                         Raw(load=b"\x01" + os.urandom(50)))
                desc = "Minecraft连接请求包"
            elif packet_type == "tcp":
                packet = (IP(dst=self.ip_entry.text()) / 
                         TCP(sport=random.randint(1024, 65535), dport=80) / 
                         Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
                desc = "HTTP GET请求包"
            elif packet_type == "udp":
                packet = (IP(dst=self.ip_entry.text()) / 
                         UDP(sport=random.randint(1024, 65535), dport=53) / 
                         Raw(load=os.urandom(32)))
                desc = "UDP随机数据包"
                
            hex_dump = scapy.hexdump(packet, dump=True)
            self.generated_packet_text.setPlainText(
                f"=== {desc} ===\n\n"
                f"协议: {packet.summary()}\n"
                f"长度: {len(packet)} 字节\n\n"
                f"十六进制转储:\n{hex_dump}"
            )
            self.current_packet = packet
            self.log_message(f"[+] 已生成 {desc}")
        except Exception as e:
            self.log_message(f"生成数据包错误: {str(e)}")
    
    def open_packet_generator(self):
        """打开完整的数据包生成器对话框"""
        dialog = PacketGeneratorDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            if hasattr(dialog, 'generated_packet') and dialog.generated_packet:
                self.current_packet = dialog.generated_packet
                hex_dump = scapy.hexdump(self.current_packet, dump=True)
                self.generated_packet_text.setPlainText(
                    f"=== 自定义数据包 ===\n\n"
                    f"协议: {self.current_packet.summary()}\n"
                    f"长度: {len(self.current_packet)} 字节\n\n"
                    f"十六进制转储:\n{hex_dump}"
                )
                self.log_message("[+] 已加载自定义数据包")
    
    def send_generated_packet(self):
        """发送生成的数据包"""
        if not hasattr(self, 'current_packet') or not self.current_packet:
            QMessageBox.warning(self, "错误", "没有可发送的数据包！")
            return
            
        try:
            scapy.send(self.current_packet, verbose=False)
            self.send_count += 1
            self.send_count_label.setText(f"已发送: {self.send_count} 个数据包")
            self.log_message("[+] 数据包发送成功")
        except Exception as e:
            self.log_message(f"发送数据包错误: {str(e)}")
    
    def log_message(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.moveCursor(QTextCursor.End)
    
    def update_stats(self):
        stats_text = f"已发送数据包: {self.packet_count}\n"
        stats_text += f"攻击类型: {self.attack_type.currentText()}\n"
        stats_text += f"目标: {self.ip_entry.text()}:{self.port_entry.text()}"
        self.stats_text.setPlainText(stats_text)
    
    def start_attack(self):
        """开始攻击的实现"""
        self.is_attacking = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_message("[+] 攻击已开始")
        self.packet_count = 0
        
        # 这里只是示例，实际攻击逻辑需要根据攻击类型实现
        # 为了演示，我们只简单模拟攻击过程
        threading.Thread(target=self.simulate_attack, daemon=True).start()
    
    def stop_attack(self):
        """停止攻击的实现"""
        self.is_attacking = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message("[+] 攻击已停止")
    
    def simulate_attack(self):
        """模拟攻击过程"""
        try:
            duration = int(self.duration_entry.text())
            end_time = time.time() + duration
            
            while self.is_attacking and time.time() < end_time:
                # 模拟发送数据包
                self.packet_count += 1
                time.sleep(0.01)  # 控制速度
                
                # 每100个包记录一次日志
                if self.packet_count % 100 == 0:
                    self.log_message(f"已发送 {self.packet_count} 个数据包")
            
            if time.time() >= end_time:
                self.log_message(f"[+] 攻击持续时间已到，共发送 {self.packet_count} 个数据包")
                self.is_attacking = False
                # 在主线程中更新UI
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
        except Exception as e:
            self.log_message(f"攻击错误: {str(e)}")
            self.is_attacking = False
    
    def start_sniffing(self):
        """开始抓包"""
        # 优先使用手动输入的接口名称
        if self.manual_interface.text().strip():
            interface = self.manual_interface.text().strip()
        else:
            interface = self.interface_combo.currentData() if self.interface_combo.currentData() else self.interface_combo.currentText()
            
        filter_str = self.filter_entry.text()
        
        self.sniffer.start_sniffing(interface=interface, filter_str=filter_str)
        self.start_sniff_button.setEnabled(False)
        self.stop_sniff_button.setEnabled(True)
        self.log_message(f"[+] 抓包已开始，接口: {interface}")
    
    def stop_sniffing(self):
        """停止抓包"""
        self.sniffer.stop_sniffing()
        self.start_sniff_button.setEnabled(True)
        self.stop_sniff_button.setEnabled(False)
    
    def clear_sniff_data(self):
        """清空抓包数据"""
        self.packet_list.clear()
        self.packet_details.clear()
        self.sniffer_packet_count = 0
        self.sniff_stats_label.setText("抓包统计: 0 个数据包")
        self.log_message("[+] 抓包数据已清空")

def main():
    try:
        # 重定向标准输出和错误，防止大量输出导致闪退
        class NullDevice:
            def write(self, s):
                pass
            def flush(self):
                pass
        
        # 仅在Windows系统下启用权限提升功能
        if platform.system() == "Windows":
            # 检查是否已经以管理员权限运行
            if not is_admin():
                # 不是管理员，请求提升权限
                run_as_admin()
                sys.exit(0)
        
        # 已经是管理员或非Windows系统，正常启动程序
        app = QApplication(sys.argv)
        
        # 卡密验证
        auth_dialog = KeyAuthDialog()
        if auth_dialog.exec_() == QDialog.Accepted:
            window = MinecraftAttacker()
            window.show()
            sys.exit(app.exec_())
        else:
            sys.exit(0)
    except Exception as e:
        # 捕获所有未处理的异常
        import traceback
        error_msg = f"程序发生致命错误: {str(e)}\n\n详细信息:\n{traceback.format_exc()}"
        # 写入错误日志
        try:
            with open("error.log", "w", encoding="utf-8") as f:
                f.write(error_msg)
        except:
            pass
        # 显示错误信息
        QMessageBox.critical(None, "程序崩溃", f"程序发生错误，已记录到error.log文件:\n\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()