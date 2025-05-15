#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import re
import subprocess
from urllib.parse import urlparse, parse_qs
from PyQt5.QtCore import QTimer, pyqtSignal
import time
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QFileDialog, QLineEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QComboBox, QSpinBox, QProgressBar,
    QMessageBox, QCheckBox, QGroupBox, QRadioButton
)

from crawler import WebCrawlerThread, EnhancedWebCrawler
from sqlmap_executor import SQLMapExecutor
from url_manager import URLManager
from workers import ScanThread, DataExtractThread


class MainWindow(QMainWindow):
    """主窗口类：提供GUI界面"""

    def __init__(self, config):
        super(MainWindow, self).__init__()

        # 配置
        self.thread_spin = None
        self.param_only_check = None
        self.tabs = None
        self.debug_mode_check = None
        self.depth_spin = None
        self.preprocess_button = None
        self.target_text = None
        self.max_urls_spin = None
        self.export_targets_button = None
        self.import_targets_button = None
        self.crawler_thread = None
        self.config = config

        # 初始化组件
        self.sqlmap_executor = SQLMapExecutor(config)
        self.url_manager = URLManager(config)

        # 工作线程
        self.scan_thread = None
        self.scan_worker = None
        self.extract_thread = None
        self.extract_worker = None

        # 添加这一行，用于存储发现的URL
        self.found_urls = []

        # 初始化UI
        self.init_ui()

        # 加载URL
        self.load_urls()

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("SQLMap GUI Tool")
        self.setGeometry(100, 100, 1000, 700)

        # 创建标签页
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # 创建各标签页
        self.create_url_tab()
        self.create_crawler_tab()  # 新增爬虫标签页
        self.create_scan_tab()
        self.create_result_tab()

        # 显示窗口
        self.show()

    def create_crawler_tab(self):
        """创建URL爬取标签页 - 移除日志部分"""
        crawler_tab = QWidget()
        self.tabs.addTab(crawler_tab, "URL爬取")

        layout = QVBoxLayout()
        crawler_tab.setLayout(layout)

        # 输入区域
        input_group = QGroupBox("目标输入")
        layout.addWidget(input_group)
        input_layout = QVBoxLayout()
        input_group.setLayout(input_layout)

        # 目标输入文本框
        self.target_text = QTextEdit()
        self.target_text.setPlaceholderText("输入目标站点，每行一个...\n例如: example.com 或 https://example.com")
        self.target_text.setMaximumHeight(150)
        input_layout.addWidget(self.target_text)

        # 按钮区域
        button_layout = QHBoxLayout()
        input_layout.addLayout(button_layout)

        # 前处理按钮
        self.preprocess_button = QPushButton("预处理目标")
        self.preprocess_button.clicked.connect(self.preprocess_targets)
        button_layout.addWidget(self.preprocess_button)

        # 导入按钮
        self.import_targets_button = QPushButton("从文件导入")
        self.import_targets_button.clicked.connect(self.import_targets)
        button_layout.addWidget(self.import_targets_button)

        # 导出按钮
        self.export_targets_button = QPushButton("导出目标")
        self.export_targets_button.clicked.connect(self.export_targets)
        button_layout.addWidget(self.export_targets_button)

        # 爬取设置区域
        settings_group = QGroupBox("爬取设置")
        layout.addWidget(settings_group)
        settings_layout = QVBoxLayout()
        settings_group.setLayout(settings_layout)

        # 爬取深度
        depth_layout = QHBoxLayout()
        settings_layout.addLayout(depth_layout)
        depth_layout.addWidget(QLabel("爬取深度:"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 5)
        self.depth_spin.setValue(3)  # 增加爬取深度到3
        depth_layout.addWidget(self.depth_spin)
        depth_layout.addWidget(QLabel("线程数:"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 100)
        self.thread_spin.setValue(20)
        depth_layout.addWidget(self.thread_spin)
        depth_layout.addWidget(QLabel("超时(秒):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(30)  # 增加到15秒
        depth_layout.addWidget(self.timeout_spin)

        # 添加最大URL限制
        max_urls_layout = QHBoxLayout()
        settings_layout.addLayout(max_urls_layout)
        max_urls_layout.addWidget(QLabel("最大URL数:"))
        self.max_urls_spin = QSpinBox()
        self.max_urls_spin.setRange(1000, 100000)
        self.max_urls_spin.setValue(10000)
        self.max_urls_spin.setSingleStep(1000)
        max_urls_layout.addWidget(self.max_urls_spin)

        # 高级选项
        options_layout = QHBoxLayout()
        settings_layout.addLayout(options_layout)
        self.param_only_check = QCheckBox("仅抓取带参数URL")
        self.param_only_check.setChecked(True)
        options_layout.addWidget(self.param_only_check)
        self.skip_static_check = QCheckBox("跳过静态资源")
        self.skip_static_check.setChecked(True)
        options_layout.addWidget(self.skip_static_check)
        self.respect_robots_check = QCheckBox("遵循robots.txt")
        self.respect_robots_check.setChecked(True)
        options_layout.addWidget(self.respect_robots_check)
        self.smart_crawl_check = QCheckBox("智能爬取(优先参数URL)")
        self.smart_crawl_check.setChecked(True)
        options_layout.addWidget(self.smart_crawl_check)

        # 添加调试模式选项
        debug_layout = QHBoxLayout()
        settings_layout.addLayout(debug_layout)
        self.debug_mode_check = QCheckBox("调试模式")
        self.debug_mode_check.setChecked(False)
        debug_layout.addWidget(self.debug_mode_check)

        # 添加爬虫模式选择
        crawler_mode_layout = QHBoxLayout()
        settings_layout.addLayout(crawler_mode_layout)
        crawler_mode_layout.addWidget(QLabel("爬虫模式:"))
        self.crawler_mode_combo = QComboBox()
        self.crawler_mode_combo.addItems(["标准爬虫", "增强爬虫（SQL注入专用）"])
        self.crawler_mode_combo.setCurrentIndex(1)  # 默认选择增强爬虫
        crawler_mode_layout.addWidget(self.crawler_mode_combo)

        # 爬取控制按钮
        control_layout = QHBoxLayout()
        layout.addLayout(control_layout)
        self.start_crawl_button = QPushButton("开始爬取")
        self.start_crawl_button.clicked.connect(self.start_crawling)
        control_layout.addWidget(self.start_crawl_button)
        self.stop_crawl_button = QPushButton("停止爬取")
        self.stop_crawl_button.clicked.connect(self.stop_crawling)
        self.stop_crawl_button.setEnabled(False)
        control_layout.addWidget(self.stop_crawl_button)
        self.add_to_urls_button = QPushButton("添加到URL管理")
        self.add_to_urls_button.clicked.connect(self.add_to_url_manager)
        self.add_to_urls_button.setEnabled(False)
        control_layout.addWidget(self.add_to_urls_button)

        # 进度条
        self.crawl_progress_bar = QProgressBar()
        layout.addWidget(self.crawl_progress_bar)
        self.crawl_status_label = QLabel("就绪")
        layout.addWidget(self.crawl_status_label)

        # 添加这一行，用于跟踪URL分组信息
        self.url_groups = {}

        # 爬取结果区域 - 只保留URL表格部分
        urls_layout = QVBoxLayout()
        layout.addLayout(urls_layout)
        urls_layout.addWidget(QLabel("发现的URL:"))
        self.crawled_urls_table = QTableWidget(0, 2)
        self.crawled_urls_table.setHorizontalHeaderLabels(["URL", "参数"])
        self.crawled_urls_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.crawled_urls_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        urls_layout.addWidget(self.crawled_urls_table)

        # 统计信息
        stats_layout = QHBoxLayout()
        urls_layout.addLayout(stats_layout)
        stats_layout.addWidget(QLabel("总计:"))
        self.total_crawled_label = QLabel("0")
        stats_layout.addWidget(self.total_crawled_label)
        stats_layout.addWidget(QLabel("带参数:"))
        self.param_crawled_label = QLabel("0")
        stats_layout.addWidget(self.param_crawled_label)


    def create_url_tab(self):
        """创建URL管理标签页"""
        url_tab = QWidget()
        self.tabs.addTab(url_tab, "URL管理")

        layout = QVBoxLayout()
        url_tab.setLayout(layout)

        # URL输入区域
        input_layout = QHBoxLayout()
        layout.addLayout(input_layout)

        self.url_text = QTextEdit()
        self.url_text.setPlaceholderText("输入URL列表，每行一个...\n例如: https://example.com/page.php?id=1")
        input_layout.addWidget(self.url_text)

        # URL操作按钮
        button_layout = QVBoxLayout()
        input_layout.addLayout(button_layout)

        self.add_button = QPushButton("添加URL")
        self.add_button.clicked.connect(self.add_urls)
        button_layout.addWidget(self.add_button)

        self.load_button = QPushButton("从文件加载")
        self.load_button.clicked.connect(self.load_urls_dialog)
        button_layout.addWidget(self.load_button)

        self.export_button = QPushButton("导出URL")
        self.export_button.clicked.connect(self.export_urls)
        button_layout.addWidget(self.export_button)

        # URL统计信息
        stats_layout = QHBoxLayout()
        layout.addLayout(stats_layout)

        stats_layout.addWidget(QLabel("总URL数:"))
        self.urls_label = QLabel("0")
        stats_layout.addWidget(self.urls_label)

        stats_layout.addWidget(QLabel("带参数URL数:"))
        self.param_urls_label = QLabel("0")
        stats_layout.addWidget(self.param_urls_label)

        # URL列表显示
        layout.addWidget(QLabel("URL列表:"))
        self.url_table = QTableWidget(0, 2)
        self.url_table.setHorizontalHeaderLabels(["URL", "参数"])
        self.url_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.url_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.url_table)

        # 过滤按钮
        filter_layout = QHBoxLayout()
        layout.addLayout(filter_layout)

        self.filter_button = QPushButton("过滤带参数URL")
        self.filter_button.clicked.connect(self.filter_param_urls)
        filter_layout.addWidget(self.filter_button)

        self.filter_static_button = QPushButton("过滤静态资源")
        self.filter_static_button.clicked.connect(self.filter_static_resources)
        filter_layout.addWidget(self.filter_static_button)

        self.smart_filter_button = QPushButton("智能筛选SQL注入")
        self.smart_filter_button.clicked.connect(self.smart_filter_urls)
        filter_layout.addWidget(self.smart_filter_button)

        self.export_param_button = QPushButton("导出带参数URL")
        self.export_param_button.clicked.connect(self.export_param_urls)
        filter_layout.addWidget(self.export_param_button)

    def filter_static_resources(self):
        """仅过滤掉静态资源URL（CSS、JS等）"""
        if not self.url_manager.urls:
            QMessageBox.warning(self, "警告", "没有URL可过滤")
            return

        # 定义静态资源扩展名
        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                             '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
                             '.mp3', '.mp4', '.webp', '.tif', '.tiff', '.bmp']

        # 过滤前的URL数量
        original_count = len(self.url_manager.urls)

        # 过滤掉静态资源URL
        non_static_urls = []

        for url in self.url_manager.urls:
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                path = parsed_url.path.lower()

                # 检查是否为静态资源
                is_static = any(path.endswith(ext) for ext in static_extensions)

                if not is_static:  # 保留非静态资源
                    non_static_urls.append(url)
            except:
                # 如果URL解析出错，保留该URL
                non_static_urls.append(url)

        # 更新URL列表
        self.url_manager.urls = non_static_urls

        # 如果之前过滤过带参数的URL，也需要更新param_urls
        if self.url_manager.param_urls:
            self.url_manager.param_urls = [url for url in self.url_manager.param_urls if url in non_static_urls]

        # 更新URL表格
        self.update_url_table()

        # 显示过滤结果
        removed_count = original_count - len(non_static_urls)
        QMessageBox.information(
            self,
            "过滤完成",
            f"已过滤掉 {removed_count} 个静态资源URL\n"
            f"剩余 {len(non_static_urls)} 个URL"
        )

    def create_scan_tab(self):
        """创建扫描设置标签页"""
        scan_tab = QWidget()
        self.tabs.addTab(scan_tab, "扫描设置")

        layout = QVBoxLayout()
        scan_tab.setLayout(layout)

        # SQLMap路径设置
        path_layout = QHBoxLayout()
        layout.addLayout(path_layout)

        path_layout.addWidget(QLabel("SQLMap路径:"))
        self.sqlmap_path_edit = QLineEdit(self.config.sqlmap_path)
        path_layout.addWidget(self.sqlmap_path_edit)

        self.browse_sqlmap_button = QPushButton("浏览...")
        self.browse_sqlmap_button.clicked.connect(self.browse_sqlmap)
        path_layout.addWidget(self.browse_sqlmap_button)

        # 基本扫描参数
        basic_group = QGroupBox("扫描参数")
        layout.addWidget(basic_group)
        basic_layout = QVBoxLayout()
        basic_group.setLayout(basic_layout)

        # 风险和级别设置
        risk_level_layout = QHBoxLayout()
        basic_layout.addLayout(risk_level_layout)

        # 风险级别
        risk_level_layout.addWidget(QLabel("风险级别:"))
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["1 (低)", "2 (中)", "3 (高)"])
        self.risk_combo.setCurrentIndex(self.config.risk_level - 1)
        risk_level_layout.addWidget(self.risk_combo)

        # 测试级别
        risk_level_layout.addWidget(QLabel("测试级别:"))
        self.level_combo = QComboBox()
        self.level_combo.addItems(["1", "2", "3", "4", "5"])
        self.level_combo.setCurrentIndex(self.config.test_level - 1)
        risk_level_layout.addWidget(self.level_combo)

        # 高级选项
        advanced_options_layout = QHBoxLayout()
        basic_layout.addLayout(advanced_options_layout)

        # 添加智能扫描选项
        self.smart_scan_check = QCheckBox("智能扫描(发现一个网站存在漏洞后跳过该网站其他URL)")
        self.smart_scan_check.setChecked(True)  # 默认启用
        advanced_options_layout.addWidget(self.smart_scan_check)

        # 输出目录
        output_layout = QHBoxLayout()
        layout.addLayout(output_layout)

        output_layout.addWidget(QLabel("输出目录:"))
        self.output_dir_edit = QLineEdit(self.config.output_dir)
        output_layout.addWidget(self.output_dir_edit)

        self.browse_output_button = QPushButton("浏览...")
        self.browse_output_button.clicked.connect(self.browse_output_dir)
        output_layout.addWidget(self.browse_output_button)

        # 扫描控制
        control_layout = QHBoxLayout()
        layout.addLayout(control_layout)

        self.scan_button = QPushButton("开始扫描")
        self.scan_button.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_button)

        self.stop_button = QPushButton("停止扫描")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)

        # 进度显示
        self.scan_progress_bar = QProgressBar()
        layout.addWidget(self.scan_progress_bar)

        self.scan_status_label = QLabel("就绪")
        layout.addWidget(self.scan_status_label)

        # 扫描日志
        layout.addWidget(QLabel("扫描日志:"))
        self.scan_log_text = QTextEdit()
        self.scan_log_text.setReadOnly(True)
        layout.addWidget(self.scan_log_text)

    def preprocess_targets(self):
        """预处理目标站点 - 去重、格式化"""
        targets_text = self.target_text.toPlainText()
        if not targets_text.strip():
            QMessageBox.warning(self, "警告", "请输入至少一个目标")
            return

        # 分割和清理目标
        targets = []
        for line in targets_text.split('\n'):
            line = line.strip()
            if line:
                targets.append(line)

        if not targets:
            QMessageBox.warning(self, "警告", "没有有效的目标")
            return

        # 去重
        targets = list(set(targets))

        # 标准化URL格式
        normalized_targets = []
        for target in targets:
            # 如果没有协议前缀，添加https://
            if not target.startswith(('http://', 'https://')):
                # 如果有端口号，使用http而不是https
                if ':' in target and any(c.isdigit() for c in target.split(':')[1]):
                    target = 'http://' + target
                else:
                    target = 'https://' + target

            # 确保没有结尾的斜杠
            if target.endswith('/'):
                target = target[:-1]

            normalized_targets.append(target)

        # 更新文本框
        self.target_text.clear()
        self.target_text.setText('\n'.join(normalized_targets))

        # 显示结果
        QMessageBox.information(
            self,
            "预处理完成",
            f"已处理 {len(normalized_targets)} 个目标\n" +
            f"去重并标准化格式完成"
        )

    def import_targets(self):
        """从文件导入目标"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "选择目标文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    targets = [line.strip() for line in f if line.strip()]

                # 更新文本框
                self.target_text.setText('\n'.join(targets))

                # 询问是否自动预处理
                result = QMessageBox.question(
                    self,
                    "导入成功",
                    f"已导入 {len(targets)} 个目标\n是否自动预处理？",
                    QMessageBox.Yes | QMessageBox.No
                )

                if result == QMessageBox.Yes:
                    self.preprocess_targets()

            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入目标文件出错: {str(e)}")

    def export_targets(self):
        """导出目标到文件"""
        targets_text = self.target_text.toPlainText()
        if not targets_text.strip():
            QMessageBox.warning(self, "警告", "没有目标可导出")
            return

        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self,
            "保存目标文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(targets_text)

                QMessageBox.information(self, "成功", "目标已成功导出到文件")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出目标文件出错: {str(e)}")

    def refresh_ui(self):
        """定期刷新UI以确保显示最新数据"""
        # 强制处理UI事件
        QApplication.processEvents()

        # 更新统计数据
        if hasattr(self, 'found_urls'):
            total_count = len(self.found_urls)
            param_count = sum(1 for url in self.found_urls if '?' in url and '=' in url)

            # 更新计数标签
            self.total_crawled_label.setText(str(total_count))
            self.param_crawled_label.setText(str(param_count))

            # 如果爬虫正在运行，尝试从爬虫线程获取最新的带参数URL
            if hasattr(self, 'crawler_thread') and self.crawler_thread.isRunning():
                try:
                    # 获取爬虫线程中最新的10个带参数URL
                    with self.crawler_thread.lock:
                        latest_urls = []
                        # 倒序遍历找到带参数的URL
                        for url in reversed(self.crawler_thread.found_urls[-50:]):
                            if '?' in url and '=' in url:
                                params = self.get_url_params(url)
                                if params:
                                    latest_urls.append((url, params))
                                    if len(latest_urls) >= 5:  # 最多处理5个
                                        break

                        # 将这些URL添加到表格
                        for url, params in latest_urls:
                            self._add_single_url(url, params)
                except Exception as e:
                    print(f"刷新UI时出错: {e}")

    def start_crawling(self):
        """开始爬取URL - 增强UI响应性"""
        targets_text = self.target_text.toPlainText()
        if not targets_text.strip():
            QMessageBox.warning(self, "警告", "请输入至少一个目标")
            return

        # 获取爬取参数
        depth = max(5, self.depth_spin.value())  # 确保爬取深度至少为5
        threads = min(50, max(20, self.thread_spin.value()))  # 线程数范围20-50
        timeout = max(30, self.timeout_spin.value())  # 超时时间至少30秒
        param_only = False  # 初始爬取不限制仅带参数URL
        skip_static = self.skip_static_check.isChecked()
        respect_robots = self.respect_robots_check.isChecked()
        smart_crawl = self.smart_crawl_check.isChecked()
        max_urls = max(20000, self.max_urls_spin.value())  # 确保最大URL数量足够

        # 获取目标列表
        targets = [line.strip() for line in targets_text.split('\n') if line.strip()]

        if not targets:
            QMessageBox.warning(self, "警告", "没有有效的目标")
            return

        # 更新界面状态
        self.start_crawl_button.setEnabled(False)
        self.stop_crawl_button.setEnabled(True)
        self.add_to_urls_button.setEnabled(False)
        self.crawl_status_label.setText("爬取中...")
        self.crawl_progress_bar.setValue(0)

        # 清空爬取结果表格
        self.crawled_urls_table.setRowCount(0)
        self.total_crawled_label.setText("0")
        self.param_crawled_label.setText("0")
        self.found_urls = []  # 重置发现的URL列表
        self.url_groups = {}  # 重置URL分组

        try:
            # 使用增强爬虫
            self.crawler_thread = EnhancedWebCrawler(
                targets, depth, threads, timeout,
                param_only, skip_static, respect_robots, smart_crawl
            )
            # 设置最大URL数量
            self.crawler_thread.max_urls = max_urls

            # 启用增强功能
            self.crawler_thread.aggressive_form_parsing = True
            self.crawler_thread.follow_subdomains = True
            self.crawler_thread.js_parsing_enabled = True

            self.crawl_status_label.setText("爬取中(增强模式)...")

            # 修改这里，使用正确的方法名或者直接连接到print函数
            # self.crawler_thread.log_signal.connect(self.update_crawl_log)  # 有问题的行
            self.crawler_thread.log_signal.connect(lambda msg: print(f"爬虫日志: {msg}"))  # 直接打印到控制台

            self.crawler_thread.url_found_signal.connect(self.add_crawled_url)
            self.crawler_thread.progress_signal.connect(self.crawl_progress_bar.setValue)
            self.crawler_thread.finished.connect(self.crawling_finished)

            # 启动定期UI刷新的计时器
            self.refresh_timer = QTimer()
            self.refresh_timer.timeout.connect(self.refresh_ui)
            self.refresh_timer.start(1000)  # 每秒刷新一次UI

            # 启动线程
            self.crawler_thread.start()

        except Exception as e:
            import traceback
            error_text = traceback.format_exc()
            print(f"启动爬虫时出错: {str(e)}\n{error_text}")

            # 恢复界面状态
            self.start_crawl_button.setEnabled(True)
            self.stop_crawl_button.setEnabled(False)
            self.crawl_status_label.setText("启动失败")

            # 显示错误消息
            QMessageBox.critical(self, "错误", f"启动爬虫时出错: {str(e)}")

    def stop_crawling(self):
        """停止爬取URL - 强制停止所有线程"""
        if hasattr(self, 'crawler_thread') and self.crawler_thread.isRunning():
            print("正在停止爬虫...")
            self.crawl_status_label.setText("正在停止爬虫...")
            self.stop_crawl_button.setEnabled(False)

            # 设置停止标志
            self.crawler_thread.running = False

            # 如果是WebCrawlerThread类的实例，还需要停止其内部的enhanced_crawler
            if isinstance(self.crawler_thread, WebCrawlerThread):
                self.crawler_thread.enhanced_crawler.running = False

            # 停止UI刷新计时器
            if hasattr(self, 'refresh_timer') and self.refresh_timer.isActive():
                self.refresh_timer.stop()

            # 创建一个新线程来等待爬虫线程结束，避免UI冻结
            class WaitThread(QThread):
                finished = pyqtSignal()

                def __init__(self, crawler_thread):
                    super().__init__()
                    self.crawler_thread = crawler_thread

                def run(self):
                    # 最多等待5秒
                    for _ in range(50):
                        if not self.crawler_thread.isRunning():
                            break
                        time.sleep(0.1)
                    self.finished.emit()

            # 创建等待线程
            self.wait_thread = WaitThread(self.crawler_thread)
            self.wait_thread.finished.connect(self.on_crawler_really_stopped)
            self.wait_thread.start()

            # 显示进度条等待
            self.crawl_progress_bar.setRange(0, 0)  # 设置为不确定模式

            # 更新界面
            QApplication.processEvents()

            print("已请求停止爬虫，等待爬虫线程结束...")

    def on_crawler_really_stopped(self):
        """爬虫线程真正停止后的处理"""
        print("爬虫线程已经停止")
        self.crawl_progress_bar.setRange(0, 100)  # 恢复进度条正常模式
        self.crawl_progress_bar.setValue(100)
        self.crawl_status_label.setText("爬取已停止")
        self.start_crawl_button.setEnabled(True)

        # 强制处理所有找到的带参数URL
        try:
            if hasattr(self.crawler_thread, 'found_urls'):
                param_urls = []
                for url in self.crawler_thread.found_urls:
                    params = self.get_url_params(url)
                    if params:
                        param_urls.append((url, params))

                # 显示找到的带参数URL数量
                if param_urls:
                    print(f"爬取停止，发现 {len(param_urls)} 个带参数URL，正在添加到表格...")

                # 分批处理
                batch_size = 50
                for i in range(0, len(param_urls), batch_size):
                    batch = param_urls[i:i + batch_size]
                    if batch:
                        # 添加批次到表格
                        self.add_crawled_url(batch)
                        # 强制UI更新
                        QApplication.processEvents()
                        # 稍微延迟以确保UI更新
                        time.sleep(0.1)

                # 更新统计
                if param_urls:
                    self.total_crawled_label.setText(str(len(self.crawler_thread.found_urls)))
                    self.param_crawled_label.setText(str(len(param_urls)))
        except Exception as e:
            print(f"处理停止爬取时出错: {e}")
            import traceback
            print(traceback.format_exc())

    def _get_url_group_key(self, url):
        """生成URL的分组键 - 基于域名、路径结构和参数名"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # 获取路径部分，但移除最后的数字部分
            path = parsed.path
            path_parts = path.split('/')
            # 移除路径中的数字部分和空部分
            normalized_path = '/'.join(re.sub(r'\d+', 'X', part) for part in path_parts if part)

            # 获取参数名（不含值）
            params = sorted(parse_qs(parsed.query).keys())

            # 组合键
            return f"{domain}:{normalized_path}:{','.join(params)}"
        except:
            # 出错时返回原始URL
            return url

    def add_crawled_url(self, url_batch):
        """添加爬取到的一批URL到表格 - 确保正确显示"""
        try:
            print(f"收到URL批次: {type(url_batch)}, 长度: {len(url_batch) if isinstance(url_batch, list) else 'N/A'}")

            # 处理不同格式的URL批次
            processed_urls = []

            # 处理列表格式批次
            if isinstance(url_batch, list):
                for url_item in url_batch:
                    # 处理元组格式
                    if isinstance(url_item, tuple):
                        url = url_item[0] if len(url_item) > 0 else ""
                        params = url_item[1] if len(url_item) > 1 else []

                        # 确保params是列表
                        if not isinstance(params, list):
                            params = [params] if params else []

                        # 打印信息以便调试
                        if url:
                            if params:
                                print(f"处理带参数URL: {url}, 参数: {params}")
                            processed_urls.append((url, params))

                    # 处理字符串格式
                    elif isinstance(url_item, str):
                        url = url_item
                        params = self.get_url_params(url)
                        processed_urls.append((url, params))

            # 强制UI立即处理事件，避免冻结
            QApplication.processEvents()

            # 将处理后的URL添加到表格
            for url, params in processed_urls:
                self._add_single_url(url, params)

            # 再次强制UI更新
            QApplication.processEvents()

            # 更新统计数据
            if self.found_urls:
                param_count = sum(1 for url in self.found_urls if '?' in url and '=' in url)
                self.total_crawled_label.setText(str(len(self.found_urls)))
                self.param_crawled_label.setText(str(param_count))

        except Exception as e:
            import traceback
            print(f"处理URL批次出错: {e}\n{traceback.format_exc()}")

    def get_url_params(self, url):
        """提取URL参数并处理潜在的解码问题"""
        try:
            # 主动解析查询参数
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            # 打印参数信息
            if query_params:
                print(f"从URL成功提取参数: {url} -> {list(query_params.keys())}")

            # 如果能找到参数，直接返回
            if query_params:
                return list(query_params.keys())

            # 如果找不到参数但URL中有'='，可能是格式问题，尝试手动解析
            if '=' in url:
                if '?' in url:
                    query_part = url.split('?', 1)[1]
                    params = []
                    for param_pair in query_part.split('&'):
                        if '=' in param_pair:
                            param_name = param_pair.split('=', 1)[0]
                            if param_name:
                                params.append(param_name)
                    print(f"手动解析参数: {url} -> {params}")
                    return params

            # 如果URL中没有标准参数，检查是否有路径参数
            path = parsed.path
            if re.search(r'/\d+/?$', path):
                # 找到可能是ID的数字参数
                print(f"检测到路径参数: {url} -> ['id']")
                return ["id"]  # 添加隐式ID参数

            return []
        except Exception as e:
            print(f"URL参数提取错误: {e}")
            return []

    def _add_single_url(self, url, params):
        """添加单个URL到表格 - 确保实时显示"""
        try:
            # 打印参数信息以便调试
            print(f"添加URL到表格: {url}, 参数: {params}")

            # 先添加到内部URL列表，用于后续处理
            if url not in self.found_urls:
                self.found_urls.append(url)

            # 判断是否有参数
            has_params = bool(params)

            # 如果没有参数且设置了仅显示带参数URL，则跳过
            if self.param_only_check.isChecked() and not has_params:
                print(f"跳过无参数URL: {url}")
                return

            # 生成URL分组键
            group_key = self._get_url_group_key(url)

            # 检查是否已存在此URL
            for row in range(self.crawled_urls_table.rowCount()):
                url_item = self.crawled_urls_table.item(row, 0)
                if url_item and url_item.text() == url:
                    print(f"URL已存在于表格中: {url}")
                    return

            # 检查表格行数是否已达到上限
            max_display_rows = 5000  # 增加最大显示行数
            if self.crawled_urls_table.rowCount() >= max_display_rows:
                # 如果已达到上限，替换最后一行为总结行
                last_row = self.crawled_urls_table.rowCount() - 1
                summary_item = QTableWidgetItem(
                    f"... 总共发现更多URL (仅显示前{max_display_rows - 1}个，还有{len(self.found_urls) - max_display_rows + 1}个未显示) ...")
                summary_item.setForeground(Qt.gray)
                self.crawled_urls_table.setItem(last_row, 0, summary_item)
                self.crawled_urls_table.setItem(last_row, 1, QTableWidgetItem(""))
                return

            # 正常添加URL到表格
            row = self.crawled_urls_table.rowCount()
            self.crawled_urls_table.insertRow(row)

            # URL列
            url_item = QTableWidgetItem(url)
            self.crawled_urls_table.setItem(row, 0, url_item)

            # 参数列
            params_str = ", ".join(params) if params else ""
            params_item = QTableWidgetItem(params_str)

            # 根据是否有参数设置颜色
            if params:
                params_item.setForeground(Qt.blue)  # 有参数显示蓝色
                # 有参数的URL行的背景设为浅黄色，更容易看到
                url_item.setBackground(QColor(255, 255, 200))
                params_item.setBackground(QColor(255, 255, 200))

            self.crawled_urls_table.setItem(row, 1, params_item)

            # 自动滚动到新添加的行
            self.crawled_urls_table.scrollToItem(url_item)

            # 强制处理UI事件，确保界面更新
            QApplication.processEvents()

        except Exception as e:
            import traceback
            print(f"添加URL到表格时出错: {str(e)}\n{traceback.format_exc()}")

    def is_similar_url_exists(self, url):
        """检查是否已存在相似的URL"""
        # 分解URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path_parts = parsed.path.split('/')

        # 检查是否有相同域名和类似路径的URL
        similar_count = 0
        for existing_url in self.found_urls[-20:]:  # 只检查最近添加的20个URL
            existing_parsed = urlparse(existing_url)
            if existing_parsed.netloc == domain:
                existing_path_parts = existing_parsed.path.split('/')

                # 检查路径长度和前缀
                if len(existing_path_parts) == len(path_parts):
                    # 检查除最后一部分外的路径是否相同
                    prefix_match = True
                    for i in range(len(path_parts) - 1):
                        if i < len(existing_path_parts) and path_parts[i] != existing_path_parts[i]:
                            prefix_match = False
                            break

                    if prefix_match:
                        similar_count += 1
                        if similar_count >= 5:  # 已有5个相似URL
                            return True

        return False

    def update_similar_url_count(self, url):
        """更新相似URL的计数"""
        # 当发现相似URL时，更新最后一行的信息
        if self.crawled_urls_table.rowCount() > 0:
            last_row = self.crawled_urls_table.rowCount() - 1
            last_item = self.crawled_urls_table.item(last_row, 0)

            if last_item and "..." in last_item.text():
                # 更新计数
                current_text = last_item.text()
                if "还有" in current_text and "个URL未显示" in current_text:
                    try:
                        count_str = current_text.split("还有")[1].split("个URL")[0].strip()
                        count = int(count_str) + 1
                        new_text = f"... 仅显示部分URL（还有 {count} 个URL未显示）..."
                        last_item.setText(new_text)
                    except:
                        pass

    def crawling_finished(self):
        """爬取完成处理 - 确保所有URL都被显示"""
        # 恢复界面状态
        self.start_crawl_button.setEnabled(True)
        self.stop_crawl_button.setEnabled(False)
        self.add_to_urls_button.setEnabled(True)
        self.crawl_status_label.setText("爬取完成")
        self.crawl_progress_bar.setValue(100)

        # 停止UI刷新计时器
        if hasattr(self, 'refresh_timer') and self.refresh_timer.isActive():
            self.refresh_timer.stop()

        # 确保所有带参数的URL都被添加到表格中
        try:
            if hasattr(self.crawler_thread, 'found_urls'):
                # 计算发现的总URL和带参数URL
                total = len(self.crawler_thread.found_urls)
                param_urls = []

                # 收集所有带参数URL
                for url in self.crawler_thread.found_urls:
                    params = self.get_url_params(url)
                    if params:
                        param_urls.append((url, params))

                param_count = len(param_urls)

                # 显示进度
                print(f"爬取完成，发现 {total} 个URL，其中 {param_count} 个带参数，正在全部添加到表格...")

                # 重新添加所有带参数URL到表格
                # 分批处理以避免UI卡顿
                batch_size = 100
                for i in range(0, len(param_urls), batch_size):
                    batch = param_urls[i:i + batch_size]
                    if batch:
                        self.add_crawled_url(batch)
                        QApplication.processEvents()  # 强制UI更新
                        time.sleep(0.05)  # 稍微延迟

                # 更新统计数据
                self.total_crawled_label.setText(str(total))
                self.param_crawled_label.setText(str(param_count))
        except Exception as e:
            print(f"爬取完成处理出错: {e}")
            import traceback
            print(traceback.format_exc())

        # 显示完成信息
        total = len(self.found_urls)
        param_count = sum(1 for url in self.found_urls if '?' in url and '=' in url)

        # 弹出提示
        QMessageBox.information(
            self,
            "爬取完成",
            f"爬取完成，共发现 {total} 个URL，其中 {param_count} 个带参数\n\n" +
            f"点击「添加到URL管理」可将爬取结果添加到URL管理中进行后续扫描。"
        )

    def add_to_url_manager(self):
        """将爬取结果添加到URL管理器"""
        # 使用找到的所有URL，而不仅仅是表格中显示的
        urls = self.found_urls

        if not urls:
            QMessageBox.warning(self, "警告", "没有URL可添加")
            return

            # 如果只添加带参数的URL
        if self.param_only_check.isChecked():
            urls = [url for url in urls if self.get_url_params(url)]

        if not urls:
            QMessageBox.warning(self, "警告", "没有符合条件的URL可添加")
            return

        # 询问导入方式
        import_options = QMessageBox(self)
        import_options.setWindowTitle("导入方式")
        import_options.setText("请选择URL导入方式:")
        import_options.setIcon(QMessageBox.Question)

        normal_btn = import_options.addButton("常规导入", QMessageBox.ActionRole)
        smart_btn = import_options.addButton("智能导入(过滤静态资源)", QMessageBox.ActionRole)
        cancel_btn = import_options.addButton("取消", QMessageBox.RejectRole)

        import_options.exec_()

        clicked_btn = import_options.clickedButton()

        if clicked_btn == cancel_btn:
            return
        elif clicked_btn == smart_btn:
            # 智能导入
            result = self.url_manager.smart_import_urls(urls)

            # 更新URL管理页面的表格
            self.update_url_table()

            # 切换到URL管理标签页
            self.tabs.setCurrentIndex(0)

            # 显示结果
            QMessageBox.information(
                self,
                "智能导入成功",
                f"共处理 {result['original']} 个URL\n" +
                f"过滤后保留 {result['filtered']} 个URL\n" +
                f"成功添加 {result['added']} 个URL到URL管理\n\n" +
                f"已自动切换到URL管理标签页"
            )
        else:
            # 常规导入
            urls_text = "\n".join(urls)
            added_count = self.url_manager.add_urls(urls_text)

            # 更新URL管理页面的表格
            self.update_url_table()

            # 切换到URL管理标签页
            self.tabs.setCurrentIndex(0)

            # 显示结果
            QMessageBox.information(
                self,
                "导入成功",
                f"已添加 {added_count} 个URL到URL管理\n\n" +
                f"已自动切换到URL管理标签页"
            )

    def smart_filter_urls(self):
        """智能筛选潜在SQL注入URL"""
        if not self.url_manager.urls:
            QMessageBox.warning(self, "警告", "没有URL可筛选")
            return

        # 首先确保过滤出带参数的URL
        param_urls = self.url_manager.filter_param_urls()

        if not param_urls:
            QMessageBox.warning(self, "警告", "没有带参数的URL可筛选")
            return

        # 询问筛选模式
        filter_mode = QMessageBox.question(
            self,
            "筛选模式",
            "请选择筛选模式:\n\n基本模式 - 仅根据参数名称筛选\n高级模式 - 使用风险评分系统全面评估",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        # 询问是否进行URL分组
        grouping_mode = QMessageBox.question(
            self,
            "URL分组",
            "是否对类似URL进行智能分组?\n\n是 - 对类似URL结构进行分组，每组只保留几个代表性样本\n否 - 保留所有URL",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        # 进行URL分组
        if grouping_mode == QMessageBox.Yes:
            # 按URL结构分组
            url_groups = {}

            for url in param_urls:
                try:
                    from urllib.parse import urlparse, parse_qs
                    parsed_url = urlparse(url)
                    path = parsed_url.path

                    # 提取参数名称（不包括值）
                    query_params = parse_qs(parsed_url.query)
                    param_names = sorted(query_params.keys())

                    # 创建URL模式：域名+路径+参数名
                    domain = parsed_url.netloc
                    url_pattern = f"{domain}:{path}:{','.join(param_names)}"

                    if url_pattern not in url_groups:
                        url_groups[url_pattern] = []
                    url_groups[url_pattern].append(url)
                except Exception as e:
                    print(f"URL分组出错: {url} - {str(e)}")

            # 从每组中选择代表性URL
            grouped_urls = []
            for pattern, urls in url_groups.items():
                # 每组选择最多3个样本
                sample_count = min(3, len(urls))
                if sample_count == 1:
                    grouped_urls.append(urls[0])
                else:
                    # 选择第一个、中间一个和最后一个
                    grouped_urls.append(urls[0])
                    if sample_count >= 2:
                        grouped_urls.append(urls[len(urls) // 2])
                    if sample_count >= 3:
                        grouped_urls.append(urls[-1])

            # 使用分组后的URL继续处理
            param_urls = grouped_urls

            # 显示分组结果
            QMessageBox.information(
                self,
                "URL分组结果",
                f"URL已分组：原始 {len(self.url_manager.param_urls)} 个 → 分组后 {len(param_urls)} 个"
            )

        # 根据选择的模式继续处理
        if filter_mode == QMessageBox.Yes:
            # 基本模式 - 使用原有代码
            # 定义静态资源扩展名
            static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                                 '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip']

            # 定义常见的数据库参数名
            db_param_names = ['id', 'user_id', 'product_id', 'cat', 'category', 'article',
                              'post', 'page', 'news', 'item', 'order', 'key', 'search', 'query',
                              'username', 'user', 'name', 'pid', 'cid', 'uid', 'sid', 'mid']

            potential_urls = []
            skipped_urls = []

            for url in param_urls:
                # 解析URL
                from urllib.parse import urlparse, parse_qs
                parsed_url = urlparse(url)
                path = parsed_url.path.lower()
                query_params = parse_qs(parsed_url.query)

                # 检查是否为静态资源
                is_static = any(path.endswith(ext) for ext in static_extensions)

                if is_static:
                    skipped_urls.append(url)
                    continue

                # 检查是否包含数据库相关参数
                has_db_param = False
                for param in query_params.keys():
                    param_lower = param.lower()
                    if any(db_name in param_lower for db_name in db_param_names):
                        has_db_param = True
                        break

                # 如果不是静态资源且包含数据库相关参数，则可能存在SQL注入
                if not is_static and (has_db_param or 'id=' in url or '=' in url):
                    potential_urls.append(url)
                else:
                    skipped_urls.append(url)
        else:
            # 高级模式 - 使用风险评分系统
            # 创建一个临时的EnhancedWebCrawler实例来使用其评分功能
            temp_crawler = EnhancedWebCrawler([])

            # 对URL进行评分
            scored_urls = []
            for url in param_urls:
                try:
                    # 提取参数用于评分，而不是风险分数
                    params = self.get_url_params(url)
                    # 简单评分方式：参数数量越多，评分越高
                    score = len(params) * 5
                    if any(p.lower() in ['id', 'uid', 'pid'] for p in params):
                        score += 5  # ID类参数加分
                    scored_urls.append((url, score))
                except Exception as e:
                    print(f"URL评分出错: {url} - {str(e)}")
                    scored_urls.append((url, 0))  # 出错时，分数为0

            # 按风险分数排序
            scored_urls.sort(key=lambda x: x[1], reverse=True)

            # 询问筛选严格程度
            result = QMessageBox.question(
                self,
                "筛选严格程度",
                "请选择筛选严格程度:\n\n严格 - 仅保留高价值参数URL\n中等 - 保留中高价值参数URL\n宽松 - 保留所有带参数URL并按价值排序",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.No
            )

            if result == QMessageBox.Yes:  # 严格
                threshold = 10
            elif result == QMessageBox.No:  # 中等
                threshold = 5
            else:  # 宽松
                threshold = 0

            # 根据阈值筛选
            potential_urls = [url for url, score in scored_urls if score > threshold]
            skipped_urls = [url for url, score in scored_urls if score <= threshold]

        # 更新URL管理器中的URL列表
        if potential_urls:
            self.url_manager.urls = potential_urls
            self.url_manager.param_urls = potential_urls
            self.update_url_table()

            # 显示结果
            QMessageBox.information(
                self,
                "筛选完成",
                f"已找到 {len(potential_urls)} 个潜在SQL注入URL\n"
                f"已过滤掉 {len(skipped_urls)} 个低风险URL"
            )
        else:
            QMessageBox.warning(self, "警告", "没有找到潜在的SQL注入URL")

    def create_result_tab(self):
        """创建结果显示标签页 - 简化版只用于展示"""
        result_tab = QWidget()
        self.tabs.addTab(result_tab, "扫描结果")

        layout = QVBoxLayout()
        result_tab.setLayout(layout)

        # 结果表格 - 只保留URL和状态两列
        layout.addWidget(QLabel("扫描结果:"))
        self.result_table = QTableWidget(0, 2)  # 只有2列：URL和状态
        self.result_table.setHorizontalHeaderLabels(["URL", "状态"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        layout.addWidget(self.result_table)

        # 结果统计
        stats_layout = QHBoxLayout()
        layout.addLayout(stats_layout)

        stats_layout.addWidget(QLabel("总计:"))
        self.total_label = QLabel("0")
        stats_layout.addWidget(self.total_label)

        stats_layout.addWidget(QLabel("成功:"))
        self.success_label = QLabel("0")
        stats_layout.addWidget(self.success_label)

        stats_layout.addWidget(QLabel("失败:"))
        self.failed_label = QLabel("0")
        stats_layout.addWidget(self.failed_label)

        # 移除数据提取日志部分

    # URL标签页功能
    def add_urls(self):
        """添加URL"""
        urls_text = self.url_text.toPlainText()
        if not urls_text.strip():
            QMessageBox.warning(self, "警告", "请输入至少一个URL")
            return

        added_count = self.url_manager.add_urls(urls_text)

        if added_count > 0:
            self.url_text.clear()
            self.update_url_table()
            QMessageBox.information(self, "成功", f"已添加 {added_count} 个URL")
        else:
            QMessageBox.warning(self, "警告", "没有添加任何有效的URL")

    def load_urls(self):
        """加载URL"""
        count = self.url_manager.load_urls()
        self.update_url_table()
        return count

    def load_urls_dialog(self):
        """从文件加载URL"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "选择URL文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )

        if file_path:
            try:
                count = self.url_manager.load_urls(file_path)
                self.update_url_table()
                QMessageBox.information(self, "成功", f"已从文件加载 {count} 个URL")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载URL文件出错: {str(e)}")

    def export_urls(self):
        """导出URL"""
        if not self.url_manager.urls:
            QMessageBox.warning(self, "警告", "没有URL可导出")
            return

        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self,
            "保存URL文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )

        if file_path:
            try:
                success = self.url_manager.save_urls(self.url_manager.urls, file_path)
                if success:
                    QMessageBox.information(self, "成功", "URL已成功导出到文件")
                else:
                    QMessageBox.critical(self, "错误", "导出URL时出错")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出URL文件出错: {str(e)}")

    def filter_param_urls(self):
        """过滤带参数的URL"""
        param_urls = self.url_manager.filter_param_urls()

        self.update_url_table()
        QMessageBox.information(self, "成功", f"找到 {len(param_urls)} 个带参数的URL")

    def group_urls_by_domain(self):
        """按域名分组URL并为每个域名选择代表性URL"""
        if not self.url_manager.param_urls:
            self.url_manager.filter_param_urls()

        if not self.url_manager.param_urls:
            QMessageBox.warning(self, "警告", "没有带参数的URL可分组")
            return

        # 按域名分组
        domain_groups = {}

        for url in self.url_manager.param_urls:
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                domain = parsed_url.netloc

                if domain not in domain_groups:
                    domain_groups[domain] = []

                domain_groups[domain].append(url)
            except:
                continue

        # 对每个域名，按参数结构进行二次分组
        representative_urls = []

        for domain, urls in domain_groups.items():
            # 按参数结构分组
            param_structure_groups = {}

            for url in urls:
                try:
                    from urllib.parse import urlparse, parse_qs
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)

                    # 创建参数结构签名（只考虑参数名，不考虑值）
                    param_signature = ','.join(sorted(query_params.keys()))

                    if param_signature not in param_structure_groups:
                        param_structure_groups[param_signature] = []

                    param_structure_groups[param_signature].append(url)
                except:
                    continue

            # 从每个参数结构组中选择一个代表性URL
            for param_structure, structure_urls in param_structure_groups.items():
                representative_urls.append(structure_urls[0])

        # 更新URL列表
        if representative_urls:
            self.url_manager.grouped_urls = representative_urls

            # 显示分组结果
            original_count = len(self.url_manager.param_urls)
            grouped_count = len(representative_urls)
            reduction = original_count - grouped_count

            result = QMessageBox.question(
                self,
                "域名智能分组",
                f"已将 {original_count} 个URL分组为 {grouped_count} 个代表性URL，减少了 {reduction} 个URL。\n\n"
                f"是否使用分组后的URL列表？",
                QMessageBox.Yes | QMessageBox.No
            )

            if result == QMessageBox.Yes:
                self.url_manager.param_urls = representative_urls
                self.update_url_table()
                return True

        return False

    def export_param_urls(self):
        """导出带参数的URL"""
        if not self.url_manager.param_urls:
            self.url_manager.filter_param_urls()

        if not self.url_manager.param_urls:
            QMessageBox.warning(self, "警告", "没有带参数的URL可导出")
            return

        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self,
            "保存带参数URL文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )

        if file_path:
            try:
                success = self.url_manager.export_param_urls(file_path)
                if success:
                    QMessageBox.information(self, "成功", "带参数的URL已成功导出到文件")
                else:
                    QMessageBox.critical(self, "错误", "导出带参数URL时出错")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出带参数URL文件出错: {str(e)}")

    def update_url_table(self):
        """更新URL表格 - 添加高亮潜在注入点"""
        self.url_table.setRowCount(0)

        # 定义常见的数据库参数名
        db_param_names = ['id', 'user_id', 'product_id', 'cat', 'category', 'article',
                          'post', 'page', 'news', 'item', 'order', 'key', 'search', 'query',
                          'username', 'user', 'name', 'pid', 'cid', 'uid', 'sid']

        for url in self.url_manager.urls:
            row = self.url_table.rowCount()
            self.url_table.insertRow(row)

            # URL列
            url_item = QTableWidgetItem(url)
            self.url_table.setItem(row, 0, url_item)

            # 参数列
            params = self.url_manager.get_params_from_url(url)
            params_str = ", ".join(params)
            params_item = QTableWidgetItem(params_str)

            # 检查是否包含数据库相关参数，如果有则高亮显示
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            has_db_param = False
            for param in query_params.keys():
                param_lower = param.lower()
                if any(db_name in param_lower for db_name in db_param_names):
                    has_db_param = True
                    break

            if has_db_param:
                params_item.setForeground(Qt.red)  # 高亮数据库相关参数

            self.url_table.setItem(row, 1, params_item)

        self.urls_label.setText(str(len(self.url_manager.urls)))
        self.param_urls_label.setText(str(len(self.url_manager.param_urls)))

    def scan_finished(self):
        """扫描完成处理"""
        # 恢复界面状态
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.scan_status_label.setText("扫描完成")
        self.scan_progress_bar.setValue(100)

        # 切换到结果标签页
        self.tabs.setCurrentIndex(2)

    def add_to_result_table(self, url, vulnerable, detail=""):
        """添加到结果表格 - 简化版，没有操作列"""
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        # URL列
        url_item = QTableWidgetItem(url)
        self.result_table.setItem(row, 0, url_item)

        # 状态列
        if "跳过检测" in detail:
            status = "跳过检测" + detail.replace("跳过检测", "")
            color = Qt.blue  # 用蓝色标记跳过的URL
        else:
            status = "存在SQL注入" if vulnerable else "未发现注入"
            if detail:
                status += f" ({detail})"
            color = Qt.red if vulnerable else Qt.black

        status_item = QTableWidgetItem(status)
        status_item.setForeground(color)
        self.result_table.setItem(row, 1, status_item)

    def browse_sqlmap(self):
        """浏览选择SQLMap路径"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "选择SQLMap路径",
            "",
            "Python文件 (*.py);;所有文件 (*.*)"
        )

        if file_path:
            self.sqlmap_path_edit.setText(f"python \"{file_path}\"")

    def browse_output_dir(self):
        """浏览选择输出目录"""
        dir_dialog = QFileDialog()
        dir_path = dir_dialog.getExistingDirectory(
            self,
            "选择输出目录",
            self.config.output_dir
        )

        if dir_path:
            self.output_dir_edit.setText(dir_path)

    def start_scan(self):
        """开始扫描 - 支持智能扫描"""
        # 确保有URL可扫描
        if not self.url_manager.param_urls:
            self.url_manager.filter_param_urls()

        if not self.url_manager.param_urls:
            QMessageBox.warning(self, "警告", "没有带参数的URL可扫描")
            return

        # 更新配置
        self.config.sqlmap_path = self.sqlmap_path_edit.text()
        self.config.output_dir = self.output_dir_edit.text()
        self.config.risk_level = int(self.risk_combo.currentText().split()[0])
        self.config.test_level = int(self.level_combo.currentText())

        # 创建临时URL文件
        os.makedirs(self.config.output_dir, exist_ok=True)
        temp_file = os.path.join(self.config.output_dir, "scan_urls.txt")

        # 写入URL
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                for url in self.url_manager.param_urls:
                    if not url.startswith(('http://', 'https://')):
                        url = 'http://' + url
                    f.write(url + '\n')
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建URL文件时出错: {str(e)}")
            return

        # 准备扫描参数
        params = {
            "risk": self.config.risk_level,
            "level": self.config.test_level
        }

        # 是否启用智能扫描
        smart_scan = self.smart_scan_check.isChecked()

        # 更新界面状态
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.scan_status_label.setText("扫描中...")
        self.scan_progress_bar.setValue(0)
        self.scan_log_text.clear()

        # 重置结果表格
        self.result_table.setRowCount(0)
        self.total_label.setText("0")
        self.success_label.setText("0")
        self.failed_label.setText("0")

        try:
            # 导入SQLMapRunnerThread类
            from workers import SQLMapRunnerThread

            # 创建线程实例，传入智能扫描选项
            self.sqlmap_runner = SQLMapRunnerThread(self.config, temp_file, params, smart_scan)

            # 连接信号
            self.sqlmap_runner.log_signal.connect(self.update_scan_log)
            self.sqlmap_runner.result_signal.connect(self.update_scan_result)
            self.sqlmap_runner.progress_signal.connect(self.scan_progress_bar.setValue)
            self.sqlmap_runner.finished.connect(self.scan_finished)

            # 启动线程
            self.sqlmap_runner.start()

            # 显示开始信息
            url_count = len(self.url_manager.param_urls)
            mode_str = "启用智能扫描" if smart_scan else "常规扫描"
            self.scan_log_text.append(f"准备{mode_str} {url_count} 个URL...")

        except Exception as e:
            import traceback
            error_msg = f"启动扫描线程时出错: {str(e)}\n{traceback.format_exc()}"
            print(error_msg)
            self.scan_log_text.append(error_msg)

            # 恢复界面状态
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.scan_status_label.setText("错误")

    def on_url_scan_start(self, url, index, total):
        """URL扫描开始时的处理"""
        progress = int((index / total) * 100)
        self.scan_progress_bar.setValue(progress)
        self.scan_status_label.setText(f"扫描URL {index + 1}/{total}")
        self.scan_log_text.append(f"\n--- 扫描URL [{index + 1}/{total}]: {url} ---")

        # 保存当前URL以便其他处理
        self.current_url = url

    def on_url_scan_finish(self, url, vulnerable, detail=""):
        """URL扫描完成时的处理"""
        # 添加到结果表格
        self.add_to_result_table(url, vulnerable, detail)

        # 更新统计信息
        self.total_label.setText(str(self.result_table.rowCount()))
        self.success_label.setText(str(len([
            i for i in range(self.result_table.rowCount())
            if "存在SQL注入" in self.result_table.item(i, 1).text()
        ])))
        self.failed_label.setText(str(len([
            i for i in range(self.result_table.rowCount())
            if "未发现注入" in self.result_table.item(i, 1).text()
        ])))

    def update_batch_progress(self, progress):
        """更新批量扫描进度"""
        self.scan_progress_bar.setValue(progress)

    def on_batch_scan_finished(self):
        """批量扫描完成时的处理"""
        self.scan_log_text.append("\n所有URL扫描完成！")
        self.scan_finished()

    def stop_scan(self):
        """停止扫描"""
        # 停止SQLMap运行线程
        if hasattr(self, 'sqlmap_runner') and self.sqlmap_runner.isRunning():
            self.sqlmap_runner.stop()
            self.scan_log_text.append("正在停止扫描...")
            self.scan_status_label.setText("正在停止...")

        # 更新界面状态
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_scan_progress(self, data):
        """更新扫描进度"""
        # 添加消息到日志
        if "message" in data:
            self.scan_log_text.append(data["message"])
            # 滚动到底部
            self.scan_log_text.verticalScrollBar().setValue(
                self.scan_log_text.verticalScrollBar().maximum()
            )

        # 更新进度条
        if "progress" in data:
            self.scan_progress_bar.setValue(data["progress"])

        # 更新漏洞URL
        if "url" in data and data.get("vulnerable", False):
            self.add_to_result_table(
                data["url"],
                True,
                data.get("detail", "")
            )
            # 更新统计信息
            self.total_label.setText(str(self.result_table.rowCount()))
            self.success_label.setText(str(len([
                i for i in range(self.result_table.rowCount())
                if "存在SQL注入" in self.result_table.item(i, 1).text()
            ])))
            self.failed_label.setText(str(len([
                i for i in range(self.result_table.rowCount())
                if "未发现注入" in self.result_table.item(i, 1).text()
            ])))

        # 扫描完成
        if data.get("complete", False):
            # 处理所有URL的结果
            result = data.get("result", {})
            vulnerable_urls = result.get("vulnerable_urls", [])

            # 将所有未添加的URL添加为未发现漏洞
            for url in self.url_manager.param_urls:
                # 检查是否已经添加过这个URL
                found = False
                for i in range(self.result_table.rowCount()):
                    if self.result_table.item(i, 0).text() == url:
                        found = True
                        break

                if not found:
                    self.add_to_result_table(url, False)

    def update_scan_log(self, message):
        """更新扫描日志"""
        self.scan_log_text.append(message)
        # 滚动到底部
        self.scan_log_text.verticalScrollBar().setValue(
            self.scan_log_text.verticalScrollBar().maximum()
        )
        # 强制处理事件，确保界面响应
        QApplication.processEvents()

    def update_scan_result(self, data):
        """更新扫描结果 - 适应简化的表格结构"""
        if "url" in data:
            self.add_to_result_table(
                data["url"],
                data.get("vulnerable", False),
                data.get("detail", "")
            )

            # 更新统计信息
            self.total_label.setText(str(self.result_table.rowCount()))
            self.success_label.setText(str(len([
                i for i in range(self.result_table.rowCount())
                if "存在SQL注入" in self.result_table.item(i, 1).text()
            ])))
            self.failed_label.setText(str(len([
                i for i in range(self.result_table.rowCount())
                if "未发现注入" in self.result_table.item(i, 1).text() and "跳过检测" not in self.result_table.item(i,
                                                                                                                    1).text()
            ])))