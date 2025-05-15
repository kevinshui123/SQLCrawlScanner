#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os


class Config:
    """配置类：存储全局设置和路径"""

    def __init__(self):
        # SQLMap路径配置
        self.sqlmap_path = self._find_sqlmap_path()

        # 输出目录
        self.output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "sql-result")
        os.makedirs(self.output_dir, exist_ok=True)

        # URL处理设置
        self.url_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url.txt")

        # SQLMap设置默认值
        self.risk_level = 2
        self.test_level = 2
        self.threads = 5  # 默认每实例线程数
        self.instances = 4  # 默认并发实例数
        self.timeout = 15  # 默认超时时间
        self.technique = "BEUSTQ"  # 默认使用所有技术
        self.tamper_scripts = ["space2comment", "charencode"]
        self.auto_exploit = False
        self.extract_rows = 20
        self.extract_cols = 5

    def _find_sqlmap_path(self):
        """查找SQLMap路径"""
        # 尝试几种可能的路径
        possible_paths = [
            r"C:\sqlmap\sqlmap.py",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "sqlmap", "sqlmap.py"),
            r"C:\Web-Secure\Other-Exploit\sqlmap-master\sqlmap.py",
            r"C:\Users\liamh\Desktop\sqlmap\sqlmap1\sqlmap.py"  # 从您之前的代码看到的路径
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return f"python \"{path}\""

        # 如果未找到sqlmap，提示用户选择
        return "python sqlmap.py"  # 默认值，假设sqlmap已添加到PATH中