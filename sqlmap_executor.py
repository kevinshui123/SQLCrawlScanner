#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import re
import json


class SQLMapExecutor:
    """SQLMap执行类：负责调用SQLMap并处理输出"""

    def __init__(self, config):
        self.config = config
        # 确保输出目录存在
        os.makedirs(self.config.output_dir, exist_ok=True)

    def build_command(self, url_file, mode="scan", params=None):
        """构建SQLMap命令"""
        if not params:
            params = {}

        # 确保URL文件存在
        if not os.path.exists(url_file):
            print(f"错误: URL文件不存在: {url_file}")
            return None

        # 检查文件内容
        try:
            with open(url_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            if not urls:
                print("警告: URL文件为空")
                return None
        except Exception as e:
            print(f"读取URL文件出错: {str(e)}")
            return None

        # 提取python解释器和sqlmap路径
        sqlmap_parts = self.config.sqlmap_path.split()
        python_exe = sqlmap_parts[0]  # 例如 "python"
        sqlmap_script = sqlmap_parts[1].strip('"')  # 去除引号

        # 基础命令列表
        cmd_parts = [
            python_exe,  # Python 解释器
            sqlmap_script,  # SQLMap 脚本路径
            "-m", url_file,  # 使用文件批量扫描
            "--risk", str(params.get("risk", self.config.risk_level)),
            "--level", str(params.get("level", self.config.test_level)),
            "--batch",
            "--random-agent",
            "--output-dir", self.config.output_dir,
            "--dbs"
        ]

        # 添加指定参数 (-p)，如果提供了
        if "p" in params and params["p"]:
            cmd_parts.append("-p")
            cmd_parts.append(params["p"])

        # 返回命令字符串
        return cmd_parts  # 返回列表而不是字符串

    def execute(self, command_parts, callback=None):
        """执行SQLMap命令 - 改进版"""
        if not command_parts:
            error_msg = "错误: 命令为空"
            print(error_msg)
            if callback:
                callback(error_msg)
            return {"error": error_msg}

        cmd_str = " ".join(command_parts)
        print(f"执行命令: {cmd_str}")

        if callback:
            callback(f"执行命令: {cmd_str}")

        try:
            # 使用命令列表而不是字符串，避免shell解析问题
            process = subprocess.Popen(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,
                shell=False
            )

            # 逐行读取输出，避免阻塞
            output_lines = []

            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                output_lines.append(line)
                print(line)
                if callback:
                    callback(line)

            # 读取错误输出
            stderr, _ = process.communicate()
            if stderr:
                print(f"错误输出: {stderr}")
                if callback:
                    callback(f"错误: {stderr}")

            # 等待进程完成
            return_code = process.wait()

            if return_code != 0:
                error_msg = f"命令执行失败，返回码: {return_code}"
                print(error_msg)
                if callback:
                    callback(error_msg)

            # 解析结果
            result = self._parse_output(output_lines)
            return result

        except Exception as e:
            error_msg = f"执行命令时出错: {str(e)}"
            print(error_msg)
            if callback:
                callback(error_msg)
            import traceback
            traceback.print_exc()
            return {"error": error_msg}

    def _parse_output(self, output_lines):
        """解析SQLMap输出"""
        result = {
            "vulnerable": False,
            "vulnerable_urls": [],
            "databases": []
        }

        current_url = ""

        for line in output_lines:
            # 检测当前URL
            if "testing URL '" in line:
                url_match = re.search(r"testing URL '([^']+)'", line)
                if url_match:
                    current_url = url_match.group(1)

            # 检测漏洞
            elif "is vulnerable" in line:
                result["vulnerable"] = True

                param_match = re.search(r"Parameter '([^']+)'", line)
                if param_match and current_url:
                    param = param_match.group(1)
                    result["vulnerable_urls"].append((current_url, param))

            # 检测恢复的注入点
            elif "sqlmap resumed the following injection point" in line:
                result["vulnerable"] = True
                # 继续处理以获取参数信息

            # 检测数据库列表
            elif "available databases [" in line:
                db_match = re.search(r'available databases \[\d+\]:\s+\[(.*?)\]', line)
                if db_match:
                    dbs_str = db_match.group(1)
                    result["databases"] = [db.strip().strip("'") for db in dbs_str.split(",")]

        return result

    def get_databases(self, url_file, callback=None):
        """获取数据库列表"""
        params = {
            "auto_exploit": False,
            "risk": self.config.risk_level,
            "level": self.config.test_level,
            "threads": self.config.threads,
            "timeout": self.config.timeout,
            "technique": self.config.technique,
            "tamper": self.config.tamper_scripts
        }

        command = self.build_command(url_file, "scan", params)
        return self.execute(command, callback)

    def scan_and_exploit(self, url_file, params, callback=None):
        """扫描并利用SQL注入"""
        command = self.build_command(url_file, "scan", params)
        return self.execute(command, callback)

    def dump_table(self, url_file, db, table, callback=None):
        """导出指定表数据"""
        params = {
            "auto_exploit": True,
            "risk": self.config.risk_level,
            "level": self.config.test_level,
            "threads": self.config.threads,
            "timeout": self.config.timeout,
            "technique": self.config.technique,
            "tamper": self.config.tamper_scripts,
            "db": db,
            "table": table,
            "rows": self.config.extract_rows,
            "cols": self.config.extract_cols
        }

        command = self.build_command(url_file, "dump", params)
        return self.execute(command, callback)