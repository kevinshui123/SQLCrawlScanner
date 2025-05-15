#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtCore import QThread, pyqtSignal
import subprocess
import os
import re


class BatchScanThread(QThread):
    """批量扫描线程 - 用于逐个扫描多个URL"""
    url_start_signal = pyqtSignal(str, int, int)  # URL, 当前索引, 总数
    url_finish_signal = pyqtSignal(str, bool, str)  # URL, 是否漏洞, 详情
    log_signal = pyqtSignal(str)  # 日志信号
    progress_signal = pyqtSignal(int)  # 进度信号
    finished = pyqtSignal()  # 完成信号

    def __init__(self, parent, url_file, params):
        super(BatchScanThread, self).__init__()
        self.parent = parent
        self.url_file = url_file
        self.params = params
        self.running = True

    def run(self):
        """线程主函数"""
        try:
            # 读取所有URL
            with open(self.url_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]

            if not urls:
                self.log_signal.emit("没有URL可扫描")
                return

            # 创建单URL文件
            single_url_file = os.path.join(self.parent.config.output_dir, "single_url.txt")

            # 逐个处理URL
            for i, url in enumerate(urls):
                if not self.running:
                    self.log_signal.emit("扫描已中止")
                    break

                # 发送URL开始扫描的信号
                self.url_start_signal.emit(url, i, len(urls))

                # 更新进度
                progress = int((i / len(urls)) * 100)
                self.progress_signal.emit(progress)

                # 创建单URL文件
                with open(single_url_file, 'w', encoding='utf-8') as f:
                    f.write(url + '\n')

                # 漏洞标志
                found_vulnerable = False
                vulnerability_detail = ""

                # 创建临时函数捕获输出
                def update_log_for_url(message):
                    # 发送日志
                    self.log_signal.emit(message)

                    # 检测漏洞
                    nonlocal found_vulnerable, vulnerability_detail
                    if "is vulnerable" in message:
                        found_vulnerable = True
                        param_match = re.search(r"Parameter '([^']+)'", message)
                        if param_match:
                            param = param_match.group(1)
                            vulnerability_detail = f"参数: {param}"

                # 执行扫描
                self.parent.sqlmap_executor.scan_and_exploit(
                    single_url_file,
                    self.params,
                    update_log_for_url
                )

                # 发送URL完成扫描的信号
                self.url_finish_signal.emit(url, found_vulnerable, vulnerability_detail)

            # 发送100%进度信号
            self.progress_signal.emit(100)



        except Exception as e:
            import traceback
            self.log_signal.emit(f"批量扫描出错: {str(e)}")
            self.log_signal.emit(traceback.format_exc())

        # 发送完成信号
        self.finished.emit()

    def stop(self):
        """停止扫描"""
        self.running = False


class SQLMapThread(QThread):
    """SQLMap执行线程 - 真正独立的线程"""
    log_signal = pyqtSignal(str)  # 日志信号
    result_signal = pyqtSignal(dict)  # 结果信号

    def __init__(self, sqlmap_executor, url_file, params):
        super(SQLMapThread, self).__init__()
        self.sqlmap_executor = sqlmap_executor
        self.url_file = url_file
        self.params = params
        self.running = True

    def run(self):
        """线程主函数"""
        self.log_signal.emit("开始SQLMap扫描...")

        try:
            # 构建命令
            cmd_parts = self.sqlmap_executor.build_command(self.url_file, "scan", self.params)

            if not cmd_parts:
                self.log_signal.emit("错误: 无法构建SQLMap命令")
                return

            # 创建进程
            process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,
                shell=False
            )

            # 解析结果变量
            result = {
                "vulnerable": False,
                "vulnerable_urls": [],
                "databases": []
            }

            # 当前URL和参数
            current_url = ""

            # 读取输出
            for line in iter(process.stdout.readline, ''):
                if not self.running:
                    process.terminate()
                    self.log_signal.emit("扫描已中止")
                    break

                line = line.strip()
                if not line:
                    continue

                # 发送日志
                self.log_signal.emit(line)

                # 解析结果
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

                        # 发送单个URL结果信号
                        self.result_signal.emit({
                            "url": current_url,
                            "vulnerable": True,
                            "detail": f"参数: {param}"
                        })

                # 检测数据库列表
                elif "available databases [" in line:
                    db_match = re.search(r'available databases \[\d+\]:\s+\[(.*?)\]', line)
                    if db_match:
                        dbs_str = db_match.group(1)
                        result["databases"] = [db.strip().strip("'") for db in dbs_str.split(",")]

            # 读取错误输出
            stderr = process.stderr.read()
            if stderr:
                self.log_signal.emit(f"错误: {stderr}")

            # 发送完成日志
            self.log_signal.emit("扫描完成")

        except Exception as e:
            import traceback
            self.log_signal.emit(f"扫描线程出错: {str(e)}")
            self.log_signal.emit(traceback.format_exc())

    def stop(self):
        """停止扫描"""
        self.running = False

class ScanWorkerThread(QThread):
    """扫描工作线程 - 防止界面卡死"""
    log_signal = pyqtSignal(str)  # 日志信号
    result_signal = pyqtSignal(dict)  # 结果信号
    finished = pyqtSignal()  # 完成信号

    def __init__(self, parent, url_file, params):
        super(ScanWorkerThread, self).__init__()
        self.parent = parent
        self.url_file = url_file
        self.params = params
        self.running = True
        self.process = None

    def run(self):
        """线程主函数"""
        self.log_signal.emit("开始扫描...")

        try:
            # 构建命令
            python_exe = "python"
            sqlmap_path = self.parent.config.sqlmap_path.replace("python ", "").strip('"')

            # 基础命令列表
            cmd = [
                python_exe,
                sqlmap_path,
                "-m", self.url_file,
                "--risk", str(self.params.get("risk", 1)),
                "--level", str(self.params.get("level", 1)),
                "--batch",
                "--random-agent",
                "--output-dir", self.parent.config.output_dir,
                "--dbs"
            ]

            # 添加指定参数 (-p)，如果提供了
            if "p" in self.params and self.params["p"]:
                cmd.extend(["-p", self.params["p"]])

            # 输出命令
            cmd_str = " ".join(cmd)
            self.log_signal.emit(f"执行命令: {cmd_str}")

            # 启动进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # 行缓冲
            )

            # 读取标准输出
            current_url = ""
            for line in iter(self.process.stdout.readline, ''):
                if not self.running:
                    break

                line = line.strip()
                if line:
                    self.log_signal.emit(line)

                    # 解析测试URL
                    if "testing URL" in line:
                        url_match = re.search(r"testing URL '([^']+)'", line)
                        if url_match:
                            current_url = url_match.group(1)

                    # 解析漏洞
                    elif "is vulnerable" in line:
                        param_match = re.search(r"Parameter '([^']+)'", line)
                        if param_match and current_url:
                            param = param_match.group(1)
                            self.result_signal.emit({
                                "url": current_url,
                                "vulnerable": True,
                                "detail": f"参数: {param}"
                            })

            # 读取错误输出
            stderr = self.process.stderr.read()
            if stderr:
                self.log_signal.emit(f"错误: {stderr}")

            # 检查进程退出码
            return_code = self.process.wait()
            if return_code != 0:
                self.log_signal.emit(f"SQLMap退出码: {return_code}")

            self.log_signal.emit("扫描完成")

        except Exception as e:
            self.log_signal.emit(f"扫描过程出错: {str(e)}")

        # 发送完成信号
        self.finished.emit()

    def stop(self):
        """停止扫描"""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.log_signal.emit("扫描进程已终止")
            except:
                pass

class ScanThread(QObject):
    """扫描线程：处理SQLMap扫描任务"""
    progress = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, url_file, sqlmap_executor, params):
        super(ScanThread, self).__init__()
        self.url_file = url_file
        self.sqlmap_executor = sqlmap_executor
        self.params = params
        self.running = True

    def run(self):
        """执行扫描任务"""
        try:
            # 发送开始消息
            mode = "检测并自动利用" if self.params.get("auto_exploit", False) else "检测"
            self.progress.emit({
                "message": f"开始{mode}SQL注入...",
                "progress": 0
            })

            # 回调函数，用于更新进度
            def update_progress(message):
                if not self.running:
                    return

                # 尝试提取进度信息
                progress = 0
                current_url = ""

                # 如果是测试URL的消息
                if "testing URL" in message:
                    url_match = re.search(r"testing URL '([^']+)'", message)
                    if url_match:
                        current_url = url_match.group(1)
                        self.progress.emit({
                            "message": f"正在测试: {current_url}",
                            "url": current_url
                        })

                # 如果是发现漏洞的消息
                elif "is vulnerable" in message:
                    param_match = re.search(r"Parameter '([^']+)'", message)
                    if param_match and current_url:
                        param = param_match.group(1)
                        self.progress.emit({
                            "message": f"发现SQL注入漏洞: {current_url} (参数: {param})",
                            "url": current_url,
                            "vulnerable": True,
                            "detail": f"参数: {param}"
                        })

                # 其他常规消息
                else:
                    self.progress.emit({
                        "message": message
                    })

            # 执行扫描
            result = self.sqlmap_executor.scan_and_exploit(
                self.url_file,
                self.params,
                update_progress
            )

            # 发送完成信息
            if result.get("vulnerable", False):
                self.progress.emit({
                    "message": f"扫描完成，发现 {len(result.get('vulnerable_urls', []))} 个SQL注入漏洞",
                    "progress": 100,
                    "complete": True,
                    "result": result
                })
            else:
                self.progress.emit({
                    "message": "扫描完成，未发现SQL注入漏洞",
                    "progress": 100,
                    "complete": True,
                    "result": result
                })

            # 发送完成信号
            self.finished.emit()

        except Exception as e:
            # 发送错误消息
            self.progress.emit({
                "message": f"扫描过程中出错: {str(e)}",
                "progress": 0,
                "error": str(e)
            })

            # 仍然发送完成信号
            self.finished.emit()

    def stop(self):
        """停止扫描"""
        self.running = False


class DataExtractThread(QObject):
    """数据提取线程：处理表数据提取任务"""
    progress = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, url_file, sqlmap_executor, db, table):
        super(DataExtractThread, self).__init__()
        self.url_file = url_file
        self.sqlmap_executor = sqlmap_executor
        self.db = db
        self.table = table
        self.running = True

    def run(self):
        """执行数据提取任务"""
        try:
            # 发送开始消息
            self.progress.emit({
                "message": f"开始提取数据库 {self.db} 表 {self.table} 的数据...",
                "progress": 0
            })

            # 回调函数，用于更新进度
            def update_progress(message):
                if not self.running:
                    return

                # 发送消息更新
                self.progress.emit({
                    "message": message
                })

            # 执行提取
            result = self.sqlmap_executor.dump_table(
                self.url_file,
                self.db,
                self.table,
                update_progress
            )

            # 发送完成信息
            self.progress.emit({
                "message": f"数据提取完成",
                "progress": 100,
                "complete": True,
                "result": result
            })

            # 发送完成信号
            self.finished.emit()

        except Exception as e:
            # 发送错误消息
            self.progress.emit({
                "message": f"提取数据过程中出错: {str(e)}",
                "progress": 0,
                "error": str(e)
            })

            # 仍然发送完成信号
            self.finished.emit()

    def stop(self):
        """停止提取"""
        self.running = False


class SQLMapRunnerThread(QThread):
    """逐个URL运行SQLMap的线程 - 支持智能扫描"""
    log_signal = pyqtSignal(str)  # 日志信号
    result_signal = pyqtSignal(dict)  # 结果信号
    progress_signal = pyqtSignal(int)  # 进度信号

    def __init__(self, config, url_file, scan_params, smart_scan=True):
        super(SQLMapRunnerThread, self).__init__()
        self.config = config
        self.url_file = url_file
        self.scan_params = scan_params
        self.smart_scan = smart_scan  # 是否启用智能扫描
        self.running = True

    def run(self):
        """线程主函数"""
        try:
            # 读取URL文件
            urls = []
            try:
                with open(self.url_file, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log_signal.emit(f"读取URL文件出错: {str(e)}")
                return

            if not urls:
                self.log_signal.emit("URL文件为空，没有URL可扫描")
                return

            # 日志文件
            log_dir = os.path.join(self.config.output_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)

            # 获取SQLMap路径
            sqlmap_parts = self.config.sqlmap_path.split()
            python_exe = sqlmap_parts[0]  # 例如 "python"
            sqlmap_script = sqlmap_parts[1].strip('"')  # 去除引号

            # 智能扫描需要跟踪已检测到漏洞的域名
            vulnerable_domains = set()

            # 添加域名跟踪
            scanned_domains = set()
            domain_param_patterns = {}

            # 逐个处理URL
            for i, url in enumerate(urls):
                if not self.running:
                    self.log_signal.emit("扫描已中止")
                    break

                # 更新进度
                progress = int((i / len(urls)) * 100)
                self.progress_signal.emit(progress)

                # 解析URL域名和参数模式
                try:
                    from urllib.parse import urlparse, parse_qs
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    query_params = parse_qs(parsed_url.query)
                    param_pattern = ','.join(sorted(query_params.keys()))
                except:
                    domain = "unknown"
                    param_pattern = ""

                # 如果启用智能扫描且该域名已被检测出漏洞，则跳过
                if self.smart_scan and domain in vulnerable_domains:
                    self.log_signal.emit(f"\n--- 跳过URL [{i + 1}/{len(urls)}]: {url} ---")
                    self.log_signal.emit(f"原因: 该域名 ({domain}) 已检测到存在SQL注入漏洞")

                    # 添加到结果表中，但标记为已跳过
                    self.result_signal.emit({
                        "url": url,
                        "vulnerable": False,
                        "detail": "跳过检测(同域名已发现漏洞)"
                    })

                    continue

                # 如果启用智能扫描且该域名参数模式已被扫描，则跳过
                domain_param_key = f"{domain}:{param_pattern}"
                if self.smart_scan and domain_param_key in domain_param_patterns:
                    result = domain_param_patterns[domain_param_key]
                    is_vulnerable = result.get("vulnerable", False)
                    detail = result.get("detail", "")

                    self.log_signal.emit(f"\n--- 跳过URL [{i + 1}/{len(urls)}]: {url} ---")
                    self.log_signal.emit(f"原因: 类似URL已扫描 ({domain}，参数: {param_pattern})")

                    # 直接使用之前的结果
                    self.result_signal.emit({
                        "url": url,
                        "vulnerable": is_vulnerable,
                        "detail": detail if is_vulnerable else "跳过检测(类似URL已扫描)"
                    })

                    continue

                # 检查是否为静态资源
                static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                                     '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
                                     '.mp3', '.mp4', '.webp', '.tif', '.tiff', '.bmp']
                path = parsed_url.path.lower()
                if any(path.endswith(ext) for ext in static_extensions):
                    self.log_signal.emit(f"\n--- 跳过URL [{i + 1}/{len(urls)}]: {url} ---")
                    self.log_signal.emit(f"原因: 静态资源文件不太可能存在SQL注入漏洞")

                    # 添加到结果表中，但标记为已跳过
                    self.result_signal.emit({
                        "url": url,
                        "vulnerable": False,
                        "detail": "跳过检测(静态资源文件)"
                    })

                    continue

                # 开始扫描当前URL
                self.log_signal.emit(f"\n--- 扫描URL [{i + 1}/{len(urls)}]: {url} ---")

                # 自动从URL中提取参数
                params = []
                if '?' in url:
                    query_part = url.split('?')[1]
                    if '&' in query_part:
                        param_pairs = query_part.split('&')
                        for pair in param_pairs:
                            if '=' in pair:
                                param_name = pair.split('=')[0]
                                params.append(param_name)
                    elif '=' in query_part:
                        param_name = query_part.split('=')[0]
                        params.append(param_name)

                # 创建单URL文件
                single_url_file = os.path.join(self.config.output_dir, "single_url.txt")

                try:
                    with open(single_url_file, 'w', encoding='utf-8') as f:
                        f.write(url + '\n')
                except Exception as e:
                    self.log_signal.emit(f"创建单URL文件时出错: {str(e)}")
                    continue

                # 构建命令
                cmd = [
                    python_exe,
                    sqlmap_script,
                    "-u", url,
                    "--risk", str(self.scan_params.get("risk", 1)),
                    "--level", str(self.scan_params.get("level", 1)),
                    "--batch",
                    "--random-agent",
                    "--output-dir", self.config.output_dir,
                    "--dbs"
                ]

                # 如果检测到参数，使用-p指定
                if params:
                    param_str = ",".join(params)
                    cmd.extend(["-p", param_str])
                    self.log_signal.emit(f"检测到URL参数: {param_str}")

                # 日志信息
                cmd_str = " ".join(cmd)
                self.log_signal.emit(f"执行命令: {cmd_str}")

                # 创建进程
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,
                    shell=False
                )

                # 漏洞标志和详情
                vulnerable = False
                detail = ""
                vulnerable_param = ""

                # 读取输出
                for line in iter(process.stdout.readline, ''):
                    if not self.running:
                        process.terminate()
                        self.log_signal.emit("扫描已中止")
                        break

                    line = line.strip()
                    if not line:
                        continue

                    # 发送日志
                    self.log_signal.emit(line)

                    # 检测漏洞
                    if "is vulnerable" in line:
                        vulnerable = True
                        param_match = re.search(r"Parameter '([^']+)'", line)
                        if param_match:
                            vulnerable_param = param_match.group(1)
                            detail = f"参数: {vulnerable_param}"

                # 读取错误输出
                stderr = process.stderr.read()
                if stderr:
                    self.log_signal.emit(f"错误: {stderr}")

                # 等待进程完成
                return_code = process.wait()

                # 发送结果信号
                self.result_signal.emit({
                    "url": url,
                    "vulnerable": vulnerable,
                    "detail": detail
                })

                # 如果发现漏洞，将域名添加到已漏洞域名集合
                if vulnerable and self.smart_scan:
                    vulnerable_domains.add(domain)
                    self.log_signal.emit(f"已将域名 {domain} 添加到跳过列表(发现漏洞)")

                # 保存扫描结果
                domain_param_patterns[domain_param_key] = {
                    "vulnerable": vulnerable,
                    "detail": detail
                }

            # 完成所有URL
            self.progress_signal.emit(100)
            self.log_signal.emit("\n所有URL扫描完成!")

        except Exception as e:
            import traceback
            error_text = traceback.format_exc()
            self.log_signal.emit(f"扫描线程出错: {str(e)}\n{error_text}")

        # 发送完成信号
        self.finished.emit()

    def stop(self):
        """停止扫描"""
        self.running = False