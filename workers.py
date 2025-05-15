#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
from urllib.parse import urlparse

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
    """SQLMap运行线程 - 每个URL单独运行一个SQLMap进程"""
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)

    def __init__(self, config, url_file, scan_params, smart_scan=True, max_instances=4):
        super(SQLMapRunnerThread, self).__init__()
        self.config = config
        self.url_file = url_file
        self.scan_params = scan_params
        self.smart_scan = smart_scan
        self.running = True
        self.max_instances = max_instances

    def run(self):
        """线程主函数 - 每个URL单独进程"""
        try:
            # 读取URL文件
            urls = []
            try:
                with open(self.url_file, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]

                # 确保URL格式正确
                fixed_urls = []
                for url in urls:
                    if not url.startswith(('http://', 'https://')):
                        url = 'http://' + url
                    fixed_urls.append(url)
                urls = fixed_urls

            except Exception as e:
                self.log_signal.emit(f"读取URL文件出错: {str(e)}")
                return

            if not urls:
                self.log_signal.emit("URL文件为空，没有URL可扫描")
                return

            # 获取SQLMap参数
            sqlmap_parts = self.config.sqlmap_path.split()
            python_exe = sqlmap_parts[0]  # python
            sqlmap_script = sqlmap_parts[1].strip('"')  # sqlmap.py路径

            # 创建工作目录
            output_dir = os.path.join(self.config.output_dir, "single_url_mode")
            os.makedirs(output_dir, exist_ok=True)

            self.log_signal.emit(f"准备扫描 {len(urls)} 个URL，每个URL单独进程")

            # 标准SQLMap参数
            base_params = [
                "--risk", str(self.scan_params.get("risk", 2)),
                "--level", str(self.scan_params.get("level", 2)),
                "--batch",
                "--random-agent",
                "--threads", str(self.scan_params.get("threads", 3)),
                "--timeout", str(self.scan_params.get("timeout", 15)),
                "--dbs"
            ]

            # 使用多线程管理并发进程
            max_concurrent = min(self.max_instances, 4)  # 限制最大并发数
            active_processes = 0
            url_index = 0
            total_urls = len(urls)
            processes = []  # 存储所有进程信息
            active_procs = []  # 存储活动进程

            # 智能扫描域名跟踪
            vulnerable_domains = set()

            while url_index < total_urls and self.running:
                # 检查是否可以启动新进程
                while active_processes < max_concurrent and url_index < total_urls and self.running:
                    url = urls[url_index]
                    url_index += 1

                    # 如果启用智能扫描，检查域名是否已存在漏洞
                    if self.smart_scan:
                        try:
                            domain = urlparse(url).netloc
                            if domain in vulnerable_domains:
                                # 域名已有漏洞，跳过扫描
                                self.log_signal.emit(f"跳过URL: {url} (域名已发现漏洞)")
                                self.result_signal.emit({
                                    "url": url,
                                    "vulnerable": False,
                                    "detail": "跳过检测(同域名已发现漏洞)"
                                })
                                continue
                        except:
                            pass

                    # 构建命令 - 使用单URL模式
                    cmd = [
                              python_exe,
                              sqlmap_script,
                              "-u", url
                          ] + base_params + [
                              "--output-dir", output_dir
                          ]

                    # 显示命令
                    cmd_str = " ".join(cmd)
                    self.log_signal.emit(f"扫描URL ({url_index}/{total_urls}): {url}")
                    self.log_signal.emit(
                        f"执行命令: python C:\\Users\\liamh\\Desktop\\sqlmap\\sqlmap1\\sqlmap.py -u {url} --risk 2 --level 2 --batch --random-agent --output-dir C:\\Users\\liamh\\Desktop\\sql-result --dbs -p mode")

                    # 启动进程
                    try:
                        process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            bufsize=1
                        )

                        # 存储进程信息
                        proc_info = {
                            "process": process,
                            "url": url,
                            "cmd": cmd_str,
                            "output": [],
                            "vulnerable": False,
                            "detail": "",
                            "start_time": time.time()
                        }

                        processes.append(proc_info)
                        active_procs.append(proc_info)
                        active_processes += 1

                    except Exception as e:
                        self.log_signal.emit(f"启动SQLMap进程出错: {str(e)}")
                        # 标记为失败
                        self.result_signal.emit({
                            "url": url,
                            "vulnerable": False,
                            "detail": f"启动失败: {str(e)}"
                        })

                # 检查活动进程的状态
                completed_procs = []
                for proc_info in active_procs:
                    process = proc_info["process"]

                    # 检查是否完成
                    if process.poll() is not None:  # 进程已结束
                        # 获取输出
                        stdout, stderr = process.communicate()

                        # 处理输出
                        if stdout:
                            for line in stdout.splitlines():
                                proc_info["output"].append(line)
                                self.log_signal.emit(line)

                                # 检测漏洞
                                if "is vulnerable" in line:
                                    proc_info["vulnerable"] = True
                                    param_match = re.search(r"Parameter '([^']+)'", line)
                                    if param_match:
                                        proc_info["detail"] = f"参数: {param_match.group(1)}"

                                        # 如果启用智能扫描，添加到漏洞域名
                                        if self.smart_scan:
                                            try:
                                                domain = urlparse(proc_info["url"]).netloc
                                                vulnerable_domains.add(domain)
                                            except:
                                                pass

                        # 发送结果
                        self.result_signal.emit({
                            "url": proc_info["url"],
                            "vulnerable": proc_info["vulnerable"],
                            "detail": proc_info["detail"]
                        })

                        # 标记为完成
                        completed_procs.append(proc_info)
                        active_processes -= 1

                # 从活动进程列表中移除已完成的进程
                for proc_info in completed_procs:
                    active_procs.remove(proc_info)

                # 检查长时间运行的进程
                current_time = time.time()
                for proc_info in active_procs[:]:
                    # 如果进程运行时间超过timeout*2秒，终止它
                    if current_time - proc_info["start_time"] > self.scan_params.get("timeout", 15) * 2:
                        try:
                            proc_info["process"].terminate()
                            self.log_signal.emit(f"终止超时进程: {proc_info['url']}")
                        except:
                            pass

                        # 发送结果
                        self.result_signal.emit({
                            "url": proc_info["url"],
                            "vulnerable": False,
                            "detail": "扫描超时"
                        })

                        # 从活动列表中移除
                        active_procs.remove(proc_info)
                        active_processes -= 1

                # 更新进度
                progress = int((url_index / total_urls) * 100)
                self.progress_signal.emit(progress)

                # 短暂休眠
                time.sleep(0.1)

            # 等待所有活动进程完成
            while active_procs and self.running:
                # 检查活动进程的状态
                completed_procs = []
                for proc_info in active_procs:
                    process = proc_info["process"]

                    # 检查是否完成
                    if process.poll() is not None:  # 进程已结束
                        # 获取输出
                        stdout, stderr = process.communicate()

                        # 处理输出
                        if stdout:
                            for line in stdout.splitlines():
                                proc_info["output"].append(line)
                                self.log_signal.emit(line)

                                # 检测漏洞
                                if "is vulnerable" in line:
                                    proc_info["vulnerable"] = True
                                    param_match = re.search(r"Parameter '([^']+)'", line)
                                    if param_match:
                                        proc_info["detail"] = f"参数: {param_match.group(1)}"

                        # 发送结果
                        self.result_signal.emit({
                            "url": proc_info["url"],
                            "vulnerable": proc_info["vulnerable"],
                            "detail": proc_info["detail"]
                        })

                        # 标记为完成
                        completed_procs.append(proc_info)

                # 从活动进程列表中移除已完成的进程
                for proc_info in completed_procs:
                    active_procs.remove(proc_info)

                # 更新进度
                completed = total_urls - len(active_procs)
                progress = int((completed / total_urls) * 100)
                self.progress_signal.emit(progress)

                # 短暂休眠
                time.sleep(0.1)

            # 终止所有进程（如果停止）
            if not self.running:
                for proc_info in active_procs:
                    try:
                        proc_info["process"].terminate()
                    except:
                        pass

                    # 发送结果
                    self.result_signal.emit({
                        "url": proc_info["url"],
                        "vulnerable": False,
                        "detail": "扫描中断"
                    })

            # 发送100%进度
            self.progress_signal.emit(100)
            self.log_signal.emit("所有URL扫描完成")

        except Exception as e:
            import traceback
            error_text = traceback.format_exc()
            self.log_signal.emit(f"SQLMap运行线程出错: {str(e)}\n{error_text}")

        # 发送完成信号
        self.finished.emit()

    def stop(self):
        """停止扫描"""
        self.running = False
        self.log_signal.emit("正在停止所有SQLMap进程...")