#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
import queue
import threading
import urllib.parse
import urllib.robotparser
from PyQt5.QtCore import QThread, pyqtSignal
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse, urlencode, unquote
import urllib3
import random
import hashlib
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EnhancedWebCrawler(QThread):
    """增强版网站爬虫线程 - 专注于发现带参数的URL"""
    log_signal = pyqtSignal(str)  # 日志信号
    url_found_signal = pyqtSignal(list)  # 发送URL列表
    progress_signal = pyqtSignal(int)  # 进度信号

    def __init__(self, targets, depth=3, thread_count=10, timeout=10,
                 param_only=True, skip_static=True, respect_robots=True, smart_crawl=True):
        super().__init__()
        self.worker_threads = None
        self.targets = targets
        self.depth = depth
        self.thread_count = thread_count
        self.timeout = timeout
        self.param_only = param_only
        self.skip_static = skip_static
        self.respect_robots = respect_robots
        self.smart_crawl = smart_crawl
        self.max_urls = 10000  # 设置URL上限

        # 新增的属性
        self.aggressive_form_parsing = True  # 激进的表单处理
        self.follow_subdomains = True  # 跟踪子域名
        self.js_parsing_enabled = True  # 启用JavaScript解析

        self.running = True
        self.visited_urls = set()
        self.found_urls = []
        self.robots_parsers = {}
        self.url_queue = queue.Queue()
        self.lock = threading.Lock()

        # 创建必要的目录
        self.output_dir = "param_spider_output"
        os.makedirs(self.output_dir, exist_ok=True)

        # 高价值参数名称列表
        self.high_value_params = {
            'id', 'uid', 'user_id', 'pid', 'product_id', 'cat', 'category', 'item',
            'page_id', 'news_id', 'article_id', 'post_id', 'file_id', 'doc_id',
            'document_id', 'search', 'query', 'keyword', 'key', 'order', 'sort',
            'view', 'action', 'do', 'func', 'function', 'method', 'op', 'option',
            'act', 'type', 'process', 'mode', 'edit', 'modify', 'update', 'delete',
            'remove', 'show', 'display', 'get', 'select', 'set', 'add', 'create',
            'submit', 'exec', 'execute', 'load', 'write', 'save', 'upload', 'filter',
            'year', 'month', 'day', 'date', 'start', 'end', 'from', 'to', 'min', 'max',
            'price', 'size', 'width', 'height', 'limit', 'offset', 'count', 'cart',
            'checkout', 'payment', 'review', 'comment', 'msg', 'message', 'send',
            'view_mode', 'lang', 'language', 'country', 'region', 'state', 'city'
        }

        # 常见URL模式
        self.valuable_url_patterns = [
            r'/(admin|manage|control|dashboard)[/\w]*',
            r'/(search|find|query|look)[/\w]*',
            r'/(product|item|catalog|shop|store)[/\w]*',
            r'/(user|profile|account|member)[/\w]*',
            r'/(view|display|show|get)[/\w]*',
            r'/(edit|update|modify|change)[/\w]*',
            r'/(delete|remove|destroy)[/\w]*',
            r'/(add|create|insert|new)[/\w]*',
            r'/(api|service|json|xml|rpc)[/\w]*',
            r'/(ajax|async|fetch)[/\w]*',
            r'/(blog|news|article|post)[/\w]*',
            r'/(download|upload|file)[/\w]*',
            r'/(login|signin|register|signup)[/\w]*',
            r'/(cart|basket|checkout|order)[/\w]*',
            r'/(comment|review|rate|feedback)[/\w]*',
            r'/(filter|sort|order)[/\w]*',
            r'/(category|tag|topic|section)[/\w]*',
            r'/(detail|info|desc|description)[/\w]*',
            r'/(config|setting|preference|option)[/\w]*',
            r'/(report|stat|analytic|chart)[/\w]*',
            r'\.(php|aspx|asp|jsp|do)[/\w]*',
            r'\.cgi[/\w]*',
            r'\.action[/\w]*'
        ]
        self.valuable_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.valuable_url_patterns]
        self.domain_param_patterns = {}
        self.url_groups = {}  # 用于跟踪URL分组信息

    def run(self):
        """爬虫主函数"""
        try:
            # 初始化URL队列
            for target in self.targets:
                # 确保目标URL格式正确
                if not target.startswith(('http://', 'https://')):
                    if ':' in target and any(c.isdigit() for c in target.split(':')[1]):
                        target = 'http://' + target  # 有端口号用http
                    else:
                        target = 'https://' + target

                url_info = {
                    'url': target,
                    'depth': 0,
                    'from_url': None,
                    'priority': 0
                }
                self.url_queue.put(url_info)

            self.log_signal.emit(f"初始化爬取队列，{len(self.targets)} 个目标")

            # 创建工作线程
            threads = []
            self.worker_threads = []  # 保存线程引用，便于停止
            for i in range(min(self.thread_count, 50)):
                t = threading.Thread(target=self.crawl_worker)
                t.daemon = True
                threads.append(t)
                self.worker_threads.append(t)  # 保存线程引用
                t.start()

            self.log_signal.emit(f"启动了 {len(threads)} 个爬虫线程")

            # 进度监控
            last_report_time = time.time()
            last_found_count = 0
            last_cleanup_time = time.time()
            last_ui_update_time = time.time()  # 添加用于UI更新的计时器

            while any(t.is_alive() for t in threads) and self.running:
                current_time = time.time()

                # 定期清理缓存
                if current_time - last_cleanup_time > 120:
                    if len(self.robots_parsers) > 10:
                        self.robots_parsers = dict(list(self.robots_parsers.items())[-10:])
                    if len(self.found_urls) > 5000:
                        self.found_urls = self.found_urls[-5000:]
                    last_cleanup_time = current_time

                # 报告进度
                if current_time - last_report_time > 30:
                    current_found = len(self.found_urls)
                    new_found = current_found - last_found_count
                    self.log_signal.emit(f"已访问 {len(self.visited_urls)} 个URL，"
                                         f"队列中还有 {self.url_queue.qsize()} 个，"
                                         f"已找到 {current_found} 个参数URL "
                                         f"(新增 {new_found} 个)")
                    last_report_time = current_time
                    last_found_count = current_found

                # 新增：定期强制发送URL到UI，确保UI更新
                if current_time - last_ui_update_time > 2:  # 每2秒强制更新一次
                    with self.lock:
                        # 从最近的found_urls中提取10个带参数的URL发送到UI
                        param_urls_batch = []
                        counter = 0

                        # 倒序遍历found_urls，找出最近的10个带参数URL
                        for u in reversed(self.found_urls[-100:]):
                            params = self._extract_params_enhanced(u)
                            if params:
                                param_urls_batch.append((u, params))
                                counter += 1
                                if counter >= 10:
                                    break

                        # 如果找到带参数URL，发送到UI
                        if param_urls_batch:
                            print(f"定期更新UI: 发送 {len(param_urls_batch)} 个带参数URL")
                            self.url_found_signal.emit(param_urls_batch)

                    last_ui_update_time = current_time


                # 计算进度
                visited_count = len(self.visited_urls)
                queue_size = self.url_queue.qsize()
                total_estimate = visited_count + queue_size
                if total_estimate > 0:
                    progress = min(int((visited_count / (total_estimate)) * 100), 99)
                    self.progress_signal.emit(progress)

                # 检查队列是否长时间为空
                if self.url_queue.empty():
                    all_waiting = True
                    for t in threads:
                        if t.is_alive() and getattr(t, '_is_waiting', False) == False:
                            all_waiting = False
                            break
                    if all_waiting:
                        self.log_signal.emit("所有线程都在等待，队列为空，停止爬取")
                        break

                time.sleep(0.5)

            # 停止所有线程
            self.running = False
            self.progress_signal.emit(100)

            # 最终发送一次所有带参数URL
            with self.lock:
                final_param_urls = []
                for u in self.found_urls:
                    params = self._extract_params_enhanced(u)
                    if params:
                        final_param_urls.append((u, params))

                # 批量发送，每次最多20个
                batch_size = 20
                for i in range(0, len(final_param_urls), batch_size):
                    batch = final_param_urls[i:i + batch_size]
                    if batch:
                        print(
                            f"最终更新UI: 发送 {len(batch)} 个带参数URL (总批次 {i // batch_size + 1}/{(len(final_param_urls) - 1) // batch_size + 1})")
                        self.url_found_signal.emit(batch)
                        time.sleep(0.1)  # 稍微延迟，确保UI能处理


            # 整理URL
            try:
                self.found_urls = self._normalize_urls(self.found_urls)
                print(f"爬取完成，发现 {len(self.found_urls)} 个URL")
            except Exception as e:
                import traceback
                print(f"URL处理错误: {str(e)}\n{traceback.format_exc()}")

            self.log_signal.emit(f"爬取完成，共访问 {len(self.visited_urls)} 个URL，"
                                 f"发现 {len(self.found_urls)} 个参数URL (去重后)")

        except Exception as e:
            import traceback
            error_text = traceback.format_exc()
            self.log_signal.emit(f"爬虫线程出错: {str(e)}\n{error_text}")

    def _extract_all_js_urls(self, soup, base_url, html_content):
        """增强版JavaScript URL提取"""
        js_urls = []

        try:
            # 从脚本标签中提取
            for script in soup.find_all('script'):
                # 脚本内容
                script_content = script.string
                if script_content:
                    # 查找URL模式
                    js_urls.extend(self._extract_urls_from_text(script_content, base_url))

            # 从内联事件中提取
            event_attrs = ['onclick', 'onchange', 'onsubmit', 'onload', 'onmouseover', 'onmouseout']
            for event in event_attrs:
                elements = soup.find_all(attrs={event: True})
                for element in elements:
                    js_content = element.get(event, '')
                    if js_content:
                        # 查找可能的URL
                        urls = self._extract_urls_from_text(js_content, base_url)
                        js_urls.extend(urls)

            # 从整个HTML中提取URL
            more_urls = self._extract_urls_from_text(html_content, base_url)
            js_urls.extend(more_urls)

            # 查找常见API端点模式
            api_patterns = [
                r'"(https?://[^"]+/api/[^"]+)"',
                r"'(https?://[^']+/api/[^']+)'",
                r'"(/api/[^"]+)"',
                r"'(/api/[^']+)'",
                r'"(https?://[^"]+/rest/[^"]+)"',
                r"'(https?://[^']+/rest/[^']+)'",
                r'"(/rest/[^"]+)"',
                r"'(/rest/[^']+)'",
                r'"(https?://[^"]+/v\d+/[^"]+)"',
                r"'(https?://[^']+/v\d+/[^']+)'",
                r'"(/v\d+/[^"]+)"',
                r"'(/v\d+/[^']+)'"
            ]

            for pattern in api_patterns:
                matches = re.findall(pattern, html_content)
                for match in matches:
                    if match.startswith('/'):
                        full_url = urljoin(base_url, match)
                    else:
                        full_url = match

                    # 如果URL不带参数，添加id参数
                    if '?' not in full_url:
                        full_url = f"{full_url}?id=1"

                    js_urls.append(full_url)

        except Exception as e:
            print(f"JS URL提取出错: {str(e)}")

        return js_urls

    def _extract_pattern_urls(self, soup, base_url):
        """从HTML中提取基于模式的URL，寻找可能的参数化链接"""
        pattern_urls = []

        try:
            # 寻找所有元素
            all_elements = soup.find_all()

            # 常见ID模式
            id_patterns = [
                r'id=(\d+)',
                r'item_id=(\d+)',
                r'product_id=(\d+)',
                r'category_id=(\d+)',
                r'article_id=(\d+)',
                r'page_id=(\d+)',
                r'user_id=(\d+)',
                r'post_id=(\d+)',
                r'news_id=(\d+)'
            ]

            html_text = str(soup)

            # 寻找所有可能的ID模式
            for pattern in id_patterns:
                matches = re.findall(pattern, html_text)
                for match in matches:
                    param_name = pattern.split('=')[0]
                    test_url = f"{base_url}?{param_name}={match}"
                    pattern_urls.append(test_url)

            # 寻找所有数据属性，可能包含URL
            data_attrs = []
            for element in all_elements:
                for attr_name, attr_value in element.attrs.items():
                    if attr_name.startswith('data-') and isinstance(attr_value, str):
                        if 'url' in attr_name.lower() or 'href' in attr_name.lower() or 'link' in attr_name.lower():
                            if attr_value and not attr_value.startswith(('#', 'javascript:')):
                                full_url = urljoin(base_url, attr_value)
                                data_attrs.append(full_url)

                                # 如果URL没有参数，添加一个测试参数
                                if '?' not in full_url:
                                    test_url = f"{full_url}?id=1"
                                    data_attrs.append(test_url)

            pattern_urls.extend(data_attrs)

            # 寻找可能的分页URL
            pagination_containers = []

            # 常见的分页容器
            pagination_containers.extend(
                soup.find_all(class_=lambda c: c and ('pagination' in c.lower() or 'pager' in c.lower())))
            pagination_containers.extend(
                soup.find_all(id=lambda i: i and ('pagination' in i.lower() or 'pager' in i.lower())))

            for container in pagination_containers:
                links = container.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href and not href.startswith(('#', 'javascript:')):
                        full_url = urljoin(base_url, href)
                        pattern_urls.append(full_url)

                # 寻找可能的列表项目
            list_containers = []
            list_containers.extend(soup.find_all(class_=lambda c: c and ('list' in c.lower() or 'items' in c.lower() or 'products' in c.lower())))

            for container in list_containers:
                links = container.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href and not href.startswith(('#', 'javascript:')):
                        full_url = urljoin(base_url, href)
                        pattern_urls.append(full_url)

                        # 分析URL中的数字模式
                        if re.search(r'/\d+/?$', href):
                            # 如果URL以数字结尾，尝试构造更多测试URL
                            parts = href.rstrip('/').split('/')
                            if parts:
                                # 取路径的最后一部分，通常是ID
                                id_value = parts[-1]
                                if id_value.isdigit():
                                    # 生成常见的ID参数测试URL
                                    test_urls = [
                                        f"{full_url}?id={id_value}",
                                        f"{full_url}?item_id={id_value}",
                                        f"{full_url}?product_id={id_value}"
                                    ]
                                    pattern_urls.extend(test_urls)

            # 检查所有表格，可能包含数据行
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    # 查找所有链接
                    links = row.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        if href and not href.startswith(('#', 'javascript:')):
                            full_url = urljoin(base_url, href)
                            pattern_urls.append(full_url)

                    # 查找所有按钮
                    buttons = row.find_all('button')
                    for button in buttons:
                        # 检查data-*属性
                        for attr, value in button.attrs.items():
                            if attr.startswith('data-') and isinstance(value, str) and ('id' in attr or 'url' in attr):
                                if value.isdigit():
                                    # 可能是ID值，构造测试URL
                                    test_url = f"{base_url}?id={value}"
                                    pattern_urls.append(test_url)
                                elif '/' in value:
                                    # 可能是URL路径
                                    full_url = urljoin(base_url, value)
                                    pattern_urls.append(full_url)

            # 检查所有脚本标签，查找硬编码的API调用
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # 查找URL和ID模式
                    api_matches = re.findall(r'(api|rest)/(\w+)/(\d+)', script.string)
                    for match in api_matches:
                        api_type, resource, id_value = match
                        test_url = f"{base_url}/{api_type}/{resource}?id={id_value}"
                        pattern_urls.append(test_url)

                    # 查找GET请求模式
                    get_matches = re.findall(r'get[:\s]+[\'"]([^\'"]*/\w+(?:\?\w+=\w+(?:&\w+=\w+)*)?)[\'"]',
                                             script.string, re.IGNORECASE)
                    for match in get_matches:
                        if not match.startswith(('http://', 'https://')):
                            full_url = urljoin(base_url, match)
                        else:
                            full_url = match
                        pattern_urls.append(full_url)

            # 从JSON-LD和其他结构化数据中提取URL
            ld_scripts = soup.find_all('script', {'type': 'application/ld+json'})
            for ld_script in ld_scripts:
                if ld_script.string:
                    try:
                        # 尝试解析JSON
                        import json
                        ld_data = json.loads(ld_script.string)

                        # 提取所有URL
                        def extract_urls_from_json(obj):
                            urls = []
                            if isinstance(obj, dict):
                                for key, value in obj.items():
                                    if key.lower() in ('url', 'link', 'href') and isinstance(value, str):
                                        urls.append(value)
                                    elif isinstance(value, (dict, list)):
                                        urls.extend(extract_urls_from_json(value))
                            elif isinstance(obj, list):
                                for item in obj:
                                    urls.extend(extract_urls_from_json(item))
                            return urls

                        json_urls = extract_urls_from_json(ld_data)
                        for json_url in json_urls:
                            if not json_url.startswith(('http://', 'https://')):
                                full_url = urljoin(base_url, json_url)
                            else:
                                full_url = json_url
                            pattern_urls.append(full_url)

                    except Exception as e:
                        print(f"解析JSON-LD时出错: {str(e)}")

            # 去重并清理URL
            cleaned_urls = set()
            for url in pattern_urls:
                clean_url = self._clean_url(url)
                if clean_url:
                    cleaned_urls.add(clean_url)

            return list(cleaned_urls)

        except Exception as e:
            print(f"提取模式URL时出错: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return []

    def _extract_urls_from_text(self, text, base_url):
        """从文本中提取所有可能的URL，包括JS、JSON等"""
        urls = []

        if not text:
            return urls

        try:
            # 完整URL模式
            full_urls = re.findall(r'https?://[^\s\'"<>]+', text)
            for url in full_urls:
                # 清理URL
                clean_url = url.rstrip('.,;:\'\"')
                if ')' in clean_url and '(' not in clean_url:
                    clean_url = clean_url.split(')', 1)[0]
                urls.append(clean_url)

            # 相对URL模式
            relative_patterns = [
                r'[\'"]([/][^\s\'"<>]+)[\'"]',  # 引号包围的路径
                r'href=[\'"]([^\s\'"<>]+)[\'"]',  # href属性
                r'src=[\'"]([^\s\'"<>]+)[\'"]',  # src属性
                r'url\([\'"]?([^\s\'"<>)]+)[\'"]?\)',  # CSS URL函数
                r'link[\'"]?:\s*[\'"]([^\s\'"<>]+)[\'"]',  # link属性
                r'path[\'"]?:\s*[\'"]([^\s\'"<>]+)[\'"]'  # path属性
            ]

            for pattern in relative_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    if match and not match.startswith(('http://', 'https://', 'javascript:', 'mailto:', '#')):
                        # 构建完整URL
                        full_url = urljoin(base_url, match)
                        urls.append(full_url)

            # 参数模式
            param_patterns = [
                r'[?&](\w+)=([^&\s]+)',  # 标准查询参数
                r'params\[[\'"](\w+)[\'"]\]\s*=\s*[\'"]([^\'"\s]+)[\'"]',  # JS对象参数
                r'data-(\w+)=[\'"]([^\'"\s]+)[\'"]'  # 数据属性
            ]

            for pattern in param_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    param_name, param_value = match
                    if param_name and param_value:
                        # 构建测试URL
                        test_url = f"{base_url}?{param_name}={param_value}"
                        urls.append(test_url)

            # 去重和清理
            clean_urls = set()
            for url in urls:
                clean_url = self._clean_url(url)
                if clean_url:
                    clean_urls.add(clean_url)

            return list(clean_urls)

        except Exception as e:
            print(f"从文本提取URL时出错: {str(e)}")
            return urls

    def crawl_worker(self):
        """爬虫工作线程 - 强化版，大幅增强表单和JS处理能力"""
        print("工作线程启动")
        # 初始化批量处理相关变量
        url_batch = []
        last_batch_time = time.time()

        # 爬虫线程统计信息
        processed_count = 0
        param_url_count = 0

        while self.running:
            try:
                # 获取URL信息，使用更短的超时
                try:
                    url_info = self.url_queue.get(timeout=0.5)  # 缩短超时时间
                    print(f"处理URL: {url_info['url']}")
                except queue.Empty:
                    # 如果队列为空且停止标志已设置，直接退出
                    if not self.running:
                        print("检测到停止标志，工作线程退出")
                        break
                    print("URL队列为空")
                    time.sleep(0.1)  # 短暂等待以减少CPU使用
                    continue

                # 如果停止标志已设置，立即退出
                if not self.running:
                    print("检测到停止标志，放弃当前URL处理，工作线程退出")
                    self.url_queue.task_done()
                    break

                url = url_info['url']
                depth = url_info['depth']
                from_url = url_info['from_url']

                # 计数
                processed_count += 1
                if processed_count % 100 == 0:
                    print(f"工作线程已处理: {processed_count}个URL, 发现{param_url_count}个带参数URL")

                # 检查URL是否已访问
                with self.lock:
                    if url in self.visited_urls:
                        self.url_queue.task_done()
                        continue

                    # 检查URL数量限制
                    if len(self.visited_urls) >= self.max_urls:
                        self.url_queue.task_done()
                        continue

                    self.visited_urls.add(url)

                # 处理URL格式
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url

                # 标准化URL，移除无用部分
                url = self._clean_url(url)

                # 提取URL参数 - 增强版
                params = self._extract_params_enhanced(url)
                if params:
                    param_url_count += 1
                    print(f"发现带参数URL: {url} 参数: {params}")

                # 判断是否为静态资源并且没有参数
                if self.skip_static and self._is_static_resource(url) and not params:
                    self.url_queue.task_done()
                    continue

                # 尝试进行HTTP请求
                try:
                    # 完整的请求头 - 更像真实浏览器
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1',
                        'Cache-Control': 'max-age=0',
                        'Referer': from_url if from_url else url
                    }

                    # 发送请求，增加超时时间，禁用SSL验证
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )

                    # 记录当前URL到found_urls，不管是什么内容类型
                    with self.lock:
                        self.found_urls.append(url)

                        # 如果有参数，直接添加到批处理
                        if params:
                            url_batch.append((url, params))

                            # 检查是否应该发送批次
                            current_time = time.time()
                            if len(url_batch) >= 10 or current_time - last_batch_time > 0.3:
                                # 复制批处理列表再发送，避免并发问题
                                batch_to_send = url_batch.copy()
                                self.url_found_signal.emit(batch_to_send)
                                url_batch = []
                                last_batch_time = current_time

                    # 检查内容类型
                    content_type = response.headers.get('Content-Type', '').lower()

                    # 处理HTML内容
                    if 'text/html' in content_type or 'application/xhtml+xml' in content_type:
                        # 如果已达到最大深度，不再继续爬取
                        if depth >= self.depth:
                            self.url_queue.task_done()
                            continue

                        # 解析HTML
                        try:
                            soup = BeautifulSoup(response.text, 'html.parser')
                        except Exception as e:
                            print(f"解析HTML出错: {url} - {str(e)}")
                            self.url_queue.task_done()
                            continue

                        # 收集所有新链接
                        new_links = []

                        # 1. 查找所有常规链接
                        for a_tag in soup.find_all('a', href=True):
                            href = a_tag['href'].strip()
                            if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                                next_url = urljoin(url, href)
                                # 加入所有链接，不只是同域名
                                if self.follow_subdomains or self._is_same_domain(url, next_url):
                                    new_links.append(next_url)

                        # 2. 高级表单处理 - 大幅增强这部分
                        form_results = self._process_all_forms(soup, url)
                        if form_results:
                            print(f"从表单提取了 {len(form_results)} 个URL: {url}")
                            new_links.extend(form_results)

                            # 有些表单URL已经带参数，直接添加到批处理
                            for form_url in form_results:
                                form_params = self._extract_params_enhanced(form_url)
                                if form_params:
                                    with self.lock:
                                        self.found_urls.append(form_url)
                                        url_batch.append((form_url, form_params))

                        # 3. 从JS中提取URL
                        js_results = self._extract_all_js_urls(soup, url, response.text)
                        if js_results:
                            print(f"从JS提取了 {len(js_results)} 个URL: {url}")
                            new_links.extend(js_results)

                        # 4. 提取API端点
                        api_results = self._extract_api_endpoints(response.text, url)
                        if api_results:
                            print(f"发现 {len(api_results)} 个API端点: {url}")
                            new_links.extend(api_results)

                        # 5. 使用更多启发式方法寻找URL
                        # 像爬遍页面所有元素寻找URL模式
                        pattern_urls = self._extract_pattern_urls(soup, url)
                        if pattern_urls:
                            print(f"从页面模式中提取了 {len(pattern_urls)} 个URL: {url}")
                            new_links.extend(pattern_urls)

                        # 去重并处理所有发现的链接
                        unique_links = set()
                        for link in new_links:
                            # 清理和标准化URL
                            clean_link = self._clean_url(link)
                            if clean_link and clean_link not in unique_links:
                                unique_links.add(clean_link)

                        # 添加所有链接到队列
                        for next_url in unique_links:
                            # 跳过访问过的URL
                            with self.lock:
                                if next_url in self.visited_urls:
                                    continue

                            # 计算优先级 - 带参数的URL优先级更高
                            priority = 0
                            if '?' in next_url and '=' in next_url:
                                priority -= 20  # 大幅提高带参数URL的优先级

                            # 加入队列
                            next_info = {
                                'url': next_url,
                                'depth': depth + 1,
                                'from_url': url,
                                'priority': priority
                            }
                            self.url_queue.put(next_info)

                    # 处理其他内容类型 - JSON、JavaScript文件等
                    elif 'json' in content_type or 'javascript' in content_type:
                        # 从这些内容中提取可能的URL
                        json_js_urls = self._extract_urls_from_text(response.text, url)
                        if json_js_urls:
                            print(f"从JSON/JS文件中提取了 {len(json_js_urls)} 个URL: {url}")
                            for next_url in json_js_urls:
                                with self.lock:
                                    if next_url in self.visited_urls:
                                        continue

                                self.url_queue.put({
                                    'url': next_url,
                                    'depth': depth + 1,
                                    'from_url': url,
                                    'priority': -10  # 提高这些URL的优先级
                                })

                except requests.exceptions.RequestException as e:
                    print(f"请求出错: {url} - {str(e)}")
                except Exception as e:
                    print(f"处理URL时出错: {url} - {str(e)}")
                    import traceback
                    print(traceback.format_exc())

                self.url_queue.task_done()

            except Exception as e:
                import traceback
                print(f"爬虫工作线程出错: {str(e)}\n{traceback.format_exc()}")
                self.log_signal.emit(f"爬虫工作线程出错: {str(e)}")

        # 在线程结束前发送剩余的批次
        if url_batch:
            with self.lock:
                self.url_found_signal.emit(url_batch)

    def _process_all_forms(self, soup, base_url):
        """增强的表单处理，尝试提取所有可能的表单URL"""
        form_urls = []

        try:
            # 找出所有表单
            forms = soup.find_all('form')
            print(f"在页面找到 {len(forms)} 个表单: {base_url}")

            for form in forms:
                # 获取表单属性
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()

                # 处理相对URL
                if not form_action:
                    form_action = base_url
                elif not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(base_url, form_action)

                # 标准化表单操作URL
                form_action = self._clean_url(form_action)

                # 查找所有输入字段
                inputs = form.find_all(['input', 'select', 'textarea'])
                select_fields = form.find_all('select')

                # 收集所有字段信息
                form_fields = []
                for input_field in inputs:
                    field_name = input_field.get('name', '')
                    if not field_name:
                        continue

                    field_type = input_field.get('type', 'text') if input_field.name == 'input' else input_field.name
                    field_value = input_field.get('value', '')

                    form_fields.append({
                        'name': field_name,
                        'type': field_type,
                        'value': field_value
                    })

                # 更多细致处理选择框
                for select in select_fields:
                    field_name = select.get('name', '')
                    if not field_name:
                        continue

                    options = select.find_all('option')
                    if options:
                        option_values = [opt.get('value', '') for opt in options]
                        form_fields.append({
                            'name': field_name,
                            'type': 'select',
                            'values': option_values
                        })

                # 构建测试值
                test_values = {
                    'text': ['test', '1', 'search'],
                    'number': ['1', '100'],
                    'email': ['test@example.com'],
                    'password': ['password123'],
                    'search': ['test', 'query'],
                    'hidden': [''],  # 保持原值
                    'checkbox': ['on', '1', 'true'],
                    'radio': ['1', 'on', 'selected'],
                    'select': ['1', '0', 'default'],
                    'default': ['1', 'test', 'value']
                }

                # 如果是GET表单或者我们想要更积极地测试
                if form_method == 'get' or self.aggressive_form_parsing:
                    if form_fields:
                        # 为每个字段生成测试URL
                        for field in form_fields:
                            field_name = field.get('name', '')
                            if not field_name:
                                continue

                            field_type = field.get('type', 'default')

                            # 选择测试值
                            values = test_values.get(field_type, test_values['default'])

                            # 对于每个测试值生成一个URL
                            for value in values[:2]:  # 限制每个字段最多2个测试值
                                # 构建URL
                                if '?' in form_action:
                                    form_url = f"{form_action}&{field_name}={value}"
                                else:
                                    form_url = f"{form_action}?{field_name}={value}"

                                form_urls.append(form_url)

                        # 如果有多个字段，为组合字段生成URL
                        if len(form_fields) > 1:
                            # 最多使用3个字段组合
                            filtered_fields = [f for f in form_fields if 'name' in f and f['name']][:3]
                            if filtered_fields:
                                params = {}
                                for field in filtered_fields:
                                    field_name = field['name']
                                    field_type = field.get('type', 'default')
                                    values = test_values.get(field_type, test_values['default'])
                                    params[field_name] = values[0]  # 使用第一个测试值

                                # 构建URL
                                query = urlencode(params)
                                if '?' in form_action:
                                    form_url = f"{form_action}&{query}"
                                else:
                                    form_url = f"{form_action}?{query}"

                                form_urls.append(form_url)

                # 对搜索表单特殊处理
                if any('search' in str(attr).lower() for attr in form.attrs.values()):
                    search_inputs = form.find_all('input', {'type': 'search'})
                    search_inputs += form.find_all('input', {'name': lambda x: x and 'search' in x.lower()})
                    search_inputs += form.find_all('input', {'name': lambda x: x and x.lower() == 'q'})

                    for search_input in search_inputs:
                        field_name = search_input.get('name', '')
                        if field_name:
                            # 添加搜索测试
                            if '?' in form_action:
                                form_url = f"{form_action}&{field_name}=test"
                            else:
                                form_url = f"{form_action}?{field_name}=test"

                            form_urls.append(form_url)

                            # 添加SQL注入测试值
                            sql_test_url = f"{form_action}?{field_name}=1' OR '1'='1"
                            form_urls.append(sql_test_url)

        except Exception as e:
            print(f"表单处理出错: {str(e)}")
            import traceback
            print(traceback.format_exc())

        return form_urls

    def _process_form(self, form, base_url):
        """处理表单，尝试构造带参数的URL"""
        form_urls = []

        try:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()

            # 只处理GET方法的表单
            if form_method != 'get':
                return []

            # 处理相对URL
            if not form_action:
                form_action = base_url
            elif not form_action.startswith(('http://', 'https://')):
                form_action = urljoin(base_url, form_action)

            # 提取表单字段
            form_fields = []
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                field_name = input_tag.get('name', '')
                field_type = input_tag.get('type', 'text') if input_tag.name == 'input' else input_tag.name
                field_value = input_tag.get('value', '')

                if field_name:  # 只考虑有名称的字段
                    form_fields.append({
                        'name': field_name,
                        'type': field_type,
                        'value': field_value
                    })

            # 构造测试值
            test_values = {
                'text': ['test', '1', 'search'],
                'number': ['1', '100'],
                'email': ['test@example.com'],
                'password': ['password123'],
                'search': ['test', 'query'],
                'hidden': [''],  # 保持原值
                'checkbox': ['on', '1', 'true'],
                'radio': ['1', 'on', 'selected'],
                'select': ['1', '0', 'default'],
                'default': ['1', 'test', 'value']
            }

            # 生成测试URL
            if form_fields:
                # 每个字段单独生成URL
                for field in form_fields:
                    field_name = field['name']
                    field_type = field['type']

                    # 根据字段类型选择测试值
                    values = test_values.get(field_type, test_values['default'])

                    # 为每个测试值生成URL
                    for value in values:
                        # 构造参数
                        if '?' in form_action:
                            form_url = f"{form_action}&{field_name}={value}"
                        else:
                            form_url = f"{form_action}?{field_name}={value}"

                        form_urls.append(form_url)

                # 如果有多个字段，还可以组合字段生成URL
                if len(form_fields) > 1:
                    params = {}
                    for field in form_fields[:3]:  # 最多使用前3个字段
                        field_name = field['name']
                        field_type = field['type']
                        values = test_values.get(field_type, test_values['default'])
                        params[field_name] = values[0]  # 使用第一个测试值

                    # 构造查询字符串
                    query_string = urlencode(params)

                    # 构造完整URL
                    if '?' in form_action:
                        form_url = f"{form_action}&{query_string}"
                    else:
                        form_url = f"{form_action}?{query_string}"

                    form_urls.append(form_url)

        except Exception as e:
            print(f"处理表单时出错: {str(e)}")

        return form_urls

    def _extract_js_urls(self, soup, base_url):
        """从JavaScript代码中提取URL"""
        js_urls = []

        try:
            # 查找所有脚本标签
            for script in soup.find_all('script'):
                # 只处理有内容的脚本
                if script.string:
                    # 使用正则表达式查找URL
                    # 1. 查找常规URL
                    urls = re.findall(r'(https?://[^\s\'"]+)', script.string)
                    # 2. 查找相对URL路径
                    relative_urls = re.findall(r'[\'"](/[^\s\'"]*?)[\'"]', script.string)

                    # 处理找到的URL
                    for url in urls:
                        # 检查是否带参数
                        if '?' in url:
                            js_urls.append(url)

                    # 处理相对URL
                    for rel_url in relative_urls:
                        full_url = urljoin(base_url, rel_url)
                        # 添加测试参数
                        if '?' not in full_url:
                            # 为常见ID参数添加测试值
                            test_url = f"{full_url}?id=1"
                            js_urls.append(test_url)
                        else:
                            js_urls.append(full_url)

            # 查找内联事件处理器中的URL
            url_patterns = [
                r'href=[\'"]([^\'"]*?)[\'"]',
                r'src=[\'"]([^\'"]*?)[\'"]',
                r'url\([\'"]?([^\'"]*?)[\'"]?\)',
                r'location[\.\s]=[\s\'"]([^\'"]*?)[\'"]',
                r'location\.href[\s=][\'"]([^\'"]*?)[\'"]',
                r'window\.open\([\'"]([^\'"]*?)[\'"]\)',
                r'ajax\(\s*[\'"]([^\'"]*?)[\'"]\)',
                r'fetch\([\'"]([^\'"]*?)[\'"]\)',
            ]

            # 获取页面的所有HTML
            html_content = str(soup)

            # 在整个HTML中查找URL模式
            for pattern in url_patterns:
                matches = re.findall(pattern, html_content)
                for match in matches:
                    # 处理相对URL
                    if not match.startswith(('http://', 'https://')):
                        match = urljoin(base_url, match)

                    # 检查是否带参数或添加测试参数
                    if '?' in match:
                        js_urls.append(match)
                    else:
                        test_url = f"{match}?id=1"
                        js_urls.append(test_url)

        except Exception as e:
            print(f"从JavaScript提取URL时出错: {str(e)}")

        return js_urls

    def _extract_api_endpoints(self, html_content, base_url):
        """提取API端点"""
        api_urls = []

        try:
            # API端点模式
            api_patterns = [
                r'"(https?://[^"]+/api/[^"]+)"',
                r"'(https?://[^']+/api/[^']+)'",
                r'"(/api/[^"]+)"',
                r"'(/api/[^']+)'",
                r'"(https?://[^"]+/rest/[^"]+)"',
                r"'(https?://[^']+/rest/[^']+)'",
                r'"(/rest/[^"]+)"',
                r"'(/rest/[^']+)'",
                r'"(https?://[^"]+/v\d+/[^"]+)"',
                r"'(https?://[^']+/v\d+/[^']+)'",
                r'"(/v\d+/[^"]+)"',
                r"'(/v\d+/[^']+)'"
            ]

            for pattern in api_patterns:
                endpoints = re.findall(pattern, html_content)
                for endpoint in endpoints:
                    # 处理相对URL
                    if endpoint.startswith('/'):
                        full_endpoint = urljoin(base_url, endpoint)
                    else:
                        full_endpoint = endpoint

                    # 添加测试参数
                    if '?' not in full_endpoint:
                        api_url = f"{full_endpoint}?id=1"
                        api_urls.append(api_url)
                    else:
                        api_urls.append(full_endpoint)

        except Exception as e:
            print(f"提取API端点时出错: {str(e)}")

        return api_urls

    def _process_search_forms(self, soup, base_url):
        """特殊处理搜索表单"""
        search_urls = []

        try:
            # 找出所有的搜索框 - 修复参数传递错误
            search_forms = soup.find_all('form', attrs={'role': 'search'})
            # 修复以下两行，避免参数重复
            search_forms += soup.find_all('form',
                                          id=lambda x: x and ('search' in str(x).lower() or 'find' in str(x).lower()))
            search_forms += soup.find_all('form', attrs={'action': lambda x: x and 'search' in str(x).lower()})

            for search_form in search_forms:
                action = search_form.get('action', '')
                method = search_form.get('method', 'get').lower()

                # 只处理GET方法
                if method != 'get':
                    continue

                # 处理相对URL
                if not action:
                    action = base_url
                elif not action.startswith(('http://', 'https://')):
                    action = urljoin(base_url, action)

                # 寻找搜索字段 - 修复这一部分
                search_inputs = search_form.find_all('input', {'type': 'search'})
                # 避免使用name作为关键字参数
                query_inputs = search_form.find_all(lambda tag: tag.name == 'input' and tag.get('name') and
                                                                ('search' in tag.get('name', '').lower() or
                                                                 tag.get('name', '') == 'q' or
                                                                 'query' in tag.get('name', '').lower()))
                search_inputs.extend(query_inputs)

                for search_input in search_inputs:
                    field_name = search_input.get('name', '')
                    if field_name:
                        # 生成搜索URL
                        if '?' in action:
                            search_url = f"{action}&{field_name}=test"
                        else:
                            search_url = f"{action}?{field_name}=test"

                        search_urls.append(search_url)

                        # 添加SQL注入测试值
                        sql_test_url = f"{action}?{field_name}=1' OR '1'='1"
                        search_urls.append(sql_test_url)

        except Exception as e:
            print(f"处理搜索表单时出错: {str(e)}")
            import traceback
            print(traceback.format_exc())

        return search_urls

    def _generate_test_urls(self, url):
        """生成常见参数的测试URL"""
        test_urls = []

        try:
            # 解析URL
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # 常见参数列表
            common_params = [
                'id', 'page', 'category', 'search', 'q', 'query',
                'item', 'product', 'article', 'post', 'user', 'uid',
                'file', 'action', 'type', 'view', 'sort', 'order',
                'limit', 'offset', 'start', 'end', 'filter', 'lang',
                'date', 'month', 'year', 'day', 'size', 'format',
                'mode', 'style', 'theme', 'dir', 'path', 'name'
            ]

            # 常见ID值
            id_values = ['1', '2', '100', 'test']

            # 检查URL是否已经有参数
            if parsed.query:
                # 已有参数，添加额外参数
                for param in common_params[:5]:  # 只使用前5个参数避免过多
                    if param not in parse_qs(parsed.query):
                        for value in id_values[:2]:  # 只使用前2个值
                            test_url = f"{url}&{param}={value}"
                            test_urls.append(test_url)
            else:
                # 没有参数，添加新参数
                for param in common_params[:10]:  # 只使用前10个参数
                    for value in id_values[:2]:  # 只使用前2个值
                        test_url = f"{base_url}?{param}={value}"
                        test_urls.append(test_url)

                # 添加高价值参数组合
                test_urls.append(f"{base_url}?id=1&page=1")
                test_urls.append(f"{base_url}?product_id=1&category=test")
                test_urls.append(f"{base_url}?search=test&sort=asc")

            # 添加SQL注入测试值 (只对没有参数的URL)
            if not parsed.query:
                test_urls.append(f"{base_url}?id=1'")

        except Exception as e:
            print(f"生成测试URL时出错: {str(e)}")

        return test_urls

    def _calculate_url_priority(self, url):
        """计算URL优先级，值越小越优先"""
        priority = 0

        try:
            # 检查是否有参数
            if '?' in url and '=' in url:
                priority -= 10  # 有参数的URL优先级高

                # 检查是否包含高价值参数
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param in params:
                    if param.lower() in self.high_value_params:
                        priority -= 5  # 高价值参数更高优先级

                # 检查是否为数字ID
                id_params = ['id', 'uid', 'pid', 'product_id', 'item_id']
                for param in id_params:
                    if param in params and params[param] and params[param][0].isdigit():
                        priority -= 3  # 数字ID更高优先级

            # 检查是否为可能的API端点
            if '/api/' in url or '/rest/' in url or '/v1/' in url:
                priority -= 8  # API端点优先级高

            # 检查是否为可能的数据库相关URL
            for pattern in self.valuable_patterns:
                if pattern.search(url):
                    priority -= 5  # 匹配高价值模式的URL优先级高
                    break

            # 检查是否是动态脚本
            if re.search(r'\.(php|aspx|jsp|do|cgi|action)(\?|$)', url):
                priority -= 7  # 动态脚本优先级高

        except Exception as e:
            print(f"计算URL优先级时出错: {str(e)}")

        return priority

    def _is_static_resource(self, url):
        """判断URL是否为静态资源，优化处理方式"""
        # 始终允许带参数的URL，无论扩展名如何
        if '?' in url and '=' in url:
            return False

        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                             '.ico', '.woff', '.woff2', '.ttf', '.eot']  # 减少限制

        parsed_url = urlparse(url)
        path = parsed_url.path.lower()

        # 检查扩展名
        for ext in static_extensions:
            if path.endswith(ext):
                return True

        return False

    def _extract_params_enhanced(self, url):
        """增强版参数提取函数 - 更彻底地提取所有可能的参数"""
        try:
            parsed_url = urlparse(url)

            # 1. 标准查询参数
            query_params = parse_qs(parsed_url.query)

            # 如果找到参数，返回参数名列表
            if query_params:
                params = list(query_params.keys())
                print(f"从URL成功提取参数: {url} -> {params}")
                return params

            # 2. 如果没有参数但URL中有等号，尝试手动解析
            if '=' in url:
                params = []
                if '?' in url:
                    query_part = url.split('?', 1)[1]
                    for param_pair in query_part.split('&'):
                        if '=' in param_pair:
                            param_name = param_pair.split('=', 1)[0]
                            if param_name and param_name not in params:
                                params.append(param_name)

                    if params:
                        print(f"手动提取参数: {url} -> {params}")
                        return params

            # 3. 检查是否有路径参数
            path = parsed_url.path
            if re.search(r'/\d+/?$', path):
                print(f"检测到路径ID参数: {url}")
                return ["id"]

            # 4. 检查连续的路径模式
            path_segments = path.strip('/').split('/')
            if len(path_segments) > 1:
                for i in range(len(path_segments) - 1):
                    # 有类别/ID模式
                    if path_segments[i].isalpha() and i + 1 < len(path_segments) and path_segments[i + 1].isdigit():
                        param_name = path_segments[i].lower().rstrip('s') + "_id"
                        print(f"检测到路径参数模式: {url} -> {param_name}")
                        return [param_name]

            return []
        except Exception as e:
            print(f"增强参数提取出错: {url} - {str(e)}")
            return []

    def log_message(self, message):
        """只在关键节点发送日志信号"""
        important_keywords = ['错误', '完成', '发现', '漏洞']
        if any(keyword in message for keyword in important_keywords):
            self.log_signal.emit(message)

    def _is_same_domain(self, url1, url2):
        """判断两个URL是否属于同一域名"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc

            # 去除可能的www前缀
            if domain1.startswith('www.'):
                domain1 = domain1[4:]
            if domain2.startswith('www.'):
                domain2 = domain2[4:]

            return domain1 == domain2
        except:
            return False

    def is_same_domain(self, url1, url2):
        """判断两个URL是否属于同一域名"""
        return self._is_same_domain(url1, url2)

    def _is_similar_url_exists(self, url):
        """判断URL是否为重复或类似的URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path_parts = parsed.path.split('/')
            query_params = sorted(parse_qs(parsed.query).keys())

            # 生成URL模式签名
            param_sig = ','.join(query_params)
            path_sig = '/'.join([p for p in path_parts if p])
            url_pattern = f"{domain}:{path_sig}:{param_sig}"

            # 检查URL组内是否已有足够多的URL
            if url_pattern in self.url_groups and len(self.url_groups[url_pattern]) >= 5:
                return True

            # 添加到URL分组
            if url_pattern not in self.url_groups:
                self.url_groups[url_pattern] = []
            self.url_groups[url_pattern].append(url)

            return False
        except Exception as e:
            print(f"检查相似URL时出错: {url} - {str(e)}")
            return False

    def _is_allowed_by_robots(self, url):
        """检查URL是否被robots.txt允许访问"""
        if not self.respect_robots:
            return True

        try:
            parsed_url = urlparse(url)
            domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # 检查是否已经获取过robots.txt
            if domain not in self.robots_parsers:
                try:
                    # 获取robots.txt
                    robots_url = f"{domain}/robots.txt"
                    self.log_signal.emit(f"获取 {robots_url}")

                    parser = urllib.robotparser.RobotFileParser()
                    parser.set_url(robots_url)
                    parser.read()

                    self.robots_parsers[domain] = parser
                except Exception as e:
                    self.log_signal.emit(f"获取 {domain}/robots.txt 出错: {str(e)}")
                    # 如果获取失败，默认允许
                    return True

            # 检查URL是否被允许
            parser = self.robots_parsers[domain]
            path = parsed_url.path
            if not path:
                path = '/'

            if parsed_url.query:
                path += f"?{parsed_url.query}"

            return parser.can_fetch('*', path)
        except Exception as e:
            print(f"检查robots.txt时出错: {url} - {str(e)}")
            return True

    def _clean_url(self, url):
        """增强的URL清理函数"""
        if not url:
            return ""

        try:
            # 解码URL
            url = unquote(url)

            # 移除URL中的锚点
            url = url.split('#')[0]

            # 确保URL有正确的协议前缀
            if not url.startswith(('http://', 'https://')):
                if ':' in url and any(c.isdigit() for c in url.split(':')[1]):
                    url = 'http://' + url  # 有端口号用http
                else:
                    url = 'https://' + url

            # 解析URL
            parsed = urlparse(url)

            # 检查是否为域名
            if not parsed.netloc:
                return ""

            # 修复路径中的问题
            path = parsed.path

            # 如果路径有问题，尝试修复
            if '/http' in path or '//' in path:
                path_parts = []
                for part in path.split('/'):
                    if part and not part.startswith('http'):
                        path_parts.append(part)

                # 重建路径
                path = '/' + '/'.join(path_parts)

            # 重建URL
            clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"

            # 保留查询参数
            if parsed.query:
                clean_url += f"?{parsed.query}"

            return clean_url

        except Exception as e:
            print(f"清理URL时出错: {url} - {str(e)}")
            return url

    def _normalize_urls(self, urls):
        """对URL列表进行归一化处理，每类URL只保留少量样本"""
        if not urls:
            return []

        # 按域名和路径分组
        path_groups = {}
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                path = parsed.path

                # 提取参数类型特征
                query_params = parse_qs(parsed.query)
                param_types = sorted([param.lower() for param in query_params.keys()])

                # 创建分组键：域名+路径+参数类型
                group_key = f"{domain}:{path}:{','.join(param_types)}"

                if group_key not in path_groups:
                    path_groups[group_key] = []
                path_groups[group_key].append(url)
            except Exception as e:
                print(f"URL分组时出错: {url} - {str(e)}")

        # 每组只保留1-2个URL
        normalized_urls = []
        for group_urls in path_groups.values():
            # 简单地从每组中选择第一个和最后一个
            if group_urls:
                normalized_urls.append(group_urls[0])

                # 如果组内URL超过5个，再添加一个样本
                if len(group_urls) > 5:
                    normalized_urls.append(group_urls[-1])

        print(f"URL归一化: 原始 {len(urls)} 个 -> 归一化后 {len(normalized_urls)} 个")
        return normalized_urls

    def stop(self):
        """停止爬虫 - 强制停止所有线程"""
        self.running = False
        self.log_signal.emit("正在停止爬虫...")
        print("爬虫停止标志已设置")

        # 清空队列，防止新任务加入
        try:
            while not self.url_queue.empty():
                self.url_queue.get_nowait()
                self.url_queue.task_done()
        except:
            pass

        # 发送一个最终的信号，表明爬虫已停止
        self.log_signal.emit("爬虫已停止")

class WebCrawlerThread(QThread):
    """原始网站爬虫线程 - 保留为兼容性"""
    log_signal = pyqtSignal(str)  # 日志信号
    url_found_signal = pyqtSignal(list)  # 发送URL列表
    progress_signal = pyqtSignal(int)  # 进度信号

    def __init__(self, targets, depth=2, thread_count=10, timeout=10,
                    param_only=True, skip_static=True, respect_robots=True, smart_crawl=True):
        super(WebCrawlerThread, self).__init__()
        # 创建增强爬虫
        self.enhanced_crawler = EnhancedWebCrawler(
            targets, depth, thread_count, timeout,
            param_only, skip_static, respect_robots, smart_crawl
        )

        # 转发信号
        self.enhanced_crawler.log_signal.connect(self.log_signal.emit)
        self.enhanced_crawler.url_found_signal.connect(self.url_found_signal.emit)
        self.enhanced_crawler.progress_signal.connect(self.progress_signal.emit)

        # 保留其他属性
        self.running = True
        self.max_urls = 10000  # 与增强爬虫同步

    def run(self):
        """直接使用增强爬虫"""
        self.enhanced_crawler.start()
        self.enhanced_crawler.wait()  # 等待增强爬虫完成

    def stop(self):
        """停止爬虫 - 确保同时停止内部的增强爬虫"""
        self.running = False
        print("WebCrawlerThread停止标志已设置")
        if hasattr(self, 'enhanced_crawler'):
            self.enhanced_crawler.stop()
