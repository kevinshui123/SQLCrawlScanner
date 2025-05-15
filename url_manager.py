#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
from urllib.parse import urlparse, parse_qs


class URLManager:
    """URL管理类：处理URL文件的读写和URL验证"""

    def __init__(self, config):
        self.config = config
        self.urls = []
        self.param_urls = []  # 带参数的URL
        self.grouped_urls = []  # 分组后的代表性URL

    def load_urls(self, file_path=None):
        """从文件加载URL列表"""
        if not file_path:
            file_path = self.config.url_file

        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    self.urls = self._validate_urls(urls)
                return len(self.urls)
            return 0
        except Exception as e:
            print(f"加载URL文件出错: {str(e)}")
            return 0

    def smart_import_urls(self, urls):
        """智能导入URL，自动过滤静态资源和无参数URL"""
        # 过滤前的URL数量
        original_count = len(urls)

        # 定义静态资源扩展名
        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                             '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip']

        # 过滤URL
        filtered_urls = []

        for url in urls:
            try:
                from urllib.parse import urlparse, parse_qs
                parsed_url = urlparse(url)
                path = parsed_url.path.lower()

                # 检查是否为静态资源
                is_static = any(path.endswith(ext) for ext in static_extensions)

                # 检查是否有参数
                query_params = parse_qs(parsed_url.query)
                has_params = len(query_params) > 0

                # 只保留非静态且有参数的URL
                if not is_static and has_params:
                    filtered_urls.append(url)
            except:
                # 如果URL解析出错，保留该URL
                filtered_urls.append(url)

        # 添加到URL列表
        added_count = self.add_urls("\n".join(filtered_urls))

        return {
            "original": original_count,
            "filtered": len(filtered_urls),
            "added": added_count
        }
    
    def save_urls(self, urls, file_path=None):
        """保存URL列表到文件"""
        if not file_path:
            file_path = self.config.url_file

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for url in urls:
                    f.write(f"{url}\n")
            return True
        except Exception as e:
            print(f"保存URL文件出错: {str(e)}")
            return False

    def add_urls(self, urls_text):
        """添加URL列表"""
        urls = [line.strip() for line in urls_text.split('\n') if line.strip()]
        new_urls = self._validate_urls(urls)

        # 添加到现有URL列表，去重
        added_count = 0
        for url in new_urls:
            if url not in self.urls:
                self.urls.append(url)
                added_count += 1

        return added_count

    def filter_param_urls(self):
        """筛选带参数的URL"""
        self.param_urls = [url for url in self.urls if '?' in url and '=' in url]
        return self.param_urls

    def get_params_from_url(self, url):
        """从URL中提取参数，并返回参数名和值"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # 格式化为 "参数名=值" 的列表
            param_list = []
            for param, values in query_params.items():
                value = values[0] if values else ''
                param_list.append(f"{param}={value}")

            return param_list
        except:
            return []

    def _validate_urls(self, urls):
        """验证URL格式"""
        valid_urls = []
        for url in urls:
            # 添加http/https前缀如果没有
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            # 简单格式验证
            if '.' in url:  # 非常基本的验证，可以增强
                valid_urls.append(url)

        return valid_urls

    def export_param_urls(self, file_path):
        """导出带参数的URL到文件"""
        if not self.param_urls:
            self.filter_param_urls()

        return self.save_urls(self.param_urls, file_path)

    def is_static_resource(self, url):
        """判断URL是否为静态资源"""
        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                             '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
                             '.mp3', '.mp4', '.webp', '.tif', '.tiff', '.bmp']

        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            path = parsed_url.path.lower()
            return any(path.endswith(ext) for ext in static_extensions)
        except:
            return False

    def filter_potential_sqli_urls(self):
        """筛选潜在SQL注入URL"""
        # 首先确保有带参数的URL
        if not self.param_urls:
            self.filter_param_urls()

        # 定义常见的数据库参数名
        db_param_names = ['id', 'user_id', 'product_id', 'cat', 'category', 'article',
                          'post', 'page', 'news', 'item', 'order', 'key', 'search', 'query',
                          'username', 'user', 'name', 'pid', 'cid', 'uid', 'sid']

        potential_urls = []

        for url in self.param_urls:
            # 跳过静态资源
            if self.is_static_resource(url):
                continue

            # 解析URL参数
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # 检查是否包含数据库相关参数
            has_db_param = False
            for param in query_params.keys():
                param_lower = param.lower()
                if any(db_name in param_lower for db_name in db_param_names):
                    has_db_param = True
                    break

            # 如果包含数据库相关参数，则可能存在SQL注入
            if has_db_param:
                potential_urls.append(url)

        # 更新潜在URLs列表
        if potential_urls:
            self.param_urls = potential_urls

        return self.param_urls