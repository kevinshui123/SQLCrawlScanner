#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import threading

# 增加递归限制
sys.setrecursionlimit(5000)  # 增加递归深度限制

# 增加线程栈大小 (仅适用于Windows)
try:
    threading.stack_size(4*1024*1024)  # 设置栈大小为4MB
except:
    pass  # 如果不支持，则忽略

import os
import traceback
from PyQt5.QtWidgets import QApplication, QMessageBox
from gui.main_window import MainWindow
from config import Config
from crawler import WebCrawlerThread  # 导入爬虫线程类


# 添加这个函数在main函数之前
def exception_hook(exctype, value, tb):
    """全局异常处理器"""
    error_msg = ''.join(traceback.format_exception(exctype, value, tb))
    print(f"错误: {error_msg}")

    # 显示错误对话框
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle("程序错误")
    msg_box.setText("程序遇到了错误并需要关闭。")
    msg_box.setDetailedText(error_msg)
    msg_box.exec_()


def main():
    """主函数"""
    # 设置全局异常钩子
    sys.excepthook = exception_hook

    # 检查环境
    if not check_environment():
        print("环境检查失败，程序可能无法正常运行")
        return 1

    # 创建应用
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # 使用Fusion风格，在不同平台上保持一致外观

    # 加载配置
    config = Config()

    # 创建主窗口
    window = MainWindow(config)
    window.show()

    # 执行应用
    return app.exec_()


def check_environment():
    """检查运行环境"""
    try:
        # 检查目录结构
        if not os.path.exists("gui"):
            os.makedirs("gui", exist_ok=True)
            print("已创建gui目录")

        # 确保输出目录存在
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "sql-result")
        os.makedirs(output_dir, exist_ok=True)

        return True
    except Exception as e:
        print(f"检查环境时出错: {str(e)}")
        return False


def main():
    """主函数"""
    # 检查环境
    if not check_environment():
        print("环境检查失败，程序可能无法正常运行")
        return 1

    # 创建应用
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # 使用Fusion风格，在不同平台上保持一致外观

    # 加载配置
    config = Config()

    # 创建主窗口
    window = MainWindow(config)
    window.show()

    # 执行应用
    return app.exec_()


# 添加全局异常处理器
def exception_hook(exctype, value, tb):
    """全局异常处理器"""
    error_msg = ''.join(traceback.format_exception(exctype, value, tb))
    print(f"错误: {error_msg}")

    # 显示错误对话框
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle("程序错误")
    msg_box.setText("程序遇到了错误并需要关闭。")
    msg_box.setDetailedText(error_msg)
    msg_box.exec_()


# 确保在主函数开始时设置异常钩子
sys.excepthook = exception_hook


if __name__ == "__main__":
    sys.exit(main())