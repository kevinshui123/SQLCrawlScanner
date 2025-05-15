# SQLCrawlScanner

一个基于PyQt5的SQLMap图形界面工具，集成了Web爬虫、URL管理和SQL注入扫描功能。

## 功能特点

- **网站爬虫**：智能爬取网站，自动发现带参数URL
- **URL管理**：过滤、分组和管理爬取到的URL
- **SQL注入扫描**：集成SQLMap进行自动化注入测试
- **结果分析**：清晰展示扫描结果，方便漏洞分析

## 系统要求

- Python 3.6+
- PyQt5
- BeautifulSoup4
- Requests
- SQLMap

## 安装方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/kevinshui123/SQLCrawlScanner.git
   cd SpiderSQLi
   ```

2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

3. 确保SQLMap已安装并配置正确：
   ```bash
   python -m pip install sqlmap
   ```
   或指定本地SQLMap路径

## 使用方法

1. 启动程序：
   ```bash
   python main.py
   ```

2. 输入目标网站，进行爬虫扫描
3. 管理和筛选爬取到的URL
4. 配置SQLMap参数并开始扫描
5. 查看扫描结果

## 主要模块

- **爬虫模块**：智能爬取网站，发现潜在注入点
- **URL管理模块**：整理、过滤和分类URL
- **扫描模块**：调用SQLMap进行批量扫描
- **结果分析模块**：展示漏洞信息

## 项目结构

```
sqlscan/
├── gui/
│   ├── __init__.py
│   └── main_window.py  # 主窗口界面
├── config.py           # 配置管理
├── crawler.py          # 爬虫实现
├── sqlmap_executor.py  # SQLMap调用
├── url_manager.py      # URL管理
├── workers.py          # 工作线程
└── main.py             # 程序入口
```

## 性能优化

- 多线程爬虫
- 智能URL筛选
- SQLMap参数优化
- 爬虫结果智能分组

## 特色功能

1. **智能爬虫**：能够深度解析JavaScript、表单等元素，发现隐藏的参数URL
2. **参数分析**：自动识别和提取URL参数，分析潜在注入点
3. **批量扫描**：支持批量URL扫描，提高测试效率
4. **域名智能分组**：按域名分组管理URL，优化扫描策略
5. **实时监控**：实时显示爬虫和扫描进度，便于监控

## 注意事项

- 本工具仅用于授权的安全测试和教育目的
- 未经授权对网站进行测试可能违反法律
- 请负责任地使用本工具

测试：
![image](https://github.com/user-attachments/assets/706fa589-5663-4aea-8147-80cc3663004c)
![image](https://github.com/user-attachments/assets/aad08aa6-5b5d-4d22-9126-22d282b91149)
![image](https://github.com/user-attachments/assets/a6044841-256a-43ec-b2cf-16c7e36ef9a3)
![image](https://github.com/user-attachments/assets/3cfe7b47-77ae-4073-b84f-7a632782b7a5)




## 致谢

- [SQLMap项目](https://github.com/sqlmapproject/sqlmap)
- PyQt5团队
- 当然还有伟大的Chatgpt和Claude
