@echo off
REM SQLMap GUI Tool 一键启动脚本
echo ===== 启动 SQLMap GUI 工具 =====
echo 作者: SQLi安全团队
echo 版本: 1.0

REM 设置当前目录
cd /d "%~dp0"

echo 当前工作目录: %CD%

REM 检查Python环境
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 未检测到Python环境，请安装Python(3.6+)后再运行本程序
    pause
    exit /b 1
)

REM 检查PyQt5
python -c "import PyQt5" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo 正在安装PyQt5模块...
    pip install PyQt5
)

REM 创建必要的目录
if not exist "gui" mkdir "gui"
if not exist "sql-result" mkdir "sql-result"

REM 检查并拷贝所需文件
if not exist "gui\__init__.py" (
    echo. > "gui\__init__.py"
    echo 创建了 gui\__init__.py
)

if not exist "gui\main_window.py" (
    if exist "main_window.py" (
        copy "main_window.py" "gui\main_window.py" >nul
        echo 已将 main_window.py 复制到 gui 目录
    ) else (
        echo [警告] 未找到 main_window.py 文件
    )
)

echo.
echo 配置完成，正在启动SQLMap GUI工具...
echo.

REM 启动程序
python main.py

REM 检查是否正常退出
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [错误] 程序异常退出，错误代码: %ERRORLEVEL%
    echo 可能的原因:
    echo 1. Python模块缺失
    echo 2. GUI代码存在错误
    echo 3. SQLMap路径配置不正确
    echo.
    echo 尝试手动运行以下命令查看详细错误:
    echo python main.py
) else (
    echo.
    echo 程序已正常关闭
)

echo.
echo 按任意键退出...
pause >nul