@echo off
setlocal enabledelayedexpansion

REM 设置命令行编码为UTF-8
chcp 65001

REM 切换到目标目录
cd /d "D:\Program Files\modifyingSecurityGroup\"

REM 创建日志目录（如果不存在）
if not exist "logs\" mkdir logs

REM 生成带时间戳的日志文件名
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value ^| findstr "LocalDateTime"') do set "datetime=%%a"
set "logfile=logs\execution_!datetime:~0,8!_!datetime:~8,6!.log"

REM 执行程序并记录日志
echo [Start Time] !date! !time! >> "!logfile!"
modifyingSecurityGroup.exe --minRequiredIPs 2 --maxRequiredIPs 5 >> "!logfile!" 2>&1
echo [End Time] !date! !time! >> "!logfile!"