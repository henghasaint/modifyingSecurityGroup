#!/bin/bash

# 设置编码为UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# 切换到目标目录
cd "/data/workspace/projects-code/modifyingSecurityGroup/" || {
    echo "Error: Cannot change to target directory"
    exit 1
}

# 创建日志目录（如果不存在）
mkdir -p logs

# 生成带时间戳的日志文件名
datetime=$(date +"%Y%m%d_%H%M%S")
logfile="logs/execution_${datetime}.log"

# 执行程序并记录日志
{
    echo "[Start Time] $(date '+%Y-%m-%d %H:%M:%S')"
    ./modifyingSecurityGroup_linux --minRequiredIPs 1 --maxRequiredIPs 10
    echo "[End Time] $(date '+%Y-%m-%d %H:%M:%S')"
} >> "$logfile" 2>&1

echo "Execution completed. Log saved to: $logfile"
