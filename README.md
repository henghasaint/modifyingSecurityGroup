# 前置条件

## 获得你当前局域网的出口 ip

```
for i in {1..4};do dig +timeout=10 +short myip.opendns.com @resolver$i.opendns.com;done | sort -n | uniq
```

得到 N 个出口 ip

## 预先设置 N 条规则 **非常重要！！！**

把前面得到的 N 个出口 ip，在每个安全组中预先添加 N 条规则。**_以防止脚本执行后安全组中的前 N 条规则会被覆盖_**

# 构建二进制文件

更新 go.mod 和 go.sum 文件

```
go mod tidy
```

移动到 vendor 目录

```
go mod vendor
```

编译成 Linux 客户端

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o modifyingSecurityGroup_linux main.go
```

编译成 Windows 客户端

```
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -o modifyingSecurityGroup.exe main.go
```

编译成 Mac 客户端

```
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -o modifyingSecurityGroup_mac main.go
```

# 在 linux 上运行

## 创建 cron 任务

复制 config.toml 和 modifyingSecurityGroup_linux 到 Linux 服务器上，在 config.toml 中配置适当的认证信息和安全组

```
crontab -e ，然后添加以下内容
#调腾讯云安全组接口，公司ip变化加入白名单，每1小时执行一次
* */1 * * * cd /root/modifyingSecurityGroup && ./modifyingSecurityGroup_linux --requiredIPs 2 >> /tmp/txmodSecurityGroup.log 2>&1
```

## 手动指定出口 ip(特殊情况下使用)

### 1. 手动将待添加的出口 ip 写入到一个文本文件中，假设是 myips.txt

### 2. 执行以下命令

```
    ./modifyingSecurityGroup_linux -ip myips.txt
```

### 参数说明

- --ip：指定包含 IP 地址的文件路径。如果提供此参数，程序将从文件中读取 IP 地址，而不是在线获取。
- --maxAttempts：最大尝试次数，用于在线获取 IP 地址时的并发请求数。默认值为 35。
- --requiredIPs：所需的唯一 IP 数量。程序将在获取到指定数量的唯一 IP 后停止。默认值为 3,此参数保持与前面的 N 相等。

# 在 Windows 上运行

## 创建计划任务

以管理员权限运行命令提示符，然后执行以下命令

```
schtasks /create /tn "modifyingSecurityGroup" /tr "\"D:\Program Files\modifyingSecurityGroup\modifyingSG.bat\"" /sc DAILY /st 00:00 /ri 2 /du 23:59 /ed 9999/12/31 /ru "SYSTEM" /rl HIGHEST /f
```

### 参数说明

- `/tn` 指定任务名称
- `/tr` 指定任务执行的程序路径
- `/sc` 指定任务的触发方式，DAILY：任务每日触发
- `/st` 指定任务的开始时间，00:00：每日开始时间为00:00
- `/ri` 指定任务的重复间隔，15：重复间隔15分钟
- `/du` 指定任务的持续时间，23:59：持续23:59
- `/ed` 指定任务的结束时间，9999/12/31：任务永久有效
- `/ru` 指定任务的运行用户，SYSTEM：以系统用户运行
- `/rl` 指定任务的运行权限，HIGHEST：最高权限
- `/f` 强制创建任务

# 注意

0. 暂时仅支持腾讯云
1. 支持 Windows、linux 和 MAC 平台
2. 暂时仅支持 ipv4 的地址
