# 前置条件

## 1. 安装 dig 命令

### ubuntu and Debian

```
sudo apt install dnsutils
```

### Centos

```
sudo yum install bind-util
```

## 2. 获得你当前局域网的出口 ip

```
for i in {1..4};do dig +timeout=10 +short myip.opendns.com @resolver$i.opendns.com;done | sort -n | uniq
```

得到 N 个出口 ip

## 3. 预先设置 N 条规则 **非常重要！！！**

把前面得到的 N 个出口 ip，在每个安全组中预先添加 N 条规则。**_以防止脚本执行后安全组中的前 N 条规则会被覆盖_**

# 构建二进制文件

```
编译成Linux客户端
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o modifyingSecurityGroup_linux main.go

编译成Windows客户端 (暂时不支持)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -o modifyingSecurityGroup.exe main.go

编译成Mac客户端 (暂时不支持)
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -o modifyingSecurityGroup_mac main.go
```

# 创建 cron 任务

复制 config.toml 和 modifyingSecurityGroup_linux 到 Linux 服务器上，在 config.toml 中配置适当的认证信息和安全组

```
crontab -e ，然后添加以下内容
#调腾讯云安全组接口，公司ip变化加入白名单，每1小时执行一次
* */1 * * * cd /root/modifyingSecurityGroup && ./modifyingSecurityGroup_linux >> /tmp/txmodSecurityGroup.log 2>&1
```

# 手动指定出口 ip(特殊情况下使用)

## 1. 手动将待添加的出口 ip 写入到一个文本文件中，假设是 myips.txt

## 2. 执行以下命令

```
    ./modifyingSecurityGroup_linux -ip myips.txt
```

# 注意

0. 暂时仅支持腾讯云
1. 暂时仅支持 linux 平台
2. 暂时仅支持 ipv4 的地址
