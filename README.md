# 前置条件
安装dig命令
## ubuntu and Debian
```
sudo apt install dnsutils
```
### Centos
``` 
sudo yum install bind-util
```
# 构建二进制文件
```
编译成Linux客户端
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o modifyingSecurityGroup_linux main.go

编译成Windows客户端
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -o modifyingSecurityGroup.exe main.go

编译成Mac客户端
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -o modifyingSecurityGroup_mac main.go
```
# 创建cron任务
```
crontab -e ，然后添加以下内容
#调腾讯云安全组接口，公司ip变化加入白名单，每1小时执行一次
* */1 * * * cd /root/modifyingSecurityGroup && ./modifyingSecurityGroup_linux >> /tmp/txmodSecurityGroup.log 2>&1
```

# 注意
1. 仅限于linux平台
2. 没有适配ipv6的地址
