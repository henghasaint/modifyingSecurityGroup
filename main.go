package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/viper"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
)

type Creds struct {
    SecretID       string
    SecretKey      string
    Region         string
    SecurityGroups []string // 添加这个字段来存储安全组ID
}

type SecurityGroup struct {
    SgID         string `mapstructure:"id"` // 确保标签正确映射了TOML文件中的键
    Ports        string
    Protocol     string
    Action       string
    Description  string
}


type DingTalkMessage struct {
	Msgtype string `json:"msgtype"`
	Text    struct {
		Content string `json:"content"`
	} `json:"text"`
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w ", err))
	}
}

func sendDingTalkMessage(newIP string) {
	webhook := viper.GetString("dingtalk.webhook")
	message := DingTalkMessage{
		Msgtype: "text",
		Text: struct {
			Content string `json:"content"`
		}{
			// 在这里添加关键词“IP变化”
			Content: fmt.Sprintf("IP变化 -新IP地址已添加到安全组: %s", newIP),
		},
	}

	messageBytes, _ := json.Marshal(message)
	_, err := http.Post(webhook, "application/json", bytes.NewBuffer(messageBytes))
	if err != nil {
		fmt.Printf("发送钉钉消息失败: %v\n", err)
	}
}

func getResolverIPs() ([]string, error) {
    // ips := []string{"175.178.168.11", "175.178.168.12", "175.178.168.13"}
    var ips []string
    // 构建并执行shell命令
    cmd := "for i in {1..4};do dig +short myip.opendns.com @resolver$i.opendns.com;done | sort -n | uniq"
    execCmd := exec.Command("bash", "-c", cmd) // 使用bash执行命令

    var out bytes.Buffer
    execCmd.Stdout = &out // 将命令的标准输出连接到out变量

    // 运行命令
    err := execCmd.Run()
    if err != nil {
        return nil, err // 如果命令执行失败，返回错误
    }

    // 处理命令输出
    output := strings.TrimSpace(out.String()) // 去除输出字符串的首尾空白字符
    if output != "" {
        ips = strings.Split(output, "\n") // 按换行符分割输出字符串，得到IP地址列表
    }
    fmt.Println("ips: ", ips)
    return ips, nil // 返回去重并排序后的IP地址列表
}


func getUniqueIPs() map[string]bool {
    ips,_ := getResolverIPs()
    uniqueIPs := make(map[string]bool)
    for _, ip := range ips {
        uniqueIPs[ip] = true
    }
    return uniqueIPs
}

func readWriteIPs(filePath string, ips map[string]bool, mode string) map[string]bool {
    if mode == "r" {
        file, err := os.Open(filePath)
        if err != nil {
            return make(map[string]bool)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        result := make(map[string]bool)
        for scanner.Scan() {
            result[scanner.Text()] = true
        }
        return result
    } else if mode == "w" {
        file, err := os.Create(filePath)
        if err != nil {
            fmt.Println("Error creating file:", err)
            return nil
        }
        defer file.Close()

        for ip := range ips {
            file.WriteString(ip + "\n")
        }
    }
    return nil
}

func geSG_version(sgID string, creds Creds) (*string, error) {
    credential := common.NewCredential(
        creds.SecretID,
        creds.SecretKey,
    )
    cpf := profile.NewClientProfile()
    cpf.HttpProfile.Endpoint = "vpc.tencentcloudapi.com"
    client, _ := vpc.NewClient(credential, creds.Region, cpf)
    request := vpc.NewDescribeSecurityGroupPoliciesRequest()
    request.SecurityGroupId = common.StringPtr(sgID)

    response, err := client.DescribeSecurityGroupPolicies(request)
    if err != nil {
        return nil, err
    }

    return response.Response.SecurityGroupPolicySet.Version, nil
}

func update_security_group_policy(creds Creds, sg SecurityGroup, ip string, policyIndex int64) error {
    credential := common.NewCredential(
        creds.SecretID,
        creds.SecretKey,
    )
    cpf := profile.NewClientProfile()
    cpf.HttpProfile.Endpoint = "vpc.tencentcloudapi.com"
    client, _ := vpc.NewClient(credential, creds.Region, cpf)

    version, err := geSG_version(sg.SgID, creds)
    if err != nil {
        return err
    }

    request := vpc.NewReplaceSecurityGroupPolicyRequest()
    request.SecurityGroupId = common.StringPtr(sg.SgID)
    fmt.Printf("version is :  %v\n", version)
    fmt.Printf("policyIndex is :  %v\n", policyIndex)
    request.SecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{
        Version: version,
        Ingress: []*vpc.SecurityGroupPolicy{
            {
                PolicyIndex:      common.Int64Ptr(policyIndex),
                Protocol:         common.StringPtr(sg.Protocol),
                Port:             common.StringPtr(sg.Ports),
                CidrBlock:        common.StringPtr(ip),
                Action:           common.StringPtr(sg.Action),
                PolicyDescription: common.StringPtr(sg.Description),
            },
        },
    }
    request.OriginalSecurityGroupPolicySet = &vpc.SecurityGroupPolicySet {
        Version: version,
        Ingress: []*vpc.SecurityGroupPolicy {
                 {
                        PolicyIndex: common.Int64Ptr(policyIndex),
                },
        },
    }

    // 返回的resp是一个ReplaceSecurityGroupPolicyResponse的实例，与请求对象对应
    response, err := client.ReplaceSecurityGroupPolicy(request)
    if _, ok := err.(*errors.TencentCloudSDKError); ok {
            fmt.Printf("An API error has returned: %s", err)
            return err
    }
    if err != nil {
            panic(err)
    }
    // 输出json格式的字符串回包
    fmt.Printf("%s", response.ToJsonString())
    return nil
}

func main() {
    initConfig()

    var credsConfig []Creds
    err := viper.UnmarshalKey("creds", &credsConfig)
    if err != nil {
        fmt.Println("Unable to decode into struct", err)
        return
    }

    var sgConfig []SecurityGroup
    err = viper.UnmarshalKey("securityGroups", &sgConfig)
    if err != nil {
        fmt.Println("Unable to decode into struct", err)
        return
    }

    uniqueIPs := getUniqueIPs()
    existingIPs := readWriteIPs("./ips.txt", nil, "r")
    var newIPs []string // 收集新增的IP
    for ip := range uniqueIPs {
        newIPs = append(newIPs, ip) // 记录新增的IP
    }

    for _, cred := range credsConfig {
        for _, sgID := range cred.SecurityGroups {
            var sg SecurityGroup
            // 查找sgID对应的SecurityGroup配置
            for _, s := range sgConfig {
                if s.SgID == sgID {
                    sg = s
                    break
                }
            }
            policyIndex := int64(0) // 初始化PolicyIndex
            for ip := range uniqueIPs {
                if _, exists := existingIPs[ip]; !exists {
                    // 对每个新IP和每个安全组执行更新操作
                    err := update_security_group_policy(cred, sg, ip, policyIndex) // 注意：policyIndex如何处理取决于业务逻辑
                    if err != nil {
                        fmt.Printf("Error updating security group %s policy: %v\n", sgID, err)
                        continue
                    }
                    policyIndex++ // 每成功更新一个IP，PolicyIndex加1
                }
            }
        }
    }

    // 如果有新的IP被添加，更新IPs文件
    if len(newIPs) > 0 {
        readWriteIPs("ips.txt", uniqueIPs, "w")
        newIPsString := strings.Join(newIPs, ", ")
        sendDingTalkMessage(fmt.Sprintf("新增的IP地址: %s", newIPsString)) // 发送新增的IP到钉钉
        fmt.Println("更新成功，已向钉钉机器人发送消息")
    } else {
        fmt.Println("没有发现新的IP或者安全组无需更新")
    }
}