package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
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
    SgID         string // 修改这里以匹配字段访问
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


func getResolverIPs() []string {
    var ips []string
    // ips := []string{"175.178.168.11", "175.178.168.12", "175.178.168.13"}
    resolvers := []string{"resolver1.opendns.com", "resolver2.opendns.com", "resolver3.opendns.com", "resolver4.opendns.com"}

    for _, resolver := range resolvers {
        ipAddresses, err := net.LookupIP(resolver)
        if err != nil {
            fmt.Printf("Failed to lookup IP for %s: %v\n", resolver, err)
            continue
        }
        for _, ipAddress := range ipAddresses {
            ips = append(ips, ipAddress.String()) // 将IP地址转换为字符串并添加到ips切片中
        }
    }
    return ips
}


func getUniqueIPs() map[string]bool {
    ips := getResolverIPs()
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
    initConfig() // 初始化配置

    // 从配置文件读取Creds和SecurityGroups
    var credsConfig []Creds
    var sgConfig []SecurityGroup
    err := viper.UnmarshalKey("creds", &credsConfig)
    if err != nil {
        fmt.Println("Unable to decode into struct", err)
    }
    err = viper.UnmarshalKey("securityGroups", &sgConfig)
    if err != nil {
        fmt.Println("Unable to decode into struct", err)
    }

    uniqueIPs := getUniqueIPs()
    existingIPs := readWriteIPs("ips.txt", nil, "r")

    var policyIndex int64 = 0
    var updateOccurred bool = false

    // 此处逻辑根据实际情况调整，以匹配配置文件中的Creds和SecurityGroups
    for _, cred := range credsConfig {
        for _, sgID := range cred.SecurityGroups { // 使用正确的字段名
            for ip := range uniqueIPs {
                if _, exists := existingIPs[ip]; !exists {
                    // 找到对应的SecurityGroup
                    var sg SecurityGroup
                    for _, s := range sgConfig {
                        if s.SgID == sgID { // 使用正确的字段名
                            sg = s
                            break
                        }
                    }
                    // fmt.Printf("cred:%s, sg:%s, ip:%s, policyIndex:%s\n",cred, sg, ip, policyIndex)
                    fmt.Printf("cred:%s\n",cred)
                    err := update_security_group_policy(cred, sg, ip, policyIndex)
                    if err != nil {
                        fmt.Printf("Error updating security group policy: %v\n", err)
                        continue
                    }
                    policyIndex++
                    updateOccurred = true
                }
            }
        }
    }    

    // 构建IP地址字符串
    var newIPs []string
    for ip := range uniqueIPs {
        if _, exists := existingIPs[ip]; !exists {
            newIPs = append(newIPs, ip)
        }
    }

    if updateOccurred {
        newIPsString := strings.Join(newIPs, ", ")
        // 更新成功的逻辑，例如发送钉钉机器人消息
        sendDingTalkMessage(newIPsString)
        fmt.Println("更新成功，已向钉钉机器人发送消息")
    } else {
        fmt.Println("没有发现新的IP")
    }

    // 如果有新的IP被添加，更新IPs文件
    if policyIndex > 0 {
        readWriteIPs("ips.txt", uniqueIPs, "w")
    }
}