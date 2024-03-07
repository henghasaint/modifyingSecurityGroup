package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

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
	SgID        string `mapstructure:"id"` // 确保标签正确映射了TOML文件中的键
	Ports       string
	Protocol    string
	Action      string
	Description string
}

type DingTalkMessage struct {
	Msgtype string `json:"msgtype"`
	Text    struct {
		Content string `json:"content"`
	} `json:"text"`
}

// 用于存储成功更新信息的结构
type updateInfo struct {
	SG  string   //安全组id
	IPs []string //更新的ip
}

func currentDateTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
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

func sendDingTalkMessage(updates []updateInfo) {
	webhook := viper.GetString("dingtalk.webhook")
	var content strings.Builder

	content.WriteString("IP变化汇总:\n")
	for _, u := range updates {
		content.WriteString(fmt.Sprintf("- 安全组%s更新了IP: %s\n", u.SG, strings.Join(u.IPs, ", ")))
	}

	message := DingTalkMessage{
		Msgtype: "text",
		Text: struct {
			Content string `json:"content"`
		}{
			Content: content.String(),
		},
	}

	messageBytes, _ := json.Marshal(message)
	_, err := http.Post(webhook, "application/json", bytes.NewBuffer(messageBytes))
	if err != nil {
		fmt.Printf("%s 发送钉钉消息失败: %v\n", currentDateTime(), err)
	} else {
		fmt.Printf("%s 发送钉钉消息成功\n", currentDateTime())
	}
}

func getResolverIPs() ([]string, error) {
	// ips := []string{"121.35.46.172", "121.35.44.242", "121.35.46.168"}
	var ips []string
	// 构建并执行shell命令
	// cmd := "for i in {1..4};do dig +timeout=5 +short myip.opendns.com @resolver$i.opendns.com;done | sort -n | uniq"
	cmd := "for i in {1..4};do dig -4 TXT +short o-o.myaddr.l.google.com @ns$i.google.com;done | sort -n | uniq"
	execCmd := exec.Command("bash", "-c", cmd)

	var out bytes.Buffer
	execCmd.Stdout = &out

	err := execCmd.Run()
	if err != nil {
		return nil, err
	}

	output := strings.TrimSpace(out.String())
	fmt.Printf("%s output: %s\n", currentDateTime(), output)
	if output != "" {
		// 使用正则表达式从TXT记录中提取IP地址
		re := regexp.MustCompile(`"(.+?)"`)
		matches := re.FindAllStringSubmatch(output, -1)
		for _, match := range matches {
			if len(match) > 1 {
				ip := match[1]
				if net.ParseIP(ip) != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	fmt.Printf("%s 最新获得的ip: %v\n", currentDateTime(), ips)
	return ips, nil
}

func getUniqueIPs() map[string]bool {
	ips, _ := getResolverIPs()
	uniqueIPs := make(map[string]bool)
	for _, ip := range ips { //去重
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
			fmt.Println(currentDateTime(), " sError creating file:", err)
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
	fmt.Printf(currentDateTime(), "---> version is : %s, ", *version)
	fmt.Printf(", policyIndex is :  %d\n", policyIndex)
	request.SecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{
		Version: version,
		Ingress: []*vpc.SecurityGroupPolicy{
			{
				PolicyIndex:       common.Int64Ptr(policyIndex),
				Protocol:          common.StringPtr(sg.Protocol),
				Port:              common.StringPtr(sg.Ports),
				CidrBlock:         common.StringPtr(ip),
				Action:            common.StringPtr(sg.Action),
				PolicyDescription: common.StringPtr(sg.Description),
			},
		},
	}
	request.OriginalSecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{
		Version: version,
		Ingress: []*vpc.SecurityGroupPolicy{
			{
				PolicyIndex: common.Int64Ptr(policyIndex),
			},
		},
	}

	// 返回的resp是一个ReplaceSecurityGroupPolicyResponse的实例，与请求对象对应
	response, err := client.ReplaceSecurityGroupPolicy(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf(currentDateTime(), " An API error has returned: %s\n", err)
		return err
	}
	if err != nil {
		panic(err)
	}
	// 输出json格式的字符串回包
	// fmt.Printf(currentDateTime(), " response: %s\n", response.ToJsonString())
	return nil
}

func main() {
	initConfig()
	var updates []updateInfo
	var credsConfig []Creds
	err := viper.UnmarshalKey("creds", &credsConfig)
	if err != nil {
		fmt.Println(currentDateTime(), " Unable to decode into struct", err)
		return
	}

	var sgConfig []SecurityGroup
	err = viper.UnmarshalKey("securityGroups", &sgConfig)
	if err != nil {
		fmt.Println(currentDateTime(), " Unable to decode into struct", err)
		return
	}

	uniqueIPs := getUniqueIPs()
	existingIPs := readWriteIPs("./ips.txt", nil, "r") //从ips.txt中读取ip

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
			var sgUpdate updateInfo
			sgUpdate.SG = sg.SgID

			policyIndex := int64(0) // 初始化PolicyIndex
			for single_ip := range uniqueIPs {
				if _, exists := existingIPs[single_ip]; !exists {
					// 对每个新IP和每个安全组执行更新操作
					err := update_security_group_policy(cred, sg, single_ip, policyIndex) // 注意：policyIndex如何处理取决于业务逻辑
					if err != nil {
						fmt.Printf(currentDateTime(), " Error updating security group %s policy: %v\n", sgID, err)
						continue

					}
					sgUpdate.IPs = append(sgUpdate.IPs, single_ip)
					policyIndex++ // 每成功更新一个IP，PolicyIndex加1
				} else {
					fmt.Printf(currentDateTime(), " 出口IP地址无变化，暂时不需要更新安全组中的规则\n")
				}
			}
			if len(sgUpdate.IPs) > 0 {
				updates = append(updates, sgUpdate)
			}
		}
	}
	readWriteIPs("ips.txt", uniqueIPs, "w") //不论ip是否有变化，都重新写入一次
	// 使用收集到的更新信息发送汇总消息到钉钉
	if len(updates) > 0 {
		sendDingTalkMessage(updates)
	}
}
