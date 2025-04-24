package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/viper"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
)

type Creds struct {
	SecretID       string
	SecretKey      string
	SecurityGroups []string // 添加这个字段来存储安全组ID
}

type SecurityGroup struct {
	SgID        string `mapstructure:"id"` // 确保标签正确映射了TOML文件中的键
	Region      string
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

func getIframeURL(client *http.Client) (string, error) {
	resp, err := client.Get("http://nstool.netease.com")
	if err != nil {
		return "", fmt.Errorf("无法连接到 http://nstool.netease.com: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("无法连接到 http://nstool.netease.com: %v", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %v", err)
	}

	iframe := doc.Find("iframe").First()
	if iframe.Length() > 0 {
		iframeURL, exists := iframe.Attr("src")
		if exists {
			return iframeURL, nil
		}
	}

	return "", fmt.Errorf("未找到 iframe 标签")
}

func getIPFromURL(client *http.Client, url string) ([]string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("无法连接到 %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("无法连接到 %s: %v", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	re := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	content := string(body)
	ipAddresses := re.FindAllString(content, -1)

	// 排除包含 "DNS" 后面的内容
	dnsIndex := len(content)
	if dnsPos := regexp.MustCompile(`DNS`).FindStringIndex(content); dnsPos != nil {
		dnsIndex = dnsPos[0]
	}
	ipAddresses = re.FindAllString(content[:dnsIndex], -1)

	return ipAddresses, nil
}

func getUniqueIPs(maxAttempts int, requiredIPs int) map[string]bool {
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	uniqueIPs := make(map[string]bool)
	ch := make(chan struct{}, maxAttempts)

	for len(uniqueIPs) < requiredIPs {
		for i := 0; i < maxAttempts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ch <- struct{}{}
				defer func() { <-ch }()

				pause := time.Duration(rnd.Intn(11)+5) * time.Second
				time.Sleep(pause)

				iframeURL, err := getIframeURL(client)
				if err != nil {
					fmt.Println(err)
					return
				}
				fmt.Printf("提取到的 iframe 链接：%s\n", iframeURL)

				ipAddresses, err := getIPFromURL(client, iframeURL)
				if err != nil {
					fmt.Println(err)
					return
				}

				mu.Lock()
				for _, ip := range ipAddresses {
					if len(uniqueIPs) >= requiredIPs {
						mu.Unlock()
						return
					}
					if _, exists := uniqueIPs[ip]; !exists {
						uniqueIPs[ip] = true
						fmt.Printf("找到IP: %s\n", ip) // 添加调试日志，打印找到的IP
					}
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
	}

	fmt.Printf("最终找到的Unique IPs: %v\n", uniqueIPs) // 打印最终找到的Unique IPs
	return uniqueIPs
}

func readWriteIPs(filePath string, ips map[string]bool, mode string) map[string]bool {
	if mode == "r" {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Println(currentDateTime(), " Error opening file:", err)
			return make(map[string]bool)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		result := make(map[string]bool)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text()) // 去除每行的前后空格
			if ip != "" {
				result[ip] = true
				fmt.Printf("读取到IP: '%s'\n", ip) // 添加调试日志，打印读取到的IP
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(currentDateTime(), " Error reading file:", err)
		}
		fmt.Printf("最终读取到的Existing IPs: %v\n", result) // 打印最终读取到的IPs
		return result
	} else if mode == "w" {
		file, err := os.Create(filePath)
		if err != nil {
			fmt.Println(currentDateTime(), " Error creating file:", err)
			return nil
		}
		defer file.Close()

		for ip := range ips {
			_, err := file.WriteString(ip + "\n")
			if err != nil {
				fmt.Println(currentDateTime(), " Error writing to file:", err)
			}
			fmt.Printf("写入IP: '%s'\n", ip) // 添加调试日志，打印写入的IP
		}
	}
	return nil
}

func geSG_version(sgID string, region string, credential *common.Credential) (*string, error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "vpc.tencentcloudapi.com"
	client, _ := vpc.NewClient(credential, region, cpf)
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
	client, _ := vpc.NewClient(credential, sg.Region, cpf)

	version, err := geSG_version(sg.SgID, sg.Region, credential)
	if err != nil {
		return err
	}

	request := vpc.NewReplaceSecurityGroupPolicyRequest()
	request.SecurityGroupId = common.StringPtr(sg.SgID)
	fmt.Printf("%s ---> version is : %s, policyIndex is : %d\n", currentDateTime(), *version, policyIndex)
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
		fmt.Printf("%s An API error has returned: %s\n", currentDateTime(), err)
		return err
	}
	if err != nil {
		panic(err)
	}
	// 输出json格式的字符串回包
	fmt.Printf("%s response: %s\n", currentDateTime(), response.ToJsonString())
	return nil
}

var (
	ipFilePath  string // 新增变量用于存储命令行参数
	maxAttempts int    // 新增变量用于存储最大尝试次数
	requiredIPs int    // 新增变量用于存储所需的唯一IP数量
)

func init() {
	flag.StringVar(&ipFilePath, "ip", "", "Path to the file containing IP addresses")
	flag.IntVar(&maxAttempts, "maxAttempts", 35, "Maximum number of attempts")
	flag.IntVar(&requiredIPs, "requiredIPs", 3, "Number of required unique IPs")
	initConfig() // 初始化配置，保持在init函数中以保证首先执行
}

func main() {
	flag.Parse() // 解析命令行参数

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

	var uniqueIPs map[string]bool
	if ipFilePath != "" {
		uniqueIPs = readWriteIPs(ipFilePath, nil, "r") // 当提供-ip参数时，从文件读取IPs
	} else {
		uniqueIPs = getUniqueIPs(maxAttempts, requiredIPs)
		fmt.Printf("获取到的Unique IPs: %v\n", uniqueIPs)
	}

	existingIPs := readWriteIPs("./ips.txt", nil, "r") //从ips.txt中读取ip
	fmt.Printf("从ips.txt读取的Existing IPs: %v\n", existingIPs)

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
					// 调试日志：IP 不存在时进行更新
					fmt.Printf("Updating Security Group %s with IP %s\n", sg.SgID, single_ip)
					fmt.Printf("正在循环中...从ips.txt读取的Existing IPs: %v\n", existingIPs)
					err := update_security_group_policy(cred, sg, single_ip, policyIndex) // 注意：policyIndex如何处理取决于业务逻辑
					if err != nil {
						fmt.Printf("%s Error updating security group %s policy: %v\n", currentDateTime(), sgID, err)
						continue
					} else {
						fmt.Printf("%s 安全组 %s 中的规则已成功更新ip %s \n", currentDateTime(), sgID, single_ip)
					}
					sgUpdate.IPs = append(sgUpdate.IPs, single_ip)
					policyIndex++ // 每成功更新一个IP，PolicyIndex加1
				} else {
					fmt.Printf("%s IP %s 在上次已经更新过，跳过本次更新\n", currentDateTime(), single_ip)
				}
			}
			if len(sgUpdate.IPs) > 0 {
				updates = append(updates, sgUpdate)
			}
		}
	}

	readWriteIPs("ips.txt", uniqueIPs, "w")        // 不论ip是否有变化，都重新写入一次
	fmt.Printf("最终写入的Unique IPs: %v\n", uniqueIPs) // 打印最终写入的IPs

	// 使用收集到的更新信息发送汇总消息到钉钉
	if len(updates) > 0 {
		sendDingTalkMessage(updates)
	}
}
