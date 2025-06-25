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
	SecurityGroups []string
}

type SecurityGroup struct {
	SgID        string `mapstructure:"id"`
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

type updateInfo struct {
	SG  string
	IPs []string
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
	if webhook == "" {
		fmt.Printf("%s 钉钉webhook未配置，跳过消息发送\n", currentDateTime())
		return
	}

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

	dnsIndex := len(content)
	if dnsPos := regexp.MustCompile(`DNS`).FindStringIndex(content); dnsPos != nil {
		dnsIndex = dnsPos[0]
	}
	ipAddresses = re.FindAllString(content[:dnsIndex], -1)

	return ipAddresses, nil
}

func getIPFromInip(client *http.Client) (string, error) {
	resp, err := client.Get("http://inip.in/ipinfo.html")
	if err != nil {
		return "", fmt.Errorf("无法连接到 http://inip.in/ipinfo.html: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("无法连接到 http://inip.in/ipinfo.html: %v", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("解析HTML失败: %v", err)
	}

	ip := doc.Find("strong.your-ip").Text()
	if ip == "" {
		return "", fmt.Errorf("未找到IP地址")
	}

	ip = strings.TrimSpace(ip)
	return ip, nil
}

func getUniqueIPs(maxAttempts int, requiredIPs int) []string {
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	uniqueIPs := make(map[string]bool)
	ch := make(chan struct{}, maxAttempts)
	gotRequired := false

	for len(uniqueIPs) < requiredIPs {
		for i := 0; i < maxAttempts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ch <- struct{}{}
				defer func() { <-ch }()

				pause := time.Duration(rnd.Intn(11)+5) * time.Second
				time.Sleep(pause)

				mu.Lock()
				currentCount := len(uniqueIPs)
				mu.Unlock()

				if currentCount == requiredIPs-1 && !gotRequired {
					ip, err := getIPFromInip(client)
					if err != nil {
						fmt.Printf("从inip.in获取IP失败: %v\n", err)
						return
					}

					mu.Lock()
					if len(uniqueIPs) < requiredIPs {
						uniqueIPs[ip] = true
						fmt.Printf("从inip.in获取到第%d个IP: %s\n", requiredIPs)
						gotRequired = true
					}
					mu.Unlock()
					return
				}

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
						fmt.Printf("找到IP: %s\n", ip)
					}
				}
				mu.Unlock()
			}()
		}
		wg.Wait()

		mu.Lock()
		if len(uniqueIPs) >= requiredIPs {
			mu.Unlock()
			break
		}
		mu.Unlock()
	}

	// 将map转换为有序的slice
	var result []string
	for ip := range uniqueIPs {
		result = append(result, ip)
	}

	// 确保返回的IP数量不超过requiredIPs
	if len(result) > requiredIPs {
		result = result[:requiredIPs]
	}

	fmt.Printf("最终找到的Unique IPs: %v\n", result)
	return result
}

func readWriteIPs(filePath string, ips []string, mode string) []string {
	if mode == "r" {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Println(currentDateTime(), " Error opening file:", err)
			return []string{}
		}
		defer file.Close()

		var result []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				result = append(result, ip)
				fmt.Printf("读取到IP: '%s'\n", ip)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(currentDateTime(), " Error reading file:", err)
		}
		fmt.Printf("最终读取到的Existing IPs: %v\n", result)
		return result
	} else if mode == "w" {
		file, err := os.Create(filePath)
		if err != nil {
			fmt.Println(currentDateTime(), " Error creating file:", err)
			return nil
		}
		defer file.Close()

		for _, ip := range ips {
			_, err := file.WriteString(ip + "\n")
			if err != nil {
				fmt.Println(currentDateTime(), " Error writing to file:", err)
			}
			fmt.Printf("写入IP: '%s'\n", ip)
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

// 逐个替换安全组规则
func updateSecurityGroupPolicies(creds Creds, sg SecurityGroup, newIPs []string) error {
	credential := common.NewCredential(
		creds.SecretID,
		creds.SecretKey,
	)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "vpc.tencentcloudapi.com"
	client, _ := vpc.NewClient(credential, sg.Region, cpf)

	fmt.Printf("%s 开始逐个更新安全组 %s 的规则\n", currentDateTime(), sg.SgID)

	// 逐个替换每条规则
	for i, ip := range newIPs {
		// 获取当前版本（每次替换前都要获取最新版本）
		version, err := geSG_version(sg.SgID, sg.Region, credential)
		if err != nil {
			return fmt.Errorf("获取安全组版本失败: %v", err)
		}

		policyIndex := int64(i)

		request := vpc.NewReplaceSecurityGroupPolicyRequest()
		request.SecurityGroupId = common.StringPtr(sg.SgID)

		// 设置新规则
		request.SecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{
			Version: version,
			Ingress: []*vpc.SecurityGroupPolicy{
				{
					PolicyIndex:       common.Int64Ptr(policyIndex),
					Protocol:          common.StringPtr(sg.Protocol),
					Port:              common.StringPtr(sg.Ports),
					CidrBlock:         common.StringPtr(ip),
					Action:            common.StringPtr(sg.Action),
					PolicyDescription: common.StringPtr(fmt.Sprintf("%s - %s", sg.Description, ip)),
				},
			},
		}

		// 设置原规则（用于定位要替换的规则）
		request.OriginalSecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{
			Version: version,
			Ingress: []*vpc.SecurityGroupPolicy{
				{
					PolicyIndex: common.Int64Ptr(policyIndex),
				},
			},
		}

		fmt.Printf("%s 正在更新规则 %d: IP %s (版本: %s)\n",
			currentDateTime(), i, ip, *version)

		_, err = client.ReplaceSecurityGroupPolicy(request)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			fmt.Printf("%s API错误 (规则 %d): %s\n", currentDateTime(), i, err)
			return err
		}
		if err != nil {
			return fmt.Errorf("替换规则 %d 失败: %v", i, err)
		}

		fmt.Printf("%s 规则 %d 更新成功: %s\n", currentDateTime(), i, ip)

		// 添加短暂延迟，避免API调用过于频繁
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("%s 安全组 %s 所有规则更新完成\n", currentDateTime(), sg.SgID)
	return nil
}

// 比较两个IP列表是否相同（顺序不敏感）
func compareIPLists(list1, list2 []string) bool {
	if len(list1) != len(list2) {
		return false
	}

	// 将两个列表转换为map进行比较
	map1 := make(map[string]bool)
	map2 := make(map[string]bool)

	for _, ip := range list1 {
		map1[ip] = true
	}

	for _, ip := range list2 {
		map2[ip] = true
	}

	// 比较两个map是否相同
	for ip := range map1 {
		if !map2[ip] {
			return false
		}
	}

	for ip := range map2 {
		if !map1[ip] {
			return false
		}
	}

	return true
}

var (
	ipFilePath  string
	maxAttempts int
	requiredIPs int
)

func init() {
	flag.StringVar(&ipFilePath, "ip", "", "Path to the file containing IP addresses")
	flag.IntVar(&maxAttempts, "maxAttempts", 35, "Maximum number of attempts")
	flag.IntVar(&requiredIPs, "requiredIPs", 3, "Number of required unique IPs")
	initConfig()
}

func main() {
	flag.Parse()

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

	var uniqueIPs []string
	if ipFilePath != "" {
		uniqueIPs = readWriteIPs(ipFilePath, nil, "r")
	} else {
		uniqueIPs = getUniqueIPs(maxAttempts, requiredIPs)
	}

	// 确保IP数量符合要求
	if len(uniqueIPs) > requiredIPs {
		uniqueIPs = uniqueIPs[:requiredIPs]
	}

	fmt.Printf("当前获取到的IPs: %v\n", uniqueIPs)

	existingIPs := readWriteIPs("./ips.txt", nil, "r")
	fmt.Printf("从ips.txt读取的历史IPs: %v\n", existingIPs)

	// 比较IP列表是否有变化
	hasChanges := !compareIPLists(uniqueIPs, existingIPs)

	if !hasChanges {
		fmt.Printf("%s IP列表无变化，跳过更新\n", currentDateTime())
		return
	}

	fmt.Printf("%s IP列表有变化，开始更新安全组\n", currentDateTime())

	// 更新每个安全组
	for _, cred := range credsConfig {
		for _, sgID := range cred.SecurityGroups {
			var sg SecurityGroup
			for _, s := range sgConfig {
				if s.SgID == sgID {
					sg = s
					break
				}
			}

			if sg.SgID == "" {
				fmt.Printf("%s 未找到安全组 %s 的配置\n", currentDateTime(), sgID)
				continue
			}

			fmt.Printf("%s 开始更新安全组 %s\n", currentDateTime(), sg.SgID)

			err := updateSecurityGroupPolicies(cred, sg, uniqueIPs)
			if err != nil {
				fmt.Printf("%s 更新安全组 %s 失败: %v\n", currentDateTime(), sgID, err)
				continue
			}

			// 记录成功更新的信息
			updates = append(updates, updateInfo{
				SG:  sg.SgID,
				IPs: uniqueIPs,
			})

			fmt.Printf("%s 安全组 %s 更新完成\n", currentDateTime(), sg.SgID)
		}
	}

	// 保存新的IP列表到文件
	readWriteIPs("ips.txt", uniqueIPs, "w")
	fmt.Printf("已将新的IP列表写入文件: %v\n", uniqueIPs)

	// 发送钉钉通知
	if len(updates) > 0 {
		sendDingTalkMessage(updates)
	}
}
