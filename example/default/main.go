package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zan8in/cdncheck"
)

func main() {
	// 创建默认CDN检测器
	checker := cdncheck.NewDefaultCDNChecker()

	// 检查单个域名
	result, err := checker.CheckDomain("example.com")
	if err != nil {
		log.Printf("检查域名失败: %v", err)
	} else {
		fmt.Printf("域名: %s\n", result.Domain)
		fmt.Printf("IP地址: %s\n", cdncheck.IPsToString(result.IPs))
		fmt.Printf("是否CDN: %v\n", result.IsCDN)
		fmt.Printf("提供商: %s\n", result.Provider)
		fmt.Printf("原因: %s\n", result.Reason)
		fmt.Println("详细信息:")
		for _, detail := range result.Details {
			fmt.Printf("  IP: %s, CDN: %v, 提供商: %s\n", detail.IP, detail.IsCDN, detail.Provider)
		}
		fmt.Println()
	}

	// 检查单个IP
	isCDN, provider := checker.IsCDNIP("104.16.1.1")
	fmt.Printf("IP检查 - IP: %s, 是否CDN: %v, 提供商: %s\n\n", "104.16.1.1", isCDN, provider)

	// 批量检查IP
	ips := []string{"104.16.1.1", "8.8.8.8", "1.1.1.1", "192.168.1.1"}
	ipResults := checker.CheckIPs(ips)
	fmt.Println("批量IP检查结果:")
	for _, result := range ipResults {
		fmt.Printf("IP: %s, CDN: %v, 提供商: %s, 原因: %s\n",
			result.IP, result.IsCDN, result.Provider, result.Reason)
	}
	fmt.Println()

	// 批量检查域名
	domains := []string{"google.com", "cloudflare.com", "example.com", "qq.com", "baidu.com"}
	results, errors := checker.CheckDomains(domains)

	if len(errors) > 0 {
		fmt.Println("检查过程中的错误:")
		for _, err := range errors {
			fmt.Printf("  %v\n", err)
		}
		fmt.Println()
	}

	fmt.Println("批量域名检查结果:")
	for _, result := range results {
		fmt.Printf("域名: %s, IP: %s, CDN: %v, 提供商: %s\n",
			result.Domain,
			cdncheck.IPsToString(result.IPs, " | "),
			result.IsCDN,
			result.Provider)
	}
	fmt.Println()

	// 自定义配置示例
	config := cdncheck.DefaultConfig()
	config.RetryCount = 5
	config.DNSTimeout = 5 * time.Second
	config.EnableMultipleDNS = true
	config.Concurrency = 20

	customChecker, err := cdncheck.NewCDNChecker(config)
	if err != nil {
		log.Printf("创建自定义检测器失败: %v", err)
		return
	}

	// 添加自定义CDN提供商
	customChecker.AddCustomProvider("MyCDN", []string{"192.168.1.0/24", "10.0.0.0/8"})

	// 演示带上下文的检查
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err = customChecker.CheckDomainWithContext(ctx, "github.com")
	if err != nil {
		log.Printf("带上下文检查失败: %v", err)
	} else {
		fmt.Printf("带上下文检查 - 域名: %s, CDN: %v, 提供商: %s\n",
			result.Domain, result.IsCDN, result.Provider)
	}
	fmt.Println()

	// 演示IP数组转字符串的不同格式
	testIPs := []string{"1.1.1.1", "8.8.8.8", "114.114.114.114"}
	fmt.Println("IP数组转字符串示例:")
	fmt.Printf("默认格式: %s\n", cdncheck.IPsToString(testIPs))
	fmt.Printf("空格分隔: %s\n", cdncheck.IPsToStringWithFormat(testIPs, "space"))
	fmt.Printf("换行分隔: %s\n", cdncheck.IPsToStringWithFormat(testIPs, "line"))
	fmt.Printf("JSON格式: %s\n", cdncheck.IPsToStringWithFormat(testIPs, "json"))
	fmt.Printf("自定义分隔符: %s\n", cdncheck.IPsToStringWithFormat(testIPs, "custom", " -> "))
	fmt.Println()

	// 演示统计信息
	if len(results) > 0 {
		stats := checker.GetStatistics(results)
		fmt.Println("检查统计信息:")
		fmt.Printf("总检查数: %d\n", stats.TotalChecked)
		fmt.Printf("CDN数量: %d\n", stats.CDNCount)
		fmt.Printf("非CDN数量: %d\n", stats.NonCDNCount)
		fmt.Println("提供商统计:")
		for provider, count := range stats.ProviderStats {
			fmt.Printf("  %s: %d\n", provider, count)
		}
	}

	// 演示获取所有提供商
	fmt.Println("\n支持的CDN提供商:")
	providers := checker.GetProviders()
	for _, provider := range providers {
		fmt.Printf("  - %s\n", provider)
	}
}
