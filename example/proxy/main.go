package main

import (
	"fmt"
	"log"
	"time"

	"github.com/zan8in/cdncheck"
)

func main() {
	fmt.Println("=== CDN检测器 - DoH + 代理支持演示 ===")

	// 1. 默认配置（启用DoH）
	fmt.Println("\n1. 使用默认配置（DoH优先）")
	checker1, err := cdncheck.NewCDNChecker(nil)
	if err != nil {
		log.Fatal("创建检测器失败:", err)
	}

	result, err := checker1.CheckDomain("google.com")
	if err != nil {
		fmt.Printf("检测失败: %v\n", err)
	} else {
		fmt.Printf("域名: %s, 使用CDN: %t, IP: %v\n", result.Domain, result.IsCDN, result.IPs)
	}

	// 2. 配置HTTP代理 + DoH
	fmt.Println("\n2. 配置HTTP代理 + DoH")
	config := &cdncheck.Config{
		// 启用DoH（推荐）
		EnableDoH: true,
		DoHServers: []string{
			"https://1.1.1.1/dns-query",
			"https://8.8.8.8/resolve",
			"https://dns.alidns.com/dns-query",
		},

		// 配置HTTP代理
		EnableProxy: true,
		Proxy: cdncheck.ProxyConfig{
			Type:    "http",
			URL:     "http://127.0.0.1:20170", // 替换为你的HTTP代理
			Timeout: 10 * time.Second,
			// Username: "user",     // 如果需要认证
			// Password: "pass",     // 如果需要认证
		},

		// 传统DNS作为回退
		DNSServers: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
		},
		DNSTimeout:        10 * time.Second,
		RetryCount:        3,
		RetryInterval:     100 * time.Millisecond,
		EnableMultiIP:     true,
		EnableMultipleDNS: true,
		Concurrency:       10,
		CustomProviders:   make(map[string][]string),
	}

	checker2, err := cdncheck.NewCDNChecker(config)
	if err != nil {
		log.Fatal("创建检测器失败:", err)
	}

	// 检查配置状态
	enabled, proxyType, proxyURL := checker2.GetProxyStatus()
	fmt.Printf("代理状态: %t, 类型: %s, URL: %s\n", enabled, proxyType, proxyURL)

	// 测试域名检测
	domains := []string{"google.com", "github.com", "baidu.com"}
	for _, domain := range domains {
		result, err := checker2.CheckDomain(domain)
		if err != nil {
			fmt.Printf("域名 %s 检测失败: %v\n", domain, err)
		} else {
			fmt.Printf("域名: %s, 使用CDN: %t, 提供商: %s\n", result.Domain, result.IsCDN, result.Provider)
		}
	}

	// 3. 动态切换代理类型
	fmt.Println("\n3. 动态切换到SOCKS5代理")
	err = checker2.SetSOCKS5Proxy("socks5://127.0.0.1:20170")
	if err != nil {
		fmt.Printf("设置SOCKS5代理失败: %v\n", err)
	} else {
		_, proxyType, proxyURL := checker2.GetProxyStatus()
		fmt.Printf("代理已切换 - 类型: %s, URL: %s\n", proxyType, proxyURL)
	}

	// 4. 仅使用DoH（无代理）
	fmt.Println("\n4. 禁用代理，仅使用DoH")
	checker2.DisableProxy()
	result, err = checker2.CheckDomain("cloudflare.com")
	if err != nil {
		fmt.Printf("检测失败: %v\n", err)
	} else {
		fmt.Printf("域名: %s, 使用CDN: %t, 提供商: %s\n", result.Domain, result.IsCDN, result.Provider)
	}

	// 5. 批量检测演示
	fmt.Println("\n5. 批量检测演示")
	testDomains := []string{"amazon.com", "microsoft.com", "alibaba.com"}
	results, errors := checker2.CheckDomains(testDomains)

	// 安全的批量结果处理
	if len(results) == 0 && len(errors) == 0 {
		fmt.Println("批量检测返回空结果")
	} else {
		// 确保使用testDomains的长度进行迭代，避免数组越界
		for i := 0; i < len(testDomains); i++ {
			domain := testDomains[i]

			// 检查errors数组是否有对应的错误
			if i < len(errors) && errors[i] != nil {
				fmt.Printf("域名 %s 检测失败: %v\n", domain, errors[i])
			} else if i < len(results) && results[i] != nil {
				// 检查results数组是否有对应的结果
				result := results[i]
				fmt.Printf("域名: %s, 使用CDN: %t, 提供商: %s\n", result.Domain, result.IsCDN, result.Provider)
			} else {
				fmt.Printf("域名 %s: 无结果数据\n", domain)
			}
		}
	}

	fmt.Println("\n=== 演示完成 ===")
	fmt.Println("\n使用建议:")
	fmt.Println("1. 优先使用DoH，安全且兼容性好")
	fmt.Println("2. 企业环境推荐HTTP代理 + DoH组合")
	fmt.Println("3. SOCKS5代理适用于特殊网络环境")
	fmt.Println("4. 传统DNS作为最后的回退方案")
}
