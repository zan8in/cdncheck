package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zan8in/cdncheck"
)

func main() {
	// 基本使用
	basicExample()

	// 高级配置
	advancedExample()

	// IP检测
	ipExample()
}

func basicExample() {
	fmt.Println("=== 基本CDN检测 ===")

	// 创建默认检测器
	checker := cdncheck.NewDefault()

	// 检测域名
	domains := []string{"www.baidu.com", "github.com", "example.com", "deepseek.com", "qq.com"}
	for _, domain := range domains {

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := checker.CheckDomain(ctx, domain)
		if err != nil {
			log.Printf("检测 %s 失败: %v", domain, err)
			continue
		}

		fmt.Printf("域名: %s\n", result.Target)
		fmt.Printf("是否CDN: %v\n", result.IsCDN)
		if result.Provider != "" {
			fmt.Printf("CDN服务商: %s\n", result.Provider)
		}
		fmt.Printf("IP列表: %v\n", result.IPs)
		fmt.Printf("检测原因: %s\n", result.Reason)
		fmt.Println("---")
	}
}

func advancedExample() {
	fmt.Println("\n=== 高级配置示例 ===")

	// 使用DoH协议
	checker := cdncheck.New(
		cdncheck.WithDoH(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := checker.CheckDomain(ctx, "www.cloudflare.com")
	if err != nil {
		log.Printf("DoH检测失败: %v", err)
		return
	}

	fmt.Printf("域名: %s\n", result.Target)
	fmt.Printf("是否CDN: %v\n", result.IsCDN)
	if result.Provider != "" {
		fmt.Printf("CDN服务商: %s\n", result.Provider)
	}
	fmt.Printf("IP列表: %v\n", result.IPs)
	fmt.Printf("检测原因: %s\n", result.Reason)
	fmt.Println("---")
}

func ipExample() {
	fmt.Println("\n=== IP检测示例 ===")

	checker := cdncheck.NewDefault()

	// 测试已知的CDN IP
	testIPs := []string{
		"104.16.1.1",  // Cloudflare
		"23.32.1.1",   // Akamai
		"8.8.8.8",     // Google (非CDN)
		"192.168.1.1", // 私有IP
	}

	for _, ip := range testIPs {
		result, err := checker.CheckIP(ip)
		if err != nil {
			log.Printf("检测IP %s 失败: %v", ip, err)
			continue
		}

		fmt.Printf("IP: %s, CDN: %v", result.Target, result.IsCDN)
		if result.Provider != "" {
			fmt.Printf(", 服务商: %s", result.Provider)
		}
		fmt.Printf(", 原因: %s\n", result.Reason)
	}
}
