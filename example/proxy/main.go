package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zan8in/cdncheck"
)

func main() {
	// SOCKS5代理示例
	socks5Example()

	// HTTP代理示例
	httpProxyExample()
}

func socks5Example() {
	fmt.Println("=== SOCKS5代理CDN检测 ===")

	// 创建SOCKS5代理检测器
	checker := cdncheck.New(
		cdncheck.WithSOCKS5Proxy("127.0.0.1:20170", nil),
		cdncheck.WithTimeout(3*time.Second),
		cdncheck.WithRetries(1),
	)

	testDomains(checker)
}

func httpProxyExample() {
	fmt.Println("\n=== HTTP代理CDN检测（仅DoH协议）===")

	// 创建HTTP代理检测器，强制使用DoH协议
	checker := cdncheck.New(
		cdncheck.WithHTTPProxy("127.0.0.1:20170", nil),
		cdncheck.WithTimeout(3*time.Second),
		cdncheck.WithRetries(1),
	)

	testDomains(checker)
}

func testDomains(checker *cdncheck.CDNChecker) {
	// 检测域名
	domains := []string{"www.baidu.com", "github.com", "example.com", "deepseek.com", "qq.com", "x.com"}
	for _, domain := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
