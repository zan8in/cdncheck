package main

import (
	"fmt"
	"log"

	"github.com/zan8in/cdncheck"
)

func main() {
	// 创建自定义CDN检测器
	// 导入 cdncheck 包

	checker := cdncheck.NewDefaultCDNChecker()

	// 添加自定义提供商
	checker.AddCustomProvider("MyCDN", []string{"192.168.66.0/24", "10.0.0.0/8"})

	// 检查域名
	result, err := checker.CheckDomains([]string{"192.168.66.100", "example.com"})
	if err != nil {
		log.Printf("检查域名失败: %v", err)
	} else {
		for _, r := range result {
			fmt.Printf("域名: %s, 是否CDN: %v, 提供商: %s\n", r.Domain, r.IsCDN, r.Provider)
		}
	}
}
