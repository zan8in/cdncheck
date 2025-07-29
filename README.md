# CDNCheck

一个高性能的Go语言CDN检测库，用于检测域名和IP地址是否使用了CDN服务。

## 特性

- 🚀 高性能并发检测
- 🌐 支持多种主流CDN提供商（Cloudflare、Akamai、Amazon CloudFront等）
- 🔧 可配置的DNS设置和重试机制
- 📊 详细的检测结果和统计信息
- 🎯 支持批量域名/IP检测
- 🔄 支持自定义CDN提供商
- ⚡ CIDR缓存优化性能
- 🕐 Context超时控制

## 安装

```bash
go get github.com/zan8in/cdncheck
```

## 快速开始

### 基本用法

```go
package main

import (
    "fmt"
    "log"
    "github.com/zan8in/cdncheck"
)

func main() {
    // 创建默认配置的检测器
    checker, err := cdncheck.NewDefaultCDNChecker()
    if err != nil {
        log.Fatal(err)
    }

    // 检测域名
    result, err := checker.CheckDomain("example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("域名: %s\n", result.Domain)
    fmt.Printf("使用CDN: %t\n", result.IsCDN)
    if result.IsCDN {
        fmt.Printf("CDN提供商: %v\n", result.Providers)
    }
}
```

### 自定义配置

```go
config := &cdncheck.Config{
    DNSServers: []string{"8.8.8.8:53", "1.1.1.1:53"},
    DNSTimeout: 5 * time.Second,
    MaxRetries: 3,
    MaxConcurrency: 50,
}

checker, err := cdncheck.NewCDNChecker(config)
if err != nil {
    log.Fatal(err)
}
```

### 批量检测

```go
// 批量检测域名
domains := []string{"example.com", "google.com", "github.com"}
results, err := checker.CheckDomains(domains)
if err != nil {
    log.Fatal(err)
}

for _, result := range results {
    fmt.Printf("%s: CDN=%t\n", result.Domain, result.IsCDN)
}

// 批量检测IP
ips := []string{"1.1.1.1", "8.8.8.8", "104.16.0.1"}
ipResults, err := checker.CheckIPs(ips)
if err != nil {
    log.Fatal(err)
}

for _, result := range ipResults {
    fmt.Printf("%s: CDN=%t\n", result.IP, result.IsCDN)
}
```

### 自定义CDN提供商

```go
// 添加自定义CDN提供商
err := checker.AddCustomProvider("MyCustomCDN", []string{"192.168.1.0/24"})
if err != nil {
    log.Fatal(err)
}

// 检测IP是否属于自定义CDN
result := checker.IsCDNIP("192.168.1.100")
fmt.Printf("IP 192.168.1.100 使用CDN: %t\n", result.IsCDN)
```

### Context超时控制

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

result, err := checker.CheckDomainWithContext(ctx, "example.com")
if err != nil {
    log.Fatal(err)
}
```

### IP数组格式化

```go
ips := []string{"1.1.1.1", "8.8.8.8", "104.16.0.1"}

// 按行分隔
lineFormat := cdncheck.IPsToStringWithFormat(ips, "line")
fmt.Println(lineFormat)

// 空格分隔
spaceFormat := cdncheck.IPsToStringWithFormat(ips, "space")
fmt.Println(spaceFormat)

// JSON格式
jsonFormat := cdncheck.IPsToStringWithFormat(ips, "json")
fmt.Println(jsonFormat)

// 自定义分隔符
customFormat := cdncheck.IPsToStringWithFormat(ips, ",")
fmt.Println(customFormat)
```

## API文档

### 核心结构

#### CDNChecker

主要的CDN检测器结构，提供所有检测功能。

#### Config

```go
type Config struct {
    DNSServers     []string      // DNS服务器列表
    DNSTimeout     time.Duration // DNS查询超时时间
    MaxRetries     int           // 最大重试次数
    MaxConcurrency int           // 最大并发数
    CustomProviders map[string][]string // 自定义CDN提供商
}
```

#### CheckResult

```go
type CheckResult struct {
    Domain    string          // 检测的域名
    IsCDN     bool           // 是否使用CDN
    Providers []string       // CDN提供商列表
    IPs       []IPCheckResult // IP检测结果
    Error     *CheckError    // 错误信息
}
```

#### IPCheckResult

```go
type IPCheckResult struct {
    IP        string   // IP地址
    IsCDN     bool     // 是否为CDN IP
    Providers []string // CDN提供商列表
}
```

### 主要方法

#### 创建检测器

- `NewDefaultCDNChecker() (*CDNChecker, error)` - 创建默认配置的检测器
- `NewCDNChecker(config *Config) (*CDNChecker, error)` - 创建自定义配置的检测器

#### 域名检测

- `CheckDomain(domain string) (*CheckResult, error)` - 检测单个域名
- `CheckDomainWithContext(ctx context.Context, domain string) (*CheckResult, error)` - 带超时控制的域名检测
- `CheckDomains(domains []string) ([]*CheckResult, error)` - 批量检测域名

#### IP检测

- `IsCDNIP(ip string) *IPCheckResult` - 检测单个IP
- `CheckIPs(ips []string) ([]*IPCheckResult, error)` - 批量检测IP

#### 提供商管理

- `AddCustomProvider(name string, cidrs []string) error` - 添加自定义CDN提供商
- `RemoveCustomProvider(name string)` - 移除自定义CDN提供商
- `GetCustomProviders() map[string][]string` - 获取所有自定义提供商

#### 配置管理

- `UpdateConfig(config *Config) error` - 更新配置
- `GetConfig() *Config` - 获取当前配置
- `GetStatistics() *Statistics` - 获取统计信息

#### 工具函数

- `IPsToString(ips []string) string` - 将IP数组转换为字符串（按行分隔）
- `IPsToStringWithFormat(ips []string, format string) string` - 按指定格式转换IP数组

## 支持的CDN提供商

库内置了以下主流CDN提供商的IP范围：

- **Cloudflare** - 全球领先的CDN和安全服务
- **Akamai** - 企业级CDN解决方案
- **Amazon CloudFront** - AWS的CDN服务
- **Fastly** - 边缘云平台
- **Google Cloud CDN** - 谷歌云CDN服务
- **Microsoft Azure CDN** - 微软云CDN服务

## 性能优化

- **CIDR缓存**: 预编译CIDR范围以提高IP检测性能
- **并发控制**: 可配置的并发限制避免资源过度使用
- **DNS重试**: 智能重试机制提高检测可靠性
- **内存优化**: 使用strings.Builder优化字符串操作

## 错误处理

库提供了详细的错误分类：

```go
type CheckError struct {
    Domain string    // 相关域名
    Type   string    // 错误类型
    Err    error     // 原始错误
}
```

错误类型包括：
- `dns_resolution` - DNS解析错误
- `validation` - 输入验证错误
- `timeout` - 超时错误
- `network` - 网络错误

## 统计信息

```go
type Statistics struct {
    TotalChecks     int64            // 总检测次数
    CDNDetected     int64            // 检测到CDN的次数
    ProviderCounts  map[string]int64 // 各提供商检测次数
    AverageLatency  time.Duration    // 平均延迟
}
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

## 更新日志

### v2.0.0
- 重构核心架构，移除向后兼容代码
- 添加Context超时控制
- 新增批量IP检测功能
- 添加CIDR缓存优化
- 增强错误处理和统计功能
- 新增IP数组格式化工具

### v1.x.x
- 基础CDN检测功能
- 支持主流CDN提供商
- 自定义提供商支持