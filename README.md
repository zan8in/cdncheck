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
- 🔒 **代理支持** - 支持HTTP和SOCKS5代理，企业环境友好
- 🌍 **DNS-over-HTTPS (DoH)** - 安全的DNS查询，绕过DNS污染

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

### 代理配置

#### HTTP代理 + DoH（推荐）

```go
config := &cdncheck.Config{
    // 启用DoH（推荐）
    EnableDoH: true,
    DoHServers: []string{
        "https://1.1.1.1/dns-query",        // Cloudflare DoH
        "https://8.8.8.8/resolve",          // Google DoH
        "https://dns.alidns.com/dns-query",  // 阿里DoH
        "https://doh.pub/dns-query",         // 腾讯DoH
    },

    // 配置HTTP代理
    EnableProxy: true,
    Proxy: cdncheck.ProxyConfig{
        Type:     "http",
        URL:      "http://proxy.company.com:8080",
        Username: "user",     // 可选认证
        Password: "pass",     // 可选认证
        Timeout:  10 * time.Second,
    },

    // 传统DNS作为回退
    DNSServers: []string{"8.8.8.8:53", "1.1.1.1:53"},
    DNSTimeout: 10 * time.Second,
    RetryCount: 3,
    Concurrency: 10,
}

checker, err := cdncheck.NewCDNChecker(config)
if err != nil {
    log.Fatal(err)
}
```

#### SOCKS5代理

```go
config := &cdncheck.Config{
    EnableProxy: true,
    Proxy: cdncheck.ProxyConfig{
        Type: "socks5",
        URL:  "socks5://127.0.0.1:1080",
        Timeout: 10 * time.Second,
    },
    // ... 其他配置
}
```

#### 动态代理管理

```go
// 设置HTTP代理
err := checker.SetHTTPProxy("http://proxy.example.com:8080", "user", "pass")
if err != nil {
    log.Fatal(err)
}

// 设置SOCKS5代理
err = checker.SetSOCKS5Proxy("socks5://127.0.0.1:1080")
if err != nil {
    log.Fatal(err)
}

// 禁用代理
checker.DisableProxy()

// 检查代理状态
enabled, proxyType, proxyURL := checker.GetProxyStatus()
fmt.Printf("代理状态: %t, 类型: %s, URL: %s\n", enabled, proxyType, proxyURL)
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

#### ProxyConfig

```go
type ProxyConfig struct {
    Type     string        `json:"type"`     // "http", "socks5"
    URL      string        `json:"url"`      // 代理服务器URL
    Username string        `json:"username"` // 认证用户名（可选）
    Password string        `json:"password"` // 认证密码（可选）
    Timeout  time.Duration `json:"timeout"`  // 代理连接超时
}
```

#### Config

```go
type Config struct {
    // DNS配置
    DNSServers    []string      // 传统DNS服务器列表
    DNSTimeout    time.Duration // DNS查询超时时间
    RetryCount    int           // 重试次数
    RetryInterval time.Duration // 重试间隔

    // 检测配置
    EnableMultiIP     bool // 是否启用多IP检测
    EnableMultipleDNS bool // 是否启用多DNS服务器查询
    Concurrency       int  // 并发数

    // DoH配置（推荐）
    EnableDoH  bool     `json:"enable_doh"`  // 是否启用DNS-over-HTTPS
    DoHServers []string `json:"doh_servers"` // DoH服务器列表

    // 代理配置
    EnableProxy bool        `json:"enable_proxy"` // 是否启用代理
    Proxy       ProxyConfig `json:"proxy"`        // 代理配置

    // 自定义CDN提供商
    CustomProviders map[string][]string
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

#### 代理管理

- `SetProxy(proxyType, proxyURL string, auth ...string) error` - 设置代理
- `SetHTTPProxy(proxyURL string, auth ...string) error` - 设置HTTP代理（便捷方法）
- `SetSOCKS5Proxy(proxyURL string, auth ...string) error` - 设置SOCKS5代理（便捷方法）
- `DisableProxy()` - 禁用代理
- `GetProxyStatus() (bool, string, string)` - 获取代理状态

#### DoH管理

- `EnableDoH(dohServers ...string)` - 启用DoH
- `DisableDoH()` - 禁用DoH

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

## 代理功能详解

### 支持的代理类型

#### 1. HTTP代理（推荐）
- **优势**: 与DoH完美兼容，企业环境友好
- **适用场景**: 企业内网、防火墙环境
- **认证支持**: 支持用户名/密码认证

#### 2. SOCKS5代理
- **优势**: 支持TCP/UDP流量
- **适用场景**: 特殊网络环境、隐私保护
- **限制**: 不直接支持DNS查询，需配合DoH使用

### DNS解析策略

库采用智能DNS解析策略，优先级如下：

1. **DNS-over-HTTPS (DoH)** - 通过HTTPS加密传输，支持HTTP代理
2. **代理DNS** - 通过配置的代理进行DNS查询
3. **传统DNS** - 直连DNS服务器（回退方案）

### 企业环境最佳实践

```go
// 企业环境推荐配置
config := &cdncheck.Config{
    // 优先使用DoH，绕过DNS限制
    EnableDoH: true,
    DoHServers: []string{
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/resolve",
    },
    
    // 配置企业HTTP代理
    EnableProxy: true,
    Proxy: cdncheck.ProxyConfig{
        Type:     "http",
        URL:      "http://proxy.company.com:8080",
        Username: "domain\\username", // Windows域认证
        Password: "password",
        Timeout:  30 * time.Second,
    },
    
    // 增加超时和重试，适应企业网络
    DNSTimeout:    15 * time.Second,
    RetryCount:    5,
    RetryInterval: 200 * time.Millisecond,
}
```

### 代理故障排除

#### 常见问题

1. **代理连接失败**
   - 检查代理服务器地址和端口
   - 验证认证信息
   - 确认网络连通性

2. **DNS解析失败**
   - 启用DoH作为主要解析方式
   - 配置多个DoH服务器
   - 检查防火墙HTTPS出站规则

3. **性能问题**
   - 调整代理超时时间
   - 减少并发数
   - 使用就近的代理服务器

#### 调试示例

```go
// 启用详细日志
config.Debug = true

// 测试代理连接
checker, err := cdncheck.NewCDNChecker(config)
if err != nil {
    log.Printf("配置错误: %v", err)
    return
}

// 检查代理状态
enabled, proxyType, proxyURL := checker.GetProxyStatus()
log.Printf("代理状态: 启用=%t, 类型=%s, URL=%s", enabled, proxyType, proxyURL)

// 测试简单域名解析
result, err := checker.CheckDomain("example.com")
if err != nil {
    log.Printf("检测失败: %v", err)
} else {
    log.Printf("检测成功: %+v", result)
}
```

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
- **代理连接池**: 复用代理连接减少建立开销
- **DoH缓存**: 缓存DoH查询结果提高响应速度

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
- `proxy_error` - 代理连接错误
- `doh_error` - DoH查询错误

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

### v2.1.0
- 🔒 **新增代理支持** - HTTP和SOCKS5代理
- 🌍 **DNS-over-HTTPS (DoH)** - 安全的DNS查询
- 🏢 **企业环境优化** - 代理认证、防火墙友好
- 🔄 **智能DNS策略** - DoH > 代理DNS > 传统DNS
- 🛠️ **动态代理管理** - 运行时切换代理配置
- 📊 **增强错误处理** - 代理和DoH相关错误分类

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