# CDNCheck

一个简洁高效的Go语言CDN检测库，基于godns实现多协议DNS查询和IPv6支持。

## 特性

- 🚀 **高性能**: 基于godns的并发DNS查询
- 🌐 **IPv6支持**: 同时检测IPv4和IPv6地址
- 🔍 **多重验证**: IP段匹配、多IP检测、地理分布分析
- 📡 **多协议支持**: UDP、DoH、DoT、SOCKS5/HTTP代理
- 🎯 **准确检测**: 内置主流CDN服务商IP段
- 💡 **简洁设计**: 遵循"less is more"原则

## 支持的CDN服务商

- **Cloudflare**: IPv4/IPv6完整支持
- **Akamai**: 包含最新IP段
- **Amazon CloudFront**: AWS全球节点
- **Fastly**: 包含GitHub等知名服务

## 安装

```bash
go get github.com/zan8in/cdncheck
```

## 快速开始

### 基本使用

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/zan8in/cdncheck"
)

func main() {
    // 创建检测器
    checker := cdncheck.NewDefault()
    
    // 检测域名
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    result, err := checker.CheckDomain(ctx, "github.com")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("域名: %s\n", result.Target)
    fmt.Printf("是否CDN: %v\n", result.IsCDN)
    fmt.Printf("CDN服务商: %s\n", result.Provider)
    fmt.Printf("IP列表: %v\n", result.IPs)
}
```

### 高级配置

```go
// 使用DoH协议
checker := cdncheck.New(
    cdncheck.WithDoH(),
)

// 自定义DNS服务器
checker := cdncheck.New(
    cdncheck.WithDNSServers("8.8.8.8:53", "1.1.1.1:53"),
)

// 使用SOCKS5代理
checker := cdncheck.New(
    cdncheck.WithSOCKS5Proxy("127.0.0.1:1080", nil),
)

// 使用HTTP代理（强制DoH协议）
checker := cdncheck.New(
    cdncheck.WithHTTPProxy("127.0.0.1:8080", nil),
)

// 使用带认证的HTTP代理
auth := &godns.ProxyAuth{
    Username: "user",
    Password: "pass",
}
checker := cdncheck.New(
    cdncheck.WithHTTPProxy("127.0.0.1:8080", auth),
)
```

### IP检测

```go
// 直接检测IP是否属于CDN
result, err := checker.CheckIP("104.16.1.1")
if err != nil {
    panic(err)
}

fmt.Printf("IP: %s, CDN: %v, 服务商: %s\n", 
    result.Target, result.IsCDN, result.Provider)
```

### 自定义CDN提供商

```go
// 添加自定义CDN服务商
checker.AddCustomProvider("MyCDN", []string{
    "192.168.1.0/24",
    "2001:db8::/32",
})
```

## API文档

### 核心类型

```go
type CheckResult struct {
    Target    string    `json:"target"`    // 域名或IP
    IsCDN     bool      `json:"is_cdn"`    // 是否为CDN
    Provider  string    `json:"provider"`  // CDN服务商
    IPs       []string  `json:"ips"`       // 解析到的IP列表
    Reason    string    `json:"reason"`    // 检测原因
    Timestamp time.Time `json:"timestamp"` // 检测时间
}
```

### 主要方法

#### `NewDefault() *CDNChecker`
创建默认配置的CDN检测器

#### `New(options ...Option) *CDNChecker`
创建自定义配置的CDN检测器

#### `CheckDomain(ctx context.Context, domain string) (*CheckResult, error)`
检测域名是否使用CDN（支持IPv4+IPv6）

#### `CheckIP(ip string) (*CheckResult, error)`
检测IP是否属于CDN网段

#### `AddCustomProvider(name string, cidrs []string)`
添加自定义CDN服务商

### 配置选项

- `WithDNSServers(servers ...string)`: 设置DNS服务器
- `WithDoH()`: 启用DNS over HTTPS
- `WithSOCKS5Proxy(addr string, auth *godns.ProxyAuth)`: 设置SOCKS5代理
- `WithHTTPProxy(proxyURL string, auth *godns.ProxyAuth)`: 设置HTTP代理（强制使用DoT协议）

## 检测策略

本库采用多重验证策略确保检测准确性：

1. **IP段匹配**: 检查IP是否属于已知CDN网段
2. **多IP检测**: CDN通常返回多个IP地址
3. **地理分布**: 分析IP的地理分布特征
4. **IPv6支持**: 同时分析IPv4和IPv6地址

## 性能特点

- **并发查询**: 同时查询A和AAAA记录
- **缓存优化**: 内置CIDR缓存提高查询效率
- **超时控制**: 支持context超时控制
- **错误处理**: 优雅的错误处理和降级策略

## 示例输出

```json
{
  "target": "github.com",
  "is_cdn": true,
  "provider": "Fastly",
  "ips": ["140.82.116.4", "20.205.243.166"],
  "reason": "检测到CDN特征",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 运行示例

```bash
# 运行示例程序
cd example
go run main.go
```

## 依赖

- Go 1.24+
- [godns](https://github.com/zan8in/godns) - 高性能DNS查询库

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

## 更新日志

### v1.0.0
- 初始版本发布
- 支持IPv4/IPv6双栈检测
- 集成godns多协议支持
- 内置主流CDN服务商数据