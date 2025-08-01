package cdncheck

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zan8in/godns"
)

// CDNChecker 简洁的CDN检测器
type CDNChecker struct {
	dnsClient *godns.Client
	cidrCache map[string][]*net.IPNet
	mu        sync.RWMutex
	cacheOnce sync.Once
}

// CheckResult CDN检测结果
type CheckResult struct {
	Target    string    `json:"target"`    // 域名或IP
	IsCDN     bool      `json:"is_cdn"`    // 是否为CDN
	Provider  string    `json:"provider"`  // CDN服务商
	IPs       []string  `json:"ips"`       // 解析到的IP列表
	Reason    string    `json:"reason"`    // 检测原因
	Timestamp time.Time `json:"timestamp"` // 检测时间
}

var CDNProviders = map[string][]string{
	"Cloudflare": {
		// IPv4段
		"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
		"141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
		"173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
		"197.234.240.0/22", "198.41.128.0/17",
		"104.18.0.0/16", "104.19.0.0/16",
		// IPv6段
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
		"2405:b500::/32", "2405:8100::/32", "2c0f:f248::/32",
	},
	"Akamai": {
		// IPv4段
		"23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
		"184.50.0.0/15", "184.84.0.0/14", "2.16.0.0/13",
		"95.100.0.0/15", "23.0.0.0/12", "96.16.0.0/15",
		"72.246.0.0/15",
		// IPv6段
		"2600:1400::/28", "2a02:26f0::/32",
	},
	"Amazon CloudFront": {
		// IPv4段
		"54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
		"54.239.128.0/18", "54.239.192.0/19", "99.84.0.0/16",
		"205.251.192.0/19", "52.124.128.0/17", "13.32.0.0/15",
		"13.224.0.0/14", "13.35.0.0/16",
		"18.160.0.0/14", "65.9.128.0/18",
		// IPv6段
		"2600:9000::/28",
	},
	"Fastly": {
		// IPv4段
		"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
		"146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18",
		"167.82.0.0/17", "185.31.16.0/22", "199.27.72.0/21",
		"199.232.0.0/16", "159.65.0.0/16",
		// GitHub相关IP段（Fastly提供CDN服务）
		"20.205.0.0/16", "140.82.0.0/16",
		// IPv6段
		"2a04:4e40::/32", "2a04:4e42::/32",
	},
}

// New 创建CDN检测器
func New(options ...Option) *CDNChecker {
	c := &CDNChecker{
		cidrCache: make(map[string][]*net.IPNet),
	}

	// 默认配置：使用多协议DNS查询
	c.dnsClient = godns.New(
		godns.WithProtocol(godns.UDP),
		godns.WithTimeout(5*time.Second),
		godns.WithRetries(2),
	)

	// 应用自定义选项
	for _, opt := range options {
		opt(c)
	}

	c.initCIDRCache()
	return c
}

// NewDefault 创建默认配置的CDN检测器
func NewDefault() *CDNChecker {
	return New()
}

// Option 配置选项
type Option func(*CDNChecker)

// WithDNSServers 设置DNS服务器
func WithDNSServers(servers ...string) Option {
	return func(c *CDNChecker) {
		c.dnsClient = godns.New(
			godns.WithServers(servers...),
			godns.WithTimeout(5*time.Second),
			godns.WithRetries(2),
		)
	}
}

// WithDoH 启用DNS over HTTPS
func WithDoH() Option {
	return func(c *CDNChecker) {
		c.dnsClient = godns.New(
			godns.WithProtocol(godns.DoH),
			godns.WithTimeout(10*time.Second),
			godns.WithRetries(2),
		)
	}
}

// WithSOCKS5Proxy 设置SOCKS5代理
func WithSOCKS5Proxy(addr string, auth *godns.ProxyAuth) Option {
	return func(c *CDNChecker) {
		c.dnsClient = godns.New(
			godns.WithSOCKS5Proxy(addr, auth),
			godns.WithTimeout(10*time.Second),
			godns.WithRetries(2),
		)
	}
}

// WithHTTPProxy 设置HTTP代理（仅支持DoT协议）
func WithHTTPProxy(proxyURL string, auth *godns.ProxyAuth) Option {
	return func(c *CDNChecker) {
		// HTTP代理模式下强制使用DoT协议
		c.dnsClient = godns.New(
			godns.WithProtocol(godns.DoH),       // 强制使用DoT
			godns.WithHTTPProxy(proxyURL, auth), // 添加auth参数
			godns.WithTimeout(15*time.Second),   // HTTP代理可能需要更长超时
			godns.WithRetries(2),
		)
	}
}

// initCIDRCache 初始化CIDR缓存
func (c *CDNChecker) initCIDRCache() {
	c.cacheOnce.Do(func() {
		for provider, cidrs := range CDNProviders {
			for _, cidr := range cidrs {
				if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
					c.cidrCache[provider] = append(c.cidrCache[provider], ipNet)
				}
			}
		}
	})
}

// CheckDomain 检测域名是否使用CDN
func (c *CDNChecker) CheckDomain(ctx context.Context, domain string) (*CheckResult, error) {
	result := &CheckResult{
		Target:    domain,
		Timestamp: time.Now(),
	}

	// 并发查询IPv4和IPv6
	var ipv4IPs, ipv6IPs []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(2)

	// 查询A记录（IPv4）
	go func() {
		defer wg.Done()
		if dnsResult, err := c.dnsClient.MultiQueryA(ctx, domain); err == nil {
			mu.Lock()
			ipv4IPs = dnsResult.AllIPs
			mu.Unlock()
		}
	}()

	// 查询AAAA记录（IPv6）
	go func() {
		defer wg.Done()
		if dnsResult, err := c.dnsClient.MultiQueryAAAA(ctx, domain); err == nil {
			mu.Lock()
			ipv6IPs = dnsResult.AllIPs
			mu.Unlock()
		}
	}()

	wg.Wait()

	// 合并IPv4和IPv6地址
	allIPs := append(ipv4IPs, ipv6IPs...)
	if len(allIPs) == 0 {
		result.Reason = "DNS查询无结果"
		return result, nil
	}

	result.IPs = allIPs

	// 多重验证策略
	isCDN, provider := c.validateCDN(allIPs)
	result.IsCDN = isCDN
	result.Provider = provider

	if isCDN {
		result.Reason = "检测到CDN特征"
	} else {
		result.Reason = "未检测到CDN特征"
	}

	return result, nil
}

// CheckIP 检测IP是否属于CDN
func (c *CDNChecker) CheckIP(ip string) (*CheckResult, error) {
	result := &CheckResult{
		Target:    ip,
		IPs:       []string{ip},
		Timestamp: time.Now(),
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		result.Reason = "无效的IP地址"
		return result, nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for provider, networks := range c.cidrCache {
		for _, network := range networks {
			if network.Contains(parsedIP) {
				result.IsCDN = true
				result.Provider = provider
				result.Reason = "IP属于" + provider + "CDN网段"
				return result, nil
			}
		}
	}

	result.Reason = "IP不属于已知CDN网段"
	return result, nil
}

// validateCDN 多重验证CDN（避免误报和漏报）
func (c *CDNChecker) validateCDN(ips []string) (bool, string) {
	if len(ips) == 0 {
		return false, ""
	}

	// 策略1: IP段匹配
	providerCount := make(map[string]int)
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		c.mu.RLock()
		for provider, networks := range c.cidrCache {
			for _, network := range networks {
				if network.Contains(parsedIP) {
					providerCount[provider]++
					break
				}
			}
		}
		c.mu.RUnlock()
	}

	// 策略2: 多IP检测（CDN通常返回多个IP）
	hasMultipleIPs := len(ips) >= 2

	// 策略3: 地理分布检测（简化版）
	hasGeoDistribution := c.checkGeoDistribution(ips)

	// 综合判断
	if len(providerCount) > 0 {
		// 找到匹配的CDN服务商
		maxCount := 0
		maxProvider := ""
		for provider, count := range providerCount {
			if count > maxCount {
				maxCount = count
				maxProvider = provider
			}
		}
		return true, maxProvider
	}

	// 基于其他特征判断
	if hasMultipleIPs && hasGeoDistribution {
		return true, ""
	}

	return false, ""
}

// checkGeoDistribution 检查IP地理分布（简化实现）
func (c *CDNChecker) checkGeoDistribution(ips []string) bool {
	if len(ips) < 2 {
		return false
	}

	ipv4Subnets := make(map[string]bool)
	ipv6Subnets := make(map[string]bool)

	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		if ipv4 := parsedIP.To4(); ipv4 != nil {
			// IPv4地理分布检测（/16网段）
			subnet := fmt.Sprintf("%d.%d", ipv4[0], ipv4[1])
			ipv4Subnets[subnet] = true
		} else {
			// IPv6地理分布检测（前32位）
			ipv6 := parsedIP.To16()
			subnet := fmt.Sprintf("%02x%02x:%02x%02x", ipv6[0], ipv6[1], ipv6[2], ipv6[3])
			ipv6Subnets[subnet] = true
		}
	}

	// 如果IPv4或IPv6有多个不同网段，认为有地理分布
	return len(ipv4Subnets) > 1 || len(ipv6Subnets) > 1
}

// AddCustomProvider 添加自定义CDN服务商
func (c *CDNChecker) AddCustomProvider(name string, cidrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cidr := range cidrs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			c.cidrCache[name] = append(c.cidrCache[name], ipNet)
		}
	}
}

// GetProviders 获取所有CDN服务商列表
func (c *CDNChecker) GetProviders() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	providers := make([]string, 0, len(c.cidrCache))
	for provider := range c.cidrCache {
		providers = append(providers, provider)
	}
	return providers
}
