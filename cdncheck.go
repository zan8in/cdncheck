package cdncheck

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// CDNChecker CDN检测器
type CDNChecker struct {
	config    *Config
	mu        sync.RWMutex
	cidrCache map[string][]*net.IPNet
	cacheOnce sync.Once
}

// Config CDN检测配置
type Config struct {
	// DNS配置
	DNSServers    []string      // DNS服务器列表
	DNSTimeout    time.Duration // DNS查询超时时间
	RetryCount    int           // 重试次数
	RetryInterval time.Duration // 重试间隔

	// 检测配置
	EnableMultiIP     bool // 是否启用多IP检测
	EnableMultipleDNS bool // 是否启用多DNS服务器查询
	Concurrency       int  // 并发数

	// 自定义CDN提供商
	CustomProviders map[string][]string
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		DNSServers: []string{
			"8.8.8.8:53",         // Google DNS
			"1.1.1.1:53",         // Cloudflare DNS
			"114.114.114.114:53", // 114 DNS
			"223.5.5.5:53",       // 阿里DNS
		},
		DNSTimeout:        3 * time.Second,
		RetryCount:        3,
		RetryInterval:     50 * time.Millisecond,
		EnableMultiIP:     true,
		EnableMultipleDNS: true,
		Concurrency:       10,
		CustomProviders:   make(map[string][]string),
	}
}

// Validate 配置验证
func (c *Config) Validate() error {
	if c.DNSTimeout <= 0 {
		return fmt.Errorf("DNS超时时间必须大于0")
	}
	if c.RetryCount < 0 {
		return fmt.Errorf("重试次数不能为负数")
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("并发数必须大于0")
	}
	// 验证DNS服务器格式
	for _, server := range c.DNSServers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return fmt.Errorf("无效的DNS服务器格式: %s", server)
		}
	}
	return nil
}

// NewCDNChecker 创建新的CDN检测器
func NewCDNChecker(config *Config) (*CDNChecker, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}
	return &CDNChecker{
		config: config,
	}, nil
}

// NewDefaultCDNChecker 创建默认配置的CDN检测器
func NewDefaultCDNChecker() *CDNChecker {
	checker, _ := NewCDNChecker(DefaultConfig())
	return checker
}

// CDNProvider 内置CDN提供商CIDR列表
var CDNProvider = map[string][]string{
	"Cloudflare":        {"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"},
	"Akamai":            {"23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14", "2.16.0.0/13", "95.100.0.0/15", "23.0.0.0/12", "96.16.0.0/15", "72.246.0.0/15"},
	"Amazon CloudFront": {"54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "54.239.192.0/19", "99.84.0.0/16", "205.251.192.0/19", "52.124.128.0/17", "204.246.164.0/22", "204.246.168.0/22", "204.246.174.0/23", "204.246.176.0/20", "13.32.0.0/15", "13.224.0.0/14", "13.35.0.0/16", "204.246.172.0/24", "204.246.173.0/24"},
	"Fastly":            {"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20", "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"},
	"Google":            {"34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17", "35.199.128.0/18", "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13", "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "70.32.128.0/19", "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19"},
	"Microsoft Azure":   {"13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.33.0.0/16", "20.34.0.0/15", "20.36.0.0/14", "20.40.0.0/13", "20.48.0.0/12", "20.64.0.0/10", "20.128.0.0/16", "20.135.0.0/16", "20.136.0.0/16", "20.143.0.0/16", "20.144.0.0/14", "20.150.0.0/15", "20.152.0.0/16", "20.153.0.0/16", "20.157.0.0/16", "20.158.0.0/15", "20.160.0.0/12", "20.176.0.0/14", "20.180.0.0/14", "20.184.0.0/13", "20.192.0.0/10"},
}

// CheckResult CDN检测结果
type CheckResult struct {
	Domain    string            `json:"domain"`
	IPs       []string          `json:"ips"`
	IsCDN     bool              `json:"is_cdn"`
	Provider  string            `json:"provider,omitempty"`
	Reason    string            `json:"reason"`
	Details   []IPCheckResult   `json:"details,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// IPCheckResult 单个IP的检测结果
type IPCheckResult struct {
	IP       string `json:"ip"`
	IsCDN    bool   `json:"is_cdn"`
	Provider string `json:"provider,omitempty"`
	Reason   string `json:"reason"`
}

// CheckError 检测错误
type CheckError struct {
	Domain string
	Err    error
	Type   string // "dns_error", "timeout", "invalid_domain"
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("CDN检测错误 [%s] %s: %v", e.Type, e.Domain, e.Err)
}

// Statistics 统计信息
type Statistics struct {
	TotalChecked   int            `json:"total_checked"`
	CDNCount       int            `json:"cdn_count"`
	NonCDNCount    int            `json:"non_cdn_count"`
	ProviderStats  map[string]int `json:"provider_stats"`
	AverageLatency time.Duration  `json:"average_latency"`
}

// 域名验证正则表达式
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)

// isValidDomain 验证域名格式
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}

// initCIDRCache 预编译CIDR缓存
func (c *CDNChecker) initCIDRCache() {
	c.cidrCache = make(map[string][]*net.IPNet)

	// 预编译内置CDN提供商的CIDR
	for provider, cidrs := range CDNProvider {
		var nets []*net.IPNet
		for _, cidr := range cidrs {
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				nets = append(nets, ipNet)
			}
		}
		c.cidrCache[provider] = nets
	}

	// 预编译自定义CDN提供商的CIDR
	for provider, cidrs := range c.config.CustomProviders {
		var nets []*net.IPNet
		for _, cidr := range cidrs {
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				nets = append(nets, ipNet)
			}
		}
		c.cidrCache[provider] = nets
	}
}

// IsCDNIP 检查IP是否属于CDN提供商（优化版本）
func (c *CDNChecker) IsCDNIP(ip string) (bool, string) {
	c.cacheOnce.Do(c.initCIDRCache)
	c.mu.RLock()
	defer c.mu.RUnlock()

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, ""
	}

	// 使用预编译的CIDR缓存
	for provider, nets := range c.cidrCache {
		for _, ipNet := range nets {
			if ipNet.Contains(ipAddr) {
				return true, provider
			}
		}
	}

	return false, ""
}

// CheckDomain 检查单个域名
func (c *CDNChecker) CheckDomain(domain string) (*CheckResult, error) {
	return c.CheckDomainWithContext(context.Background(), domain)
}

// CheckDomainWithContext 带上下文的域名检查
func (c *CDNChecker) CheckDomainWithContext(ctx context.Context, domain string) (*CheckResult, error) {
	select {
	case <-ctx.Done():
		return nil, &CheckError{Domain: domain, Err: ctx.Err(), Type: "timeout"}
	default:
	}

	if domain == "" {
		return nil, &CheckError{Domain: domain, Err: fmt.Errorf("域名不能为空"), Type: "invalid_domain"}
	}

	domain = strings.TrimSpace(strings.ToLower(domain))

	if !isValidDomain(domain) {
		return nil, &CheckError{Domain: domain, Err: fmt.Errorf("无效的域名格式"), Type: "invalid_domain"}
	}

	result := &CheckResult{
		Domain:    domain,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	// 检查context是否被取消
	select {
	case <-ctx.Done():
		return nil, &CheckError{Domain: domain, Err: ctx.Err(), Type: "timeout"}
	default:
	}

	// 获取IP地址
	ips, err := c.resolveIPsWithContext(ctx, domain)
	if err != nil {
		return nil, &CheckError{Domain: domain, Err: err, Type: "dns_error"}
	}

	if len(ips) == 0 {
		return nil, &CheckError{Domain: domain, Err: fmt.Errorf("无法解析域名"), Type: "dns_error"}
	}

	result.IPs = ips
	result.Metadata["ip_count"] = fmt.Sprintf("%d", len(ips))

	// 检查每个IP
	var details []IPCheckResult
	cdnCount := 0
	providers := make(map[string]int)

	for _, ip := range ips {
		isCDN, provider := c.IsCDNIP(ip)
		detail := IPCheckResult{
			IP:    ip,
			IsCDN: isCDN,
		}

		if isCDN {
			cdnCount++
			detail.Provider = provider
			detail.Reason = "已知CDN提供商"
			providers[provider]++
		} else {
			detail.Reason = "非CDN IP"
		}

		details = append(details, detail)
	}

	result.Details = details

	// 判断整体CDN状态
	if cdnCount > 0 {
		result.IsCDN = true
		if len(providers) == 1 {
			// 单一提供商
			for provider := range providers {
				result.Provider = provider
				break
			}
			result.Reason = "已知CDN提供商"
		} else if len(providers) > 1 {
			// 多个提供商
			var providerList []string
			for provider := range providers {
				providerList = append(providerList, provider)
			}
			result.Provider = strings.Join(providerList, ",")
			result.Reason = "多CDN提供商"
		}
	} else if c.config.EnableMultiIP && len(ips) > 1 {
		// 多IP可能是CDN
		result.IsCDN = true
		result.Reason = "多IP可能CDN"
	} else {
		result.IsCDN = false
		result.Reason = "非CDN"
	}

	return result, nil
}

// CheckDomains 批量检查域名
func (c *CDNChecker) CheckDomains(domains []string) ([]*CheckResult, []error) {
	if len(domains) == 0 {
		return nil, nil
	}

	var results []*CheckResult
	var errors []error
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 控制并发数
	semaphore := make(chan struct{}, c.config.Concurrency)

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			result, err := c.CheckDomain(d)
			mu.Lock()
			if err != nil {
				errors = append(errors, err)
			} else {
				results = append(results, result)
			}
			mu.Unlock()
		}(domain)
	}

	wg.Wait()
	return results, errors
}

// CheckIPs 批量检查IP地址
func (c *CDNChecker) CheckIPs(ips []string) []IPCheckResult {
	var results []IPCheckResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 控制并发数
	semaphore := make(chan struct{}, c.config.Concurrency)

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			isCDN, provider := c.IsCDNIP(ipAddr)
			result := IPCheckResult{
				IP:    ipAddr,
				IsCDN: isCDN,
			}

			if isCDN {
				result.Provider = provider
				result.Reason = "已知CDN提供商"
			} else {
				result.Reason = "非CDN IP"
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()

	// 按IP地址排序结果
	sort.Slice(results, func(i, j int) bool {
		return results[i].IP < results[j].IP
	})

	return results
}

// resolveIPs 解析域名获取IP地址
func (c *CDNChecker) resolveIPs(domain string) ([]string, error) {
	return c.resolveIPsWithContext(context.Background(), domain)
}

// resolveIPsWithContext 带上下文的DNS解析
func (c *CDNChecker) resolveIPsWithContext(ctx context.Context, domain string) ([]string, error) {
	if c.config.EnableMultipleDNS {
		return c.resolveWithMultipleDNS(ctx, domain)
	}
	return c.resolveWithRetry(ctx, domain)
}

// resolveWithRetry 带重试的DNS解析
func (c *CDNChecker) resolveWithRetry(ctx context.Context, domain string) ([]string, error) {
	allIPs := make(map[string]bool)

	for i := 0; i < c.config.RetryCount; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ips, err := net.LookupIP(domain)
		if err != nil {
			if i == c.config.RetryCount-1 {
				return nil, err
			}
			time.Sleep(c.config.RetryInterval)
			continue
		}

		for _, ip := range ips {
			allIPs[ip.String()] = true
		}

		if i < c.config.RetryCount-1 {
			time.Sleep(c.config.RetryInterval)
		}
	}

	var result []string
	for ip := range allIPs {
		result = append(result, ip)
	}

	return result, nil
}

// resolveWithMultipleDNS 使用多个DNS服务器解析
func (c *CDNChecker) resolveWithMultipleDNS(ctx context.Context, domain string) ([]string, error) {
	allIPs := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, dnsServer := range c.config.DNSServers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: c.config.DNSTimeout,
					}
					return d.DialContext(ctx, network, server)
				},
			}

			ctx, cancel := context.WithTimeout(ctx, c.config.DNSTimeout)
			defer cancel()

			ips, err := r.LookupIPAddr(ctx, domain)
			if err == nil {
				mu.Lock()
				for _, ip := range ips {
					allIPs[ip.IP.String()] = true
				}
				mu.Unlock()
			}
		}(dnsServer)
	}

	wg.Wait()

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("所有DNS服务器都无法解析域名")
	}

	var result []string
	for ip := range allIPs {
		result = append(result, ip)
	}

	return result, nil
}

// AddCustomProvider 添加自定义CDN提供商
func (c *CDNChecker) AddCustomProvider(name string, cidrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.CustomProviders[name] = cidrs
	// 重置缓存，下次调用时重新初始化
	c.cacheOnce = sync.Once{}
}

// RemoveCustomProvider 移除自定义CDN提供商
func (c *CDNChecker) RemoveCustomProvider(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.config.CustomProviders, name)
	// 重置缓存，下次调用时重新初始化
	c.cacheOnce = sync.Once{}
}

// GetProviders 获取所有CDN提供商列表
func (c *CDNChecker) GetProviders() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var providers []string
	for provider := range CDNProvider {
		providers = append(providers, provider)
	}
	for provider := range c.config.CustomProviders {
		providers = append(providers, provider)
	}
	return providers
}

// UpdateConfig 更新配置
func (c *CDNChecker) UpdateConfig(config *Config) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
	// 重置缓存，下次调用时重新初始化
	c.cacheOnce = sync.Once{}
	return nil
}

// GetConfig 获取当前配置
func (c *CDNChecker) GetConfig() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

// GetStatistics 获取统计信息
func (c *CDNChecker) GetStatistics(results []*CheckResult) *Statistics {
	stats := &Statistics{
		ProviderStats: make(map[string]int),
	}

	var totalLatency time.Duration
	for _, result := range results {
		stats.TotalChecked++
		if result.IsCDN {
			stats.CDNCount++
			if result.Provider != "" {
				stats.ProviderStats[result.Provider]++
			}
		} else {
			stats.NonCDNCount++
		}
		// 这里可以添加延迟统计逻辑
	}

	if stats.TotalChecked > 0 {
		stats.AverageLatency = totalLatency / time.Duration(stats.TotalChecked)
	}

	return stats
}

// IPsToString 将IP数组转换为字符串
func IPsToString(ips []string, separator ...string) string {
	if len(ips) == 0 {
		return ""
	}

	sep := ","
	if len(separator) > 0 && separator[0] != "" {
		sep = separator[0]
	}

	return strings.Join(ips, sep)
}

// IPsToStringWithFormat 将IP数组转换为格式化字符串
func IPsToStringWithFormat(ips []string, format string, customSep ...string) string {
	if len(ips) == 0 {
		return ""
	}

	switch format {
	case "line":
		return strings.Join(ips, "\n")
	case "space":
		return strings.Join(ips, " ")
	case "json":
		// 使用strings.Builder优化性能
		var builder strings.Builder
		builder.WriteString(`["`) 
		builder.WriteString(strings.Join(ips, `","`))
		builder.WriteString(`"]`)
		return builder.String()
	case "custom":
		if len(customSep) > 0 {
			return strings.Join(ips, customSep[0])
		}
		return strings.Join(ips, ",")
	default:
		return strings.Join(ips, ",")
	}
}
