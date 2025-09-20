package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ==================== ECS选项和EDNS管理器 ====================

type EDNSManager struct {
	defaultECS     *ECSOption
	detector       *IPDetector
	cache          sync.Map
	paddingEnabled bool
	cookieEnabled  bool
	cookieSecret   [32]byte // 用于生成服务器cookie的秘密值
}

func NewEDNSManager(defaultSubnet string, paddingEnabled bool, cookieEnabled bool) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector:       NewIPDetector(),
		paddingEnabled: paddingEnabled,
		cookieEnabled:  cookieEnabled,
	}

	// 初始化cookie secret
	_, err := rand.Read(manager.cookieSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate cookie secret: %w", err)
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("🌍 ECS配置解析失败: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			writeLog(LogInfo, "🌍 默认ECS配置: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	if paddingEnabled {
		writeLog(LogInfo, "📦 DNS Padding已启用 (块大小: %d字节)", DNSPaddingBlockSizeBytes)
	}

	if cookieEnabled {
		writeLog(LogInfo, "🍪 DNS Cookies已启用")
	}

	return manager, nil
}

func (em *EDNSManager) GetDefaultECS() *ECSOption {
	if em == nil {
		return nil
	}
	return em.defaultECS
}

func (em *EDNSManager) IsPaddingEnabled() bool {
	return em != nil && em.paddingEnabled
}

func (em *EDNSManager) IsCookieEnabled() bool {
	return em != nil && em.cookieEnabled
}

// generateServerCookie 生成一个固定长度的16字节（32个十六进制字符）服务器cookie
func (em *EDNSManager) generateServerCookie(clientCookie []byte, clientAddr net.Addr) string {
	if em == nil || clientAddr == nil {
		return ""
	}

	// 根据RFC 7873，服务器cookie必须是8到32字节
	// 我们生成一个固定长度的16字节（32个十六进制字符）服务器cookie
	mac := hmac.New(sha256.New, em.cookieSecret[:])
	mac.Write(clientCookie)
	mac.Write([]byte(clientAddr.String()))

	// 取前16字节作为服务器cookie
	hash := mac.Sum(nil)[:16]
	return hex.EncodeToString(hash)
}

// 处理DNS cookie
func (em *EDNSManager) processDNSCookie(clientAddr net.Addr, clientCookie string) (string, bool) {
	if em == nil || !em.cookieEnabled || clientAddr == nil || clientCookie == "" {
		writeLog(LogDebug, "🍪 processDNSCookie: 参数无效 - em:%v, cookieEnabled:%v, clientAddr:%v, clientCookie:%v",
			em == nil, em != nil && em.cookieEnabled, clientAddr != nil, clientCookie != "")
		// 即使参数无效，我们也应该返回一些信息，让调用者决定是否返回BADCOOKIE
		return "", false
	}

	// 解码cookie
	cookieData, err := hex.DecodeString(clientCookie)
	if err != nil {
		writeLog(LogDebug, "🍪 无效的DNS cookie格式: %v", err)
		return "", false
	}

	writeLog(LogDebug, "🍪 processDNSCookie: 接收到Cookie长度: %d 字节", len(cookieData))

	// 检查客户端cookie长度（必须是8字节，即16个十六进制字符）
	if len(cookieData) < 8 {
		writeLog(LogDebug, "🍪 客户端cookie长度不足: %d 字节", len(cookieData))
		return "", false
	}

	// 如果只有客户端cookie（8字节），则生成服务器cookie
	if len(cookieData) == 8 {
		writeLog(LogDebug, "🍪 只有客户端cookie，生成服务器cookie")
		serverCookie := em.generateServerCookie(cookieData[:8], clientAddr)
		return serverCookie, true
	}

	// 如果包含服务器cookie（总共24字节），验证它
	if len(cookieData) >= 24 {
		// 取前24字节进行处理
		if len(cookieData) > 24 {
			writeLog(LogDebug, "🍪 Cookie长度超过24字节，截取前24字节进行处理")
			cookieData = cookieData[:24]
		}

		clientCookiePart := cookieData[:8]
		providedServerCookie := cookieData[8:24] // 服务器cookie应该是接下来的16字节

		expectedServerCookie := em.generateServerCookie(clientCookiePart, clientAddr)
		expectedServerCookieBytes, _ := hex.DecodeString(expectedServerCookie)

		writeLog(LogDebug, "🍪 验证完整cookie: 客户端=%x, 提供的服务器=%x, 期望的服务器=%x",
			clientCookiePart, providedServerCookie, expectedServerCookieBytes)

		// 比较服务器cookie（防止时序攻击的安全比较）
		match := hmac.Equal(providedServerCookie, expectedServerCookieBytes)
		if match {
			// Cookie有效，不需要返回服务器cookie，因为客户端已经有了
			writeLog(LogDebug, "🍪 Cookie验证成功")
			return "", true
		} else {
			// Cookie无效
			writeLog(LogDebug, "🍪 Cookie验证失败")
			return "", false
		}
	}

	writeLog(LogDebug, "🍪 DNS cookie长度无效: %d 字节，期望8或24字节", len(cookieData))
	return "", false
}

// 生成新的客户端cookie
func (em *EDNSManager) generateClientCookie() string {
	clientCookie := make([]byte, 8) // 8字节客户端cookie
	_, err := rand.Read(clientCookie)
	if err != nil {
		writeLog(LogDebug, "🍪 生成客户端cookie失败: %v", err)
		return ""
	}
	return hex.EncodeToString(clientCookie)
}

func (em *EDNSManager) calculatePaddingSize(currentSize int) int {
	if !em.paddingEnabled || currentSize <= 0 || currentSize >= DNSPaddingMaxSizeBytes {
		return 0
	}

	nextBlockSize := ((currentSize + DNSPaddingBlockSizeBytes - 1) / DNSPaddingBlockSizeBytes) * DNSPaddingBlockSizeBytes
	paddingSize := nextBlockSize - currentSize

	if currentSize+paddingSize > DNSPaddingMaxSizeBytes {
		return DNSPaddingMaxSizeBytes - currentSize
	}

	return paddingSize
}

func (em *EDNSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if em == nil || msg == nil {
		return nil
	}

	// 确保msg.Extra字段安全，防止IsEdns0()出现index out of range错误
	if msg.Extra == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
			return &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.SourceNetmask,
				ScopePrefix:  subnet.SourceScope,
				Address:      subnet.Address,
			}
		}
	}

	return nil
}

func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, dnssecEnabled bool, isSecureConnection bool, clientAddr net.Addr, clientCookieStr string) {
	if em == nil || msg == nil {
		return
	}

	// 确保消息结构安全，防止在ExchangeContext中调用IsEdns0时出现panic
	if msg.Question == nil {
		msg.Question = []dns.Question{}
	}
	if msg.Answer == nil {
		msg.Answer = []dns.RR{}
	}
	if msg.Ns == nil {
		msg.Ns = []dns.RR{}
	}
	if msg.Extra == nil {
		msg.Extra = []dns.RR{}
	}

	// 清理现有OPT记录
	cleanExtra := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	// 创建新的OPT记录
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  ClientUDPBufferSizeBytes,
			Ttl:    0,
		},
	}

	if dnssecEnabled {
		opt.SetDo(true)
	}

	var options []dns.EDNS0

	// 添加ECS选项
	if ecs != nil {
		ecsOption := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSClientScope,
			Address:       ecs.Address,
		}
		options = append(options, ecsOption)
		writeLog(LogDebug, "🌍 添加ECS选项: %s/%d", ecs.Address, ecs.SourcePrefix)
	}

	// 处理DNS Cookie
	if em.cookieEnabled {
		writeLog(LogDebug, "🍪 Cookie功能已启用，clientCookieStr='%s'", clientCookieStr)
		var finalCookie string

		if clientCookieStr != "" {
			// 客户端发送了cookie，处理它
			if clientAddr != nil {
				// 验证客户端cookie长度（必须是8字节，即16个十六进制字符）
				clientCookieBytes, err := hex.DecodeString(clientCookieStr)
				if err == nil && len(clientCookieBytes) >= 8 {
					// 只取客户端cookie的前8字节
					clientPart := clientCookieStr[:16]
					writeLog(LogDebug, "🍪 客户端发送了cookie，clientPart='%s'", clientPart)

					// 处理服务器cookie
					serverCookie, valid := em.processDNSCookie(clientAddr, clientCookieStr)
					writeLog(LogDebug, "🍪 processDNSCookie返回: serverCookie='%s', valid=%v", serverCookie, valid)

					if !valid {
						// Cookie无效，生成新的服务器cookie
						writeLog(LogDebug, "🍪 Cookie无效，生成新的服务器cookie")
						serverCookie = em.generateServerCookie(clientCookieBytes[:8], clientAddr)
					}

					// 组合客户端和服务器cookie
					finalCookie = clientPart + serverCookie
					writeLog(LogDebug, "🍪 组合后的finalCookie='%s'", finalCookie)
				} else {
					writeLog(LogDebug, "🍪 客户端cookie解码失败或长度不足: err=%v, len=%d", err, len(clientCookieBytes))
				}
			} else {
				// 没有客户端地址，只返回客户端cookie部分
				clientCookieBytes, err := hex.DecodeString(clientCookieStr)
				if err == nil && len(clientCookieBytes) >= 8 {
					finalCookie = clientCookieStr[:16] // 只取客户端cookie部分
					writeLog(LogDebug, "🍪 没有客户端地址，只返回客户端cookie部分: '%s'", finalCookie)
				}
			}
		} else {
			// 客户端没有发送cookie，生成一个新的随机客户端cookie
			clientCookieStr = em.generateClientCookie()
			finalCookie = clientCookieStr
			writeLog(LogDebug, "🍪 客户端没有发送cookie，生成新的客户端cookie: '%s'", clientCookieStr)

			// 如果有客户端地址，也生成服务器cookie
			if clientAddr != nil && clientCookieStr != "" {
				clientCookieBytes, _ := hex.DecodeString(clientCookieStr)
				if len(clientCookieBytes) >= 8 {
					serverCookie := em.generateServerCookie(clientCookieBytes[:8], clientAddr)
					finalCookie = clientCookieStr[:16] + serverCookie // 确保只使用8字节客户端cookie
					writeLog(LogDebug, "🍪 生成服务器cookie，最终cookie: '%s'", finalCookie)
				}
			}
		}

		// 添加cookie选项（如果存在有效的cookie）
		if finalCookie != "" {
			// 根据RFC 7873验证总长度
			// 客户端cookie（8字节）+ 服务器cookie（16字节）= 总共24字节（48个十六进制字符）
			cookieBytes, err := hex.DecodeString(finalCookie)
			if err == nil && len(cookieBytes) == 24 { // 必须正好是24字节
				cookieOption := &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: finalCookie,
				}
				options = append(options, cookieOption)
				writeLog(LogDebug, "🍪 添加DNS Cookie到响应: %s (长度: %d字节)", finalCookie, len(cookieBytes))
			} else if err == nil {
				writeLog(LogDebug, "🍪 DNS Cookie长度不正确: %d字节，期望24字节，cookie='%s'", len(cookieBytes), finalCookie)

				// 如果长度不正确，我们仍然添加它，但记录警告
				cookieOption := &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: finalCookie,
				}
				options = append(options, cookieOption)
				writeLog(LogDebug, "⚠️  添加了长度不标准的DNS Cookie到响应: %s (长度: %d字节)", finalCookie, len(cookieBytes))
			} else {
				writeLog(LogDebug, "🍪 DNS Cookie格式错误: %v", err)
			}
		}
	}

	// 添加Padding选项（仅对安全连接）
	if em.paddingEnabled && isSecureConnection {
		// 临时计算当前大小
		tempMsg := *msg
		opt.Option = options
		tempMsg.Extra = append(tempMsg.Extra, opt)

		currentSize := tempMsg.Len()
		paddingSize := em.calculatePaddingSize(currentSize)

		if paddingSize > 0 {
			paddingOption := &dns.EDNS0_PADDING{
				Padding: make([]byte, paddingSize),
			}
			options = append(options, paddingOption)
			writeLog(LogDebug, "📦 DNS Padding: %d -> %d 字节 (+%d)",
				currentSize, currentSize+paddingSize, paddingSize)
		}
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)
}

func (em *EDNSManager) parseECSConfig(subnet string) (*ECSOption, error) {
	switch strings.ToLower(subnet) {
	case "auto":
		return em.detectPublicIP(false, true)
	case "auto_v4":
		return em.detectPublicIP(false, false)
	case "auto_v6":
		return em.detectPublicIP(true, false)
	default:
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("🔍 解析CIDR失败: %w", err)
		}

		prefix, _ := ipNet.Mask.Size()
		family := uint16(1)
		if ipNet.IP.To4() == nil {
			family = 2
		}

		return &ECSOption{
			Family:       family,
			SourcePrefix: uint8(prefix),
			ScopePrefix:  DefaultECSClientScope,
			Address:      ipNet.IP,
		}, nil
	}
}

func (em *EDNSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			return cachedECS, nil
		}
	}

	var ecs *ECSOption
	if ip := em.detector.DetectPublicIP(forceIPv6); ip != nil {
		family := uint16(1)
		prefix := uint8(DefaultECSIPv4PrefixLen)

		if forceIPv6 {
			family = 2
			prefix = DefaultECSIPv6PrefixLen
		}

		ecs = &ECSOption{
			Family:       family,
			SourcePrefix: prefix,
			ScopePrefix:  DefaultECSClientScope,
			Address:      ip,
		}
	}

	// 回退处理
	if ecs == nil && allowFallback && !forceIPv6 {
		if ip := em.detector.DetectPublicIP(true); ip != nil {
			ecs = &ECSOption{
				Family:       2,
				SourcePrefix: DefaultECSIPv6PrefixLen,
				ScopePrefix:  DefaultECSClientScope,
				Address:      ip,
			}
		}
	}

	// 缓存结果
	if ecs != nil {
		em.cache.Store(cacheKey, ecs)
		time.AfterFunc(IPDetectionCacheExpiry, func() {
			em.cache.Delete(cacheKey)
		})
	}

	return ecs, nil
}

// ==================== IP检测器 ====================

type IPDetector struct {
	httpClient *http.Client
}

func NewIPDetector() *IPDetector {
	return &IPDetector{
		httpClient: &http.Client{
			Timeout: HTTPClientRequestTimeout,
		},
	}
}

func (d *IPDetector) DetectPublicIP(forceIPv6 bool) net.IP {
	if d == nil {
		return nil
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: PublicIPDetectionTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: SecureConnHandshakeTimeout,
	}

	client := &http.Client{
		Timeout:   HTTPClientRequestTimeout,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭响应体失败: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	re := regexp.MustCompile(`ip=([^\s\n]+)`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return nil
	}

	ip := net.ParseIP(matches[1])
	if ip == nil {
		return nil
	}

	// 检查IP版本匹配
	if forceIPv6 && ip.To4() != nil {
		return nil
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil
	}

	return ip
}
