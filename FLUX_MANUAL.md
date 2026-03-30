# FLUX v5.4 使用手册

## 目录

1. [简介](#1-简介)
2. [安装与运行](#2-安装与运行)
3. [快速开始](#3-快速开始)
4. [命令参数参考](#4-命令参数参考)
5. [扫描模式详解](#5-扫描模式详解)
6. [使用场景示例](#6-使用场景示例)
7. [常见问题](#7-常见问题)
8. [架构说明](#8-架构说明)
9. [更新日志](#9-更新日志)

---

## 1. 简介

FLUX v5.4 是一款专业的 Web 安全扫描工具。

### 核心特性

| 类别 | 特性 |
|------|------|
| 🔍 **信息收集** | JS敏感信息、API端点提取、页面爬取、子域名发现 |
| 🎯 **指纹识别** | 25,000+ 指纹规则、40+ AI组件识别 |
| 🛡️ **漏洞测试** | SQL注入、XSS、LFI、RCE、SSRF、XXE、SSTI |
| ☁️ **云安全** | 12种云服务商、AccessKey泄露检测、存储桶遍历 |
| 🤖 **AI安全** | AI组件检测、589+ CVE漏洞、提示词注入 |
| 🛤️ **容器/K8s** | Docker/K8s逃逸检测、未授权访问、CVE扫描 |
| 📊 **报告** | 美观HTML报告、实时JSON报告、漏洞优先级排序 |

### v5.4 新增特性

- 🔄 **统一敏感信息扫描入口**: 106条规则全链路复用
- 📊 **SecretMatcher全量化**: 移除JS文件[:20]限制
- 🎯 **优先级采样机制**: 按风险评分采样
- 🔒 **SSRF危险探测**: 内网/云元数据/协议探测
- 🌐 **Header轮换**: 模拟不同浏览器访问
- 🛡️ **CSRF被动分析**: 检测敏感端点缺少CSRF防护

---

## 2. 安装与运行

### 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows x64 |
| 内存 | 建议 8GB+ |
| 网络 | 需要访问目标网站 |

### 运行方式

```
解压 FLUX_v5.4_Release.zip 后：

方式一：命令行运行
  cd FLUX_v5.4打包
  flux.exe -t https://example.com

方式二：PowerShell运行
  .\START.ps1 -t https://example.com
```

---

## 3. 快速开始

### 一键扫描（推荐）

```bash
# 基础全功能扫描
flux.exe -t https://example.com --full

# 全功能扫描 + DNSLog盲测
flux.exe -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

### 获取DNSLog域名

1. 访问 https://dnslog.cn
2. 点击 "Get SubDomain" 获取子域名
3. 使用 `--dnslog abc123.dnslog.cn` 运行扫描

---

## 4. 命令参数参考

### 目标指定

| 参数 | 说明 | 示例 |
|------|------|------|
| `-t, --target` | 单个目标URL | `-t https://example.com` |
| `-tf, --target-file` | URL列表文件 | `-tf urls.txt` |
| `--fscan` | 导入fscan结果 | `--fscan fscan.txt` |
| `--dddd` | 导入dddd结果 | `--dddd dddd.txt` |

### 扫描控制

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--scan-mode` | 扫描模式(static/render/hybrid) | static |
| `--full` | 一键全功能扫描 | - |
| `-d, --depth` | 爬取深度 | 3 |
| `-T, --threads` | 线程数 | 20 |
| `--timeout` | 请求超时(秒) | 30 |

### 漏洞测试

| 参数 | 说明 |
|------|------|
| `--vuln-test` | 启用漏洞测试 |
| `--ssrf-dangerous` | SSRF危险探测（内网/云元数据） |
| `--dnslog` | DNSLog域名（用于SSRF盲测） |
| `--csrf-test` | CSRF测试 |

### 渲染扫描

| 参数 | 说明 |
|------|------|
| `--render-deep-spider` | 深度爬虫，发现更多页面 |
| `--render-enable-interaction` | 启用交互引擎 |
| `--render-interaction-budget` | 交互预算，默认50 |

### 认证与会话

| 参数 | 说明 |
|------|------|
| `--cookie-file` | Cookie文件路径（JSON格式，用于登录后扫描） |
| `--save-cookies` | 保存Cookie到文件 |
| `--header` | 自定义请求头，格式: "Name: Value" |
| `--header-file` | 从文件加载自定义请求头 |

### 输出控制

| 参数 | 说明 |
|------|------|
| `-o, --output` | 输出HTML报告 |
| `--json-report` | 输出JSON格式报告 |
| `--no-progress` | 不显示进度条 |

### 其他选项

| 参数 | 说明 |
|------|------|
| `--proxy` | 代理服务器 |
| `-v, --verbose` | 详细输出 |
| `--version` | 显示版本 |
| `--help` | 显示帮助信息 |

---

## 5. 扫描模式详解

### 三种模式对比

| 模式 | 原理 | 速度 | 适用场景 |
|------|------|------|----------|
| **static** | HTTP请求，直接获取HTML | 最快 | 传统网站、服务端渲染 |
| **render** | Playwright渲染，执行JS | 慢 | SPA应用（React/Vue/Angular） |
| **hybrid** | 先静态后渲染验证 | 中 | 通用推荐、复杂应用 |

### 推荐配置

| 场景 | 推荐命令 |
|------|----------|
| 传统网站 | `--scan-mode static` |
| SPA应用 | `--scan-mode hybrid --render-deep-spider` |
| 需要登录 | `--scan-mode hybrid --cookie-file cookies.json` |

---

## 6. 使用场景示例

### 场景1：快速扫描一个网站

```bash
flux.exe -t https://example.com --full
```

### 场景2：批量扫描多个网站

```bash
# 创建URL列表
echo https://example1.com > urls.txt
echo https://example2.com >> urls.txt

# 批量扫描
flux.exe -tf urls.txt --full
```

### 场景3：扫描需要登录的网站

```bash
# 1. 浏览器登录后导出Cookie（JSON格式）
# 2. 使用 --cookie-file 加载
flux.exe -t https://example.com --full --cookie-file cookies.json
```

**Cookie文件格式 (JSON)**:
```json
[
    {"name": "SESSION", "value": "abc123", "domain": ".example.com"},
    {"name": "token", "value": "xyz789", "domain": ".example.com"}
]
```

### 场景4：扫描 SPA 应用

```bash
flux.exe -t https://example.com --scan-mode hybrid --render-deep-spider --full
```

### 场景5：SSRF 漏洞测试

```bash
# 1. 访问 https://dnslog.cn 获取子域名
# 2. 运行扫描
flux.exe -t https://example.com --vuln-test --dnslog abc123.dnslog.cn
```

### 场景6：导入其他扫描工具结果

```bash
# 导入fscan结果
flux.exe --fscan fscan_result.txt

# 导入dddd结果
flux.exe --dddd dddd_result.txt
```

### 场景8：最全功能扫描（渗透测试推荐）

此命令会启用所有扫描功能，适合正式渗透测试：

```bash
# 最全功能扫描命令
flux.exe -t https://example.com ^
  --full ^
  --dnslog xxx.dnslog.cn ^
  --scan-mode hybrid ^
  --render-deep-spider ^
  --render-enable-interaction ^
  -d 5 ^
  -T 20 ^
  -o report.html
```

**--full 启用的功能：**

| 类别 | 启用的功能 |
|------|------------|
| 🔐 **密钥验证** | 12种云服务商AccessKey验证 |
| 🎯 **参数Fuzzing** | 从JS提取参数并测试 |
| 📁 **路径Fuzzing** | 敏感路径探测 |
| 🛡️ **漏洞测试** | SQLi/XSS/LFI/RCE/SSRF/XXE/SSTI |
| 📄 **API解析** | Swagger/OpenAPI/Postman文档 |
| 🌐 **WAF绕过** | 40+种WAF检测与绕过 |
| 🔒 **CSRF测试** | CSRF Token检测 |
| 🔗 **SSRF测试** | 含危险探测（内网/云元数据） |
| 🚪 **越权测试** | 水平越权检测 |
| ☁️ **云安全** | 存储桶遍历/接管/ACL检测 |
| 🛤️ **K8s安全** | K8s组件/CVE检测 |
| 🐳 **容器安全** | Docker逃逸/特权容器检测 |
| 🔄 **CI/CD安全** | Jenkins/GitLab/GitHub检测 |
| ⚡ **智能限速** | 自适应请求频率 |
| 🌐 **Header轮换** | 模拟不同浏览器 |
| 🕷️ **混合扫描** | 静态+渲染混合模式 |
| 🖱️ **浏览器交互** | 轻量点击引擎 |
| 🕷️ **深度Spider** | 深度页面爬取 |

> ⚠️ **警告**: SSRF危险探测可能对目标造成影响，仅在授权测试中使用

---

## 7. 常见问题

### 基础问题

**Q1: FLUX 是什么类型的工具？**

A: FLUX 是一款专业的 Web 安全扫描工具，支持：
- 信息收集（JS敏感信息、API端点）
- 指纹识别（25,000+ 规则）
- 漏洞测试（SQL注入、XSS、RCE等）
- 云安全（AWS/阿里云/腾讯云等）
- AI安全（Gradio/Dify/Ollama等组件）

---

**Q2: 支持 macOS 或 Linux 吗？**

A: 当前版本为 Windows x64，macOS/Linux 版本需手动打包。

---

### 安装与运行

**Q3: 杀毒软件报毒怎么办？**

A: PyInstaller 打包的工具会被部分杀毒软件误报。
- 解决方法：将 `flux.exe` 加入白名单
- 误报是 PyInstaller 打包工具的常见现象

---

**Q4: 提示缺少 DLL 文件**

A: 需要安装 Visual C++ 运行库。
- 下载地址：https://aka.ms/vs/17/release/vc_redist.x64.exe

---

### 扫描相关

**Q5: 扫描速度太慢怎么办？**

A: 优化方法：
```bash
# 增加线程
flux.exe -t https://example.com --full -T 30

# 降低深度
flux.exe -t https://example.com --full -d 2

# 使用静态模式
flux.exe -t https://example.com --scan-mode static
```

---

**Q6: 如何扫描需要登录的网站？**

A: 使用 `--cookie-file` 参数：
```bash
flux.exe -t https://example.com --full --cookie-file cookies.json
```

---

**Q7: `--full` 和 `--vuln-test` 有什么区别？**

| 参数 | 说明 |
|------|------|
| `--full` | 一键全功能，包含指纹、漏洞测试等 |
| `--vuln-test` | 仅漏洞测试 |

---

**Q8: SSRF 测试需要 DNSLog 是什么？**

A: SSRF 是盲漏洞，需要 DNSLog 检测：
```
攻击者让服务器请求DNSLog服务器 → DNSLog收到请求 → 证明漏洞存在
```

使用方法：
```bash
flux.exe -t https://example.com --vuln-test --dnslog abc123.dnslog.cn
```

---

**Q9: 什么情况下需要 `--ssrf-dangerous`？**

A: 会进行危险探测：
- 云元数据探测 (AWS 169.254.169.254)
- 内网地址探测
- 协议探测 (file://, dict://)

⚠️ 仅在授权测试中使用，可能对目标造成影响

---

**Q10: 批量扫描会生成多个报告吗？**

A: 是的，每个目标自动生成独立报告。

---

### 故障排除

**Q11: 扫描报错 "Connection timeout"**

A: 解决方法：
```bash
# 增加超时
flux.exe -t https://example.com --timeout 60

# 减少并发
flux.exe -t https://example.com -T 5
```

---

**Q12: 浏览器渲染模式无法启动**

A: 可能缺少 Playwright 浏览器：
```bash
# 安装浏览器
playwright install chromium
```

或使用静态模式：
```bash
flux.exe -t https://example.com --scan-mode static
```

---

**Q13: 扫描结果为空怎么办？**

A: 排查步骤：
1. 检查目标是否可达：`curl -I https://example.com`
2. 增加超时时间：`--timeout 60`
3. 使用详细模式：`flux.exe -t https://example.com -v`

---

## 8. 架构说明

```
FLUX/
├── flux.py                 # 主程序入口
├── core/                   # 核心模块
│   ├── fingerprint/       # 指纹识别
│   ├── secret_matcher/    # 敏感信息匹配
│   ├── js_pipeline/       # JS处理流水线
│   └── ...
├── modules/                # 扫描模块
│   ├── ai/               # AI安全检测
│   ├── cloud/            # 云安全检测
│   ├── cicd/            # CI/CD安全检测
│   ├── container/        # 容器安全检测
│   ├── kubernetes/       # K8s安全检测
│   └── vulnerability/    # 漏洞测试
├── utils/                  # 工具模块
│   └── report.py         # 报告生成
├── config/                 # 配置文件
│   └── rules.yaml        # 扫描规则
└── data/                   # 数据文件
    └── fingerprints_merged.json  # 指纹库
```

---

## 9. 更新日志

### v5.4 (2026-03-29)
- 🔄 **统一敏感信息扫描入口**: 106条规则全链路复用
- 📊 **SecretMatcher全量化**: 移除JS文件[:20]限制
- 🎯 **优先级采样机制**: 按风险评分采样
- 🔒 **SSRF危险探测**: --ssrf-dangerous 参数
- 🌐 **Header轮换**: 模拟不同浏览器访问
- 🛡️ **CSRF被动分析**: 检测敏感端点缺少CSRF防护
- ⚡ **--full模式增强**: 混合扫描+浏览器交互+深度Spider+SSRF危险探测
- 🐛 **多目标日志修复**: 每个目标生成独立日志文件

### v5.2.4 (2026-03-28)
- 📊 **报告优化**: API端点表格增加响应长度列
- 📋 **一键复制**: 所有来源列添加复制功能
- 🐛 **批量扫描修复**: 修复统计为0的问题

### v5.2.3 (2026-03-27)
- 🔒 **安全检测修复**: CSRF/CORS检测分离、XSS/RCE上下文判断
- 🛡️ **扫描模式分层**: low_risk/dangerous模式

### v5.2.2 (2026-03-23)
- ✨ **JS智能解析**: Webpack/Vite/Next.js/Nuxt.js识别
- ✨ **端点融合引擎**: 多来源端点去重分类
- ✨ **敏感信息智能匹配**: 结构化规则+上下文判断

---

## 法律声明

> ⚠️ **免责声明**
>
> FLUX 是一款安全研究工具，仅供授权的安全测试使用。
> 使用 FLUX 进行未经授权的扫描是违法行为。
> 使用者需自行承担使用风险，作者不承担任何责任。
