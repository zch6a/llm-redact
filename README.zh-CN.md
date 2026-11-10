<div align="center">

# 🫥 llm-redact

**Agent 照样把真实的 key 写进 `.env`，模型服务商却从来看不到它。**

一个跑在本机的代理，位于你的 AI 编程 Agent 和模型 API 之间。请求离开电脑之前，API key、token、私钥和个人信息会被换成占位符；回复回来、Agent 读到之前，再换回真实值——文本、工具调用、流式输出都一样。

Claude Code · Codex · OpenCode · DeepSeek · 任何兼容 OpenAI 或 Anthropic 接口的客户端

本地运行 · 零依赖 · 除一个随机密钥外什么都不落盘

[English](README.md) · [简体中文](README.zh-CN.md)

```bash
npx llm-redact
```

</div>

---

## 为什么需要它

编程 Agent 什么都读：你的 `.env`、你贴进去的配置、带着连接串的报错堆栈、测试数据里的客户邮箱。这些全都会发给模型服务商——并可能在那里被记录、保留或用于滥用监测。

你可以尽量不让密钥进入上下文；也可以确保无论什么进了上下文，真实的值都不会离开你的电脑。

## 它做了什么

Agent 请模型写一份配置文件。**服务商**收到的是这样的（`llm-redact scan docs/example.env.txt` 的真实输出）：

```text
Please add these to my deployment config and check the database connects:

OPENAI_API_KEY=[[REDACTED:openai_key:a3aec50a]]
DATABASE_URL=postgres://app:[[REDACTED:url_password:1e808a61]]@db.internal:5432/prod
STRIPE_SECRET=[[REDACTED:stripe_key:f1350c3c]]
MAX_TOKENS=4096
LOG_LEVEL=info

If it fails, email [[REDACTED:email:c58c2eab]] or call [[REDACTED:cn_mobile:602543a6]].
```

模型回复一个工具调用，把 `OPENAI_API_KEY=[[REDACTED:openai_key:a3aec50a]]` 写进 `.env`。llm-redact 在回程中把占位符换回真实的 key，所以**你磁盘上的文件里是真 key**——而服务商自始至终只见过占位符。

`MAX_TOKENS=4096` 和 `LOG_LEVEL=info` 不会被动：把不是密钥的东西替换掉会搞坏 Agent 的工作，所以“不误伤”和“不漏抓”同样重要。

## 快速开始

```bash
npx llm-redact          # 监听 http://127.0.0.1:8787
npx llm-redact env      # 按你的 shell 打印每个客户端要设置什么
```

然后把 Agent 指向它：

| 客户端 | 设置 |
|---|---|
| **Claude Code** | `ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic` |
| **OpenAI SDK、OpenCode** 以及大多数兼容 OpenAI 的工具 | `OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1` |
| **Codex** | 在 `~/.codex/config.toml` 里加一个 `base_url = "http://127.0.0.1:8787/openai/v1"` 的 provider（`llm-redact env codex` 会打印出来） |
| **DeepSeek**（OpenAI 兼容接口，例如 DeepSeek Harness） | `OPENAI_BASE_URL=http://127.0.0.1:8787/deepseek/v1` |
| **通过 Claude Code 用 DeepSeek** | `ANTHROPIC_BASE_URL=http://127.0.0.1:8787/deepseek/anthropic` |

已经在用网关或中转？串起来即可：`llm-redact --upstream anthropic=https://你的网关`。`llm-redact env` 发现你已经设置了 `ANTHROPIC_BASE_URL` 时，会直接打印这一行。

开着 HTTP 代理（`HTTPS_PROXY`，或系统全局代理——Codex 连 `127.0.0.1` 的请求也会走 Windows 系统代理）？发给 llm-redact 的请求必须绕过它，否则会收到代理返回的 502：`llm-redact env` 也会打印 `NO_PROXY=127.0.0.1,localhost`，并保留你原有的 `NO_PROXY`。

你的 API key 在请求头里原样转发——服务商需要它。只有请求体会被脱敏。

已用真实的 **Claude Code 2.1** 和 **Codex 0.131** 命令行做过端到端测试（`npm run smoke`，对接本地 mock，不消耗 token）：各自发送一个合成的 key 和邮箱，mock 只看到占位符，命令行打印出真实值；把占位符和说明还原后，经代理的请求与直连时逐字节相同。

## 能识别什么

| 密钥 | 个人信息 |
|---|---|
| Anthropic、OpenAI / DeepSeek（`sk-…`）、GitHub、GitLab、AWS、Google、Slack、Stripe、npm、Hugging Face、Telegram 的 key 和 token · Slack / Discord webhook · JWT · Bearer token · PEM 私钥 · URL 里的密码（`postgres://user:…@`）· `*_SECRET`、`*_TOKEN`、`*PASSWORD`、`*_API_KEY` 的值（文本、`.env` 文件和 JSON 里都识别） | 邮箱 · 中国大陆手机号 · 身份证号（校验位和出生日期都要正确）· 国际格式电话 · 银行卡号（Luhn）· IBAN（mod 97）· 美国 SSN · 公网 IPv4（需手动开启） |

`llm-redact detectors` 列出全部检测器。用 `--disable email,phone` 关闭某些（或整类：`--disable pii`），用 `--allow` 保留特定值。

**刻意不替换**的：文档里的占位写法（`your_api_key`、`ghp_your_token`、`${TOKEN}`、`<key>`、`changeme`）、变量引用和代码（`process.env.X`、`$API_KEY`、`config.token`、`getenv(…)`）、token 计数（`max_tokens=4096`）、示例域名和 `noreply@` 邮箱、校验不通过的数字、提交哈希、UUID 和时间戳。

这是实测得出的：在 2955 个真实文件（5 个流行的公开 skill 仓库加 3 个代码项目）上，通用的 `名字=值` 规则从 317 处命中（几乎全是代码和占位写法）降到 25 处，剩下的都是密码形态的示例值。实测中发现的每一类误报都写成了测试。

## 工作原理

- **占位符稳定。** `[[REDACTED:openai_key:a3aec50a]]` 里的标签是值的 HMAC，密钥在首次运行时随机生成（`~/.config/llm-redact/key`，Windows 上是 `%APPDATA%\llm-redact\key`）。同一个密钥在每次请求、每次重启后都得到同一个占位符，所以**服务商的 prompt 缓存能一直命中**，模型看到的对话也前后一致。
- **真实值只在内存里。** 重启后映射会自己补全：客户端会重发历史记录，其中含有真实值，再次脱敏后得到同样的占位符。
- **流式输出。** 一个占位符可能被拆在任意多段流式输出里（`[[RED` + `ACTED:op…`）。还原器只暂扣“还可能变成占位符”的那一小截尾巴，普通文字不会被延迟；即使还原出的值含有引号或反斜杠，工具调用参数也仍然是合法 JSON。
- **编码过的文本也会搜索。** 工具结果常常引用日志、配置和 API 响应，所以文本还会往下解一到两层再搜索——各种写法的 JSON 转义（`\"`、Go 的 `&`、.NET 的 `+`、Python 的 `ä`）、HTML 实体、百分号编码、CSV 里双写的引号——在那里找到的值会在原文中对应的位置被精确替换。写成 JSON 数字的卡号和手机号也能识别；其他数字按原样保留（`12345678901234567890`、`1.10`）。请求里已有的占位符（模型此前自己的输出）不会被再次脱敏。
- **带签名的块原样保留。** 带签名的 Anthropic thinking 块、OpenAI / OpenRouter 的加密推理（包括其摘要）会被服务商逐字节校验，两个方向都绝不修改。没有签名的推理文本（DeepSeek 的 `reasoning_content`）按普通文本处理。
- **告诉模型发生了什么。** 请求里有占位符时，会在系统提示词末尾追加一句说明（让模型原样写出占位符，而不是向你要 key）。追加在末尾不会破坏已缓存的前缀。`--no-note` 可关闭。

- **出错时宁可拒绝（fail closed）。** 无法脱敏的请求体会被拒绝，绝不原样转发：不合法的 JSON → 400；嵌套深得离谱、压缩后解压超过上限、或一段文本里要替换的值超过一百万个 → 413；文件上传等二进制内容、或非 UTF-8 字符集的文本 → 415（用 `--allow-unredacted` 启动可以让这类请求原样转发，日志会逐条标注）。纯文本请求体按文本脱敏，表单请求体逐字段脱敏。重定向到同一上游以外的地址会被拒绝，因为客户端会把原始的、未脱敏的请求体重新发到那里。

支持的接口格式：Anthropic Messages（也包括经 Vertex AI 的 `:streamRawPredict`）、OpenAI Chat Completions、OpenAI Responses——流式和非流式都支持，包括工具输入、工具结果、历史工具调用参数、Predicted Outputs 和 Codex 的自定义工具；以 base64 发送的文本文件也会脱敏。其他任何 JSON 接口（Ollama、Gemini 等）按通用方式脱敏——所有字符串和对象键——响应也会还原，包括逐行 JSON 流（Ollama）和未识别路径上的 SSE 流。

有意不改动的部分：**工具定义和输出 schema**（由客户端编写，相当于它的代码，并且要逐字节稳定以保证 prompt 缓存命中）、请求设置（`stop`、`safety_identifier`、`mcp_servers`）、带签名的块，以及二进制文件（图片、PDF）。

## 命令

| 命令 | |
|---|---|
| `llm-redact` / `llm-redact start` | 启动代理（`-p 8787`） |
| `llm-redact env [claude\|codex\|openai\|deepseek]` | 该设置什么，支持 `--shell bash\|zsh\|fish\|powershell\|cmd` |
| `llm-redact scan [文件\|-]` | 预览一个文件或一段粘贴内容脱敏后的样子（`--json` 输出位置） |
| `llm-redact detectors` | 列出检测器 |
| `llm-redact stats` | 正在运行的代理截至目前替换了多少个值（只显示数量） |

选项：`--upstream name=url`（可重复）· `--disable ids` · `--enable ids` · `--allow value` · `--no-note` · `--require-token` · `--allow-unredacted` · `--config file` · `-q`。配置文件（与密钥同目录的 `config.json`）支持同样的设置：`{ "port": 8787, "upstreams": {}, "disable": [], "enable": [], "allow": [], "requireToken": false, "allowUnredacted": false }`。

请求日志只显示数量——`POST /anthropic/v1/messages -> 200 1834ms  redacted openai_key x1 email x2`——从不显示请求体或具体值。

## 安全

- **只监听 127.0.0.1**，并拒绝 `Host` 不是回环地址的请求（防止网页通过 DNS 重绑定访问）。不返回 CORS 头：浏览器里的网页读不到它的响应。
- **多人共用的机器上请加 `--require-token`。** 本机任何能连上这个端口的进程，都能让代理把它见过的占位符还原成真实值（代理对响应做的正是这件事）。加上这个参数后，代理只响应带随机路径令牌的地址（`http://127.0.0.1:8787/<token>/anthropic`），`llm-redact env` 会打印带令牌的地址。
- 除了 HMAC 密钥和（使用 `--require-token` 时的）令牌之外不写任何文件，两者都只有你自己能读（权限 600；Windows 上会把继承来的 ACL 换成只授权你本人账户的 ACL——用户目录有可能对其他账户可读，比如沙箱用户组）。没有遥测，除了你配置的上游之外不产生任何网络流量。
- 零运行时依赖——经手你密钥的代码，就是这个仓库里的代码。

## 局限——请务必读一下

- **基于模式匹配。** 没有可识别形态、周围也没有提示性名字的密钥（句子中间的 `hunter2`）识别不出来。人名、地址和自由文本里的个人信息不在检测范围内。可以用 `scan` 看看你自己的文件会变成什么样。
- **上传的文件和二进制文件不脱敏。** 以 `multipart/form-data` 发送的请求会被拒绝；如果传了 `--allow-unredacted`，则原样发出。请求里的图片和 PDF 原样通过（以 base64 发送的文本文件会脱敏）。
- **工具定义不脱敏。** 写进 MCP 服务器工具描述里的密钥会随之发出。
- **只管经过代理的流量。** Agent 自己运行的工具（网页抓取、`curl`）不经过它。
- **占位符在你这边被还原——不管是谁写的。** 这是设计本身：模型把 `[[REDACTED:…]]` 写进命令或文件，真实值落到你的机器上。这也意味着被提示注入（网页、README、工具结果）劫持的 agent 仍可能被诱导去使用还原后的密钥——比如用 `curl` 把它发到别处。llm-redact 让密钥不进入*服务商*，但并不能让一个够得着密钥的 agent 变得安全。
- 模型看到的是占位符，所以它无法根据密钥的*内容*推理（比如“这是测试环境还是生产环境的 key？”）。这正是目的所在。

## 运行要求

Node.js 22.15+，没有任何依赖。

## 许可证

[MIT](LICENSE)
