# SakuraFRP 纯 HTTP 协议签到 — 技术文档

## 概述

本项目通过纯 HTTP 协议实现 SakuraFRP (natfrp.com) 的自动登录与每日签到，完全不依赖浏览器或 Playwright。核心难点在于逆向 GeeTest v3 验证码协议和正确复现 OpenID OAuth 跨域登录态桥接。

**端到端耗时约 2-3 秒**（浏览器自动化版本需要 30 秒以上）。

### 技术路线：协议逆向 + AI 多模态识别

本项目采用的是**混合方案**，而非纯协议逆向：

| 层面 | 方案 | 说明 |
|------|------|------|
| 登录/签到流程 | **纯协议逆向** | HTTP 请求、OAuth 跳转、cookie 管理，全部协议级实现 |
| GeeTest 握手 | **纯协议逆向** | gettype → get → ajax → get_pic → verify，完整复现加密、编码、JSONP 解析 |
| 验证码图片求解 | **AI 多模态识别** | 将验证码图片 URL 发送给 OpenAI 兼容的多模态模型，由 AI 返回识别结果 |
| 验证码结果提交 | **纯协议逆向** | 将 AI 返回的坐标/格子编号编码后通过协议提交 |

**为什么不是纯协议？**

GeeTest v3 的九宫格/点选验证码本质是一个**视觉理解问题**（"找出图中所有的鹿"），不存在可以绕过图像内容的协议漏洞。GeeTest 服务端随机生成图片，客户端必须理解图片内容才能回答。因此图像识别环节必须借助外部能力——本项目选择了多模态 AI。

**协议逆向覆盖了什么？**

除图像内容理解外的**所有环节**都是纯协议实现：
- AES-CBC + RSA 混合加密的 `w` 参数构造
- GeeTest 自定义 base64 编码
- 鼠标轨迹录制、编码、混淆（preprocess → process → postprocess）
- 浏览器指纹伪造（ep.tm / ep.em / ven / ren 等字段）
- JSONP 回调解析
- 跨域 OAuth 重定向链桥接
- Cookie jar 状态管理

---

## 整体架构

```
┌─────────────────────────────────────────────────────┐
│                  auto_signin_http.py                 │
│                                                     │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │ 1. 登录  │──▶│ 2. 签到  │──▶│ 3. 验证结果     │ │
│  └────┬─────┘   └────┬─────┘   └──────────────────┘ │
│       │              │                               │
│       ▼              ▼                               │
│  ┌─────────────────────────┐   ┌──────────────────┐ │
│  │   geetest_crack.py      │   │ OpenAI 多模态 API │ │
│  │   GeeTest v3 协议实现   │   │ 验证码图片识别    │ │
│  └─────────────────────────┘   └──────────────────┘ │
└─────────────────────────────────────────────────────┘
```

**文件清单：**

| 文件 | 职责 |
|------|------|
| `auto_signin_http.py` | 主流程编排：登录 → 签到 → 验证 |
| `geetest_crack.py` | GeeTest v3 协议逆向实现 |
| `mousepath.json` | 预录制的鼠标轨迹数据 |
| `.env` | 账号密码与 AI API 配置 |

---

## 阶段一：登录

### 1.1 OAuth 会话建立 (`_prime_openid_session`)

SakuraFRP 使用 Nyatwork OpenID 作为第三方登录。浏览器的真实链路是：

```
GET natfrp.com/cgi/user/login
  → 302 openid.13a.com/oauth/authorize?response_type=code&client_id=...
    → 302 openid.13a.com/login
```

**关键发现：** 必须让 HTTP client **完整跟完这条重定向链**，不能直接独立 GET 各端点。原因是 `/oauth/authorize` 这一步在服务端建立了 OAuth 会话状态（设置 `oauth_redirect` cookie 和服务端关联），后续 `/redirect` 端点依赖这个状态才能签发 authorization code 并跳转回 natfrp。

如果跳过 `/oauth/authorize`，登录后 `/redirect` 会返回 `302 /user`（停留在 openid.13a.com），而不是预期的跨域跳转。

**实现要点：** client 使用 `follow_redirects=False`，手动逐步跟踪每个 302，确保 cookie jar 正确积累所有域的 cookie。

### 1.2 获取 GeeTest 验证码配置

```
GET openid.13a.com/cgi/captcha?login
Headers: X-Requested-With: XMLHttpRequest
```

返回：
```json
{
  "success": true,
  "message": {
    "gt": "f53512a605e97afa6985c0daee8c8179",
    "challenge": "<32位随机hex>"
  }
}
```

`gt` 是 GeeTest 账户标识（固定），`challenge` 每次不同。

**风控注意：** 此端点有严格的频率限制。触发后返回 `{"success":false,"message":"操作频繁, 请 24 小时后重试"}`。经验证：
- 不是 IP 级限制（换代理无效）
- 更像是账号/会话/风控指纹级限制
- 冷却期约 24 小时

### 1.3 GeeTest v3 协议握手

这是整个逆向中最复杂的部分，详见下方 [GeeTest 协议详解](#geetest-v3-协议详解)。

握手结果有两种分支：

| ajax() 返回 | 含义 | 后续动作 |
|-------------|------|---------|
| `{"result":"success","validate":"..."}` | 直接通过 | 用 validate 提交登录 |
| `{"result":"click"}` | 需要图片验证 | 进入 get_pic → AI 识别 → verify 循环 |

实测中，大部分情况 ajax() 直接返回 validate（score 1-6），偶尔降级到图片验证。

### 1.4 提交登录凭据

```
POST openid.13a.com/cgi/password/login
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

username=...&password=...
&geetest_id=<challenge>
&geetest_challenge=<challenge>
&geetest_validate=<validate>
&geetest_seccode=<validate>|jordan
```

注意 `geetest_id` 和 `geetest_challenge` 的值**相同**，都是 challenge。`seccode` 固定格式为 `{validate}|jordan`。

成功返回：`{"success":true,"message":null}`

### 1.5 OpenID → natfrp 登录态桥接 (`_follow_openid_redirect`)

这是协议实现中**第二个关键发现**。浏览器登录成功后执行 `location.href = '/redirect'`，触发以下跨域重定向链：

```
GET openid.13a.com/redirect
  Referer: openid.13a.com/login
  → 302 natfrp.com/cgi/user/login?code=<authorization_code>
    → 302 natfrp.com/user/login?success
```

- 第一跳：OpenID 服务端用之前 `/oauth/authorize` 建立的会话，签发一次性 authorization code
- 第二跳：natfrp 后端用 code 换取用户身份，设置 natfrp 侧 session cookie
- 第三跳：落地到成功页面

实现中必须**手动逐步跟踪每个 302**，确保跨域 cookie 正确传递。

### 1.6 验证登录状态

```
GET natfrp.com/cgi/v4/user/info
```

成功返回用户完整信息：
```json
{
  "id": 77985,
  "name": "liyangzhong02",
  "token": "...",
  "sign": {
    "signed": false,
    "last": "2026-04-15",
    "days": 38,
    "traffic": 98.1
  }
}
```

---

## 阶段二：签到

### 2.1 签到状态检查

复用 `/cgi/v4/user/info`，检查 `sign.signed` 字段。若为 `true` 则跳过，避免浪费验证码次数。

### 2.2 获取签到 GeeTest 配置

```
GET natfrp.com/cgi/v4/user/sign?gt
```

返回独立的 gt + challenge（与登录的不同，签到用的 gt 是 `78aaca6a49add69b...`）。

### 2.3 签到验证码求解

签到阶段的 GeeTest 固定走图片验证码（ajax 返回 `{"result":"click"}`，不会直接给 validate）。

流程：`get_pic()` → AI 识别 → `verify()` → 重试直到成功。

验证码类型有：

| pic_type | 描述 | 识别策略 |
|----------|------|---------|
| `nine` | 九宫格：9 个格子 + 1 个参考图 | AI 识别每格物品名，匹配参考图，返回 col_row 坐标 |
| `space` | 空间识别：点选特定物体 | AI 返回像素坐标 |
| 其他 icon 类 | 点选文字/图标 | AI 返回像素坐标 |

### 2.4 提交签到

```
POST natfrp.com/cgi/v4/user/sign
Content-Type: application/x-www-form-urlencoded
Referer: natfrp.com/user/

geetest_challenge=<challenge>
&geetest_validate=<validate>
&geetest_seccode=<validate>|jordan
```

成功返回字符串：`"运气不错，获得 1.6 GiB 流量。"`

---

## GeeTest v3 协议详解

### 协议总览

GeeTest v3 fullpage 模式的完整请求序列：

```
1. gettype.php  → 获取验证码类型元数据
2. get.php      → 获取加密参数 c, s 和服务端配置
3. ajax.php     → 提交第一轮交互（模拟按钮点击）
   ├─ 返回 validate → 完成
   └─ 返回 "click"  → 继续:
4. get.php      → 获取验证码图片 (is_next=true)
5. refresh.php  → 刷新图片 (重试时)
6. ajax.php     → 提交点击结果验证
```

### 加密体系

每次会话生成一对密钥：

- **AES 密钥**：随机 16 字节 hex 字符串，用于加密 `w` payload
- **RSA 公钥**：GeeTest 固定的 1024-bit RSA 公钥，用于加密 AES 密钥

`w` 参数的构造：
```
w = custom_base64(AES_CBC_encrypt(payload_json)) + RSA_encrypt(aes_key).hex()
```

- AES 模式：CBC，IV 固定 `"0000000000000000"`，PKCS7 padding
- Base64：GeeTest 自定义字符表 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()`，使用位掩码变换而非标准 base64

### 鼠标轨迹编码 (`encode_mouse_path`)

GeeTest 要求提交鼠标行为轨迹，编码过程分三步：

1. **预处理** (`preprocess`)：过滤输入类型（pointer/mouse/touch），计算相对位移和时间差
2. **处理** (`process`)：将事件类型、坐标、时间分别编码为变长二进制串，然后用自定义 6-bit 字符集压缩
3. **后处理** (`postprocess`)：用服务端返回的 `c` 和 `s` 参数做二次混淆（在编码结果的特定位置插入干扰字符）

`c` 是一个 5 元素整数数组（二次多项式系数），`s` 是一个 hex 字符串。后处理的位置由 `(c[0]*x^2 + c[2]*x + c[4]) mod len(str)` 决定。

### 关键请求参数

**get.php (get_c_s) 的 w payload：**
```json
{
  "gt": "<gt>",
  "challenge": "<challenge>",
  "offline": false,
  "new_captcha": true,
  "product": "float",
  "width": "100%",
  "https": true,
  "protocol": "https://",
  "type": "fullpage",      // 来自 gettype 响应
  "static_servers": [...],  // 来自 gettype 响应
  "cc": 16,
  "ww": true,
  "i": "-1!!-1!!...!!-1"   // 74 个 -1，用 !! 分隔
}
```

**ajax.php 的 w payload：**
```json
{
  "lang": "zh-cn",
  "type": "fullpage",
  "tt": "<encoded_mouse_path>",
  "light": "DIV_0",
  "s": "<固定 hash>",
  "h": "<固定 hash>",
  "hh": "<固定 hash>",
  "hi": "<固定 hash>",
  "vip_order": -1,
  "ct": -1,
  "ep": {
    "v": "9.1.9-dbjg5z",
    "te": false,
    "me": true,
    "ven": "Google Inc. (Intel)",
    "ren": "ANGLE (Intel, ...)",
    "fp": ["scroll", 0, 1602, <timestamp>, null],
    "lp": ["up", 386, 217, <timestamp>, "pointerup"],
    "em": {"ph":0,"cp":0,"ek":"11","wd":1,"nt":0,"si":0,"sc":0},
    "tm": {"a":<ts>,"b":<ts>,...,"u":<ts>}
  },
  "passtime": 1600,
  "rp": "<md5(gt + challenge + s)>",
  "captcha_token": "1198034057",
  "du6o": "eyjf7nne"
}
```

**verify (ajax.php) 的 w payload：**
```json
{
  "lang": "zh-cn",
  "passtime": 1600,
  "a": "2_1,3_2,2_3",    // 点击坐标，col_row 格式
  "pic": "/captcha_v3/...",
  "tt": "<encoded_mouse_path>",
  "ep": {
    "ca": [{"x":524,"y":209,"t":0,"dt":1819}, ...],
    "v": "3.1.2",
    "me": true,
    "tm": {...}
  },
  "h9s9": "1816378497",
  "rp": "<md5(gt + challenge + passtime)>"
}
```

### 动态 Host 切换

GeeTest 的 API 分布在多个域名上，且会在响应中动态指定后续请求应该使用的 host：

| 域名 | 用途 |
|------|------|
| `api.geetest.com` | gettype.php, get.php, refresh.php |
| `api.geevisit.com` | ajax.php（初始默认） |
| `static.geetest.com` | JS/CSS/图片资源 |

`get_c_s()` 和 `get_pic()` 的响应中包含 `api_server` 和 `static_servers` 字段，实现中通过 `_apply_geetest_hosts()` 动态更新后续请求的 host。这是协议实现中容易遗漏的点——硬编码 host 会导致后续请求返回 `error_00`。

### JSONP 响应格式

所有 GeeTest API 返回 JSONP 格式：
```
geetest_1776314265701({"status":"success","data":{...}})
```

解析时提取括号内的 JSON 即可。callback 参数格式为 `geetest_` + 13 位毫秒时间戳。

---

## AI 验证码识别

### 九宫格 (nine)

Prompt 策略：要求 AI 按序识别 9 个格子 + 1 个参考图（位置 10）的物品名称，输出 JSON：
```json
{"1":"冰箱","2":"鹿","3":"冰箱",...,"10":"鹿"}
```

然后在代码侧匹配 `recognition[i] == recognition["10"]` 的格子，转换为 `col_row` 坐标。

坐标映射：位置 i（0-indexed）→ `col = i%3+1`, `row = i//3+1`

### 点选 (space/icon)

Prompt 要求 AI 返回像素坐标：
```json
[{"x": 309, "y": 278}, {"x": 386, "y": 532}]
```

也兼容 `point_2d` 格式（部分 AI provider 返回）：
```json
[{"point_2d": [309, 278], "label": "球体"}]
```

### Provider 兼容性

通过 `_extract_message_content()` 和 `_strip_json_fence()` 两个辅助函数处理不同 OpenAI 兼容 API 的响应差异：

- `response.choices[0].message.content` 可能是 string、list、或 None
- 部分 provider 会将 JSON 包裹在 markdown 代码块中（`` ```json ... ``` ``）
- `response.choices` 本身可能为 None（API 异常/限流时）

---

## 关键调试经验

### 问题 1：OpenID redirect 回到 /user 而不是跨域跳转

**根因：** `_prime_openid_session` 未访问 `/oauth/authorize`，导致服务端没有 OAuth 会话上下文。

**修复：** 从 `natfrp.com/cgi/user/login` 开始手动跟完整条重定向链。

### 问题 2：GeeTest get_pic 返回 error_00

**根因：** `product` 参数硬编码为 `embed`（应为 `float`），`api_server` 硬编码为 `api.geevisit.com`（应从前序响应动态获取）。

**修复：** 引入 `_apply_geetest_hosts()` 动态更新 host，`product` 改为 `float`。

### 问题 3：频率限制无法绕过

**现象：** `cgi/captcha?login` 返回 `操作频繁, 请 24 小时后重试`，换 IP 代理无效。

**结论：** 限制绑定的是账号/会话/风控指纹，不仅是 IP。只能等冷却期过后重试。

### 问题 4：natfrp API 字段不匹配

**现象：** 代码检查 `user_info["username"]`，但实际 API 返回的字段是 `name`。签到响应直接返回字符串而不是 JSON 对象。

**修复：** 改用 `name`/`id` 检查，签到响应增加 `isinstance(result, str)` 分支。

---

## 环境配置

### .env 文件

```env
username=your_email@example.com
password=your_password

# AI 验证码识别 API（OpenAI 兼容）
CAPTCHA_API_BASE=https://api.openai.com/v1
CAPTCHA_API_KEY=sk-...
CAPTCHA_MODEL=gpt-4o

# 验证码最大重试次数
MAX_RETRIES=10
```

### 依赖

```
httpx[http2]
python-dotenv
openai
cryptography
```

---

## 请求时序图

```
Client              OpenID (13a.com)         natfrp.com          GeeTest
  │                      │                      │                  │
  │─── GET /cgi/user/login ─────────────────────▶│                  │
  │◀── 302 /oauth/authorize ────────────────────│                  │
  │─── GET /oauth/authorize ────▶│               │                  │
  │◀── 302 /login ──────────────│               │                  │
  │─── GET /login ──────────────▶│               │                  │
  │◀── 200 (登录页 HTML) ───────│               │                  │
  │                              │               │                  │
  │─── GET /cgi/captcha?login ──▶│               │                  │
  │◀── {gt, challenge} ─────────│               │                  │
  │                              │               │                  │
  │─── GET gettype.php ─────────────────────────────────────────────▶│
  │◀── {type, static_servers} ──────────────────────────────────────│
  │─── GET get.php (w=...) ─────────────────────────────────────────▶│
  │◀── {c, s, api_server} ─────────────────────────────────────────│
  │─── GET ajax.php (w=...) ────────────────────────────────────────▶│
  │◀── {validate} 或 {result:"click"} ─────────────────────────────│
  │                              │               │                  │
  │  [如果 click: get_pic → AI识别 → verify 循环]                    │
  │                              │               │                  │
  │─── POST /cgi/password/login ▶│               │                  │
  │◀── {success: true} ─────────│               │                  │
  │                              │               │                  │
  │─── GET /redirect ───────────▶│               │                  │
  │◀── 302 /cgi/user/login?code=... ────────────▶│                  │
  │◀── 302 /user/login?success ─────────────────│                  │
  │                              │               │                  │
  │─── GET /cgi/v4/user/info ───────────────────▶│                  │
  │◀── {name, sign:{signed:false}} ─────────────│                  │
  │                              │               │                  │
  │═══════════ 签到阶段 ═════════════════════════│                  │
  │                              │               │                  │
  │─── GET /cgi/v4/user/sign?gt ────────────────▶│                  │
  │◀── {gt, challenge} ─────────────────────────│                  │
  │                              │               │                  │
  │─── [GeeTest 握手: gettype → get → ajax] ────────────────────────▶│
  │─── [get_pic → AI识别 → verify 循环] ────────────────────────────▶│
  │◀── {validate} ──────────────────────────────────────────────────│
  │                              │               │                  │
  │─── POST /cgi/v4/user/sign ──────────────────▶│                  │
  │◀── "运气不错，获得 1.6 GiB 流量。" ─────────│                  │
```

---

## 致谢与参考

本项目的实现参考了以下开源项目，在此表示感谢：

### [ladeng07/sakura-signin](https://github.com/ladeng07/sakura-signin)

- **引用范围：** `geetest_crack.py` 的 GeeTest v3 协议逆向实现（加密体系、鼠标轨迹编码、请求序列）是基于此仓库的 `crack.py` 改写的。
- **开源协议：** 该仓库**未包含 LICENSE 文件**。README 声明"本项目仅供学习研究使用"。
- **主要贡献：** GeeTest v3 fullpage 模式的完整协议流程、AES+RSA 混合加密的 `w` 参数构造、自定义 base64 编码、鼠标轨迹编码算法。

### [Yumu2497/SakuraFrpQiandao](https://github.com/Yumu2497/SakuraFrpQiandao)

- **引用范围：** `auto_signin.py`（Playwright 浏览器自动化版本）的整体流程和 AI 九宫格识别的 Prompt 设计参考了此仓库。
- **开源协议：** **MIT License**。
- **主要贡献：** SakuraFRP 签到的完整业务流程（登录 → 年龄确认 → 签到按钮 → 验证码求解），以及九宫格验证码的 AI 识别 Prompt 策略。

### 本项目在上游基础上的独立工作

以下部分是本项目独立实现的，不来自上游参考仓库：

- **OpenID OAuth 跨域登录态桥接**（`_prime_openid_session` + `_follow_openid_redirect`）：上游仓库要么使用浏览器自动化（Yumu2497），要么使用预获取的 cookie（ladeng07）。本项目从零逆向了 natfrp → openid.13a.com 的完整 OAuth code 交换链路。
- **GeeTest 动态 host 切换**（`_apply_geetest_hosts`）：上游硬编码了 `api.geevisit.com`，本项目改为从响应中动态获取。
- **登录验证码分支处理**：上游只处理了签到阶段的图片验证码，本项目额外处理了登录阶段 `ajax()` 返回 `click` 的降级场景。
- **多模态 AI 响应兼容层**（`_extract_message_content` + `_strip_json_fence`）：处理不同 OpenAI 兼容 provider 的响应格式差异。
- **`space` 类型验证码和 `point_2d` 坐标格式**的支持。
