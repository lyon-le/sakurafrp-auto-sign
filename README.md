# SakuraFRP 自动签到

纯 HTTP 协议实现 SakuraFRP (natfrp.com) 每日自动签到。无浏览器依赖，端到端耗时约 2-3 秒。

**技术路线：** GeeTest v3 协议逆向 + AI 多模态验证码识别。详见 [Solve.md](Solve.md)。

## 快速开始

### 环境要求

- Python >= 3.9
- [uv](https://docs.astral.sh/uv/)
- 一个支持多模态的 OpenAI 兼容 API（用于验证码识别）

### 1. 安装依赖

```bash
uv sync
```

### 2. 配置环境变量

复制并编辑 `.env` 文件：

```env
# SakuraFRP 账号
username=your_email@example.com
password=your_password

# AI 验证码识别 API（OpenAI 兼容）
CAPTCHA_API_BASE=https://api.openai.com/v1
CAPTCHA_API_KEY=sk-...
CAPTCHA_MODEL=gpt-4o

# 验证码最大重试次数（可选，默认 10）
MAX_RETRIES=10
```

### 3. 运行

```bash
uv run python auto_signin_http.py
```

输出示例：

```
[1/3] 正在登录 ...
  ✓ 登录成功! 用户: your_username
[2/3] 正在签到 ...
  ✓ 验证码通过!
  签到响应: "运气不错，获得 1.6 GiB 流量。"
[3/3] 验证签到结果 ...

✓ 签到成功! 耗时: 2.7s
```

## Docker 部署

### 构建并运行

```bash
docker compose run --rm signin
```

### 定时任务

配合 cron 实现每日自动签到：

```cron
0 9 * * * cd /path/to/sakuraFRP && docker compose run --rm signin >> signin.log 2>&1
```

## 环境变量说明

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `username` | 是 | - | SakuraFRP 登录邮箱/用户名 |
| `password` | 是 | - | SakuraFRP 登录密码 |
| `CAPTCHA_API_BASE` | 否 | `https://api.openai.com/v1` | OpenAI 兼容 API 地址 |
| `CAPTCHA_API_KEY` | 是 | - | API Key |
| `CAPTCHA_MODEL` | 否 | `gpt-4o` | 多模态模型名称 |
| `MAX_RETRIES` | 否 | `10` | 验证码最大重试次数 |

## 项目结构

```
sakuraFRP/
├── auto_signin_http.py   # 主程序：登录 → 签到 → 验证
├── geetest_crack.py      # GeeTest v3 协议逆向实现
├── mousepath.json        # 预录制鼠标轨迹数据
├── pyproject.toml        # uv 项目配置
├── Dockerfile            # 容器构建
├── docker-compose.yml    # Compose 配置
├── Solve.md              # 协议逆向技术文档
└── .env                  # 环境变量（需自行创建）
```

## 致谢

- [ladeng07/sakura-signin](https://github.com/ladeng07/sakura-signin) — GeeTest v3 协议逆向实现的核心参考
- [Yumu2497/SakuraFrpQiandao](https://github.com/Yumu2497/SakuraFrpQiandao) (MIT License) — 签到流程与九宫格 Prompt 设计参考

## 免责声明

本项目仅供学习研究使用。使用本工具造成的任何后果由使用者自行承担。请遵守 SakuraFRP 的服务条款。
