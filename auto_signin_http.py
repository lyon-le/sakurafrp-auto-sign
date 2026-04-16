"""
SakuraFRP 自动签到 (纯 HTTP 协议版)
无浏览器依赖，速度远快于 Playwright 版

流程: HTTP登录 → HTTP签到 → GeeTest验证码破解 → AI识别 → 完成签到
"""

import ast
import json
import os
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from openai import OpenAI

from urllib.parse import urljoin

from geetest_crack import GeeTestCrack

# ── 加载环境变量 ──────────────────────────────────────────────
load_dotenv(Path(__file__).parent / ".env")
USERNAME = os.getenv("username", "")
PASSWORD = os.getenv("password", "")

CAPTCHA_API_BASE = os.getenv("CAPTCHA_API_BASE", "https://api.openai.com/v1")
CAPTCHA_API_KEY = os.getenv("CAPTCHA_API_KEY", "")
CAPTCHA_MODEL = os.getenv("CAPTCHA_MODEL", "gpt-4o")

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "10"))

MOUSE_PATH_FILE = str(Path(__file__).parent / "mousepath.json")

# ── 通用请求头 ────────────────────────────────────────────────
COMMON_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "sec-ch-ua": '"Chromium";v="145", "Not:A_Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    ),
}

OPENID_AJAX_HEADERS = {
    "accept": "application/json, text/javascript, */*; q=0.01",
    "x-requested-with": "XMLHttpRequest",
}
def _create_client(follow_redirects: bool = False) -> httpx.Client:
    return httpx.Client(
        follow_redirects=follow_redirects,
        timeout=30.0,
        headers=COMMON_HEADERS,
    )


def _prime_openid_session(client: httpx.Client) -> None:
    """建立 OAuth 会话上下文: natfrp → oauth/authorize → openid login"""
    resp = client.get("https://www.natfrp.com/cgi/user/login")
    # 手动跟完整条重定向链，确保 /oauth/authorize 被访问到
    step = 0
    while resp.is_redirect and step < 10:
        location = resp.headers.get("location")
        if not location:
            break
        next_url = urljoin(str(resp.url), location)
        referer = str(resp.url)
        resp = client.get(next_url, headers={"referer": referer})
        step += 1
        print(f"  prime[{step}]: {resp.status_code} -> {resp.url}")
    # 最终应该落在 openid.13a.com/login


def _follow_openid_redirect(client: httpx.Client) -> None:
    """完成 OpenID -> natfrp 的登录态桥接"""
    resp = client.get(
        "https://openid.13a.com/redirect",
        headers={"referer": "https://openid.13a.com/login"},
    )
    print(f"  OpenID redirect: {resp.status_code} -> {resp.url}")

    redirect_steps = 0
    while resp.is_redirect and redirect_steps < 10:
        location = resp.headers.get("location")
        if not location:
            break
        next_url = urljoin(str(resp.url), location)
        referer = str(resp.url)
        resp = client.get(next_url, headers={"referer": referer})
        redirect_steps += 1
        print(f"  follow redirect[{redirect_steps}]: {resp.status_code} -> {resp.url}")


def _extract_message_content(response) -> str:
    """兼容不同 OpenAI 兼容实现，尽量提取文本内容"""
    choices = getattr(response, "choices", None) or []
    if choices:
        message = getattr(choices[0], "message", None)
        if message is not None:
            content = getattr(message, "content", None)
            if isinstance(content, str):
                return content.strip()
            if isinstance(content, list):
                parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        parts.append(item.get("text", ""))
                text = "\n".join(part for part in parts if part).strip()
                if text:
                    return text

    data = getattr(response, "model_dump", lambda: None)()
    if isinstance(data, dict):
        choices = data.get("choices") or []
        if choices:
            message = choices[0].get("message") or {}
            content = message.get("content")
            if isinstance(content, str):
                return content.strip()
            if isinstance(content, list):
                parts = [item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text"]
                text = "\n".join(part for part in parts if part).strip()
                if text:
                    return text
    return ""


def _strip_json_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```json") and text.endswith("```"):
        return text[7:-3].strip()
    if text.startswith("```") and text.endswith("```"):
        return text[3:-3].strip()
    return text


def _solve_click_captcha(crack) -> str:
    """登录阶段的图片验证码求解 (与签到共用 AI 识别逻辑)"""
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n  --- 登录验证码尝试 {attempt}/{MAX_RETRIES} ---")
        pic_type, pic_url = crack.get_pic(0 if attempt == 1 else attempt)
        print(f"  验证码类型: {pic_type}")

        points = _recognize_captcha(pic_url, pic_type)
        if not points:
            print("  ✗ 识别失败，重试 ...")
            time.sleep(2)
            continue
        print(f"  识别结果: {points}")

        result = crack.verify(points)
        print(f"  验证结果: {result}")

        if result.get("status") == "success" and result.get("data", {}).get("result") == "success":
            validate = result["data"]["validate"]
            print("  ✓ 验证码通过!")
            return validate
        else:
            print("  ✗ 验证失败，重试 ...")
            time.sleep(2)

    raise RuntimeError(f"登录验证码重试 {MAX_RETRIES} 次均失败")



def login() -> httpx.Client:
    """
    纯 HTTP 登录流程:
    1. 获取 OpenID GeeTest 验证码配置
    2. 破解 GeeTest 获取 validate
    3. POST 登录
    4. 获取 session cookies
    """
    print("[1/3] 正在登录 ...")

    client = _create_client(follow_redirects=True)
    _prime_openid_session(client)

    # 1.1 获取 OpenID 的 GeeTest 配置
    print("  获取验证码配置 ...")
    resp = client.get(
        "https://openid.13a.com/cgi/captcha?login",
        headers={"referer": "https://openid.13a.com/login", **OPENID_AJAX_HEADERS},
    )
    captcha_data = resp.json()
    if not captcha_data.get("success"):
        raise RuntimeError(f"获取验证码配置失败: {captcha_data}")

    gt = captcha_data["message"]["gt"]
    challenge = captcha_data["message"]["challenge"]
    print(f"  GT: {gt[:16]}...  Challenge: {challenge[:16]}...")

    # 1.2 第一轮 GeeTest 交互，浏览器登录流在这里就拿到 validate
    print("  执行登录验证码握手 ...")
    crack = GeeTestCrack(gt, challenge, MOUSE_PATH_FILE, referer="https://openid.13a.com/")
    crack.get_type()
    crack.get_c_s()
    ajax_result = crack.ajax()

    validate = ajax_result.get("validate")
    print(f"  ajax 返回: {json.dumps(ajax_result, ensure_ascii=False)[:200]}...")
    if ajax_result.get("result") == "click":
        validate = _solve_click_captcha(crack)
    elif not validate:
        crack.close()
        raise RuntimeError(f"登录验证码未返回 validate: {ajax_result}")
    else:
        print(f"  验证成功! validate: {validate[:16]}...")

    # 1.3 POST 登录到 OpenID
    print("  提交登录 ...")
    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "geetest_id": challenge,
        "geetest_challenge": challenge,
        "geetest_validate": validate,
        "geetest_seccode": f"{validate}|jordan",
    }
    resp = client.post(
        "https://openid.13a.com/cgi/password/login",
        data=login_data,
        headers={
            "referer": "https://openid.13a.com/login",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            **OPENID_AJAX_HEADERS,
        },
    )

    if resp.status_code not in (200, 302):
        crack.close()
        raise RuntimeError(f"登录请求失败: {resp.status_code} {resp.text[:200]}")

    # 1.6 完成 OpenID -> natfrp 跳转桥接
    _follow_openid_redirect(client)

    # 1.7 验证登录状态
    resp = client.get("https://www.natfrp.com/cgi/v4/user/info")
    user_info = resp.json()

    if "name" not in user_info and "id" not in user_info:
        crack.close()
        raise RuntimeError(f"登录验证失败: {user_info}")

    username = user_info.get("name", "unknown")
    print(f"  ✓ 登录成功! 用户: {username}")

    crack.close()
    return client


def login_with_redirects() -> httpx.Client:
    """
    纯 HTTP 登录流程 (手动处理重定向)
    """
    print("[1/3] 正在登录 ...")

    client = _create_client(follow_redirects=False)
    _prime_openid_session(client)

    # 1.1 获取 OpenID 的 GeeTest 配置
    print("  获取验证码配置 ...")
    resp = client.get(
        "https://openid.13a.com/cgi/captcha?login",
        headers={"referer": "https://openid.13a.com/login", **OPENID_AJAX_HEADERS},
    )
    captcha_data = resp.json()
    if not captcha_data.get("success"):
        raise RuntimeError(f"获取验证码配置失败: {captcha_data}")

    gt = captcha_data["message"]["gt"]
    challenge = captcha_data["message"]["challenge"]
    print(f"  GT: {gt[:16]}...  Challenge: {challenge[:16]}...")

    # 1.2 第一轮 GeeTest 交互，浏览器登录流在这里就拿到 validate
    print("  执行登录验证码握手 ...")
    crack = GeeTestCrack(gt, challenge, MOUSE_PATH_FILE, referer="https://openid.13a.com/")
    crack.get_type()
    crack.get_c_s()
    ajax_result = crack.ajax()

    validate = ajax_result.get("validate")
    print(f"  ajax 返回: {json.dumps(ajax_result, ensure_ascii=False)[:200]}...")
    if ajax_result.get("result") == "click":
        validate = _solve_click_captcha(crack)
    elif not validate:
        crack.close()
        raise RuntimeError(f"登录验证码未返回 validate: {ajax_result}")
    else:
        print("  ✓ 验证码通过")

    # 1.3 POST 登录
    print("  提交登录 ...")
    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "geetest_id": challenge,
        "geetest_challenge": challenge,
        "geetest_validate": validate,
        "geetest_seccode": f"{validate}|jordan",
    }
    resp = client.post(
        "https://openid.13a.com/cgi/password/login",
        data=login_data,
        headers={
            "referer": "https://openid.13a.com/login",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            **OPENID_AJAX_HEADERS,
        },
    )

    # 1.4 完成 OpenID -> natfrp 跳转桥接
    _follow_openid_redirect(client)

    # 1.5 验证登录
    resp = client.get("https://www.natfrp.com/cgi/v4/user/info")
    user_info = resp.json()

    if "name" not in user_info and "id" not in user_info:
        crack.close()
        raise RuntimeError(f"登录验证失败: {user_info}")

    print(f"  ✓ 登录成功! 用户: {user_info.get('name', 'unknown')}")
    crack.close()
    return client


# ── 步骤 2: 签到 ──────────────────────────────────────────────

def check_sign_status(client: httpx.Client) -> dict:
    """检查签到状态"""
    resp = client.get("https://www.natfrp.com/cgi/v4/user/info")
    return resp.json()


def sign_in(client: httpx.Client) -> bool:
    """
    签到流程:
    1. 获取签到的 GeeTest 配置
    2. 破解验证码
    3. AI 识别九宫格
    4. POST 签到
    """
    print("[2/3] 正在签到 ...")

    # 2.1 检查是否已签到
    user_info = check_sign_status(client)
    print(f"  用户信息: {json.dumps(user_info, ensure_ascii=False)[:200]}...")

    sign_info = user_info.get("sign", {})
    if sign_info.get("signed"):
        print(f"  今天已经签到过了! 连续签到 {sign_info.get('days', '?')} 天")
        return True

    # 2.2 获取签到的 GeeTest 配置
    print("  获取签到验证码配置 ...")
    resp = client.get("https://www.natfrp.com/cgi/v4/user/sign?gt")
    try:
        geetest_data = resp.json()
    except Exception:
        # 可能返回 JSONP 或其他格式
        print(f"  签到 GeeTest 响应: {resp.text[:200]}...")
        # 尝试从响应中提取 JSON
        import re
        match = re.search(r'\((.+)\)', resp.text, re.DOTALL)
        if match:
            geetest_data = json.loads(match.group(1))
        else:
            raise RuntimeError(f"无法解析签到 GeeTest 数据: {resp.text[:200]}")

    if "gt" not in geetest_data:
        raise RuntimeError(f"签到 GeeTest 数据格式异常: {geetest_data}")

    gt = geetest_data["gt"]
    challenge = geetest_data["challenge"]
    print(f"  GT: {gt[:16]}...  Challenge: {challenge[:16]}...")

    # 2.3 破解 GeeTest
    print("  破解签到验证码 ...")
    crack = GeeTestCrack(gt, challenge, MOUSE_PATH_FILE, referer="https://openid.13a.com/")
    crack.get_type()
    crack.get_c_s()
    crack.ajax()

    # 2.4 获取验证码图片并识别 (带重试)
    validate = None
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n  --- 验证码尝试 {attempt}/{MAX_RETRIES} ---")

        pic_type, pic_url = crack.get_pic(0 if attempt == 1 else attempt)
        print(f"  验证码类型: {pic_type}")

        points = _recognize_captcha(pic_url, pic_type)
        if not points:
            print("  ✗ 识别失败，重试 ...")
            time.sleep(2)
            continue
        print(f"  识别结果: {points}")

        result = crack.verify(points)
        print(f"  验证结果: {result}")

        if result.get("status") == "success" and result.get("data", {}).get("result") == "success":
            validate = result["data"]["validate"]
            print(f"  ✓ 验证码通过!")
            break
        else:
            print(f"  ✗ 验证失败，重试 ...")
            time.sleep(2)

    crack.close()

    if not validate:
        raise RuntimeError(f"验证码重试 {MAX_RETRIES} 次均失败")

    # 2.5 POST 签到
    print("  提交签到 ...")
    sign_data = {
        "geetest_challenge": challenge,
        "geetest_validate": validate,
        "geetest_seccode": f"{validate}|jordan",
    }
    sign_headers = dict(COMMON_HEADERS)
    sign_headers["content-type"] = "application/x-www-form-urlencoded"
    sign_headers["referer"] = "https://www.natfrp.com/user/"

    resp = client.post(
        "https://www.natfrp.com/cgi/v4/user/sign",
        data=sign_data,
        headers=sign_headers,
    )
    sign_result = resp.json()
    print(f"  签到响应: {json.dumps(sign_result, ensure_ascii=False)}")

    if isinstance(sign_result, str):
        # API 直接返回成功消息字符串
        return True
    return sign_result.get("status") == "success" or sign_result.get("code") == 0


# ── 验证码识别 ────────────────────────────────────────────────

def _recognize_captcha(image_url: str, pic_type: str) -> list:
    """
    调用多模态 AI 识别验证码图片
    返回点击坐标列表，格式为 ["col_row", ...]
    """
    if not CAPTCHA_API_KEY:
        print("  ✗ 未配置 CAPTCHA_API_KEY")
        return []

    client = OpenAI(base_url=CAPTCHA_API_BASE, api_key=CAPTCHA_API_KEY)

    if pic_type == "nine":
        # 九宫格验证码
        prompt = (
            '这是一个九宫格验证码。请按从左到右、从上到下的顺序识别每个格子里的物品名称，'
            '最后识别左下角的参考图。输出格式为JSON：{"1":"名称", "2":"名称", ..., "10":"参考图名称"}。'
            '名称要简洁，参考图名称必须是九宫格里已有的名称。若有类似物品（如气球与热气球），请统一名称。'
            '只输出JSON，不要其他文字。'
        )
        response = client.chat.completions.create(
            model=CAPTCHA_MODEL,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_url}},
                ],
            }],
            stream=False,
        )
        result_text = _strip_json_fence(_extract_message_content(response))
        if not result_text:
            choices = getattr(response, "choices", None) or []
            if choices:
                message = getattr(choices[0], "message", None)
                if message and getattr(message, "refusal", None):
                    print(f"  AI 拒绝识别: {message.refusal}")
            return []
        print(f"  AI 识别原始结果: {result_text}")

        try:
            recognition = json.loads(result_text)
        except json.JSONDecodeError:
            print("  ✗ JSON 解析失败")
            return []

        target_name = recognition.get("10", "").strip()
        if not target_name:
            print("  ✗ 未能获取参考图名称")
            return []

        print(f"  目标物品: {target_name}")

        # 匹配格子，返回 col_row 格式
        points = []
        for i in range(9):
            position = str(i + 1)
            item_name = recognition.get(position, "").strip()
            if item_name == target_name:
                # 位置 i: 行 = i // 3 + 1, 列 = i % 3 + 1
                row = i // 3 + 1
                col = i % 3 + 1
                points.append(f"{col}_{row}")
                print(f"  匹配! 位置 {position}: {item_name} → {col}_{row}")

        return points

    else:
        # icon/space 类型验证码 (点选文字/图标位置)
        prompt = (
            '这是一个点选验证码。请识别图中需要点击的目标文字或图标，'
            '并返回每个目标的大致坐标位置。输出格式为JSON列表：'
            '[{"x": 100, "y": 200}, ...]。坐标原点在左上角。'
            '只输出JSON，不要其他文字。'
        )
        response = client.chat.completions.create(
            model=CAPTCHA_MODEL,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_url}},
                ],
            }],
            stream=False,
        )
        result_text = _strip_json_fence(_extract_message_content(response))
        if not result_text:
            choices = getattr(response, "choices", None) or []
            if choices:
                message = getattr(choices[0], "message", None)
                if message and getattr(message, "refusal", None):
                    print(f"  AI 拒绝识别: {message.refusal}")
            return []
        print(f"  AI 识别原始结果: {result_text}")

        try:
            coords = json.loads(result_text)
            if isinstance(coords, dict):
                coords = coords.get("coordinates", coords.get("points", []))
            points = []
            for c in coords:
                if isinstance(c, dict):
                    if "x" in c and "y" in c:
                        points.append(f"{c['x']}_{c['y']}")
                    elif "point_2d" in c:
                        pt = c["point_2d"]
                        points.append(f"{pt[0]}_{pt[1]}")
            return points
        except (json.JSONDecodeError, KeyError, TypeError, IndexError):
            print("  ✗ 坐标解析失败")
            return []


# ── 主流程 ────────────────────────────────────────────────────

def main():
    if not USERNAME or not PASSWORD:
        print("错误: 请在 .env 文件中配置 username 和 password")
        sys.exit(1)
    if not CAPTCHA_API_KEY:
        print("错误: 请设置 CAPTCHA_API_KEY 环境变量")
        sys.exit(1)

    start_time = time.time()

    try:
        # 步骤 1: 登录
        client = login_with_redirects()

        # 步骤 2: 签到
        success = sign_in(client)

        # 步骤 3: 验证结果
        print("[3/3] 验证签到结果 ...")
        user_info = check_sign_status(client)
        print(f"  用户信息: {json.dumps(user_info, ensure_ascii=False)[:200]}...")

        elapsed = time.time() - start_time
        if success:
            print(f"\n✓ 签到成功! 耗时: {elapsed:.1f}s")
        else:
            print(f"\n✗ 签到可能失败，请检查。耗时: {elapsed:.1f}s")

        client.close()

    except Exception as e:
        print(f"\n✗ 流程出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
