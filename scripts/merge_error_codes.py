#!/usr/bin/env python3
"""One-shot merge of the 2026-08 backend i18n sweep.

Registers the new machine-readable error codes in hub/errors.py and adds the
matching err.* translations to the en / zh-CN / ja locale files.  Idempotent:
codes and keys that already exist are skipped.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# code, status, en, zh, ja  — collected from the sweep agents' reports.
NEW_CODES: list[tuple[str, int, str, str, str]] = [
    # ── network ──
    ("network.invalid_ip", 400, "invalid IP address / netmask", "IP / 子网掩码格式无效", "IP / サブネットマスクの形式が無効です"),
    ("network.invalid_router", 400, "invalid gateway address", "网关格式无效", "ゲートウェイの形式が無効です"),
    ("network.invalid_netmask", 400, "invalid netmask", "子网掩码无效", "サブネットマスクが無効です"),
    ("network.invalid_dns", 400, "invalid DNS server: {server}", "非法 DNS: {server}", "無効な DNS サーバー: {server}"),
    ("network.order_required", 400, "the full service order list is required", "需要完整的服务顺序列表", "サービス順序の完全なリストが必要です"),
    ("network.unknown_service", 400, "unknown network service: {service}", "未知服务: {service}", "不明なネットワークサービス: {service}"),
    ("network.services_unreadable", 500, "could not read network services", "无法读取网络服务", "ネットワークサービスを読み取れません"),
    ("network.bad_profile", 400, "profile must be one of: wifi | ethernet | wifi_only | ethernet_only", "profile 可选: wifi | ethernet | wifi_only | ethernet_only", "profile は wifi | ethernet | wifi_only | ethernet_only のいずれかを指定してください"),
    ("network.invalid_device", 400, "invalid interface name: {device}", "非法网卡名: {device}", "無効なインターフェース名: {device}"),
    ("network.device_not_found", 404, "no such interface: {device}", "网卡不存在: {device}", "インターフェースが見つかりません: {device}"),
    ("network.invalid_service_name", 400, "invalid network service name", "无效的网络服务名", "ネットワークサービス名が無効です"),
    ("network.service_not_found", 404, "network service not found: {service}", "找不到网络服务: {service}", "ネットワークサービスが見つかりません: {service}"),
    ("network.invalid_hostname", 400, "invalid hostname", "非法主机名", "無効なホスト名です"),
    ("network.docker_args_required", 400, "network and container are required", "需要 network 与 container", "network と container が必要です"),
    ("network.builtin_network_connect", 400, "cannot connect to the host/none network", "不能 connect 到 host/none", "host/none ネットワークへは接続できません"),
    ("network.container_not_found", 404, "container not found: {name}", "容器不存在: {name}", "コンテナが見つかりません: {name}"),
    ("network.image_unresolvable", 400, "could not resolve the container's image", "无法解析镜像", "コンテナのイメージを解決できません"),
    # ── cloudflared ──
    ("cloudflared.not_installed", 503, 'cloudflared is not installed (install "Cloudflared (native)" from the app store first)', "未找到 cloudflared（请先在应用商店安装「Cloudflared（原生）」）", "cloudflared が見つかりません（先にアプリストアから「Cloudflared（ネイティブ）」をインストールしてください）"),
    ("cloudflared.tunnel_required", 400, "a tunnel name or UUID is required", "请指定隧道名称或 UUID", "トンネル名または UUID を指定してください"),
    ("cloudflared.not_logged_in", 400, "not signed in to Cloudflare (cert.pem missing); sign in first", "尚未登录 Cloudflare（缺少 cert.pem），请先完成登录", "Cloudflare に未ログインです（cert.pem がありません）。先にログインしてください"),
    ("cloudflared.token_fetch_failed", 400, "could not fetch the tunnel token: {error}", "无法获取隧道 token：{error}", "トンネルトークンを取得できませんでした: {error}"),
    ("cloudflared.invalid_token", 400, "invalid token (too short)", "Token 无效（过短）", "トークンが無効です（短すぎます）"),
    ("cloudflared.no_token", 400, "no tunnel token saved yet", "尚未保存 tunnel token", "トンネルトークンがまだ保存されていません"),
    ("cloudflared.invalid_name", 400, "invalid tunnel name (letters, digits, . _ - only)", "隧道名无效（仅字母数字 ._-）", "トンネル名が無効です（英数字と . _ - のみ使用できます）"),
    ("cloudflared.login_required", 400, "sign in to Cloudflare first", "请先登录 Cloudflare", "先に Cloudflare にログインしてください"),
    ("cloudflared.route_args_required", 400, "tunnel and hostname are required", "需要 tunnel 与 hostname", "tunnel と hostname が必要です"),
    # ── apps (unified app manager) ──
    ("apps.bad_id", 400, "id must be kind:source, e.g. docker:plex / native:native-redis / vm:uuid", "id 格式应为 kind:source，如 docker:plex / native:native-redis / vm:uuid", "id は kind:source 形式で指定してください（例: docker:plex / native:native-redis / vm:uuid）"),
    ("apps.cloudflared_token_required", 400, "select a tunnel or paste a token and start it once before enabling autostart", "请先选择隧道或粘贴 Token 并启动一次，再开自启", "自動起動を有効にする前に、トンネルを選択するかトークンを貼り付けて一度起動してください"),
    ("apps.autostart_unsupported", 400, "this native app does not support toggling login autostart (it may require System Settings)", "该原生应用不支持切换开机自启（或需改系统设置）", "このネイティブアプリはログイン時自動起動の切り替えに対応していません（システム設定での変更が必要な場合があります）"),
    ("apps.vm_autostart_external", 400, "configure VM autostart in UTM / OrbStack", "虚拟机自启请在 UTM / OrbStack 中设置", "VM の自動起動は UTM / OrbStack 側で設定してください"),
    ("apps.bad_autostart_kind", 400, "autostart is not supported for kind: {kind}", "不支持的 autostart kind: {kind}", "この種類では自動起動はサポートされていません: {kind}"),
    ("apps.docker_action_unsupported", 400, "unsupported docker action: {action}", "docker 不支持动作: {action}", "サポートされていない docker 操作です: {action}"),
    ("apps.native_action_unsupported", 400, "unsupported native app action: {action}", "native 不支持动作: {action}", "サポートされていないネイティブアプリ操作です: {action}"),
    # ── disk power ──
    ("disk_power.protected", 403, "system disks and non-sleepable disks cannot be slept or ejected", "系统盘或不可休眠磁盘不能休眠或推出", "システムディスクおよびスリープ不可のディスクは操作できません"),
    # ── service credentials ──
    ("credentials.bad_service_id", 400, "invalid service id", "非法服务 ID", "サービス ID が不正です"),
    ("credentials.username_required", 400, "username is required", "用户名不能为空", "ユーザー名は必須です"),
    ("credentials.password_too_short", 400, "the service password must be at least {min} characters", "服务密码至少需要 {min} 个字符", "サービスパスワードは {min} 文字以上必要です"),
    ("credentials.keychain_write_failed", 503, "could not write to the macOS Keychain: {error}", "无法写入 macOS 钥匙串：{error}", "macOS キーチェーンに書き込めませんでした: {error}"),
    ("credentials.index_save_failed", 500, "could not save the credential index: {error}", "无法保存凭据索引：{error}", "資格情報インデックスを保存できませんでした: {error}"),
    ("credentials.bad_username", 400, "usernames may only contain letters, digits and . _ @ + - and must start with a letter or digit", "用户名只能包含字母、数字与 . _ @ + -，且需以字母或数字开头", "ユーザー名に使えるのは英数字と . _ @ + - のみで、先頭は英数字である必要があります"),
    ("credentials.filebrowser_missing", 404, "File Browser is not installed or its database is missing", "未安装 File Browser 或数据库不存在", "File Browser がインストールされていないか、データベースが存在しません"),
    ("credentials.filebrowser_stop_failed", 503, "could not pause File Browser; the password was not changed", "无法暂停 File Browser，未修改密码", "File Browser を一時停止できなかったため、パスワードは変更されていません"),
    ("credentials.filebrowser_update_failed", 400, "File Browser rejected the password change: {error}", "File Browser 拒绝修改密码：{error}", "File Browser がパスワード変更を拒否しました: {error}"),
    ("credentials.teslamate_gateway_missing", 409, "the TeslaMate password gateway is not installed", "TeslaMate 密码网关尚未安装", "TeslaMate パスワードゲートウェイがインストールされていません"),
    ("credentials.htpasswd_failed", 503, "could not generate the TeslaMate password digest: {error}", "无法生成 TeslaMate 密码摘要：{error}", "TeslaMate パスワードダイジェストを生成できませんでした: {error}"),
    ("credentials.teslamate_apply_failed", 503, "the TeslaMate password was not applied and has been rolled back: {error}", "TeslaMate 密码未生效，已回滚：{error}", "TeslaMate パスワードは適用されず、ロールバックされました: {error}"),
    ("credentials.adapter_unsupported", 400, "this service does not support automated password changes; the credential can still be saved", "该插件暂不支持自动改密，可仅保存凭据", "このサービスは自動パスワード変更に対応していません。資格情報の保存のみ可能です"),
    # ── login autostart ──
    ("autostart.self_protected", 400, "{label} is ServerHub's own login task and cannot be disabled here; use the 'Start at login' switch on the Settings page instead", "{label} 是 ServerHub 面板自身的开机任务，不能从这里关闭；请使用设置页的「登录时启动」开关。", "{label} は ServerHub パネル自身のログインタスクのため、ここでは無効化できません。設定ページの「ログイン時に起動」スイッチを使用してください。"),
    ("autostart.bad_id", 400, "id must be kind:name", "id 格式: kind:name", "id は kind:name 形式で指定してください"),
    # ── power ──
    ("power.unknown_action", 400, "unknown power action: {action} (choose one of {choices})", "未知电源操作: {action}（可选 {choices}）", "不明な電源操作: {action}（選択肢: {choices}）"),
    ("power.confirm_required", 400, "power actions require confirm=true", "电源操作需要 confirm=true", "電源操作には confirm=true が必要です"),
    # ── VMs ──
    ("vms.name_required", 400, "a new name is required", "需要新名称", "新しい名前が必要です"),
    ("vms.utm_unavailable", 503, "utmctl is not available; install UTM", "utmctl 不可用，请安装 UTM", "utmctl が利用できません。UTM をインストールしてください"),
    ("vms.utm_unsupported_action", 400, "UTM does not support action: {action}", "UTM 不支持操作: {action}", "UTM は操作 {action} に対応していません"),
    ("vms.orb_unavailable", 503, "orbctl is not available", "orbctl 不可用", "orbctl が利用できません"),
    ("vms.orb_unsupported_action", 400, "OrbStack does not support action: {action}", "Orb 不支持操作: {action}", "OrbStack は操作 {action} に対応していません"),
    ("vms.distro_required", 400, "distro is required, e.g. ubuntu or ubuntu:24.04", "需要 distro，例如 ubuntu 或 ubuntu:24.04", "distro が必要です（例: ubuntu、ubuntu:24.04）"),
    ("vms.bad_distro", 400, "invalid distro", "非法 distro", "不正な distro です"),
    ("vms.bad_machine_name", 400, "invalid machine name", "非法机器名", "不正なマシン名です"),
    # ── misc ──
    ("services.docker_unavailable", 400, "the docker CLI is not available", "docker 不可用", "docker CLI が利用できません"),
    ("jobs.already_running", 409, "a maintenance task is already running; wait for it to finish", "已有维护任务在运行，请等它结束", "メンテナンスタスクが既に実行中です。完了までお待ちください"),
    # Registered by hub/catalog.py at import time; listed here for the i18n keys only.
    ("catalog.browser_session_required", 401, "sign in from a browser to manage service credentials", "请先在浏览器登录后管理服务凭据", "サービス資格情報を管理するには、ブラウザからログインしてください"),
]

# Codes owned by CODES.setdefault() in their modules — skip in errors.py.
SKIP_ERRORS_PY = {"catalog.browser_session_required"}


def merge_errors_py() -> int:
    path = ROOT / "hub" / "errors.py"
    txt = path.read_text()
    existing = set(re.findall(r'"([a-z_]+\.[a-z_0-9]+)":\s*\(', txt))
    add = [(c, s, en) for c, s, en, _, _ in NEW_CODES
           if c not in existing and c not in SKIP_ERRORS_PY]
    if not add:
        return 0
    block = ["    # ── 2026-08 backend i18n sweep ───────────────────────────────────────────"]
    for code, status, en in add:
        line = f'    "{code}": ({status}, {en!r}),'
        block.append(line)
    anchor = "\n}\n\n\ndef error_payload"
    assert anchor in txt, "errors.py anchor not found"
    txt = txt.replace(anchor, "\n" + "\n".join(block) + anchor)
    path.write_text(txt)
    return len(add)


def js_quote(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def merge_locale(path: pathlib.Path, lang_idx: int) -> int:
    """lang_idx: 2=en, 3=zh, 4=ja (tuple positions)."""
    lines = path.read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("  err: {"))
    depth = 0
    end = None
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0 and i > start:
            end = i
            break
    assert end is not None, f"unclosed err block in {path.name}"

    # Map area -> (start line, end line) within the err block (top level only).
    areas: dict[str, tuple[int, int]] = {}
    i = start + 1
    while i < end:
        m = re.match(r"^    (\w+): \{", lines[i])
        if m:
            d = 0
            j = i
            while j <= end:
                d += lines[j].count("{") - lines[j].count("}")
                if d == 0:
                    break
                j += 1
            areas[m.group(1)] = (i, j)
            i = j + 1
        else:
            i += 1

    by_area: dict[str, list[tuple[str, str]]] = {}
    for row in NEW_CODES:
        area, key = row[0].split(".", 1)
        by_area.setdefault(area, []).append((key, row[lang_idx]))

    added = 0
    # Insert bottom-up so earlier line numbers stay valid.
    for area in sorted(by_area, key=lambda a: -(areas[a][0] if a in areas else end)):
        entries = by_area[area]
        if area in areas:
            a_start, a_end = areas[area]
            body = "\n".join(lines[a_start:a_end + 1])
            new = [f"      {k}: {js_quote(v)}," for k, v in entries
                   if not re.search(rf"^\s+{re.escape(k)}:", body, re.M)]
            if new:
                lines[a_end:a_end] = new
                added += len(new)
        else:
            block = [f"    {area}: {{"]
            block += [f"      {k}: {js_quote(v)}," for k, v in entries]
            block.append("    },")
            lines[end:end] = block
            added += len(entries)
    path.write_text("\n".join(lines) + "\n")
    return added


if __name__ == "__main__":
    n = merge_errors_py()
    print(f"hub/errors.py: +{n} codes")
    for fname, idx in (("en.js", 2), ("zh-CN.js", 3), ("ja.js", 4)):
        p = ROOT / "web" / "src" / "i18n" / fname
        print(f"{fname}: +{merge_locale(p, idx)} keys")
