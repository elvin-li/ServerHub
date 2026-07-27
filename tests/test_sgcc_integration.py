"""SGCC 接入 ServerHub 的配置契约。

为什么要有这个文件: SGCC 的抓数流程会碰到手机号、13 位户号、账号密码和
Home Assistant 的长效 token。面板这一侧只允许引用"状态"和"脱敏日志",
一旦配置写错, 表现不是报错而是**静默泄漏**或**静默写生产数据** ——
两种都只能靠契约测试拦。

具体守四条:
  1. 三个任务只能指向 sgcc_native/panel_task.py, 不能直接调 fetch.py
     (直接调 fetch.py 就绕过了脱敏和 --show 保护)
  2. 联网/抓数的两个任务必须 confirm: true, 不能一点就跑
  3. 配置里不能出现密码/token/cookie/完整手机号/完整户号
  4. 日志源只能指向脱敏后的 sgcc-native.log
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.config import cfg  # noqa: E402

SGCC_ROOT = Path('/Users/a0000/Services/sgcc_native')
PANEL_TASK = SGCC_ROOT / 'panel_task.py'
EXPECTED_LOG = Path.home() / 'Library' / 'Logs' / 'sgcc-native.log'

STATUS_ID = 'sgcc-status'
CHECK_ID = 'sgcc-session-check'
DRY_RUN_ID = 'sgcc-dry-run'
ALL_IDS = (STATUS_ID, CHECK_ID, DRY_RUN_ID)

#: 会联网或会开浏览器的任务。误点一次就是一次真实登录尝试, 而 95598 对
#: 失败登录是累积计数的, 所以必须二次确认。
NETWORKED_IDS = (CHECK_ID, DRY_RUN_ID)


def _tasks() -> dict[str, dict]:
    return {t.get('id'): t for t in (cfg().get('maintenance') or [])}


def _log_sources() -> dict[str, dict]:
    return {s.get('id'): s for s in (cfg().get('log_sources') or [])}


class TestTasksArePresent(unittest.TestCase):
    def test_all_three_tasks_exist(self):
        tasks = _tasks()
        for tid in ALL_IDS:
            self.assertIn(tid, tasks, f'维护任务 {tid} 不在 services.yaml 里')

    def test_task_ids_are_unique(self):
        ids = [t.get('id') for t in (cfg().get('maintenance') or [])]
        dupes = {i for i in ids if ids.count(i) > 1}
        self.assertEqual(dupes, set(), f'任务 id 重复: {dupes}')

    def test_every_task_has_a_name_and_timeout(self):
        for tid, task in ((i, _tasks()[i]) for i in ALL_IDS):
            self.assertTrue(task.get('name'), f'{tid} 缺 name')
            self.assertGreater(int(task.get('timeout', 0)), 0, f'{tid} 缺 timeout')


class TestCommandsGoThroughTheAdapter(unittest.TestCase):
    """命令必须走 panel_task.py。

    直接写 `fetch.py --show` 也能跑, 但那样输出不过脱敏就进了 ServerHub
    的任务日志(手机号和户号都在里面), 而且少了 `--show` 的结构性保护。
    """

    def test_commands_point_at_panel_task(self):
        for tid in ALL_IDS:
            command = _tasks()[tid].get('command') or ''
            self.assertIn(str(PANEL_TASK), command, f'{tid} 没有走 panel_task.py')

    def test_commands_do_not_call_fetch_directly(self):
        for tid in ALL_IDS:
            command = _tasks()[tid].get('command') or ''
            self.assertNotIn('fetch.py', command,
                             f'{tid} 直接调用了 fetch.py, 绕过脱敏')

    def test_each_task_uses_its_own_subcommand(self):
        expected = {
            STATUS_ID: 'status',
            CHECK_ID: 'check-session',
            DRY_RUN_ID: 'dry-run',
        }
        for tid, sub in expected.items():
            command = _tasks()[tid].get('command') or ''
            self.assertTrue(command.rstrip().endswith(sub),
                            f'{tid} 的子命令不是 {sub}: {command!r}')

    def test_adapter_exists_on_disk(self):
        self.assertTrue(PANEL_TASK.is_file(),
                        f'适配器不存在: {PANEL_TASK} —— 任务会直接失败')

    def test_no_ha_write_path_in_any_command(self):
        """配置里不能出现"写 HA"的入口。

        panel_task.py 的 dry-run 内部固定带 --show; 这里防的是有人在配置里
        另加一条不带 --show 的命令, 把生产数据写进 recorder ——
        统计数据一旦导进去, 清理比写入麻烦得多。
        """
        for task in (cfg().get('maintenance') or []):
            command = task.get('command') or ''
            if 'sgcc' not in command.lower():
                continue
            self.assertNotRegex(
                command, r'fetch\.py(?!.*--show)',
                f'{task.get("id")} 可能会写 HA 生产数据',
            )


class TestDangerousTasksNeedConfirmation(unittest.TestCase):
    def test_networked_tasks_require_confirm(self):
        for tid in NETWORKED_IDS:
            self.assertTrue(_tasks()[tid].get('confirm'),
                            f'{tid} 会联网, 必须 confirm: true')

    def test_status_is_cheap_enough_to_run_without_confirm(self):
        """状态只读本地文件, 不该逼用户点确认。"""
        self.assertFalse(_tasks()[STATUS_ID].get('confirm'))


class TestLogSource(unittest.TestCase):
    def test_log_source_points_at_the_redacted_log(self):
        source = _log_sources().get('sgcc-native')
        self.assertIsNotNone(source, 'log_sources 里没有 sgcc-native')
        self.assertEqual(Path(source['path']), EXPECTED_LOG)

    def test_no_log_source_exposes_sgcc_internals(self):
        """不能把凭据文件、会话文件或浏览器 profile 挂成日志源。"""
        forbidden = ('.sgcc_cred', '.sgcc_session', '.sgcc_browser_profile')
        for sid, source in _log_sources().items():
            path = str(source.get('path') or '')
            for bad in forbidden:
                self.assertNotIn(bad, path,
                                 f'日志源 {sid} 指向了凭据文件: {bad}')


class TestNoSecretsInConfig(unittest.TestCase):
    """services.yaml 本身不能带任何 SGCC 凭据。

    这个文件会进备份、也会被面板的设置页读写, 所以哪怕权限是 600,
    也不该出现明文凭据。
    """

    def setUp(self):
        self.raw = (BASE / 'services.yaml').read_text(encoding='utf-8')
        self.sgcc_lines = [
            line for line in self.raw.splitlines()
            if 'sgcc' in line.lower() or '95598' in line
        ]

    def test_sgcc_lines_exist_at_all(self):
        """先确认真的读到了 SGCC 相关配置, 否则下面几条是空转的假绿。"""
        self.assertTrue(self.sgcc_lines, '配置里找不到 SGCC 相关行')

    def test_no_credential_keys_near_sgcc_config(self):
        bad = ('password', 'passwd', 'token', 'cookie', 'secret', 'api_key')
        for line in self.sgcc_lines:
            low = line.lower()
            for key in bad:
                self.assertNotIn(key, low, f'SGCC 配置行含凭据字段 {key}: {line!r}')

    def test_no_full_phone_number_in_sgcc_config(self):
        for line in self.sgcc_lines:
            self.assertIsNone(
                re.search(r'(?<!\d)1[3-9]\d{9}(?!\d)', line),
                f'SGCC 配置行含完整手机号: {line!r}',
            )

    def test_no_full_user_id_in_sgcc_config(self):
        for line in self.sgcc_lines:
            self.assertIsNone(
                re.search(r'(?<!\d)\d{13}(?!\d)', line),
                f'SGCC 配置行含完整户号: {line!r}',
            )


class TestSgccIsNotAResidentService(unittest.TestCase):
    """SGCC 是按需任务, 不是常驻服务。

    塞进 apps/scripts 会被状态探测按"端口通不通"判定, 而它根本不监听端口
    —— 面板会永久显示一个红色的假告警, 久了就没人看告警了。
    """

    def test_not_registered_as_an_app(self):
        for app in (cfg().get('apps') or []):
            blob = f'{app.get("id")} {app.get("name")} {app.get("process")}'.lower()
            self.assertNotIn('sgcc', blob)

    def test_not_registered_as_a_script(self):
        for script in (cfg().get('scripts') or []):
            blob = f'{script.get("id")} {script.get("name")}'.lower()
            self.assertNotIn('sgcc', blob)

    def test_no_sgcc_port_in_quick_links(self):
        for link in (cfg().get('quick_links') or []):
            blob = f'{link.get("name")} {link.get("url")}'.lower()
            self.assertNotIn('sgcc', blob)
            self.assertNotIn('95598', blob)


if __name__ == '__main__':
    unittest.main(verbosity=2)
