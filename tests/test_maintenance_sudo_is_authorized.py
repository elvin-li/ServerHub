"""Every `sudo -n` a maintenance task runs must be one the sudoers policy allows.

The maintenance tasks in services.yaml shell out through ``sudo -n``, which by
definition cannot prompt: if the policy does not cover the exact command *and its
arguments*, the task fails with "sudo: a password is required".  The rules are
argument-anchored regexes, so tightening one silently breaks any caller whose
arguments no longer match -- nothing links the two.

Tightening the policy did exactly that, twice:

  * ``smart-report`` ran ``sudo -n /opt/homebrew/bin/smartctl -a /dev/disk0``.
    Authorization moved to the root-owned copy at
    /usr/local/libexec/serverhub/smartctl (because /opt/homebrew/bin is writable
    by this account, so the binary there can be replaced).  The task ends in
    ``|| true``, so it went on reporting success while producing nothing --
    a monitoring task that had quietly stopped monitoring.
  * ``reboot`` ran ``sudo -n /sbin/shutdown -r +1 'ServerHub reboot'`` while the
    policy grants only ``-h now`` and ``-r now``.

Both were found by hand.  This test is the thing that finds the next one: it
extracts every ``sudo -n`` invocation out of the configured commands and asks the
policy parser whether it would be allowed.
"""
from __future__ import annotations

import shlex
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import sudoers_policy  # noqa: E402
from hub.config import cfg  # noqa: E402

TEMPLATE = BASE / "deploy" / "sudoers.d" / "serverhub"

#: Flags that sit between `sudo` and the command and take no value of their own.
_SUDO_FLAGS = {"-n", "-E", "-A", "-b", "-H", "-K", "-k", "-P", "-S", "-s"}


def _sudo_invocations(command: str) -> list[tuple[str, str]]:
    """(binary, argument string) for each `sudo -n ...` in a shell snippet.

    Deliberately crude: the commands are shell, not argv, so this splits on shell
    words and stops an invocation at the first operator.  A command it cannot
    parse is skipped rather than guessed at -- a false pass is better than a test
    that fails on quoting it does not understand.
    """
    try:
        words = shlex.split(command, comments=True)
    except ValueError:
        return []
    out: list[tuple[str, str]] = []
    operators = {"&&", "||", ";", "|", "(", ")", "{", "}", "then", "do", "else"}
    command_position = True
    for i, word in enumerate(words):
        at_command_start = command_position
        command_position = word in operators
        if not at_command_start:
            # `sudo` appearing among another command's arguments is not an
            # invocation.  The reboot task's own echo advises "可用 sudo killall
            # shutdown 取消", and reading that as a call reported a phantom
            # unauthorized command.
            continue
        if word != "sudo" and not word.endswith("/sudo"):
            continue
        rest = words[i + 1:]
        # Drop sudo's own flags; anything with a value we do not model ends the scan.
        while rest and rest[0].startswith("-"):
            if rest[0] in _SUDO_FLAGS:
                rest = rest[1:]
                continue
            rest = []
        if not rest:
            continue
        binary, args = rest[0], rest[1:]
        stop = {"&&", "||", ";", "|", ">", ">>", "<"}
        clean: list[str] = []
        for arg in args:
            if arg in stop:
                break
            clean.append(arg)
        out.append((binary, " ".join(clean)))
    return out


class MaintenanceSudoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = sudoers_policy.parse_template(
            TEMPLATE.read_text(encoding="utf-8"),
            state_root=str(BASE),
            user="a0000",
        )
        cls.tasks = list(cfg().get("maintenance") or [])

    def test_the_fixture_found_rules_and_tasks(self):
        # Without this, an empty parse would make every assertion below vacuous.
        self.assertGreater(len(self.rules), 20, "the sudoers template did not parse")
        self.assertGreater(len(self.tasks), 3, "no maintenance tasks configured")

    def test_the_extractor_understands_the_shapes_in_use(self):
        self.assertEqual(
            _sudo_invocations("sudo -n /sbin/shutdown -r now && echo done"),
            [("/sbin/shutdown", "-r now")],
        )
        self.assertEqual(
            _sudo_invocations("sudo -n /usr/local/libexec/serverhub/smartctl -a /dev/disk0 || true"),
            [("/usr/local/libexec/serverhub/smartctl", "-a /dev/disk0")],
        )
        self.assertEqual(_sudo_invocations("brew update && brew outdated"), [])
        # `sudo` without -n can prompt, so it is not this test's business, but it
        # still has to be extracted rather than mistaken for a bare word.
        self.assertEqual(
            _sudo_invocations("sudo /sbin/shutdown -h now"),
            [("/sbin/shutdown", "-h now")],
        )

    def test_every_maintenance_sudo_call_is_authorized(self):
        offenders = []
        checked = 0
        for task in self.tasks:
            for binary, argstr in _sudo_invocations(str(task.get("command") or "")):
                checked += 1
                if sudoers_policy.authorised(binary, argstr, self.rules) is None:
                    offenders.append(
                        f"task {task.get('id')!r}: sudo -n {binary} {argstr}"
                    )
        self.assertGreater(checked, 0, "no sudo invocations were examined")
        self.assertEqual(
            offenders,
            [],
            "these maintenance tasks call sudo -n with arguments the policy does "
            "not allow, so they fail with 'sudo: a password is required'. Either "
            "fix the command or add the rule to deploy/sudoers.d/serverhub:\n"
            + "\n".join(offenders),
        )

    def test_no_maintenance_task_hides_a_sudo_failure(self):
        """`sudo -n … || true` turns an authorization failure into a green run.

        Only flagged for commands that actually use sudo: plenty of tasks
        legitimately tolerate a failing step.
        """
        offenders = []
        for task in self.tasks:
            command = str(task.get("command") or "")
            if not _sudo_invocations(command):
                continue
            if "|| true" in command:
                offenders.append(f"task {task.get('id')!r}")
        self.assertEqual(
            offenders,
            [],
            "a sudo step whose failure is swallowed by `|| true` reports success "
            "while doing nothing; drop the `|| true` so the task shows the error:\n"
            + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
