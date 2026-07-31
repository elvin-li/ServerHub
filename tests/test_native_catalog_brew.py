from hub.native_catalog import _brew_shell_command, _needs_admin_retry


def test_needs_admin_retry_sudo_password():
    msg = "sudo: a password is required\nError: Failure while executing; `/usr/bin/sudo"
    assert _needs_admin_retry(msg) is True


def test_needs_admin_retry_user_cancel():
    assert _needs_admin_retry("User canceled.") is False


def test_brew_shell_command_quotes():
    cmd = ["/opt/homebrew/bin/brew", "install", "--cask", "tailscale-app"]
    line = _brew_shell_command(cmd)
    assert "HOMEBREW_NO_AUTO_UPDATE=1" in line
    assert "tailscale-app" in line
