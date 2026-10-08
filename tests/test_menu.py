"""Menu wizard tests — input() is mocked, no network, no tty needed."""


def _run_essentials(monkeypatch, answers, **kw):
    import builtins
    from core import menu
    it = iter(answers)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))
    argv = []
    params = dict(is_bulk=False, profile="QUICK", selected=set(),
                  target_desc="-t example.com")
    params.update(kw)
    menu._step_essentials(argv, **params)
    return argv


def test_essentials_defaults_save_report(monkeypatch):
    argv = _run_essentials(monkeypatch, ["n", "n", "", "", "n", "n"])
    assert "-o" in argv
    assert argv[argv.index("-o") + 1] == "reports/example.com.html"
    assert "-v" not in argv


def test_essentials_skip_report(monkeypatch):
    argv = _run_essentials(monkeypatch, ["n", "n", "", "n", "n", "n"])
    assert "-o" not in argv


def test_essentials_auth(monkeypatch):
    argv = _run_essentials(monkeypatch,
                           ["y", "session=abc", "", "boss", "s3cret", "",
                            "n", "", "", "n", "n"])
    assert "--cookie" in argv and "--login-user" in argv
    assert "s3cret" in argv  # real argv keeps it; display masks it


def test_confirm_masks_password(monkeypatch, capsys):
    import builtins
    from core import menu
    it = iter(["y"])
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))
    argv = ["-t", "x", "--login-pass", "s3cret", "--full"]
    assert menu._confirm("-t x", "FULL (deep)", argv) is True
    out = capsys.readouterr().out
    assert "s3cret" not in out and "****" in out
    assert "Xmar1881" in out


def test_banner_credit(capsys):
    from core.banner import show_banner
    show_banner("9.9.9-test")
    out = capsys.readouterr().out
    assert "Xmar1881" in out
