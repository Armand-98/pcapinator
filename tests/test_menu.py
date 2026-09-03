"""Menu tests.

The menu is the first thing a person sees, and the one part of the tool that
can hang. Both properties are worth pinning.
"""

from unittest.mock import patch

import pytest

from pcapinator.cli import _menu_action, main
from pcapinator.menu import ENTRIES, banner, clean_path, run


def test_banner_box_is_square():
    lines = banner("pcapinator").split("\n")
    assert len({len(line) for line in lines}) == 1, "box edges must line up"
    assert "PCAPINATOR" in lines[1]
    assert "LyfieldCreationsOS" in lines[1]


def test_banner_adapts_to_the_title():
    for title in ("pcapi", "certinator", "a-much-longer-tool-name"):
        lines = banner(title).split("\n")
        assert len({len(line) for line in lines}) == 1


@pytest.mark.parametrize("answer", ["7", "q", "Q", ""])
def test_every_way_of_quitting(answer, capsys):
    with patch("builtins.input", side_effect=[answer]):
        assert run("pcapinator", lambda *_: None) == 0
    assert "Done. See you next time." in capsys.readouterr().out


@pytest.mark.parametrize("interrupt", [EOFError, KeyboardInterrupt])
def test_closing_the_terminal_exits_cleanly(interrupt, capsys):
    """Control-d and control-c are how people leave a menu, not crashes."""
    with patch("builtins.input", side_effect=interrupt):
        assert run("pcapinator", lambda *_: None) == 0
    assert "Done" in capsys.readouterr().out


def test_bad_input_reprompts_rather_than_exiting(capsys):
    with patch("builtins.input", side_effect=["banana", "99", "0", "q"]):
        assert run("pcapinator", lambda *_: None) == 0
    out = capsys.readouterr().out
    assert out.count("Please type a number from 1 to 7") == 3


def test_a_choice_reaches_dispatch_and_returns_to_the_menu():
    seen = []

    def dispatch(number, entry):
        seen.append((number, entry[0]))
        return None

    with patch("builtins.input", side_effect=["1", "3", "q"]):
        run("pcapinator", dispatch)
    assert seen == [(1, "Analyse"), (3, "Beacons")]


def test_menu_lines_have_no_trailing_whitespace(capsys):
    with patch("builtins.input", side_effect=["q"]):
        run("pcapinator", lambda *_: None)
    for line in capsys.readouterr().out.split("\n"):
        assert line == line.rstrip(), f"trailing space: {line!r}"


# --- the path a person actually types --------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("capture.pcap", "capture.pcap"),
    ("  capture.pcap  ", "capture.pcap"),
    ("'capture.pcap'", "capture.pcap"),
    ('"capture.pcap"', "capture.pcap"),
    ("/tmp/my\\ capture.pcap", "/tmp/my capture.pcap"),
])
def test_dragged_and_pasted_paths_are_understood(raw, expected):
    """Dragging a file into a terminal escapes its spaces; pasting one often
    brings quotes. Neither is a path, and failing on them is the tool's fault."""
    assert clean_path(raw) == expected


def test_home_is_expanded():
    assert clean_path("~/x.pcap").startswith("/")


# --- the menu must never appear where nobody can answer it ------------------

def test_no_arguments_from_a_script_errors_instead_of_prompting():
    """A prompt in a pipeline hangs forever. Fail fast instead."""
    with patch("pcapinator.cli.interactive", return_value=False):
        with pytest.raises(SystemExit) as exit_info:
            main([])
    assert exit_info.value.code == 2


def test_tutorial_returns_to_the_menu(capsys):
    assert _menu_action(6, ENTRIES[5]) is None
    assert "pcapinator reads a packet capture" in capsys.readouterr().out


def test_a_missing_capture_is_reported_not_raised(capsys):
    with patch("pcapinator.cli.ask", return_value="/nope/missing.pcap"):
        assert _menu_action(1, ENTRIES[0]) is None
    assert "no such file" in capsys.readouterr().out


def test_an_empty_answer_backs_out(capsys):
    with patch("pcapinator.cli.ask", return_value=""):
        assert _menu_action(1, ENTRIES[0]) is None


def test_analyse_from_the_menu_runs_the_pipeline(tmp_path, capsys):
    from pcapinator.synth import beacon
    path = beacon("10.0.0.5", "203.0.113.9", 443, period=60.0, count=30).write(
        tmp_path / "b.pcap")
    with patch("pcapinator.cli.ask", return_value=str(path)):
        assert _menu_action(1, ENTRIES[0]) is None
    assert "Scheduled callbacks" in capsys.readouterr().out
