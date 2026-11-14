#!/usr/bin/env python3
"""Tests for lscore. Run with python3 test_lscore.py."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lscore  # noqa: E402


def R(category, weight, status, detail="", fix="", cmd="", title="t", rid="x"):
    return lscore.Result(rid, category, title, weight, status, detail, fix, cmd)


class TestParsers(unittest.TestCase):
    def test_systemd_total_with_equals(self):
        text = "Startup finished in 3.1s (kernel) + 9.2s (userspace) = 12.3s"
        self.assertAlmostEqual(lscore.parse_systemd_total(text), 12.3)

    def test_systemd_total_without_equals_sums_parts(self):
        text = "Startup finished in 1.503s (kernel) + 802ms (userspace)"
        self.assertAlmostEqual(lscore.parse_systemd_total(text), 2.305)

    def test_systemd_total_firmware_line_uses_final_total(self):
        text = ("Startup finished in 4.0s (firmware) + 1.0s (loader) "
                "+ 2.0s (kernel) + 5.0s (userspace) = 12.0s")
        self.assertAlmostEqual(lscore.parse_systemd_total(text), 12.0)

    def test_systemd_total_units(self):
        text = "Startup finished in 500ms (kernel) + 200us (userspace) + 1min (x)"
        self.assertAlmostEqual(lscore.parse_systemd_total(text), 0.5 + 0.0002 + 60)

    def test_systemd_total_missing(self):
        self.assertIsNone(lscore.parse_systemd_total("no such line"))
        self.assertIsNone(lscore.parse_systemd_total(""))
        self.assertIsNone(lscore.parse_systemd_total("Startup finished in a while"))

    def test_ss_listeners_filters_localhost_and_sorts(self):
        text = "\n".join([
            'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=6))',
            'LISTEN 0 128 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=2,fd=14))',
            'LISTEN 0 511 [::]:8080 [::]:* users:(("node",pid=3,fd=18))',
            'LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=4,fd=3))',
            'LISTEN 0 511 192.168.1.10%wlan0:22 0.0.0.0:* users:(("sshd",pid=5,fd=3))',
            'LISTEN 0 511 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=6,fd=4))',
            'too short',
        ])
        self.assertEqual(lscore.parse_ss_listeners(text),
                         [("22", "sshd"), ("443", "nginx"), ("8080", "node")])

    def test_ss_listeners_empty_and_no_process_names(self):
        self.assertEqual(lscore.parse_ss_listeners(""), [])
        out = lscore.parse_ss_listeners('LISTEN 0 128 0.0.0.0:993 0.0.0.0:*')
        self.assertEqual(out, [("993", "")])

    def test_ss_listeners_ignores_udp_and_established(self):
        text = 'UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\nESTAB 0 0 10.0.0.1:22 10.0.0.2:51234'
        self.assertEqual(lscore.parse_ss_listeners(text), [])

    def test_apt_upgradable(self):
        text = "\n".join([
            "Listing...",
            "firefox/jammy-security 129.0 amd64 [upgradable from: 128.0]",
            "foo/jammy 1.0 amd64 [upgradable from: 0.9]",
        ])
        self.assertEqual(lscore.parse_apt_upgradable(text), (2, 1))
        self.assertEqual(lscore.parse_apt_upgradable(""), (0, 0))

    def test_journal_bytes(self):
        self.assertEqual(lscore.parse_journal_bytes(
            "Archived and active journals take up 3.9G in the file system."),
            int(3.9 * lscore.GiB))
        self.assertEqual(lscore.parse_journal_bytes("take up 512K"), 512 * 1024)
        self.assertEqual(lscore.parse_journal_bytes("take up 2M"), 2 * 1024 ** 2)
        self.assertIsNone(lscore.parse_journal_bytes("nothing useful"))

    def test_sshd_config_first_value_wins(self):
        first = "PermitRootLogin yes\nPasswordAuthentication no\n"
        second = "PermitRootLogin prohibit-password\nPort 2222\n"
        cfg = lscore.parse_sshd_config([first, second])
        self.assertEqual(cfg["permitrootlogin"], "yes")
        self.assertEqual(cfg["passwordauthentication"], "no")
        self.assertEqual(cfg["port"], "2222")

    def test_sshd_config_comments_equals_and_match(self):
        cfg = lscore.parse_sshd_config([
            "# PermitRootLogin yes\n"
            "Port 2222 # inline comment\n"
            "PermitRootLogin=no\n"
            "Match User root\n"
            "  PermitRootLogin yes\n"
        ])
        self.assertEqual(cfg["port"], "2222")
        self.assertEqual(cfg["permitrootlogin"], "no")
        self.assertNotIn("match", cfg)

    def test_sshd_config_empty(self):
        self.assertEqual(lscore.parse_sshd_config([]), {})
        self.assertEqual(lscore.parse_sshd_config(["# only a comment\n"]), {})

    def test_autostart_entries(self):
        with tempfile.TemporaryDirectory() as d:
            files = {
                "always.desktop": "[Desktop Entry]\nName=Always\n",
                "hidden.desktop": "[Desktop Entry]\nHidden=true\n",
                "off.desktop": "[Desktop Entry]\nX-GNOME-Autostart-enabled=false\n",
                "explicit.desktop": "[Desktop Entry]\nX-GNOME-Autostart-enabled=true\n",
            }
            for name, body in files.items():
                with open(os.path.join(d, name), "w") as f:
                    f.write(body)
            self.assertEqual(lscore.autostart_entries(d),
                             ["always", "explicit"])


class TestScoring(unittest.TestCase):
    def test_grade_boundaries(self):
        for score, grade in ((100, "A+"), (95, "A+"), (94, "A"), (90, "A"),
                             (89, "B"), (80, "B"), (79, "C"), (70, "C"),
                             (69, "D"), (60, "D"), (59, "F"), (0, "F")):
            self.assertEqual(lscore.grade_of(score), grade, f"score {score}")

    def test_report_math_single_category(self):
        results = [R("Speed", 6, "pass"),
                   R("Speed", 4, "fail"),
                   R("Speed", 3, "skip", detail="n/a")]
        rep = lscore.build_report(results, {})
        self.assertIsNotNone(rep)
        # 6 pass, 4 fail -> Speed 60; Speed is 25% of the total.
        self.assertEqual(rep.cats["Speed"], 60)
        self.assertEqual(rep.score, 60)
        # skip must not count against the machine
        self.assertEqual(sum(1 for r in rep.results if r.status == "skip"), 1)
        failing = next(r for r in rep.results if r.status == "fail")
        self.assertAlmostEqual(failing.impact, 40.0)

    def test_report_all_skipped_returns_none(self):
        results = [R("Speed", 6, "skip"), R("Security", 7, "skip")]
        self.assertIsNone(lscore.build_report(results, {}))

    def test_report_clean_machine_scores_100(self):
        rep = lscore.build_report([R("Speed", 6, "pass"), R("Privacy", 5, "pass")], {})
        self.assertEqual(rep.score, 100)
        self.assertEqual(rep.grade, "A+")

    def test_report_never_shows_100_with_open_issues(self):
        # 99.95 rounds to 100, but open issues cap it at 99.
        results = [R("Speed", 999, "pass"), R("Speed", 1, "warn")]
        rep = lscore.build_report(results, {})
        self.assertEqual(rep.score, 99)

    def test_report_weighted_categories(self):
        base = [R("Speed", 6, "pass"), R("Security", 7, "pass"),
                R("Privacy", 5, "pass"), R("Storage", 6, "pass")]
        sec_bad = lscore.build_report(base[:1] + [R("Security", 7, "fail")] + base[2:], {})
        priv_bad = lscore.build_report(base[:2] + [R("Privacy", 5, "fail")] + base[3:], {})
        self.assertLess(sec_bad.score, priv_bad.score)

    def test_factor_table(self):
        self.assertEqual(lscore.FACTOR, {"pass": 0.0, "warn": 0.5, "fail": 1.0})


class TestRegistry(unittest.TestCase):
    def test_checks_are_well_formed(self):
        ids = [fn.__name__[2:] for _, _, _, fn in lscore.CHECKS]
        titles = [t for _, _, t, _ in lscore.CHECKS]
        self.assertEqual(len(ids), len(set(ids)), "check ids must be unique")
        self.assertEqual(len(titles), len(set(titles)), "check titles must be unique")
        for category, weight, _, _ in lscore.CHECKS:
            self.assertIn(category, lscore.CAT_WEIGHT)
            self.assertGreater(weight, 0)

    def test_category_weights(self):
        self.assertEqual(sum(lscore.CAT_WEIGHT.values()), 100)
        self.assertEqual(list(lscore.CAT_WEIGHT), lscore.CAT_ORDER)

    def test_every_registered_category_is_scored(self):
        used = {category for category, _, _, _ in lscore.CHECKS}
        self.assertEqual(used, set(lscore.CAT_ORDER),
                         "every category shown must contain checks, and vice versa")

    def test_checks_follow_naming_convention(self):
        for _, _, _, fn in lscore.CHECKS:
            self.assertTrue(fn.__name__.startswith("c_"),
                            f"{fn.__name__} must be named c_*")
            self.assertTrue(callable(fn))

    def test_status_helpers(self):
        self.assertEqual(lscore.ok("d").status, "pass")
        self.assertEqual(lscore.warn("d").status, "warn")
        self.assertEqual(lscore.bad("d").status, "fail")
        self.assertEqual(lscore.skip("r").status, "skip")
        self.assertEqual(lscore.skip().detail, "")


class TestHelpers(unittest.TestCase):
    def test_human(self):
        # divides by 1024; IEC labels (KiB/MiB/GiB) are correct.
        self.assertEqual(lscore.human(0), "0 B")
        self.assertEqual(lscore.human(512), "512 B")
        self.assertEqual(lscore.human(1024), "1.0 KiB")
        self.assertEqual(lscore.human(1536), "1.5 KiB")
        self.assertEqual(lscore.human(1024 ** 4), "1.0 TiB")
        self.assertEqual(lscore.human(5 * 1024 ** 3), "5.0 GiB")
        self.assertNotIn(" GB", lscore.human(1024 ** 3))

    def test_run_never_raises_on_missing_command(self):
        self.assertEqual(lscore.run(["/definitely/not/a/command"]), (None, ""))

    def test_run_returns_exit_code_and_output(self):
        rc, out = lscore.run([sys.executable, "-c", "print('hi')"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "hi")

    def test_run_captures_exit_code_and_drops_stderr(self):
        rc, out = lscore.run([sys.executable, "-c",
                              "import sys; sys.stderr.write('noise'); sys.exit(3)"])
        self.assertEqual((rc, out), (3, ""))

    def test_read_missing_file(self):
        self.assertEqual(lscore.read("/definitely/not/here"), "")

    def test_dir_size_and_budget(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sub"))
            with open(os.path.join(d, "sub", "f"), "wb") as f:
                f.write(b"x" * 100)
            size, done = lscore.dir_size(d, budget=10.0)
            self.assertTrue(done)
            self.assertGreater(size, 0)
            size2, done2 = lscore.dir_size(d, budget=-1)
            self.assertFalse(done2)
            self.assertEqual(size2, 0)

    def test_index_age_days(self):
        self.assertIsNone(lscore.index_age_days("/no/such/file-*"))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "list.db")
            with open(p, "w") as f:
                f.write("x")
            age = lscore.index_age_days(os.path.join(d, "*.db"))
            self.assertIsNotNone(age)
            self.assertLess(age, 1.0)

    def test_meminfo(self):
        mi = lscore.meminfo()
        if sys.platform.startswith("linux"):
            self.assertIn("MemTotal", mi)
            self.assertGreater(mi["MemTotal"], 0)

    def test_big_number_layout(self):
        rows = lscore.big_number(85)
        self.assertEqual(len(rows), 5)
        self.assertEqual(len(set(len(r) for r in rows)), 1)
        self.assertEqual(len(lscore.big_number(100)), 5)

    def test_big_number_ascii_fallback(self):
        old = lscore.UNICODE
        try:
            lscore.UNICODE = False
            self.assertNotIn("█", lscore.big_number(85)[0])
            self.assertIn("#", lscore.big_number(85)[0])
        finally:
            lscore.UNICODE = old

    def test_painter(self):
        truecolor = lscore.make_painter("true")
        basic = lscore.make_painter("16")
        off = lscore.make_painter(None)
        self.assertEqual(off("x", "foam"), "x")
        self.assertTrue(truecolor("x", "foam").startswith("\033[38;2;156;207;216m"))
        self.assertEqual(basic("x", "foam"), "\033[36mx\033[0m")
        self.assertEqual(truecolor("x", "not-a-style"), "x")


class TestOutput(unittest.TestCase):
    def _rep(self, score=85):
        results = [R("Speed", 6, "pass", detail="fine"),
                   R("Security", 5, "pass", detail="firewall up"),
                   R("Security", 7, "warn", detail="open ports", fix="close them",
                     cmd="sudo ss -ltnp", title="Open ports", rid="ports"),
                   R("Privacy", 5, "fail", detail="telemetry", fix="disable it",
                     cmd="sudo systemctl disable --now whoopsie", title="Telemetry", rid="tel"),
                   R("Storage", 3, "skip", detail="n/a")]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1.0",
                                            "arch": "x86_64", "laptop": True})
        rep.score, rep.grade = score, lscore.grade_of(score)
        return rep

    def test_render_shape(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render(self._rep(), lscore.make_painter(None), verbose=False)
        text = out.getvalue()
        self.assertIn("Linux Score", text)
        self.assertIn("out of 100", text)
        self.assertIn("Grade", text)
        self.assertIn("What to improve", text)
        self.assertIn("biggest wins first", text)
        self.assertIn("Speed", text)
        self.assertIn("Telemetry", text)
        self.assertIn("checks passed", text)
        self.assertNotIn("\033[", text)

    def test_render_orders_issues_by_impact(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render(self._rep(), lscore.make_painter(None))
        text = out.getvalue()
        self.assertLess(text.index("Telemetry"), text.index("Open ports"))
        impacts = [float(m) for m in re.findall(r"[−-](\d+\.\d+)", text)]
        self.assertEqual(impacts, sorted(impacts, reverse=True))
        self.assertEqual(len(impacts), 2)

    def test_render_skips_eight_issues_without_verbose(self):
        results = [R("Speed", 1, "warn", detail=f"issue {i}", title=f"Issue {i}",
                     rid=f"i{i}") for i in range(12)]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1",
                                            "arch": "x86_64", "laptop": False})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render(rep, lscore.make_painter(None), verbose=False)
        text = out.getvalue()
        self.assertIn("and 4 more", text)
        self.assertIn("-v to see all", text)

    def test_render_no_issues_message(self):
        results = [R("Speed", 6, "pass")]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1",
                                            "arch": "x86_64", "laptop": False})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render(rep, lscore.make_painter(None))
        self.assertIn("Nothing to improve", out.getvalue())

    def test_render_shows_disk_usage_when_the_disk_check_passes(self):
        results = [R("Storage", 6, "pass", title="Disk space", rid="disk",
                     detail="78% used (175.50 GiB of 224.02 GiB), "
                            "37.07 GiB free (16.55%)")]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1",
                                            "arch": "x86_64", "laptop": False})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render(rep, lscore.make_painter(None))
        text = out.getvalue()
        self.assertIn("Storage (health)", text)
        self.assertIn("└─ Disk        78% used · 175.50 / 224.02 GiB "
                      "(37.07 GiB free)", text)

    def test_render_shows_disk_usage_when_the_disk_needs_attention(self):
        results = [R("Storage", 6, "warn", title="Disk space", rid="disk",
                     detail="85% used (190.42 GiB of 224.02 GiB), "
                            "33.60 GiB free (15.00%)")]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1",
                                            "arch": "x86_64", "laptop": False})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render(rep, lscore.make_painter(None))
        text = out.getvalue()
        self.assertIn("└─ Disk        85% used · 190.42 / 224.02 GiB "
                      "(33.60 GiB free)", text)

    def test_disk_usage_line_is_compact_and_falls_back(self):
        self.assertEqual(
            lscore.disk_usage_line(
                "78% used (175.51 GiB of 224.02 GiB), 37.07 GiB free "
                "(16.55%), 11.45 GiB reserved on /nix"),
            "78% used · 175.51 / 224.02 GiB (37.07 GiB free)")
        self.assertEqual(lscore.disk_usage_line("unexpected detail"),
                         "unexpected detail")

    def test_badge_colors(self):
        for score, role in ((95, "foam"), (90, "foam"), (85, "foam"),
                            (84, "gold"), (70, "gold"), (69, "love"), (30, "love")):
            color = lscore.PALETTE[role].lstrip("#")
            self.assertIn(f"-{score}-{color}", lscore.badge_md(self._rep(score)),
                          f"score {score}")

    def test_fix_script_is_reviewable_and_imperative(self):
        rep = self._rep()
        script = lscore.fix_script(rep)
        self.assertTrue(script.startswith("#!/usr/bin/env bash"))
        self.assertIn("Nothing has been executed", script)
        self.assertIn("sudo systemctl disable --now whoopsie", script)
        self.assertLess(script.index("whoopsie"), script.index("sudo ss -ltnp"),
                        "bigger impact must come first")
        penalties = [float(m) for m in re.findall(r"\(-([\d.]+)\)", script)]
        self.assertEqual(penalties, sorted(penalties, reverse=True))

    def test_fix_script_skips_checks_without_a_command(self):
        results = [R("Privacy", 5, "fail", detail="advice only, no cmd",
                     title="NoCmd", rid="nocmd"),
                   R("Security", 7, "warn", detail="has a cmd", fix="do it",
                     cmd="echo hi", title="HasCmd", rid="hascmd")]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1",
                                            "arch": "x86_64", "laptop": False})
        script = lscore.fix_script(rep)
        self.assertIn("echo hi", script)
        self.assertNotIn("advice only, no cmd", script)

    def test_fix_script_when_nothing_is_fixable(self):
        results = [R("Speed", 6, "pass"), R("Storage", 3, "warn", detail="x")]
        rep = lscore.build_report(results, {"distro": "TestOS", "kernel": "1",
                                            "arch": "x86_64", "laptop": False})
        self.assertIn("Nothing here can be fixed automatically", lscore.fix_script(rep))

    def test_card_is_valid_svg_and_escapes_text(self):
        rep = self._rep()
        rep.system["distro"] = 'Evil <script>alert(1)</script> & "friends"'
        card = lscore.make_card(rep)
        root = ET.fromstring(card)
        self.assertTrue(root.tag.endswith("svg"))
        self.assertIn("85", card)
        self.assertNotIn("<script>", card)
        self.assertIn("&lt;script&gt;", card)

    def test_card_carries_no_personal_details(self):
        import socket
        card = lscore.make_card(self._rep())
        user = os.environ.get("USER", "")
        if user:
            self.assertNotIn(user, card)
        try:
            host = socket.gethostname()
        except OSError:
            host = ""
        if host and len(host) > 2:
            self.assertNotIn(host, card)
        self.assertNotIn("127.0.0.1", card)

    def test_json_roundtrip(self):
        rep = self._rep()
        data = json.loads(lscore.to_json(rep))
        self.assertEqual(data["score"], rep.score)
        self.assertEqual(data["version"], lscore.__version__)
        self.assertEqual(len(data["checks"]), len(rep.results))
        self.assertIn("categories", data)


class TestHistory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        # CI containers run as root, and lscore deliberately skips recording there.
        patcher = mock.patch("os.geteuid", return_value=1000)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _rep(self, score=85):
        return lscore.Report(score, lscore.grade_of(score), {}, [], {})

    def test_path_follows_xdg_state_home(self):
        self.assertEqual(lscore.history_path(),
                         os.path.join(self.tmp.name, "lscore", "history.jsonl"))

    def test_record_and_load_roundtrip(self):
        path = lscore.record_score(self._rep(85))
        self.assertTrue(os.path.isfile(path))
        entries = lscore.load_history()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["score"], 85)
        self.assertEqual(entries[0]["grade"], "B")
        self.assertAlmostEqual(time.time() - float(entries[0]["t"]), 0, delta=60)

    def test_load_ignores_corrupt_lines_and_sorts(self):
        path = lscore.history_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write('{"t": 300, "score": 70, "grade": "C"}\n')
            f.write("not json at all\n")
            f.write('["a", "list"]\n')
            f.write('{"t": 200, "grade": "no-score"}\n')
            f.write('{"t": 100, "score": 90, "grade": "A"}\n')
        entries = lscore.load_history()
        self.assertEqual([e["score"] for e in entries], [90, 70])

    def test_missing_history_is_empty(self):
        self.assertEqual(lscore.load_history(), [])

    def test_record_prunes_old_runs(self):
        path = lscore.history_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            for i in range(lscore.HISTORY_KEEP + 100):
                f.write(json.dumps({"t": i, "score": 50, "grade": "D"}) + "\n")
        lscore.record_score(self._rep(90))
        with open(path) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), lscore.HISTORY_KEEP)
        self.assertEqual(json.loads(lines[-1])["score"], 90)

    def test_record_never_raises_when_unwritable(self):
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": "/proc/definitely/not/writable"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assertEqual(lscore.record_score(self._rep()), "")

    def test_render_history_shows_trend_and_marks_current_run(self):
        entries = [{"t": time.time() - 86400, "score": 71, "grade": "C"},
                   {"t": time.time() - 3600, "score": 78, "grade": "C"},
                   {"t": time.time(), "score": 85, "grade": "B"}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render_history(entries, lscore.make_painter(None), recorded=True)
        text = out.getvalue()
        self.assertIn("History", text)
        for score in ("71", "78", "85"):
            self.assertIn(f" {score} ", text)
        self.assertIn("+7", text)
        self.assertIn("since", text)
        self.assertIn("<- this run", text)

    def test_render_history_without_record_marker(self):
        entries = [{"t": time.time(), "score": 71, "grade": "C"}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render_history(entries, lscore.make_painter(None), recorded=False)
        self.assertNotIn("<- this run", out.getvalue())
        self.assertIn("   -", out.getvalue())

    def test_render_history_empty(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render_history([], lscore.make_painter(None), recorded=False)
        self.assertIn("No runs recorded yet", out.getvalue())

    def test_render_history_limits_rows(self):
        entries = [{"t": time.time() - i * 60, "score": 50 + i, "grade": "D"}
                   for i in range(40, 0, -1)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render_history(entries, lscore.make_painter(None), recorded=True)
        text = out.getvalue()
        self.assertIn("showing the newest", text)
        self.assertIn("<- this run", text)


class TestRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_journal_parser_never_raises_on_junk(self):
        self.assertIsNone(lscore.parse_journal_bytes("take up ..G"))
        self.assertIsNone(lscore.parse_journal_bytes("take up ."))
        for junk in ("take up 1..5G", "take up ...", "take up 9"*10):
            lscore.parse_journal_bytes(junk)
        self.assertEqual(lscore.parse_journal_bytes("take up 2.5G"), int(2.5 * lscore.GiB))

    def test_ss_parser_rejects_ports_that_are_not_numbers(self):
        self.assertEqual(lscore.parse_ss_listeners("LISTEN 0 0 ::: 0.0.0.0:*"), [])
        self.assertEqual(lscore.parse_ss_listeners("LISTEN 0 0 * 0.0.0.0:*"), [])
        self.assertEqual(lscore.parse_ss_listeners("LISTEN 0 0 0.0.0.0:http 0.0.0.0:*"), [])
        self.assertEqual(lscore.parse_ss_listeners("LISTEN 0 0 0.0.0.0:8080 0.0.0.0:*"),
                         [("8080", "")])

    def test_apt_parser_requires_a_package_token(self):
        self.assertEqual(lscore.parse_apt_upgradable("[upgradable from:\n"), (0, 0))
        self.assertEqual(lscore.parse_apt_upgradable(
            "foo/jammy 1.0 amd64 [upgradable from: 0.9]"), (1, 0))
        self.assertEqual(lscore.parse_apt_upgradable(
            "foo/jammy-security 2.0 amd64 [upgradable from: 1.0]"), (1, 1))

    def test_memory_reports_available_not_free(self):
        titles = [t for _, _, t, _ in lscore.CHECKS]
        self.assertIn("Available memory", titles)
        with mock.patch.object(lscore, "meminfo", return_value={
                "MemTotal": 8 * lscore.GiB, "MemAvailable": 2 * lscore.GiB}):
            out = lscore.c_memory(lscore.Ctx())
        self.assertEqual(out.status, "pass")
        self.assertEqual(out.detail, "2.0 GiB available of 8.0 GiB (25%)")

    @staticmethod
    def _fake_fs(table, inodes=None):
        class Vfs:
            def __init__(self, dev, blocks, free):
                self.st_dev, self.f_frsize = dev, 4096
                self.f_blocks, self.f_bavail = blocks, free
                self.f_bfree = free                 # no root-reserved blocks in the fake
                self.f_files, self.f_ffree = inodes or (0, 0)   # 0 = inodes not reported

        def fake_statvfs(path):
            if path not in table:
                raise OSError("no such path")
            dev, blocks, free = table[path]
            return Vfs(dev, blocks, free)

        def fake_stat(path):
            if path not in table:
                raise OSError("no such path")

            class S:
                st_dev = table[path][0]
            return S()

        return fake_statvfs, fake_stat

    def test_disk_judges_the_real_disk_not_a_ramdisk_root(self):
        ctx = lscore.Ctx()
        table = {"/": (1, 1000, 1000),           # ramdisk root: looks empty
                 "/nix": (2, 100000, 5000),      # real disk: 5% free
                 ctx.home: (2, 100000, 5000)}    # same device: counted once
        fsvfs, fsstat = self._fake_fs(table)
        with mock.patch("os.statvfs", side_effect=fsvfs), \
                mock.patch("os.stat", side_effect=fsstat):
            out = lscore.c_disk(ctx)
        self.assertEqual(out.status, "fail")
        self.assertTrue(out.detail.startswith("95% used"), out.detail)
        self.assertIn("on /nix", out.detail)

    def test_disk_on_a_single_device_system_reads_like_before(self):
        ctx = lscore.Ctx()
        table = {"/": (7, 100000000, 80000000),
                 ctx.home: (7, 100000000, 80000000)}
        fsvfs, fsstat = self._fake_fs(table)
        with mock.patch("os.statvfs", side_effect=fsvfs), \
                mock.patch("os.stat", side_effect=fsstat):
            out = lscore.c_disk(ctx)
        self.assertEqual(out.status, "pass")
        expected = (f"20% used ({lscore.human2(20000000 * 4096)} of "
                    f"{lscore.human2(100000000 * 4096)}), "
                    f"{lscore.human2(80000000 * 4096)} free (80.00%)")
        self.assertEqual(out.detail, expected)

    def test_disk_without_any_readable_filesystem_skips(self):
        with mock.patch("os.statvfs", side_effect=OSError), \
                mock.patch("os.stat", side_effect=OSError):
            self.assertEqual(lscore.c_disk(lscore.Ctx()).status, "skip")

    def test_swap_usage_alone_does_not_claim_ram_is_short(self):
        mi = {"MemTotal": 8 * lscore.GiB, "MemAvailable": 5 * lscore.GiB,
              "SwapTotal": 8 * lscore.GiB, "SwapFree": 3 * lscore.GiB}
        with mock.patch.object(lscore, "meminfo", return_value=mi):
            out = lscore.c_swap(lscore.Ctx())
        self.assertEqual(out.status, "pass")
        self.assertNotIn("running short", out.detail)
        self.assertIn("idle pages in swap", out.detail)
        self.assertIn("5.0 GiB of RAM is available", out.detail)

    def test_swap_usage_with_low_available_memory_is_called_short(self):
        mi = {"MemTotal": 8 * lscore.GiB, "MemAvailable": 1 * lscore.GiB,
              "SwapTotal": 8 * lscore.GiB, "SwapFree": 3 * lscore.GiB}
        with mock.patch.object(lscore, "meminfo", return_value=mi):
            out = lscore.c_swap(lscore.Ctx())
        self.assertEqual(out.status, "warn")
        self.assertIn("RAM is running short", out.detail)
        self.assertIn("1.0 GiB available", out.detail)

    def test_no_swap_message_does_not_promise_a_freeze(self):
        mi = {"MemTotal": 4 * lscore.GiB, "MemAvailable": 1 * lscore.GiB,
              "SwapTotal": 0, "SwapFree": 0}
        with mock.patch.object(lscore, "meminfo", return_value=mi):
            out = lscore.c_swap(lscore.Ctx())
        self.assertEqual(out.status, "warn")
        self.assertNotIn("freezes", out.detail)
        self.assertIn("killed", out.detail)

    def test_telemetry_all_clear_says_found_not_running(self):
        with mock.patch.object(lscore, "units_active", return_value=[]), \
                mock.patch.object(lscore, "read", return_value=""):
            out = lscore.c_telemetry(lscore.Ctx())
        self.assertEqual(out.status, "pass")
        self.assertIn("found", out.detail)
        self.assertNotIn("running", out.detail)

    def test_dns_warning_scopes_the_claim_to_system_lookups(self):
        with mock.patch.object(lscore, "resolvectl_status", return_value="Link 1 (eth0)"), \
                mock.patch.object(lscore, "read", side_effect=lambda p: "127.0.0.53" if p == "/etc/resolv.conf" else ""), \
                mock.patch.object(lscore, "units_active", return_value=[]):
            out = lscore.c_dns(lscore.Ctx())
        self.assertEqual(out.status, "warn")
        self.assertTrue(out.detail.startswith("System DNS lookups"), out.detail)
        self.assertNotIn("every site you visit", out.detail)

    def test_dns_accepts_an_encrypted_proxy_without_systemd_resolved(self):
        with mock.patch.object(lscore, "resolvectl_status", return_value=""), \
                mock.patch.object(lscore, "units_active", return_value=["dnscrypt-proxy"]):
            out = lscore.c_dns(lscore.Ctx())
        self.assertEqual(out.status, "pass")
        self.assertIn("encrypted DNS proxy", out.detail)

    def test_trim_ignores_removable_flash_drives(self):
        def fake_read(path):
            if path.endswith("/queue/rotational"):
                return "0" if "sdb" in path else "1"     # sdb = USB stick
            if path.endswith("/removable"):
                return "1" if "sdb" in path else "0"
            if path == "/proc/mounts":
                return "/dev/sda1 / ext4 rw 0 0\n"
            return ""

        with mock.patch.object(lscore.glob, "glob",
                               side_effect=lambda p: ["/sys/block/sda", "/sys/block/sdb"]
                               if p == "/sys/block/*" else []), \
                mock.patch.object(lscore, "read", side_effect=fake_read):
            out = lscore.c_trim(lscore.Ctx())
        self.assertEqual(out.status, "skip")
        self.assertEqual(out.detail, "no SSD detected")

    def test_trim_with_no_timer_unit_skips_instead_of_claiming_trim_is_off(self):
        def fake_read(path):
            if path.endswith("/queue/rotational"):
                return "0"
            if path.endswith("/removable"):
                return "0"
            if path == "/proc/mounts":
                return "/dev/nvme0n1p2 / ext4 rw 0 0\n"
            return ""

        with mock.patch.object(lscore.glob, "glob",
                               side_effect=lambda p: ["/sys/block/nvme0n1"]
                               if p == "/sys/block/*" else []), \
                mock.patch.object(lscore, "read", side_effect=fake_read), \
                mock.patch.object(lscore, "run",
                                  return_value=(4, "not-found")):
            out = lscore.c_trim(lscore.Ctx())
        self.assertEqual(out.status, "skip")
        self.assertIn("not installed", out.detail)
        self.assertNotIn("enable", out.cmd)

    def test_trim_masked_timer_gets_unmask_advice(self):
        def fake_read(path):
            if path.endswith("/queue/rotational"):
                return "0"
            if path.endswith("/removable"):
                return "0"
            if path == "/proc/mounts":
                return "/dev/nvme0n1p2 / ext4 rw 0 0\n"
            return ""

        with mock.patch.object(lscore.glob, "glob",
                               side_effect=lambda p: ["/sys/block/nvme0n1"]
                               if p == "/sys/block/*" else []), \
                mock.patch.object(lscore, "read", side_effect=fake_read), \
                mock.patch.object(lscore, "run", return_value=(1, "masked")):
            out = lscore.c_trim(lscore.Ctx())
        self.assertEqual(out.status, "warn")
        self.assertIn("unmask", out.cmd)

    def test_pacman_without_sync_database_is_skipped_not_trusted(self):
        ctx = lscore.Ctx()
        ctx.nixos = False
        ctx.pm = "pacman"
        with mock.patch.object(lscore, "index_age_days", return_value=None):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("package list is empty", out.detail)

    def test_dnf_stale_package_list_is_distrusted(self):
        ctx = lscore.Ctx()
        ctx.nixos = False
        ctx.pm = "dnf"
        with mock.patch.object(lscore, "index_age_days", return_value=30.0), \
                mock.patch.object(lscore, "run", return_value=(0, "")):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("30 days old", out.detail)

    def test_dnf_unparseable_update_list_is_skipped(self):
        ctx = lscore.Ctx()
        ctx.nixos = False
        ctx.pm = "dnf"
        with mock.patch.object(lscore, "index_age_days", return_value=1.0), \
                mock.patch.object(lscore, "run", return_value=(100, "totally unexpected format")):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("couldn't parse", out.detail)

    def test_dnf_parseable_update_list_still_reports(self):
        ctx = lscore.Ctx()
        ctx.nixos = False
        ctx.pm = "dnf"
        with mock.patch.object(lscore, "index_age_days", return_value=1.0), \
                mock.patch.object(lscore, "run", return_value=(
                    100, "foo.x86_64 1.0-1.fc41 updates\nbar.x86_64 2.0-1.fc41 updates")):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("2 update(s) waiting", out.detail)

    def test_history_rejects_impossible_scores_and_times(self):
        path = lscore.history_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write('{"t": 100, "score": 150, "grade": "A+"}\n')
            f.write('{"t": 100, "score": -5, "grade": "F"}\n')
            f.write('{"t": 100, "score": true, "grade": "A"}\n')
            f.write('{"t": 1e18, "score": 80, "grade": "B"}\n')
            f.write('{"t": -1, "score": 80, "grade": "B"}\n')
            f.write('{"t": null, "score": 80, "grade": "B"}\n')
            f.write('{"t": 200, "score": 80, "grade": "B"}\n')
        entries = lscore.load_history()
        self.assertEqual([e["score"] for e in entries], [80])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            lscore.render_history(entries, lscore.make_painter(None), recorded=True)
        self.assertIn("<- this run", out.getvalue())

    def test_history_accepts_normal_entries(self):
        path = lscore.history_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write('{"t": 100, "score": 0, "grade": "F"}\n')
            f.write('{"t": 200, "score": 100, "grade": "A+"}\n')
        self.assertEqual([e["score"] for e in lscore.load_history()], [0, 100])

    def test_dir_size_counts_directory_blocks_and_dedupes_hardlinks(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "sub")
            os.makedirs(sub)
            p = os.path.join(sub, "blob")
            with open(p, "wb") as f:
                f.write(b"x" * (1024 * 1024))
            one_link = lscore.dir_size(d, budget=10)[0]
            os.link(p, os.path.join(sub, "blob2"))
            two_links = lscore.dir_size(d, budget=10)[0]
            self.assertGreaterEqual(one_link, 1024 * 1024)
            self.assertEqual(two_links, one_link)
            if shutil.which("du"):
                du = subprocess.run(["du", "-s", "--block-size=1", d],
                                    capture_output=True, text=True, timeout=30)
                if du.returncode == 0 and du.stdout.split():
                    self.assertEqual(int(du.stdout.split()[0]), two_links)

    def test_sshkeys_without_private_keys_is_skipped(self):
        home = os.path.join(self.tmp.name, "home")
        ssh = os.path.join(home, ".ssh")
        os.makedirs(ssh, mode=0o700)
        with open(os.path.join(ssh, "known_hosts"), "w") as f:
            f.write("example.com ssh-ed25519 AAAA\n")
        out = lscore.c_sshkeys(mock.Mock(home=home))
        self.assertEqual(out.status, "skip")
        self.assertIn("no private", out.detail)

    def test_sshkeys_private_key_permissions_are_judged(self):
        home = os.path.join(self.tmp.name, "home2")
        ssh = os.path.join(home, ".ssh")
        os.makedirs(ssh, mode=0o700)
        key = os.path.join(ssh, "id_ed25519")
        with open(key, "w") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        os.chmod(key, 0o600)
        self.assertEqual(lscore.c_sshkeys(mock.Mock(home=home)).status, "pass")
        os.chmod(key, 0o644)
        out = lscore.c_sshkeys(mock.Mock(home=home))
        self.assertEqual(out.status, "fail")
        self.assertIn("id_ed25519", out.detail)

    def test_autostart_all_clear_is_scoped_to_the_autostart_folder(self):
        with mock.patch.object(lscore, "autostart_entries", return_value=[]):
            out = lscore.c_autostart(mock.Mock(home=self.tmp.name))
        self.assertEqual(out.status, "pass")
        self.assertIn("~/.config/autostart", out.detail)
        self.assertNotIn("0 app(s)", out.detail)

    def test_encryption_inspects_the_disk_holding_home_not_a_tmpfs_root(self):
        ctx = mock.Mock(laptop=True, home="/home/someone")

        def fake_run(cmd, *a, **k):
            if cmd[0] == "findmnt":
                return (0, "/dev/sda2[/home]" if cmd[-1] == ctx.home else "tmpfs")
            return (0, "crypt\npart\n")

        with mock.patch.object(lscore.os.path, "exists", return_value=True), \
                mock.patch.object(lscore, "run", side_effect=fake_run):
            out = lscore.c_encryption(ctx)
        self.assertEqual(out.status, "pass")
        self.assertIn("your home folder", out.detail)
        self.assertIn("encrypted", out.detail)

    def test_encryption_skips_when_no_block_device_holds_data(self):
        ctx = mock.Mock(laptop=True, home="/home/someone")
        with mock.patch.object(lscore.os.path, "exists", return_value=True), \
                mock.patch.object(lscore, "run", return_value=(0, "tmpfs")):
            out = lscore.c_encryption(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("no block device", out.detail)

    def test_ssh_on_a_nonstandard_port_is_still_detected(self):
        ctx = mock.Mock(systemd=False)
        listener = ('LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* '
                    'users:(("sshd",pid=1,fd=3))')
        with mock.patch.object(lscore, "ss_output", return_value=listener), \
                mock.patch.object(lscore, "running_processes", return_value=("sshd",)), \
                mock.patch.object(lscore, "read",
                                  return_value="PermitRootLogin no\nPasswordAuthentication no\n"
                                               "UsePAM no\n"), \
                mock.patch.object(lscore.glob, "glob", return_value=["/etc/ssh/sshd_config"]):
            out = lscore.c_ssh(ctx)
        self.assertEqual(out.status, "pass")

    def test_nixos_generation_count_does_not_call_the_current_one_old(self):
        gens = [(i, time.time()) for i in range(1, 13)]
        with mock.patch.object(lscore, "nixos_generations", return_value=gens):
            out = lscore.nixos_generations_check()
        self.assertEqual(out.status, "warn")
        self.assertIn("11 old system generation(s)", out.detail)
        self.assertNotIn("12 old", out.detail)

    def test_broadcast_all_clear_names_what_was_checked(self):
        with mock.patch.object(lscore, "units_active", return_value=[]), \
                mock.patch.object(lscore, "resolvectl_status",
                                  return_value="Protocols: -LLMNR -mDNS"), \
                mock.patch.object(lscore, "ss_udp_output", return_value=""):
            out = lscore.c_broadcast(mock.Mock(systemd=True))
        self.assertEqual(out.status, "pass")
        self.assertIn("mDNS", out.detail)
        self.assertIn("LLMNR", out.detail)

    def test_index_age_days_accepts_several_patterns(self):
        self.assertIsNone(lscore.index_age_days("/nope/*.a", "/nope/*.b"))
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "repo.xml"), "w") as f:
                f.write("x")
            self.assertIsNotNone(lscore.index_age_days(os.path.join(d, "*.a"),
                                                       os.path.join(d, "*.xml")))


class TestTrustFixes(unittest.TestCase):
    # firewall: an active nftables.service proves nothing by itself
    @staticmethod
    def _units(*active):
        def fake(ctx, names):
            return [n for n in names if n in active]
        return fake

    def test_nftables_unit_without_root_is_skipped_not_passed(self):
        ctx = mock.Mock(is_root=False, systemd=True, nixos=False, pm=None)
        with mock.patch.object(lscore, "units_active", side_effect=self._units("nftables")):
            out = lscore.c_firewall(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("nftables", out.detail)
        self.assertIn("run as root", out.detail)

    def test_nftables_with_a_drop_rule_passes_as_root(self):
        ctx = mock.Mock(is_root=True, systemd=True, nixos=False, pm=None)
        ruleset = ("table inet filter {\n"
                   "  chain input {\n"
                   "    type filter hook input priority filter; policy drop;\n"
                   "  }\n"
                   "}\n")
        with mock.patch.object(lscore, "units_active", side_effect=self._units("nftables")), \
                mock.patch.object(lscore, "run", return_value=(0, ruleset)):
            out = lscore.c_firewall(ctx)
        self.assertEqual(out.status, "pass")
        self.assertIn("filter incoming traffic", out.detail)

    def test_container_forward_rules_are_not_a_host_firewall(self):
        # Docker/Podman DROP rules live in FORWARD and say nothing about input.
        docker = ("table ip nat {\n"
                  "  chain DOCKER {\n"
                  "    ip daddr 172.17.0.2 tcp dport 80 dnat to 172.17.0.2:80\n"
                  "  }\n"
                  "}\n"
                  "table ip filter {\n"
                  "  chain FORWARD {\n"
                  "    type filter hook forward priority filter; policy drop;\n"
                  "  }\n"
                  "}\n")
        self.assertFalse(lscore.nft_input_filtered(docker))
        ctx = mock.Mock(is_root=True, systemd=True, nixos=False, pm="apt-get")
        with mock.patch.object(lscore, "units_active", side_effect=self._units("nftables")), \
                mock.patch.object(lscore, "run", return_value=(0, docker)):
            out = lscore.c_firewall(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("no drop/reject rule", out.detail)

    def test_iptables_input_policy_drop_passes(self):
        self.assertTrue(lscore.iptables_input_filtered("-P INPUT DROP\n-P FORWARD ACCEPT"))
        self.assertTrue(lscore.iptables_input_filtered(
            "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP"))
        # FORWARD/OUTPUT rules say nothing about incoming traffic
        self.assertFalse(lscore.iptables_input_filtered(
            "-P INPUT ACCEPT\n-P FORWARD DROP\n-A OUTPUT -j DROP"))

    def test_active_nftables_without_rules_warns_as_root(self):
        ctx = mock.Mock(is_root=True, systemd=True, nixos=False, pm="pacman")
        with mock.patch.object(lscore, "units_active", side_effect=self._units("nftables")), \
                mock.patch.object(lscore, "run", return_value=(0, "")):
            out = lscore.c_firewall(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("no drop/reject rule", out.detail)

    def test_ufw_and_nixos_firewall_units_are_trusted(self):
        for unit in ("ufw", "firewalld", "firewall"):
            ctx = mock.Mock(is_root=False, systemd=True, nixos=False, pm=None)
            with mock.patch.object(lscore, "units_active", side_effect=self._units(unit)):
                out = lscore.c_firewall(ctx)
            self.assertEqual(out.status, "pass", unit)
            self.assertIn(unit, out.detail)

    # network announcements: UDP sockets and systemd-resolved
    def test_parse_udp_announcements_maps_and_filters(self):
        text = "\n".join([
            'UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=1,fd=12))',
            'UNCONN 0 0 127.0.0.1:1900 0.0.0.0:* users:(("miniupnpd",pid=2,fd=3))',
            'UNCONN 0 0 [::]:3702 [::]:* users:(("wsdd",pid=3,fd=4))',
            'UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("dhclient",pid=4,fd=5))',
            'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*',
        ])
        self.assertEqual(lscore.parse_udp_announcements(text),
                         [("mDNS", "avahi-daemon"), ("WS-Discovery", "wsdd")])

    def test_broadcast_sees_ssdp_through_its_udp_socket(self):
        ssdp = 'UNCONN 0 0 0.0.0.0:1900 0.0.0.0:* users:(("miniupnpd",pid=2,fd=3))'
        with mock.patch.object(lscore, "units_active", return_value=[]), \
                mock.patch.object(lscore, "resolvectl_status", return_value=""), \
                mock.patch.object(lscore, "ss_udp_output", return_value=ssdp):
            out = lscore.c_broadcast(mock.Mock(systemd=True))
        self.assertEqual(out.status, "warn")
        self.assertIn("SSDP", out.detail)
        self.assertIn("miniupnpd", out.cmd)

    def test_broadcast_sees_mdns_through_systemd_resolved(self):
        with mock.patch.object(lscore, "units_active", return_value=[]), \
                mock.patch.object(lscore, "resolvectl_status",
                                  return_value="Protocols: +mDNS -LLMNR"), \
                mock.patch.object(lscore, "ss_udp_output", return_value=""):
            out = lscore.c_broadcast(mock.Mock(systemd=True))
        self.assertEqual(out.status, "warn")
        self.assertIn("mDNS", out.detail)
        self.assertIn("systemd-resolved", out.detail)

    def test_broadcast_notices_an_avahi_socket_without_the_service(self):
        with mock.patch.object(lscore, "units_active",
                               side_effect=self._units("avahi-daemon.socket")), \
                mock.patch.object(lscore, "resolvectl_status", return_value=""), \
                mock.patch.object(lscore, "ss_udp_output", return_value=""):
            out = lscore.c_broadcast(mock.Mock(systemd=True))
        self.assertEqual(out.status, "warn")
        self.assertIn("Avahi", out.detail)

    def test_broadcast_still_inspects_udp_without_systemd(self):
        # OpenRC/runit systems have no systemd units, but the sockets are still real
        mdns = ('UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* '
                'users:(("avahi-daemon",pid=1,fd=2))')
        with mock.patch.object(lscore, "units_active", return_value=[]), \
                mock.patch.object(lscore, "resolvectl_status", return_value=""), \
                mock.patch.object(lscore, "ss_udp_output", return_value=mdns):
            out = lscore.c_broadcast(mock.Mock(systemd=False))
        self.assertEqual(out.status, "warn")
        self.assertIn("mDNS", out.detail)

    # SSH: PasswordAuthentication alone is not the whole story
    def test_ssh_pam_keyboard_interactive_still_allows_passwords(self):
        cfg = {"passwordauthentication": "no"}          # UsePAM and kbd-int default to yes
        self.assertTrue(lscore.password_login_possible(cfg))

    def test_ssh_keyboard_interactive_off_closes_pam_passwords(self):
        cfg = {"passwordauthentication": "no", "usepam": "yes",
               "kbdinteractiveauthentication": "no"}
        self.assertFalse(lscore.password_login_possible(cfg))

    def test_ssh_challengeresponse_alias_is_understood(self):
        cfg = {"passwordauthentication": "no", "challengeresponseauthentication": "no"}
        self.assertFalse(lscore.password_login_possible(cfg))

    def test_ssh_authenticationmethods_publickey_only_passes(self):
        cfg = {"passwordauthentication": "no",
               "authenticationmethods": "publickey"}
        self.assertFalse(lscore.password_login_possible(cfg))
        cfg["authenticationmethods"] = "publickey,keyboard-interactive"
        self.assertTrue(lscore.password_login_possible(cfg))

    def test_sshd_config_include_is_followed(self):
        with tempfile.TemporaryDirectory() as d:
            extra = os.path.join(d, "my-own.conf")
            with open(extra, "w") as f:
                f.write("PermitRootLogin yes\n")
            main = os.path.join(d, "sshd_config")
            with open(main, "w") as f:
                f.write(f"Include {extra}\nPasswordAuthentication no\n")
            cfg = lscore.parse_sshd_config(lscore.sshd_config_texts(main))
        self.assertEqual(cfg["permitrootlogin"], "yes")

    # disk encryption: say LUKS when LUKS is what was checked
    def test_encryption_without_luks_says_so_precisely(self):
        ctx = mock.Mock(laptop=True, home="/home/someone")

        def fake_run(cmd, *a, **k):
            if cmd[0] == "findmnt":
                return (0, "/dev/sda2[/home]" if cmd[-1] == ctx.home else "tmpfs")
            return (0, "part\n")

        with mock.patch.object(lscore.os.path, "exists", return_value=True), \
                mock.patch.object(lscore, "run", side_effect=fake_run):
            out = lscore.c_encryption(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("LUKS", out.detail)
        self.assertIn("unencrypted parts", out.detail)
        self.assertIn("fscrypt", out.fix)

    # open ports: the check is TCP, so say TCP
    def test_ports_detail_says_tcp(self):
        listener = ('LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* '
                    'users:(("python3",pid=1,fd=3))')
        with mock.patch.object(lscore, "ss_output", return_value=listener):
            out = lscore.c_ports(mock.Mock())
        self.assertEqual(out.status, "warn")
        self.assertIn("TCP port", out.detail)

    def test_ports_ignore_ipv4_mapped_loopback(self):
        listener = ('LISTEN 0 128 [::ffff:127.0.0.1]:8080 [::]:* '
                    'users:(("python3",pid=1,fd=3))')
        with mock.patch.object(lscore, "ss_output", return_value=listener):
            out = lscore.c_ports(mock.Mock())
        self.assertEqual(out.status, "pass")
        self.assertIn("No TCP ports", out.detail)

    # disk: df-compatible percentage, inodes, /boot and /var
    @staticmethod
    def _fake_fs(table, inodes=None):
        class Vfs:
            def __init__(self, dev, blocks, bfree, bavail, flag=0):
                self.st_dev, self.f_frsize = dev, 4096
                self.f_blocks, self.f_bfree, self.f_bavail = blocks, bfree, bavail
                self.f_files, self.f_ffree = inodes or (0, 0)
                self.f_bsize, self.f_flag = 4096, flag

        def fake_statvfs(path):
            if path not in table:
                raise OSError("no such path")
            return Vfs(*table[path])

        def fake_stat(path):
            if path not in table:
                raise OSError("no such path")

            class S:
                st_dev = table[path][0]
            return S()

        return fake_statvfs, fake_stat

    def _disk(self, table, inodes=None, home="/home/someone"):
        fsvfs, fsstat = self._fake_fs(table, inodes)
        with mock.patch("os.statvfs", side_effect=fsvfs), \
                mock.patch("os.stat", side_effect=fsstat):
            return lscore.c_disk(mock.Mock(home=home))

    def _disk_with_mounts(self, table, mounts, inodes=None, home="/home/someone"):
        fsvfs, fsstat = self._fake_fs(table, inodes)
        rows = []
        for item in mounts:
            options = item[2] if len(item) > 2 else "rw"
            rows.append(f"/dev/x {item[0]} {item[1]} {options} 0 0")
        text = "\n".join(rows)

        def fake_read(path):
            return text if path == "/proc/self/mounts" else ""

        with mock.patch("os.statvfs", side_effect=fsvfs), \
                mock.patch("os.stat", side_effect=fsstat), \
                mock.patch.object(lscore, "read", side_effect=fake_read):
            return lscore.c_disk(mock.Mock(home=home))

    def test_parse_mounts_decodes_escaped_mountpoints(self):
        text = (r"/dev/sda1 /mnt/my\040disk ext4 rw,relatime 0 0" "\n"
                "tmpfs /tmp tmpfs rw 0 0")
        self.assertEqual(lscore.parse_mounts(text), [
            ("/mnt/my disk", "ext4", "rw,relatime"),
            ("/tmp", "tmpfs", "rw"),
        ])

    def test_disk_checks_a_full_efi_partition(self):
        table = {"/": (1, 100000, 80000, 80000),
                 "/boot/efi": (2, 1000, 100, 50)}
        out = self._disk_with_mounts(
            table, [("/", "ext4"), ("/boot/efi", "vfat")])
        self.assertEqual(out.status, "fail")
        self.assertIn("on /boot/efi", out.detail)

    def test_disk_checks_a_separate_data_mount(self):
        table = {"/": (1, 100000, 80000, 80000),
                 "/data": (2, 100000, 10000, 5000)}
        out = self._disk_with_mounts(
            table, [("/", "ext4"), ("/data", "ext4")])
        self.assertEqual(out.status, "fail")
        self.assertIn("on /data", out.detail)

    def test_disk_ignores_read_only_filesystems(self):
        table = {"/": (1, 100000, 80000, 80000, 1),
                 "/data": (2, 100000, 10000, 5000)}
        out = self._disk_with_mounts(
            table, [("/", "ext4", "ro"), ("/data", "ext4")])
        self.assertEqual(out.status, "fail")
        self.assertIn("on /data", out.detail)

    def test_disk_skips_when_only_read_only_filesystems_exist(self):
        table = {"/": (1, 100000, 0, 0, 1)}
        out = self._disk_with_mounts(table, [("/", "ext4", "ro")])
        self.assertEqual(out.status, "skip")

    def test_disk_ignores_network_and_non_root_tmpfs(self):
        table = {"/": (1, 100000, 80000, 80000)}
        out = self._disk_with_mounts(
            table, [("/", "ext4"), ("/mnt/nas", "nfs4"), ("/run", "tmpfs")])
        self.assertEqual(out.status, "pass")
        self.assertTrue(out.detail.startswith("20% used"), out.detail)

    def test_disk_ignores_a_full_removable_stick(self):
        table = {"/": (1, 100000, 80000, 80000),
                 "/media/usb": (2, 1000, 10, 10)}
        with mock.patch.object(lscore, "_is_removable",
                               side_effect=lambda dev: dev == 2):
            out = self._disk_with_mounts(
                table, [("/", "ext4"), ("/media/usb", "vfat")])
        self.assertEqual(out.status, "pass")

    def test_disk_falls_back_to_block_size_when_frsize_is_zero(self):
        class Vfs:
            f_blocks, f_bfree, f_bavail = 1000, 300, 200
            f_frsize, f_bsize = 0, 4096
            f_files = f_ffree = f_flag = 0

        with mock.patch("os.statvfs", return_value=Vfs()), \
                mock.patch("os.stat", return_value=mock.Mock(st_dev=1)), \
                mock.patch.object(lscore, "read", return_value=""):
            out = lscore.c_disk(mock.Mock(home="/home/someone"))
        self.assertTrue(out.detail.startswith("70% used"), out.detail)
        self.assertIn("2.73 MiB of 3.91 MiB), 800.00 KiB free (20.00%), "
                      "400.00 KiB reserved", out.detail)

    def test_disk_hides_the_home_path_in_detail_and_fix(self):
        table = {"/home/someone": (1, 1000, 100, 50)}
        out = self._disk_with_mounts(
            table, [("/home/someone", "ext4")], home="/home/someone")
        self.assertEqual(out.status, "fail")
        self.assertIn("on ~", out.detail)
        self.assertIn("$HOME", out.fix)
        self.assertNotIn("someone", out.detail + out.fix)

    def test_disk_percentage_uses_total_capacity_and_shows_reserved(self):
        # Match fastfetch: used / total. Reserved blocks are shown separately
        # so used + free + reserved still adds up to the total.
        out = self._disk({"/": (1, 1000, 300, 200)})
        self.assertTrue(out.detail.startswith("70% used"), out.detail)
        self.assertIn("2.73 MiB of 3.91 MiB), 800.00 KiB free (20.00%), "
                      "400.00 KiB reserved", out.detail)

    def test_disk_passes_at_the_fifteen_percent_safety_margin(self):
        out = self._disk({"/": (1, 1000, 150, 150)})
        self.assertEqual(out.status, "pass")
        self.assertIn("15.00%", out.detail)

    def test_disk_warns_below_the_fifteen_percent_safety_margin(self):
        out = self._disk({"/": (1, 1000, 149, 149)})
        self.assertEqual(out.status, "warn")
        self.assertIn("14.90%", out.detail)

    def test_disk_fails_below_ten_percent_free(self):
        out = self._disk({"/": (1, 1000, 99, 99)})
        self.assertEqual(out.status, "fail")
        self.assertIn("9.90%", out.detail)

    def test_disk_reports_inode_exhaustion(self):
        out = self._disk({"/": (1, 100000, 80000, 80000)}, inodes=(1000, 2))
        self.assertEqual(out.status, "fail")
        self.assertIn("inodes", out.detail)

    def test_disk_judges_boot_when_it_is_the_tightest(self):
        table = {"/": (1, 100000, 80000, 80000),
                 "/boot": (2, 1000, 30, 30)}
        out = self._disk(table)
        self.assertEqual(out.status, "fail")
        self.assertIn("on /boot", out.detail)

    def test_trash_reports_a_timed_out_scan_as_a_lower_bound(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Trash"))
            ctx = mock.Mock(data_home=d)
            with mock.patch.object(lscore, "dir_size",
                                   return_value=(2 * lscore.GiB, False)):
                out = lscore.c_trash(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("at least 2.0 GiB", out.detail)

    def test_journal_falls_back_to_disk_when_journalctl_reports_zero(self):
        ctx = mock.Mock(systemd=True)
        zero = "Archived and active journals take up 0B in the file system."
        with mock.patch.object(lscore.shutil, "which",
                               return_value="/usr/bin/journalctl"), \
                mock.patch.object(lscore, "run", return_value=(0, zero)), \
                mock.patch.object(lscore.os.path, "isdir",
                                   side_effect=lambda p: p == "/var/log/journal"), \
                mock.patch.object(lscore, "dir_size",
                                   return_value=(5 * lscore.GiB, True)):
            out = lscore.c_journal(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("Journal logs use 5.0 GiB", out.detail)

    def test_journal_fallback_marks_a_timed_out_scan_as_a_lower_bound(self):
        ctx = mock.Mock(systemd=True)
        zero = "Archived and active journals take up 0B in the file system."
        with mock.patch.object(lscore.shutil, "which",
                               return_value="/usr/bin/journalctl"), \
                mock.patch.object(lscore, "run", return_value=(0, zero)), \
                mock.patch.object(lscore.os.path, "isdir",
                                   side_effect=lambda p: p == "/var/log/journal"), \
                mock.patch.object(lscore, "dir_size",
                                   return_value=(5 * lscore.GiB, False)):
            out = lscore.c_journal(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("at least 5.0 GiB", out.detail)

    def test_journal_trusts_journalctl_when_it_reports_a_size(self):
        ctx = mock.Mock(systemd=True)
        real = "Archived and active journals take up 2.5G in the file system."
        with mock.patch.object(lscore.shutil, "which",
                               return_value="/usr/bin/journalctl"), \
                mock.patch.object(lscore, "run", return_value=(0, real)), \
                mock.patch.object(lscore, "dir_size",
                                   side_effect=AssertionError("must not fall back")):
            out = lscore.c_journal(ctx)
        self.assertEqual(out.status, "pass")
        self.assertIn("Journal logs use 2.5 GiB", out.detail)

    def test_journal_accepts_the_systemd_default_four_gib_cap(self):
        ctx = mock.Mock(systemd=True)
        real = "Archived and active journals take up 4G in the file system."
        with mock.patch.object(lscore.shutil, "which",
                               return_value="/usr/bin/journalctl"), \
                mock.patch.object(lscore, "run", return_value=(0, real)):
            out = lscore.c_journal(ctx)
        self.assertEqual(out.status, "pass")
        self.assertIn("4.0 GiB", out.detail)

    def test_journal_warns_above_the_default_cap_and_fails_above_ten_gib(self):
        ctx = mock.Mock(systemd=True)
        with mock.patch.object(lscore.shutil, "which",
                               return_value="/usr/bin/journalctl"), \
                mock.patch.object(lscore, "run",
                                   return_value=(0, "journals take up 5G")), \
                mock.patch.object(lscore, "dir_size",
                                   side_effect=AssertionError("must not fall back")):
            self.assertEqual(lscore.c_journal(ctx).status, "warn")
        with mock.patch.object(lscore.shutil, "which",
                               return_value="/usr/bin/journalctl"), \
                mock.patch.object(lscore, "run",
                                   return_value=(0, "journals take up 11G")), \
                mock.patch.object(lscore, "dir_size",
                                   side_effect=AssertionError("must not fall back")):
            self.assertEqual(lscore.c_journal(ctx).status, "fail")

    def test_battery_advice_respects_an_active_charge_limit(self):
        with mock.patch.object(lscore, "battery_health",
                               return_value=(71.0, "655")), \
                mock.patch.object(lscore, "battery_charge_limit",
                                   return_value=70):
            out = lscore.c_battery(mock.Mock(laptop=True))
        self.assertEqual(out.status, "warn")
        self.assertIn("charging capped at 70%", out.detail)
        self.assertIn("already capped at 70%", out.fix)
        self.assertNotIn("Cap charging at 80%", out.fix)

    def test_battery_advice_offers_a_limit_when_none_is_active(self):
        with mock.patch.object(lscore, "battery_health",
                               return_value=(71.0, "655")), \
                mock.patch.object(lscore, "battery_charge_limit",
                                   return_value=None):
            out = lscore.c_battery(mock.Mock(laptop=True))
        self.assertEqual(out.status, "warn")
        self.assertIn("Cap charging at 80%", out.fix)
        self.assertNotIn("already capped", out.fix)

    def test_cpu_temp_accepts_normal_laptop_load_temperatures(self):
        with mock.patch.object(lscore, "cpu_temp_c", return_value=90.0):
            out = lscore.c_temp(mock.Mock())
        self.assertEqual(out.status, "pass")
        self.assertIn("90", out.detail)

    def test_cpu_temp_warns_near_throttling_and_fails_above_it(self):
        with mock.patch.object(lscore, "cpu_temp_c", return_value=91.0):
            self.assertEqual(lscore.c_temp(mock.Mock()).status, "warn")
        with mock.patch.object(lscore, "cpu_temp_c", return_value=96.0):
            self.assertEqual(lscore.c_temp(mock.Mock()).status, "fail")

    # containers: /proc values belong to the host
    def test_container_skips_host_wide_memory_load_and_swap(self):
        ctx = lscore.Ctx()
        ctx.container = True
        for fn in (lscore.c_memory, lscore.c_load, lscore.c_swap):
            out = fn(ctx)
            self.assertEqual(out.status, "skip", fn.__name__)
            self.assertIn("container", out.detail)

    def test_in_container_detects_docker_marker(self):
        with mock.patch.object(lscore.os.path, "exists",
                               side_effect=lambda p: p == "/.dockerenv"), \
                mock.patch.object(lscore, "read", return_value=""):
            self.assertTrue(lscore.in_container())

    # NixOS: no pending-update list exists
    def test_nixos_update_wording_does_not_invent_pending_updates(self):
        with mock.patch.object(lscore, "nixos_generations",
                               return_value=[(1, time.time())]):
            out = lscore.nixos_update_check()
        self.assertEqual(out.status, "pass")
        self.assertIn("no pending-update list", out.detail)

    def test_trim_accepts_continuous_discard_on_the_home_disk(self):
        with mock.patch.object(lscore, "read",
                               side_effect=lambda p: (
                                   "/dev/nvme0n1p2 /home ext4 rw,discard 0 0\n"
                                   if p == "/proc/mounts" else "0")), \
                mock.patch.object(lscore.glob, "glob",
                                  return_value=["/sys/block/nvme0n1"]):
            out = lscore.c_trim(lscore.Ctx())
        self.assertEqual(out.status, "pass")
        self.assertIn("discard", out.detail.lower())

    def test_power_management_offers_a_nixos_command(self):
        ctx = mock.Mock(laptop=True, systemd=True, nixos=True, pm=None)
        with mock.patch.object(lscore, "units_active", return_value=[]):
            out = lscore.c_power(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("nixos-rebuild", out.cmd)

    def test_power_management_accepts_tuned_and_laptop_mode(self):
        for unit in ("tuned", "laptop-mode"):
            ctx = mock.Mock(laptop=True, systemd=True, nixos=False, pm=None)
            with mock.patch.object(lscore, "units_active",
                                   side_effect=self._units(unit)):
                self.assertEqual(lscore.c_power(ctx).status, "pass", unit)


class TestHistoryPrivacy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("os.geteuid", return_value=1000)   # CI containers run as root
        patcher.start()
        self.addCleanup(patcher.stop)

    def _rep(self):
        return lscore.Report(80, lscore.grade_of(80), {}, [], {})

    def test_history_directory_and_file_are_private(self):
        path = lscore.record_score(self._rep())
        self.assertTrue(path)
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_existing_world_readable_history_is_tightened(self):
        path = lscore.history_path()
        os.makedirs(os.path.dirname(path), mode=0o755)
        with open(path, "w") as f:
            f.write("")
        os.chmod(path, 0o644)
        lscore.record_score(self._rep())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_concurrent_runs_never_lose_a_line(self):
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: lscore.record_score(self._rep()), range(80)))
        self.assertEqual(len(lscore.load_history()), 80)


class TestMorePackageManagers(unittest.TestCase):
    ZYPPER_XML = """<?xml version='1.0'?>
<stream>
<message type="info">Loading repository data...</message>
<update-status version="0.6">
<update-list>
<update kind="package" name="bash" edition="5.2.15-2.1" arch="x86_64" edition-old="5.2.15-1.1">
  <summary>Bash</summary>
</update>
<update kind="package" name="curl" edition="8.6.0-1.1" arch="x86_64" edition-old="8.5.0-1.1">
  <summary>curl</summary>
</update>
</update-list>
</update-status>
</stream>
"""

    APK_OUTPUT = """Installed:                                Available:
busybox-1.36.1-r5                        < 1.36.1-r6
musl-1.2.5-r0                            < 1.2.5-r1
"""

    XBPS_OUTPUT = """bash-5.2.021_1 update 5.2.026_1
curl-8.5.0_1 update 8.6.0_1
"""

    # Pure parsers
    def test_parse_zypper_updates(self):
        self.assertEqual(lscore.parse_zypper_updates(self.ZYPPER_XML), 2)
        empty = ("<?xml version='1.0'?>\n<stream>\n"
                 "<update-status version=\"0.6\"/>\n</stream>\n")
        self.assertEqual(lscore.parse_zypper_updates(empty), 0)
        nested_empty = ("<stream><update-status version='0.6'>"
                        "<update-list/></update-status></stream>")
        self.assertEqual(lscore.parse_zypper_updates(nested_empty), 0)
        self.assertIsNone(lscore.parse_zypper_updates(""))
        self.assertIsNone(lscore.parse_zypper_updates("<stream><message type=\"error\"/></stream>"))
        self.assertIsNone(lscore.parse_zypper_updates("not xml"))

    def test_parse_apk_updates(self):
        self.assertEqual(lscore.parse_apk_updates(self.APK_OUTPUT), 2)
        self.assertEqual(lscore.parse_apk_updates("Installed:   Available:\n"), 0)
        self.assertEqual(lscore.parse_apk_updates(""), 0)

    def test_parse_xbps_updates(self):
        self.assertEqual(lscore.parse_xbps_updates(self.XBPS_OUTPUT), 2)
        self.assertEqual(lscore.parse_xbps_updates("0 packages will be updated\n"), 0)

    def test_parse_rpm_ostree_status(self):
        def stamp(days_ago):
            return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime(time.time() - days_ago * 86400))

        recent = json.dumps({"deployments": [
            {"booted": True, "staged": False, "timestamp": stamp(3)}]})
        staged, age = lscore.parse_rpm_ostree_status(recent)
        self.assertFalse(staged)
        self.assertAlmostEqual(age, 3, delta=0.1)

        staged_json = json.dumps({"deployments": [
            {"booted": True, "staged": True, "timestamp": stamp(3)}]})
        self.assertTrue(lscore.parse_rpm_ostree_status(staged_json)[0])

        self.assertIsNone(lscore.parse_rpm_ostree_status("not json"))
        self.assertIsNone(lscore.parse_rpm_ostree_status('{"deployments": "no"}'))

    def test_parse_rc_crashed(self):
        text = ("Runlevel: default\n"
                " networking                                            [  crashed  ]\n"
                " chronyd                                               [  crashed  ]\n")
        self.assertEqual(lscore.parse_rc_crashed(text), ["networking", "chronyd"])
        self.assertEqual(lscore.parse_rc_crashed(""), [])

    # Pending updates
    def test_zypper_reports_pending_updates(self):
        ctx = mock.Mock(pm="zypper", nixos=False)
        with mock.patch.object(lscore, "index_age_days", return_value=1.0), \
                mock.patch.object(lscore, "run", return_value=(0, self.ZYPPER_XML)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("2 update(s) waiting", out.detail)
        self.assertIn("zypper update", out.cmd)

    def test_zypper_without_metadata_skips_instead_of_claiming_uptodate(self):
        ctx = mock.Mock(pm="zypper", nixos=False)
        with mock.patch.object(lscore, "index_age_days", return_value=None), \
                mock.patch.object(lscore, "run", return_value=(1, "")):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("zypper refresh", out.detail)

    def test_zypper_failure_with_an_empty_list_is_not_an_all_clear(self):
        # a non-zero exit plus an empty <update-status> must not become "up to date"
        ctx = mock.Mock(pm="zypper", nixos=False)
        empty = "<stream><update-status version='0.6'><update-list/></update-status></stream>"
        with mock.patch.object(lscore, "index_age_days", return_value=1.0), \
                mock.patch.object(lscore, "run", return_value=(1, empty)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")

    def test_apk_without_index_skips(self):
        ctx = mock.Mock(pm="apk", nixos=False)
        with mock.patch.object(lscore.glob, "glob", return_value=[]):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("apk update", out.detail)

    def test_apk_reports_pending_updates(self):
        ctx = mock.Mock(pm="apk", nixos=False)
        with mock.patch.object(lscore.glob, "glob", return_value=["/var/cache/apk/APKINDEX.x"]), \
                mock.patch.object(lscore, "index_age_days", return_value=1.0), \
                mock.patch.object(lscore, "run", return_value=(0, self.APK_OUTPUT)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("2 update(s) waiting", out.detail)
        self.assertIn("apk upgrade", out.cmd)

    def test_apk_failure_without_output_skips(self):
        ctx = mock.Mock(pm="apk", nixos=False)
        with mock.patch.object(lscore.glob, "glob", return_value=["/var/cache/apk/APKINDEX.x"]), \
                mock.patch.object(lscore, "index_age_days", return_value=1.0), \
                mock.patch.object(lscore, "run", return_value=(1, "")):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")

    def test_xbps_reports_pending_updates(self):
        ctx = mock.Mock(pm="xbps-install", nixos=False)
        with mock.patch.object(lscore, "run", return_value=(0, self.XBPS_OUTPUT)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("2 update(s) waiting", out.detail)
        self.assertIn("xbps-install -Su", out.cmd)

    def test_rpm_ostree_staged_update_asks_for_a_reboot(self):
        ctx = mock.Mock(pm="rpm-ostree", nixos=False)
        payload = json.dumps({"deployments": [
            {"booted": True, "staged": True, "timestamp": "2026-01-01T00:00:00Z"}]})
        with mock.patch.object(lscore, "run", return_value=(0, payload)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("reboot", out.detail.lower())

    def test_rpm_ostree_reports_image_age_not_a_fake_update_list(self):
        ctx = mock.Mock(pm="rpm-ostree", nixos=False)
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() - 120 * 86400))
        payload = json.dumps({"deployments": [
            {"booted": True, "staged": False, "timestamp": old}]})
        with mock.patch.object(lscore, "run", return_value=(0, payload)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("120 days ago", out.detail)

        recent = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                               time.gmtime(time.time() - 2 * 86400))
        payload = json.dumps({"deployments": [
            {"booted": True, "staged": False, "timestamp": recent}]})
        with mock.patch.object(lscore, "run", return_value=(0, payload)):
            out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "pass")
        self.assertIn("2 day(s) ago", out.detail)
        self.assertIn("online", out.detail)

    def test_gentoo_portage_is_skipped_honestly(self):
        ctx = mock.Mock(pm="emerge", nixos=False)
        out = lscore.c_updates(ctx)
        self.assertEqual(out.status, "skip")
        self.assertIn("Portage", out.detail)

    def test_nixos_generations_win_over_an_extra_package_manager(self):
        # a NixOS box can have dnf or apt installed, but the system is still NixOS
        ctx = mock.Mock(pm="dnf", nixos=True)
        with mock.patch.object(lscore, "nixos_generations",
                               return_value=[(1, time.time())]):
            out = lscore.c_updates(ctx)
        self.assertIn("no pending-update list", out.detail)

    # Caches
    def test_each_package_manager_gets_its_own_clean_command(self):
        cases = {
            "zypper": "zypper clean",
            "apk": "apk cache clean",
            "xbps-install": "xbps-remove -O",
            "emerge": "eclean-dist",
        }
        for pm, command in cases.items():
            ctx = mock.Mock(pm=pm, nixos=False, ostree=False)
            with mock.patch.object(lscore, "dir_size", return_value=(2 * lscore.GiB, True)):
                out = lscore.c_pkgcache(ctx)
            self.assertEqual(out.status, "warn", pm)
            self.assertIn(command, out.cmd, pm)
            self.assertIn("2.0 GiB", out.detail, pm)

    def test_immutable_and_nixos_systems_have_no_package_cache(self):
        for pm, ostree in (("rpm-ostree", True), ("dnf", False)):
            ctx = mock.Mock(pm=pm, nixos=pm != "rpm-ostree", ostree=ostree)
            self.assertEqual(lscore.c_pkgcache(ctx).status, "skip", pm)

    # unused packages: skip where no honest answer exists
    def test_unused_packages_skips_managers_without_a_list(self):
        for pm, word in (("rpm-ostree", "rpm-ostree"), ("zypper", "zypper"),
                         ("apk", "Alpine"), ("xbps-install", "Void"),
                         ("emerge", "Portage")):
            ctx = mock.Mock(pm=pm, nixos=False)
            out = lscore.c_unused(ctx)
            self.assertEqual(out.status, "skip", pm)
            self.assertIn(word, out.detail, pm)

    # OpenRC: the same question, answered with the tools that exist
    def test_openrc_crashed_services_are_reported(self):
        ctx = mock.Mock(systemd=False)
        text = ("Runlevel: default\n"
                " networking                                            [  crashed  ]\n"
                " chronyd                                               [  crashed  ]\n")
        with mock.patch.object(lscore.shutil, "which",
                               side_effect=lambda n: "/sbin/rc-status" if n == "rc-status" else None), \
                mock.patch.object(lscore, "run", return_value=(0, text)):
            out = lscore.c_failed(ctx)
        self.assertEqual(out.status, "warn")
        self.assertIn("2 crashed", out.detail)
        self.assertIn("networking", out.detail)

    def test_openrc_with_no_crashed_services_passes(self):
        ctx = mock.Mock(systemd=False)
        with mock.patch.object(lscore.shutil, "which",
                               side_effect=lambda n: "/sbin/rc-status" if n == "rc-status" else None), \
                mock.patch.object(lscore, "run", return_value=(0, "Runlevel: default\n")):
            out = lscore.c_failed(ctx)
        self.assertEqual(out.status, "pass")
        self.assertIn("OpenRC", out.detail)

    def test_without_systemd_or_openrc_the_check_skips(self):
        with mock.patch.object(lscore.shutil, "which", return_value=None):
            out = lscore.c_failed(mock.Mock(systemd=False))
        self.assertEqual(out.status, "skip")
        self.assertIn("OpenRC", out.detail)

    # Detection
    def test_ostree_systems_prefer_rpm_ostree_over_dnf(self):
        with mock.patch.object(lscore.os.path, "exists",
                               side_effect=lambda p: p == "/run/ostree-booted"), \
                mock.patch.object(lscore.shutil, "which",
                                  side_effect=lambda n: f"/usr/bin/{n}"
                                  if n in ("rpm-ostree", "dnf") else None):
            self.assertEqual(lscore.Ctx().pm, "rpm-ostree")

    def test_package_manager_order_prefers_the_native_one(self):
        with mock.patch.object(lscore.os.path, "exists", return_value=False), \
                mock.patch.object(lscore.shutil, "which",
                                  side_effect=lambda n: f"/usr/bin/{n}"
                                  if n in ("zypper", "pacman", "apt-get") else None):
            self.assertEqual(lscore.Ctx().pm, "zypper")


@unittest.skipUnless(sys.platform.startswith("linux"), "end-to-end needs Linux")
class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp.name,
                                               "NO_COLOR": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("os.geteuid", return_value=1000)   # CI containers run as root
        patcher.start()
        self.addCleanup(patcher.stop)

    def _main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = lscore.main(argv)
        if rc == 2 and "couldn't run any checks" in err.getvalue():
            self.skipTest("no check could run on this system")
        return rc, out.getvalue(), err.getvalue()

    def test_quiet_prints_only_the_score(self):
        rc, out, _ = self._main(["-q"])
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1, "stdout must hold the score and nothing else")
        self.assertTrue(lines[0].isdigit())

    def test_quiet_plus_badge_keeps_stdout_clean(self):
        rc, out, err = self._main(["-q", "--badge"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("img.shields.io", err)

    def test_json_is_parseable_and_complete(self):
        rc, out, _ = self._main(["--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIn("score", data)
        self.assertGreaterEqual(len(data["checks"]), 20)
        self.assertIn(data["grade"], ("A+", "A", "B", "C", "D", "F"))

    def test_history_flag_records_and_prints(self):
        rc, out, _ = self._main(["--history"])
        self.assertEqual(rc, 0)
        self.assertIn("History", out)
        self.assertIn("<- this run", out)
        self.assertTrue(os.path.isfile(lscore.history_path()))
        self.assertEqual(len(lscore.load_history()), 1)

    def test_no_history_writes_nothing(self):
        rc, out, _ = self._main(["-q", "--no-history"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(lscore.history_path()))

    def test_card_failure_exits_with_an_error_code(self):
        bad_path = os.path.join(self.tmp.name, "no-such-dir", "card.svg")
        rc, _, err = self._main(["-q", "--card", bad_path])
        self.assertEqual(rc, 2, "a failed requested output must not look like success")
        self.assertIn("couldn't write the card", err)

    def test_successful_card_still_exits_zero(self):
        good_path = os.path.join(self.tmp.name, "ok.svg")
        rc, out, _ = self._main(["-q", "--card", good_path])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(good_path))
        self.assertEqual(len(out.strip().splitlines()), 1)

    def test_min_flag_controls_exit_code(self):
        rc, _, _ = self._main(["-q", "--min", "0"])
        self.assertEqual(rc, 0)

    def test_version_runs(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                lscore.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(lscore.__version__, out.getvalue())


class TestCliFeatures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp.name,
                                               "NO_COLOR": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("os.geteuid", return_value=1000)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, argv, statuses=None):
        seen = []
        statuses = statuses or {}

        def fake(ctx, progress, checks=None, debug=False):
            chosen = list(lscore.CHECKS if checks is None else checks)
            seen.extend(lscore.check_id(fn) for _c, _w, _t, fn in chosen)
            return [lscore.Result(lscore.check_id(fn), cat, title, weight,
                                  statuses.get(lscore.check_id(fn), "pass"))
                    for cat, weight, title, fn in chosen]

        with mock.patch.object(lscore, "run_checks", side_effect=fake):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = lscore.main(argv)
        return rc, out.getvalue(), err.getvalue(), seen

    # Listing and selection
    def test_list_checks_text_lists_every_id(self):
        rc, out, _, seen = self._run(["--list-checks"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen, [])                  # listing must not run a scan
        for _cat, _w, _t, fn in lscore.CHECKS:
            self.assertIn(lscore.check_id(fn), out)

    def test_list_checks_json_is_machine_readable(self):
        rc, out, _, _ = self._run(["--list-checks", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(len(data), len(lscore.CHECKS))
        self.assertEqual(set(data[0]), {"id", "category", "weight", "title"})

    def test_list_checks_respects_only_and_skip(self):
        rc, out, _, _ = self._run(["--list-checks", "--only", "disk", "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual([c["id"] for c in json.loads(out)], ["disk"])

    def test_only_runs_a_subset(self):
        rc, out, _, seen = self._run(["--only", "disk", "-q"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen, ["disk"])
        self.assertEqual(out.strip(), "100")

    def test_skip_removes_checks(self):
        rc, _, _, seen = self._run(["--skip", "disk", "-q"])
        self.assertEqual(rc, 0)
        self.assertNotIn("disk", seen)
        self.assertEqual(len(seen), len(lscore.CHECKS) - 1)

    def test_categories_answer_to_full_name_and_short_key(self):
        for token in ("Battery & Heat", "battery", "battery-heat"):
            rc, _, _, seen = self._run(["--only", token, "-q"])
            self.assertEqual(rc, 0, token)
            self.assertEqual(set(seen), {"battery", "power", "temp"}, token)

    def test_only_and_skip_together(self):
        rc, _, _, seen = self._run(["--only", "security", "--skip", "ssh", "-q"])
        self.assertEqual(rc, 0)
        self.assertNotIn("ssh", seen)
        self.assertIn("firewall", seen)
        selected = {lscore.check_id(fn) for c, _w, _t, fn in lscore.CHECKS if c == "Security"}
        self.assertEqual(set(seen), selected - {"ssh"})

    def test_split_tokens_keeps_a_category_name_whole(self):
        self.assertEqual(lscore.split_tokens(["Battery & Heat"]), ["battery & heat"])
        self.assertEqual(lscore.split_tokens(["disk, updates", "Disk"]), ["disk", "updates"])

    def test_unknown_check_exits_2_without_scanning(self):
        with mock.patch.object(lscore, "run_checks") as run:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = lscore.main(["--only", "nope", "-q"])
        self.assertEqual(rc, 2)
        self.assertIn("unknown check or category: nope", err.getvalue())
        run.assert_not_called()

    def test_selecting_nothing_exits_2(self):
        rc, _, err, seen = self._run(["--only", "all", "--skip", "all", "-q"])
        self.assertEqual(rc, 2)
        self.assertIn("no checks selected", err)
        self.assertEqual(seen, [])

    # CI exit codes
    def test_fail_on_warn_trips_only_on_warnings_or_failures(self):
        rc, _, _, _ = self._run(["--only", "disk", "-q", "--fail-on", "warn"],
                                {"disk": "warn"})
        self.assertEqual(rc, 1)
        rc, _, _, _ = self._run(["--only", "disk", "-q", "--fail-on", "warn"],
                                {"disk": "pass"})
        self.assertEqual(rc, 0)

    def test_fail_on_fail_ignores_warnings(self):
        rc, _, _, _ = self._run(["--only", "disk", "-q", "--fail-on", "fail"],
                                {"disk": "warn"})
        self.assertEqual(rc, 0)
        rc, _, _, _ = self._run(["--only", "disk", "-q", "--fail-on", "fail"],
                                {"disk": "fail"})
        self.assertEqual(rc, 1)

    def test_min_still_works_with_a_subset(self):
        rc, _, _, _ = self._run(["--only", "disk", "-q", "--min", "80"], {"disk": "warn"})
        self.assertEqual(rc, 1)

    # Comparison
    def test_compare_prints_score_and_category_deltas(self):
        path = os.path.join(self.tmp.name, "old.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": "0.4.0", "score": 40, "grade": "F",
                       "categories": {"Storage": 50}}, f)
        rc, out, err, _ = self._run(["--only", "disk", "-q", "--compare", path])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "100")        # stdout stays reserved for the score
        self.assertIn("Compared with", err)
        self.assertIn("40", err)
        self.assertIn("100", err)
        self.assertIn("+60", err)
        self.assertIn("Storage", err)

    def test_compare_rejects_a_corrupt_file_before_scanning(self):
        path = os.path.join(self.tmp.name, "bad.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("not json")
        with mock.patch.object(lscore, "run_checks") as run:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = lscore.main(["--compare", path, "-q"])
        self.assertEqual(rc, 2)
        self.assertIn("couldn't read", err.getvalue())
        run.assert_not_called()

    def test_compare_rejects_a_file_without_a_score(self):
        path = os.path.join(self.tmp.name, "nos.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"hello": "world"}, f)
        rc, _, err, _ = self._run(["--compare", path, "-q"])
        self.assertEqual(rc, 2)
        self.assertIn("no valid score", err)

    # Colors and ASCII
    def test_color_always_wins_even_with_no_color(self):
        rc, out, _, _ = self._run(["--only", "disk", "--color", "always"])
        self.assertEqual(rc, 0)
        self.assertIn("\033[", out)

    def test_color_never_emits_no_escape_codes(self):
        rc, out, _, _ = self._run(["--only", "disk", "--color", "never"])
        self.assertEqual(rc, 0)
        self.assertNotIn("\033[", out)

    def test_ascii_output_is_plain_ascii(self):
        rc, out, _, _ = self._run(["--only", "disk", "--ascii", "--color", "never"])
        self.assertEqual(rc, 0)
        self.assertTrue(all(ord(ch) < 128 for ch in out), out)
        self.assertIn("ok", out)                    # ASCII stand-in for the checkmark

    def test_ascii_restores_the_unicode_global(self):
        before = lscore.UNICODE
        self._run(["--only", "disk", "--ascii", "-q"])
        self.assertEqual(lscore.UNICODE, before)
        # and on the error path, where main() returns before the report is built
        self._run(["--only", "nope", "--ascii", "-q"])
        self.assertEqual(lscore.UNICODE, before)

    # History and completion
    def test_env_no_history_is_honoured(self):
        with mock.patch.dict(os.environ, {"LSCORE_NO_HISTORY": "1"}):
            rc, _, _, _ = self._run(["--only", "disk", "-q"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(lscore.history_path()))

    def test_env_no_history_accepts_true_yes_and_on(self):
        for value in ("1", "true", "YES", "on"):
            with mock.patch.dict(os.environ, {"LSCORE_NO_HISTORY": value}):
                self.assertTrue(lscore.env_truthy("LSCORE_NO_HISTORY"), value)
        with mock.patch.dict(os.environ, {"LSCORE_NO_HISTORY": "0"}):
            self.assertFalse(lscore.env_truthy("LSCORE_NO_HISTORY"))

    def test_completion_scripts_are_generated(self):
        for shell, marker in (("bash", "complete -F _lscore lscore"),
                              ("zsh", "#compdef lscore"),
                              ("fish", "complete -c lscore")):
            rc, out, _, seen = self._run(["--completion", shell])
            self.assertEqual(rc, 0, shell)
            self.assertIn(marker, out, shell)
            self.assertEqual(seen, [], shell)       # completion never runs a scan

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_bash_completion_parses(self):
        rc, out, _, _ = self._run(["--completion", "bash"])
        self.assertEqual(rc, 0)
        path = os.path.join(self.tmp.name, "lscore.bash")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        proc = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    # Debug
    def test_debug_prints_a_traceback_and_keeps_going(self):
        def boom(ctx):
            raise RuntimeError("kaboom")

        def fine(ctx):
            return lscore.ok("fine")

        checks = [("Speed", 1, "Boom", boom), ("Speed", 1, "Fine", fine)]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(lscore, "CHECKS", checks), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = lscore.main(["--only", "boom,fine", "--debug", "-q"])
        self.assertEqual(rc, 0)
        self.assertIn("Traceback", err.getvalue())
        self.assertIn("kaboom", err.getvalue())
        self.assertEqual(out.getvalue().strip(), "100")


class TestConfigFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "config.ini")

    def _write(self, text):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_path_follows_xdg_config_home(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/xdg"}):
            self.assertEqual(lscore.config_path(), "/tmp/xdg/lscore/config.ini")

    def test_path_falls_back_to_home_dot_config(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        env["HOME"] = "/home/someone"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(lscore.config_path(),
                             "/home/someone/.config/lscore/config.ini")

    def test_every_documented_key_is_parsed(self):
        self._write("[lscore]\n"
                    "only = disk, updates\n"
                    "skip = ssh\n"
                    "min = 75\n"
                    "fail_on = warn\n"
                    "theme = basic\n"
                    "color = never\n"
                    "ascii = yes\n"
                    "no_history = on\n")
        cfg, warnings = lscore.load_config(self.path)
        self.assertEqual(warnings, [])
        self.assertEqual(cfg["only"], ["disk", "updates"])
        self.assertEqual(cfg["skip"], ["ssh"])
        self.assertEqual(cfg["min"], 75)
        self.assertEqual(cfg["fail_on"], "warn")
        self.assertEqual(cfg["theme"], "basic")
        self.assertEqual(cfg["color"], "never")
        self.assertIs(cfg["ascii"], True)
        self.assertIs(cfg["no_history"], True)

    def test_booleans_accept_common_spellings(self):
        for value, expected in (("1", True), ("TRUE", True), ("yes", True), ("On", True),
                                ("0", False), ("false", False), ("NO", False), ("off", False)):
            with self.subTest(value=value):
                self._write(f"[lscore]\nascii = {value}\n")
                cfg, warnings = lscore.load_config(self.path)
                self.assertEqual(warnings, [])
                self.assertIs(cfg["ascii"], expected)

    def test_unknown_keys_warn_and_are_ignored(self):
        self._write("[lscore]\nmin = 10\ncolour = always\n")
        cfg, warnings = lscore.load_config(self.path)
        self.assertEqual(cfg, {"min": 10})
        self.assertTrue(any("unknown key 'colour'" in w for w in warnings), warnings)

    def test_invalid_values_warn_and_are_ignored(self):
        self._write("[lscore]\nmin = lots\nfail_on = sometimes\ntheme = neon\n"
                    "color = maybe\nascii = perhaps\nno_history = 2\n")
        cfg, warnings = lscore.load_config(self.path)
        self.assertEqual(cfg, {})
        for key in ("min", "fail_on", "theme", "color", "ascii", "no_history"):
            self.assertTrue(any(key in w for w in warnings), (key, warnings))

    def test_missing_file_is_silent_by_default(self):
        cfg, warnings = lscore.load_config(os.path.join(self.tmp.name, "nope.ini"))
        self.assertEqual((cfg, warnings), ({}, []))

    def test_strict_missing_file_raises(self):
        with self.assertRaises(OSError):
            lscore.load_config(os.path.join(self.tmp.name, "nope.ini"), strict=True)

    def test_missing_section_warns_or_raises(self):
        self._write("[other]\nmin = 1\n")
        cfg, warnings = lscore.load_config(self.path)
        self.assertEqual(cfg, {})
        self.assertTrue(any("no [lscore] section" in w for w in warnings), warnings)
        with self.assertRaises(ValueError):
            lscore.load_config(self.path, strict=True)

    def test_malformed_file_warns_or_raises(self):
        self._write("[lscore\nmin = 1\n")
        cfg, warnings = lscore.load_config(self.path)
        self.assertEqual(cfg, {})
        self.assertTrue(any("couldn't read" in w for w in warnings), warnings)
        with self.assertRaises(ValueError):
            lscore.load_config(self.path, strict=True)

    def test_values_are_not_interpolated(self):
        self._write("[lscore]\nonly = 100%\n")
        cfg, warnings = lscore.load_config(self.path)
        self.assertEqual(cfg["only"], ["100%"])
        self.assertEqual(warnings, [])


class TestConfigIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg_dir = os.path.join(self.tmp.name, "config")
        os.makedirs(os.path.join(self.cfg_dir, "lscore"))
        self.cfg = os.path.join(self.cfg_dir, "lscore", "config.ini")
        patcher = mock.patch.dict(os.environ, {
            "XDG_CONFIG_HOME": self.cfg_dir,
            "XDG_STATE_HOME": os.path.join(self.tmp.name, "state"),
            "NO_COLOR": "1",
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("os.geteuid", return_value=1000)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, text):
        with open(self.cfg, "w", encoding="utf-8") as f:
            f.write(text)

    def _run(self, argv, statuses=None):
        seen = []
        statuses = statuses or {}

        def fake(ctx, progress, checks=None, debug=False):
            chosen = list(lscore.CHECKS if checks is None else checks)
            seen.extend(lscore.check_id(fn) for _c, _w, _t, fn in chosen)
            return [lscore.Result(lscore.check_id(fn), cat, title, weight,
                                  statuses.get(lscore.check_id(fn), "pass"))
                    for cat, weight, title, fn in chosen]

        with mock.patch.object(lscore, "run_checks", side_effect=fake):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = lscore.main(argv)
        return rc, out.getvalue(), err.getvalue(), seen

    def test_only_and_skip_from_config_select_checks(self):
        self._write("[lscore]\nonly = security\nskip = ssh\n")
        rc, _, _, seen = self._run(["-q"])
        self.assertEqual(rc, 0)
        self.assertNotIn("ssh", seen)
        self.assertIn("firewall", seen)

    def test_cli_only_overrides_config_only(self):
        self._write("[lscore]\nonly = disk\n")
        rc, _, _, seen = self._run(["--only", "updates", "-q"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen, ["updates"])

    def test_no_config_ignores_the_file(self):
        self._write("[lscore]\nonly = disk\nmin = 101\n")
        rc, _, _, seen = self._run(["--no-config", "-q"])
        self.assertEqual(rc, 0)
        self.assertGreater(len(seen), 1)

    def test_config_min_sets_the_exit_code_and_cli_min_wins(self):
        self._write("[lscore]\nmin = 101\n")
        rc, _, _, _ = self._run(["-q"])
        self.assertEqual(rc, 1)
        rc, _, _, _ = self._run(["-q", "--min", "0"])
        self.assertEqual(rc, 0)

    def test_config_fail_on_trips_and_cli_fail_on_wins(self):
        self._write("[lscore]\nmin = 0\nfail_on = warn\n")
        rc, _, _, _ = self._run(["--only", "disk", "-q"], {"disk": "warn"})
        self.assertEqual(rc, 1)
        rc, _, _, _ = self._run(["--only", "disk", "-q", "--fail-on", "fail"],
                                {"disk": "warn"})
        self.assertEqual(rc, 0)

    def test_config_no_history_skips_recording(self):
        self._write("[lscore]\nno_history = true\n")
        rc, _, _, _ = self._run(["-q"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(lscore.history_path()))

    def test_config_ascii_switches_the_output(self):
        self._write("[lscore]\nascii = true\n")
        rc, out, _, _ = self._run(["--only", "disk"])
        self.assertEqual(rc, 0)
        self.assertTrue(all(ord(ch) < 128 for ch in out), out)

    def test_config_color_beats_the_no_color_environment(self):
        self._write("[lscore]\ncolor = always\n")
        rc, out, _, _ = self._run(["--only", "disk"])
        self.assertEqual(rc, 0)
        self.assertIn("\033[", out)
        rc, out, _, _ = self._run(["--only", "disk", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertNotIn("\033[", out)

    def test_config_warnings_go_to_stderr_and_the_run_continues(self):
        self._write("[lscore]\nmin = 0\ncolour = always\n")
        rc, out, err, _ = self._run(["--only", "disk", "-q"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "100")
        self.assertIn("unknown key 'colour'", err)

    def test_a_broken_default_config_warns_but_does_not_stop_the_run(self):
        self._write("[lscore\nmin = 1\n")
        rc, _, err, _ = self._run(["--only", "disk", "-q"])
        self.assertEqual(rc, 0)
        self.assertIn("config", err)
        self.assertIn("ignoring it", err)

    def test_explicit_missing_config_is_an_error(self):
        missing = os.path.join(self.tmp.name, "nope.ini")
        rc, _, err, seen = self._run(["--config", missing, "-q"])
        self.assertEqual(rc, 2)
        self.assertIn("couldn't read config", err)
        self.assertIn("file not found", err)
        self.assertEqual(seen, [])

    def test_explicit_config_without_the_section_is_an_error(self):
        path = os.path.join(self.tmp.name, "other.ini")
        with open(path, "w", encoding="utf-8") as f:
            f.write("[other]\nmin = 1\n")
        rc, _, err, _ = self._run(["--config", path, "-q"])
        self.assertEqual(rc, 2)
        self.assertIn("no [lscore] section", err)

    def test_config_only_with_an_unknown_id_is_an_error(self):
        self._write("[lscore]\nonly = nope\n")
        rc, _, err, seen = self._run(["-q"])
        self.assertEqual(rc, 2)
        self.assertIn("unknown check or category: nope", err)
        self.assertEqual(seen, [])

    def test_list_checks_ignores_config_only(self):
        self._write("[lscore]\nonly = disk\n")
        rc, out, _, seen = self._run(["--list-checks", "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)), len(lscore.CHECKS))
        self.assertEqual(seen, [])


class TestCompareAndHistoryPhase4(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {
            "XDG_STATE_HOME": os.path.join(self.tmp.name, "state"),
            "XDG_CONFIG_HOME": os.path.join(self.tmp.name, "config"),
            "NO_COLOR": "1",
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("os.geteuid", return_value=1000)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, argv, statuses=None):
        statuses = statuses or {}

        def fake(ctx, progress, checks=None, debug=False):
            chosen = list(lscore.CHECKS if checks is None else checks)
            results = []
            for cat, weight, title, fn in chosen:
                cid = lscore.check_id(fn)
                status = statuses.get(cid, "pass")
                results.append(lscore.Result(cid, cat, title, weight, status,
                                             "current detail" if status != "pass" else ""))
            return results

        with mock.patch.object(lscore, "run_checks", side_effect=fake):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = lscore.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _old_report(self, checks, score=40):
        path = os.path.join(self.tmp.name, "old.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": "0.6.0", "score": score, "grade": lscore.grade_of(score),
                       "categories": {"Storage": 50}, "checks": checks}, f)
        return path

    def _check(self, cid, status, title=None):
        return {"id": cid, "status": status, "title": title or cid,
                "detail": "old detail", "impact": 1}

    def test_compare_reports_a_check_that_got_better(self):
        path = self._old_report([self._check("disk", "fail")])
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path])
        self.assertEqual(rc, 0)
        self.assertIn("Check changes:", err)
        self.assertIn("(better)", err)
        self.assertIn("fail", err)
        self.assertIn("pass", err)

    def test_compare_reports_a_check_that_got_worse_with_its_detail(self):
        path = self._old_report([self._check("disk", "pass")])
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path],
                               {"disk": "fail"})
        self.assertEqual(rc, 0)
        self.assertIn("(worse)", err)
        self.assertIn("current detail", err)

    def test_compare_reports_a_new_issue(self):
        path = self._old_report([self._check("updates", "pass")])
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path],
                               {"disk": "warn"})
        self.assertEqual(rc, 0)
        self.assertIn("(new issue)", err)

    def test_compare_reports_a_check_that_became_skipped(self):
        path = self._old_report([self._check("disk", "pass"),
                                 self._check("updates", "pass")])
        rc, _, err = self._run(["--only", "disk,updates", "-q", "--compare", path],
                               {"updates": "skip"})
        self.assertEqual(rc, 0)
        self.assertIn("(not checked now)", err)
        self.assertIn("updates", err)

    def test_compare_reports_a_check_that_is_now_checked(self):
        path = self._old_report([self._check("disk", "skip")])
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path])
        self.assertEqual(rc, 0)
        self.assertIn("(now checked)", err)

    def test_compare_says_when_nothing_changed(self):
        path = self._old_report([self._check("disk", "pass")])
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path])
        self.assertEqual(rc, 0)
        self.assertIn("No check changed status.", err)

    def test_compare_warns_when_the_distro_differs(self):
        path = os.path.join(self.tmp.name, "old.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": "0.6.0", "score": 50, "grade": "C",
                       "system": {"distro": "Something Else 1.0"}}, f)
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path])
        self.assertEqual(rc, 0)
        self.assertIn("that report is from Something Else 1.0", err)

    def test_compare_notes_when_the_two_runs_covered_different_checks(self):
        path = self._old_report([self._check("disk", "pass"),
                                 self._check("updates", "pass")])
        rc, _, err = self._run(["--only", "disk", "-q", "--compare", path])
        self.assertEqual(rc, 0)
        self.assertIn("that run covered 2 checks; this one covers 1", err)
        self.assertIn("not directly comparable", err)

    def test_compare_with_history_notes_a_subset_run(self):
        rc, _, _ = self._run(["--only", "disk", "-q"])
        self.assertEqual(rc, 0)
        rc, _, err = self._run(["-q", "--compare"])
        self.assertEqual(rc, 0)
        self.assertIn("not directly comparable", err)

    def test_compare_without_a_file_uses_the_last_recorded_run(self):
        rc, _, _ = self._run(["--only", "disk", "-q"])
        self.assertEqual(rc, 0)
        rc, _, err = self._run(["--only", "disk", "-q", "--compare"])
        self.assertEqual(rc, 0)
        self.assertIn("Compared with your last recorded run", err)
        self.assertIn("no per-check data", err)

    def test_compare_without_history_exits_2(self):
        rc, _, err = self._run(["--only", "disk", "-q", "--compare"])
        self.assertEqual(rc, 2)
        self.assertIn("no recorded runs yet", err)

    def test_record_score_keeps_category_scores(self):
        rep = lscore.Report(85, lscore.grade_of(85), {"Speed": 90, "Storage": 80}, [], {})
        path = lscore.record_score(rep)
        self.assertTrue(os.path.isfile(path))
        entry = lscore.load_history()[0]
        self.assertEqual(entry["cats"], {"Speed": 90, "Storage": 80})
        self.assertEqual(entry["n"], 0)

    def test_load_last_history_report_returns_categories_and_a_label(self):
        lscore.record_score(lscore.Report(70, lscore.grade_of(70), {"Speed": 60}, [], {}))
        old = lscore.load_last_history_report()
        self.assertEqual(old["score"], 70)
        self.assertEqual(old["categories"], {"Speed": 60})
        self.assertEqual(old["checks"], {})
        self.assertEqual(old["checks_run"], 0)
        self.assertIn("recorded ", old["source_label"])

    def test_load_last_history_report_without_history_raises(self):
        with self.assertRaises(ValueError):
            lscore.load_last_history_report()

    def test_format_age_is_short_and_honest(self):
        self.assertEqual(lscore.format_age(0), "just now")
        self.assertEqual(lscore.format_age(59), "just now")
        self.assertEqual(lscore.format_age(60), "1m ago")
        self.assertEqual(lscore.format_age(3599), "59m ago")
        self.assertEqual(lscore.format_age(3600), "1h ago")
        self.assertEqual(lscore.format_age(86400), "1d ago")
        self.assertEqual(lscore.format_age(-5), "just now")

    def test_history_summary_reports_runs_best_average_and_latest(self):
        now = time.time()
        entries = [{"t": now - 7200, "score": 70, "grade": "C"},
                   {"t": now - 60, "score": 80, "grade": "B"}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lscore.render_history(entries, lambda s, *a: s, recorded=False)
        text = out.getvalue()
        self.assertIn("2 runs", text)
        self.assertIn("best 80", text)
        self.assertIn("average 75.0", text)
        self.assertIn("latest 80", text)
        self.assertIn("last run 1m ago", text)
        self.assertIn("since ", text)


class TestManPage(unittest.TestCase):
    HERE = os.path.dirname(os.path.abspath(__file__))

    def setUp(self):
        self.path = os.path.join(self.HERE, "man", "lscore.1")
        with open(self.path, encoding="utf-8") as f:
            self.text = f.read()

    def test_exists_and_carries_the_install_marker(self):
        self.assertIn(lscore.INSTALL_MARKER, self.text)
        self.assertTrue(self.text.startswith('.\\"'), "must start with a roff comment")

    def test_has_the_standard_sections(self):
        for section in ("NAME", "SYNOPSIS", "DESCRIPTION", "OPTIONS",
                        "CONFIGURATION FILE", "FILES", "ENVIRONMENT",
                        "EXIT STATUS", "EXAMPLES"):
            self.assertIn(f".SH {section}", self.text, section)

    def test_documents_every_flag_the_cli_advertises(self):
        proc = subprocess.run([sys.executable, os.path.join(self.HERE, "lscore.py"), "--help"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        flags = sorted(set(re.findall(r"--[a-z][a-z-]+", proc.stdout)))
        self.assertGreaterEqual(len(flags), 20, flags)
        for flag in flags:
            escaped = "\\-\\-" + flag[2:]
            self.assertIn(escaped, self.text, flag)

    def test_documents_every_config_key(self):
        for key in lscore.CONFIG_KEYS:
            self.assertIn(key, self.text, key)

    def test_documents_exit_codes_and_files(self):
        self.assertIn("history.jsonl", self.text)
        self.assertIn("config.ini", self.text)
        for code in ("0", "1", "2"):
            self.assertIn(f".B {code}", self.text, code)

    def test_mentions_read_only_and_offline(self):
        self.assertIn("read-only", self.text)
        self.assertIn("offline", self.text)

    def test_version_in_the_header_matches_the_program(self):
        self.assertIn(lscore.__version__, self.text)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class TestShellScripts(unittest.TestCase):
    HERE = os.path.dirname(os.path.abspath(__file__))

    def _run(self, script, *args, cwd=None):
        p = subprocess.run(["sh", os.path.join(self.HERE, script), *args],
                           capture_output=True, text=True, timeout=60, cwd=cwd)
        return p.returncode, p.stdout + p.stderr

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prefix = os.path.join(self.tmp.name, "bin")

    def test_both_scripts_exist_are_executable_and_parse(self):
        for name in ("install.sh", "uninstall.sh"):
            path = os.path.join(self.HERE, name)
            with self.subTest(script=name):
                self.assertTrue(os.path.isfile(path), f"{name} is missing")
                self.assertTrue(os.stat(path).st_mode & 0o111, f"{name} is not executable")
                parsers = [["bash", "-n"], ["sh", "-n"]]
                if shutil.which("dash"):
                    parsers.append(["dash", "-n"])
                if shutil.which("busybox"):
                    parsers.append(["busybox", "sh", "-n"])
                for parser in parsers:
                    with self.subTest(script=name, parser=parser):
                        rc = subprocess.run([*parser, path], capture_output=True)
                        self.assertEqual(rc.returncode, 0,
                                         f"{name} has a syntax error under {parser[0]}")

    def test_help_exits_zero_and_bad_options_do_not(self):
        for script in ("install.sh", "uninstall.sh"):
            with self.subTest(script=script):
                self.assertEqual(self._run(script, "--help")[0], 0)
                self.assertNotEqual(self._run(script, "--nope")[0], 0)

    def test_prefix_must_be_absolute_non_empty_and_not_root(self):
        for script in ("install.sh", "uninstall.sh"):
            for bad in ("", "relative/bin", "/", "//"):
                with self.subTest(script=script, prefix=bad):
                    rc, out = self._run(script, "--prefix", bad)
                    self.assertEqual(rc, 2, out)
                    self.assertIn("--prefix", out)

    def test_install_refuses_a_source_without_the_marker(self):
        # a mixed-up release directory must not put an unrelated program on PATH
        release = os.path.join(self.tmp.name, "release")
        os.makedirs(release)
        shutil.copy2(os.path.join(self.HERE, "install.sh"), release)
        with open(os.path.join(release, "lscore.py"), "w") as f:
            f.write("#!/usr/bin/env python3\nprint('not lscore')\n")
        p = subprocess.run(["sh", os.path.join(release, "install.sh"),
                            "--prefix", self.prefix],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not an lscore source file", p.stdout + p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.prefix, "lscore")))

    def test_failed_commit_keeps_the_old_copy_and_leaves_no_temp_file(self):
        self.assertEqual(self._run("install.sh", "--prefix", self.prefix)[0], 0)
        target = os.path.join(self.prefix, "lscore")
        with open(target, "rb") as f:
            before = f.read()

        # Make only mv fail; the old install must survive and the temp file go.
        fakebin = os.path.join(self.tmp.name, "fakebin")
        os.makedirs(fakebin)
        fake_mv = os.path.join(fakebin, "mv")
        with open(fake_mv, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(fake_mv, 0o755)
        env = dict(os.environ)
        env["PATH"] = fakebin + os.pathsep + env.get("PATH", "")
        p = subprocess.run(["sh", os.path.join(self.HERE, "install.sh"),
                            "--prefix", self.prefix],
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot replace", p.stdout + p.stderr)
        with open(target, "rb") as f:
            self.assertEqual(f.read(), before)
        leftovers = [n for n in os.listdir(self.prefix) if n.startswith(".lscore.tmp.")]
        self.assertEqual(leftovers, [])

    def test_purge_refuses_when_the_history_location_is_unknown(self):
        env = dict(os.environ)
        env.pop("HOME", None)
        env.pop("XDG_STATE_HOME", None)
        p = subprocess.run(["sh", os.path.join(self.HERE, "uninstall.sh"),
                            "--prefix", self.prefix, "--purge"],
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot locate", p.stdout + p.stderr)

    def test_install_then_uninstall_roundtrip(self):
        rc, out = self._run("install.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        target = os.path.join(self.prefix, "lscore")
        self.assertTrue(os.path.isfile(target))
        self.assertTrue(os.access(target, os.X_OK))
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)
        man = os.path.join(self.tmp.name, "share", "man", "man1", "lscore.1")
        self.assertTrue(os.path.isfile(man), out)
        self.assertEqual(os.stat(man).st_mode & 0o777, 0o644)
        v = subprocess.run([target, "--version"], capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stderr)
        self.assertIn(lscore.__version__, v.stdout)
        self.assertEqual(self._run("install.sh", "--prefix", self.prefix)[0], 0)
        rc, out = self._run("uninstall.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(man))
        self.assertIn("removed 2", out)

    def test_install_refuses_a_foreign_file_that_merely_mentions_linux_score(self):
        # A file that merely mentions the name is not ours.
        os.makedirs(self.prefix)
        foreign = os.path.join(self.prefix, "lscore")
        with open(foreign, "w") as f:
            f.write("#!/bin/sh\n# Linux Score - a totally different tool\n"
                    "echo mine\n")
        rc, out = self._run("install.sh", "--prefix", self.prefix)
        self.assertNotEqual(rc, 0)
        self.assertIn("not lscore", out)
        with open(foreign) as f:
            self.assertIn("echo mine", f.read())

    def test_install_upgrades_a_legacy_0_3_0_copy(self):
        # Older releases predate the marker.
        os.makedirs(self.prefix)
        legacy = os.path.join(self.prefix, "lscore")
        with open(legacy, "w") as f:
            f.write("#!/usr/bin/env python3\n"
                    '"""lscore - Linux Score"""\n'
                    '__version__ = "0.3.0"\n'
                    "# see lscore --no-history\n")
        rc, out = self._run("install.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        with open(legacy) as f:
            self.assertIn(lscore.INSTALL_MARKER, f.read())

    def test_uninstall_removes_a_legacy_0_3_0_copy(self):
        os.makedirs(self.prefix)
        legacy = os.path.join(self.prefix, "lscore")
        with open(legacy, "w") as f:
            f.write("#!/usr/bin/env python3\n"
                    '"""lscore - Linux Score"""\n'
                    '__version__ = "0.3.0"\n'
                    "# see lscore --no-history\n")
        rc, out = self._run("uninstall.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(legacy))

    def test_marker_is_unique_and_present_in_both_scripts(self):
        self.assertIn(":", lscore.INSTALL_MARKER)
        self.assertGreater(len(lscore.INSTALL_MARKER), 20)
        root = os.path.dirname(os.path.abspath(__file__))
        for name in ("lscore.py", "install.sh", "uninstall.sh", os.path.join("man", "lscore.1")):
            with open(os.path.join(root, name), encoding="utf-8") as f:
                self.assertIn(lscore.INSTALL_MARKER, f.read(), name)

    def test_install_refuses_to_overwrite_a_foreign_lscore(self):
        os.makedirs(self.prefix)
        foreign = os.path.join(self.prefix, "lscore")
        with open(foreign, "w") as f:
            f.write("#!/bin/sh\necho something else\n")
        rc, out = self._run("install.sh", "--prefix", self.prefix)
        self.assertNotEqual(rc, 0)
        self.assertIn("not lscore", out)
        with open(foreign) as f:
            self.assertIn("something else", f.read())
        self.assertEqual(self._run("install.sh", "--prefix", self.prefix, "--force")[0], 0)
        with open(foreign) as f:
            self.assertIn(lscore.INSTALL_MARKER, f.read())

    def test_uninstall_leaves_a_foreign_lscore_alone(self):
        os.makedirs(self.prefix)
        foreign = os.path.join(self.prefix, "lscore")
        with open(foreign, "w") as f:
            f.write("#!/bin/sh\necho something else\n")
        rc, out = self._run("uninstall.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.exists(foreign))
        self.assertIn("not lscore", out)

    def test_uninstall_never_deletes_the_working_copy(self):
        os.makedirs(self.prefix)
        link = os.path.join(self.prefix, "lscore")
        os.symlink(os.path.join(self.HERE, "lscore.py"), link)
        rc, out = self._run("uninstall.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.exists(link))
        self.assertTrue(os.path.exists(os.path.join(self.HERE, "lscore.py")))
        self.assertIn("source copy", out)

    def test_uninstall_purges_history_only_when_asked(self):
        state = os.path.join(self.tmp.name, "state")
        hist = os.path.join(state, "lscore")
        os.makedirs(hist)
        with open(os.path.join(hist, "history.jsonl"), "w") as f:
            f.write('{"t": 1, "score": 99, "grade": "A+"}\n')
        env = dict(os.environ, XDG_STATE_HOME=state)
        p = subprocess.run(["sh", os.path.join(self.HERE, "uninstall.sh"),
                            "--prefix", self.prefix], capture_output=True, text=True, env=env)
        self.assertIn("history kept", p.stdout + p.stderr)
        self.assertTrue(os.path.isdir(hist))
        p = subprocess.run(["sh", os.path.join(self.HERE, "uninstall.sh"),
                            "--prefix", self.prefix, "--purge"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(hist))

    def test_install_works_from_any_working_directory(self):
        # SRC_DIR comes from the script's location, not $PWD.
        elsewhere = self.tmp.name
        p = subprocess.run(["sh", os.path.join(self.HERE, "install.sh"), "--prefix", self.prefix],
                           capture_output=True, text=True, cwd=elsewhere, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.prefix, "lscore")))

    def test_uninstall_removes_an_install_inside_the_release_tree(self):
        # Installing inside the release tree is still an install, not a dev checkout.
        release = os.path.join(self.tmp.name, "release")
        os.makedirs(os.path.join(release, "man"))
        for name in ("install.sh", "uninstall.sh", "lscore.py"):
            shutil.copy2(os.path.join(self.HERE, name), release)
        shutil.copy2(os.path.join(self.HERE, "man", "lscore.1"),
                     os.path.join(release, "man"))
        prefix = os.path.join(release, "bin")
        p = subprocess.run(["sh", os.path.join(release, "install.sh"),
                            "--prefix", prefix],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p = subprocess.run(["sh", os.path.join(release, "uninstall.sh"),
                            "--prefix", prefix],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("removed 2", p.stdout + p.stderr)
        self.assertFalse(os.path.exists(os.path.join(prefix, "lscore")))
        self.assertFalse(os.path.exists(
            os.path.join(release, "share", "man", "man1", "lscore.1")))

    def test_install_and_uninstall_leave_a_foreign_man_page_alone(self):
        os.makedirs(self.prefix)
        man_dir = os.path.join(self.tmp.name, "share", "man", "man1")
        os.makedirs(man_dir)
        page = os.path.join(man_dir, "lscore.1")
        with open(page, "w") as f:
            f.write(".TH OTHER 1\nnot ours\n")
        rc, out = self._run("install.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        self.assertIn("skipping it", out)
        with open(page) as f:
            self.assertIn("not ours", f.read())
        rc, out = self._run("uninstall.sh", "--prefix", self.prefix)
        self.assertEqual(rc, 0, out)
        self.assertIn("not ours", out)
        self.assertTrue(os.path.exists(page))

    def test_force_replaces_a_foreign_man_page(self):
        os.makedirs(self.prefix)
        man_dir = os.path.join(self.tmp.name, "share", "man", "man1")
        os.makedirs(man_dir)
        page = os.path.join(man_dir, "lscore.1")
        with open(page, "w") as f:
            f.write(".TH OTHER 1\n")
        rc, out = self._run("install.sh", "--prefix", self.prefix, "--force")
        self.assertEqual(rc, 0, out)
        with open(page) as f:
            self.assertIn(lscore.INSTALL_MARKER, f.read())

    def test_uninstall_keeps_a_shared_man_directory(self):
        os.makedirs(self.prefix)
        man_dir = os.path.join(self.tmp.name, "share", "man", "man1")
        os.makedirs(man_dir)
        other = os.path.join(man_dir, "other.1")
        with open(other, "w") as f:
            f.write(".TH OTHER 1\n")
        self.assertEqual(self._run("install.sh", "--prefix", self.prefix)[0], 0)
        self.assertEqual(self._run("uninstall.sh", "--prefix", self.prefix)[0], 0)
        self.assertTrue(os.path.isfile(other), "a shared man directory must survive")
        self.assertFalse(os.path.exists(os.path.join(man_dir, "lscore.1")))

    def test_uninstall_with_nothing_installed_is_friendly(self):
        empty = os.path.join(self.tmp.name, "empty")
        rc, out = self._run("uninstall.sh", "--prefix", empty)
        self.assertEqual(rc, 0, out)
        self.assertIn("lscore is not installed", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
