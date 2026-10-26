"""WordPress-aware security checks (filesystem checks run for real; wp-cli is faked)."""
from datetime import datetime, timezone
from pathlib import Path

from harbor.system import wpcheck


def make_wp(tmp_path, plugins=(), dropins=(), uploads_php=(), user_ini=None):
    root = tmp_path / "site"
    pub = root / "public"
    (pub / "wp-admin").mkdir(parents=True)
    (pub / "wp-includes").mkdir(parents=True)
    (pub / "wp-includes" / "version.php").write_text("<?php $wp_version='6.6';")
    (pub / "wp-config.php").write_text("<?php // config")
    (pub / "wp-content" / "plugins").mkdir(parents=True)
    (pub / "wp-content" / "uploads").mkdir(parents=True)
    for name, files in plugins:
        d = pub / "wp-content" / "plugins" / name
        d.mkdir()
        for fname, content in files:
            (d / fname).write_text(content)
    for name in dropins:
        (pub / "wp-content" / name).write_text("<?php // dropin")
    for rel in uploads_php:
        f = pub / "wp-content" / "uploads" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("<?php // x")
    if user_ini is not None:
        (pub / ".user.ini").write_text(user_ini)
    return root, pub


def test_find_installs(tmp_path):
    root, pub = make_wp(tmp_path)
    assert wpcheck.find_installs(root) == [pub]


def test_dropin_without_owner_is_high(tmp_path):
    root, pub = make_wp(tmp_path, dropins=("db.php",))
    f = [x for x in wpcheck._dropins(pub)]
    assert len(f) == 1 and f[0].kind == "dropin" and f[0].severity == "high" and "db.php" in f[0].title


def test_dropin_with_cache_plugin_is_review(tmp_path):
    root, pub = make_wp(tmp_path, plugins=[("w3-total-cache", [("w3.php", "<?php")])], dropins=("object-cache.php",))
    f = wpcheck._dropins(pub)
    assert len(f) == 1 and f[0].severity == "review"


def test_fake_plugin_single_big_file(tmp_path):
    big = "<?php /* Plugin Name: Pixel Keeper */ " + "A" * (400 * 1024)
    root, pub = make_wp(tmp_path, plugins=[("ridge-keeper-cue", [("ridge-keeper-cue.php", big)])])
    f = [x for x in wpcheck._fake_plugins(pub) if x.kind == "fake-plugin"]
    assert f and f[0].severity == "high" and "ridge-keeper-cue" in f[0].title


def test_branded_plugin_name_not_flagged(tmp_path):
    # real plugins routinely brand differently from their folder slug; this must NOT be flagged
    hdr = "<?php\n/* Plugin Name: Noptin */\n"
    root, pub = make_wp(tmp_path, plugins=[("newsletter-optin-box", [("noptin.php", hdr), ("readme.txt", "x"),
                                                                      ("includes.php", "<?php")])])
    assert [x for x in wpcheck._fake_plugins(pub) if x.kind == "fake-plugin"] == []


def test_real_plugin_not_flagged(tmp_path):
    hdr = "<?php\n/* Plugin Name: Akismet Anti-Spam */\n"
    root, pub = make_wp(tmp_path, plugins=[("akismet", [("akismet.php", hdr), ("readme.txt", "x")])])
    assert [x for x in wpcheck._fake_plugins(pub) if x.kind == "fake-plugin"] == []


def test_uploads_php_flagged_cache_ignored(tmp_path):
    root, pub = make_wp(tmp_path, uploads_php=["2026/evil.php", "mailpoet/cache/abc.php", "index.php"])
    f = wpcheck._uploads_php(pub)
    assert len(f) == 1 and "1 PHP file" in f[0].title and "2026/evil.php" in f[0].detail
    assert "abc.php" not in f[0].detail and "mailpoet" not in f[0].detail


def test_user_ini_prepend(tmp_path):
    root, pub = make_wp(tmp_path, user_ini="auto_prepend_file = /tmp/x.php\n")
    f = wpcheck._user_ini(pub)
    assert len(f) == 1 and f[0].severity == "high"
    root2, pub2 = make_wp(tmp_path / "b", user_ini="memory_limit = 256M\n")
    assert wpcheck._user_ini(pub2) == []


def test_checksum_aggregated_and_categorised():
    core_out = ("Warning: File doesn't verify against checksum: wp-admin/includes/class-x.php\n"
                "Warning: File doesn't verify against checksum: wp-includes/load.php\n"
                "Warning: File should not exist: wp-includes/evil.php\n"
                "Warning: File doesn't exist: wp-includes/missing-one.php\n"
                "Error: WordPress installation doesn't verify against checksums.\n")
    plugin_out = ("Warning: File doesn't verify against checksum: akismet/akismet.php\n"
                  "Warning: Could not retrieve the checksums for version 1.2 of plugin foobar, "
                  "please check the error log.\n")
    run = lambda args: ((core_out if args[0] == "core" else plugin_out), 1)
    f = {x.kind: x for x in wpcheck._checksums(run)}
    # modified files: one aggregated HIGH finding, not one per file
    assert f["core-modified"].severity == "high" and "2 core file" in f["core-modified"].title
    assert "wp-includes/load.php" in f["core-modified"].detail
    assert f["core-extra"].severity == "review" and "evil.php" in f["core-extra"].detail
    assert f["core-missing"].severity == "review" and "missing-one.php" in f["core-missing"].detail
    assert f["plugin-modified"].severity == "high"
    assert f["unverifiable-plugin"].severity == "review" and "foobar" in f["unverifiable-plugin"].detail


def test_bundled_library_mismatch_is_not_malware():
    # a big WordPress-bundled library (php-ai-client) out of sync with the manifest must not flood as "altered"
    lines = ["Warning: File doesn't exist: wp-includes/php-ai-client/src/Providers/Models/Thing%d.php" % i for i in range(40)]
    core_out = "\n".join(lines) + "\nError: WordPress installation doesn't verify against checksums.\n"
    f = {x.kind: x for x in wpcheck._checksums(lambda args: ((core_out if args[0] == "core" else ""), 1))}
    assert f == {}                                       # a bundled library out of sync produces no findings at all


def test_too_many_core_diffs_is_inconclusive():
    lines = ["Warning: File should not exist: wp-includes/x%d.php" % i for i in range(20)]
    core_out = "\n".join(lines) + "\n"
    f = {x.kind: x for x in wpcheck._checksums(lambda args: ((core_out if args[0] == "core" else ""), 1))}
    assert "core-verify" in f and f["core-verify"].severity == "review" and "core-modified" not in f


def test_admin_recent_flagged():
    now = datetime(2026, 10, 16, tzinfo=timezone.utc)
    out = ("user_login,user_registered,user_email\n"
           "CookDiaries,2019-05-28 16:15:08,contact@site.com\n"
           "admin_3f9d77f8aa,2026-10-07 11:22:30,x@site.com\n")
    f = wpcheck._admins(lambda args: (out, 0), now)
    assert len(f) == 1 and f[0].kind == "new-admin" and "admin_3f9d77f8aa" in f[0].title


def test_wp_unavailable_kept_separate(tmp_path):
    root, pub = make_wp(tmp_path, dropins=("db.php",))
    def run(args):
        return ("Error: Error establishing a database connection", 1)
    res = wpcheck.check(pub, root, run, now=datetime(2026, 10, 16, tzinfo=timezone.utc))
    assert res.error and any(x.kind == "dropin" for x in res.findings)   # file checks still ran
