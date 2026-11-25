from forace.analyzers import (
    analyze_sshd, analyze_authorized_keys, analyze_crontab,
    analyze_passwd, analyze_sudoers, analyze_systemd,
)
from forace.rules import load_rules
from forace.detection import compare_scans
from forace.scanner import scan_directory


def test_sshd_detects_security_value_but_ignores_comments_and_case():
    assert analyze_sshd("# PermitRootLogin yes\nPermitRootLogin no\n", "permitrootlogin YES\n") == ["PermitRootLogin=yes"]
    assert analyze_sshd("PermitRootLogin no\n", "# changed comment\nPermitRootLogin no\n") == []


def test_sshd_uses_first_value_for_duplicate_directives():
    assert analyze_sshd("PermitRootLogin no\n", "PermitRootLogin no\nPermitRootLogin yes\n") == []


def test_authorized_keys_compares_normalized_entries():
    old = "# old key\nssh-ed25519 AAAA key-one\n"
    new = "ssh-ed25519   AAAA   key-one\nssh-rsa BBBB key-two\n"
    assert analyze_authorized_keys(old, new) == {"added": ["ssh-rsa BBBB"], "removed": [], "modified": []}


def test_authorized_keys_ignores_comment_whitespace_but_detects_option_change():
    old = 'command="/usr/bin/true" ssh-ed25519 AAAA old-label\n'
    relabeled = 'command="/usr/bin/true"   ssh-ed25519 AAAA new-label\n'
    changed = 'from="192.0.2.10" ssh-ed25519 AAAA new-label\n'
    assert analyze_authorized_keys(old, relabeled) == {"added": [], "removed": [], "modified": []}
    assert analyze_authorized_keys(old, changed)["modified"] == ["ssh-ed25519 AAAA"]


def test_crontab_finds_only_new_real_entries_and_flags_suspicious_command():
    old = "# scheduled jobs\n0 2 * * * root echo backup\n"
    new = "# edited note\n0 2 * * * root echo backup\n*/5 * * * * root curl http://example.invalid/x\n"
    result = analyze_crontab(old, new)
    assert result["added"] == ["*/5 * * * * root curl http://example.invalid/x"]
    assert result["suspicious"] == result["added"]
    assert result["removed"] == []


def test_crontab_reports_removed_entry():
    assert analyze_crontab("0 2 * * * root echo old\n", "") == {"added": [], "removed": ["0 2 * * * root echo old"], "suspicious": []}


def test_passwd_detects_added_user_uid_zero_and_service_shell_change():
    old = "root:x:0:0:root:/root:/bin/bash\nsvc-backup:x:998:998:Backup:/srv:/usr/sbin/nologin\n"
    new = old + "admin2:x:0:0:Admin:/home/a:/bin/bash\n"
    new = new.replace("svc-backup:x:998:998:Backup:/srv:/usr/sbin/nologin", "svc-backup:x:998:998:Backup:/srv:/bin/bash")
    assert analyze_passwd(old, new) == {"new_users": ["admin2"], "removed_users": [], "uid_changes": [], "gid_changes": [], "uid_zero": ["admin2"], "service_shell": ["svc-backup"]}


def test_sudoers_ignores_formatting_and_comments_but_finds_new_rule():
    old = "# initial\noperator ALL=(ALL) /usr/bin/id\n"
    assert analyze_sudoers(old, "# different\noperator   ALL=(ALL) /usr/bin/id\n") == {"nopasswd": [], "admin_privileges": [], "removed_admin_privileges": []}
    assert analyze_sudoers(old, old + "operator ALL=(ALL) NOPASSWD: ALL\n") == {"nopasswd": ["operator ALL=(ALL) NOPASSWD: ALL"], "admin_privileges": ["operator ALL=(ALL) NOPASSWD: ALL"], "removed_admin_privileges": []}


def test_sudoers_reports_added_and_removed_admin_privilege_lines():
    assert analyze_sudoers("", "operator ALL=(root) /usr/bin/id\n")["admin_privileges"] == ["operator ALL=(root) /usr/bin/id"]
    assert analyze_sudoers("operator ALL=(root) /usr/bin/id\n", "")["removed_admin_privileges"] == ["operator ALL=(root) /usr/bin/id"]


def test_systemd_ignores_comments_and_spacing_but_detects_execstart():
    old = "[Service]\nExecStart=/usr/bin/echo ok\n"
    assert analyze_systemd(old, "# harmless\n[Service]\n ExecStart = /usr/bin/echo ok\n") is False
    assert analyze_systemd(old, "[Service]\nExecStart=/bin/sh -c id\n") is True


def test_rules_include_all_required_ids_and_metadata():
    rules = load_rules()
    assert len(rules) == 12
    assert {rule["id"] for rule in rules} == {f"R{i:02}" for i in range(1, 13)}
    assert all({"trigger", "severity", "attack_id", "explanation_template"} <= rule.keys() for rule in rules)
    expected_severities = {
        "R01": "High", "R02": "Medium", "R03": "High", "R04": "Medium",
        "R05": "Critical", "R06": "High", "R07": "Critical", "R08": "High",
        "R09": "Critical", "R10": "High", "R11": "High", "R12": "Medium",
    }
    assert {rule["id"]: rule["severity"] for rule in rules} == expected_severities
    expected = {"R01": "T1021.004", "R02": "T1021.004", "R03": "T1098.004", "R04": "T1053.003", "R05": "T1053.003", "R06": "T1136.001", "R07": "T1136.001", "R08": "T1098", "R09": "T1548.003", "R10": "T1548.001", "R11": "T1685.006", "R12": "T1543.002"}
    assert {rule["id"]: rule["attack_id"] for rule in rules} == expected


def test_smart_and_hash_only_modes_share_changes_but_differ_in_explanation():
    old = {"sha256": "a" * 64, "snapshot": "PermitRootLogin no\n", "mode": 0o644, "uid": 1, "gid": 1, "size": 19}
    new = {"sha256": "b" * 64, "snapshot": "PermitRootLogin yes\n", "mode": 0o644, "uid": 1, "gid": 1, "size": 20}
    baseline = {"files": {"etc/ssh/sshd_config": old}}
    current = {"files": {"etc/ssh/sshd_config": new}, "errors": {}}
    smart = compare_scans(baseline, current, mode="smart")
    basic = compare_scans(baseline, current, mode="hash-only")
    assert any(f["rule_id"] == "R01" and f["attack_id"] == "T1021.004" for f in smart)
    assert basic == [{"file_path": "etc/ssh/sshd_config", "change_type": "modified", "rule_id": None, "severity": None, "attack_id": None, "explanation": None}]


def test_metadata_add_delete_rename_and_auth_log_truncation():
    base_entry = {"sha256": "a" * 64, "snapshot": "log line\n", "mode": 0o644, "uid": 1, "gid": 1, "size": 9}
    baseline = {"files": {"var/log/auth.log": base_entry, "old.txt": {**base_entry, "sha256": "d" * 64, "snapshot": None}}}
    current = {"files": {"var/log/auth.log": {**base_entry, "sha256": "b" * 64, "snapshot": "", "size": 0}, "new.txt": {**base_entry, "sha256": "c" * 64, "snapshot": None}, "moved.txt": {**base_entry, "sha256": "d" * 64, "snapshot": None}}, "errors": {}}
    smart = compare_scans(baseline, current, mode="smart")
    kinds = {(f["file_path"], f["change_type"], f["rule_id"]) for f in smart}
    assert ("new.txt", "added", None) in kinds
    assert ("old.txt", "renamed", None) in kinds
    assert ("var/log/auth.log", "truncated", "R11") in kinds


def test_each_rule_trigger_maps_to_yaml_metadata():
    empty = {"sha256": "a" * 64, "snapshot": "", "mode": 0o644, "uid": 1, "gid": 1, "size": 0}
    scenarios = [
        ("etc/ssh/sshd_config", "PermitRootLogin no\n", "PermitRootLogin yes\n", "R01"),
        ("etc/ssh/sshd_config", "PasswordAuthentication no\n", "PasswordAuthentication yes\n", "R02"),
        ("home/user/.ssh/authorized_keys", "", "ssh-ed25519 AAAA key\n", "R03"),
        ("etc/crontab", "", "0 2 * * * root echo ok\n", "R04"),
        ("etc/crontab", "", "0 2 * * * root curl http://example.invalid/x\n", "R05"),
        ("etc/passwd", "root:x:0:0:r:/root:/bin/sh\n", "root:x:0:0:r:/root:/bin/sh\nnew:x:1001:1001:n:/home/n:/bin/sh\n", "R06"),
        ("etc/passwd", "root:x:0:0:r:/root:/bin/sh\n", "root:x:0:0:r:/root:/bin/sh\nnew:x:0:1001:n:/home/n:/bin/sh\n", "R07"),
        ("etc/passwd", "root:x:0:0:r:/root:/bin/sh\nsvc-job:x:998:998:s:/srv:/usr/sbin/nologin\n", "root:x:0:0:r:/root:/bin/sh\nsvc-job:x:998:998:s:/srv:/bin/bash\n", "R08"),
        ("etc/sudoers", "", "ops ALL=(ALL) NOPASSWD: ALL\n", "R09"),
        ("etc/systemd/system/new.service", "", "[Service]\nExecStart=/bin/true\n", "R12"),
    ]
    for path, old_text, new_text, expected_rule in scenarios:
        old = {**empty, "snapshot": old_text, "sha256": "a" * 64}
        new = {**empty, "snapshot": new_text, "sha256": "b" * 64, "size": len(new_text)}
        old_files = {} if not old_text and expected_rule in {"R03", "R12"} else {path: old}
        new_files = {path: new}
        findings = compare_scans({"files": old_files}, {"files": new_files, "errors": {}}, mode="smart")
        finding = next((f for f in findings if f["rule_id"] == expected_rule), None)
        assert finding is not None, expected_rule
        rule = next(rule for rule in load_rules() if rule["id"] == expected_rule)
        assert finding["severity"] == rule["severity"]
        assert finding["attack_id"] == rule["attack_id"]
        assert finding["explanation"] == rule["explanation_template"]

    # R10 is driven by the metadata transition, even when file contents also change.
    old = {"files": {"bin/tool": {**empty, "mode": 0o755}}}
    new = {"files": {"bin/tool": {**empty, "mode": 0o4755, "sha256": "b" * 64}}}
    finding = next(f for f in compare_scans(old, {**new, "errors": {}}, mode="smart") if f["rule_id"] == "R10")
    assert finding["severity"] == "High"
    assert finding["attack_id"] == "T1548.001"
    assert finding["explanation"] == next(rule["explanation_template"] for rule in load_rules() if rule["id"] == "R10")


def test_metadata_permissions_ownership_and_hash_only_add_delete():
    e = {"sha256": "a" * 64, "snapshot": "x", "mode": 0o644, "uid": 10, "gid": 10, "size": 1}
    before = {"files": {"a": e, "gone": e}}
    after = {"files": {"a": {**e, "mode": 0o600, "uid": 11}, "new": {**e, "sha256": "b" * 64}}, "errors": {}}
    smart = compare_scans(before, after, mode="smart")
    assert {f["change_type"] for f in smart} >= {"permission_changed", "ownership_changed", "added", "deleted"}
    basic = compare_scans(before, after, mode="hash-only")
    assert {(f["file_path"], f["change_type"]) for f in basic} == {("new", "added"), ("gone", "deleted")}


def test_new_sgid_bit_is_detected_as_generic_metadata_finding():
    base = {"files": {"bin/tool": {"sha256": "a" * 64, "mode": 0o755}}}
    now = {"files": {"bin/tool": {"sha256": "a" * 64, "mode": 0o2755}}, "errors": {}}
    assert any(item["change_type"] == "sgid_enabled" for item in compare_scans(base, now, mode="smart"))


def test_inaccessible_baseline_path_is_reported_as_error_and_deleted_and_traversal_rejected():
    e = {"sha256": "a" * 64}
    findings = compare_scans({"files": {"keep": e}}, {"files": {}, "errors": {"keep": "permission denied"}})
    assert {item["change_type"] for item in findings} == {"unreadable", "deleted"}
    import pytest
    with pytest.raises(ValueError, match="outside the lab"):
        compare_scans({"files": {"../outside": e}}, {"files": {}, "errors": {}})


def test_key_removal_and_passwd_uid_gid_changes_are_reported():
    assert analyze_authorized_keys("ssh-ed25519 AAAA key\n", "") == {"added": [], "removed": ["ssh-ed25519 AAAA"], "modified": []}
    old = "operator:x:1000:1000:Operator:/home/operator:/bin/bash\n"
    new = "operator:x:1001:1002:Operator:/home/operator:/bin/bash\n"
    result = analyze_passwd(old, new)
    assert result["uid_changes"] == ["operator"]
    assert result["gid_changes"] == ["operator"]


def test_comment_only_and_timestamp_only_edits_are_benign_in_smart_mode():
    before = {"files": {"etc/ssh/sshd_config": {"sha256": "a" * 64,
             "snapshot": "PermitRootLogin no\n", "mode": 0o644, "uid": 1, "gid": 1,
             "mtime_ns": 10, "size": 18}}}
    after = {"files": {"etc/ssh/sshd_config": {"sha256": "b" * 64,
            "snapshot": "# reviewed\nPermitRootLogin no\n", "mode": 0o644, "uid": 1,
            "gid": 1, "mtime_ns": 20, "size": 29}}, "errors": {}}
    assert compare_scans(before, after, mode="smart") == []
    after["files"]["etc/ssh/sshd_config"]["sha256"] = "a" * 64
    after["files"]["etc/ssh/sshd_config"]["snapshot"] = "PermitRootLogin no\n"
    assert compare_scans(before, after, mode="smart") == []


def test_deleted_authentication_log_gets_rule_r11():
    entry = {"sha256": "a" * 64, "snapshot": "auth event\n", "size": 11}
    result = compare_scans({"files": {"var/log/auth.log": entry}}, {"files": {}, "errors": {}}, mode="smart")
    assert result[0]["rule_id"] == "R11"
    assert result[0]["severity"] == "High"
    assert result[0]["attack_id"] == "T1685.006"
    assert result[0]["explanation"] == next(rule["explanation_template"] for rule in load_rules() if rule["id"] == "R11")


def test_other_ssh_security_setting_changes_are_explained():
    old_text, new_text = "PubkeyAuthentication yes\n", "PubkeyAuthentication no\n"
    before = {"files": {"etc/ssh/sshd_config": {"sha256": "a" * 64, "snapshot": old_text, "size": len(old_text)}}}
    after = {"files": {"etc/ssh/sshd_config": {"sha256": "b" * 64, "snapshot": new_text, "size": len(new_text)}}, "errors": {}}
    findings = compare_scans(before, after, mode="smart")
    assert any(item["change_type"] == "ssh_setting_changed" for item in findings)


def test_smart_falls_back_to_generic_when_semantic_snapshots_are_missing():
    before = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": None}}}
    after = {"files": {"etc/crontab": {"sha256": "b" * 64, "snapshot": None}}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert len(findings) == 1
    assert findings[0]["change_type"] == "modified"
    assert findings[0]["rule_id"] is None
    assert findings[0]["severity"] is None


def test_smart_falls_back_for_oversized_semantic_file_without_snapshot(tmp_path):
    root = tmp_path / "lab"
    crontab = root / "etc" / "crontab"
    crontab.parent.mkdir(parents=True)
    crontab.write_bytes(b"a" * (1024 * 1024))
    before = scan_directory(root)
    crontab.write_bytes(b"b" * (1024 * 1024))
    after = scan_directory(root)

    assert before["files"]["etc/crontab"]["snapshot"] is None
    assert after["files"]["etc/crontab"]["snapshot"] is None
    findings = compare_scans(before, after, mode="smart")
    assert len(findings) == 1
    assert findings[0]["change_type"] == "modified"
    assert findings[0]["rule_id"] is None


def test_smart_falls_back_for_invalid_utf8_semantic_file_without_snapshot(tmp_path):
    root = tmp_path / "lab"
    crontab = root / "etc" / "crontab"
    crontab.parent.mkdir(parents=True)
    crontab.write_bytes(b"# old\xff\n")
    before = scan_directory(root)
    crontab.write_bytes(b"# new\xff\n")
    after = scan_directory(root)

    assert before["files"]["etc/crontab"]["snapshot"] is None
    assert after["files"]["etc/crontab"]["snapshot"] is None
    findings = compare_scans(before, after, mode="smart")
    assert len(findings) == 1
    assert findings[0]["change_type"] == "modified"
    assert findings[0]["rule_id"] is None


def test_smart_falls_back_when_semantic_analyzer_raises(monkeypatch):
    import forace.detection as detection

    def fail_analyzer(*_args):
        raise RuntimeError("unsupported crontab input")

    monkeypatch.setattr(detection, "analyze_crontab", fail_analyzer)
    before = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": "old text\n"}}}
    after = {"files": {"etc/crontab": {"sha256": "b" * 64, "snapshot": "new text\n"}}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert len(findings) == 1
    assert findings[0]["change_type"] == "modified"
    assert findings[0]["rule_id"] is None


def test_smart_reports_unrecognized_active_crontab_change_generically():
    before = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": "SHELL=/bin/sh\n"}}}
    after = {"files": {"etc/crontab": {
        "sha256": "b" * 64,
        "snapshot": "SHELL=/bin/sh\nIntegrityWatch test modification\n",
    }}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert len(findings) == 1
    assert findings[0]["change_type"] == "modified"
    assert findings[0]["rule_id"] is None
    assert findings[0]["severity"] is None


def test_smart_keeps_r04_specialized_metadata_and_ignores_unchanged_missing_snapshot():
    before = {"files": {"etc/crontab": {
        "sha256": "a" * 64,
        "snapshot": "0 2 * * * root echo old\n",
    }}}
    after = {"files": {"etc/crontab": {
        "sha256": "b" * 64,
        "snapshot": "0 2 * * * root echo old\n17 3 * * * root echo new\n",
    }}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert len(findings) == 1
    assert findings[0]["change_type"] == "new_cron_entry"
    assert findings[0]["rule_id"] == "R04"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["attack_id"] == "T1053.003"
    assert findings[0]["explanation"]

    unchanged = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": None}}, "errors": {}}
    baseline = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": None}}}
    assert compare_scans(baseline, unchanged, mode="smart") == []


def test_smart_preserves_r05_metadata_for_suspicious_cron_entry():
    before = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": ""}}}
    after = {"files": {"etc/crontab": {
        "sha256": "b" * 64,
        "snapshot": "23 4 * * * root echo 'curl inert-marker'\n",
    }}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert len(findings) == 1
    assert findings[0]["change_type"] == "suspicious_cron"
    assert findings[0]["rule_id"] == "R05"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["attack_id"] == "T1053.003"
    assert findings[0]["explanation"]


def test_smart_keeps_auth_log_truncation_rule_when_snapshot_is_missing():
    before = {"files": {"var/log/auth.log": {
        "sha256": "a" * 64,
        "snapshot": None,
        "size": 100,
    }}}
    after = {"files": {"var/log/auth.log": {
        "sha256": "b" * 64,
        "snapshot": None,
        "size": 10,
    }}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert len(findings) == 1
    assert findings[0]["change_type"] == "truncated"
    assert findings[0]["rule_id"] == "R11"
    assert findings[0]["severity"] == "High"


def test_smart_ignores_case_only_sshd_value_change():
    before = {"files": {"etc/ssh/sshd_config": {
        "sha256": "a" * 64,
        "snapshot": "PermitRootLogin no\n",
    }}}
    after = {"files": {"etc/ssh/sshd_config": {
        "sha256": "b" * 64,
        "snapshot": "permitrootlogin NO\n",
    }}, "errors": {}}

    assert compare_scans(before, after, mode="smart") == []


def test_smart_rename_without_metadata_changes_reports_only_rename():
    entry = {"sha256": "a" * 64, "mode": 0o644, "uid": 1000, "gid": 1000}

    findings = compare_scans(
        {"files": {"old.txt": entry}},
        {"files": {"new.txt": entry}, "errors": {}},
        mode="smart",
    )

    assert [(item["file_path"], item["change_type"]) for item in findings] == [
        ("old.txt", "renamed"),
    ]


def test_smart_rename_reports_permission_change_at_new_path():
    before = {"files": {"old.txt": {"sha256": "a" * 64, "mode": 0o644, "uid": 1000, "gid": 1000}}}
    after = {"files": {"new.txt": {"sha256": "a" * 64, "mode": 0o600, "uid": 1000, "gid": 1000}}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert [(item["file_path"], item["change_type"]) for item in findings] == [
        ("old.txt", "renamed"),
        ("new.txt", "permission_changed"),
    ]


def test_smart_rename_reports_ownership_change_at_new_path():
    before = {"files": {"old.txt": {"sha256": "a" * 64, "mode": 0o644, "uid": 1000, "gid": 1000}}}
    after = {"files": {"new.txt": {"sha256": "a" * 64, "mode": 0o644, "uid": 2000, "gid": 2000}}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert [(item["file_path"], item["change_type"]) for item in findings] == [
        ("old.txt", "renamed"),
        ("new.txt", "ownership_changed"),
    ]


def test_smart_rename_reports_permission_and_ownership_changes():
    before = {"files": {"old.txt": {"sha256": "a" * 64, "mode": 0o644, "uid": 1000, "gid": 1000}}}
    after = {"files": {"new.txt": {"sha256": "a" * 64, "mode": 0o600, "uid": 2000, "gid": 2000}}, "errors": {}}

    findings = compare_scans(before, after, mode="smart")

    assert [(item["file_path"], item["change_type"]) for item in findings] == [
        ("old.txt", "renamed"),
        ("new.txt", "permission_changed"),
        ("new.txt", "ownership_changed"),
    ]


def _cron_findings_for_additions(additions):
    before = {"files": {"etc/crontab": {"sha256": "a" * 64, "snapshot": "SHELL=/bin/sh\n"}}}
    after = {"files": {"etc/crontab": {
        "sha256": "b" * 64,
        "snapshot": "SHELL=/bin/sh\n" + additions,
    }}, "errors": {}}
    return compare_scans(before, after, mode="smart")


def test_cron_normal_addition_emits_one_medium_r04_finding():
    findings = _cron_findings_for_additions(
        "17 3 * * * root /bin/echo normal-fixture\n",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "R04"
    assert findings[0]["change_type"] == "new_cron_entry"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["attack_id"] == "T1053.003"
    assert findings[0]["explanation"]


def test_cron_suspicious_addition_emits_one_critical_r05_finding():
    findings = _cron_findings_for_additions(
        "23 4 * * * root /bin/echo 'curl inert-fixture'\n",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "R05"
    assert findings[0]["change_type"] == "suspicious_cron"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["attack_id"] == "T1053.003"
    assert findings[0]["explanation"]


def test_cron_combined_additions_emit_one_finding_for_each_rule():
    findings = _cron_findings_for_additions(
        "17 3 * * * root /bin/echo normal-fixture\n"
        "23 4 * * * root /bin/echo 'curl inert-fixture'\n",
    )

    assert len(findings) == 2
    assert {(item["rule_id"], item["change_type"], item["severity"], item["attack_id"])
            for item in findings} == {
        ("R04", "new_cron_entry", "Medium", "T1053.003"),
        ("R05", "suspicious_cron", "Critical", "T1053.003"),
    }
    assert all(item["explanation"] for item in findings)


def test_cron_multiple_additions_matching_each_rule_do_not_duplicate_findings():
    findings = _cron_findings_for_additions(
        "17 3 * * * root /bin/echo normal-one\n"
        "18 3 * * * root /bin/echo normal-two\n"
        "23 4 * * * root /bin/echo 'curl inert-one'\n"
        "24 4 * * * root /bin/echo 'wget inert-two'\n",
    )

    assert [item["rule_id"] for item in findings].count("R04") == 1
    assert [item["rule_id"] for item in findings].count("R05") == 1
    assert len(findings) == 2
