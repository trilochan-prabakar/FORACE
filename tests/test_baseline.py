from forace.baseline import create_baseline, save_baseline, load_baseline


def test_baseline_save_load_and_overwrite_protection(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "sample.txt").write_text("IntegrityWatch test\\n", encoding="utf-8")

    baseline = create_baseline(lab)
    baseline_path = tmp_path / "baseline.json"

    save_baseline(baseline, baseline_path)
    assert load_baseline(baseline_path) == baseline

    try:
        save_baseline(baseline, baseline_path)
    except FileExistsError:
        pass
    else:
        raise AssertionError("Overwrite protection failed")
