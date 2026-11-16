import hashlib

from integritywatch.scanner import scan_directory


def test_scanner_reads_files_from_temporary_directory(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    content = "IntegrityWatch scanner test\\n"
    sample = lab / "sample.txt"
    sample.write_text(content, encoding="utf-8")

    result = scan_directory(lab)

    assert "sample.txt" in result["files"]
    assert result["files"]["sample.txt"]["sha256"] == hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()
    assert result["files"]["sample.txt"]["size"] == len(content.encode("utf-8"))
    assert not result["errors"]
