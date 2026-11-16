
from integritywatch.baseline import (
    create_baseline,
    save_baseline,
    load_baseline,
)
from tempfile import TemporaryDirectory

BASELINE_PATH = "data/baseline.json"

print("\nIntegrityWatch Lite - Baseline Test")
print("-----------------------------------")

# Generate baseline from the sandbox.
baseline = create_baseline("lab")

print("Files in baseline:", len(baseline["files"]))

with TemporaryDirectory() as temporary_directory:
    test_path = f"{temporary_directory}/baseline.json"
    saved_path = save_baseline(baseline, test_path)
    print("Baseline saved:", saved_path)
    # Load the saved baseline.
    loaded_baseline = load_baseline(test_path)
    print("Baseline loaded successfully.")
    assert loaded_baseline == baseline
    print("Baseline contents verified.")
    # Test overwrite protection.
    try:
        save_baseline(baseline, test_path)
    except FileExistsError:
        print("Overwrite protection: PASSED")
    else:
        raise AssertionError("Overwrite protection failed")

print("\nAll baseline tests passed.")
