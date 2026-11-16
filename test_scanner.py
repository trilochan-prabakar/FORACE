
from integritywatch.scanner import scan_directory

result = scan_directory("lab")

print("\nIntegrityWatch Lite - Scanner Results")
print("--------------------------------------")

print("Files scanned:", len(result["files"]))
print("Errors:", len(result["errors"]))

for path, details in result["files"].items():

    print(f"\nFile: {path}")
    print("SHA-256:", details["sha256"])
    print("Size:", details["size"])
    print("Permissions:", oct(details["mode"]))
    print("UID:", details["uid"])
    print("GID:", details["gid"])
    print("Snapshot available:", details["snapshot"] is not None)

if result["errors"]:
    print("\nScanning errors:")

    for path, error in result["errors"].items():
        print(path, ":", error)
