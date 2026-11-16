from pathlib import Path
import argparse
import os


LAB_DIR = Path("lab")


# Sample Linux-like configuration files.
SAMPLE_FILES = {
    "etc/ssh/sshd_config": (
        "# IntegrityWatch Lite - Sample SSH Configuration\n"
        "Port 22\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "PubkeyAuthentication yes\n"
        "PermitEmptyPasswords no\n"
    ),

    "etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "labuser:x:1000:1000:Lab User:/home/labuser:/bin/bash\n"
        "svc-backup:x:998:998:Backup Service:/var/lib/backup:/usr/sbin/nologin\n"
    ),

    "etc/sudoers": (
        "# IntegrityWatch Lite - Sample Sudoers\n"
        "root ALL=(ALL:ALL) ALL\n"
        "labuser ALL=(ALL) /usr/bin/systemctl status\n"
    ),

    "etc/crontab": (
        "# IntegrityWatch Lite - Sample Crontab\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/bin:/bin\n"
        "0 2 * * * root echo 'Daily lab backup check'\n"
    ),

    "etc/systemd/system/backup.service": (
        "[Unit]\n"
        "Description=IntegrityWatch Lite Sample Backup Service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/echo Sample backup service executed\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ),

    "home/user/.ssh/authorized_keys": (
        "# Synthetic sample public key - not a real user credential\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG5vcmVhbGtleWZvcmxhYg== lab-key\n"
    ),

    "var/log/auth.log": (
        "Nov 01 10:00:01 lab-server sshd[1001]: Server listening on port 22.\n"
        "Nov 01 10:05:12 lab-server sshd[1002]: Accepted publickey for labuser.\n"
        "Nov 01 10:10:30 lab-server sshd[1003]: Failed password for invalid user guest.\n"
    ),
}


# Simulated Linux permissions.
FILE_MODES = {
    "etc/ssh/sshd_config": 0o644,
    "etc/passwd": 0o644,
    "etc/sudoers": 0o440,
    "etc/crontab": 0o644,
    "etc/systemd/system/backup.service": 0o644,
    "home/user/.ssh/authorized_keys": 0o600,
    "var/log/auth.log": 0o640,
}


def create_lab(force=False):
    """Generate the controlled Linux-like sandbox."""

    # Check whether generated files already exist.
    existing_files = [
        LAB_DIR / relative_path
        for relative_path in SAMPLE_FILES
        if (LAB_DIR / relative_path).exists()
    ]

    if existing_files and not force:
        print("ERROR: Sample files already exist.")
        print("Use --force to regenerate the sample files.")
        return False

    for relative_path, content in SAMPLE_FILES.items():

        # Construct the complete file path.
        file_path = LAB_DIR / relative_path

        # Create parent directories if necessary.
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write the sample configuration.
        file_path.write_text(content, encoding="utf-8")

        # Apply simulated Linux permissions.
        os.chmod(file_path, FILE_MODES[relative_path])

        print(f"[CREATED] {file_path}")

    print("\nIntegrityWatch Lite sandbox created successfully.")
    print(f"Total files generated: {len(SAMPLE_FILES)}")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate the IntegrityWatch Lite sandbox."
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate existing sample files."
    )

    args = parser.parse_args()

    create_lab(force=args.force)


if __name__ == "__main__":
    main()
