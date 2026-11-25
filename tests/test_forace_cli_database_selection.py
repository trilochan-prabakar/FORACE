from forace.cli import _parser


def test_verify_accepts_explicit_database_path():
    args = _parser().parse_args(["verify", "--db", "custom.sqlite"])
    assert args.db == "custom.sqlite"


def test_init_accepts_explicit_database_path():
    args = _parser().parse_args(["init", "lab", "--db", "custom.sqlite"])
    assert args.db == "custom.sqlite"
