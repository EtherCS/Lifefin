import os


CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PAR_DIR = os.path.dirname(CUR_DIR)
RELEASE_DIR = os.path.join(PAR_DIR, "target", "release")
MYSTICETI_PATH = os.path.join(RELEASE_DIR, "mysticeti")


def get_mysticeti_path():
    return MYSTICETI_PATH


def check_mysticeti_path():
    return os.path.exists(MYSTICETI_PATH)


def build_mysticeti():
    os.system(f"cd {PAR_DIR} && cargo build --release")
    if not check_mysticeti_path():
        raise Exception(f"Failed to build Mysticeti. {MYSTICETI_PATH} does not exist.")
    print(f"Mysticeti built successfully at {MYSTICETI_PATH}")
    return MYSTICETI_PATH


def clean():
    # clean up
    os.system("rm attack.v* || true")
    os.system("rm -rf dryattackrun-validator-* || true")
    # stop any running tmux sessions
    os.system("tmux kill-server || true")
