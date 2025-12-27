import subprocess

def get_git_version():
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--dirty", "--always"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown"
print(get_git_version())    
