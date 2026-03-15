import subprocess
import os
import shutil

def clone_repo(repo_url: str, target_dir: str) -> str:
    """
    Clones a GitHub repository to a target directory.
    If the directory already exists, it removes it first to ensure a fresh clone.
    """
    if os.path.exists(target_dir):
        print(f"[Utils] Removing existing target directory: {target_dir}")
        shutil.rmtree(target_dir)
    
    print(f"[Utils] Cloning repository {repo_url} to {target_dir}...")
    try:
        subprocess.run(["git", "clone", repo_url, target_dir], check=True, capture_output=True, text=True)
        print(f"[Utils] Successfully cloned repo: {repo_url}")
        return target_dir
    except subprocess.CalledProcessError as e:
        print(f"[Utils] Failed to clone repo: {e.stderr}")
        raise Exception(f"Failed to clone repository: {e.stderr}")
