from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from core.llm_client import LocalLLMClient
import json

app = FastAPI()

import os
from core.orchestrator import AgentOrchestrator
from core.utils import clone_repo

class CodeAnalysisRequest(BaseModel):
    code: str

class RepoLinkAnalysisRequest(BaseModel):
    repo_url: str

templates = Jinja2Templates(directory="dashboard/templates")

# In a real app we might serve static files. Currently we just template HTML inline.
# app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")

def get_results():
    try:
        with open("dashboard/results.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"summary": {"issues_found": 0, "patches_generated": 0}, "patches": []}

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """
    Renders the local HITL (Human-In-The-Loop) Dashboard showing proposed patches
    and results from the C.H.A.K.R.A air-gapped auditor.
    """
    results = get_results()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "results": results}
    )

@app.post("/analyze")
async def analyze_code(req: CodeAnalysisRequest):
    # Save code to target repo for the squad to scan
    os.makedirs("target_repo_ui", exist_ok=True)
    with open("target_repo_ui/user_code.py", "w") as f:
        f.write(req.code)
        
    orchestrator = AgentOrchestrator("target_repo_ui")
    orchestrator.run_squad()
    
    # Reload the generated results
    results = get_results()
    return results

@app.post("/analyze-repo")
async def analyze_repo(req: RepoLinkAnalysisRequest):
    """
    Clones a GitHub repo and audits it.
    """
    target_dir = os.path.join(os.getcwd(), "target_repo_cloned")
    try:
        clone_repo(req.repo_url, target_dir)
        orchestrator = AgentOrchestrator(target_dir)
        orchestrator.run_squad()
        results = get_results()
        return results
    except Exception as e:
        return {"status": "error", "message": f"Failed to analyze repo: {str(e)}"}

@app.get("/repo-dir")
async def get_repo_dir():
    target_dir = os.path.join(os.getcwd(), "target_repo_cloned")
    if not os.path.exists(target_dir):
        return {"status": "error", "message": "No cloned repository found."}

    def build_tree(dir_path):
        tree = []
        for item in sorted(os.listdir(dir_path)):
            if item == ".git":
                continue
            item_path = os.path.join(dir_path, item)
            if os.path.isdir(item_path):
                tree.append({
                    "name": item,
                    "type": "directory",
                    "children": build_tree(item_path)
                })
            else:
                tree.append({
                    "name": item,
                    "type": "file"
                })
        return tree

    try:
        return {"status": "success", "tree": build_tree(target_dir)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/approve/{patch_id}")
async def approve_patch(patch_id: int):
    """
    Endpoint conceptually applies the git-diff to the user's workspace locally.
    In real usage, this would execute `git apply <patch_file>.patch`.
    """
    return {"status": "success", "message": f"Patch {patch_id} scheduled for git apply locally."}

@app.post("/reject/{patch_id}")
async def reject_patch(patch_id: int):
    """
    Endpoint discards the patch without applying.
    """
    return {"status": "discarded", "message": f"Patch {patch_id} permanently rejected."}

if __name__ == "__main__":
    import uvicorn
    # Use 8080 or a safe local port
    uvicorn.run(app, host="127.0.0.1", port=8000)
