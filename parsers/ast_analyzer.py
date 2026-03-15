import ast
import os
from typing import Dict, List, Tuple, Any

class ASTAnalyzer:
    """
    Parses Python code to build a deterministic representation of the application structure
    used by the Scout and Auditor agents prior to LLM reasoning.
    """
    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    def extract_structure(self, file_path: str) -> Dict[str, Any]:
        """
        Parses a single file to extract classes, functions, and imports.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source)
            
            classes = []
            functions = []
            imports = []

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module if node.module else ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")

            return {
                "file": file_path,
                "classes": classes,
                "functions": functions,
                "imports": imports,
                "source": source
            }
        except Exception as e:
            print(f"Failed to parse {file_path}: {e}")
            return {
                "file": file_path,
                "classes": [],
                "functions": [],
                "imports": [],
                "source": source
            }

    def map_repository(self) -> List[Dict[str, Any]]:
        """
        Walks the target directory, extracting ast structure for every Python file.
        """
        repo_data = []
        for root, _, files in os.walk(self.target_dir):
            # Skip hidden dirs or common non-code folders
            if any(part.startswith('.') or part in ['__pycache__', 'venv', 'env'] for part in root.split(os.sep)):
                continue

            for file in files:
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    data = self.extract_structure(full_path)
                    if data:
                        repo_data.append(data)
        
        return repo_data

if __name__ == "__main__":
    parser = ASTAnalyzer(".")
    result = parser.map_repository()
    for res in result:
        print(f"File: {res.get('file')} | Classes: {len(res.get('classes', []))} | Functions: {len(res.get('functions', []))}")
