import ast
import os
import json
from typing import Dict, List, Any

def run_scout(source_code: str, filepath: str) -> dict:
    source = ""
    # "ensure source is assigned to an empty string at the very beginning of the function before any file I/O is attempted, so the except block never references an unbound variable."
    
    try:
        source = source_code
        if not source and filepath and os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
    except Exception as e:
        return {
            "functions": [],
            "classes": [],
            "imports": [],
            "dangerous_patterns": [],
            "structure_summary": f"Failed to read file: {str(e)}",
            "source": source
        }

    if not source:
        return {
            "functions": [],
            "classes": [],
            "imports": [],
            "dangerous_patterns": [],
            "structure_summary": "Empty file.",
            "source": source
        }

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return {
            "functions": [],
            "classes": [],
            "imports": [],
            "dangerous_patterns": [],
            "structure_summary": f"Syntax error during parsing: {e}",
            "source": source
        }

    lines = source.split("\n")
    
    classes = []
    functions = []
    imports = []
    dangerous_patterns = []
    
    def get_snippet(node):
        if hasattr(node, "lineno") and node.lineno:
            idx = node.lineno - 1
            if 0 <= idx < len(lines):
                return lines[idx].strip()
        return ""

    class ScoutVisitor(ast.NodeVisitor):
        def visit_ClassDef(self, node):
            methods = []
            for item in node.body:
                if isinstance(item, ast.FunctionDef) or isinstance(item, ast.AsyncFunctionDef):
                    methods.append(item.name)
            classes.append({
                "name": node.name,
                "start_line": node.lineno,
                "methods": methods
            })
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            self._handle_function(node)
            
        def visit_AsyncFunctionDef(self, node):
            self._handle_function(node)

        def _handle_function(self, node):
            args = [arg.arg for arg in node.args.args]
            if node.args.vararg: args.append("*" + node.args.vararg.arg)
            if node.args.kwarg: args.append("**" + node.args.kwarg.arg)
            
            has_return = any(isinstance(n, ast.Return) for n in ast.walk(node))
            end_line = getattr(node, "end_lineno", node.lineno)
            
            functions.append({
                "name": node.name,
                "start_line": node.lineno,
                "end_line": end_line,
                "arguments": args,
                "has_return": has_return
            })
            
            local_concat_vars = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Assign):
                    is_concat = False
                    val = n.value
                    if isinstance(val, ast.JoinedStr):
                        is_concat = True
                    elif isinstance(val, ast.BinOp) and isinstance(val.op, (ast.Add, ast.Mod)):
                        is_concat = True
                    elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "format":
                        is_concat = True
                    
                    if is_concat:
                        for t in n.targets:
                            if isinstance(t, ast.Name):
                                local_concat_vars.add(t.id)

            for n in ast.walk(node):
                if isinstance(n, ast.Call):
                    func_name = ""
                    val_id = ""
                    if isinstance(n.func, ast.Name):
                        func_name = n.func.id
                    elif isinstance(n.func, ast.Attribute):
                        func_name = n.func.attr
                        if isinstance(n.func.value, ast.Name):
                            val_id = n.func.value.id

                    snippet = get_snippet(n)
                    lineno = getattr(n, 'lineno', 0)

                    if func_name in ["execute", "executemany"]:
                        for arg in n.args:
                            if isinstance(arg, ast.Name) and arg.id in local_concat_vars:
                                dangerous_patterns.append({"pattern_type": "sql_string_concat", "line_number": lineno, "source_snippet": snippet})
                            elif isinstance(arg, ast.JoinedStr) or (isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod))):
                                dangerous_patterns.append({"pattern_type": "sql_string_concat", "line_number": lineno, "source_snippet": snippet})

                    if func_name == "system" and val_id == "os":
                        dangerous_patterns.append({"pattern_type": "subprocess_call", "line_number": lineno, "source_snippet": snippet})
                    elif val_id == "subprocess" or func_name in ["Popen", "call", "check_call", "check_output", "run"]:
                        if "subprocess" in snippet or func_name in ["Popen", "system"]:
                            if not any(p["pattern_type"] == "subprocess_call" and p["line_number"] == lineno for p in dangerous_patterns):
                                dangerous_patterns.append({"pattern_type": "subprocess_call", "line_number": lineno, "source_snippet": snippet})

                    if func_name == "eval":
                        dangerous_patterns.append({"pattern_type": "eval_call", "line_number": lineno, "source_snippet": snippet})
                    if func_name == "exec":
                        dangerous_patterns.append({"pattern_type": "exec_call", "line_number": lineno, "source_snippet": snippet})

                    if val_id == "pickle" and func_name in ["loads", "load"]:
                        dangerous_patterns.append({"pattern_type": "pickle_load", "line_number": lineno, "source_snippet": snippet})

                    if val_id == "hashlib" and func_name == "md5":
                        dangerous_patterns.append({"pattern_type": "md5_hash", "line_number": lineno, "source_snippet": snippet})

                    if val_id == "random":
                        dangerous_patterns.append({"pattern_type": "insecure_random", "line_number": lineno, "source_snippet": snippet})

            self.generic_visit(node)

        def visit_Import(self, node):
            for alias in node.names:
                imports.append({
                    "module": alias.name,
                    "alias": alias.asname,
                    "is_from_import": False
                })
            self.generic_visit(node)

        def visit_ImportFrom(self, node):
            mod = node.module or ""
            for alias in node.names:
                imports.append({
                    "module": f"{mod}.{alias.name}",
                    "alias": alias.asname,
                    "is_from_import": True
                })
            self.generic_visit(node)

        def visit_Assign(self, node):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(kw in name_lower for kw in ["password", "secret", "api_key", "token"]):
                            dangerous_patterns.append({
                                "pattern_type": "hardcoded_string_credential",
                                "line_number": node.lineno,
                                "source_snippet": get_snippet(node)
                            })
            self.generic_visit(node)

    visitor = ScoutVisitor()
    visitor.visit(tree)

    # ------------------------------------------------------------------
    # Module-level scan: the ScoutVisitor only walks inside function/class
    # bodies.  This second pass covers dangerous calls that appear at
    # module scope (e.g. `os.system('ls')` written directly in a script).
    # ------------------------------------------------------------------
    # Track which (pattern_type, lineno) pairs were already found inside
    # functions so we don't double-count them.
    _visitor_sigs = set(
        (p["pattern_type"], p.get("line_number", 0)) for p in dangerous_patterns
    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = ""
        val_id = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                val_id = node.func.value.id

        lineno = getattr(node, "lineno", 0)
        snippet = lines[lineno - 1].strip() if lineno and 0 < lineno <= len(lines) else ""

        candidate = None
        if func_name == "system" and val_id == "os":
            candidate = {"pattern_type": "subprocess_call", "line_number": lineno, "source_snippet": snippet}
        elif val_id == "subprocess" or func_name in ["Popen", "call", "check_call", "check_output", "run"]:
            if "subprocess" in snippet or func_name in ["Popen", "system"]:
                candidate = {"pattern_type": "subprocess_call", "line_number": lineno, "source_snippet": snippet}
        elif func_name == "eval":
            candidate = {"pattern_type": "eval_call", "line_number": lineno, "source_snippet": snippet}
        elif func_name == "exec":
            candidate = {"pattern_type": "exec_call", "line_number": lineno, "source_snippet": snippet}
        elif val_id == "pickle" and func_name in ["loads", "load"]:
            candidate = {"pattern_type": "pickle_load", "line_number": lineno, "source_snippet": snippet}
        elif val_id == "hashlib" and func_name == "md5":
            candidate = {"pattern_type": "md5_hash", "line_number": lineno, "source_snippet": snippet}

        if candidate:
            sig = (candidate["pattern_type"], candidate["line_number"])
            if sig not in _visitor_sigs:
                _visitor_sigs.add(sig)
                dangerous_patterns.append(candidate)
    # ------------------------------------------------------------------

    unique_imports = list(set([imp["module"].split(".")[0] for imp in imports]))
    
    def normalize_finding(f):
        f["severity"] = str(f.get("severity") or f.get("chakra_severity") or "LOW").upper()
        f["cwe"] = str(f.get("cwe") or f.get("cwe_id") or "CWE-UNKNOWN")
        f["message"] = str(f.get("message") or f.get("description") or "Security finding detected")
        f["line"] = int(f.get("line") or f.get("line_number") or 0)
        return f

    seen = set()
    deduped = []
    for dp in dangerous_patterns:
        dp = normalize_finding(dp)
        sig = (dp["pattern_type"], dp.get("line_number", 0))
        if sig not in seen:
            seen.add(sig)
            deduped.append(dp)
    dangerous_patterns = deduped

    framework = "Python module"
    if "flask" in unique_imports: framework = "Flask web application"
    elif "django" in unique_imports: framework = "Django web application"
    elif "fastapi" in unique_imports: framework = "FastAPI application"
    
    summary_parts = [f"This file defines a {framework} with {len(classes)} classes and {len(functions)} functions."]
    if unique_imports:
        if len(unique_imports) > 3:
            summary_parts.append(f"It imports libraries including {', '.join(unique_imports[:3])}, alongside others.")
        else:
            summary_parts.append(f"It imports {', '.join(unique_imports)}.")
    
    if dangerous_patterns:
        sql_count = sum(1 for p in dangerous_patterns if p["pattern_type"] == "sql_string_concat")
        cred_count = sum(1 for p in dangerous_patterns if p["pattern_type"] == "hardcoded_string_credential")
        exec_count = sum(1 for p in dangerous_patterns if p["pattern_type"] in ["exec_call", "eval_call", "subprocess_call"])
        pickle_count = sum(1 for p in dangerous_patterns if p["pattern_type"] == "pickle_load")
        
        flags = []
        if sql_count > 0: flags.append(f"{sql_count} instance(s) of database query construction using string concatenation")
        if cred_count > 0: flags.append("hardcoded credentials")
        if exec_count > 0: flags.append("dynamic execution patterns (exec/eval/subprocess)")
        if pickle_count > 0: flags.append("unsafe deserialization")
        
        if flags:
            summary_parts.append(f"The AST walk uncovered: {', '.join(flags)}.")
            
    summary = " ".join(summary_parts)

    return {
        "filepath": filepath,
        "functions": functions,
        "classes": classes,
        "imports": imports,
        "dangerous_patterns": dangerous_patterns,
        "structure_summary": summary
    }

if __name__ == "__main__":
    demo_path = os.path.normpath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "demo", "chakra_demo_app.py"))
    
    if os.path.exists(demo_path):
        with open(demo_path, "r", encoding="utf-8") as f:
            code = f.read()
            
        result = run_scout(code, demo_path)
        print("AST Walker Found these Vulnerability Patterns:")
        print(json.dumps(result["dangerous_patterns"], indent=2))
        
        types_found = [p["pattern_type"] for p in result["dangerous_patterns"]]
        print(f"\nTotal structure/danger findings: {len(result['dangerous_patterns'])}")
        print(f"Types identified: {set(types_found)}")
        
        summary = result["structure_summary"]
        print(f"\nStructured Summary Component:\n{summary}")
    else:
        print(f"Demo app not found at {demo_path}")
