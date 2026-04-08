import hashlib

def compute_fingerprints(source_code: str) -> dict:
    """
    Computes a fingerprint for each line of the provided source code.
    Empty lines and lines with only whitespace are assigned a constant hash 'whitespace_line'.
    Other lines are hashed using SHA-256 and the first 16 characters are used.
    
    Returns a dictionary mapping line numbers (1-indexed) to their fingerprint.
    """
    fingerprints = {}
    
    # split('\n') is used to preserve matching line numbers properly
    lines = source_code.split('\n')
    
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            fingerprints[idx] = "whitespace_line"
        else:
            # Generate SHA-256 hash and take the first 16 chars
            line_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
            fingerprints[idx] = line_hash[:16]
            
    return {int(line_num): hash_val for line_num, hash_val in fingerprints.items()}

def compute_changed_range(old_fingerprints: dict, new_fingerprints: dict) -> tuple:
    """
    Computes the padded range of changed lines between old and new state.
    
    Finds every line number where hashes differ or a line exists in one but not the other.
    Returns a tuple of (start_line, end_line) representing the padded range.
    If no lines differ, returns None.
    """
    old_fingerprints = {int(k): v for k, v in old_fingerprints.items()}
    new_fingerprints = {int(k): v for k, v in new_fingerprints.items()}
    changed_lines = []
    
    all_line_numbers = set(old_fingerprints.keys()).union(set(new_fingerprints.keys()))
    
    for line_num in all_line_numbers:
        if old_fingerprints.get(line_num) != new_fingerprints.get(line_num):
            changed_lines.append(line_num)
            
    if not changed_lines:
        return None
        
    min_changed = min(changed_lines)
    max_changed = max(changed_lines)
    
    start_line = min_changed - 5
    end_line = max_changed + 5
    
    # Clamp to valid file bounds
    max_file_line = max(new_fingerprints.keys()) if new_fingerprints else 1
    
    if start_line < 1:
        start_line = 1
        
    if end_line > max_file_line:
        end_line = max_file_line
        
    if start_line > end_line:
        start_line = end_line
        
    return (start_line, end_line)
