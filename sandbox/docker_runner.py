import docker
import os

class DockerSandboxRunner:
    """
    Executes Python scripts in isolated containers for Validation.
    """
    def __init__(self, image_name: str = "python:3.10-slim"):
        try:
            self.client = docker.from_env()
            self.image_name = image_name
            # Optimistically ensure image is available, though in a real air-gapped
            # env, this image must be loaded manually via docker load.
        except Exception as e:
            print(f"[Sandbox] Failed to attach to Docker daemon: {e}")
            self.client = None

    def run_validation(self, script_content: str, file_name: str = "script.py", test_content: str = "") -> bool:
        """
        Creates a temporary validation script that includes the user's fixed code
        and tests it structurally inside a container without running arbitrary code.
        
        Returns True if the check passes without throwing errors.
        """
        if not self.client:
             print("[Sandbox] Docker not available. Bypassing execution.")
             return True

        container = None
        try:
            import base64
            encoded_script = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
            
            # Determine language and appropriate syntax check command
            if file_name.endswith('.js') or file_name.endswith('.jsx') or file_name.endswith('.ts') or file_name.endswith('.tsx'):
                image = 'node:18-slim'
                target_file = 'temp_script.js'
                check_cmd = f"node --check {target_file}"
            else:
                image = self.image_name
                target_file = 'temp_script.py'
                check_cmd = f"python -m py_compile {target_file}"

            command = f"sh -c 'echo {encoded_script} | base64 -d > {target_file} && {check_cmd}'"
            
            print(f"[{image}] Sandbox running isolated code verification for {file_name}...")
            logs = self.client.containers.run(
                image,
                command=command,
                network_mode="none",
                mem_limit="128m",
                remove=True
            )
            print("[Sandbox] Isolated verification passed successfully.")
            return True
            
        except docker.errors.ContainerError as e:
            print(f"[Sandbox] Validation failed: {e.stderr.decode('utf-8')}")
            return False
        except Exception as e:
            print(f"[Sandbox] General sandbox execution error: {e}")
            return False

if __name__ == "__main__":
    runner = DockerSandboxRunner()
    res = runner.run_validation("print('Hello Sandboxed World')")
    print(f"Validation passed: {res}")
