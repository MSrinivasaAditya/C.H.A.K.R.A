import requests
import json

class LocalLLMClient:
    """
    Zero-egress LLM client for interacting with a local Ollama or vLLM instance.
    Defaults to assuming Ollama happens to be running on localhost:11434.
    """
    def __init__(self, model_name: str = "qwen2.5-coder:7b", base_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.base_url = base_url

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """
        Sends a generation request to the local LLM.
        """
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False
        }
        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except requests.exceptions.RequestException as e:
            return f"Error communicating with local LLM: {e}"

    def get_embeddings(self, text: str) -> list[float]:
        """
        Retrieves embeddings for a given text from the local LLM.
        """
        url = f"{self.base_url}/api/embeddings"
        payload = {
            "model": self.model_name,
            "prompt": text
        }
        try:
            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("embedding", [])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching embeddings: {e}")
            return []

if __name__ == "__main__":
    client = LocalLLMClient()
    print(client.generate("Test prompt - Reply 'Hello World' if working."))
