import os
import requests
import json
import anthropic

class LLMClient:
    """
    Dual-mode LLM client: Local via Ollama or Cloud API via Anthropic.
    """
    def __init__(self, mode: str = "ollama", model_name: str = None, base_url: str = "http://localhost:11434"):
        self.mode = mode
        self.base_url = base_url
        if self.mode == "ollama":
            self.model_name = model_name or "qwen2.5-coder:7b"
        elif self.mode == "anthropic":
            self.model_name = model_name or "claude-3-5-sonnet-20241022"
            self.api_key = os.getenv("ANTHROPIC_API_KEY")
            if not self.api_key:
                raise ValueError("ANTHROPIC_API_KEY environment variable is required for anthropic mode.")
            self.client = anthropic.Anthropic(api_key=self.api_key)
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        if self.mode == "ollama":
            return self._generate_ollama(prompt, system_prompt)
        elif self.mode == "anthropic":
            return self._generate_anthropic(prompt, system_prompt)
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

    def _generate_ollama(self, prompt: str, system_prompt: str) -> str:
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

    def _generate_anthropic(self, prompt: str, system_prompt: str) -> str:
        try:
            response = self.client.messages.create(
                model=self.model_name,
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        except Exception as e:
            return f"Error communicating with Anthropic: {e}"

    def get_embeddings(self, text: str) -> list[float]:
        """
        Retrieves embeddings for a given text from the local LLM.
        """
        url = f"{self.base_url}/api/embeddings"
        payload = {
            "model": self.model_name if self.mode == "ollama" else "qwen2.5-coder:7b",
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
    client = LLMClient(mode="ollama")
    print(client.generate("Test prompt - Reply 'Hello World' if working."))
