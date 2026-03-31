import os
import requests
import anthropic
import json
import logging
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()
logger = logging.getLogger(__name__)

class LLMClient:
    """
    A single class that abstracts away whether the LLM is Ollama (local) or Anthropic (cloud).
    The rest of the codebase never checks which mode is active.
    """
    def __init__(self):
        self.backend = os.getenv("LLM_BACKEND", "anthropic").lower()
        
        if self.backend == "anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY is required when LLM_BACKEND is anthropic")
            self.client = anthropic.Anthropic(api_key=api_key)
            self.anthropic_model = "claude-sonnet-4-20250514"
        elif self.backend == "ollama":
            self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            self.ollama_model = os.getenv("OLLAMA_MODEL", "codellama:13b")
        else:
            raise ValueError(f"Unsupported LLM_BACKEND: {self.backend}. Must be 'anthropic' or 'ollama'.")

    def complete(self, system_prompt: str, user_prompt: str, expect_json: bool = False):
        """
        Takes system and user prompts and returns the LLM's response.
        If expect_json=True, returns a parsed dict. Otherwise returns a string.
        On network errors, returns a structured error dict.
        """
        json_instruction = "Respond only with valid JSON. No preamble, no markdown fences, no explanation outside the JSON structure."
        
        if expect_json:
            system_prompt = f"{system_prompt}\n\n{json_instruction}"

        # 1. Dispatch Request
        if self.backend == "anthropic":
            raw_response = self._complete_anthropic(system_prompt, user_prompt)
        elif self.backend == "ollama":
            raw_response = self._complete_ollama(system_prompt, user_prompt)
        else:
            return {"error": f"Unknown backend state: {self.backend}"}

        # 2. Check for Network Errors
        if isinstance(raw_response, dict) and "error" in raw_response:
            return raw_response

        # 3. Handle Output format
        if expect_json:
            return self._parse_json(raw_response)
        
        return raw_response

    def _complete_anthropic(self, system_prompt: str, user_prompt: str):
        try:
            response = self.client.messages.create(
                model=self.anthropic_model,
                max_tokens=2000,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
                timeout=60.0
            )
            return response.content[0].text
        except Exception as e:
            return {"error": f"Network Error (Anthropic): {str(e)}"}

    def _complete_ollama(self, system_prompt: str, user_prompt: str):
        url = f"{self.ollama_host}/api/generate"
        
        # Concatenation of system and user prompts with a clear separator
        full_prompt = f"System:\n{system_prompt}\n\nUser:\n{user_prompt}"
        
        payload = {
            "model": self.ollama_model,
            "prompt": full_prompt,
            "stream": False
        }
        
        try:
            response = requests.post(url, json=payload, timeout=60.0)
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            return {"error": f"Network Error (Ollama): {str(e)}"}

    def _parse_json(self, text: str):
        text = text.strip()
        
        # Clean up stray markdown fences silently
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
            
        if text.endswith("```"):
            text = text[:-3]
            
        text = text.strip()
        
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            # Note: logging raw text so developers can observe why it failed without crashing server
            logger.error(f"JSON Parsing failed: {e}\nRaw Response:\n{text}")
            return {}

if __name__ == "__main__":
    # Test initialization
    try:
        client = LLMClient()
        print(f"Successfully initialized LLMClient with backend: {client.backend}")
    except Exception as e:
        print(f"Initialization Failed: {e}")
