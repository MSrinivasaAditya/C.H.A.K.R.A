from typing import Any, Dict
from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager

class BaseAgent:
    """
    Base class for all Security Squad agents.
    Provides shared configuration and state access.
    """
    def __init__(self, llm_client: LocalLLMClient, db_manager: ChromaDBManager):
        self.llm = llm_client
        self.db = db_manager

    def act(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main execution loop for the agent. Returns modified context.
        To be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement act()")
