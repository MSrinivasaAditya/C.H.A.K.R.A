from typing import Any, Dict
from agents.base import BaseAgent
from parsers.ast_analyzer import ASTAnalyzer
from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager
import hashlib

class ScoutAgent(BaseAgent):
    """
    Scout maps the architecture, parses AST, and stores embedded logic into ChromaDB.
    """
    def __init__(self, target_dir: str, llm_client: LocalLLMClient, db_manager: ChromaDBManager):
        super().__init__(llm_client, db_manager)
        self.analyzer = ASTAnalyzer(target_dir)

    def _hash_file(self, content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()

    def act(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Populate the Vector DB with analyzed file chunks.
        """
        print("[Scout] Starting architecture mapping...")
        parsed_files = self.analyzer.map_repository()
        
        file_list = []
        for file_data in parsed_files:
            file_path = file_data["file"]
            source = file_data["source"]
            chunk_id = file_path

            print(f"[Scout] Adding {file_path} to VectorDB...")
            
            # Metadata describes the file's architectural role
            metadata = {
                "file": file_path,
                "classes": ",".join(file_data.get("classes", [])),
                "functions": ",".join(file_data.get("functions", []))
            }

            self.db.add_code_chunk(chunk_id, source, metadata)
            file_list.append(file_path)

        context["mapped_files"] = file_list
        print(f"[Scout] Finished mapping {len(file_list)} files.")
        return context

if __name__ == "__main__":
    llm = LocalLLMClient()
    db = ChromaDBManager()
    agent = ScoutAgent(".", llm, db)
    agent.act({})
