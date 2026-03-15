import chromadb
from typing import List, Dict, Any
from core.llm_client import LocalLLMClient

class ChromaDBManager:
    """
    Manages local ChromaDB instance to guarantee zero-egress for vectors representing code chunks.
    """
    def __init__(self, persist_directory: str = "./db", llm_client: LocalLLMClient = None):
        self.persist_directory = persist_directory
        self.client = chromadb.PersistentClient(path=self.persist_directory)
        self.llm_client = llm_client or LocalLLMClient()
        self.collection_name = "codebase_context"
        self.collection = self.client.get_or_create_collection(name=self.collection_name)

    def add_code_chunk(self, chunk_id: str, code: str, metadata: dict):
        """
        Embeds a piece of code and adds it to the ChromaDB.
        """
        embedding = self.llm_client.get_embeddings(code)
        
        if not embedding:
            raise ValueError(f"Failed to generate embedding for {chunk_id}")

        self.collection.upsert(
            ids=[chunk_id],
            embeddings=[embedding],
            documents=[code],
            metadatas=[metadata]
        )

    def search_similar(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieves the most semantically similar code snippets to a search query.
        """
        query_embedding = self.llm_client.get_embeddings(query)
        if not query_embedding:
             return []

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results
        )

        output = []
        if results and results.get("documents"):
            for doc, meta, doc_id in zip(results["documents"][0], results["metadatas"][0], results["ids"][0]):
                output.append({
                    "id": doc_id,
                    "code": doc,
                    "metadata": meta
                })
        return output

    def clear(self):
        """
        Deletes the entire collection.
        """
        try:
             self.client.delete_collection(name=self.collection_name)
             self.collection = self.client.create_collection(name=self.collection_name)
        except ValueError:
             pass

if __name__ == "__main__":
    db = ChromaDBManager()
    print("ChromaDB manager initialized.")
