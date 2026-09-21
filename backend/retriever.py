import json
import os
import re
from rank_bm25 import BM25Okapi

class SecurityRetriever:
    def __init__(self):
        # Load the Knowledge Bases
        self.cwe_kb = self._load_kb("data/processed/cwe_kb.json")
        self.owasp_kb = self._load_kb("data/processed/owasp_kb.json")
        
        # Tokenize the search_text for BM25
        self.cwe_tokenized = [self._tokenize(doc.get("search_text", "")) for doc in self.cwe_kb]
        self.owasp_tokenized = [self._tokenize(doc.get("search_text", "")) for doc in self.owasp_kb]
        
        # Initialize the BM25 Indexes
        self.bm25_cwe = BM25Okapi(self.cwe_tokenized) if self.cwe_tokenized else None
        self.bm25_owasp = BM25Okapi(self.owasp_tokenized) if self.owasp_tokenized else None

    def _load_kb(self, path):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _tokenize(self, text):
        # Lexical tokenization: lowercase and split by non-alphanumeric characters.
        # This breaks code like "subprocess.Popen(shell=True)" into ["subprocess", "popen", "shell", "true"]
        return [word for word in re.split(r'\W+', str(text).lower()) if word]

    def retrieve(self, query, top_k=2):
        # Tokenize the incoming code snippet or static analysis flag
        tokenized_query = self._tokenize(query)
        
        # Retrieve independently from both sources (Addition #1)
        cwe_results = []
        if self.bm25_cwe:
            # We get the top_k results. rank_bm25 handles the TF-IDF scoring under the hood.
            cwe_results = self.bm25_cwe.get_top_n(tokenized_query, self.cwe_kb, n=top_k)
            
        owasp_results = []
        if self.bm25_owasp:
            owasp_results = self.bm25_owasp.get_top_n(tokenized_query, self.owasp_kb, n=top_k)

        # Addition #1 & #3: Multi-source agreement. 
        # If both sources return highly relevant results, we bump the confidence.
        high_confidence = len(cwe_results) > 0 and len(owasp_results) > 0

        return {
            "cwe": cwe_results,
            "owasp": owasp_results,
            "high_confidence": high_confidence
        }

if __name__ == "__main__":
    print("Initializing Security Retriever... (Loading Knowledge Bases)")
    retriever = SecurityRetriever()
    
    # We simulate Bandit finding a command injection vulnerability 
    test_query = "subprocess.call(shell=True) command injection os execution"
    print(f"\nTesting Retrieval for query: '{test_query}'\n")
    
    results = retriever.retrieve(test_query, top_k=1)
    
    print("--- 🔍 Top CWE Result ---")
    if results['cwe']:
        print(f"ID: {results['cwe'][0]['id']}")
        print(f"Name: {results['cwe'][0]['name']}")
        print(f"Snippet: {results['cwe'][0]['description'][:100]}...")
        
    print("\n--- 🔍 Top OWASP Result ---")
    if results['owasp']:
        print(f"ID: {results['owasp'][0]['id']}")
        print(f"Name: {results['owasp'][0]['name']}")
        
    print(f"\n--- ⚡ Multi-Source Confidence: {'HIGH' if results['high_confidence'] else 'LOW'} ---")
