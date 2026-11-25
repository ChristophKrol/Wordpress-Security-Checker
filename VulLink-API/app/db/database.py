from neo4j import GraphDatabase
import logging
from typing import Any, Dict, List
import os
from dotenv import load_dotenv
import platform
from pathlib import Path

# Load environment variables
IS_LINUX = platform.system().lower() == "linux"
api_dir = Path(__file__).resolve().parent.parent.parent
for env_name in (".env", ".env.development"):  # .env wins; .env.development kept for old setups
    load_dotenv(dotenv_path=api_dir / env_name)
if IS_LINUX:
    load_dotenv()

class Neo4jDatabase:
    def __init__(self):
        uri = os.getenv("NEO4J_URI")
        user = os.getenv("NEO4J_USER")
        password = os.getenv("NEO4J_PASSWORD")
        assert uri and user and password, "NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD must be set"
        logging.info(f"Connecting to Neo4j at {uri} as {user}")
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            self.driver.verify_connectivity()
            logging.info("Connected to Neo4j database")
        except Exception as e:
            logging.error(f"Failed to connect to Neo4j database: {e}")
            raise
    
    def close(self):
        if self.driver:
            self.driver.close()
    
    def execute_query(self, query: str, params: Dict = None) -> List[Dict[str, Any]]:
        """Execute a Cypher query and return the results"""
        try:
            with self.driver.session() as session:
                result = session.run(query, params)
                return [dict(record) for record in result]
        except Exception as e:
            logging.error(f"Query execution failed: {e}, Query: {query}, Params: {params}")
            raise

# Create a singleton instance
db = Neo4jDatabase()

def get_db():
    """Dependency for FastAPI endpoints"""
    try:
        yield db
    finally:
        # We don't close the connection after each request
        # as Neo4j driver manages connection pooling
        pass 