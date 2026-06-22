import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent.parent

class Settings:
    # Paths
    ART_ATOMICS_PATH: str = os.getenv("ART_ATOMICS_PATH", str(BASE_DIR / "atomics"))
    RESULTS_DIR: str = os.getenv("RESULTS_DIR", str(BASE_DIR / "results"))

    # Nmap port scanning
    NMAP_PATH: str = os.getenv("NMAP_PATH", "")
    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "600"))

    # Agent
    MAX_AGENT_ITERATIONS: int = int(os.getenv("MAX_AGENT_ITERATIONS", "30"))
    AGENT_TIMEOUT_SECONDS: int = int(os.getenv("AGENT_TIMEOUT_SECONDS", "300"))

    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    PROTONRED_API_KEY: str = os.getenv("PROTONRED_API_KEY", "")

    # Provider keys
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    MISTRAL_API_KEY: str = os.getenv("MISTRAL_API_KEY", "")
    COHERE_API_KEY: str = os.getenv("COHERE_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    TOGETHER_API_KEY: str = os.getenv("TOGETHER_API_KEY", "")
    PERPLEXITY_API_KEY: str = os.getenv("PERPLEXITY_API_KEY", "")
    AZURE_API_KEY: str = os.getenv("AZURE_API_KEY", "")
    AZURE_API_BASE: str = os.getenv("AZURE_API_BASE", "")
    AZURE_API_VERSION: str = os.getenv("AZURE_API_VERSION", "2024-02-01")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    CUSTOM_PROVIDER_BASE_URL: str = os.getenv("CUSTOM_PROVIDER_BASE_URL", "")
    CUSTOM_PROVIDER_API_KEY: str = os.getenv("CUSTOM_PROVIDER_API_KEY", "")

settings = Settings()
