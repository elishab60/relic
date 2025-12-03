import os
from typing import List
from pydantic import BaseModel, Field

class Settings(BaseModel):
    DEFAULT_TIMEOUT: float = Field(default=10.0, description="Default HTTP timeout in seconds")
    MAX_RETRIES: int = Field(default=2, description="Max retries for HTTP requests")
    USER_AGENT: str = Field(default="AuditAI-Security-Scanner/1.0", description="User-Agent string")
    SCAN_PORTS: List[int] = Field(
        default=[21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443], 
        description="Ports to scan"
    )
    MAX_CRAWL_URLS: int = Field(default=20, description="Max URLs to crawl")
    RATE_LIMIT_DELAY: float = Field(default=0.3, description="Delay between requests in seconds")
    PORT_SCAN_TIMEOUT: float = Field(default=1.0, description="Timeout for port scan in seconds")

    RESPECT_ROBOTS: bool = Field(default=False, description="Whether to respect robots.txt")
    CRAWL_SCOPE: str = Field(default="subdomains", description="Crawl scope: 'host', 'subdomains', 'path'")
    STATIC_EXTENSIONS: List[str] = Field(
        default=["css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot", "mp4", "webm", "mp3", "pdf", "zip", "tar", "gz"],
        description="Extensions to skip during crawl"
    )
    BLIND_SQLI_THRESHOLD: float = Field(default=5.0, description="Threshold in seconds for time-based SQLi detection")

    # Adaptive Rate Limiting & Safety
    ADAPTIVE_RATE_LIMIT: bool = Field(default=True, description="Enable adaptive rate limiting")
    MAX_REQUESTS_PER_MINUTE: int = Field(default=600, description="Max requests per minute per host")
    ERROR_THRESHOLD: int = Field(default=10, description="Consecutive errors to trigger backoff")
    LATENCY_THRESHOLD: float = Field(default=2.0, description="Latency threshold (seconds) to trigger backoff")
    
    # Vulnerability Detection Limits
    XSS_PAYLOAD_LIMIT: int = Field(default=5, description="Max XSS payloads per parameter for Content pages")
    SQLI_TIME_THRESHOLD_AVG: float = Field(default=3.0, description="Average time delay (seconds) to suspect Blind SQLi")

    # AI Settings
    OPENROUTER_API_KEY: str = Field(default="", description="OpenRouter API Key")
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434", description="Ollama Base URL")
    OLLAMA_MODEL: str = Field(default="gpt-oss:20b", description="Ollama Model Name")
    OPENROUTER_MODEL: str = Field(default="x-ai/grok-4.1-fast:free", description="OpenRouter Model Name")

    @classmethod
    def load(cls) -> "Settings":
        # Basic env var loading for key fields
        return cls(
            DEFAULT_TIMEOUT=float(os.getenv("SCANNER_DEFAULT_TIMEOUT", 10.0)),
            MAX_RETRIES=int(os.getenv("SCANNER_MAX_RETRIES", 2)),
            USER_AGENT=os.getenv("SCANNER_USER_AGENT", "AuditAI-Security-Scanner/1.0"),
            MAX_CRAWL_URLS=int(os.getenv("SCANNER_MAX_CRAWL_URLS", 20)),
            RATE_LIMIT_DELAY=float(os.getenv("SCANNER_RATE_LIMIT_DELAY", 0.3)),
            PORT_SCAN_TIMEOUT=float(os.getenv("SCANNER_PORT_SCAN_TIMEOUT", 1.0)),
            RESPECT_ROBOTS=os.getenv("SCANNER_RESPECT_ROBOTS", "false").lower() == "true",
            CRAWL_SCOPE=os.getenv("SCANNER_CRAWL_SCOPE", "subdomains"),
            BLIND_SQLI_THRESHOLD=float(os.getenv("SCANNER_BLIND_SQLI_THRESHOLD", 5.0)),
            ADAPTIVE_RATE_LIMIT=os.getenv("SCANNER_ADAPTIVE_RATE_LIMIT", "true").lower() == "true",
            MAX_REQUESTS_PER_MINUTE=int(os.getenv("SCANNER_MAX_REQUESTS_PER_MINUTE", 600)),
            ERROR_THRESHOLD=int(os.getenv("SCANNER_ERROR_THRESHOLD", 10)),
            LATENCY_THRESHOLD=float(os.getenv("SCANNER_LATENCY_THRESHOLD", 2.0)),
            XSS_PAYLOAD_LIMIT=int(os.getenv("SCANNER_XSS_PAYLOAD_LIMIT", 5)),
            SQLI_TIME_THRESHOLD_AVG=float(os.getenv("SCANNER_SQLI_TIME_THRESHOLD_AVG", 3.0)),
            
            # AI Settings
            OPENROUTER_API_KEY=os.getenv("OPENROUTER_API_KEY", ""),
            OLLAMA_BASE_URL=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            OLLAMA_MODEL=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
            OPENROUTER_MODEL=os.getenv("OPENROUTER_MODEL", "x-ai/grok-4.1-fast:free"),
        )

settings = Settings.load()
