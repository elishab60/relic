import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from app.scanner.engine import ScanEngine
from app.scanner.models import ScanResult, ScanLogEntry, Finding
from app.scanner.scope import EndpointClass
from app.constants import ScanStatus

@pytest.fixture
def scan_engine():
    return ScanEngine()

@pytest.mark.asyncio
async def test_scan_engine_initialization(scan_engine):
    """Verify ScanEngine initializes correctly"""
    assert scan_engine.http_client is None
    assert scan_engine.scope_manager is not None

@pytest.mark.asyncio
async def test_scan_normalization_error(scan_engine):
    """Verify handling of normalization errors"""
    with patch("app.scanner.engine.normalize_target", side_effect=Exception("Invalid URL")):
        result = await scan_engine.run_scan("invalid-url")
        assert result.grade == "F"
        assert result.score == 0
        assert result.scan_status == ScanStatus.FAILED
        assert len(result.findings) == 1
        assert result.findings[0].title == "Scan Failed"

@pytest.mark.asyncio
async def test_scan_dns_failure(scan_engine):
    """Verify handling of DNS resolution failure"""
    # Mock normalization
    mock_target_info = MagicMock()
    mock_target_info.full_url = "http://example.com"
    mock_target_info.hostname = "example.com"
    mock_target_info.port = 80
    
    with patch("app.scanner.engine.normalize_target", return_value=mock_target_info), \
         patch("app.scanner.engine.HttpClient") as MockHttpClient:
        
        # Mock HttpClient context manager
        mock_http_client = AsyncMock()
        MockHttpClient.return_value.__aenter__.return_value = mock_http_client
        
        # Mock DNS failure
        with patch("socket.getaddrinfo", side_effect=Exception("DNS Error")):
             result = await scan_engine.run_scan("http://example.com")
             
             # Host Unreachable is High severity (25 penalty) -> Score 75 -> Grade C
             assert result.grade == "C" 
             assert result.score == 75
             assert any(f.title == "Host Unreachable" for f in result.findings)

@pytest.mark.asyncio
async def test_scan_http_connection_failed(scan_engine):
    """Verify handling of HTTP connection failure"""
    mock_target_info = MagicMock()
    mock_target_info.full_url = "http://example.com"
    mock_target_info.hostname = "example.com"
    mock_target_info.port = 80
    
    with patch("app.scanner.engine.normalize_target", return_value=mock_target_info), \
         patch("app.scanner.engine.HttpClient") as MockHttpClient:
        
        mock_http_client = AsyncMock()
        mock_http_client.get.side_effect = Exception("Connection Refused")
        MockHttpClient.return_value.__aenter__.return_value = mock_http_client
        
        # Mock DNS success
        with patch("socket.getaddrinfo", return_value=[(0,0,0,0,('127.0.0.1', 80))]), \
             patch("app.scanner.engine.scan_ports", return_value=[]):
            
            result = await scan_engine.run_scan("http://example.com")
            
            assert any(f.title == "HTTP Connection Failed" for f in result.findings)

@pytest.mark.asyncio
async def test_scan_success_flow_v2(scan_engine):
    """Verify a successful scan flow"""
    mock_target_info = MagicMock()
    mock_target_info.full_url = "https://example.com"
    mock_target_info.hostname = "example.com"
    mock_target_info.port = 443
    
    with patch("app.scanner.engine.normalize_target", return_value=mock_target_info), \
         patch("app.scanner.engine.HttpClient") as MockHttpClient, \
         patch("socket.getaddrinfo", return_value=[(0,0,0,0,('127.0.0.1', 443))]), \
         patch("app.scanner.engine.scan_ports", return_value=[]), \
         patch("app.scanner.engine.check_tls", return_value=([], {})), \
         patch("app.scanner.engine.check_security_headers", return_value=[]), \
         patch("app.scanner.engine.analyze_cookies", return_value=([], {}, [])), \
         patch("app.scanner.cors_checks.check_cors", return_value=([], {})), \
         patch("app.scanner.engine.check_xss_url", return_value=([], [])), \
         patch("app.scanner.engine.check_sqli_url", return_value=([], [])), \
         patch("app.scanner.engine.check_sensitive_url", return_value=([], [])), \
         patch("app.scanner.engine.check_https_enforcement", return_value=([], {})), \
         patch("app.scanner.engine.check_exposure", return_value=[]), \
         patch("app.scanner.engine.detect_waf_and_visibility", return_value={"scan_status": "ok"}), \
         patch("app.scanner.engine.calculate_score", return_value=(100, "A")):
        
        mock_http_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url.scheme = "https"
        mock_response.url.host = "example.com"
        mock_response.url.port = 443
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html></html>"
        mock_http_client.get.return_value = mock_response
        mock_http_client.history = []
        
        MockHttpClient.return_value.__aenter__.return_value = mock_http_client
        
        # Mock Crawler
        with patch("app.scanner.crawler.SimpleCrawler") as MockCrawler:
             mock_crawler_instance = MockCrawler.return_value
             async def async_gen(*args, **kwargs):
                 if False: yield
             mock_crawler_instance.crawl_generator = async_gen
             
             # Configure http_client to return 200 for main target and 404 for others (PathDiscovery)
             def get_side_effect(url, *args, **kwargs):
                 mock_resp = MagicMock()
                 if url == "https://example.com" or url == "https://example.com/":
                     mock_resp.status_code = 200
                     mock_resp.url.scheme = "https"
                     mock_resp.url.host = "example.com"
                     mock_resp.url.port = 443
                     mock_resp.headers = {"Content-Type": "text/html"}
                     mock_resp.text = "<html></html>"
                     return mock_resp
                 else:
                     mock_resp.status_code = 404
                     return mock_resp
            
             mock_http_client.get.side_effect = get_side_effect
             
             result = await scan_engine.run_scan("https://example.com")
             
             assert result.grade == "A"
             assert result.score == 100
             assert result.scan_status == ScanStatus.OK
