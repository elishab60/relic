"""
Unit tests for Port Scanner Module
==================================
Tests for port scan profiles, service detection, and risk assessment.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from app.scanner.port_scanner import (
    PortScanProfile,
    PortScanResult,
    PortScanSummary,
    get_ports_for_profile,
    get_profile_metadata,
    guess_service,
    assess_risk,
    scan_ports,
    scan_ports_tcp,
    is_nmap_available,
    parse_nmap_xml,
    PORTS_LIGHT,
    PORTS_MID,
    PORTS_HIGH,
)


# =============================================================================
# PROFILE TESTS
# =============================================================================

class TestPortScanProfiles:
    """Tests for port scan profile configuration."""
    
    def test_profile_enum_values(self):
        """Verify all profile enum values."""
        assert PortScanProfile.LIGHT.value == "light"
        assert PortScanProfile.MID.value == "mid"
        assert PortScanProfile.HIGH.value == "high"
    
    def test_get_ports_for_light_profile(self):
        """LIGHT profile should return ~12 common ports."""
        ports = get_ports_for_profile(PortScanProfile.LIGHT)
        assert ports == PORTS_LIGHT
        assert len(ports) == 12
        assert 22 in ports  # SSH
        assert 80 in ports  # HTTP
        assert 443 in ports  # HTTPS
        assert 3306 in ports  # MySQL
    
    def test_get_ports_for_mid_profile(self):
        """MID profile should return ~100 ports."""
        ports = get_ports_for_profile(PortScanProfile.MID)
        assert len(ports) == len(PORTS_MID)
        assert len(ports) >= 90  # At least 90 ports
        # Should contain common ports
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports
        assert 3389 in ports  # RDP
    
    def test_get_ports_for_high_profile(self):
        """HIGH profile should return ~1000 ports."""
        ports = get_ports_for_profile(PortScanProfile.HIGH)
        assert len(ports) == len(PORTS_HIGH)
        assert len(ports) >= 500  # At least 500 ports
        # Should be a superset of MID
        for port in PORTS_MID:
            assert port in ports, f"Port {port} from MID missing in HIGH"
    
    def test_profile_metadata_light(self):
        """Verify LIGHT profile metadata."""
        meta = get_profile_metadata(PortScanProfile.LIGHT)
        assert meta["name"] == "light"
        assert meta["label"] == "Light"
        assert meta["port_count"] == len(PORTS_LIGHT)
        assert meta["impact"] == "fast"
    
    def test_profile_metadata_mid(self):
        """Verify MID profile metadata."""
        meta = get_profile_metadata(PortScanProfile.MID)
        assert meta["name"] == "mid"
        assert meta["label"] == "Balanced"
        assert meta["impact"] == "medium"
    
    def test_profile_metadata_high(self):
        """Verify HIGH profile metadata."""
        meta = get_profile_metadata(PortScanProfile.HIGH)
        assert meta["name"] == "high"
        assert meta["label"] == "Comprehensive"
        assert meta["impact"] == "slow"
    
    def test_ports_are_sorted(self):
        """Verify HIGH profile ports are sorted."""
        ports = get_ports_for_profile(PortScanProfile.HIGH)
        assert ports == sorted(ports)
    
    def test_no_duplicate_ports(self):
        """Verify no duplicate ports in any profile."""
        for profile in PortScanProfile:
            ports = get_ports_for_profile(profile)
            assert len(ports) == len(set(ports)), f"Duplicates found in {profile.value}"


# =============================================================================
# SERVICE DETECTION TESTS
# =============================================================================

class TestServiceDetection:
    """Tests for service guessing from port numbers."""
    
    def test_common_service_ports(self):
        """Verify common service port mappings."""
        assert guess_service(21) == "ftp"
        assert guess_service(22) == "ssh"
        assert guess_service(23) == "telnet"
        assert guess_service(25) == "smtp"
        assert guess_service(53) == "dns"
        assert guess_service(80) == "http"
        assert guess_service(443) == "https"
        assert guess_service(3306) == "mysql"
        assert guess_service(5432) == "postgresql"
        assert guess_service(6379) == "redis"
        assert guess_service(27017) == "mongodb"
    
    def test_database_ports(self):
        """Verify database service detection."""
        assert guess_service(3306) == "mysql"
        assert guess_service(5432) == "postgresql"
        assert guess_service(27017) == "mongodb"
        assert guess_service(6379) == "redis"
        assert guess_service(9200) == "elasticsearch"
    
    def test_unknown_port(self):
        """Unknown ports should return 'unknown'."""
        assert guess_service(12345) == "unknown"
        assert guess_service(65000) == "unknown"
        assert guess_service(1) == "unknown"  # No mapping for port 1


# =============================================================================
# RISK ASSESSMENT TESTS
# =============================================================================

class TestRiskAssessment:
    """Tests for port risk assessment."""
    
    def test_safe_web_ports(self):
        """Web ports should be info level."""
        for port in [80, 443, 8080, 8443]:
            level, reason, refs = assess_risk(port, "http", None)
            assert level == "info"
            assert refs == []
    
    def test_insecure_protocols_high_risk(self):
        """FTP and Telnet should be high risk."""
        # FTP
        level, reason, refs = assess_risk(21, "ftp", None)
        assert level == "high"
        assert "Insecure" in reason or "insecure" in reason.lower()
        assert len(refs) > 0
        
        # Telnet
        level, reason, refs = assess_risk(23, "telnet", None)
        assert level == "high"
        assert len(refs) > 0
    
    def test_database_ports_medium_risk(self):
        """Database ports should be medium risk."""
        db_ports = [3306, 5432, 6379, 27017]
        for port in db_ports:
            level, reason, refs = assess_risk(port, guess_service(port), None)
            assert level == "medium", f"Port {port} should be medium risk"
            assert "A05:2021" in refs or any("A05" in r for r in refs)
    
    def test_ssh_low_risk(self):
        """SSH should be low risk (generally acceptable if secured)."""
        level, reason, refs = assess_risk(22, "ssh", None)
        assert level == "low"
        assert "SSH" in reason
    
    def test_rdp_low_risk(self):
        """RDP (3389) should be low risk (remote access, not insecure by default)."""
        level, reason, refs = assess_risk(3389, "rdp", None)
        assert level == "low"
    
    def test_unknown_port_info_level(self):
        """Unknown ports should default to info."""
        level, reason, refs = assess_risk(12345, "unknown", None)
        assert level == "info"


# =============================================================================
# NMAP XML PARSING TESTS
# =============================================================================

class TestNmapXmlParsing:
    """Tests for nmap XML output parsing."""
    
    def test_parse_simple_xml(self):
        """Parse a simple nmap XML output."""
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="8.0"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.18"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="closed"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """
        results = parse_nmap_xml(xml)
        assert len(results) == 3
        
        # Check SSH
        ssh = next((r for r in results if r.port == 22), None)
        assert ssh is not None
        assert ssh.state == "open"
        assert ssh.nmap_service == "ssh"
        assert "OpenSSH" in (ssh.nmap_version or "")
        
        # Check HTTP
        http = next((r for r in results if r.port == 80), None)
        assert http is not None
        assert http.state == "open"
        assert http.nmap_service == "http"
        
        # Check 443 closed
        https = next((r for r in results if r.port == 443), None)
        assert https is not None
        assert https.state == "closed"
    
    def test_parse_filtered_state(self):
        """Parse filtered port state."""
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="3389">
                        <state state="filtered"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """
        results = parse_nmap_xml(xml)
        assert len(results) == 1
        assert results[0].state == "filtered"
    
    def test_parse_invalid_xml(self):
        """Invalid XML should return empty list."""
        results = parse_nmap_xml("not valid xml at all")
        assert results == []
    
    def test_parse_empty_xml(self):
        """Empty ports should return empty list."""
        xml = """<?xml version="1.0"?><nmaprun></nmaprun>"""
        results = parse_nmap_xml(xml)
        assert results == []


# =============================================================================
# PORT SCAN RESULT MODEL TESTS
# =============================================================================

class TestPortScanModels:
    """Tests for Pydantic models."""
    
    def test_port_scan_result_creation(self):
        """Verify PortScanResult model."""
        result = PortScanResult(
            port=22,
            state="open",
            service_guess="ssh",
            banner="SSH-2.0-OpenSSH",
            risk_level="low",
            risk_reason="SSH exposed",
            owasp_refs=["A05:2021"]
        )
        assert result.port == 22
        assert result.state == "open"
        assert result.service_guess == "ssh"
        assert result.risk_level == "low"
    
    def test_port_scan_result_minimal(self):
        """Minimal PortScanResult with only required fields."""
        result = PortScanResult(port=80, state="closed")
        assert result.port == 80
        assert result.state == "closed"
        assert result.service_guess is None
        assert result.banner is None
    
    def test_port_scan_summary(self):
        """Verify PortScanSummary model."""
        summary = PortScanSummary(
            profile="light",
            ports_scanned=12,
            open_count=3,
            filtered_count=1,
            closed_count=8,
            duration_ms=1500,
            scan_method="tcp_connect",
            nmap_available=True
        )
        assert summary.profile == "light"
        assert summary.open_count == 3
        assert summary.duration_ms == 1500


# =============================================================================
# ASYNC SCAN TESTS
# =============================================================================

@pytest.mark.asyncio
class TestAsyncPortScan:
    """Async tests for port scanning."""
    
    async def test_scan_ports_returns_tuple(self):
        """scan_ports should return (results, summary) tuple."""
        with patch('app.scanner.port_scanner.scan_ports_tcp') as mock_tcp:
            mock_tcp.return_value = [
                PortScanResult(port=80, state="open", service_guess="http"),
                PortScanResult(port=443, state="closed")
            ]
            
            results, summary = await scan_ports(
                "127.0.0.1",
                log_callback=None,
                profile=PortScanProfile.LIGHT
            )
            
            assert isinstance(results, list)
            assert isinstance(summary, PortScanSummary)
            assert summary.profile == "light"
            assert summary.open_count == 1
            assert summary.closed_count == 1
    
    async def test_scan_ports_uses_profile(self):
        """scan_ports should use the correct profile ports."""
        with patch('app.scanner.port_scanner.scan_ports_tcp') as mock_tcp:
            mock_tcp.return_value = []
            
            await scan_ports(
                "127.0.0.1",
                log_callback=None,
                profile=PortScanProfile.MID
            )
            
            # Check that scan_ports_tcp was called with MID ports
            call_args = mock_tcp.call_args
            ports_arg = call_args[0][1]  # Second positional arg is ports
            assert len(ports_arg) == len(PORTS_MID)
    
    async def test_scan_ports_log_callback(self):
        """Verify log callback is invoked."""
        log_messages = []
        
        async def mock_log(level: str, msg: str):
            log_messages.append((level, msg))
        
        with patch('app.scanner.port_scanner.scan_ports_tcp') as mock_tcp:
            mock_tcp.return_value = [
                PortScanResult(port=80, state="open")
            ]
            
            await scan_ports(
                "127.0.0.1",
                log_callback=mock_log,
                profile=PortScanProfile.LIGHT
            )
            
            # Should have at least start and end logs
            assert len(log_messages) >= 2
            assert any("Starting" in msg for _, msg in log_messages)
            assert any("completed" in msg.lower() for _, msg in log_messages)


# =============================================================================
# NMAP AVAILABILITY TESTS  
# =============================================================================

class TestNmapAvailability:
    """Tests for nmap availability detection."""
    
    def test_nmap_availability_check(self):
        """is_nmap_available should return bool."""
        result = is_nmap_available()
        assert isinstance(result, bool)
    
    def test_nmap_available_when_exists(self):
        """When nmap exists, should return True."""
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            assert is_nmap_available() is True
    
    def test_nmap_unavailable_when_missing(self):
        """When nmap missing, should return False."""
        with patch('shutil.which', return_value=None):
            assert is_nmap_available() is False


# =============================================================================
# INTEGRATION-LIKE TESTS (with mocks)
# =============================================================================

@pytest.mark.asyncio  
class TestPortScanIntegration:
    """Integration-style tests with mocked network."""
    
    async def test_full_scan_flow_light_profile(self):
        """Test complete scan flow with LIGHT profile."""
        with patch('app.scanner.port_scanner.scan_single_port') as mock_port:
            # Mock all ports as closed except 80 and 443
            async def mock_scan(ip, port, timeout, callback):
                if port in [80, 443]:
                    return PortScanResult(
                        port=port,
                        state="open",
                        service_guess="http" if port == 80 else "https",
                        risk_level="info"
                    )
                return PortScanResult(port=port, state="closed")
            
            mock_port.side_effect = mock_scan
            
            results, summary = await scan_ports(
                "192.168.1.1",
                profile=PortScanProfile.LIGHT,
                use_nmap=False
            )
            
            assert summary.profile == "light"
            assert summary.ports_scanned == 12
            assert summary.open_count == 2
            assert summary.scan_method == "tcp_connect"
            
            # Verify open ports
            open_ports = [r for r in results if r.state == "open"]
            assert len(open_ports) == 2
            assert any(r.port == 80 for r in open_ports)
            assert any(r.port == 443 for r in open_ports)
    
    async def test_scan_with_nmap_enhancement(self):
        """Test that nmap enhances results when available."""
        with patch('app.scanner.port_scanner.scan_ports_tcp') as mock_tcp, \
             patch('app.scanner.port_scanner.is_nmap_available', return_value=True), \
             patch('app.scanner.port_scanner.run_nmap_scan') as mock_nmap:
            
            # TCP scan finds open ports
            mock_tcp.return_value = [
                PortScanResult(port=22, state="open", service_guess="ssh"),
                PortScanResult(port=80, state="open", service_guess="http"),
            ]
            
            # Nmap provides service versions
            mock_nmap.return_value = [
                PortScanResult(
                    port=22, state="open", 
                    nmap_service="ssh", 
                    nmap_version="OpenSSH 8.0"
                ),
                PortScanResult(
                    port=80, state="open",
                    nmap_service="http",
                    nmap_version="nginx 1.18.0"
                )
            ]
            
            results, summary = await scan_ports(
                "10.0.0.1",
                profile=PortScanProfile.LIGHT,
                use_nmap=True
            )
            
            # Verify nmap was called
            assert mock_nmap.called
            
            # Results should have nmap service info merged
            ssh_result = next((r for r in results if r.port == 22), None)
            assert ssh_result is not None
            assert ssh_result.nmap_service == "ssh"
