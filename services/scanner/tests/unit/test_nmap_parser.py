import pytest
from app.scanner.port_scanner_v2 import parse_nmap_xml

SAMPLE_XML = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 80,443 -oX - scanme.nmap.org" start="1618300000" startstr="Mon Apr 12 12:00:00 2021" version="7.91" xmloutputversion="1.05">
<host starttime="1618300000" endtime="1618300010">
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.41</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="https" product="nginx" version="" method="table" conf="3"/></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset" reason_ttl="0"/></port>
</ports>
</host>
</nmaprun>
"""

def test_parse_nmap_xml_valid():
    results = parse_nmap_xml(SAMPLE_XML)
    
    # Check that we got results for open ports
    assert 80 in results
    assert 443 in results
    # Closed ports generally not returned by our logic if we only iterate ports with service tags, 
    # but the parser logic I implemented iterates ALL ports.
    # However, if 'service' tag is missing or checks fail, it might skip.
    # In my implementation: 
    #   service_elem = port_elem.find('service')
    #   if service_elem is not None: ...
    # Port 8080 has no service element in the sample, so it should be skipped.
    assert 8080 not in results 
    
    # Check Port 80
    p80 = results[80]
    assert p80["service"] == "http"
    assert p80["product"] == "Apache httpd"
    assert p80["version"] == "2.4.41"
    assert "Ubuntu" in p80["extrainfo"]
    assert p80["cpe"] == "cpe:/a:apache:http_server:2.4.41"
    
    # Check Port 443
    p443 = results[443]
    assert p443["service"] == "https"
    assert p443["product"] == "nginx"
    assert p443["version"] == ""
    assert p443["cpe"] is None

def test_parse_nmap_xml_empty():
    results = parse_nmap_xml("")
    assert results == {}
    
def test_parse_nmap_xml_malformed():
    results = parse_nmap_xml("<invalid>xml host port</invalid>")
    assert results == {}
