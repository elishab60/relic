from urllib.parse import urlparse
import ipaddress
import socket

def is_authorized(target: str) -> bool:
    # Allow all targets for the real scanner implementation
    return True
