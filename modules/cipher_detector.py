# modules/cipher_detector.py
"""
Cipher Detector Module
Analyzes encryption and cipher strength in web applications
"""

import ssl
import socket
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class CipherDetector:
    """
    Analyzes SSL/TLS ciphers and encryption strength
    """
    
    def __init__(self, target_host: str, port: int = 443):
        """
        Initialize cipher detector
        
        Args:
            target_host: Target hostname/IP
            port: SSL/TLS port (default: 443 for HTTPS)
        """
        self.target_host = target_host
        self.port = port
        self.weak_ciphers = []
        self.strong_ciphers = []
    
    def get_ssl_certificate_info(self) -> Dict:
        """
        Retrieve SSL certificate information from target
        
        Returns:
            Dictionary with certificate details
        
        Example:
            cert_info = detector.get_ssl_certificate_info()
            # Returns: {
            #   'subject': 'CN=example.com',
            #   'issuer': 'CN=Let's Encrypt',
            #   'version': 3,
            #   'expiration': '2025-01-01'
            # }
        """
        try:
            logger.info(f"Retrieving SSL certificate from {self.target_host}:{self.port}")
            
            # Create SSL context
            # This tells Python to connect with SSL/TLS
            context = ssl.create_default_context()
            
            # Allow self-signed certificates for testing
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create socket connection
            with socket.create_connection((self.target_host, self.port), timeout=5) as sock:
                # Upgrade to SSL connection
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # Get certificate from server
                    cert = ssock.getpeercert()
                    
                    # Extract certificate information
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'altnames': [alt[1] for alt in cert.get('subjectAltName', [])]
                    }
                    
                    logger.info(f"Certificate retrieved: {cert_info['subject']}")
                    return cert_info
        
        except Exception as e:
            logger.error(f"Failed to retrieve certificate: {str(e)}")
            return {'error': str(e)}
    
    def check_tls_version(self) -> Dict:
        """
        Check which TLS versions are supported
        
        Returns:
            Dictionary with supported TLS versions
        
        Example:
            tls_info = detector.check_tls_version()
            # Returns: {
            #   'supported': ['TLSv1.2', 'TLSv1.3'],
            #   'unsupported': ['SSLv3', 'TLSv1.0']
            # }
        """
        logger.info(f"Checking TLS versions on {self.target_host}:{self.port}")
        
        supported_versions = []
        unsupported_versions = []
        
        # TLS versions to test
        # Older versions = WEAK, newer versions = STRONG
        tls_versions = [
            ('SSLv3', ssl.PROTOCOL_SSLv23, 'WEAK - Deprecated'),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1, 'WEAK - Outdated'),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1, 'WEAK - Outdated'),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2, 'STRONG - Recommended'),
            ('TLSv1.3', ssl.PROTOCOL_TLS, 'VERY STRONG - Latest'),
        ]
        
        for version_name, protocol, strength in tls_versions:
            try:
                # Try to create connection with specific TLS version
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_host, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        # Get actual protocol version used
                        actual_version = ssock.version()
                        
                        supported_versions.append({
                            'version': version_name,
                            'strength': strength,
                            'supported': True
                        })
                        
                        logger.info(f"{version_name} is supported: {strength}")
            
            except Exception:
                # If connection fails, version is not supported
                unsupported_versions.append({
                    'version': version_name,
                    'strength': strength,
                    'supported': False
                })
        
        return {
            'target': self.target_host,
            'supported_versions': supported_versions,
            'unsupported_versions': unsupported_versions
        }
    
    def detect_weak_ciphers(self) -> List[Dict]:
        """
        Identify weak cipher suites in use
        
        Returns:
            List of weak ciphers found
        
        Example:
            weak = detector.detect_weak_ciphers()
            # Returns: [
            #   {'cipher': 'DES-CBC3-SHA', 'strength': 'WEAK', 'bits': 168}
            # ]
        """
        logger.info(f"Detecting weak ciphers on {self.target_host}:{self.port}")
        
        # Known weak ciphers - these should NOT be used
        weak_cipher_list = [
            {'name': 'DES-CBC', 'bits': 56, 'reason': 'Only 56-bit key, easily crackable'},
            {'name': 'RC4', 'bits': 40, 'reason': 'Stream cipher with known weaknesses'},
            {'name': 'MD5', 'bits': 128, 'reason': 'Hash collision vulnerabilities'},
            {'name': 'NULL', 'bits': 0, 'reason': 'No encryption'},
            {'name': 'EXPORT', 'bits': 40, 'reason': 'Weak export-grade encryption'},
        ]
        
        weak_found = []
        
        try:
            # Connect and check actual ciphers
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # Get cipher information
                    cipher = ssock.cipher()
                    # cipher = (name, protocol, bits)
                    
                    cipher_name = cipher[0]
                    cipher_bits = cipher[2]
                    
                    # Check against weak cipher list
                    for weak_cipher in weak_cipher_list:
                        if weak_cipher['name'] in cipher_name:
                            weak_found.append({
                                'cipher': cipher_name,
                                'bits': cipher_bits,
                                'severity': 'HIGH',
                                'reason': weak_cipher['reason'],
                                'recommendation': 'Disable and use AES-256-GCM or ChaCha20-Poly1305'
                            })
                            logger.warning(f"Weak cipher found: {cipher_name}")
        
        except Exception as e:
            logger.error(f"Error detecting weak ciphers: {str(e)}")
        
        return weak_found
    
    def analyze_cipher_strength(self) -> Dict:
        """
        Comprehensive analysis of cipher configuration
        
        Returns:
            Dictionary with overall cipher security assessment
        
        Example:
            analysis = detector.analyze_cipher_strength()
        """
        logger.info(f"Performing comprehensive cipher analysis on {self.target_host}")
        
        cert_info = self.get_ssl_certificate_info()
        tls_info = self.check_tls_version()
        weak_ciphers = self.detect_weak_ciphers()
        
        # Determine overall security rating
        rating = "GOOD"
        issues = []
        
        if weak_ciphers:
            rating = "POOR"
            issues.append("Weak ciphers are enabled")
        
        # Check for outdated TLS versions
        for version in tls_info.get('supported_versions', []):
            if 'WEAK' in version.get('strength', ''):
                rating = "FAIR"
                issues.append(f"Outdated {version['version']} is supported")
        
        return {
            'target': self.target_host,
            'overall_rating': rating,
            'issues': issues,
            'certificate': cert_info,
            'tls_versions': tls_info,
            'weak_ciphers': weak_ciphers,
            'recommendations': [
                'Use TLS 1.3 exclusively',
                'Disable all ciphers with < 128 bits',
                'Use AEAD ciphers (GCM, ChaCha20-Poly1305)',
                'Keep certificates up-to-date',
                'Use strong key exchange (ECDHE)'
            ]
        }

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create detector instance
    detector = CipherDetector("example.com", 443)
    
    # Analyze ciphers
    # analysis = detector.analyze_cipher_strength()
    
    print("Cipher Detector Module Loaded")
