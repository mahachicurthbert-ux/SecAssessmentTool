# modules/credential_analyzer.py
"""
Credential Analyzer Module
Analyzes weak credential storage and authentication vulnerabilities
"""

import requests
import re
import hashlib
from typing import Dict, List
import logging
from bs4 import BeautifulSoup

# Initialize logger
logger = logging.getLogger(__name__)

class CredentialAnalyzer:
    """
    Analyzes credential storage and authentication mechanisms
    for common security vulnerabilities
    """
    
    def __init__(self, target_url: str):
        """
        Initialize credential analyzer
        
        Args:
            target_url: Target web application URL
        """
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def check_plaintext_passwords(self, html_content: str) -> List[Dict]:
        """
        Check if passwords are stored/transmitted in plaintext
        
        Args:
            html_content: HTML content from web page
        
        Returns:
            List of potential plaintext password vulnerabilities
        
        Example:
            issues = analyzer.check_plaintext_passwords(page_html)
            # Returns: [{'issue': 'Password in HTML comment', 'severity': 'High'}]
        """
        vulns = []
        
        # Check for hardcoded passwords in HTML/comments
        # Pattern: password\s*=\s*["']?[^"'\s]+["']?
        password_patterns = [
            (r'password\s*=\s*["\']([^"\']+)["\']', 'Password hardcoded in HTML'),
            (r'pwd\s*:\s*["\']([^"\']+)["\']', 'Password in configuration'),
            (r'<!--.*password.*-->', 'Password in HTML comment'),
            (r'<input[^>]*value=["\']password["\']', 'Password as default value'),
        ]
        
        for pattern, description in password_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                logger.warning(f"Found potential plaintext password: {description}")
                vulns.append({
                    'type': 'Plaintext Password Storage',
                    'description': description,
                    'severity': 'CRITICAL',
                    'matches_found': len(matches)
                })
        
        return vulns
    
    def check_weak_hashing(self, password: str) -> Dict:
        """
        Check if password is hashed with weak algorithm
        
        Args:
            password: Password to test
        
        Returns:
            Dictionary showing hash results
        
        Example:
            test_pass = "password123"
            hashes = analyzer.check_weak_hashing(test_pass)
            # Shows MD5, SHA1 (WEAK) vs bcrypt, SHA256 (STRONG)
        """
        logger.info(f"Analyzing hashing for: {password}")
        
        # Weak hashing algorithms (easily crackable)
        weak_hashes = {
            'MD5': hashlib.md5(password.encode()).hexdigest(),
            'SHA1': hashlib.sha1(password.encode()).hexdigest(),
        }
        
        # Strong hashing algorithms
        strong_hashes = {
            'SHA256': hashlib.sha256(password.encode()).hexdigest(),
            'SHA512': hashlib.sha512(password.encode()).hexdigest(),
        }
        
        return {
            'password': password,
            'weak_hashes': weak_hashes,
            'strong_hashes': strong_hashes,
            'recommendation': 'Use bcrypt, scrypt, or Argon2 for password storage'
        }
    
    def detect_sql_injection_vulnerability(self, url: str, parameter: str) -> bool:
        """
        Test for SQL injection vulnerabilities in login forms
        
        Args:
            url: Target URL
            parameter: Form parameter to test (e.g., 'username')
        
        Returns:
            True if SQL injection is possible, False otherwise
        
        Example:
            is_vulnerable = analyzer.detect_sql_injection_vulnerability(
                "http://school-app.local/login",
                "username"
            )
        """
        try:
            logger.info(f"Testing SQL injection on {url} parameter: {parameter}")
            
            # SQL injection test payloads
            # These payloads try to break SQL queries
            sql_injection_payloads = [
                "' OR '1'='1",  # Classic OR condition
                "admin' --",    # Comment out rest of query
                "' OR 1=1 --",  # SQL comment bypass
                "'; DROP TABLE users; --",  # Database modification
            ]
            
            for payload in sql_injection_payloads:
                # Create test data with SQL injection
                test_data = {parameter: payload, 'password': 'test'}
                
                try:
                    # Send payload to server
                    response = self.session.post(url, data=test_data, timeout=5)
                    
                    # Check for common SQL error messages
                    sql_errors = ['SQL', 'mysql_fetch', 'Warning:', 'syntax error']
                    
                    if any(error in response.text for error in sql_errors):
                        logger.warning(f"Potential SQL injection found with payload: {payload}")
                        return True
                
                except requests.RequestException as e:
                    logger.error(f"Error testing payload: {str(e)}")
            
            return False
        
        except Exception as e:
            logger.error(f"SQL injection detection failed: {str(e)}")
            return False
    
    def check_session_security(self, cookies: Dict) -> List[Dict]:
        """
        Analyze session cookies for security issues
        
        Args:
            cookies: Dictionary of cookies from responses
        
        Returns:
            List of session security issues found
        
        Example:
            issues = analyzer.check_session_security(response.cookies)
        """
        vulns = []
        
        logger.info("Analyzing session cookies security")
        
        for cookie_name, cookie_value in cookies.items():
            # Check if cookie lacks secure flag
            # Secure flag prevents transmission over HTTP
            if not hasattr(cookies[cookie_name], 'secure'):
                vulns.append({
                    'type': 'Missing Secure Flag',
                    'cookie': cookie_name,
                    'severity': 'HIGH',
                    'description': 'Cookie can be transmitted over unencrypted HTTP'
                })
            
            # Check if cookie lacks HttpOnly flag
            # HttpOnly prevents JavaScript access
            if not hasattr(cookies[cookie_name], 'has_nonstandard_attr'):
                vulns.append({
                    'type': 'Missing HttpOnly Flag',
                    'cookie': cookie_name,
                    'severity': 'HIGH',
                    'description': 'Cookie accessible to JavaScript (XSS risk)'
                })
            
            # Check for weak session identifiers
            # Sessions should be long and random
            if len(cookie_value) < 32:
                vulns.append({
                    'type': 'Weak Session Identifier',
                    'cookie': cookie_name,
                    'length': len(cookie_value),
                    'severity': 'MEDIUM',
                    'description': 'Session ID is too short (recommended 128+ bits)'
                })
        
        return vulns
    
    def test_default_credentials(self, url: str, default_creds: List[tuple]) -> List[Dict]:
        """
        Test for common default credentials
        
        Args:
            url: Target URL login endpoint
            default_creds: List of (username, password) tuples to try
        
        Returns:
            List of successful default credential logins
        
        Example:
            defaults = [('admin', 'admin'), ('admin', 'password')]
            results = analyzer.test_default_credentials(url, defaults)
        """
        successful_logins = []
        
        logger.info(f"Testing default credentials on {url}")
        
        for username, password in default_creds:
            try:
                # Prepare login data
                login_data = {
                    'username': username,
                    'password': password,
                    'login': 'Login'
                }
                
                # Send login request
                response = self.session.post(url, data=login_data, timeout=5)
                
                # Check for successful login indicators
                # These vary by application
                success_indicators = [
                    'dashboard',
                    'Welcome',
                    'Logout',
                    'Profile',
                    'Settings'
                ]
                
                if any(indicator in response.text for indicator in success_indicators):
                    logger.warning(f"DEFAULT CREDENTIALS FOUND: {username}:{password}")
                    successful_logins.append({
                        'username': username,
                        'password': password,
                        'severity': 'CRITICAL',
                        'description': 'Application uses default credentials'
                    })
            
            except requests.RequestException as e:
                logger.error(f"Error testing credentials: {str(e)}")
        
        return successful_logins

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create analyzer instance
    analyzer = CredentialAnalyzer("http://target-app.local")
    
    # Test example password
    # hashes = analyzer.check_weak_hashing("password123")
    
    print("Credential Analyzer Module Loaded")
