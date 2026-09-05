# modules/network_scanner.py
"""
Network Scanner Module
Handles host discovery, port scanning, and service enumeration
"""

import socket
import subprocess
import platform
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import ipaddress
from typing import List, Dict
import logging

# Initialize logger
logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    Scans networks to discover active hosts and open ports
    """
    
    def __init__(self, timeout=2):
        """
        Initialize the network scanner
        
        Args:
            timeout: Timeout for network operations (default: 2 seconds)
        """
        self.timeout = timeout
        self.results = []
    
    def arp_scan(self, ip_range: str) -> List[Dict]:
        """
        Perform ARP scanning to discover hosts on the network
        
        Args:
            ip_range: IP range in CIDR format (e.g., "192.168.1.0/24")
        
        Returns:
            List of discovered hosts with MAC addresses
        
        Example:
            hosts = scanner.arp_scan("192.168.1.0/24")
            # Returns: [{'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55'}, ...]
        """
        try:
            logger.info(f"Starting ARP scan on {ip_range}")
            
            # Create ARP request packet
            # Ether(dst="ff:ff:ff:ff:ff:ff") - broadcast to all devices
            # ARP(pdst=ip_range) - ask "who is at this IP?"
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
            
            # Send packets and wait for responses
            # sr1() sends and receives responses
            answered, unanswered = srp(arp_request, timeout=self.timeout, verbose=False)
            
            discovered_hosts = []
            
            # Process responses
            for sent, received in answered:
                # Extract IP and MAC from response
                host_info = {
                    'ip': received.psrc,  # sender's IP address
                    'mac': received.hwsrc,  # sender's MAC address
                    'status': 'up'
                }
                discovered_hosts.append(host_info)
                logger.info(f"Host found: {host_info['ip']} ({host_info['mac']})")
            
            return discovered_hosts
        
        except Exception as e:
            logger.error(f"ARP scan failed: {str(e)}")
            return []
    
    def icmp_ping(self, target_ip: str) -> bool:
        """
        Send ICMP ping to test if host is alive
        
        Args:
            target_ip: Target IP address
        
        Returns:
            True if host responds to ping, False otherwise
        
        Example:
            is_alive = scanner.icmp_ping("192.168.1.1")
        """
        try:
            # Create ICMP Echo Request packet
            # IP(dst=target_ip) - destination IP
            # ICMP() - ICMP Echo Request packet
            packet = IP(dst=target_ip) / ICMP()
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=False)
            
            if response:
                logger.info(f"Host {target_ip} is UP (ICMP reply received)")
                return True
            else:
                logger.info(f"Host {target_ip} is DOWN (no ICMP reply)")
                return False
        
        except Exception as e:
            logger.error(f"ICMP ping failed for {target_ip}: {str(e)}")
            return False
    
    def tcp_port_scan(self, target_ip: str, ports: List[int] = None) -> Dict:
        """
        Scan TCP ports on target host
        
        Args:
            target_ip: Target IP address
            ports: List of ports to scan (default: common ports 1-1000)
        
        Returns:
            Dictionary with open and closed ports
        
        Example:
            results = scanner.tcp_port_scan("192.168.1.10", [22, 80, 443])
            # Returns: {'open': [80, 443], 'closed': [22]}
        """
        if ports is None:
            # Scan common ports if none specified
            ports = [22, 80, 443, 445, 3306, 5432, 8080, 8443]
        
        open_ports = []
        closed_ports = []
        
        logger.info(f"Starting TCP port scan on {target_ip}")
        
        for port in ports:
            try:
                # Create TCP SYN packet
                # IP(dst=target_ip) - destination
                # TCP(dport=port, flags="S") - TCP packet with SYN flag
                packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
                
                # Send packet and wait for response
                response = sr1(packet, timeout=self.timeout, verbose=False)
                
                if response:
                    # Check if response has SYN-ACK flag (port is open)
                    if response[TCP].flags == 0x12:  # SYN-ACK flags
                        open_ports.append(port)
                        logger.info(f"Port {port} is OPEN on {target_ip}")
                    else:
                        closed_ports.append(port)
                else:
                    # No response = filtered/closed port
                    closed_ports.append(port)
            
            except Exception as e:
                logger.error(f"Error scanning port {port}: {str(e)}")
                closed_ports.append(port)
        
        return {
            'target': target_ip,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }
    
    def service_enumeration(self, target_ip: str, port: int) -> Dict:
        """
        Try to identify service running on open port
        
        Args:
            target_ip: Target IP address
            port: Port number to check
        
        Returns:
            Dictionary with service information
        
        Example:
            service_info = scanner.service_enumeration("192.168.1.10", 80)
            # Returns: {'port': 80, 'service': 'HTTP', 'version': 'Apache/2.4.41'}
        """
        try:
            logger.info(f"Enumerating service on {target_ip}:{port}")
            
            # Try to connect and grab banner
            # Many services send a banner (identification string)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, port))
            
            # Receive banner/response
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Map common ports to services
            service_map = {
                22: 'SSH',
                80: 'HTTP',
                443: 'HTTPS',
                445: 'SMB',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                8080: 'HTTP-Alt'
            }
            
            return {
                'port': port,
                'service': service_map.get(port, 'Unknown'),
                'banner': banner[:100] if banner else 'No banner',
                'target': target_ip
            }
        
        except Exception as e:
            logger.error(f"Service enumeration failed for {target_ip}:{port}: {str(e)}")
            return {'port': port, 'service': 'Unknown', 'error': str(e)}

# Import TCP for TCP scanning
from scapy.all import TCP

# Example usage
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create scanner instance
    scanner = NetworkScanner()
    
    # Example: Scan network for active hosts
    # hosts = scanner.arp_scan("192.168.1.0/24")
    
    # Example: Ping specific host
    # is_alive = scanner.icmp_ping("192.168.1.1")
    
    # Example: Scan ports on specific host
    # results = scanner.tcp_port_scan("192.168.1.10")
    
    print("Network Scanner Module Loaded")
