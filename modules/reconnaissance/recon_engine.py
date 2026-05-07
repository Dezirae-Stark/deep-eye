"""
Reconnaissance Engine
Gathers intelligence about target
"""

import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse
from utils.logger import get_logger
from modules.reconnaissance.osint_enhanced import EnhancedOSINT

logger = get_logger(__name__)


class ReconEngine:
    """Reconnaissance and intelligence gathering."""
    
    def __init__(self, config: Dict, http_client):
        """Initialize reconnaissance engine."""
        self.config = config
        self.http_client = http_client
        self.recon_config = config.get('reconnaissance', {})
        self.enabled_modules = self.recon_config.get('enabled_modules', [])
        
        # Initialize OSINT module
        self.osint_enhanced = EnhancedOSINT(http_client, config)
    
    def run(self, target_url: str, bridge_intel: Optional[Dict] = None) -> Dict:
        """
        Run reconnaissance on target.

        Args:
            target_url: Target URL
            bridge_intel: Optional Shadowbroker bridge enrichment dict from
                run_bridge_phase(). When present, it's merged under
                results['shadowbroker'] and CT log entries are also exposed
                under results['shadowbroker']['ct_subdomains'] for downstream
                modules to fold into their own subdomain lists.

        Returns:
            Reconnaissance results
        """
        results = {
            'target': target_url,
            'domain': self._extract_domain(target_url)
        }
        
        # DNS records
        if 'dns_records' in self.enabled_modules:
            results['dns_records'] = self._get_dns_records(results['domain'])
        
        # WHOIS lookup
        if 'whois_lookup' in self.enabled_modules:
            results['whois'] = self._whois_lookup(results['domain'])
        
        # Technology detection
        if 'technology_detection' in self.enabled_modules:
            results['technologies'] = self._detect_technologies(target_url)
        
        # SSL certificate info
        if 'ssl_certificate_info' in self.enabled_modules:
            results['ssl_info'] = self._get_ssl_info(results['domain'])
        
        # Subdomain enumeration
        if 'subdomain_enumeration' in self.enabled_modules:
            results['subdomains'] = self._enumerate_subdomains(results['domain'])
        
        # OSINT gathering (integrated from osint_enhanced module)
        if 'osint_gathering' in self.enabled_modules:
            logger.info(f"Running OSINT intelligence gathering on {results['domain']}")
            osint_results = self.osint_enhanced.gather_intelligence(results['domain'])
            results['osint'] = osint_results
            
            # Flatten structure for easier access in reports
            results['osint']['emails'] = osint_results.get('email_addresses', [])
            results['osint']['subdomains'] = osint_results.get('certificate_transparency', [])
            results['osint']['technologies'] = osint_results.get('technology_intelligence', {})
            results['osint']['breaches'] = osint_results.get('data_breaches', [])
            results['osint']['github_leaks'] = osint_results.get('exposed_files', [])
            results['osint']['social_media'] = osint_results.get('social_media', {})
            results['osint']['cloud_resources'] = osint_results.get('cloud_resources', {})
        
        # Also collect basic DNS info
        if 'dns_records' not in results and results.get('domain'):
            results['dns'] = self._get_dns_records(results['domain'])

        # Shadowbroker bridge enrichment merge (Task 19).
        if bridge_intel is not None:
            results['shadowbroker'] = bridge_intel
            ct_subs = self._extract_ct_subdomains(bridge_intel.get('ct_logs') or [])
            if ct_subs:
                results['shadowbroker']['ct_subdomains'] = ct_subs

        return results

    @staticmethod
    def _extract_ct_subdomains(ct_logs: List[Dict]) -> List[str]:
        """Pull unique hostnames out of crt.sh-style ct_log entries.

        crt.sh's name_value field can be multi-line (one host per line) when
        a cert has SANs, so we split on newlines and dedupe. Empty entries
        and obvious wildcards (*.example.com) are kept as-is — downstream
        consumers can decide whether to expand or skip them.
        """
        seen: List[str] = []
        for entry in ct_logs:
            cn = (entry.get('cn') or '').strip()
            if not cn:
                continue
            for line in cn.split('\n'):
                host = line.strip()
                if host and host not in seen:
                    seen.append(host)
        return seen
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc
    
    def _get_dns_records(self, domain: str) -> Dict:
        """Get DNS records for domain."""
        # Lazy import: dnspython is optional. Module must be importable even
        # when dnspython is missing (deep_eye.py loads recon_engine at startup
        # regardless of whether dns_records is in enabled_modules).
        import dns.resolver

        records = {}

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.debug(f"No {record_type} records for {domain}: {e}")
                records[record_type] = []

        return records
    
    def _whois_lookup(self, domain: str) -> Dict:
        """Perform WHOIS lookup."""
        # Placeholder - would use python-whois
        return {
            'status': 'Not implemented',
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'expiration_date': 'N/A'
        }
    
    def _detect_technologies(self, url: str) -> List[str]:
        """Detect technologies used by target."""
        technologies = []
        
        try:
            response = self.http_client.get(url)
            if response:
                from utils.parser import ResponseParser
                parser = ResponseParser(response)
                technologies = parser.detect_technologies()
        except Exception as e:
            logger.debug(f"Error detecting technologies: {e}")
        
        return technologies
    
    def _get_ssl_info(self, domain: str) -> Dict:
        """Get SSL certificate information."""
        # Placeholder - would use ssl module
        return {
            'status': 'Not implemented',
            'issuer': 'N/A',
            'valid_from': 'N/A',
            'valid_until': 'N/A'
        }
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains."""
        subdomains = []
        
        # Common subdomain prefixes
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'dev', 'test',
            'staging', 'api', 'blog', 'shop', 'portal'
        ]
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                logger.debug(f"Found subdomain: {full_domain}")
            except socket.gaierror:
                pass
        
        return subdomains
