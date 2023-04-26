import threading

import dns.resolver
import requests

from logger import logger


class SubdomainScanner:
    def __init__(self, subdomains):
        self.subdomains = subdomains
        self.results = {}
        self.lock = threading.Lock()

    def scan_subdomains(self):
        threads = []
        for subdomain in self.subdomains:
            thread = threading.Thread(target=self._scan_subdomain, args=(subdomain,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

    def _scan_subdomain(self, subdomain):
        logger.info(f'Scanning subdomain: {subdomain}')
        output = self._check_domain(subdomain)
        # Add result to shared dictionary
        with self.lock:
            self.results[subdomain] = output

    def _query_dns_records(self, domain):
        records = {'A': [], 'CNAME': [], 'NS': []}
        for record_type in records.keys():
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    target_or_address = answer.address if record_type == 'A' else answer.target
                    if record_type in ['NS', 'CNAME']:
                        target_or_address = str(target_or_address).rstrip('. ')
                    records[record_type].append(str(target_or_address))
            except dns.resolver.NoNameservers as e:
                logger.error(e)
            except dns.resolver.NoAnswer as e:
                logger.error(e)
        return records

    def _record_redirects(self, domain):
        try:
            response = requests.get(f'http://{domain}', allow_redirects=False)
            if response.status_code in (301, 302):
                return response.headers['Location']
        except requests.exceptions.RequestException:
            pass
        return None

    def _resolve_dns(self, nameserver, domain):
        my_resolver = dns.resolver.Resolver()
        resolution_object = {}
        try:
            ips = my_resolver.resolve(nameserver, 'A')
            my_resolver.nameservers = [str(ip) for ip in ips]
            resolution_object["resolved_ips"] = my_resolver.nameservers
        except dns.resolver.NXDOMAIN:
            raise ValueError(f"Invalid nameserver: {nameserver}")
        try:
            answer = my_resolver.resolve(domain)
            resolution_object["a_records"] = [rdata.address for rdata in answer if rdata.rdtype == dns.rdatatype.A]

        except dns.resolver.NoNameservers as e:
            logger.error(e)

        return resolution_object

    def _get_redirect_chain(self, domain):
        redirect_chain = []
        current_domain = domain

        while current_domain:
            next_domain = self._record_redirects(current_domain)
            if next_domain:
                redirect_chain.append((current_domain, next_domain))
                current_domain = next_domain
            else:
                current_domain = None

        return redirect_chain

    def _check_domain(self, domain):
        records = self._query_dns_records(domain)

        output_dict = {}

        for record_type, record_values in records.items():
            output_dict[record_type] = {}
            for value in record_values:
                output_dict[record_type][value] = {}
                if record_type in ["A", "CNAME"]:
                    redirect_chain = self._get_redirect_chain(value)
                    if redirect_chain:
                        output_dict[record_type][value]["redirects"] = redirect_chain
                if record_type == "NS":
                    output_dict[record_type][value] = self._resolve_dns(value, domain)

        return output_dict
