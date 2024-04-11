#pip install google
#pip install googlesearch-python
#pip install dnspython

import whois
from datetime import datetime
import requests
from googlesearch import search

import ssl
import socket

import dns.resolver

# ------------Domain activation time (in days)--------------- #

def time_domain_activation(url):
    """Get the domain activation time (creation date) in days for a given URL."""
    try:
        # Parse the URL to extract the domain
        domain = url.split('/')[2]  # Extract domain from URL (assuming URL is in valid format)

        # Fetch WHOIS information for the domain
        domain_info = whois.whois(domain)

        if domain_info.creation_date:
            # Get the domain creation date
            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):
                # Use the first creation date if multiple dates are returned (common for some domains)
                creation_date = creation_date[0]

            # Calculate the number of days since the domain was created
            current_date = datetime.now()
            activation_time_days = (current_date - creation_date).days

            return activation_time_days
        else:
            print(f"Failed to retrieve creation date for the domain: {domain}")
            return None

    except Exception as e:
        print(f"Error occurred while fetching domain activation time: {e}")
        return None



# ------------Domain expiration time (in days)-------------- #

def time_domain_expiration(url):
    """Get the domain expiration time (expiration date) in days for a given URL."""
    try:
        # Parse the URL to extract the domain
        domain = url.split('/')[2]  # Extract domain from URL (assuming URL is in valid format)

        # Fetch WHOIS information for the domain
        domain_info = whois.whois(domain)

        if domain_info.expiration_date:
            # Get the domain expiration date
            expiration_date = domain_info.expiration_date

            if isinstance(expiration_date, list):
                # Use the first expiration date if multiple dates are returned (common for some domains)
                expiration_date = expiration_date[0]

            # Calculate the number of days until the domain expires
            current_date = datetime.now()
            time_until_expiration_days = (expiration_date - current_date).days

            return time_until_expiration_days
        else:
            print(f"Failed to retrieve expiration date for the domain: {domain}")
            return None

    except Exception as e:
        print(f"Error occurred while fetching domain expiration time: {e}")
        return None
        
  
  
#-------------whether URL redirected----------------------#

def qty_redirects(url):
    """Check if a URL is redirected."""
    try:
        # Send an HTTP HEAD request to the URL
        response = requests.head(url, allow_redirects=True)

        # Check if the response has a redirect status code
        if response.status_code in (301, 302):
            return True  # URL is redirected
        else:
            return False  # URL is not redirected

    except requests.RequestException as e:
        print(f"Error occurred while checking URL redirection: {e}")
        return None
        
        
        
#-------------whether URL indexed on Google----------------------#

def url_google_index(url):
    """Check if a URL is indexed on Google."""
    try:
        # Perform a Google search for the URL
        query = f"site:{url}"
        search_results = list(search(query, num=1, stop=1, pause=2))  # Perform search and get first result

        if search_results and url.lower() in search_results[0].lower():
            return True  # URL is indexed on Google
        else:
            return False  # URL is not indexed on Google

    except Exception as e:
        print(f"Error occurred while checking URL indexing on Google: {e}")
        return None
        
        

#-------------whether domain indexed on Google----------------------#

def domain_google_index(url):
    """Check if a domain is indexed on Google."""
    try:
        # Parse the URL to extract the domain
        domain = url.split('//')[-1].split('/')[0]

        # Perform a Google search for the domain
        query = f'site:{domain}'
        search_results = list(search(query, num=1, stop=1, pause=2))

        if search_results:
            first_result_url = search_results[0]
            if domain.lower() in first_result_url.lower():
                return True  # Domain is indexed on Google
            else:
                return False  # Domain is not indexed on Google

    except Exception as e:
        print(f"Error occurred while checking domain indexing on Google: {e}")
        return None



#---------------------Whether URL has TSL/SSL certificate----------------#

def has_valid_ssl_certificate(url):
    """Check if a URL has a valid SSL/TLS certificate."""
    try:
        # Extract the hostname from the URL
        hostname = url.split('//')[-1].split('/')[0]

        # Create an SSL context and establish a connection
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the SSL/TLS certificate
                cert = ssock.getpeercert()

                # Check certificate validation
                if cert and 'subject' in cert and 'issuer' in cert and 'notAfter' in cert:
                    return True  # Valid SSL/TLS certificate
                else:
                    return False  # Invalid SSL/TLS certificate

    except Exception as e:
        #print(f"Error occurred while checking SSL/TLS certificate: {e}")
        return False  # Assume invalid certificate on error
        
        
        
#------------------------Time to Live(TTL)-------------------------------#

def ttl_hostname(url):
    """Get the Time to Live (TTL) for DNS records associated with a URL."""
    try:
        # Extract the domain from the URL
        domain = url.split('//')[-1].split('/')[0]

        # Perform DNS resolution to retrieve DNS records
        answers = dns.resolver.resolve(domain, 'A')  # Resolve A records (IPv4 addresses)
        
        # Get the TTL value from the first DNS record (A record)
        if answers:
            ttl_seconds = answers.rrset.ttl
            return ttl_seconds
        else:
            return None  # No DNS records found or TTL not available

    except Exception as e:
        #print(f"Error occurred while retrieving DNS TTL: {e}")
        return None



#-----------------Number of resolved IPs------------------#

def qty_ip_resolved(url):
    """Get the number of resolved IP addresses associated with a URL."""
    try:
        # Extract the domain from the URL
        domain = url.split('//')[-1].split('/')[0]

        # Resolve the domain to obtain IP addresses
        ip_addresses = set()
        for address_type in [socket.AF_INET, socket.AF_INET6]:  # Resolve both IPv4 and IPv6 addresses
            try:
                addresses = socket.getaddrinfo(domain, None, address_type)
                ip_addresses.update(addr[4][0] for addr in addresses)
            except socket.gaierror:
                pass

        # Count the number of unique IP addresses resolved
        num_ips = len(ip_addresses)
        return num_ips

    except Exception as e:
        #print(f"Error occurred while retrieving resolved IP count: {e}")
        return None


#------------------Number of resolved NS(name-servers)-------------#

def qty_nameservers(url):
    """Get the number of resolved nameservers associated with a URL."""
    try:
        # Extract the domain from the URL
        domain = url.split('//')[-1].split('/')[0]

        # Perform DNS resolution to retrieve nameservers (NS records)
        answers = dns.resolver.resolve(domain, 'NS')

        # Collect unique nameservers from DNS resolution results
        nameservers = set(str(answer) for answer in answers)

        # Count the number of unique nameservers resolved
        num_nameservers = len(nameservers)
        return num_nameservers

    except dns.resolver.NoAnswer:
        # Handle case where no nameserver records (NS) are found for the domain
        #print(f"No nameserver records found for '{domain}'.")
        return 0

    except Exception as e:
        # Handle other exceptions (e.g., DNS resolution errors)
        #print(f"Error occurred while retrieving resolved nameserver count: {e}")
        return None



#-----------------Number of MX servers------------------------#

def qty_mx_servers(url):
    """Get the number of resolved Mail Exchange (MX) servers associated with a URL."""
    try:
        # Extract the domain from the URL
        domain = url.split('//')[-1].split('/')[0]

        # Perform DNS resolution to retrieve MX records
        answers = dns.resolver.resolve(domain, 'MX')

        # Count the number of unique MX servers resolved
        mx_servers = set(str(answer.exchange) for answer in answers)
        num_mx_servers = len(mx_servers)

        return num_mx_servers

    except dns.resolver.NoAnswer:
        # Handle case where no MX records are found for the domain
        #print(f"No Mail Exchange (MX) records found for '{domain}'.")
        return 0

    except Exception as e:
        # Handle other exceptions (e.g., DNS resolution errors)
        #print(f"Error occurred while retrieving MX server count: {e}")
        return None
  
