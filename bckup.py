import socket
import whois
import tldextract
import requests
from bs4 import BeautifulSoup
import ssl
import OpenSSL.crypto
import datetime
import re
import dns.resolver

def get_subdomains(domain):
    subdomains = []
    try:
        domain_ip = socket.gethostbyname(domain)
        subdomains.append({"Domain": domain, "IP": domain_ip})
    except socket.gaierror:
        pass

    try:
        # Get domain's whois information
        domain_info = whois.whois(domain)
        if domain_info.name_servers:
            for nameserver in domain_info.name_servers:
                try:
                    ns_ip = socket.gethostbyname(nameserver)
                    subdomains.append({"Domain": nameserver, "IP": ns_ip})
                except socket.gaierror:
                    pass
    except whois.parser.PywhoisError:
        pass

    return subdomains

def get_assets(url):
    assets = {"Images": [], "CSS": [], "JavaScript": []}
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extracting images
        img_tags = soup.find_all('img')
        for img in img_tags:
            src = img.get('src')
            if src:
                assets["Images"].append(src)

        # Extracting CSS files
        css_links = soup.find_all('link', rel='stylesheet')
        for link in css_links:
            href = link.get('href')
            if href:
                assets["CSS"].append(href)

        # Extracting JavaScript files
        script_tags = soup.find_all('script')
        for script in script_tags:
            src = script.get('src')
            if src:
                assets["JavaScript"].append(src)

    except requests.RequestException:
        pass

    return assets

def get_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                issuer = x509.get_issuer().CN
                subject = x509.get_subject().CN
                expiration_date = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                return {"Issuer": issuer, "Subject": subject, "Expiration Date": expiration_date}
    except (socket.gaierror, ssl.SSLError, OSError, OpenSSL.crypto.Error) as e:
        print(f"Error retrieving certificate for {domain}: {e}")
        return None

def get_emails(url):
    emails = []
    try:
        response = requests.get(url)
        text = response.text
        emails = re.findall(r'[\w\.-]+@[\w\.-]+', text)
    except requests.RequestException:
        pass
    return emails

def get_logo(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        logo = soup.find('link', rel='icon')
        if logo:
            return logo['href']
        else:
            return None
    except requests.RequestException:
        return None

def get_social_profiles(url):
    social_profiles = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for different social profiles
        social_tags = soup.find_all('a', href=re.compile(r'(facebook|twitter|linkedin|instagram)'))
        for tag in social_tags:
            social_profiles.append(tag['href'])
    except requests.RequestException:
        pass
    return social_profiles

def get_keywords(url):
    keywords = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        meta_tags = soup.find_all('meta', attrs={'name': 'keywords'})
        for tag in meta_tags:
            keywords.extend(tag['content'].split(','))
    except requests.RequestException:
        pass
    return keywords

def get_third_party_services(url):
    third_party_services = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for third-party services
        third_party_tags = soup.find_all('script', src=re.compile(r'(analytics|adsbygoogle|widgets)'))
        for tag in third_party_tags:
            third_party_services.append(tag['src'])
    except requests.RequestException:
        pass
    return third_party_services

def get_vendor_info(url):
    vendor_info = {}
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for vendor information
        vendor_tags = soup.find_all('meta', attrs={'name': 'vendor'})
        for tag in vendor_tags:
            vendor_info[tag['name']] = tag['content']
    except requests.RequestException:
        pass
    return vendor_info

def get_sister_companies(url):
    sister_companies = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for sister company information
        sister_company_tags = soup.find_all('a', href=re.compile(r'sister-company|subsidiary'))
        for tag in sister_company_tags:
            sister_companies.append(tag['href'])
    except requests.RequestException:
        pass
    return sister_companies

def get_api_details(url):
    api_details = {}
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for API details
        api_tags = soup.find_all('meta', attrs={'name': 'api'})
        for tag in api_tags:
            api_details[tag['name']] = tag['content']
    except requests.RequestException:
        pass
    return api_details

def get_object_storage(url):
    object_storage = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for object storage details
        object_storage_tags = soup.find_all('a', href=re.compile(r'storage|object-storage'))
        for tag in object_storage_tags:
            object_storage.append(tag['href'])
    except requests.RequestException:
        pass
    return object_storage

def get_cdn(url):
    cdn = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for CDN details
        cdn_tags = soup.find_all('a', href=re.compile(r'cdn|content-delivery-network'))
        for tag in cdn_tags:
            cdn.append(tag['href'])
    except requests.RequestException:
        pass
    return cdn

def get_data_storage(url):
    data_storage = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for data storage details
        data_storage_tags = soup.find_all('a', href=re.compile(r'data-storage|database'))
        for tag in data_storage_tags:
            data_storage.append(tag['href'])
    except requests.RequestException:
        pass
    return data_storage

def get_contact_details(url):
    contact_details = {"Phone Numbers": [], "Emails": []}
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for contact details
        phone_tags = soup.find_all('a', href=re.compile(r'tel:'))
        for tag in phone_tags:
            contact_details["Phone Numbers"].append(tag['href'].replace('tel:', ''))
        email_tags = soup.find_all('a', href=re.compile(r'mailto:'))
        for tag in email_tags:
            contact_details["Emails"].append(tag['href'].replace('mailto:', ''))
    except requests.RequestException:
        pass
    return contact_details

def get_login_url(url):
    login_urls = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for login URLs
        login_tags = soup.find_all('a', href=re.compile(r'login|signin|auth'))
        for tag in login_tags:
            login_urls.append(tag['href'])
    except requests.RequestException:
        pass
    return login_urls

def get_mobile_apps(url):
    mobile_apps = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Add selectors for mobile app details
        app_tags = soup.find_all('a', href=re.compile(r'apps|mobile'))
        for tag in app_tags:
            mobile_apps.append(tag['href'])
    except requests.RequestException:
        pass
    return mobile_apps

def main():
    url = input("Enter the URL: ")
    domain = tldextract.extract(url).registered_domain

    print(f"Finding details for {domain}...")
    subdomains = get_subdomains(domain)

    if subdomains:
        print("\nSubdomains and their details:")
        for subdomain in subdomains:
            print(f"Domain: {subdomain['Domain']}, IP: {subdomain['IP']}")
            # Additional details can be added here

    # Fetching assets
    print("\nFetching assets...")
    assets = get_assets(url)
    if assets:
        print("\nAssets:")
        for asset_type, asset_list in assets.items():
            print(f"{asset_type}:")
            for asset in asset_list:
                print(asset)
    else:
        print("No assets found.")

    # Fetching SSL certificate
    print("\nFetching SSL Certificate...")
    certificate = get_certificate(domain)
    if certificate:
        print("\nCertificate Details:")
        for key, value in certificate.items():
            print(f"{key}: {value}")
    else:
        print("No certificate found.")

    # Fetching emails
    print("\nFetching Emails...")
    emails = get_emails(url)
    if emails:
        print("\nEmails found:")
        for email in emails:
            print(email)
    else:
        print("No emails found.")

    # Fetching logo
    print("\nFetching Logo...")
    logo_url = get_logo(url)
    if logo_url:
        print(f"\nLogo URL: {logo_url}")
    else:
        print("No logo found.")

    # Fetching social profiles
    print("\nFetching Social Profiles...")
    social_profiles = get_social_profiles(url)
    if social_profiles:
        print("\nSocial Profiles found:")
        for profile in social_profiles:
            print(profile)
    else:
        print("No social profiles found.")

    # Fetching keywords
    print("\nFetching Keywords...")
    keywords = get_keywords(url)
    if keywords:
        print("\nKeywords found:")
        for keyword in keywords:
            print(keyword)
    else:
        print("No keywords found.")

    # Fetching third-party services
    print("\nFetching Third-party Services...")
    third_party_services = get_third_party_services(url)
    if third_party_services:
        print("\nThird-party Services found:")
        for service in third_party_services:
            print(service)
    else:
        print("No third-party services found.")

    # Fetching vendor information
    print("\nFetching Vendor Information...")
    vendor_info = get_vendor_info(url)
    if vendor_info:
        print("\nVendor Information:")
        for key, value in vendor_info.items():
            print(f"{key}: {value}")
    else:
        print("No vendor information found.")

    # Fetching sister companies
    print("\nFetching Sister Companies...")
    sister_companies = get_sister_companies(url)
    if sister_companies:
        print("\nSister Companies found:")
        for company in sister_companies:
            print(company)
    else:
        print("No sister companies found.")

    # Fetching API details
    print("\nFetching API Details...")
    api_details = get_api_details(url)
    if api_details:
        print("\nAPI Details:")
        for key, value in api_details.items():
            print(f"{key}: {value}")
    else:
        print("No API details found.")

    # Fetching Object Storage
    print("\nFetching Object Storage...")
    object_storage = get_object_storage(url)
    if object_storage:
        print("\nObject Storage found:")
        for storage in object_storage:
            print(storage)
    else:
        print("No Object Storage found.")

    # Fetching CDN
    print("\nFetching CDN...")
    cdn = get_cdn(url)
    if cdn:
        print("\nCDN found:")
        for cdn_url in cdn:
            print(cdn_url)
    else:
        print("No CDN found.")

    # Fetching Data Storage
    print("\nFetching Data Storage...")
    data_storage = get_data_storage(url)
    if data_storage:
        print("\nData Storage found:")
        for storage in data_storage:
            print(storage)
    else:
        print("No Data Storage found.")

    # Fetching Contact Details
    print("\nFetching Contact Details...")
    contact_details = get_contact_details(url)
    if contact_details:
        print("\nContact Details:")
        for key, values in contact_details.items():
            print(f"{key}:")
            for value in values:
                print(value)
    else:
        print("No contact details found.")

    # Fetching Login URLs
    print("\nFetching Login URLs...")
    login_urls = get_login_url(url)
    if login_urls:
        print("\nLogin URLs found:")
        for login_url in login_urls:
            print(login_url)
    else:
        print("No login URLs found.")

    # Fetching Mobile Apps
    print("\nFetching Mobile Apps...")
    mobile_apps = get_mobile_apps(url)
    if mobile_apps:
        print("\nMobile Apps found:")
        for app in mobile_apps:
            print(app)
    else:
        print("No mobile apps found.")

if __name__ == "__main__":
    main()
