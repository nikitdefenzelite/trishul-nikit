from flask import Flask, render_template, request
import tldextract
import socket
import whois
import requests
from bs4 import BeautifulSoup
import ssl
import OpenSSL.crypto
import datetime
import re
import dns.resolver

app = Flask(__name__)

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

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form["url"]
    domain = tldextract.extract(url).registered_domain

    subdomains = get_subdomains(domain)
    assets = get_assets(url)
    certificate = get_certificate(domain)
    emails = get_emails(url)
    logo_url = get_logo(url)
    social_profiles = get_social_profiles(url)
    keywords = get_keywords(url)
    third_party_services = get_third_party_services(url)
    vendor_info = get_vendor_info(url)
    sister_companies = get_sister_companies(url)
    api_details = get_api_details(url)
    object_storage = get_object_storage(url)
    cdn = get_cdn(url)
    data_storage = get_data_storage(url)
    contact_details = get_contact_details(url)
    login_urls = get_login_url(url)
    mobile_apps = get_mobile_apps(url)

    return render_template("results.html",
                           subdomains=subdomains,
                           assets=assets,
                           certificate=certificate,
                           emails=emails,
                           logo_url=logo_url,
                           social_profiles=social_profiles,
                           keywords=keywords,
                           third_party_services=third_party_services,
                           vendor_info=vendor_info,
                           sister_companies=sister_companies, 
                           api_details=api_details, 
                           object_storage=object_storage, 
                           cdn=cdn, 
                           data_storage=data_storage, 
                           contact_details=contact_details, 
                           login_urls=login_urls, 
                           mobile_apps=mobile_apps)

if __name__ == "__main__":
    app.run(debug=True)
