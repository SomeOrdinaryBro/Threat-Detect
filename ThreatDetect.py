import re
import os
import argparse
import requests
import urllib.parse
import logging
import sys
from html import escape
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

logging.basicConfig(filename='error.log', level=logging.ERROR)

VT_API_BASE_URL = 'https://www.virustotal.com/vtapi/v2'
VT_API_KEY = os.environ.get('VT_API_KEY')

class ApiKeyError(Exception):
    pass

class ScanError(Exception):
    pass

if not VT_API_KEY:
    logging.error('VirusTotal API key is not set in the environment')
    print('Error: VirusTotal API key is not set. Please set the VT_API_KEY environment variable.')
    exit()

def scan_url(api_key: str, url: str) -> None:
    """
    Scan a URL for threats using the VirusTotal API.
    """
    url = url.strip()

    if url == 'exit':
        print('Exiting program.')
        sys.exit()

    if not is_valid_url(url):
        print('Error: Invalid URL. Please enter a valid URL.')
        return

    if not api_key or len(api_key) != 64:
        raise ValueError("Invalid API key")

    params = {'apikey': api_key, 'resource': url}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'My Python requests library example client or username'
    }

    try:
        response = requests.get(f'{VT_API_BASE_URL}/url/report', params=params, headers=headers, timeout=30)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f'An error occurred while scanning the URL: {e}')
        raise

    json_response = response.json()

    if json_response.get('response_code', 0) == 0:
        print('No information available for URL: ' + escape(url))
        return

    if json_response['positives'] == 0:
        print(f'The URL {escape(url)} is safe.')
    else:
        print(f'The URL {escape(url)} is malicious.')
        print(f'Positive detections: {json_response["positives"]}')
        print(f'Total detections: {json_response["total"]}')

    url_report = escape(json_response['permalink'])
    if json_response['positives'] > 0:
        filename = escape(url.replace('/', '_')) + '_scan_report.html'
        try:
            with open(os.path.abspath(filename), 'w') as f:
                f.write(f'<html><body><a href="{url_report}">{url_report}</a></body></html>')
        except Exception as e:
            logging.error(f'An error occurred while writing to the file: {e}')
            raise

        print(f'A detailed report has been saved in the same directory as this script: {os.path.abspath(filename)}')
    else:
        print('No detailed report has been created as the URL is safe.')

    log_filename = 'scan_log.txt'
    with open(os.path.abspath(log_filename), 'a') as f:
        f.write(f'URL: {escape(url)}\n')
        if json_response.get('response_code', 0) != 0:
            f.write(f'Positive detections: {json_response["positives"]}\n')
            f.write(f'Total detections: {json_response["total"]}\n')
        f.write(f'Scan permalink: {url_report}\n')
        f.write('-------------------------------------------\n')

def is_valid_url(url):
    """
    Check if a given string is a valid URL
    """
    if not url:
        return False
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return False
    if not re.match(r'^[a-zA-Z0-9\-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\%]+$', parsed_url.geturl()):
        return False
    return True

def main():
    print("Starting the Threat Detect Scanner...")
    while True:
        url_to_scan = input("Enter the URL to scan (or type 'exit' to quit): ")
        if url_to_scan.lower() == 'exit':
            break
        if not is_valid_url(url_to_scan):
            print(f"Invalid URL: {url_to_scan}")
            continue
        try:
            scan_url(VT_API_KEY, url_to_scan)
        except ApiKeyError:
            print("Error: Invalid API key. Please check your API key and try again.")
            continue
        except ScanError as e:
            print(f"Error scanning URL: {str(e)}. Please try again later.")
            continue
        choice = input("Scan another URL? (y/n): ")
        if choice.lower() == 'n':
            break
    print("Exiting the Threat Detect Scanner...")

if __name__ == '__main__':
    main()
