import os
import argparse
import requests
import urllib.parse
import logging
import sys
from html import escape
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(filename='error.log', level=logging.ERROR)

VT_API_BASE_URL = 'https://www.virustotal.com/vtapi/v2'
VT_API_KEY = os.environ.get('VT_API_KEY')

if not VT_API_KEY:
    logging.error('VirusTotal API key is not set in the environment')
    print('VirusTotal API key is not set in the environment')
    exit()

def scan_url(api_key, url):
    url = url.strip()

    if url == 'exit':
        print('Exiting program.')
        sys.exit()

    if not is_valid_url(url):
        print('Invalid URL: ' + url)
        return

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
        print('An error occurred while scanning the URL. Please try again later.')
        return

    json_response = response.json()

    if json_response.get('response_code', 0) == 0:
        print('No information available for URL: ' + escape(url))
        return

    if json_response['positives'] == 0:
        print('The URL is safe: ' + escape(url))
    else:
        print('The URL is malicious: ' + escape(url))
        print('Positive detections: ' + str(json_response['positives']))
        print('Total detections: ' + str(json_response['total']))

    url_report = escape(json_response['permalink'])
    if json_response['positives'] > 0:
        filename = escape(url.replace('/', '_')) + '_scan_report.html'
        try:
            with open(os.path.abspath(filename), 'w') as f:
                f.write(f'<html><body><a href="{url_report}">{url_report}</a></body></html>')
        except Exception as e:
            logging.error(f'An error occurred while writing to the file: {e}')
            print('An error occurred while writing to the file. Please try again later.')
            return

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
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

if __name__ == '__main__':
    while True:
        url = input("Enter a URL to scan (or 'exit' to quit): ")
        if url == 'exit':
            print('Exiting program.')
            sys.exit()
        if is_valid_url(url):
            scan_url(VT_API_KEY, url)
        else:
            print('Invalid URL: ' + url)
