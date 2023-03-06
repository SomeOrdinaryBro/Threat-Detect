import os
import argparse
import requests

def scan_url(api_key, url):
    url = url.strip()
    params = {'apikey': api_key, 'resource': url}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'gzip, My Python requests library example client or username'
    }

    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'An error occurred while scanning the URL: {e}')
        return

    json_response = response.json()

    if json_response['response_code'] == 0:
        print('No information available for URL: ' + url)
        return

    if json_response['positives'] == 0:
        print('The URL is safe: ' + url)
    else:
        print('The URL is malicious: ' + url)
        print('Positive detections: ' + str(json_response['positives']))
        print('Total detections: ' + str(json_response['total']))

    url_report = json_response['permalink']
    if json_response['positives'] > 0:
        filename = url.replace('/', '_') + '_scan_report.html'
        try:
            with open(filename, 'w') as f:
                f.write(f'<html><body><a href="{url_report}">{url_report}</a></body></html>')
        except Exception as e:
            print(f'An error occurred while writing to the file: {e}')
            return

        print(f'A detailed report has been saved in the same directory as this script: {os.path.abspath(filename)}')
    else:
        print('No detailed report has been created as the URL is safe.')

    # Append the URL and its scan report to a log file
    log_filename = 'scan_log.txt'
    with open(log_filename, 'a') as f:
        f.write(f'URL: {url}\n')
        if json_response['response_code'] != 0:
            f.write(f'Positive detections: {json_response["positives"]}\n')
            f.write(f'Total detections: {json_response["total"]}\n')
            f.write(f'Scan report URL: {url_report}\n')
        f.write('\n')

def main(api_key):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('Welcome to the VirusTotal URL scanner')
        print('Please enter the URL you would like to scan (or "exit" to quit):')
        url = input()

        if url.lower() == 'exit':
            break

        try:
            response = requests.get(url)
            if response.status_code != 200:
                print('The URL is not valid: ' + url)
                continue
        except requests.exceptions.RequestException:
            print('The URL is not valid: ' + url)
            continue

        scan_url(api_key, url)

        print('\nDo you want to scan another URL? y/n')
        answer = input()
        if answer.lower() != 'y':
            break

if __name__ == '__main__':
    API_KEY = 'Your_API_Key_Goes_Here'
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params={'apikey': API_KEY, 'resource': 'https://www.google.com/'})
        if response.status_code != 200:
            print('Invalid API key or API limit exceeded')
    except requests.exceptions.RequestException:
        print('Invalid API key or API limit exceeded')
    else:
        main(api_key=API_KEY)
