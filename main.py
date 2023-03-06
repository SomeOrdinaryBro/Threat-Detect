import os
import webbrowser
import requests

API_KEY = 'API_KEY_GOES_HERE' #You can get your api key from this link >> https://www.virustotal.com/

def scan_url(url):
    url = url.strip()
    params = {'apikey': API_KEY, 'resource': url}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'gzip, My Python requests library example client or username'
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    json_response = response.json()

    if json_response['response_code'] == 0:
        print('No information available for URL: ' + url)
        return

    if json_response['positives'] == 0:
        print('The URL is safe: ' + url)
        return

    print('The URL is malicious: ' + url)
    print('Positive detections: ' + str(json_response['positives']))
    print('Total detections: ' + str(json_response['total']))
    url_report = json_response['permalink']
    filename = url.replace('/', '_') + '_scan_report.html'
    with open(filename, 'w') as f:
        f.write(f'<html><body><a href="{url_report}">{url_report}</a></body></html>')
    print('A detailed report has been downloaded in the same directory as this script: ' + os.path.abspath(filename))
    webbrowser.open_new_tab(os.path.abspath(filename))

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('Welcome to the VirusTotal URL scanner')
        print('Please enter the URL you would like to scan:')
        url = input()
        try:
            response = requests.get(url)
            if response.status_code != 200:
                print('The URL is not valid: ' + url)
                continue
        except:
            print('The URL is not valid: ' + url)
            continue

        scan_url(url)

        print('\nDo you want to scan another URL? y/n')
        answer = input()
        if answer.lower() != 'y':
            break

if __name__ == '__main__':
    main()
