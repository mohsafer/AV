import os
import json
import requests
import webbrowser
import time
import sys

API_KEY = '750cd8398a7f88cb6c260ff5e20578bcc0eb51092f9326b089103a6a63cb26f2'

def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()

def scan_results(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

def scan_usb(path):
    for dirpath, dirnames, filenames in os.walk(path):
        for file_name in filenames:
            file_path = os.path.join(dirpath, file_name)
            print(f'Scanning {file_path}...')
            scan_response = scan_file(file_path)
            resource = scan_response.get('resource')
            if resource:
                scan_result = scan_results(resource)
                print(json.dumps(scan_result, indent=4))
            else:
                print(scan_response)

    for drive in ['A:\\', 'B:\\', 'C:\\', 'D:\\', 'E:\\', 'F:\\', 'G:\\', 'H:\\']:
        try:
            os.chdir(drive)
            print(f'\nScanning {drive}...')
            scan_usb(drive)
        except:
            pass


def scan_url(url):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': API_KEY, 'url': url}
    response = requests.post(url, params=params)
    return response.json()

def scan_results(resource):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()



url = input("Enter URL Address: ")
def open_website(url):
    scan_response = scan_url(url)
    resource = scan_response.get('resource')
    if resource:
        scan_result = scan_results(resource)
        positives = scan_result.get('positives')
        if positives > 0:
            print(f'{positives} out of {scan_result.get("total")} scanners found this URL to be malicious.')
        else:
            print('This URL is not malicious.')
            webbrowser.open(url)
    else:
        print(scan_response)
open_website(url)

print("Scanning Files in progress...", end="")
while True:
    for i in ["/", "-", "\\", "|"]:
        print(f"\r{i}", end="")
        sys.stdout.flush()
        time.sleep(0.1)

