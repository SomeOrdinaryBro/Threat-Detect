# Threat Detect

This Python script allows you to scan a URL for malware using the VirusTotal API. After scanning, the script generates a detailed report on the scan results and opens it in your default web browser.

## How to Use

1.  Get an API key from VirusTotal website.
2.  Install `requests` module using `pip install requests`.
3.  Set the API key in `VT_API_KEY` variable in `,env` file.
4.  Execute the script `ThreatDetect.py`.
5.  Enter the URL you want to scan when prompted.


## How it works

This script checks the validity of a URL and scans it for threats using the VirusTotal API. It generates a report of the scan results and saves it in the same directory as the script. If the scan detects malware, the report provides information on the number of positive detections and the total number of detections. The script also logs the URL, positive detections, total detections, and scan permalink in a log file.

The script is equipped with error logging functionality using the `logging` module. If an error occurs, the script will write the error message to an error log file.

## Contributing

This project is open to contributions. Feel free to raise an issue or submit a pull request.

# License

This project is licensed under the terms of the MIT license.
