# Virustotal_checker

### Reach me at:

- [![Twitter](https://img.shields.io/twitter/follow/salehswt_?style=social)](https://twitter.com/intent/follow?screen_name=salehswt_)

###
###
![alt text](https://cdn.discordapp.com/attachments/1115755309730893858/1115756044929486931/VTChecker.png)

## Description

Virustotal_checker is a Python script that allows you to check the reputation of hashes, scan IPs and domains, and download executables from VirusTotal. It utilizes the VirusTotal API to fetch information about hashes, IPs, and domains and provides detailed analysis and results.

## Features

- Check the reputation of a single hash and get information about engines that flagged it and related Info.
- Download a file by its hash (requires a premium VirusTotal API key).
- Scan multiple IPs and domains and generate a CSV file with the detection results.
- Scan a single IP and get detailed analysis and results.
- Scan a domain and get detailed analysis and results.
- Scan a file based on its hash and get detailed analysis and results.

## Requirements

- Python 3.x
- Requests library
- PrettyTable library
- Colorama library
- dotenv library

## Usage

1. Clone the repository:
```
https://github.com/Salehswt/Virustotal_Checker.git
```
2. Install the required libraries:

```
pip install -r requirements.txt
```

3. Set up your VirusTotal API key:

- Create an account on VirusTotal.
- Generate an API key from your account settings.
- Add your API key to .env file in the project directory:

```
apikey=YOUR_API_KEY
```

## Command Line Options

The following command line options are available for use with Virustotal_checker:

- `-a`: Download an executable by its hash.
- `-l`: Scan multiple IPs, domains, or both.
- `-s`: Scan a single IP, domain, or hash.
- `-f`: Scan an executable file by its path.
