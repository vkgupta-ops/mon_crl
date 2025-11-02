import requests
import json
import os
from datetime import datetime, timezone
import subprocess
import sys



def get_crl():
    """
    Get CRL information for all valid CAs
    
    """
    all_crl_info = []

    list = [
        "https://vkgupta-ops.github.io/mon_crl/ca1.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca2.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca3.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca4.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca5.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca6.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca7.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca8.crl",
        "https://vkgupta-ops.github.io/mon_crl/ca10.crl"
    ]
    
    all_crl_info = []

    for crl_url in list:

        print(f"Processing for CRL: {crl_url}")

        try:

            curl_cmd = ['curl', '-s', crl_url]
            curl_result = subprocess.run(curl_cmd, capture_output=True, check=False)

            if curl_result.returncode != 0:
                print(f"Failed to fetch CRL from {crl_url}")
                continue

        except subprocess.CalledProcessError as e:
            print(f"{e}")

        try:

            openssl_cmd = ['openssl', 'crl', '-inform', 'DER', '-noout', '-text']
            process = subprocess.Popen(
                openssl_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout_bytes, stderr_bytes = process.communicate(input=curl_result.stdout)

            if process.returncode != 0:
                print(f"Failed to parse CRL with openssl for {crl_url}")
                continue

            openssl_output = stdout_bytes.decode('utf-8', errors='ignore')

            crl_data = _parse_crl_text(openssl_output)

            cas_info = {
                'CRL_URL': crl_url,
                'CRL_LAST_UPDATE': crl_data.get('last_update'),
                'CRL_NEXT_UPDATE': crl_data.get('next_update')
            },
            
            all_crl_info.append(cas_info)

        except Exception as e:
            print(f"Error processing CRL for {crl_url}: {e}")

    return all_crl_info


def _parse_crl_text(openssl_text):
    """
    Parse OpenSSL CRL text output
    
    """
    crl_info = {}
    lines = openssl_text.split('\n')
    
    for line in lines:
        line = line.strip()
        
        if 'Last Update:' in line:
            crl_info['last_update'] = line.replace('Last Update:', '').strip()
        
        elif 'Next Update:' in line:
            crl_info['next_update'] = line.replace('Next Update:', '').strip()
    
    return crl_info


output = get_crl()
flatten_output = [ item[0] for item in output ]
print(flatten_output)
