import requests
import json
import os
from datetime import datetime, timezone
import calendar
import subprocess
import sys
from datadog_checks.base import AgentCheck


class PkiCheck(AgentCheck):


    def get_crl(self):
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

            self.log.info(f"Processing for CRL: {crl_url}")

            try:

                curl_cmd = ['curl', '-s', crl_url]
                curl_result = subprocess.run(curl_cmd, capture_output=True, check=False)

                if curl_result.returncode != 0:
                    self.log.info(f"Failed to fetch CRL from {crl_url}")
                    continue

            except subprocess.CalledProcessError as e:
                self.log.error(f"{e}")

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
                    self.log.info(f"Failed to parse CRL with openssl for {crl_url}")
                    continue

                openssl_output = stdout_bytes.decode('utf-8', errors='ignore')

                crl_data = self._parse_crl_text(openssl_output)

                cas_info = {
                    'CRL_URL': crl_url,
                    'CRL_LAST_UPDATE': crl_data.get('last_update'),
                    'CRL_NEXT_UPDATE': crl_data.get('next_update')
                },
                
                all_crl_info.append(cas_info)

            except Exception as e:
                self.log.info(f"Error processing CRL for {crl_url}: {e}")

        return all_crl_info


    def _parse_crl_text(self, openssl_text):
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

    def convert_to_unix(self, timestamp_str):
        dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y %Z")
        unix_dt    = calendar.timegm(dt.timetuple())
        unix_dt_ms = (unix_dt * 1000)

        return unix_dt_ms


    def process_and_send_metrics(self, data):
        """Calculate metrics from data and send to Datadog"""

        current_time = int(datetime.now().timestamp() * 1000)
        total = len(data)
        expired = 0
        valid = 0
        expiring_6 = 0
        crl_pending = 0
        crl_current = 0
        six_days_ms = 6 * 24 * 60 * 60 * 1000
        total_days_until_expiry = 0
        valid_cert_count = 0
        
        for cert in data:
            crl_next_update = cert.get('CRL_NEXT_UPDATE')
            crl_last_update = cert.get('CRL_LAST_UPDATE')
            crl_url         = cert.get("CRL_URL")


            print(f"crl_url : {crl_url}")
            
            nu = self.convert_to_unix(crl_next_update)
            lu = self.convert_to_unix(crl_last_update)

            # print(f"next_update_unix : {nu}")
            # print(f"last_update_unix : {lu}")
            
            validity = nu - current_time

            # print(f"validity_in_days_unix: {validity}")

            days_difference = validity // 86400000
            print(f"validity_in_days : {days_difference}")

            
            
            if days_difference <= 1:
                expired += 1
                message = f'crl_url:{crl_url} is expired'
                print(message)
                status  = AgentCheck.CRITICAL
                self.gauge(f'{self.metric_prefix}.cert.expired', 1, tags=self.tags + [f'crl_url:{crl_url}', 'status:expired'])
                self.service_check(f'{self.metric_prefix}.status', status, message=message, tags=self.tags + [f'crl_url:{crl_url}'])


            elif days_difference <= 2:
                expiring_6 += 1
                message = f'crl_url:{crl_url} will be going to expire in 2 days'
                # days_left = (nu - current_time) / (24 * 60 * 60 * 1000)
                days_left = days_difference
                print(message)
                print(f"days_left: {days_difference}")

                status  = AgentCheck.WARNING
                self.gauge(f'{self.metric_prefix}.cert.days_until_expiry', days_left, tags=self.tags + [f'crl_url:{crl_url}', 'urgency:high'])
                self.service_check(f'{self.metric_prefix}.status', status, message=message, tags=self.tags + [f'crl_url:{crl_url}'])
                
            elif days_difference <= 6:
                expiring_6 += 1
                message = f'crl_url:{crl_url} will be going to expire in 6 days'
                # days_left = (nu - current_time) / (24 * 60 * 60 * 1000)
                print(message)
                print(f"days_left: {days_difference}")

                status  = AgentCheck.WARNING
                self.gauge(f'{self.metric_prefix}.cert.days_until_expiry', days_left, tags=self.tags + [f'crl_url:{crl_url}', 'urgency:warning'])
                self.service_check(f'{self.metric_prefix}.status', status, message=message, tags=self.tags + [f'crl_url:{crl_url}'])


            else:
                valid += 1
                message = f'crl_url:{crl_url} is valid'
                print(message)
                status  = AgentCheck.OK
                self.service_check(f'{self.metric_prefix}.status', status, message=message, tags=self.tags + [f'crl_url:{crl_url}'])
            
        
        self.gauge(f'{self.metric_prefix}.total', total, tags=self.tags)
        self.gauge(f'{self.metric_prefix}.expired', expired, tags=self.tags + ['status:expired'])
        self.gauge(f'{self.metric_prefix}.expiring_in.6days', expiring_6, tags=self.tags + ['window:7days'])
        self.gauge(f'{self.metric_prefix}.valid', valid, tags=self.tags + ['status:valid'])

        
        self.log.info(f"Metrics sent - Total: {total}, Expired: {expired}, Expiring (6d): {expiring_6}, Valid: {valid}")


    def check(self):

        try:

            output = self.get_crl()
            flatten_output = [ item[0] for item in output ]
            self.log.info(flatten_output)

            result = self.process_and_send_metrics(flatten_output)
            self.log.info(f"{result}")

        except Exception as e:
            self.log.error(f"{e}")

if __name__ == "__main__":
    # Create instance
    my_stream = PkiCheck(AgentCheck)
    
    # Call methods
    my_stream.check()
