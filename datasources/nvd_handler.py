import threading
import time
import requests
import json
from queue import Queue
from datetime import datetime, timedelta

from handlers.logger_handler import Logger
from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongodbHandler

class ThreadSafeCounter:
    def __init__(self):
        self.value = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self.value += 1
            return self.value


def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class NvdHandler:

    def __init__(self, config_file='configuration.ini'):
        config_handler = ConfigHandler(config_file)

        nvd_config = config_handler.get_nvd_config()
        self.baseurl = nvd_config.get('url', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.api_key = nvd_config.get('apikey', '')
        self.public_rate_limit = int(nvd_config.get('public_rate_limit', 5))
        self.api_rate_limit = int(nvd_config.get('apikey_rate_limit', 50))
        self.rolling_window = int(nvd_config.get('rolling_window', 30))
        self.retry_limit = int(nvd_config.get('retry_limit', 3))
        self.retry_delay = int(nvd_config.get('retry_delay', 10))
        self.results_per_page = int(nvd_config.get('results_per_page', 2000))
        self.max_threads = int(nvd_config.get('max_threads', 5))

        mongodb_config = config_handler.get_mongodb_config()        
        self.mongodb_handler = MongodbHandler(
            mongodb_config['host'],
            mongodb_config['port'],
            mongodb_config['db'],
            mongodb_config['username'],
            mongodb_config['password'],
            mongodb_config['authdb'],
            mongodb_config['prefix'])
    
    def queryNVD(self, custom_params={}, follow=True):

        def fetch_data(params, queue, counter):
            query_number = counter.increment()
            thread_name = threading.current_thread().name
            headers = {"apiKey": self.api_key} if self.api_key else {}

            Logger.log(f"Query {query_number} [{thread_name}] params {params}", "DEBUG")
            full_url = requests.Request('GET', self.baseurl, headers=headers, params=params).prepare().url

            attempts = 0
            while attempts < self.retry_limit:
                Logger.log(f"Query {query_number} [{thread_name}] Attempt {attempts + 1}: GET {full_url}", "INFO")

                response = requests.get(full_url, headers=headers)

                if response.status_code == 200:
                    try:
                        if response.headers.get('Content-Type') == 'application/json' and response.content:
                            json_data = response.json()
                            Logger.log(f"Response from Query {query_number}: {json_data}", "DEBUG")

                            vulnerabilities = [
                                vuln.get('cve', {})
                                for vuln in json_data.get('vulnerabilities', [])
                            ]

                            if vulnerabilities:
                                self.mongodb_handler.insert_many("cve", vulnerabilities)
                            
                            total_results = json_data.get('totalResults', 0)
                            queue.put((vulnerabilities, total_results))
                        else:
                            Logger.log(f"No JSON data in response from Query {query_number}", "WARNING")
                            queue.put(([], 0))
                    except json.JSONDecodeError as e:
                        Logger.log(f"JSON decoding failed for Query {query_number}: {e}", "ERROR")
                        queue.put(([], 0))                    
                    
                    break  # Exit the loop after successful processing

                elif response.status_code == 403:
                    Logger.log(f"Rate limit hit, retrying in {self.retry_delay} seconds.", "WARNING")
                    time.sleep(self.retry_delay)
                    attempts += 1

                elif response.status_code == 404:
                    Logger.log("Resource not found (HTTP 404). Stopping.", "ERROR")
                    queue.put(([], -1))  # -1 indicates an error state

                else:
                    Logger.log(f"Failed to retrieve data: HTTP {response.status_code}", "ERROR")
                    queue.put(([], 0))
                    break  # Exit the loop on other errors

        default_params = {
            "resultsPerPage": self.results_per_page,
            "startIndex": 0  # This will be updated in the loop below
        }

        queue = Queue()
        threads = []
        all_cves = []
        rate_limit = self.api_rate_limit if self.api_key else self.public_rate_limit
        query_counter = ThreadSafeCounter()

        # Fetch initial data to determine total results
        initial_params = {**default_params, **custom_params}
        fetch_data(initial_params, queue, query_counter)
        initial_data, total_results = queue.get()
        if total_results == -1:  # Error state
            return []

        all_cves.extend(initial_data)

        if follow and total_results > self.results_per_page:
            next_start_index = self.results_per_page

            while next_start_index < total_results:
                params = {**default_params, **custom_params, "startIndex": next_start_index}

                while len(threads) < self.max_threads and next_start_index < total_results:
                    thread = threading.Thread(target=fetch_data, args=(params.copy(), queue, query_counter))
                    threads.append(thread)
                    thread.start()
                    next_start_index += self.results_per_page  # Increment for next thread

                for thread in threads:  # Wait for threads to complete
                    thread.join()
                threads = []

        while not queue.empty():
            cve_items, _ = queue.get()
            all_cves.extend(cve_items)

        return all_cves

    def getAllCVE(self, custom_params={}, follow=True):
        #TODO: Do we still need to return the full list of CVE ? not sure ... 
        return self.queryNVD(custom_params, follow)

    def getUpdates(self, last_hours=1, follow=True):
        now_utc = datetime.utcnow()
        lastModStartDate = (now_utc - timedelta(hours=last_hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
        lastModEndDate = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        custom_params = {
            "lastModStartDate": lastModStartDate,
            "lastModEndDate": lastModEndDate
        }

        #TODO: Do we still need to return the full list of CVE ? not sure ... 
        return self.queryNVD(custom_params, follow)