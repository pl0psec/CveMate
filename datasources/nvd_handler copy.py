"""
This module contains the NvdHandler class used for handling operations related
to the NVD database including data retrieval and processing.
"""
import concurrent.futures
import os
import time
from datetime import datetime, timezone
from datetime import timedelta
from queue import Queue
import logging

import requests
from ratelimit import limits
from ratelimit import sleep_and_retry
from tqdm import tqdm

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongoDBHandler


def singleton(cls):
    """A decorator for creating a singleton class."""
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance


@singleton
class NvdHandler:
    """A class for handling operations with the NVD database."""

    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):
        """Initializes the NvdHandler with configuration settings."""
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f0626', 16))} CVE from NVD"

        config_handler = ConfigHandler(config_file)
        nvd_config = config_handler.get_nvd_config()

        self.baseurl = nvd_config.get('url', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.api_key = nvd_config.get('apikey', '')
        self.public_rate_limit = int(nvd_config.get('public_rate_limit', 5))
        self.api_rate_limit = int(nvd_config.get('apikey_rate_limit', 50))
        self.rolling_window = int(nvd_config.get('rolling_window', 30))
        self.retry_limit = int(nvd_config.get('retry_limit', 3))
        self.retry_delay = int(nvd_config.get('retry_delay', 30))
        self.results_per_page = int(nvd_config.get('results_per_page', 2000))
        self.max_threads = int(nvd_config.get('max_threads', 10))
        self.request_timeout = int(nvd_config.get('request_timeout', 120))

        self.save_data = config_handler.get_boolean('cvemate', 'save_data', False)

        self.mongodb_handler = mongo_handler
        self.logger = logger or logging.getLogger()


    def make_request(self, step='update', start_index=0, custom_params=None):
        """Makes a request to the NVD API with specified parameters."""
        @sleep_and_retry
        @limits(calls=self.api_rate_limit, period=self.rolling_window)
        def _make_request_limited():
            nonlocal start_index
            attempt = 0

            while attempt < self.retry_limit:
                try:
                    response = self._send_request(start_index, custom_params)
                    response.raise_for_status()
                    return response.json()
                except requests.HTTPError as e:
                    if e.response.status_code in [403, 503]:
                        attempt += 1
                        time.sleep(self.retry_delay if e.response.status_code == 403 else 30)
                        continue
                    raise
                except ValueError as e:
                    raise ValueError(f"Invalid JSON response received from NVD API: {e}")

        return self._process_data(_make_request_limited(), step)

    def _send_request(self, start_index, custom_params):
        """
        Sends an HTTP GET request to the NVD API.

        Constructs the request with the necessary headers, parameters, and API key. Handles
        the actual network communication.

        Parameters:
        start_index (int): The index from which to start fetching the data in the paginated API.
        custom_params (dict): Additional parameters to be included in the request.

        Returns:
        requests.Response: The response object received from the API request.
        """
        params = {'resultsPerPage': self.results_per_page, 'startIndex': start_index}
        if custom_params:
            params.update(custom_params)

        headers = {'apiKey': self.api_key} if self.api_key else {}
        return requests.get(self.baseurl, headers=headers, params=params, timeout=self.request_timeout)

    def _process_data(self, data, step):
        """
        Processes the data received from the NVD API.

        Extracts relevant information from the API response, primarily focusing on
        vulnerability data. Depending on the operation step (initialization or update),
        it inserts or updates data in the MongoDB database.

        Parameters:
        data (dict): The JSON data received from the NVD API.
        step (str): The operation step, either 'init' for initialization or 'update' for updating the database.

        Returns:
        dict: The processed data ready for insertion or updating in the database.
        """
        start_time = datetime.now(timezone.utc)

        vulnerabilities = []
        for vul in data.get('vulnerabilities', []):
            cve_data = vul.get('cve', {})
            cve_id = cve_data.get('id')
            if cve_id:
                vulnerabilities.append({'id': cve_id, 'nvd': cve_data})
            else:
                self.logger.error("Error: 'id' not found or empty in a record")

        if vulnerabilities:
            if step.lower() == 'init':
                self.mongodb_handler.insert_many('cve', vulnerabilities, silent=True)
            else:
                self.mongodb_handler.bulk_write('cve', vulnerabilities, silent=True)

            self.mongodb_handler.update_status('nvd', start_time)

        return data

    def download_all_data(self):
        """
        Downloads all available vulnerability data from the NVD database.
        This method handles the pagination of the API response and aggregates all
        vulnerabilities into a single list, which is then optionally saved to a file
        and sent to a MongoDB database.
        """
        self.logger.info('\n'+self.banner)
        initial_response = self.make_request()
        initial_vulnerabilities = initial_response.get('vulnerabilities', [])

        total_results = initial_response.get('totalResults', 0)
        num_pages = (total_results + self.results_per_page -
                     1) // self.results_per_page

        all_vulnerabilities = []  # List to store all vulnerabilities

        with tqdm(total=total_results, initial=len(initial_vulnerabilities)) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Start from the second page, since the first page was already fetched
                futures = [executor.submit(self.make_request, step='init', start_index=start_index * self.results_per_page)
                           for start_index in range(1, num_pages)]

                for future in concurrent.futures.as_completed(futures):
                    data = future.result()
                    vulnerabilities = data.get('vulnerabilities', [])
                    # Append vulnerabilities to the list
                    all_vulnerabilities.extend(vulnerabilities)
                    pbar.update(len(vulnerabilities))

        self.mongodb_handler.ensure_index_on_id('cve', 'id')

        if self.save_data:
            utils.write2json('data/nvd_all.json', all_vulnerabilities)

    def get_updates(self, last_hours=None):
        """
        Retrieves updates from the NVD database within a specified time window.

        This method calculates the time window based on either a provided number of hours
        or the time since the last update. It then downloads all new and updated
        vulnerabilities from the NVD database within this time window.

        Parameters:
        last_hours (int, optional): The number of hours to look back for updates. If not
                                    specified, the method uses the time since the last
                                    successful update.

        Returns:
        dict: A dictionary containing the updates retrieved from the NVD database.
        """
        self.logger.info('\n'+self.banner)
        last_update_time = self.mongodb_handler.get_last_update_time('nvd')
        now_utc = datetime.utcnow()

        if last_hours:
            lastModStartDate = now_utc - timedelta(hours=last_hours)
        elif last_update_time:
            lastModStartDate = last_update_time
        else:
            lastModStartDate = now_utc - timedelta(hours=24)

        lastModStartDate_str = lastModStartDate.strftime('%Y-%m-%dT%H:%M:%SZ')
        lastModEndDate_str = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        duration = now_utc - lastModStartDate
        days, seconds = duration.days, duration.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        duration_str = f"{days} days, {hours % 24} hours, {minutes} minutes" if days else f"{hours % 24} hours, {minutes} minutes"

        Logger.log(
            f"Downloading data for the window: Start - {lastModStartDate_str}, End - {lastModEndDate_str} (Duration: {duration_str})", 'INFO')

        custom_params = {
            'lastModStartDate': lastModStartDate_str,
            'lastModEndDate': lastModEndDate_str
        }

        updates = self.make_request(custom_params=custom_params)

        if self.save_data:
            utils.write2json('data/nvd_update.json', updates)
