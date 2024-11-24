import concurrent.futures
import json
import os
import threading
import time
from datetime import datetime
from datetime import timedelta
from queue import Queue

import requests
from ratelimit import limits
from ratelimit import sleep_and_retry
from tqdm import tqdm

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongoDBHandler

def singleton(cls):
    """A decorator that implements the singleton pattern for a class.
    
    Args:
        cls (type): The class to be turned into a singleton.
    
    Returns:
        function: A wrapper function that returns the single instance of the class.
    
    """
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class RedhatHandler:

    def __init__(self, config_file='configuration.ini'):
        """Initialize the RedHat CVE data fetcher.
        
        This method sets up the configuration for fetching CVE data from Red Hat's security data API.
        It loads various settings from a configuration file, including API endpoints, rate limits,
        and database connection details.
        
        Args:
            config_file (str, optional): Path to the configuration file. Defaults to 'configuration.ini'.
        
        Returns:
            None
        
        Raises:
            ConfigError: If there's an issue with reading or parsing the configuration file.
            MongoDBConnectionError: If there's an issue connecting to the MongoDB database.
        """
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f111b', 16))} from RedHat"

        config_handler = ConfigHandler(config_file)

        redhat_config = config_handler.get_redhat_config()
        self.baseurl = redhat_config.get('url', 'https://access.redhat.com/hydra/rest/securitydata')
        self.api_key = redhat_config.get('apikey', '')
        self.public_rate_limit = int(redhat_config.get('public_rate_limit', 5))
        self.api_rate_limit = int(redhat_config.get('apikey_rate_limit', 50))
        self.rolling_window = int(redhat_config.get('rolling_window', 30))
        self.retry_limit = int(redhat_config.get('retry_limit', 3))
        self.retry_delay = int(redhat_config.get('retry_delay', 10))
        self.results_per_page = int(redhat_config.get('results_per_page', 2000))
        self.max_threads = int(redhat_config.get('max_threads', 10))

        self.save_data = config_handler.get_boolean('cvemate', 'save_data', False)

        mongodb_config = config_handler.get_mongodb_config()
        self.mongodb_handler = MongoDBHandler(
            mongodb_config['host'],
            mongodb_config['port'],
            mongodb_config['db'],
            mongodb_config['username'],
            mongodb_config['password'],
            mongodb_config['authdb'],
            mongodb_config['prefix'])


    def make_request(self, step='update', start_index=0, custom_params=None):

        @sleep_and_retry
        @limits(calls=self.api_rate_limit, period=self.rolling_window)
        """Make a request to the API and process the response.
        
        Args:
            step (str, optional): The step of the process, either 'init' or 'update'. Defaults to 'update'.
            start_index (int, optional): The starting index for pagination. Defaults to 0.
            custom_params (dict, optional): Additional parameters to include in the API request. Defaults to None.
        
        Returns:
            dict: The JSON response from the API.
        
        Raises:
            Exception: If the API request returns a non-200 status code.
            ValueError: If the API response contains invalid JSON.
        """
        def _make_request_limited():
            params = {
                'resultsPerPage': self.results_per_page,
                'startIndex': start_index
            }
            if custom_params:
                params.update(custom_params)

            headers = {'apiKey': self.api_key} if self.api_key else {}

            # Construct the full URL for error reporting
            full_url = requests.Request('GET', self.baseurl, headers=headers, params=params).prepare().url

            response = requests.get(self.baseurl, headers=headers, params=params)
            if response.status_code != 200:
                error_msg = f'Error {response.status_code} when accessing URL: {full_url}'
                raise Exception(error_msg)

            try:
                return response.json()
            except ValueError:
                raise ValueError(f"Invalid JSON response received from URL: {full_url}")

        data = _make_request_limited()

        vulnerabilities = [
            vul.get('cve', {})
            for vul in data.get('vulnerabilities', [])
        ]

        if vulnerabilities:
            if step.lower() == 'init':
                self.mongodb_handler.insert_many('cve', vulnerabilities)
            else:
                self.mongodb_handler.bulk_write('cve', vulnerabilities)

            self.mongodb_handler.update_status('redhat')


        return data


    def download_all_data(self):
        """Downloads all vulnerability data from the API and processes it.
        
        This method performs the following steps:
        1. Makes an initial request to get the first page of vulnerabilities.
        2. Calculates the total number of pages based on the total results and results per page.
        3. Uses a ThreadPoolExecutor to concurrently fetch the remaining pages.
        4. Collects all vulnerabilities into a single list.
        5. Updates a progress bar as data is fetched.
        6. Ensures an index on the 'id' field in the 'cve' collection of the MongoDB database.
        7. Optionally saves the collected data to a JSON file.
        
        Args:
            self: The instance of the class containing this method.
        
        Returns:
            None
        
        Raises:
            Any exceptions from self.make_request() or MongoDB operations are not explicitly handled and will propagate.
        
        Note:
            - This method uses concurrent.futures for parallel processing.
            - It displays a progress bar using tqdm.
            - The method assumes the existence of a MongoDB handler and utility functions.
        """
        print('\n'+self.banner)
        initial_response = self.make_request()
        initial_vulnerabilities = initial_response.get('vulnerabilities', [])

        total_results = initial_response.get('totalResults', 0)
        num_pages = (total_results + self.results_per_page - 1) // self.results_per_page

        all_vulnerabilities = []  # List to store all vulnerabilities

        # with tqdm(total=total_results) as pbar:
        with tqdm(total=total_results, initial=len(initial_vulnerabilities)) as pbar:

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Start from the second page, since the first page was already fetched
                futures = [executor.submit(self.make_request, step='init', start_index=(start_index * self.results_per_page))
                           for start_index in range(1, num_pages)]

                for future in concurrent.futures.as_completed(futures):
                    data = future.result()
                    vulnerabilities = data.get('vulnerabilities', [])
                    all_vulnerabilities.extend(vulnerabilities)  # Append vulnerabilities to the list
                    pbar.update(len(vulnerabilities))

        self.mongodb_handler.ensure_index_on_id('cve','id')

        if self.save_data:
            utils.write2json('data/redhat_all.json', all_vulnerabilities)


    def get_updates(self, last_hours=None, follow=True):
        """Retrieves and processes updates within a specified time window.
        
        Args:
            last_hours (int, optional): Number of hours to look back for updates. If not provided, uses the last update time or defaults to 24 hours.
            follow (bool, optional): Determines whether to follow updates. Defaults to True.
        
        Returns:
            list: A list of update objects retrieved from the API.
        
        Raises:
            RequestException: If there's an error in making the API request.
        """
        print('\n'+self.banner)
        last_update_time = self.mongodb_handler.get_last_update_time('redhat')
        now_utc = datetime.utcnow()

        if last_hours:
            lastModStartDate = now_utc - timedelta(hours=last_hours)
        elif last_update_time:
            lastModStartDate = last_update_time
        else:
            lastModStartDate = now_utc - timedelta(hours=24)

        lastModStartDate_str = lastModStartDate.strftime('%Y-%m-%dT%H:%M:%SZ')
        lastModEndDate_str = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        # Calculate the duration of the window in a human-readable format
        duration = now_utc - lastModStartDate
        days, seconds = duration.days, duration.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        duration_str = f"{days} days, {hours % 24} hours, {minutes} minutes" if days else f"{hours % 24} hours, {minutes} minutes"

        # Log message with time window and its human-readable duration
        Logger.log(f"Downloading data for the window: Start - {lastModStartDate_str}, End - {lastModEndDate_str} (Duration: {duration_str})", 'INFO')

        custom_params = {
            'lastModStartDate': lastModStartDate_str,
            'lastModEndDate': lastModEndDate_str
        }

        updates = self.make_request(custom_params=custom_params)

        if self.save_data:
            utils.write2json('data/redhat_update.json', updates)
