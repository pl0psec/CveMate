"""
This module contains the NvdHandler class used for handling operations related
to the NVD database including data retrieval and processing.
"""
import logging

from datetime import timedelta, datetime
from functools import partial

from jsonPagination import Paginator

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongoDBHandler


def singleton(cls):
    """A decorator for creating a singleton class."""
    instances = {}

    def get_instance(*args, **kwargs):
        """Get or create a singleton instance of the class.
        
        Args:
            *args: Variable length argument list to be passed to the class constructor.
            **kwargs: Arbitrary keyword arguments to be passed to the class constructor.
        
        Returns:
            object: The singleton instance of the class.
        
        Note:
            This method implements the singleton pattern. It ensures that only one instance
            of the class is created. If an instance already exists, it returns that instance
            instead of creating a new one.
        """
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

        self.mongodb_handler = mongo_handler

        config_handler = ConfigHandler(config_file)
        nvd_config = config_handler.get_nvd_config()

        self.baseurl = nvd_config.get('url', 'https://services.nvd.nist.gov')
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
        self.logger = logger or logging.getLogger()

    def _process_data(self, data, init=False):
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
        vulnerabilities = []

        for vul in data:
            cve_data = vul.get('cve', {})
            cve_id = cve_data.get('id')
            if cve_id:
                vulnerabilities.append({'id': cve_id, 'nvd': cve_data})
            else:
                self.logger.info("Error: 'id' not found or empty in a record")

        if vulnerabilities:

            result = self.mongodb_handler.queue_request('cve', vulnerabilities)

            # self.logger.info(f"Mongo query: {result}")
            self.mongodb_handler.update_status('nvd')

        return data

    def download_all_data(self):
        """
        Downloads all available vulnerability data from the NVD database.
        This method handles the pagination of the API response and aggregates all
        vulnerabilities into a single list, which is then optionally saved to a file
        and sent to a MongoDB database.
        """
        self.logger.info('\n'+self.banner)

        paginator = Paginator(
            base_url=self.baseurl,
            log_level='DEBUG',
            max_threads=10,
            current_index_field='startIndex',  # Used for index-based pagination
            items_field='resultsPerPage',
            total_count_field='totalResults',
            data_field='vulnerabilities',
            headers={'apikey': self.api_key},
            ratelimit=(self.api_rate_limit, self.rolling_window),  # Rate limit configuration
            logger=self.logger
        )

        all_vulnerabilities = paginator.fetch_all_pages(
            url='/rest/json/cves/2.0',
            callback=lambda data: self._process_data(data, init=True)
        )

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

        self.logger.info(
            f"Downloading data for the window: Start - {lastModStartDate_str}, End - {lastModEndDate_str} (Duration: {duration_str})")
                
        custom_params = {
            'lastModStartDate': lastModStartDate_str,
            'lastModEndDate': lastModEndDate_str
        }

        self.logger.debug(custom_params)

        # updates = self.make_request(custom_params=custom_params)

        paginator = Paginator(
            base_url=self.baseurl,
            log_level='DEBUG',
            max_threads=10,
            current_index_field='startIndex',  # Used for index-based pagination
            items_field='resultsPerPage',
            total_count_field='totalResults',
            data_field='vulnerabilities',
            headers={'apikey': self.api_key},
            ratelimit=(self.api_rate_limit, self.rolling_window),  # Rate limit configuration
            logger=self.logger
        )

        # DEBUG
        # custom_params={'lastModStartDate': '2024-06-21T06:46:32Z', 'lastModEndDate': '2024-06-22T10:30:30Z'}

        # all_vulnerabilities = paginator.fetch_all_pages(
        #     url='/rest/json/cves/2.0',
        #     params=custom_params,
        #     callback=lambda data: self._process_data(data, step='update')
        # )
        all_vulnerabilities = paginator.fetch_all_pages(
            url='/rest/json/cves/2.0',
            params=custom_params,
            callback=lambda data: self._process_data(data)
        )

        if self.save_data:
            utils.write2json('data/nvd_all.json', all_vulnerabilities)
