"""This module is the main entry point for the CVE.org Data Handling."""
import json
import zipfile
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from datetime import timezone

import requests
from tqdm import tqdm

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongoDBHandler


def singleton(cls):
    """A decorator function that implements the Singleton design pattern.
    
    Args:
        cls (type): The class to be transformed into a Singleton.
    
    Returns:
        function: A wrapper function that ensures only one instance of the class is created.
    
    """
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance


@singleton
class CveDotOrgHandler:

    def __init__(self, config_file='configuration.ini'):
        """Initialize the CVEMate object.
        
        This method sets up the CVEMate object by reading configuration settings, 
        initializing URLs for CVE data retrieval, and setting up a MongoDB connection.
        
        Args:
            config_file (str, optional): Path to the configuration file. 
                                         Defaults to 'configuration.ini'.
        
        Returns:
            None
        
        Raises:
            ConfigError: If there's an issue with reading the configuration file.
            MongoDBConnectionError: If there's an issue connecting to MongoDB.
        """
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f0626', 16))} CVE from CVE.org"

        config_handler = ConfigHandler(config_file)

        cveorg_config = config_handler.get_config_section('cveorg')
        self.url_init = cveorg_config.get(
            'url',
            'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip')
        self.url_updates = cveorg_config.get(
            'url_updates',
            'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json')
        self.save_data = config_handler.get_boolean(
            'cvemate', 'save_data', False)

        mongodb_config = config_handler.get_mongodb_config()
        self.mongodb_handler = MongoDBHandler(
            mongodb_config['host'],
            mongodb_config['port'],
            mongodb_config['db'],
            mongodb_config['username'],
            mongodb_config['password'],
            mongodb_config['authdb'],
            mongodb_config['prefix'])

    def load_all(self, zipped_file_path, listCve=None, excludeCve=None):
        """Loads CVE data from a zipped file and updates the MongoDB database.
        
        Args:
            zipped_file_path (str): Path to the zipped file containing CVE JSON data.
            listCve (list, optional): List of specific CVE IDs to process. If None, all CVEs are processed.
            excludeCve (list, optional): List of CVE IDs to exclude from processing.
        
        Returns:
            list: A list of dictionaries containing processed CVE data, each with 'id' and 'data' keys.
        
        """
        cve_data = []

        # Convert excludeCve to a set for faster lookups
        exclude_set = set(excludeCve) if excludeCve else set()

        # Open the zip file
        with zipfile.ZipFile(zipped_file_path, 'r') as zip_ref:

            # List all files in the zip
            for file in zip_ref.namelist():

                # Check if the file is a CVE JSON file
                if file.endswith('.json') and file.split('/')[-1].startswith('CVE'):
                    cve_id = file.split('/')[-1].replace('.json', '')
                    # Skip CVEs in the exclude list
                    if cve_id in exclude_set:
                        continue
                    # Check if specific CVEs are listed or if all should be processed
                    if listCve is None or cve_id in listCve:
                        with zip_ref.open(file) as json_file:
                            data = json.load(json_file)
                            cve_data.append(
                                {'id': cve_id, 'data': {'cve': data}})

        if cve_data:
            self.mongodb_handler.update_multiple_documents('cve', cve_data)
        self.mongodb_handler.update_status('cveorg')

        return cve_data

    def init(self):
        """Initializes the object and downloads a zipped file from a specified URL.
        
        Args:
            self: The instance of the class.
        
        Returns:
            dict: The result of loading all data from the downloaded zip file.
        
        Raises:
            utils.DownloadError: If there's an error downloading the file.
        """
        print('\n'+self.banner+' - init')

        Logger.log(f"[{chr(int('f0626', 16))} cveorg] Downloading {self.url_init}", 'INFO')
        zipped_file_path = utils.download_file(
            self.url_init,
            save_path='/tmp/cveorg_main.zip',
            is_binary=True
        )

        # all_nvd_ids = self.mongodb_handler.get_all_id()
        result = self.load_all(zipped_file_path)

        return result

    def update(self):
        # Get the last update time
        """Update CVE (Common Vulnerabilities and Exposures) data from the CVE.org database.
        
        This method checks for updates since the last update time, downloads new data if available,
        and processes the updates. It handles both new and updated CVEs.
        
        Args:
            self: The instance of the class containing this method.
        
        Returns:
            list: A list of CVE IDs that were updated during this operation.
        
        Raises:
            requests.Timeout: If a request to download GitHub data times out.
            json.JSONDecodeError: If there's an error decoding the JSON data from the updates file.
        """
        last_update = self.mongodb_handler.get_last_update_time('cveorg')

        if last_update is None:
            result = self.init()
            return result

        else:
            print('\n' + self.banner+' - update')

            # Convert from string to datetime
            last_update = last_update.replace(tzinfo=timezone.utc)

            Logger.log(
                f"[{chr(int('f14ba', 16))} cveorg] Downloading {self.url_updates}", 'INFO')
            json_updates = utils.download_file(
                self.url_updates,
                save_path='/tmp/cveorg_deltaLog.json' if self.save_data else None)

            data = json.loads(json_updates)

            # Find the oldest fetch_time in the data
            oldest_fetch_time = min(datetime.fromisoformat(
                record['fetchTime'].replace('Z', '+00:00')) for record in data)

            # Check if last_update is older than the oldest fetch_time
            if last_update < oldest_fetch_time:
                result = self.init()
                return result

            else:
                Logger.log(
                    f"[{chr(int('f14ba', 16))} cveorg] Processing updates ... ", 'INFO')
                updated_cve_ids = []
                new_cve_ids = []
                github_links = []

                # Iterate through the records in the JSON data
                for record in data:
                    fetch_time = datetime.fromisoformat(
                        record['fetchTime'].replace('Z', '+00:00'))

                    if fetch_time > last_update:

                        # Process 'updated' and 'new' arrays
                        for item in record['updated'] + record['new']:

                            updated_cve_ids.extend(
                                item['cveId'] for item in record['updated'])
                            new_cve_ids.extend(item['cveId']
                                               for item in record['new'])

                            github_links.append(item['githubLink'])

                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] {len(new_cve_ids)} new CVE ",'INFO')
                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] {new_cve_ids}", 'DEBUG')
                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] {len(updated_cve_ids)} updated CVE",'INFO')
                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] {updated_cve_ids}", 'DEBUG')

                # anything to update ?
                if github_links:
                    # Multithreading downloads with tqdm progress bar
                    def download_github_data(link):
                        response = requests.get(link, timeout=10)
                        return link, response.text if response.status_code == 200 else None

                    cve_data = []
                    with ThreadPoolExecutor() as executor:
                        future_to_link = {executor.submit(
                            download_github_data, link): link for link in github_links}

                        for future in tqdm(
                                as_completed(future_to_link),
                                total=len(future_to_link),
                                desc='Downloading CVE data'):

                            link, data = future.result()
                            if data:
                                cve_data.append(
                                    {'id': link.split('/')[-1], 'data': {'cve': data}})

                    if cve_data:
                        self.mongodb_handler.update_multiple_documents(
                            'cve', cve_data)

                self.mongodb_handler.update_status('cveorg')

            return updated_cve_ids
