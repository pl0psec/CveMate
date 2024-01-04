import requests
import csv
import os
import json
import zipfile
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from handlers import utils
from handlers.logger_handler import Logger
from handlers.config_handler import ConfigHandler

from handlers.mongodb_handler import MongodbHandler

def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class CveDotOrgHandler:

    def __init__(self, config_file='configuration.ini'):
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f0626', 16))} CVE from CVE.org"

        config_handler = ConfigHandler(config_file)

        cveorg_config = config_handler.get_config_section('cveorg')
        self.url_init = cveorg_config.get('url', 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip')
        self.url_updates = cveorg_config.get('url_updates', 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json')
        self.save_data = config_handler.get_boolean('cveorg', 'save_data', False)

        mongodb_config = config_handler.get_mongodb_config()        
        self.mongodb_handler = MongodbHandler(
            mongodb_config['host'],
            mongodb_config['port'],
            mongodb_config['db'],
            mongodb_config['username'],
            mongodb_config['password'],
            mongodb_config['authdb'],
            mongodb_config['prefix'])
   
    def load_all(self, zipped_file_path, listCve=None, excludeCve=None):
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
                            cve_data.append({"id": cve_id, "data": {"cve": data}})

        if cve_data:
            self.mongodb_handler.update_multiple_documents("cve", cve_data)
        self.mongodb_handler.update_status("cveorg")

        return cve_data


    def init(self):
        print("\n"+self.banner+" - init")

        Logger.log(f"[{chr(int('f0626', 16))} cveorg] Downloading {self.url_init}", "INFO")
        zipped_file_path = utils.download_file(self.url_init, save_path='data/cveorg_main.zip' if self.save_data else None, is_binary=True)

        all_nvd_ids = self.mongodb_handler.get_all_id()
        result = self.load_all(zipped_file_path, excludeCve=all_nvd_ids)

        return result

        
    def update(self):
        # Get the last update time
        last_update = self.mongodb_handler.get_last_update_time("cveorg")
        
        if last_update is None:
            result = self.init()
            return result
            
        else:
            print("\n" + self.banner+" - update")

            # Convert from string to datetime
            last_update = last_update.replace(tzinfo=timezone.utc)

            Logger.log(f"[{chr(int('f14ba', 16))} cveorg] Downloading {self.url_updates}", "INFO")
            json_updates = utils.download_file(self.url_updates, save_path='data/cveorg_deltaLog.json' if self.save_data else None)

            data = json.loads(json_updates)

            # Find the oldest fetch_time in the data
            oldest_fetch_time = min(datetime.fromisoformat(record['fetchTime'].replace('Z', '+00:00')) for record in data)

            # Check if last_update is older than the oldest fetch_time
            if last_update < oldest_fetch_time:
                result = self.init()
                return result

            else:
                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] Processing updates ... ","INFO")
                updated_cve_ids = []
                new_cve_ids = []
                github_links = []

                # Iterate through the records in the JSON data
                for record in data:
                    fetch_time = datetime.fromisoformat(record['fetchTime'].replace('Z', '+00:00'))
                    
                    if fetch_time > last_update:
                        
                        # Process 'updated' and 'new' arrays
                        for item in record['updated'] + record['new']:

                            updated_cve_ids.extend(item['cveId'] for item in record['updated'])
                            new_cve_ids.extend(item['cveId'] for item in record['new'])

                            github_links.append(item['githubLink'])
 
                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] {len(new_cve_ids)} new CVE: {new_cve_ids}", "INFO") 
                Logger.log(f"[{chr(int('f14ba', 16))} cveorg] {len(updated_cve_ids)} updated CVE: {updated_cve_ids}", "INFO")
                
                # anything to update ?
                if github_links:
                    # Multithreading downloads with tqdm progress bar
                    def download_github_data(link):
                        response = requests.get(link)
                        return link, response.text if response.status_code == 200 else None
            
                    cve_data = []
                    with ThreadPoolExecutor() as executor:
                        future_to_link = {executor.submit(download_github_data, link): link for link in github_links}
                        for future in tqdm(as_completed(future_to_link), total=len(future_to_link), desc="Downloading CVE data"):
                            link, data = future.result()
                            if data:
                                cve_data.append({"id": link.split('/')[-1], "data": {"cve": data}})

                    if cve_data:
                        self.mongodb_handler.update_multiple_documents("cve", cve_data)
                
                self.mongodb_handler.update_status("cveorg")
                
            return updated_cve_ids
    