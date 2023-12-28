import json
import os
import argparse
import time
from bson import ObjectId

from handlers.logger_handler import Logger
from handlers.config_handler import ConfigHandler

from datasources.nvd_handler import NvdHandler

# Configuration settings
json_output = "data/cve.json"

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        return json.JSONEncoder.default(self, obj)

def write2json(filename, data):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, cls=JSONEncoder, indent=2)
        Logger.log("Data successfully written to file.", "SUCCESS")
    except Exception as e:
        Logger.log(f"An error occurred: {e}", "ERROR")

def parse_args():
    parser = argparse.ArgumentParser(description="CVE Data Handling Script")
    parser.add_argument("-d", "--debug", action="store_true", help="Set log level to DEBUG")
    parser.add_argument("--update", action="store_true", help="Fetch updates for CVE data")
    parser.add_argument("--init", action="store_true", help="Fetch all CVE data")
    return parser.parse_args(), parser

def main():
    args, parser = parse_args()
    config_handler = ConfigHandler('configuration.ini')
    cvemate_config = config_handler.get_cvemate_config()

    if args.debug:
        Logger.set_max_log_level("DEBUG")
    else:
        Logger.set_max_log_level(cvemate_config.get('loglevel', 'INFO'))

    output_directory = os.path.dirname(json_output)
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    if args.update or args.init:
        start_time = time.time()
       
        nvd = NvdHandler()

        if args.update:
            updates = nvd.getUpdates(200, follow=False)
            write2json(json_output, updates)
            
        elif args.init:            
            updates = nvd.getAllCVE(follow=False)
            write2json(json_output, updates)

        end_time = time.time()
        elapsed_time = end_time - start_time
        Logger.log(f"Execution completed in {elapsed_time:.2f} seconds.", "INFO")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
