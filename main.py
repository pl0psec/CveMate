import argparse
import os
import time
import logging
import schedule
import threading
from datetime import datetime, timezone, timedelta

import pyfiglet
from termcolor import colored
import colorama

from datasources.cisa_handler import CisaHandler
from datasources.cwe_handler import CweHandler
from datasources.epss_handler import EpssHandler
from datasources.exploitdb_handler import ExploitdbHandler
from datasources.metasploit_handler import MetasploitHandler
from datasources.nvd_handler import NvdHandler

from handlers.colored_console_handler import ColoredConsoleHandler
from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongoDBHandler
# from handlers.prioritizer_handler import Prioritizer

class WideFormatter(argparse.HelpFormatter):
    """Formatter to extend the help output to 120 columns."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=120, **kwargs)

def banner():
    # Generate ASCII art using pyfiglet
    ascii_art = pyfiglet.figlet_format('CveMate v0.1', font='big')

    # Apply color using termcolor (change 'cyan' to any color you prefer)
    colored_ascii = colored(ascii_art, 'cyan')

    # Print the colored ASCII art
    print(colored_ascii)

def parse_args():
    """Parse and return command line arguments, configuring logging and file paths."""
    parser = argparse.ArgumentParser(description='CVE Data Handling Script', formatter_class=WideFormatter)
    parser.add_argument('-d', '--debug', action='store_true', help='Set log level to DEBUG')
    parser.add_argument('-c', '--config', default='configuration.ini', help='Specify a configuration file')
    return parser.parse_args(), parser

def convert_hours_to_hms(hours):
    """Convert decimal hours to hours, minutes, and seconds."""
    full_hours = int(hours)
    remaining_minutes = (hours - full_hours) * 60
    full_minutes = int(remaining_minutes)
    full_seconds = int((remaining_minutes - full_minutes) * 60)
    return full_hours, full_minutes, full_seconds

def job(mongodb_handler, timezone, init=False):
    """Scheduled job to be run. Place the logic for the job that needs to run on schedule here."""
    logger = logging.getLogger()
    start_time = time.time()  # Start timing
    logger.info('[Job] starting')

    job_stat_datetime = datetime.now(timezone)

    # Init or Update CVE from NVD
    nvd = NvdHandler(mongodb_handler)
    if init:
        nvd.download_all_data()
    else:
        nvd.get_updates()
    
    # # Add Exploit-DB
    exploitdb = ExploitdbHandler(mongodb_handler, logger=logger)
    exploitdb.init()

    # # Add Exploit-DB
    metasploit = MetasploitHandler(mongodb_handler, logger=logger)
    metasploit.init()

    # # Update CWE from cwe.mitre.org
    cwe = CweHandler(mongodb_handler, logger=logger)
    cwe.init()

    # Add EPSS score
    epss = EpssHandler(mongodb_handler, logger=logger)
    epss.init()

    # Add known_exploited_vulnerabilities from CISA
    cisa = CisaHandler(mongodb_handler, logger=logger)
    cisa.init()

    logger.info('[Job] Waiting for DB queue to be processed.')
    mongodb_handler.wait_for_processing()  # Wait here until the queue is empty
    logger.info('[Job] All items have been processed.')

    try:
        # Update MongoDB status just before finishing the job
        # FIXME: DO NOT UPDATE IF JOB Not completed ! + add the job beginning datetime 
        mongodb_handler.update_status('cvemate', update_time=job_stat_datetime)
        logger.info('[Job] MongoDB status updated successfully.')
    except Exception as e:
        logger.error(f"[Job] Failed to update MongoDB status: {e}")

    end_time = time.time()  # End timing
    time_taken = end_time - start_time  # Calculate time taken
    logger.info(f"[Job] finished in {time_taken:.2f} seconds.")


def calculate_initial_delay(last_run_time, interval_hours):
    """Calculate the delay for the next job run based on the last run time."""
    if last_run_time is None:
        return 0  # If there's no last run, schedule immediately
    current_time = datetime.now(timezone.utc)
    elapsed_time = current_time - last_run_time
    interval = timedelta(hours=interval_hours)
    if elapsed_time > interval:
        return 0  # If more time than the interval has passed, schedule immediately
    return (interval - elapsed_time).total_seconds() / 3600  # Delay in hours

def run_once_later(delay, job_function, mongodb_handler):
    """Run the job function once after a specified delay."""
    timer = threading.Timer(delay * 3600, job_function, [mongodb_handler])
    timer.start()

def setup_schedule(cvemate_config, mongodb_handler, initial_delay):
    """Setup task scheduling using the schedule library with initial and regular intervals."""
    logger = logging.getLogger()
    full_hours, full_minutes, full_seconds = convert_hours_to_hms(initial_delay)

    if initial_delay > 0:
        logger.info(f"[Scheduler] initial job to run in {full_hours}h {full_minutes}min {full_seconds}s.")
        threading.Timer(initial_delay * 3600, job, [mongodb_handler, cvemate_config.get('timezone', 'UTC')]).start()

    # Calculate the start time for regular jobs
    interval_hours = int(cvemate_config.get('scheduler', 4))
    logger.info(f"[Scheduler] Update frequency, every {interval_hours}h")
    time_to_first_regular_job = initial_delay + interval_hours
    start_hours, start_minutes, start_seconds = convert_hours_to_hms(time_to_first_regular_job)

    logger.info(f"[Scheduler] regular jobs to start in {start_hours}h {start_minutes}min {start_seconds}s, then every {interval_hours} hours.")
    threading.Timer(time_to_first_regular_job * 3600, lambda: schedule.every(interval_hours).hours.do(job, [mongodb_handler, cvemate_config.get('timezone', 'UTC')] )).start()

    while True:
        schedule.run_pending()
        time.sleep(1)


def format_time_delta(delta):
    """Format timedelta into a more readable string."""
    days, seconds = delta.days, delta.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds"

def main():
    """Main function to set up the environment and start the scheduler."""
    args, parser = parse_args()
    config_file = args.config
    config_handler = ConfigHandler(config_file)    
    cvemate_config = config_handler.get_cvemate_config()

    # Setup logging
    logger = logging.getLogger()
    if args.debug:
        logger.setLevel('DEBUG')
    else:
        logger.setLevel(cvemate_config.get('loglevel', 'INFO').upper())

    # Remove existing handlers associated with the root logger
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Set up a colored console handler for easier reading
    custom_handler = ColoredConsoleHandler()
    formatter = logging.Formatter('%(message)s')
    custom_handler.setFormatter(formatter)
    logger.addHandler(custom_handler)

    log_timezone = config_handler.get_timezone()
    logger.info(f"[Init] loglevel: {logging.getLevelName(logger.getEffectiveLevel())}")
    logger.info(f"[Init] timezone: {log_timezone}")
    logger.debug(f"[Init] config: {config_handler}")

    # MongoDB Handler Initialization
    mongodb_config = config_handler.get_mongodb_config()
    mongodb_handler = MongoDBHandler(
        f"mongodb://{mongodb_config['username']}:{mongodb_config['password']}@{mongodb_config['host']}:{mongodb_config['port']}/{mongodb_config['authdb']}",
        mongodb_config['db'],
        collection_prefix=mongodb_config['prefix'],
        logger=logger,
        tz=log_timezone
    )
    # mongodb_handler.drop_collection('update_status')
    #FIXME: handle exception from MongoDBHandler if connection fail (probably need to update MongoDBHandler to raise an exception)

    schedule_config = config_handler.get_boolean('cvemate', 'scheduler', 4)  # Default to 4 hours if not set  

    # Determine if immediate job run is needed
    last_update_time = mongodb_handler.get_last_update_time('cvemate')
    current_time = datetime.now(timezone.utc)

    # Calculate the initial delay based on the last update time
    if last_update_time:
        last_update_time = last_update_time.replace(tzinfo=timezone.utc)  # Ensure it's timezone aware
        elapsed_time_since_last_update = current_time - last_update_time
        formatted_time_delta = format_time_delta(elapsed_time_since_last_update)
        logger.info(f"[Init] Last update was on {last_update_time} ({formatted_time_delta} ago)")
    else:
        elapsed_time_since_last_update = None

    initial_delay = calculate_initial_delay(last_update_time, schedule_config)

    # Check if immediate run is needed
    if last_update_time is None:
        logger.info('[Init] Starting DB initialization')
        job(mongodb_handler, timezone=log_timezone, init=True)  # Execute the job immediately

    elif elapsed_time_since_last_update and elapsed_time_since_last_update > timedelta(hours=schedule_config):
        logger.info('[Init] No recent updates or last update time exceeds 4 hours')
        job(mongodb_handler, timezone=log_timezone, init=False)  # Execute the job immediately

    logger.info('[Init] Starting the task scheduler.')
    setup_schedule(cvemate_config, mongodb_handler, initial_delay)

if __name__ == '__main__':
    banner()
    main()
