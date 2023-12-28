# CveMate

CveMate is a tool designed to create a local copy of the NVD (National Vulnerability Database) CVE (Common Vulnerabilities and Exposures) list into a MongoDB database. This facilitates search, processing, and integration with your homemade applications. It leverages the NVD REST API v2.0 ([NVD API](https://nvd.nist.gov/developers/vulnerabilities)) to fetch the latest vulnerability data.


TODO before publication:
[ ] last update status per handlers
[ ] Flush all and restart

## Prerequisites

Before you begin, ensure you have the necessary components set up. Start by setting up your configuration file:

1. **Create configuration file**

   Copy the template configuration file and edit it with your MongoDB details:

    ```sh
    cp configuration.ini.template configuration.ini
    ```

    After copying, open configuration.ini in your favorite text editor and fill in your MongoDB details.

2. **Install dependencies**

    To run CveMate smoothly, install the required Python packages:
    ```sh
    pip3 install -r requirements.txt
    ```

## Populate CveMate

After setting up your environment, you can initialize CveMate to create a local copy of the NVD CVE list in your MongoDB. 

Run the following command:
```sh
python3 main.py --init
```
This command will trigger the initial data population process. It might take some time depending on your internet connection and the size of the data.

## Update CveMate

To ensure CveMate stays up-to-date with the latest vulnerability data, we recommend scheduling regular updates. This can be done by setting up a cron job.

We recomment to have this in a cronjob

```sh
python3 main.py --update
```

Suggestion to add a line to your crontab file to run the update command at a regular interval. For example, to update daily at 3 AM, you might add:
```
0 3 * * * /path/to/python3 /path/to/main.py --update
```


# Future Developments
We are planning to enrich CveMate with additional sources in the future, including:
- ExploitDB
- GitHub Advisory Database
- RedHat Advisory Database
- Any suggestion ? 