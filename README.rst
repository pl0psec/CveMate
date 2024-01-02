CveMate
=======
.. |Py-Versions| image:: https://img.shields.io/pypi/pyversions/tqdm.svg?logo=python&logoColor=white
   :target: https://pypi.org/project/tqdm

|Py-Versions|

CveMate is a tool designed to replicate and maintain a comprehensive database of all CVE (Common Vulnerabilities and Exposures) entries, enhanced with additional information from a variety of security-related sources, into a local MongoDB database.

.. contents::
   :local:
   :depth: 2

Data sources
------------

CveMate currently utilizes the following sources for vulnerability data:

.. list-table:: 
   :widths: 25 75
   :header-rows: 1

   * - **Source**
     - **Description**
   * - **NVD**
     - Fetches CVE data from the National Vulnerability Database. Using NVD Rest API v2.0 `nvd <https://nvd.nist.gov/developers/vulnerabilities>`_.
   * - **Exploit-DB**
     - Database of vulnerabilities and exploits `exploit-db <https://gitlab.com/exploit-database/exploitdb>`_.
   * - **EPSS**
     - Estimate of the probability of exploitation `epss <https://www.first.org/epss/data_stats>`_.

Plans are underway to further enrich the database by integrating additional sources such as the GitHub Advisory Database, RedHat Advisory Database, and Debian.

Any suggestion ?

Prerequisites
-------------

Before you begin, ensure you have the necessary components set up. Start by setting up your configuration file:

1. **Create configuration file**

   Copy the template configuration file and edit it with your MongoDB details:

   .. code-block:: sh

       cp configuration.ini.template configuration.ini

   After copying, open configuration.ini in your favorite text editor and fill in your MongoDB details.

2. **Install dependencies**

   To run CveMate smoothly, install the required Python packages:

   .. code-block:: sh

       pip3 install -r requirements.txt

Populate CveMate
----------------

After setting up your environment, you can initialize CveMate to create a local copy of the NVD CVE list in your MongoDB. 

Run the following command:

.. code-block:: sh

    python3 main.py --init

This command will trigger the initial data population process. It might take some time depending on your internet connection and the size of the data.

Update CveMate
--------------

To ensure CveMate stays up-to-date with the latest vulnerability data, we recommend scheduling regular updates. This can be done by setting up a cron job.

We recommend to have this in a cronjob:

.. code-block:: sh

    python3 main.py --update

Suggestion to add a line to your crontab file to run the update command at a regular interval. For example, to update daily at 3 AM, you might add:

.. code-block::

    0 3 * * * /path/to/python3 /path/to/main.py --update