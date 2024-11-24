import threading
import logging
from pymongo import MongoClient, ReturnDocument, ASCENDING, UpdateOne, InsertOne
from pymongo.errors import PyMongoError
from queue import Queue
from datetime import datetime, timezone
import time

class MongoDBHandler:
    _instance = None
    _lock = threading.Lock()
    LOG_PREFIX = f"[{chr(int('e7a4', 16))} MongoDB]"

    def __new__(cls, *args, **kwargs):
        """Create or return the singleton instance of MongoDBHandler.
        
        Args:
            cls (type): The class being instantiated.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        
        Returns:
            MongoDBHandler: The singleton instance of the MongoDBHandler class.
        
        Note:
            This method implements the singleton pattern using double-checked locking.
            It ensures that only one instance of MongoDBHandler is created and returned,
            even in a multi-threaded environment.
        """
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(MongoDBHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self, uri, dbname, collection_prefix=None, logger=None, tz=timezone.utc):
        """
        Initialize the MongoDBHandler instance.

        Args:
        uri (str): The MongoDB connection URI.
        dbname (str): The name of the database.
        collection_prefix (str, optional): A prefix for collection names. Defaults to None.
        logger (logging.Logger, optional): A logger instance. Defaults to None.
        tz (datetime.timezone, optional): The timezone for timestamps. Defaults to UTC.
        """
        if not hasattr(self, 'initialized'):  # Prevent reinitialization
            self.logger = logger.bind(prefix=self.LOG_PREFIX) if logger else logger.bind(prefix=self.LOG_PREFIX)

            self.logger.info('Initializing MongoDBHandler')
            self.timezone = tz
            self._init_mongo_connection(uri, dbname, collection_prefix)
            self.initialized = True

    def _init_mongo_connection(self, uri, dbname, collection_prefix):
        """
        Initialize the MongoDB connection.

        Args:
        uri (str): The MongoDB connection URI.
        dbname (str): The name of the database.
        collection_prefix (str): A prefix for collection names.
        """
        masked_uri = self._mask_password_in_uri(uri)
        self.logger.debug(f"Connecting to MongoDB with URI: {masked_uri}")
        self.collection_prefix = collection_prefix
        
        try:
            self.client = MongoClient(uri)
            self.db = self.client[dbname]
            self.db.command('ping')  # Test the connection
            self.logger.info('Connected to MongoDB')

            # Get MongoDB server version
            server_info = self.client.server_info()
            self.logger.info(f"MongoDB server version: {server_info['version']}")

            # Ensure 
            self.ensure_index_on_id('cve','id')

        except Exception as e:
            self.logger.error(f"Failed to connect to MongoDB: {e}")
            exit(1)

        self.queue = Queue()
        self.queue_lock = threading.Lock()
        self.is_processing = False
        

    def _mask_password_in_uri(self, uri):
        """
        Mask the password in the MongoDB URI.

        Args:
        uri (str): The MongoDB connection URI.

        Returns:
        str: The URI with the password masked.
        """
        from urllib.parse import urlparse, urlunparse
        parsed_uri = urlparse(uri)
        if parsed_uri.password:
            masked_netloc = parsed_uri.netloc.replace(parsed_uri.password, '*****')
            masked_uri = parsed_uri._replace(netloc=masked_netloc)
            return urlunparse(masked_uri)
        return uri

    def _get_collection_name(self, collection_name):
        """
        Get the full collection name with prefix.

        Args:
        collection_name (str): The base collection name.

        Returns:
        str: The full collection name with prefix.
        """
        if self.collection_prefix:
            return f"{self.collection_prefix}{collection_name}"
        return collection_name

    def queue_request(self, collection_name, data, update=False, key_field=None):
        """
        Queue a request for processing.

        Args:
        collection_name (str): The name of the collection.
        data (dict or list): The data to be processed.
        update (bool, optional): Whether to perform an update. Defaults to False.
        key_field (str, optional): The key field for updates. Defaults to None.
        """
        full_collection_name = self._get_collection_name(collection_name)
        with self.queue_lock:
            self.queue.put((full_collection_name, data, update, key_field))
            if isinstance(data, list):
                self.logger.debug(f"Queued request for collection {full_collection_name} with {len(data)} documents")
            else:
                self.logger.debug(f"Queued request for collection {full_collection_name} with a single document")
            if not self.is_processing:
                self.is_processing = True
                threading.Thread(target=self.process_queue).start()

    def process_queue(self):
        """
        Process the queued requests.
        """
        while True:
            with self.queue_lock:
                if not self.queue.empty():
                    collection_name, data, update, key_field = self.queue.get()
                    self._process_request(collection_name, data, update, key_field)
                else:
                    self.is_processing = False
                    break

    def _process_request(self, collection_name, data, update, key_field):
        """
        Process a single request.

        Args:
        collection_name (str): The name of the collection.
        data (dict or list): The data to be processed.
        update (bool): Whether to perform an update.
        key_field (str): The key field for updates.
        """
        collection = self.db[collection_name]
        start_time = time.time()
        current_time = datetime.now(self.timezone)
        try:
            if update:
                operations = [
                    UpdateOne(
                        {key_field: record[key_field]},
                        {
                            '$set': {**record, 'updated_at': current_time},
                            '$setOnInsert': {'created_at': current_time}
                        },
                        upsert=True
                    ) for record in data
                ] if isinstance(data, list) else [
                    UpdateOne(
                        {key_field: data[key_field]},
                        {
                            '$set': {**data, 'updated_at': current_time},
                            '$setOnInsert': {'created_at': current_time}
                        },
                        upsert=True
                    )
                ]
                collection.bulk_write(operations)
                elapsed_time = time.time() - start_time
                self.logger.debug(f"Updated {len(data) if isinstance(data, list) else 1} documents in collection {collection_name} in {elapsed_time:.2f} seconds")
            else:
                if isinstance(data, list):
                    for record in data:
                        record['created_at'] = current_time
                        record['updated_at'] = current_time
                    collection.insert_many(data)
                    elapsed_time = time.time() - start_time
                    self.logger.debug(f"Inserted {len(data)} documents into collection {collection_name} in {elapsed_time:.2f} seconds")
                else:
                    data['created_at'] = current_time
                    data['updated_at'] = current_time
                    collection.insert_one(data)
                    elapsed_time = time.time() - start_time
                    self.logger.info(f"Inserted a document into collection {collection_name} in {elapsed_time:.2f} seconds")
        except Exception as e:
            elapsed_time = time.time() - start_time
            self.logger.error(f"Failed to process request for collection {collection_name} in {elapsed_time:.2f} seconds: {e}")
            self.logger.error(data[-1] if isinstance(data, list) else data)

    def drop_collection(self, collection_name):
        """
        Drop a collection.

        Args:
        collection_name (str): The name of the collection to drop.
        """
        full_collection_name = self._get_collection_name(collection_name)
        try:
            self.db.drop_collection(full_collection_name)
            self.logger.info(f"Dropped collection {collection_name}")
            self.logger.debug(f"Dropped collection {full_collection_name}")
        except Exception as e:
            self.logger.error(f"Failed to drop collection {full_collection_name}: {e}")

    def update_status(self, data_source: str, update_time: datetime = None):
        """
        Update the last update datetime for a specified data source.

        :param data_source: The name of the data source.
        :param update_time: The datetime to set as the last updated time. Defaults to current time if not provided.
        """
        prefixed_collection_name = self._get_collection_name('update_status')
        current_time = update_time if update_time else datetime.now(self.timezone)
        self.db[prefixed_collection_name].update_one(
            {'data_source': data_source},
            {'$set': {'last_updated': current_time}},
            upsert=True
        )

    

    def ensure_index_on_id(self, collection, field_name):
        """
        Ensure an index exists on a specified field.

        Args:
        collection (str): The name of the collection.
        field_name (str): The field to index.
        """
        try:
            full_collection_name = self._get_collection_name(collection)
            collection = self.db[full_collection_name]

            # Get current indexes on the collection
            current_indexes = collection.index_information()

            # Check if 'id' field is indexed
            id_indexed = any(
                field_name in idx_info['key'][0] for idx_info in current_indexes.values())

            if id_indexed:
                self.logger.info(
                    f"Collection {full_collection_name} Index on {field_name} already exists.")
            else:
                # Create an index on 'id' field
                collection.create_index([(field_name, ASCENDING)])
                self.logger.info(
                    f"Collection {full_collection_name} Index on {field_name} created.")

        except PyMongoError as e:
            self.logger.error(
                f"Error for {full_collection_name}: {e}")

    def get_last_update_time(self, data_source):
        """
        Fetch the last update time for a specified data source.

        Args:
        data_source (str): The name of the data source.

        Returns:
        datetime: The datetime of the last update or None if not found.
        """
        try:
            prefixed_collection = self._get_collection_name('update_status')
            status = self.db[prefixed_collection].find_one({'data_source': data_source})
            return status['last_updated'] if status else None
        except PyMongoError as e:
            self.logger.error(f"Error fetching last update time for data source '{data_source}': {e}")
            return None

    def get_source_status(self, data_source):
        """

        """
        try:
            prefixed_collection = self._get_collection_name('update_status')
            status = self.db[prefixed_collection].find_one({'data_source': data_source})
            return status if status else None
        except PyMongoError as e:
            self.logger.error(f"Error fetching source status '{data_source}': {e}")
            return None

    def update_source_status(self, data_source: str, data: dict, update_time: datetime = None):
        """
        Update the status of a data source with the provided data and the current time.

        Args:
        data_source (str): The identifier for the data source.
        data (dict): The data to be updated.
        update_time (datetime, optional): The time of the update. Defaults to the current time if not provided.
        """
        prefixed_collection_name = self._get_collection_name('update_status')
        current_time = update_time if update_time else datetime.now(self.timezone)
        data['last_updated'] = current_time
        self.db[prefixed_collection_name].update_one(
            {'data_source': data_source},
            {'$set': data},
            upsert=True
        )
