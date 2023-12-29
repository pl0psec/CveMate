from pymongo import MongoClient
from pymongo import UpdateOne
from pymongo.errors import ConnectionFailure, PyMongoError
from bson import ObjectId

from handlers.logger_handler import Logger  # Import the Logger class


def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class MongodbHandler:
    def __init__(self, url, port, db_name, user, password, authdb, prefix):
        try:
            self.client = MongoClient(f"mongodb://{user}:{password}@{url}:{port}/{authdb}")
            self.db = self.client[db_name]
            self.prefix = prefix
            self.client.admin.command('ismaster')  # Test the connection
            Logger.log("MongoDB connection established successfully.", "SUCCESS")
        except ConnectionFailure:
            Logger.log("MongoDB connection failed", "ERROR")

    def insert(self, collection, json_data):
        try:
            prefixed_collection = self.prefix + collection
            result = self.db[prefixed_collection].insert_one(json_data).inserted_id
            Logger.log(f"[MongoDB] Document inserted successfully in {collection}. ID: {result}", "SUCCESS")
            return result
        except PyMongoError as e:
            Logger.log(f"[MongoDB] Error inserting document in {collection}: {e}", "ERROR")

    # def insert_many(self, collection, json_data_list):
    #     try:
    #         prefixed_collection = self.prefix + collection
    #         result = self.db[prefixed_collection].insert_many(json_data_list).inserted_ids
    #         Logger.log(f"[MongoDB] {len(result)} documents inserted successfully in {collection}.", "SUCCESS")
    #         return result
    #     except PyMongoError as e:
    #         Logger.log(f"[MongoDB] Error inserting documents in {collection}: {e}", "ERROR")
    
    def insert_many(self, collection, json_data_list):
        try:
            prefixed_collection = self.prefix + collection
            operations = []
            for data in json_data_list:
                id = data.get('id')
                if id is not None:
                    operations.append(UpdateOne({'id': id}, {'$set': data}, upsert=True))

            if operations:
                result = self.db[prefixed_collection].bulk_write(operations)
                upserted_count = result.upserted_count
                updated_count = len(json_data_list) - upserted_count
                Logger.log(f"[MongoDB] {updated_count} documents updated and {upserted_count} documents inserted in {collection}.", "SUCCESS")
            else:
                Logger.log(f"[MongoDB] No valid operations to perform in {collection}.", "WARNING")
            return result
        except PyMongoError as e:
            Logger.log(f"[MongoDB] Error upserting/inserting documents in {collection}: {e}", "ERROR")


    def findOneAndUpdate(self, id, collection, json_data):        
        try:
            prefixed_collection = self.prefix + collection
            result = self.db[prefixed_collection].find_one_and_update({"_id": ObjectId(id)}, {"$set": json_data})
            Logger.log(f"[MongoDB] Document with ID {id} updated successfully in {collection}.", "SUCCESS")
            return result
        except PyMongoError as e:
            Logger.log(f"[MongoDB] Error updating document in {collection}: {e}", "ERROR")

    # def update_exploitdb_field(self, collection, id, exploitdb_json):
    #     """
    #     Update the 'exploitdb' field of a document with a specific ID.
    #     Args:
    #     collection (str): The name of the collection.
    #     id (str): The ID of the document to update.
    #     exploitdb_json (dict): The new JSON data for the 'exploitdb' field.
    #     """
    #     try:
    #         prefixed_collection = self.prefix + collection
    #         result = self.db[prefixed_collection].find_one_and_update(
    #             {"id": id}, 
    #             {"$set": {"exploitdb": exploitdb_json}}, 
    #             return_document=True
    #         )
    #         if result:
    #             Logger.log(f"[MongoDB] Document with ID {id} updated successfully in {collection}.", "SUCCESS")
    #         else:
    #             Logger.log(f"[MongoDB] No document found with ID {id} in {collection}.", "WARNING")
    #         return result
    #     except PyMongoError as e:
    #         Logger.log(f"[MongoDB] Error updating document in {collection}: {e}", "ERROR")

    def update_multiple_documents(self, collection, updates_list):
        """
        Update multiple documents in a collection.
        Args:
        collection (str): Collection name.
        updates_list (list): List of updates in the format [{"id": id_value, "data": data_dict}, ...].
        """
        try:
            prefixed_collection = self.prefix + collection
            operations = []
            for update in updates_list:
                id_value = update.get('id')
                data_dict = update.get('data')
                if id_value is not None and isinstance(data_dict, dict):
                    operations.append(UpdateOne({'id': id_value}, {'$set': data_dict}))
                    
            if operations:
                result = self.db[prefixed_collection].bulk_write(operations)
                Logger.log(f"[MongoDB] {len(operations)} documents updated successfully in {collection}.", "SUCCESS")                
                return result
            else:
                Logger.log(f"[MongoDB] No valid operations to perform in {collection}.", "WARNING")
        except PyMongoError as e:
            Logger.log(f"[MongoDB] Error updating multiple documents in {collection}: {e}", "ERROR")


    def drop(self, collection):
        try:
            prefixed_collection = self.prefix + collection
            self.db[prefixed_collection].drop()
            Logger.log(f"[MongoDB] Collection {collection} dropped successfully.", "SUCCESS")
        except PyMongoError as e:
            Logger.log(f"[MongoDB] Error dropping collection {collection}: {e}", "ERROR")

    def create_index(self, collection, index_fields):
        try:
            prefixed_collection = self.prefix + collection
            index_name = self.db[prefixed_collection].create_index([(field, 1) for field in index_fields])
            Logger.log(f"[MongoDB] Index {index_name} created successfully on {collection}.", "SUCCESS")
            return index_name
        except PyMongoError as e:
            Logger.log(f"[MongoDB] Error creating index on {collection}: {e}", "ERROR")

    def list_prefixed_collections(self):
        try:
            all_collections = self.db.list_collection_names()
            prefixed_collections = [col for col in all_collections if col.startswith(self.prefix)]
            Logger.log("Prefixed collections listed successfully.", "SUCCESS")
            return prefixed_collections
        except PyMongoError as e:
            Logger.log("Error listing prefixed collections: {e}", "ERROR")





