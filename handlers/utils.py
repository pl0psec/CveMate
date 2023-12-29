import requests
import os
import json
from bson import ObjectId
from handlers.logger_handler import Logger

class JSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder subclass that extends `json.JSONEncoder`.

    This class provides a custom implementation for the `default` method, allowing 
    objects of specific types to be serialized into JSON. 

    Attributes:
        Inherited from json.JSONEncoder.
    
    Methods:
        default(obj): Converts `ObjectId` instances from MongoDB to string format 
                      before JSON encoding. Defaults to the standard JSON encoder 
                      for all other types.
    """

    def default(self, obj):
        # If the object is an ObjectId (from MongoDB), convert it to a string.
        if isinstance(obj, ObjectId):
            return str(obj)
        # Otherwise, use the default JSON encoding.
        return json.JSONEncoder.default(self, obj)

def write2json(filename, data):
    """
    Writes a given data object to a JSON file.

    Args:
        filename (str): The name of the file to which the data will be written.
        data (dict/list): The data to be written to the file.

    Returns:
        None

    This function attempts to write `data` to a file specified by `filename`.
    It uses the custom `JSONEncoder` for handling specific object types like ObjectId.
    It logs the success or failure of the operation using a Logger.
    """

    try:
        with open(filename, 'w') as f:
            # Use the custom JSONEncoder to handle ObjectId, with pretty formatting.
            json.dump(data, f, cls=JSONEncoder, indent=2)
        Logger.log("Data successfully written to file.", "SUCCESS")
    except Exception as e:
        Logger.log(f"An error occurred: {e}", "ERROR")

def download_file(url, save_path=None):
    """
    Downloads a file from a given URL and optionally saves it to a specified path.

    Args:
        url (str): The URL from which to download the file.
        save_path (str, optional): The path where the file should be saved. 
                                   If None, the file is not saved to disk.

    Returns:
        str: The content of the downloaded file.

    Raises:
        Exception: If the file could not be downloaded (e.g., due to a bad HTTP response).

    This function downloads the content from `url`. If `save_path` is provided, 
    it saves the content to the specified location. If the HTTP response is not 200,
    it raises an exception.
    """

    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Failed to download file: HTTP {response.status_code}")

    # If a save path is provided, save the file to the given location.
    if save_path:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', newline='') as file:
            file.write(response.text)

    return response.text
