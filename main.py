import requests
import json
import os
import sys
import traceback
from requests.auth import HTTPBasicAuth
import pandas as pd
import urllib3
import logging
import yaml
from datetime import datetime

# --- Configuration ---
# Set to False for lab environments with self-signed certificates.
# For production, always set to True and ensure proper CA certificates are trusted.
VERIFY_SSL = False

# Disable InsecureRequestWarning when VERIFY_SSL is False
if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- YAML Configuration File Path ---
CONFIG_FILE = "config.yaml"

# --- Logging Configuration ---
LOG_FILE = "script_errors.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

# --- Function to load configuration from YAML ---
def load_config(config_path: str) -> dict:
    """
    Loads configuration from a YAML file.
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Configuration file '{config_path}' not found. Please create it.")
    except yaml.YAMLError as e:
        logging.exception(f"Error parsing YAML configuration file: {config_path}")
        raise ValueError(f"Error parsing YAML configuration file '{config_path}': {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred while loading config from {config_path}")
        raise Exception(f"An unexpected error occurred while loading config: {e}")

# Load configuration at the start
try:
    app_config = load_config(CONFIG_FILE)
    CATALYST_CENTER_CONFIG = app_config.get('catalyst_center', {})
    CATALYST_CENTER_URL = CATALYST_CENTER_CONFIG.get('url')
    CATALYST_CENTER_USERNAME = CATALYST_CENTER_CONFIG.get('username')
    CATALYST_CENTER_PASSWORD = CATALYST_CENTER_CONFIG.get('password')

except (FileNotFoundError, ValueError, Exception) as e:
    error_msg = f"FATAL ERROR: Could not load or parse configuration. {e}"
    logging.critical(error_msg)
    print(error_msg, file=sys.stderr)
    sys.exit(1)


# --- Helper Function for Authentication ---
def get_auth_token(base_url: str, username: str, password: str) -> str:
    """
    Obtains an authentication token from Cisco Catalyst Center.
    API Reference: POST /dna/system/api/v1/auth/token
    """
    auth_url = f"{base_url}/dna/system/api/v1/auth/token"
    headers = {"Content-Type": "application/json"}

    try:
        print("DEBUG: Attempting to get authentication token...")
        response = requests.post(auth_url, auth=HTTPBasicAuth(username, password), headers=headers, verify=VERIFY_SSL, timeout=30)
        response.raise_for_status() # This will raise HTTPError for 4xx/5xx responses

        token = response.json().get("Token")
        if not token:
            # User's requested message for missing 'Token' key
            print(f"    ERROR: Authentication response is valid but missing expected data ('Token' key).")
            logging.exception(f"Authentication token not found in Catalyst Center response. Raw response: {response.text}")
            raise ValueError(f"Authentication token not found in Catalyst Center response.")
        print("DEBUG: Authentication token obtained successfully.")
        return token

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 401:
            # User's requested message for 401 Unauthorized
            print(f"    ERROR: Authentication Failed (401 Unauthorized). Check username/password for {base_url}.")
        elif status_code == 400:
            # User's requested message for 400 Bad Request
            print(f"    ERROR: Bad Request (400 Client Error). Check the base URL format for {base_url}.")
        else:
            # User's requested message for other HTTP errors
            print(f"    ERROR: HTTP Error {status_code}.")
        logging.exception(f"HTTP error during authentication with Catalyst Center (Status: {e.response.status_code}). Response: {e.response.text}")
        raise ConnectionError(f"HTTP error during authentication with Catalyst Center.")

    except requests.exceptions.RequestException as e:
        # User's requested message for other unexpected request errors
        print(f"    ERROR: An unexpected API request error occurred.")
        logging.exception(f"An unexpected request error occurred during authentication.")
        raise ConnectionError(f"An unexpected request error occurred during authentication.")

    except json.JSONDecodeError:
        # User's requested message for JSON decoding error
        print(f"    ERROR: Failed to decode JSON from Catalyst Center authentication response.")
        logging.exception(f"Failed to decode JSON from Catalyst Center authentication response. Raw response: {response.text}")
        raise ValueError(f"Failed to decode JSON from Catalyst Center authentication response.")

    except Exception as e:
        # Generic catch-all for any other unexpected errors
        print(f"    ERROR: An unexpected error occurred during authentication.")
        logging.exception(f"An unexpected error occurred in get_auth_token.")
        raise Exception(f"An unexpected error occurred in get_auth_token.")

# --- Function to get device ID by name ---
def get_device_id_by_name(token: str, base_url: str, device_name: str) -> str:
    """
    Retrieves the unique device ID for a given device hostname from Cisco Catalyst Center.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    devices_url = f"{base_url}/dna/intent/api/v1/networkDevices"
    print(f"DEBUG: Attempting to retrieve devices from {devices_url} to find '{device_name}'...")
    try:
        devices_response = requests.get(devices_url, headers=headers, verify=VERIFY_SSL, timeout=30)
        devices_response.raise_for_status()

        devices_data = devices_response.json()
        device_list = devices_data.get("response", [])

        if not isinstance(device_list, list):
            logging.error(f"Unexpected device list format received from Catalyst Center. Expected a list under 'response', got: {type(device_list)}. Raw response: {devices_response.text}")
            raise ValueError(f"Unexpected device list format received from Catalyst Center.")

        for device in device_list:
            if device.get('hostname', '').lower() == device_name.lower():
                device_id = device.get('id')
                if device_id:
                    print(f"DEBUG: Found device '{device_name}' with ID: {device_id}")
                    return device_id
                else:
                    logging.error(f"Device '{device_name}' found but its 'id' field is missing or empty in the Catalyst Center response.")
                    raise ValueError(f"Device '{device_name}' found but its 'id' field is missing or empty.")
        
        logging.error(f"Device with hostname '{device_name}' not found in Catalyst Center.")
        raise ValueError(f"Device with hostname '{device_name}' not found in Catalyst Center.")

    except requests.exceptions.ConnectTimeout as e:
        logging.exception(f"Device list request timed out when connecting to Catalyst Center at {devices_url}.")
        raise ConnectionError(f"Device list request timed out.")
    except requests.exceptions.ConnectionError as e:
        logging.exception(f"Failed to connect to Catalyst Center for device list at {devices_url}. Check URL and network.")
        raise ConnectionError(f"Failed to connect to Catalyst Center for device list.")
    except requests.exceptions.HTTPError as e:
        logging.exception(f"HTTP error retrieving device list (Status: {e.response.status_code}). Response: {e.response.text}")
        raise ConnectionError(f"HTTP error retrieving device list.")
    except requests.exceptions.RequestException as e:
        logging.exception(f"An unexpected request error occurred while getting device list.")
        raise ConnectionError(f"An unexpected request error occurred while getting device list.")
    except json.JSONDecodeError:
        logging.exception(f"Failed to decode JSON from Catalyst Center device list response. Raw response: {devices_response.text}")
        raise ValueError(f"Failed to decode JSON from Catalyst Center device list response.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred while fetching device ID for '{device_name}'.")
        raise Exception(f"An unexpected error occurred while fetching device ID for '{device_name}'.")

# --- Function to get software version by ID ---
def get_software_version_by_id(token: str, base_url: str, device_id: str) -> str:
    """
    Retrieves the device details for a given device ID from Cisco Catalyst Center.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    device_details_url = f"{base_url}/dna/intent/api/v1/network-device/{device_id}"
    print(f"DEBUG: Attempting to retrieve device details from {device_details_url}...")
    try:
        device_response = requests.get(device_details_url, headers=headers, verify=VERIFY_SSL, timeout=30)
        device_response.raise_for_status()

        device_data = device_response.json()
        device_info = device_data.get("response")

        if not device_info:
            logging.error(f"Device with ID '{device_id}' not found or response format unexpected. Raw response: {device_response.text}")
            raise ValueError(f"Device with ID '{device_id}' not found or response format unexpected.")
        
        software_version = device_info.get('softwareVersion')

        if software_version:
            print(f"DEBUG: Found software version '{software_version}' for device ID '{device_id}'.")
            return software_version
        else:
            logging.error(f"Software version not found for device ID '{device_id}'. Device info: {json.dumps(device_info, indent=2)}")
            raise ValueError(f"Software version not found for device ID '{device_id}'.")

    except requests.exceptions.ConnectTimeout as e:
        logging.exception(f"Device details request timed out when connecting to Catalyst Center at {device_details_url}.")
        raise ConnectionError(f"Device details request timed out.")
    except requests.exceptions.ConnectionError as e:
        logging.exception(f"Failed to connect to Catalyst Center for device details at {device_details_url}. Check URL and network.")
        raise ConnectionError(f"Failed to connect to Catalyst Center for device details.")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logging.error(f"Device with ID '{device_id}' not found.")
            raise ValueError(f"Device with ID '{device_id}' not found.")
        logging.exception(f"HTTP error retrieving device details (Status: {e.response.status_code}). Response: {e.response.text}")
        raise ConnectionError(f"HTTP error retrieving device details.")
    except requests.exceptions.RequestException as e:
        logging.exception(f"An unexpected request error occurred while getting device details.")
        raise ConnectionError(f"An unexpected request error occurred while getting device details.")
    except json.JSONDecodeError:
        logging.exception(f"Failed to decode JSON from Catalyst Center device details response. Raw response: {device_response.text}")
        raise ValueError(f"Failed to decode JSON from Catalyst Center device details response.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred while fetching software version for device ID '{device_id}'.")
        raise Exception(f"An unexpected error occurred while fetching software version for device ID '{device_id}'.")

# --- Function to get device type by ID ---
def get_device_type_by_id(token: str, base_url: str, device_id: str) -> str:
    """
    Retrieves the device type for a given device ID from Cisco Catalyst Center.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    device_details_url = f"{base_url}/dna/intent/api/v1/network-device/{device_id}"
    print(f"DEBUG: Attempting to retrieve device details from {device_details_url}...")
    try:
        device_response = requests.get(device_details_url, headers=headers, verify=VERIFY_SSL, timeout=30)
        device_response.raise_for_status()

        device_data = device_response.json()
        device_info = device_data.get("response")

        if not device_info:
            logging.error(f"Device with ID '{device_id}' not found or response format unexpected. Raw response: {device_response.text}")
            raise ValueError(f"Device with ID '{device_id}' not found or response format unexpected.")
        
        device_type = device_info.get('type')

        if device_type:
            print(f"DEBUG: Found device type '{device_type}' for device ID '{device_id}'.")
            return device_type
        else:
            logging.error(f"Device type not found for device ID '{device_id}'. Device info: {json.dumps(device_info, indent=2)}")
            raise ValueError(f"Device type not found for device ID '{device_id}'.")

    except requests.exceptions.ConnectTimeout as e:
        logging.exception(f"Device details request timed out when connecting to Catalyst Center at {device_details_url}.")
        raise ConnectionError(f"Device details request timed out.")
    except requests.exceptions.ConnectionError as e:
        logging.exception(f"Failed to connect to Catalyst Center for device details at {device_details_url}. Check URL and network.")
        raise ConnectionError(f"Failed to connect to Catalyst Center for device details.")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logging.error(f"Device with ID '{device_id}' not found.")
            raise ValueError(f"Device with ID '{device_id}' not found.")
        logging.exception(f"HTTP error retrieving device details (Status: {e.response.status_code}). Response: {e.response.text}")
        raise ConnectionError(f"HTTP error retrieving device details.")
    except requests.exceptions.RequestException as e:
        logging.exception(f"An unexpected request error occurred while getting device details.")
        raise ConnectionError(f"An unexpected request error occurred while getting device details.")
    except json.JSONDecodeError:
        logging.exception(f"Failed to decode JSON from Catalyst Center device details response. Raw response: {device_response.text}")
        raise ValueError(f"Failed to decode JSON from Catalyst Center device details response.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred while fetching device type for device ID '{device_id}'.")
        raise Exception(f"An unexpected error occurred while fetching device type for device ID '{device_id}'.")

# --- Function to get product ordinal name(s) by partial device type ---
def get_product_ordinal_names_by_partial_type(token: str, base_url: str, partial_device_type: str) -> dict:
    """
    Retrieves list of network device product names. Based on the device type, the product ordinal name will be filtered from the list which is generated.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    product_names_url = f"{base_url}/dna/intent/api/v1/siteWiseProductNames"
    print(f"DEBUG: Attempting to retrieve product names from {product_names_url} for partial type '{partial_device_type}'...")
    try:
        product_names_response = requests.get(product_names_url, headers=headers, verify=VERIFY_SSL, timeout=30)
        product_names_response.raise_for_status()

        product_names_data = product_names_response.json()
        product_list = product_names_data.get("response", [])

        if not isinstance(product_list, list):
            logging.error(f"Unexpected product names list format received from Catalyst Center. Expected a list under 'response', got: {type(product_list)}. Raw response: {product_names_response.text}")
            raise ValueError(f"Unexpected product names list format received from Catalyst Center.")

        matching_products = {} # Store {full_product_name: product_ordinal_name}
        for product in product_list:
            product_name = product.get('productName', '')
            product_ordinal_name = product.get('productNameOrdinal')

            # Check if the product name contains the partial device type (case-insensitive)
            if partial_device_type.lower() in product_name.lower():
                if product_ordinal_name:
                    matching_products[product_name] = product_ordinal_name
                else:
                    logging.warning(f"Product entry '{product_name}' matched partial type '{partial_device_type}' but 'productNameOrdinal' is missing. This will be skipped.")
        
        if matching_products:
            print(f"DEBUG: Found {len(matching_products)} product ordinal names for partial device type '{partial_device_type}'.")
            return matching_products
        else:
            logging.error(f"No product ordinal names found for partial device type '{partial_device_type}'.")
            raise ValueError(f"No product ordinal names found for partial device type '{partial_device_type}'.")

    except requests.exceptions.ConnectTimeout as e:
        logging.exception(f"Product names request timed out when connecting to Catalyst Center at {product_names_url}.")
        raise ConnectionError(f"Product names request timed out.")
    except requests.exceptions.ConnectionError as e:
        logging.exception(f"Failed to connect to Catalyst Center for product names at {product_names_url}. Check URL and network.")
        raise ConnectionError(f"Failed to connect to Catalyst Center for product names.")
    except requests.exceptions.HTTPError as e:
        logging.exception(f"HTTP error retrieving product names (Status: {e.response.status_code}). Response: {e.response.text}")
        raise ConnectionError(f"HTTP error retrieving product names.")
    except requests.exceptions.RequestException as e:
        logging.exception(f"An unexpected request error occurred while getting product names.")
        raise ConnectionError(f"An unexpected request error occurred while getting product names.")
    except json.JSONDecodeError:
        logging.exception(f"Failed to decode JSON from Catalyst Center product names response. Raw response: {product_names_response.text}")
        raise ValueError(f"Failed to decode JSON from Catalyst Center product names response.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred while fetching product ordinal name for partial device type '{partial_device_type}'.")
        raise Exception(f"An unexpected error occurred while fetching product ordinal name for partial device type '{partial_device_type}'.")

# --- Function to get Cisco recommended and latest images ---
def get_cisco_recommended_and_latest_images(token: str, base_url: str, product_ordinal_name: str, full_product_name: str) -> list:
    """
    Retrieves Cisco recommended and latest images for a given product ordinal name from Catalyst Center.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    images_url = f"{base_url}/dna/intent/api/v1/images"
    params = {'productNameOrdinal': product_ordinal_name}
    print(f"DEBUG: Attempting to retrieve images from {images_url} with productNameOrdinal='{product_ordinal_name}' of Platform - '{full_product_name}'...")
    try:
        images_response = requests.get(images_url, headers=headers, params=params, verify=VERIFY_SSL, timeout=60)
        images_response.raise_for_status()

        images_data = images_response.json()
        images_list = images_data.get("response", [])

        if not isinstance(images_list, list):
            logging.error(f"Unexpected images list format received from Catalyst Center. Expected a list under 'response', got: {type(images_list)}. Raw response: {images_response.text}")
            raise ValueError(f"Unexpected images list format received from Catalyst Center.")

        filtered_images = []
        for image in images_list:
            if image.get('recommended') == 'CISCO' or image.get('ciscoLatest') is True:
                filtered_images.append(image)
        
        if filtered_images:
            print(f"DEBUG: Found {len(filtered_images)} recommended/latest images for product '{product_ordinal_name} of Platform - '{full_product_name}'.")
            return filtered_images
        else:
            return []

    except requests.exceptions.ConnectTimeout as e:
        logging.exception(f"Images request timed out when connecting to Catalyst Center at {images_url}.")
        raise ConnectionError(f"Images request timed out.")
    except requests.exceptions.ConnectionError as e:
        logging.exception(f"Failed to connect to Catalyst Center for images at {images_url}. Check URL and network.")
        raise ConnectionError(f"Failed to connect to Catalyst Center for images.")
    except requests.exceptions.HTTPError as e:
        logging.exception(f"HTTP error retrieving images (Status: {e.response.status_code}). Response: {e.response.text}")
        raise ConnectionError(f"HTTP error retrieving images.")
    except requests.exceptions.RequestException as e:
        logging.exception(f"An unexpected request error occurred while getting images.")
        raise ConnectionError(f"An unexpected request error occurred while getting images.")
    except json.JSONDecodeError:
        logging.exception(f"Failed to decode JSON from Catalyst Center images response. Raw response: {images_response.text}")
        raise ValueError(f"Failed to decode JSON from Catalyst Center images response.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred while fetching images for product '{product_ordinal_name}'.")
        raise Exception(f"An unexpected error occurred while fetching images for product '{product_ordinal_name}'.")

# --- Function to export data to Excel (now supports multiple sheets) ---
def export_to_excel(data_per_sheet: dict, filename: str = "cisco_recommended_images.xlsx"):
    """
    Exports a dictionary of data (where keys are sheet names and values are lists of image data)
    to a single Excel file with multiple sheets, including only the specified columns and renaming them.
    """
    if not data_per_sheet:
        print("No data to export to Excel.")
        return

    # Define the mapping from original column names to desired display names
    column_mapping = {
        'version': 'Software Version',
        'imageType': 'Image Type',
        'recommended': 'Recommended',
        'ciscoLatest': 'Latest',
        'hasAddonImages': 'Has Addon Images',
        'isGoldenTagged': 'Is Golden Tagged',
        'isAddonImage': 'Is Addon Image'
    }

    original_desired_columns = list(column_mapping.keys())

    try:
        with pd.ExcelWriter(filename, engine='xlsxwriter') as writer:
            for sheet_name, data in data_per_sheet.items():
                if not data:
                    print(f"No data for sheet '{sheet_name}', skipping.")
                    continue

                df = pd.DataFrame(data)
                
                # Filter the DataFrame to include only the original desired columns
                filtered_df = df.reindex(columns=original_desired_columns)

                # Rename the columns
                renamed_df = filtered_df.rename(columns=column_mapping)

                # Sanitize sheet name to be Excel-compatible (max 31 chars, no invalid chars)
                # Invalid characters: \ / ? * [ ] :
                # Max length 31 chars
                sanitized_sheet_name = sheet_name.replace('\\', '_').replace('/', '_').replace('?', '_').replace('*', '_').replace('[', '_').replace(']', '_').replace(':', '_')
                sanitized_sheet_name = sanitized_sheet_name[:31] # Truncate to 31 characters

                renamed_df.to_excel(writer, sheet_name=sanitized_sheet_name, index=False)
                print(f"Successfully exported data to sheet '{sanitized_sheet_name}' in '{filename}'.")
        print(f"All data successfully exported to '{filename}'.")
    except Exception as e:
        logging.exception(f"Error exporting data to Excel: {filename}")
        print(f"An error occurred during Excel export. Check '{LOG_FILE}' for details.")


# --- Main Execution Block ---
if __name__ == "__main__":
    # Check if Catalyst Center credentials are provided
    if not all([CATALYST_CENTER_URL, CATALYST_CENTER_USERNAME, CATALYST_CENTER_PASSWORD]):
        error_msg = "Configuration Error: Catalyst Center URL, Username, or Password not found in config_rec_image.yaml under 'catalyst_center' section."
        logging.error(error_msg)
        print(error_msg)
        sys.exit(1)
    current_date_str = datetime.now().strftime("%d-%m-%Y")
    try:
        choice = input("Generate report by:\n1. Device Name\n2. Device Type (e.g., 9300, 9500)\nEnter your choice (1 or 2): ")

        all_recommended_images_for_excel = {} # Dictionary to hold {sheet_name: list_of_images}

        if choice == '1':
            input_type = "Device Name"
            user_input = input("Enter the hostname of the network device: ")
            if not user_input:
                error_msg = "Input Error: Device hostname cannot be empty."
                logging.error(error_msg)
                print(error_msg)
                sys.exit(1)

            auth_token = get_auth_token(CATALYST_CENTER_URL, CATALYST_CENTER_USERNAME, CATALYST_CENTER_PASSWORD)

            device_id = get_device_id_by_name(auth_token, CATALYST_CENTER_URL, user_input)
            print(f"Device ID for '{user_input}': {device_id}")

            device_type = get_device_type_by_id(auth_token, CATALYST_CENTER_URL, device_id)
            print(f"Device Type for device ID '{device_id}': {device_type}")

            matching_products = get_product_ordinal_names_by_partial_type(auth_token, CATALYST_CENTER_URL, device_type)
            
            if not matching_products:
                error_msg = f"No product ordinal name found for exact device type '{device_type}'."
                logging.error(error_msg)
                raise ValueError(error_msg)

            # Assuming the exact device_type will be a key in matching_products if found
            if device_type in matching_products:
                product_ordinal_name = matching_products[device_type]
                print(f"Product Ordinal Name for device type '{device_type}': {product_ordinal_name}")
            else:
                # Fallback if the exact device_type isn't a key, but a partial match was found.
                # This might happen if the productName in siteWiseProductNames is slightly different
                # from the 'type' field in network-device details.
                # For now, we'll pick the first one if multiple partial matches occur.
                product_ordinal_name = list(matching_products.values())[0]
                print(f"WARNING: Exact device type '{device_type}' not found as key, using first matching product ordinal name: '{product_ordinal_name}'.")
                logging.warning(f"Exact device type '{device_type}' not found as key in matching products. Using first found product ordinal name: '{product_ordinal_name}'. Full matches: {matching_products}")
            recommended_images = get_cisco_recommended_and_latest_images(auth_token, CATALYST_CENTER_URL, product_ordinal_name, device_type)
            
            # For device name, put all images into one sheet named after the device
            all_recommended_images_for_excel[user_input] = recommended_images
            output_base_filename_prefix = user_input.replace(" ", "_").replace("/", "-")

        elif choice == '2':
            input_type = "Device Type"
            user_input_raw = input("Enter the device type(s) (e.g., '9300, 9500') [Note: You can enter multiple device types]: ")
            if not user_input_raw:
                error_msg = "Input Error: Device type(s) cannot be empty."
                logging.error(error_msg)
                print(error_msg)
                sys.exit(1)
            
            # Split multiple device types by comma and strip whitespace
            partial_device_types = [dt.strip() for dt in user_input_raw.split(',') if dt.strip()]
            print(partial_device_types[0])
            if not partial_device_types:
                error_msg = "Input Error: No valid device types entered after splitting."
                logging.error(error_msg)
                print(error_msg)
                sys.exit(1)

            auth_token = get_auth_token(CATALYST_CENTER_URL, CATALYST_CENTER_USERNAME, CATALYST_CENTER_PASSWORD)

            for partial_type in partial_device_types:
                print(f"\nProcessing partial device type: '{partial_type}'...")
                try:
                    # Get all product ordinal names that match the partial type
                    matching_product_map = get_product_ordinal_names_by_partial_type(auth_token, CATALYST_CENTER_URL, partial_type)
                    
                    if not matching_product_map:
                        print(f"No specific product platforms found for partial device type '{partial_type}'. Skipping.")
                        continue

                    for full_product_name, product_ordinal_name in matching_product_map.items():
                        print(f"  Retrieving images for platform: '{full_product_name}' (Ordinal: '{product_ordinal_name}')")
                        try:
                            recommended_images = get_cisco_recommended_and_latest_images(auth_token, CATALYST_CENTER_URL, product_ordinal_name, full_product_name)
                            if recommended_images:
                                all_recommended_images_for_excel[full_product_name] = recommended_images
                            else:
                                print(f"[NOTE: NO RECOMMENDED IMAGES FOR '{full_product_name}'.]")
                        except (ConnectionError, ValueError, Exception) as e:
                            print(f"  Error retrieving images for '{full_product_name}'. Details in log file.")
                            # Exception is already logged by the called function
                            continue # Continue to next product ordinal name

                except (ConnectionError, ValueError, Exception) as e:
                    print(f"Error processing partial device type '{partial_type}'. Details in log file.")
                    # Exception is already logged by the called function
                    continue # Continue to next partial device type

            if len(partial_device_types) > 1:
                output_base_filename_prefix = "multi_device_type"
            else: # Single device type input
                output_base_filename_prefix = partial_device_types[0].replace(" ", "_").replace("/", "-") #  # Generic filename for multiple types

        else:
            error_msg = "Invalid choice. Please enter '1' or '2'."
            logging.error(error_msg)
            print(error_msg)
            sys.exit(1)

        # 6. Export to Excel (common to both paths, now handles multiple sheets)
        if all_recommended_images_for_excel:
            output_filename = f"{output_base_filename_prefix}_recommended_images_{current_date_str}.xlsx"
            export_to_excel(all_recommended_images_for_excel, output_filename)
            print(f"Process completed. Recommended and latest images saved to '{output_filename}'.")
        else:
            print("No recommended images were found for any of the specified inputs. No Excel report generated.")

    except (ConnectionError, ValueError, Exception) as e:
        print(f"\nAn error occurred during the process. Please check '{LOG_FILE}' for detailed error information.", file=sys.stderr)
        sys.exit(1)
