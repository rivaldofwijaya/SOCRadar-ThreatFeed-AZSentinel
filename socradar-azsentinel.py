import os
import re
import requests
import logging
import json
from datetime import datetime, timedelta
import msal
from dotenv import load_dotenv
from typing import Optional

# Load environment variables from a .env file
load_dotenv()

# Set up logging early to capture all events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('socradar_threat_feed_integration_logger')

# --- Configuration using Environment Variables ---
try:
    SOCRADAR_API_KEY = os.environ['SOCRADAR_API_KEY']
    AZURE_TENANT_ID = os.environ['AZURE_TENANT_ID']
    CLIENT_ID = os.environ['CLIENT_ID']
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
except KeyError as e:
    logger.error(f"Missing required environment variable: {e}")
    raise SystemExit(f"Configuration error: Missing environment variable {e}")

# --- Constants ---
GRAPH_SERVER = "graph.microsoft.com"
AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/.default"]
EXPIRE_DATE_OFFSET = 7
VERIFY_SSL = True
THREAT_FEED_FOLDER = os.environ.get('SOCRADAR_THREAT_FEED_INTEGRATION_FOLDER', './Threats-SOCRadar')
OLD_FILE_REMOVAL_THRESHOLD = int(os.environ.get('SOCRADAR_THREAT_FEED_OLD_FILE_REMOVAL_THRESHOLD', 5))

# --- Regular Expressions for Input Validation ---
REGEX_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
REGEX_MD5 = re.compile(r"^([a-fA-F\d]{32})$")
REGEX_SHA1 = re.compile(r"^([a-fA-F\d]{40})$")
REGEX_SHA256 = re.compile(r"^([a-fA-F\d]{64})$")

# --- Functions ---

def get_graph_api_access_token():
    """Acquires a Microsoft Graph API access token using MSAL."""
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AZURE_AUTHORITY,
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_silent(SCOPE, account=None)
    if not result:
        logger.info("No suitable token in cache. Acquiring a new one.")
        result = app.acquire_token_for_client(scopes=SCOPE)
    
    if "access_token" not in result:
        error_msg = f"Failed to acquire token: {result.get('error_description')}"
        logger.critical(error_msg)
        raise RuntimeError(error_msg)
        
    return result["access_token"]

def build_azuresentinel_feed(feed_item: dict, feed_name: str) -> Optional[dict]:
    """Builds a single Azure Sentinel threat indicator object, with validation."""
    ioc = feed_item.get('feed')
    if not ioc:
        logger.warning("Skipping feed item with no 'feed' value.")
        return None
    
    ioc_type = feed_item.get('feed_type', 'unknown')
    ioc_source = feed_item.get('maintainer_name', 'Unknown')
    expire_date = datetime.utcnow() + timedelta(days=EXPIRE_DATE_OFFSET)
    
    azuresentinel_feed = {
        "action": "alert",
        "azureTenantId": AZURE_TENANT_ID,
        "tags": ["SOCRadar"],
        "description": f"{feed_name} - {ioc_source}"[:100],
        "expirationDateTime": f"{expire_date.isoformat()}Z",
        "targetProduct": "Azure Sentinel",
        "threatType": "WatchList",
        "tlpLevel": "amber",
    }
    
    if ioc_type == "ip":
        if REGEX_IPV4.match(ioc):
            azuresentinel_feed['networkIPv4'] = ioc
        else:
            # Assuming it's an IPv6 if not IPv4, but this could be more specific
            azuresentinel_feed['networkIPv6'] = ioc
    elif ioc_type == 'hash':
        azuresentinel_feed['fileHashValue'] = ioc
        if REGEX_MD5.match(ioc):
            azuresentinel_feed['fileHashType'] = 'md5'
        elif REGEX_SHA1.match(ioc):
            azuresentinel_feed['fileHashType'] = 'sha1'
        elif REGEX_SHA256.match(ioc):
            azuresentinel_feed['fileHashType'] = 'sha256'
        else:
            logger.warning(f"Invalid hash format for IOC: {ioc}")
            return None
    elif ioc_type == 'hostname':
        azuresentinel_feed['domainName'] = ioc
    elif ioc_type == 'url':
        azuresentinel_feed['url'] = ioc
    else:
        logger.warning(f"Unsupported IOC type: {ioc_type} for IOC: {ioc}")
        return None
        
    return azuresentinel_feed

def remove_old_files(threatfeed_folder: str, threshold_days: int):
    if not os.path.isdir(threatfeed_folder):
        logger.warning(f"Threat feed folder not found: {threatfeed_folder}")
        return

    remove_timestamp_threshold = datetime.now() - timedelta(days=threshold_days)
    
    for file_name in os.listdir(threatfeed_folder):
        file_path = os.path.join(threatfeed_folder, file_name)
        if not os.path.isfile(file_path):
            continue
            
        try:
            mod_timestamp = datetime.fromtimestamp(os.path.getmtime(file_path))
            if mod_timestamp < remove_timestamp_threshold:
                os.remove(file_path)
                logger.info(f"Removed old file: {file_path}")
        except Exception as e:
            logger.warning(f"Could not process file {file_path} for removal: {e}")

def main():
    threatfeed_collection_dict = {
        "e89ab3b58e174b8c82767088d8e66cae": "SOCRadar-Attackers-Recommended-Block-IP",
        "9079dcc2f96e4835bb807026d4cdcc86": "SOCRadar-APT-Recommended-Block-Domain",
        "4d7a69ce6e7c49ff8c916da5d7343916": "SOCRadar-APT-Recommended-Block-IP",
        "0cb06558728b4dc296019c93b78360d1": "SOCRadar-APT-Recommended-Block-Hash",
        "606a83358bbe466d8c3885e37fa595b7": "SOCRadar-Attackers-Recommended-Block-Domain",
        "03cc11380b5d4a77a0d0cc2a7c568230": "SOCRadar-Recommended-Phishing-Global",
        "8742cab86cc4414092217f87298e94a1": "SOCRadar-Recommended-Block-Hash",
    }

    # Ensure the threat feed folder exists with a secure mode.
    try:
        os.makedirs(THREAT_FEED_FOLDER, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create directory {THREAT_FEED_FOLDER}: {e}")
        return

    try:
        graph_api_token = get_graph_api_access_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {graph_api_token}"
        }
    except Exception as e:
        logger.critical(f"Script could not start due to authentication failure: {e}")
        return

    # Use a session for persistent connections and header management
    with requests.Session() as session:
        session.headers.update(headers)
        
        for threatfeed_uuid, threatfeed_name in threatfeed_collection_dict.items():
            logger.info(f"Processing threat feed: {threatfeed_name}")
            
            try:
                socradar_url = f'https://platform.socradar.com/api/threat/intelligence/feed_list/{threatfeed_uuid}.json'
                params = {'key': SOCRADAR_API_KEY, 'v': 2}
                
                socradar_response = session.get(socradar_url, params=params, verify=VERIFY_SSL, timeout=30)
                socradar_response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
                
                # Process the fetched data
                threat_data = socradar_response.json()
                azuresentinel_feed_list = []
                
                for feed_item in threat_data:
                    azuresentinel_feed = build_azuresentinel_feed(feed_item, threatfeed_name)
                    if azuresentinel_feed:
                        azuresentinel_feed_list.append(azuresentinel_feed)
                        
                # Batch submission to Azure Sentinel
                chunk_size = 100
                for i in range(0, len(azuresentinel_feed_list), chunk_size):
                    chunk = azuresentinel_feed_list[i:i + chunk_size]
                    payload = json.dumps({'value': chunk})
                    
                    graph_url = f"https://{GRAPH_SERVER}/beta/security/tiIndicators/submitTiIndicators"
                    response = session.post(graph_url, data=payload, verify=VERIFY_SSL, timeout=30)
                    
                    if response.status_code == 200:
                        logger.info(f'Successfully submitted chunk {i//chunk_size + 1} for {threatfeed_name}.')
                    else:
                        logger.error(f'Failed to submit chunk {i//chunk_size + 1} for {threatfeed_name}. Status Code: {response.status_code}, Response: {response.text}')
                        
                file_path_to_save = os.path.join(THREAT_FEED_FOLDER, f"{threatfeed_name}_{datetime.today().strftime('%Y-%m-%d')}.json")
                with open(file_path_to_save, 'w') as f:
                    json.dump(threat_data, f, indent=2)
                logger.info(f'Fetched {threatfeed_name} and saved to: {file_path_to_save}')

            except requests.exceptions.HTTPError as e:
                logger.error(f"HTTP error for {threatfeed_name}: {e}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error for {threatfeed_name}: {e}")
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON response for {threatfeed_name}.")
            except Exception as e:
                logger.exception(f"An unexpected error occurred while processing {threatfeed_name}: {e}")
        
    remove_old_files(THREAT_FEED_FOLDER, OLD_FILE_REMOVAL_THRESHOLD)

if __name__ == '__main__':
    main()