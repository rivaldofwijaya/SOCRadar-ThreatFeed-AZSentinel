import os
import re
import requests
import logging
import json
from datetime import datetime, timedelta
import msal

socradar_api_key = "client_api_key"
socradar_company_id = "client_company_id"
azure_tenant_id = "azure-tenant-id" 
client_id = "app-client-id" 
secret = "client-secret-value" 

graph_server = "graph.microsoft.com" 
azure_authority = f"https://login.microsoftonline.com/{azure_tenant_id}" 
scope = [ "https://graph.microsoft.com/.default" ] 
expire_date_offset = 7
verify_ssl = True


def get_graph_api_acess_token():
    # Create a preferably long-lived app instance which maintains a token cache.
    app = msal.ConfidentialClientApplication(
        client_id, authority=azure_authority,
        client_credential=secret,
        # token_cache=...  # Default cache is in memory only.
                           # You can learn how to use SerializableTokenCache from
                           # https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
        )

    return app


def build_azuresentinel_feed(feed_item, feed_name):
    regex_ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    regex_md5 = re.compile(r"^([a-fA-F\d]{32})$")
    regex_sha1 = re.compile(r"^([a-fA-F\d]{40})$")
    regex_sha256 = re.compile(r"^([a-fA-F\d]{64})$")
    expire_date = datetime.utcnow() + timedelta(expire_date_offset) # get utc time for now
    ioc = feed_item.get('feed')
    if not ioc:
        return None
    ioc_type = feed_item.get('feed_type', 'unknown')
    ioc_source = feed_item.get('maintainer_name', '')
    azuresentinel_feed = {
        "action": "alert", # unknown, allow, block, alert
        "azureTenantId": azure_tenant_id, #string, Azure Active Directory tenant id of submitting client
        "tags": ["SOCRadar"],
        "description": f"{feed_name} - {ioc_source}", # Brief description (100 characters or less)
        "expirationDateTime": f"{expire_date.isoformat()}Z", #string isoformat, add Z for utc, # DateTime string indicating when the Indicator expires.2014-01-01T00:00:00Z
        "targetProduct": "Azure Sentinel", # Azure Sentinel, Microsoft Defender ATP
        "threatType": "WatchList", # Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList
        "tlpLevel": "amber", # unknown, white, green, amber, red
    }
    if ioc_type == "ip":
        if bool(re.match(regex_ipv4, ioc)):
            azuresentinel_feed['networkIPv4'] = ioc
        else:
            azuresentinel_feed['networkIPv6'] = ioc
    elif ioc_type == 'hash':
        azuresentinel_feed['fileHashValue'] = ioc
        if bool(re.match(regex_md5, ioc)):
            azuresentinel_feed['fileHashType'] = 'md5'
        elif bool(re.match(regex_sha1, ioc)):
            azuresentinel_feed['fileHashType'] = 'sha1'
        elif bool(re.match(regex_sha256, ioc)):
            azuresentinel_feed['fileHashType'] = 'sha256'
        else:
            return None
    elif ioc_type == 'hostname':
        azuresentinel_feed['domainName'] = ioc
    elif ioc_type == 'url':
        azuresentinel_feed['url'] = ioc
    else:
        return None

    return azuresentinel_feed

def main():
    def get_file_name():
        today = datetime.today().strftime('%Y-%m-%d')
        return f'SOCRadar-Threat-Feed_{today}.json'

    def format_feeds_json_text(text, collection_name):
        return_formatted_feeds = ''
        feeds = json.loads(text)
        if type(feeds) is list:
            feeds = [{key: value for key, value in {**feed, 'collection_name': collection_name}.items() if key != 'extra_info'} for feed in feeds]
            return_formatted_feeds = '\n'.join([json.dumps(feed) for feed in feeds])
        return f"{return_formatted_feeds}\n"

    def remove_old_files(threatfeed_folder, threshold_day_count):
        if type(threshold_day_count) != int:
            try:
                threshold_day_count = int(threshold_day_count)
            except:
                threshold_day_count = 5
        if threshold_day_count > 0:
            threatfeed_file_paths = [
                f'{threatfeed_folder}/{date_folder_name}' for date_folder_name in os.listdir(threatfeed_folder)
                if os.path.isfile(f'{threatfeed_folder}/{date_folder_name}')]
            remove_datetime_threshold = datetime.today() - timedelta(days=threshold_day_count)
            for threatfeed_file_path in threatfeed_file_paths:
                try:
                    date_str = threatfeed_file_path.split('_')[-1].split('.')[0]
                    threatfeed_file_datetime = datetime.strptime(date_str, "%Y-%m-%d")
                except:
                    continue
                if threatfeed_file_datetime.date() <= remove_datetime_threshold.date():
                    os.remove(threatfeed_file_path)
    socradar_threat_feed_folder = os.environ.get('SOCRADAR_THREAT_FEED_INTEGRATION_FOLDER', './Threats-SOCRadar')
    remove_file_threshold_day = os.environ.get('SOCRADAR_THREAT_FEED_OLD_FILE_REMOVAL_THRESHOLD', 5)
    os.makedirs(socradar_threat_feed_folder, exist_ok=True)
    logging.basicConfig()
    logger = logging.getLogger('socradar_threat_feed_integration_logger')
    logger.setLevel(logging.DEBUG)
    file_name = get_file_name()
    file_path_to_save = f'{socradar_threat_feed_folder}/{file_name}.log'
    threatfeed_collection_dict = {
        "e89ab3b58e174b8c82767088d8e66cae": "SOCRadar-Attackers-Recommended-Block-IP",
        "9079dcc2f96e4835bb807026d4cdcc86": "SOCRadar-APT-Recommended-Block-Domain",
        "4d7a69ce6e7c49ff8c916da5d7343916": "SOCRadar-APT-Recommended-Block-IP",
        "0cb06558728b4dc296019c93b78360d1": "SOCRadar-APT-Recommended-Block-Hash",
        "606a83358bbe466d8c3885e37fa595b7": "SOCRadar-Attackers-Recommended-Block-Domain",
        "03cc11380b5d4a77a0d0cc2a7c568230": "SOCRadar-Recommended-Phishing-Global",
        "8742cab86cc4414092217f87298e94a1": "SOCRadar-Recommended-Block-Hash",
    }
    # get access token for graph api
    # The pattern to acquire a token looks like this.
    # result = None
    # headers = ''
    # graph_api_token = ""

    # # Firstly, looks up a token from cache
    # # Since we are looking for token for the current app, NOT for an end user,
    # # notice we give account parameter as None.
    # app = get_graph_api_acess_token()
    # result = app.acquire_token_silent(scope, account=None)
    # if not result:
    #     logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
    #     result = app.acquire_token_for_client(scopes=scope)
    # if "access_token" in result:
    #     graph_api_token = result["access_token"]
    #     headers = {
    #         "Content-Type": "application/json",
    #         "Authorization": f"Bearer {graph_api_token}"
    #     }
    # else:
    #     logger.warning("No suitable token exists. Terminating the script.")
    #     logger.warning(result.get("error"))
    #     logger.warning(result.get("error_description"))
    #     logger.warning(result.get("correlation_id"))  # You may need this when reporting a bug
    #     quit()
    for threatfeed_uuid, threatfeed_name in threatfeed_collection_dict.items():
        #if threatfeed_name == "SOCRadar-Recommended-Phishing-Global":
        print(threatfeed_name)
        try:
            socradar_threat_feed_response = requests.get(f'https://platform.socradar.com/api/threat/intelligence/feed_list/{threatfeed_uuid}.json?key={socradar_api_key}&v=2')
            if socradar_threat_feed_response.status_code < 400:
                file_path_to_save = f'{socradar_threat_feed_folder}/{threatfeed_name}.log'
                # azuresentinel_feed_list = []
                # count = 0
                # threat_chunk_count = int(len(socradar_threat_feed_response.json())/100) + 1
                # #print(len(socradar_threat_feed_response.json()))
                # #print(threat_chunk_count)
                # for feed_item in socradar_threat_feed_response.json():
                #     azuresentinel_feed = build_azuresentinel_feed(feed_item, threatfeed_name)
                #     if azuresentinel_feed:
                #         azuresentinel_feed_list.append(azuresentinel_feed)
                #     if len(azuresentinel_feed_list) == 100:
                #         count += 1
                #         azuresentinel_feed_dict_to_submit = { 'value' : azuresentinel_feed_list }
                #         '''
                #         azuresentinel_feed_file_path = f"{socradar_threat_feed_folder}/{threatfeed_name}-{count}.log"
                #         with open(azuresentinel_feed_file_path, 'w') as f:
                #             f.write(json.dumps(azuresentinel_feed_dict_to_submit, indent=2))
                #         '''
                #         payload = json.dumps(azuresentinel_feed_dict_to_submit)
                #         response = requests.post(f"https://{graph_server}/beta/security/tiIndicators/submitTiIndicators", headers=headers, data=payload, verify=verify_ssl)
                #         if response.status_code == 200:
                #             logger.info(f'{threatfeed_name} has been fetched from SOCRadar and chunk {count} has submitted to Azure Sentinel: {response.url}')
                #             logger.info(f'Status Code: \n{response.status_code}')
                #             logger.info(f'Url: \n{response.url}')
                #         else:
                #             logger.info(f'{threatfeed_name} has been fetched from SOCRadar and error on chunk {count} submission to Azure Sentinel')
                #             logger.info(f'Status Code: \n{response.status_code}')
                #             logger.info(f'Url: \n{response.url}')
                #             logger.info(f'Response: \n{response.text}')
                #         azuresentinel_feed_list = []
                # # to get the residual feeds counted below 100
                # if count < threat_chunk_count:
                #     count += 1
                #     azuresentinel_feed_dict_to_submit = { 'value' : azuresentinel_feed_list }
                #     #print(len(azuresentinel_feed_list))
                #     '''
                #     azuresentinel_feed_file_path = f"{socradar_threat_feed_folder}/{threatfeed_name}-{count}.log"
                #     with open(azuresentinel_feed_file_path, 'w') as f:
                #         f.write(json.dumps(azuresentinel_feed_dict_to_submit, indent=2))
                #     '''
                #     payload = json.dumps(azuresentinel_feed_dict_to_submit)
                #     response = requests.post(f"https://{graph_server}/beta/security/tiIndicators/submitTiIndicators", headers=headers, data=payload, verify=verify_ssl)
                #     if response.status_code == 200:
                #         logger.info(f'{threatfeed_name} has been fetched from SOCRadar and chunk {count} has submitted to Azure Sentinel: {response.url}')
                #         logger.info(f'Status Code: \n{response.status_code}')
                #         logger.info(f'Url: \n{response.url}')
                #     else:
                #         logger.info(f'{threatfeed_name} has been fetched from SOCRadar and error on chunk {count} submission to Azure Sentinel')
                #         logger.info(f'Status Code: \n{response.status_code}')
                #         logger.info(f'Url: \n{response.url}')
                #         logger.info(f'Response: \n{response.text}')

                with open(file_path_to_save, 'w') as threat_file:
                    threat_file.write(json.dumps(socradar_threat_feed_response.json(), indent=2))
                logger.info(f'{threatfeed_name} has been fetched from SOCRadar and saved to: {file_path_to_save}')
            elif socradar_threat_feed_response.status_code == 429:
                logger.info('API rate limit exceeded.')
            else:
                logger.info('Could not get response from SOCRadar API.')
        except KeyboardInterrupt as e:
            logger.info('Keyboard interrupt is taken, stopping SOCRadar threat feed integration.')
        except:
            logger.exception('Exception at SOCRadar threat feed integration.')
    else:
        remove_old_files(socradar_threat_feed_folder, remove_file_threshold_day)

if __name__ == '__main__':
    main()
