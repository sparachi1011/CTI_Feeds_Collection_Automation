"""
Created on Mon Jul 22 22:45:45 2024

AUTHOR      : Sai Koushik Parachi
VERSION     : v1
FileName    : ysoc_aiml_threat_intelligence_imports.py
Objective   : This python file try to load and intialize necessary python libraries and share across automation scripts.

Parameters  :
    INPUT   : None.
    OUPUT   : Python Library Objects.

"""

import random
import pandas as pd
import os
import sys
import stat
import pdb
import datetime
import time
from elasticsearch import Elasticsearch, helpers
import requests
import json
import logging
import multiprocessing as mp
import warnings
warnings.filterwarnings("ignore", category=Warning)

# timestamp = (datetime.datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S')
at_timestamp = datetime.datetime.now(
    datetime.timezone.utc)  # .strftime('%Y-%m-%d %H:%M:%S')

if os.name == 'nt':
    ysoc_aiml_cti_automation_logs = os.getcwd() + "/"
if os.name == 'posix':
    # ysoc_aiml_cti_automation_logs = "/home/ec2-user/YSOC_Abuse_IPDB_Module/"
    # ysoc_aiml_cti_automation_logs = "/home/zzz-ysoc-admin/YSOC_Abuse_IPDB_Module/"
    ysoc_aiml_cti_automation_logs = os.getcwd() + "/"


def check_file_or_create(sub_path):
    try:
        log_file_path = ysoc_aiml_cti_automation_logs + sub_path + \
            str(datetime.datetime.now().strftime("%Y_%m_%d")) + '.log'
        if os.path.exists(log_file_path.rsplit("/", 1)[0]):
            if os.path.exists(log_file_path):
                log_file_name = log_file_path
            else:
                log_file = open(log_file_path, 'a')
                log_file.close()
                log_file_name = log_file_path
        else:
            try:
                # # print("\n&&&&&&MakeDirectoryFromImports.py", ysoc_module_path)
                os.mkdir(log_file_path.rsplit("/", 1)[0])  # , mode=0o777)
                # os.mkdir('./execution_logs')#, mode=0o777)
                log_file = open(log_file_path, 'a')
                log_file.close()
                log_file_name = log_file_path
                # # print("\n&&&&&&AfterMakeDirectoryFromImports.py", ysoc_module_path)
            except Exception as e:
                print("Error while creating log file from imports.py\n", e)
        return log_file_name
    except Exception as e:
        print("Got Error in generate_logger function as:\n", e)


def generate_logger():
    try:
        sub_path = 'ysoc_aiml_cti_automation_logs/ysoc_aiml_cti_automation_logs_'
        log_file_name = check_file_or_create(sub_path)
        if log_file_name:
            try:
                log_process_activities(
                    'ysoc_aiml_cti_automation_logs', log_file_name)
                logger = logging.getLogger(
                    'ysoc_aiml_cti_automation_logs')
            except Exception as e:
                log_process_activities(
                    'ysoc_aiml_cti_automation_logs', log_file_name)
                logger = logging.getLogger(
                    'ysoc_aiml_cti_automation_logs')
        return logger, log_file_name
    except Exception as e:
        print("Got Error in generate_logger function as:\n", e)


def log_process_activities(logger_name, log_file):
    """
    This Function will create a logger object.

    Parameters
    ----------
    logger_name : String
        DESCRIPTION: name of the logger object.
    log_file : String
        DESCRIPTION: Path to log file.
    logger_level : String
        DESCRIPTION: Level of logging to be tracked.

    Returns
    -------
    Logger object.

    """
    try:
        level = logging.INFO
        logger = logging.getLogger(logger_name)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s')
        fileHandler = logging.FileHandler(log_file, mode='a')
        fileHandler.setFormatter(formatter)
        logger.setLevel(level)
        logger.addHandler(fileHandler)

        return logger
    except FileNotFoundError as error:
        logger.error(
            "FileNotFoundError at log_process_activities " + str(error))
    except Exception as error:
        logger.error("Error at log_process_activities " + str(error))


def get_azure_secrets():
    import os
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential

    keyVaultName = "YSOC-Internal-Secrets"  # os.environ["KEY_VAULT_NAME"]
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    secretName = "YSOC-Abuse-IPDB"

    credential = DefaultAzureCredential()
    # exclude_shared_token_cache_credential=True)
    client = SecretClient(vault_url=KVUri, credential=credential)

    # secretName = input("Input a name for your secret > ")
    # secretValue = input("Input a value for your secret > ")

    # print(
    #     f"Creating a secret in {keyVaultName} called '{secretName}' with the value '{secretValue}' ...")

    # client.set_secret(secretName, secretValue)

    # print(" done.")

    print(f"Retrieving your secret from {keyVaultName}.")
    retrieved_secret = client.get_secret(secretName)
    print(f"Retrieved your secret from {keyVaultName}.")
    # print(f"Your secret is '{retrieved_secret.value}'.")
    # print(f"Deleting your secret from {keyVaultName} ...")

    # poller = client.begin_delete_secret(secretName)
    # deleted_secret = poller.result()

    return retrieved_secret.value


def get_aws_secrets():
    # import botocore
    # import botocore.session
    # from aws_secretsmanager_caching import SecretCache, SecretCacheConfig

    # client = botocore.session.get_session().create_client(
    #     service_name='secretsmanager', region_name="us-east-1")
    # cache_config = SecretCacheConfig()
    # cache = SecretCache(config=cache_config, client=client)

    # secret = cache.get_secret_string('ysoc_dev_test1')
    from boto3 import Session

    session = Session(profile_name="For_YSOC_Secrets_Manager")
    credentials = session.get_credentials()
    # Credentials are refreshable, so accessing your access key / secret key
    # separately can lead to a race condition. Use this to get an actual matched
    # set.
    current_credentials = credentials.get_frozen_credentials()

    # I would not recommend actually printing these. Generally unsafe.
    print(current_credentials.access_key)
    print(current_credentials.secret_key)
    print(current_credentials.token)


# get_aws_secrets()
logger, log_file_path = generate_logger()
# ysoc_secrets = json.loads(get_azure_secrets())
ysoc_secrets = {'ysoc_pcap_analysis_script': {'elastic_creds': {
                'pcap_script_execution': 'pcap6734ysoc'}}}
# 'pcap_script_execution_user': 'pcapsoc12378vf'}}}  # '7YIOV9Hd4BLSAI'}}}
# print(ysoc_secrets)
