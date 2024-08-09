

# # examples = {'Attack_name': ['DarkCrystal RAT aka DCRat – Active IOCs', 'Fickle Stealer Distributed via Multiple Attack Chain',
# #                             'New Orcinius Trojan Uses VBA Stomping to Mask Infection', 'Attack Cases Against HTTP File Server (HFS) (CVE-2024-23692)'],
# #             'Alert_code': [112, 114, 777, 533], }

# # print([example for example in examples['Attack_name', 'Alert_code']])
# import pandas as pd
# from elasticsearch import Elasticsearch
# from elasticsearch.helpers import bulk

# # Function to create an Elasticsearch client


# def ysoc_connect_es():
#     try:
#         # Elasticsearch account information
#         es_user_name = "pcap_script_execution"

#         if es_user_name == 'pcap_script_execution':
#             basic_auth = (
#                 es_user_name, 'pcap6734ysoc')
#             es_ids = Elasticsearch(
#                 # ['https://060652a6cf6c4ef0b5fbc3362216e5d4.japaneast.azure.elastic-cloud.com:443'],
#                 # ['https://060652a6cf6c4ef0b5fbc3362216e5d4.japaneast.azure.elastic-cloud.com:443'],
#                 ['https://it-ot-soc-lab.es.japaneast.azure.elastic-cloud.com:9243'],
#                 basic_auth=basic_auth,
#                 verify_certs=True,
#                 request_timeout=300)
#             return es_ids
#         else:
#             print("Unknown User details provided: ", es_user_name)
#     except Exception as e:
#         print(
#             "Got error in ysoc_connect_es function with error:%s.", e)

# # Function to read Excel data into a DataFrame


# def read_excel_file(file_path):
#     df = pd.read_excel(file_path)
#     df = df.where(pd.notnull(df), None)
#     return df

# # Function to convert DataFrame to a list of dictionaries


# def df_to_dicts(df):
#     return df.to_dict(orient='records')

# # Function to index data into Elasticsearch


# def index_data(es, index_name, data):
#     actions = [
#         {
#             "_index": index_name,
#             "_source": record
#         }
#         for record in data
#     ]
#     bulk(es, actions)


# def main():
#     ysoc_secrets = {'ysoc_pcap_analysis_script': {'elastic_creds': {
#         'pcap_script_execution': 'pcap6734ysoc'}}}
#     # Path to your Excel file
#     excel_file_path = 'C:/Users/464P0459/OneDrive - Yokogawa Electric Corporation/D-Drive/YIL/Python/AIML/YSOC/YSOC_Threat_Intelligence_AIML/Excel_of_raw_data - Copy (2).xlsx'

#     # Elasticsearch index name
#     es_index_name = 'yokogawa-cti-ai-automation'

#     # Create Elasticsearch client
#     es = ysoc_connect_es()

#     # Read data from Excel file
#     df = read_excel_file(excel_file_path)

#     # Convert DataFrame to a list of dictionaries
#     data = df_to_dicts(df)

#     # Index data into Elasticsearch
#     index_data(es, es_index_name, data)

#     print("Data indexed successfully.")


# if __name__ == "__main__":
#     main()

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument('window-size=1920x1080')
chrome_options.add_argument("disable-gpu")
driver = webdriver.Chrome(options=chrome_options)

driver.get('http://google.com')
print(driver.title)
driver.implicitly_wait(3)
driver.get_screenshot_as_file('googleHomePage.png')

driver.quit()
