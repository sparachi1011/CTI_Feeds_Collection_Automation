"""
Created on Mon Jul 22 22:45:45 2024

AUTHOR      : Parachi Sai Koushik,
VERSION     : v1
FileName    : ysoc_aiml_cti_latest_feeds.py
Objective   : -- This python file captures the in latest feeds from various CTI advisories and process them to dump into elastic search DB.
              -- The program has build in a way to complete the cycle of livecapture, process, dump into ES DB then kill the prcocess finally trigger next cycle.

Parameters  :
    INPUT   : log_file_path - accepts the location value to get and update log file.
    OUPUT   : Elastic Search DB Updates with captured and parsed recent Threat Feeds data.

"""
# import platform
# print(platform.python_version())

# import pkg_resources
# installed_packages = pkg_resources.working_set
# print([f"{package.key}=={package.version}" for package in installed_packages])
# import specific Python modules for this file
from ysoc_aiml_threat_intelligence_imports import os, logger, ysoc_secrets, Elasticsearch, helpers, \
    check_file_or_create, requests, time, datetime, random, mp

import re
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument('window-size=1920x1080')
chrome_options.add_argument("disable-gpu")


def get_cisa_feeds():
    try:
        cisa_100 = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=&field_date_added_wrapper=all&sort_by=field_date_added&items_per_page=100&url="
        page_100 = requests.get(cisa_100)
        soup_100 = BeautifulSoup(page_100.content, "html.parser")
        cisa_top_100 = soup_100.find_all(string=re.compile("^CVE-"))[:10]

        cisa_latest_feeds = []

        for one_out in cisa_top_100:
            time.sleep(5)
            cisa_top_100_details = {}
            cisa_top_100_details |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}
            driver = webdriver.Chrome(options=chrome_options)
            cve_site = "https://nvd.nist.gov/vuln/detail/" + str(one_out)
            try:
                driver.get(cve_site)
                driver.implicitly_wait(10)
                web_site_content = requests.get(cve_site)  # , verify=False)
                web_site_content = BeautifulSoup(
                    web_site_content.content, "html.parser")
                web_site_content_text = str(web_site_content.get_text())
                cisa_top_100_details |= {
                    "Feed_Collected_From": "CISA"}
                cisa_top_100_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                cisa_top_100_details |= {
                    "Feed_Collected_Webcontent": web_site_content_text}
                print("- The CISA News Feed Collected for - \n"+str(one_out)+"\n")
                driver.quit()

            except Exception as e:
                cisa_top_100_details |= {
                    "Feed_Collected_From": "CISA"}
                cisa_top_100_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                cisa_top_100_details |= {
                    "Feed_Collected_Webcontent": "Unable to Fetch Feeds from CISA Advisory."}
            if len(cisa_top_100_details) != 0:
                cisa_latest_feeds.append(cisa_top_100_details)

        return cisa_latest_feeds
    except Exception as e:
        logger.error(
            "Got error in get_cisa_feeds function with error: %s", e)


def get_hacker_news_feeds():
    try:
        latest_hacker_news = "https://feeds.feedburner.com/TheHackersNews"
        latest_hacker_news_page = requests.get(latest_hacker_news)
        latest_hacker_news_links = list(set([link[1] for link in re.findall(
            r'(<link>(.*?)</link>)', latest_hacker_news_page.text)][1:]))[:10]
        hacker_news_latest_feeds = []
        for one_out in latest_hacker_news_links:
            time.sleep(5)
            hacker_news_top_50_details = {}
            hacker_news_top_50_details |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}
            driver = webdriver.Chrome(options=chrome_options)
            try:
                driver.get(one_out)
                driver.implicitly_wait(10)
                web_site_content = requests.get(one_out)  # , verify=False)
                web_site_content = BeautifulSoup(
                    web_site_content.content, "html.parser")
                web_site_content_text = str(web_site_content.get_text())
                hacker_news_top_50_details |= {
                    "Feed_Collected_From": "Hacker News"}
                hacker_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                hacker_news_top_50_details |= {
                    "Feed_Collected_Webcontent": web_site_content_text}
                print("- The Hacker News Feed Collected for - \n"+str(one_out)+"\n")
                driver.quit()
            except Exception as e:
                hacker_news_top_50_details |= {
                    "Feed_Collected_From": "Hacker News"}
                hacker_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                hacker_news_top_50_details |= {
                    "Feed_Collected_Webcontent": "Unable to Fetch Feeds from Hacker News."}
            if len(hacker_news_top_50_details) != 0:
                hacker_news_latest_feeds.append(hacker_news_top_50_details)
        return hacker_news_latest_feeds
    except Exception as e:
        logger.error(
            "Got error in get_hacker_news_feeds function with error: %s", e)


def get_rewterz_feeds():
    try:
        latest_rewterz_news = "https://www.rewterz.com/threat-advisory"
        page_100 = requests.get(latest_rewterz_news)
        soup_100 = BeautifulSoup(page_100.content, "html.parser")
        rewterz_top_100 = list(set(soup_100.find_all(href=True)))[:10]
        rewterz_latest_100 = []
        for link in rewterz_top_100:
            latest = str(link).split(" ")[1].split('="')[
                1].replace('"', "").split(">")[0]
            if "https://www.rewterz.com/threat-advisory/" in latest:
                rewterz_latest_100.append(latest)

        # latest_rewterz_news_page = requests.get(latest_rewterz_news)
        # latest_rewterz_news_links = [link[1] for link in re.findall(
        #     r'(<href>(.*?)</href>)', latest_rewterz_news_page.text)][1:]

        rewterz_news_latest_feeds = []
        for one_out in rewterz_latest_100:
            time.sleep(5)
            rewterz_news_top_50_details = {}
            rewterz_news_top_50_details |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}
            driver = webdriver.Chrome(options=chrome_options)
            try:
                driver.get(one_out)
                driver.implicitly_wait(10)
                web_site_content = requests.get(one_out)  # , verify=False)
                web_site_content = BeautifulSoup(
                    web_site_content.content, "html.parser")
                web_site_content_text = str(web_site_content.get_text())
                rewterz_news_top_50_details |= {
                    "Feed_Collected_From": "Rewterz"}
                rewterz_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                rewterz_news_top_50_details |= {
                    "Feed_Collected_Webcontent": web_site_content_text}
                print("- The Rewterz News Feed Collected for - \n"+str(one_out)+"\n")
                driver.quit()
            except Exception as e:
                rewterz_news_top_50_details |= {
                    "Feed_Collected_From": "Rewterz"}
                rewterz_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                rewterz_news_top_50_details |= {
                    "Feed_Collected_Webcontent": "Unable to Fetch Feeds from Rewterz."}
            if len(rewterz_news_top_50_details) != 0:
                rewterz_news_latest_feeds.append(rewterz_news_top_50_details)
        return rewterz_news_latest_feeds
    except Exception as e:
        logger.error(
            "Got error in get_rewterz_feeds function with error: %s", e)


def get_securonix_feeds():
    try:
        # "https://www.securonix.com/securonix-threat-research-lab/"

        latest_securonix_news = "https://www.securonix.com/full-ats-listing/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36', }
        # "Accept-Language": "en-US,en;q=0.5"}
        page_100 = requests.get(latest_securonix_news,
                                headers=headers, verify=False)
        # list(set([link[1] for link in re.findall(
        #     r'(<link>(.*?)</link>)', latest_securonix_news.text)][1:]))
        soup_100 = BeautifulSoup(page_100.content, "html.parser")
        securonix_top_100 = list(set(soup_100.find_all(href=True)))
        securonix_latest_100 = []
        excluded_hrefs = ["https://www.securonix.com/", "https://dev.visualwebsiteoptimizer.com",
                          "//static.", "//cdnjs.", "http://gmpg.org", "securonix",
                          "//fonts.", "Hover", "button", "menu-item-inner", 'false',]
        for link in securonix_top_100:
            latest = str(link).split(" ")[1].split('="')[
                1].replace('"', "").split(">")[0]

            if any(keyword.lower() in latest.lower() for keyword in excluded_hrefs):
                pass
            else:
                securonix_latest_100.append(latest)

        # latest_rewterz_news_page = requests.get(latest_rewterz_news)
        # latest_rewterz_news_links = [link[1] for link in re.findall(
        #     r'(<href>(.*?)</href>)', latest_rewterz_news_page.text)][1:]

        securonix_latest_100 = list(set(securonix_latest_100[:100]))[:10]
        headers |= {"Accept-Language": "en-US,en;q=0.5"}
        securonix_news_latest_feeds = []
        for one_out in securonix_latest_100:
            time.sleep(5)
            securonix_news_top_50_details = {}
            securonix_news_top_50_details |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}
            driver = webdriver.Chrome(options=chrome_options)
            try:
                driver.get(one_out)
                driver.implicitly_wait(10)
                web_site_content = requests.get(
                    one_out, headers=headers, verify=False, timeout=60)  # , verify=False)
                web_site_content = BeautifulSoup(
                    web_site_content.content, "html.parser")
                web_site_content_text = str(web_site_content.get_text())
                securonix_news_top_50_details |= {
                    "Feed_Collected_From": "Securonix"}
                securonix_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                securonix_news_top_50_details |= {
                    "Feed_Collected_Webcontent": web_site_content_text}
                print("- The Securonix News Feed Collected for - \n" +
                      str(one_out)+"\n")
                driver.quit()
            except Exception as e:
                securonix_news_top_50_details |= {
                    "Feed_Collected_From": "Securonix"}
                securonix_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                securonix_news_top_50_details |= {
                    "Feed_Collected_Webcontent": "Unable to Fetch Feeds from Securonix."}
            if len(securonix_news_top_50_details) != 0:
                securonix_news_latest_feeds.append(
                    securonix_news_top_50_details)
        return securonix_news_latest_feeds
    except Exception as e:
        logger.error(
            "Got error in get_securonix_feeds function with error: %s", e)


def get_fortinet_feeds():
    try:
        # ?data-loadmore-enabled='true'&data-loadmore-pagesize='100'&data-loadmore-path='/content/fortinet-blog/us/en/threat-research/jcr:content/root/bloglist'"
        latest_fortinet_news = "https://www.fortinet.com/blog/threat-research"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36', }
        # "Accept-Language": "en-US,en;q=0.5"}
        page_100 = requests.get(latest_fortinet_news,
                                headers=headers, verify=False)
        # "lxml")#"html.parser")
        soup_100 = BeautifulSoup(page_100.content, "html.parser")
        fortinet_top_100 = soup_100.find_all(href=True)
        # 'a', attrs={"class": ["category-threat-research"]}, href=True)
        fortinet_latest_100 = []
        excluded_hrefs = ["/etc", "fortinet", "#", "script", "list-item", "copyright", "category-threat-research",
                          "//fonts.", "Hover", "button", "menu-item-inner", 'false', "search?author"]
        for link in fortinet_top_100:
            latest = str(link).split(" ")[1].split('="')[
                1].replace('"', "").split(">")[0]

            if any(keyword.lower() in latest.lower() for keyword in excluded_hrefs):
                pass
            else:
                fortinet_latest_100.append(latest)

        fortinet_latest_100 = list(set(fortinet_latest_100[:100]))[:10]
        headers |= {"Accept-Language": "en-US,en;q=0.5"}
        fortinet_news_latest_feeds = []
        for one_out in fortinet_latest_100:
            time.sleep(5)
            fortinet_news_top_50_details = {}
            fortinet_news_top_50_details |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}
            one_out = latest_fortinet_news.split("/blog")[0]+one_out
            driver = webdriver.Chrome(options=chrome_options)
            try:
                driver.get(one_out)
                driver.implicitly_wait(10)
                web_site_content = requests.get(
                    one_out, headers=headers, verify=False, timeout=60)  # , verify=False)
                web_site_content = BeautifulSoup(
                    web_site_content.content, "html.parser")
                web_site_content_text = str(web_site_content.get_text())
                fortinet_news_top_50_details |= {
                    "Feed_Collected_From": "Fortinet"}
                fortinet_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                fortinet_news_top_50_details |= {
                    "Feed_Collected_Webcontent": web_site_content_text}
                print("- The Fortinet News Feed Collected for - \n" +
                      str(one_out)+"\n")
                driver.quit()
            except Exception as e:
                fortinet_news_top_50_details |= {
                    "Feed_Collected_From": "Fortinet"}
                fortinet_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                fortinet_news_top_50_details |= {
                    "Feed_Collected_Webcontent": "Unable to Fetch Feeds from Fortinet."}
            if len(fortinet_news_top_50_details) != 0:
                fortinet_news_latest_feeds.append(fortinet_news_top_50_details)
        return fortinet_news_latest_feeds
    except Exception as e:
        logger.error(
            "Got error in get_fortinet_feeds function with error: %s", e)


def get_certin_feeds():
    try:
        # ?data-loadmore-enabled='true'&data-loadmore-pagesize='100'&data-loadmore-path='/content/fortinet-blog/us/en/threat-research/jcr:content/root/bloglist'"
        latest_certin_news = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBWEL01"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36', }
        # "Accept-Language": "en-US,en;q=0.5"}
        page_100 = requests.get(latest_certin_news,
                                headers=headers, verify=False)
        # "lxml")#"html.parser")
        soup_100 = BeautifulSoup(page_100.content, "html.parser")
        certin_top_100 = list(set(soup_100.find_all(href=True)))
        # 'a', attrs={"class": ["category-threat-research"]}, href=True)
        certin_latest_100 = []
        included_hrefs = ["VLCODE=", "VACODE="]
        excluded_hrefs = ["/etc", "certin", "#",  "tenderlist", "presslist", "vlnlistpp", "VLNLISTSI",
                          "VLNLISTRE", "submail001", "javascript:call",  "/favicon", "style", "sitemap",
                          "script", "list-item", "copyright", "category-threat-research",  ".jsp", ".jpg",
                          "//fonts.", "Hover", "button", "menu-item-inner", 'false', "search?author", "TERMSOFUSE",
                          "/PDF/", "PUBADVLIST", "https://"]
        for link in certin_top_100:
            latest = str(link).split(" ")[1].split('="')[
                1].replace('"', "").split(">")[0]

            if any(keyword.lower() in latest.lower() for keyword in included_hrefs):
                # pass
                certin_latest_100.append(latest.replace("&amp;", "&"))
            else:
                # certin_latest_100.append(latest)
                pass

        certin_latest_100 = list(set(certin_latest_100[:100]))[:10]
        headers |= {"Accept-Language": "en-US,en;q=0.5"}
        certin_news_latest_feeds = []
        for one_out in certin_latest_100:
            time.sleep(5)
            certin_news_top_50_details = {}
            certin_news_top_50_details |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}
            one_out = latest_certin_news.split(
                "/s2")[0]+"/"+one_out  # one_out
            driver = webdriver.Chrome(options=chrome_options)
            try:
                driver.get(one_out)
                driver.implicitly_wait(10)
                web_site_content = requests.get(
                    one_out, headers=headers, verify=False, timeout=60)  # , verify=False)
                web_site_content = BeautifulSoup(
                    web_site_content.content, "html.parser")
                web_site_content_text = str(web_site_content.get_text())
                certin_news_top_50_details |= {
                    "Feed_Collected_From": "Cert-In"}
                certin_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                certin_news_top_50_details |= {
                    "Feed_Collected_Webcontent": web_site_content_text}
                print("- The Cert-In News Feed Collected for - \n"+str(one_out)+"\n")
                driver.quit()
            except Exception as e:
                certin_news_top_50_details |= {
                    "Feed_Collected_From": "Cert-In"}
                certin_news_top_50_details |= {
                    "Feed_Collected_Weblink": str(one_out)}
                certin_news_top_50_details |= {
                    "Feed_Collected_Webcontent": "Unable to Fetch Feeds from Cert-In."}
            if len(certin_news_top_50_details) != 0:
                certin_news_latest_feeds.append(certin_news_top_50_details)
        return certin_news_latest_feeds
    except Exception as e:
        logger.error(
            "Got error in get_certin_feeds function with error: %s", e)


def ysoc_connect_es():
    try:
        # Elasticsearch account information
        es_user_name = list(
            ysoc_secrets['ysoc_pcap_analysis_script']['elastic_creds'].keys())[0]
        es_user_pswd = ysoc_secrets['ysoc_pcap_analysis_script']['elastic_creds'][es_user_name]

        if es_user_name == 'pcap_script_execution':
            basic_auth = (
                es_user_name, es_user_pswd)
            es_ids = Elasticsearch(
                # ['https://060652a6cf6c4ef0b5fbc3362216e5d4.japaneast.azure.elastic-cloud.com:443'],
                # ['https://060652a6cf6c4ef0b5fbc3362216e5d4.japaneast.azure.elastic-cloud.com:443'],
                ['https://it-ot-soc-lab.es.japaneast.azure.elastic-cloud.com:9243'],
                basic_auth=basic_auth,
                verify_certs=True,
                request_timeout=300)
            return es_ids
        else:
            logger.info("Unknown User details provided: ", es_user_name)
    except Exception as e:
        logger.error(
            "Got error in ysoc_connect_es function with error:%s.", e)


def ysoc_update_es_cti_aiml_index(cti_feeds_collect):
    """
    This Function connects to Elastic Search and update cti_aiml Analysis Index.
    Parameters
    ----------
    processed_cti_aiml_df: DataFrame Object.
        DESCRIPTION: Holds the processed log details those can be used to update cti_aiml Index to create Kibana Dashboards.
    conn_es: Generator Object.
        DESCRIPTION: Elastic Connection Object
    Returns
    -------
    status: String Object.
    DESCRIPTION: Holds the end to end Automation status.
    """
    try:
        start_time = datetime.datetime.now()
        print("\nStart of MultiProcess(PID - {}) Execution Mode at {} for Process: {} ".format(
            os.getpid(), datetime.datetime.now(), cti_feeds_collect))
        logger.info(
            "Start of MultiProcess(PID - {}) Execution Mode at {} for Process: {} ".format(
                os.getpid(), datetime.datetime.now(), cti_feeds_collect))
        dump_into_elastic = eval(cti_feeds_collect)
        index_doc_mapper = [
            {"_index": 'yokogawa-itotsoc-cti-feeds-aiml',
             "_source": doc
             }
            for doc in dump_into_elastic]
        # print(dump_into_elastic)
        conn_es = ysoc_connect_es()
        success, failed = helpers.bulk(conn_es, index_doc_mapper)
        status = 'success'

        if success < len(index_doc_mapper):
            success, failed = helpers.bulk(conn_es, index_doc_mapper)

            status = "success"

            if failed != 0:
                sub_path = 'ysoc_cti_aiml_analysis_unprocessed_data/ysoc_cti_aiml_analysis_unprocessed_data_'
                unproc_cti_aiml_file_name = check_file_or_create(sub_path)
                with open(unproc_cti_aiml_file_name, "a") as unproc_cti_aiml_file:
                    unproc_cti_aiml_file.writelines(str(index_doc_mapper))

                status = 'failed'
        if status == 'success':
            print(
                "\nCycle - STAGE: The Recent feeds of " + cti_feeds_collect.split("()")[0].split("get_")[1].split("_")[0].upper() + " were Dumped into ES Index..Success Count : " + str(success) + " Failed Count : " + str(failed))
            logger.info("Cycle - STAGE: The Recent feeds of " + cti_feeds_collect.split("()")[0].split("get_")[1].split("_")[0].upper() + " were Dumped into ES Index..Success Count : " +
                        str(success) + " Failed Count : " + str(failed))
        else:
            print(
                "\nCycle - STAGE: The Recent feeds of " + cti_feeds_collect.split("()")[0].split("get_")[1].split("_")[0].upper() + " were Dumped into physical file..Success Count : " + str(success) + " Failed Count : " + str(failed))
            logger.info("Cycle - STAGE: The Recent feeds of " + cti_feeds_collect.split("()")[0].split("get_")[1].split("_")[0].upper() + " were Dumped into physical file ..Success Count : " +
                        str(success) + " Failed Count : " + str(failed))

        end_time = datetime.datetime.now()
        difference = end_time - start_time
        print("\nEnd of MultiProcess(Custome PID - {}) Execution Mode for Process {} and Total Time Consumed : {}".format(
            os.getpid(), cti_feeds_collect, difference))
        logger.info(
            "End of MultiProcess(Custome PID - {}) Execution Mode: at {} for Process {} and total time consumed {} ".format(
                os.getpid(), datetime.datetime.now(), difference))

        # return status
    except Exception as e:
        logger.error(
            "Got error in ysoc_update_es_cti_aiml_index function with error: %s", e)


def ysoc_cti_feeds_capturing_multiprocessing_management(list_news_feeds):
    try:
        mp_pool = mp.Pool(len(list_news_feeds))
        # for get_feed in list_news_feeds:
        mp_pool.map(ysoc_update_es_cti_aiml_index, list_news_feeds)
        # [mp_pool.map(ysoc_update_es_cti_aiml_index,get_feed) for get_feed in list_news_feeds]
        # def multiprocessing(mp_id, news_feeds):
        #     mp_id = mp.Process(
        #         target=ysoc_update_es_cti_aiml_index, args=(news_feeds,))
        #     mp_id.start()
        #     mp_id.join()
        # mp_id = format(random.randint(0, 999999), "06d")

        # for news_feeds in list_news_feeds:
        #     start_time = datetime.datetime.now()
        #     print("\nStart of MultiProcess(Custome PID - {}) Execution Mode at {} for Process: {} ".format(
        #         mp_id, datetime.datetime.now(), news_feeds))
        #     logger.info(
        #         "Start of MultiProcess(Custome PID - {}) Execution Mode at {} for Process: {} ".format(
        #             mp_id, datetime.datetime.now(), news_feeds))

        #     multiprocessing(mp_id, news_feeds)

        #     end_time = datetime.datetime.now()
        #     difference = end_time - start_time
        #     print("\nEnd of MultiProcess(Custome PID - {}) Execution Mode for Process {} and Total Time Consumed : {}".format(
        #         mp_id, news_feeds, difference))
        #     logger.info(
        #         "End of MultiProcess(Custome PID - {}) Execution Mode: at {} for Process {} and total time consumed {} ".format(
        #             mp_id, datetime.datetime.now(), difference))
        #     mp_id = int(mp_id)+1

        # return True

    except Exception as e:
        logger.error(
            "Got error in ysoc_cti_feeds_capturing_multiprocessing_management function with error: %s", e)


def main():  # last_execution_sussess):
    """
    This Function will trigger end to end automation process. 
    Parameters
    ----------
    None.

    Returns
    -------
    None.
    """
    try:
        # # list_news_feeds = ["get_certin_feeds()"]
        list_news_feeds = ['get_cisa_feeds()', 'get_hacker_news_feeds()', 'get_rewterz_feeds()',
                           'get_securonix_feeds()', 'get_fortinet_feeds()', 'get_certin_feeds()']

        ysoc_cti_feeds_capturing_multiprocessing_management(list_news_feeds)

    except Exception as e:
        logger.error("Got error in main function with error:%s.",
                     e, exc_info=False)


if __name__ == '__main__':

    main()
