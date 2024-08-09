# os, datetime, subprocess, ysoc_module_path, logger
from ysoc_aiml_threat_intelligence_imports import subprocess, ysoc_module_path, logger, datetime

detection_rules = ['ad_suspicious_event_id_alert', 'ad_alert_acctcreation_4720', 'ad_alert_acctdeleted_4726',
                   'ad_alert_acctlckout_4740', 'ad_alert_replayattck_4649',
                   'ids_alert_events', 'ids_alert_query', 'ids_darkweb',
                   'dns_alert_sslcert', 'dns_alert_suspicious_domain',
                   'mcas_alert_data_exfiltration', 'mcas_alert_impossible_travel_activity',
                   'mcas_alert_multiple_failed_login_attempts', 'mcas_alert_password_spray',
                   'mcas_alert_ransomware_activity', 'mcas_alert_suspicious_inbox_forwarding']
# os.chdir(ysoc_module_path)
# print(ysoc_module_path)
# detection_rules = ['mcas_alert_impossible_travel_activity','mcas_alert_data_exfiltration']
# not active detection rules
'''ids_rdp_alert1', 'ids_rdp_alert', 'ids_mm_vt_snow', 'ids_netsh', 'ep_alert_certutil_event','cisco_asa',
                #    'ep_alert_cred_dumping_process', 'ep_alert_untreated_event', 'atp_alert_untreated_event','''
start_time = datetime.datetime.now()
for dr in detection_rules:  # '"+ysoc_module_path +"
    print("\nScheduler Executing for: ", dr)
    logger.info("Executing from Cron Job :%s", dr)
    # command = 'python {}ysoc_alerts_snow_main.py {},{}'.format(
    #     ysoc_module_path, 'all_YHQ', dr)
    # p = subprocess.Popen(['sudo cd '+ysoc_module_path, f'python ysoc_alerts_snow_main.py all_YHQ,{dr}'],
    p = subprocess.Popen(['python ysoc_alerts_main.py {},{}'.format('all_YHQ', dr)],
                         shell=True,
                         stdin=None,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         close_fds=True)
    out, err = p.communicate()
    # pdb.set_trace()
    if err == b'':
        err = "\n No Error Found while executing from Scheduler\n"
    else:
        pass
    logger.info(f"\nExecuted from Cron Job and result is :\n {out}, \n{err}")
end_time = datetime.datetime.now()
total_time = end_time - start_time
print("\nTotal Time Cosumed to Execute All Detection Rules for All RHQ's is: %s", total_time)
