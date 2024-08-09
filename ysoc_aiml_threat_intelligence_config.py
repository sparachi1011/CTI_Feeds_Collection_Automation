livecapture_req_fields = {"ETH Layer": {"Source_MAC_Address": ["eth.src"], "Destination_MAC_Address": ["eth.dst"],
                                        "IP_Type": ["eth.type"], "MAC_OUI_Address": ["eth.addr.oui_resolved"],
                                        "Source_OUI_Resolver": ["eth.src.oui.resolved"], "Destination_OUI_Resolver": ["eth.sdt.oui.resolved"], },

                          "IP Layer": {"IP_Version": ["ip.version"], "IP_Protocol": ["ip.proto"],
                                       "IP_Source_Address": ["ip.src"], "IP_Destination_Address": ["ip.dst"], "IP_Source_Address": ["ip.src"],
                                       "IP_Source_Host": ["ip.src_host"], "IP_Destination_Host": ["ip.dst_host"],
                                       "IP_TimeToLive": ["ip.ttl"], "IP_Length": ["ip.len"], "IP_ID": ["ip.id"], "IP_Flags": ["ip.flags"],
                                       "IP_Checksum": ["ip.checksum"], "IP_Checksum_Status": ["ip.checksum_status", "ip.checksum.status"],
                                       "IP_Fragment_Offset": ["ip.frag.offset", "ip.frag_offset"], "IP_dsfield": ["ip.dsdield"],
                                       "IP_DS_Field_Description": ["ip.dsfield.dscp", "ip.dsfield_dscp"], "IP_DS_Field_Encryption": ["ip.dsfield.enc", "ip.dsfield_enc"], },

                          "IPV6 Layer": {"IPV6_Source_Address": ["ipv6.src"], "IPV6_Destination_Address": ["ipv6.dst"],
                                         "IPV6_Version": ["ipv6.version"], "IPV6_TClass": ["ipv6.tclass"], "IPV6_Flow": ["ipv6.flow"], "IPV6_Plen": ["ipv6.plen"],
                                         "IPV6_Next": ["ipv6.nxt"], "IPV6_Hlim": ["ipv6.hlim"], "IPV6_Source_Embeded_IPV4": ["ipv6.src_embeded_ipv4"], "IPV6_Destination_Embeded_IPV4": ["ipv6.dst_embeded_ipv4"], },

                          "ICMPV6 Layer": {"ICMPV6_Type": ["icmpv6.type"], "ICMPV6_Code": ["icmpv6.code", ],
                                           "ICMPV6_Checksum": ["ICMPV6.checksum"], "ICMPV6_Checksum_Status": ["ICMPV6.checksum.status"], "ICMPV6_Nd_Ns_Target_Address": ["ICMPV6.nd.ns.target_address"], "IPV6_Plen": ["ipv6.plen"],
                                           "ICMPV6_Opt": ["ICMPV6.opt"], "ICMPV6_Opt_Type": ["ICMPV6.opt.type"], "ICMPV6_Opt_Length": ["ICMPV6.opt.length"], "ICMPV6_Opt_Link_Address": ["ICMPV6.opt.linkaddress"],
                                           "ICMPV6_Opt_Source_Link_Address": ["ICMPV6.opt.src_linkaddr"]},

                          "TCP Layer": {"TCP_Source_Port": ["tcp.srcport"], "TCP_Destination_Port": ["tcp.dstport"],
                                        "TCP_Sequence_Number": ["tcp.seq"], "TCP_Acknowledgement_Number": ["tcp.ack"], "TCP_Flags": ["tcp.flags"], "TCP_Flags_Acknowledgement": ["tcp.flags.ack"],
                                        "TCP_Flags_Fin": ["tcp.flags.fin"], "TCP_Length": ["tcp.len"], "TCP_Header_Length": ["tcp.hdr_len"], "TCP_Window_Size_Value": ["tcp.window_size_value"],
                                        "TCP_Checksum": ["tcp.checksum"], "TCP_Checksum_Status": ["tcp.checksum.status"], "TCP_Urgent_Pointer": ["tcp.urgent_pointer"], "TCP_Connection_Fin": ["tcp.connection.fin"],
                                        "TCP_Connection_Fin_Active": ["tcp.connection.fin_active"], "TCP_Time_Relative": ["tcp.time_relative"], "TCP_Time_Delta": ["tcp.time_delta"], "TCP_Analysis_Retransmission": ["tcp.analysis.retransmission"],
                                        "TCP_Analysis_RTO": ["tcp.analysis.rto"]},

                          "UDP Layer": {"UDP_Source_Port": ["udp.srcport"], "UDP_Destination_Port": ["udp.dstport"], "UDP_Length": ["udp.length"],
                                        "UDP_Checksum": ["udp.checksum"], "UDP_Checksum_Status": ["udp.checksum.status"], "UDP_Payload": ["udp.payload"],
                                        "UDP_Time_Relative": ["udp.time_relative"], "udP_Time_Delta": ["udp.time_delta"]},

                          "DTLS Layer": {"DTLS_Record": ["dtls.record"], "DTLS_Record_Content_Type": ["dtls.record.content_type"], "DTLS_Record_Version": ["dtls.record.version"], "DTLS_Record_Epoch": ["dtls.record.epoch"],
                                         "DTLS_Record_Sequence_Number": ["dtls.record.sequence_number"], "DTLS_Record_Length": ["dtls.record.length"], "DTLS_App_Data": ["dtls.app_data"], },

                          "HTTP Layer": {"HTTP_Request_Method": ["http.request.method"], "HTTP_Request_URI": ["http.request.uri"], "HTTP_Request_Version": ["http.request.version"], "HTTP_Request_Full_URI": ["http.request.full_rui"],
                                         "HTTP_Request": ["http.request"], "HTTP_Request_Number": ["http.request_number"], "HTTP_Response_Version": ["http.response.version"], "HTTP_Response_Code": ["http.response.code"],
                                         "HTTP_Response_Code_Description": ["http.response.code.desc"], "HTTP_Response_Line": ["http.response.line"], "HTTP_Request_In": ["http.request_in"], "HTTP_Response_For_URI": ["http.response_for.uri"],
                                         "HTTP_Host": ["http.host"], "HTTP_User_Agent": ["http.user_agent"], "HTTP_Connection": ["http.connection"], "HTTP_Server": ["http.server"], "HTTP_Cache_Control": ["http.cache_control"],
                                         "HTTP_Content_Length_Header": ["http.content_length_header"], "HTTP_Content_Type": ["http.content_type"], "HTTP_File_Data": ["http.file_data"], "HTTP_Time": ["http.time"], "HTTP_TLS_Port": ["http.tls_port"],
                                         "HTTP_URL_Encoded_From_Key": ["http.urlencoded-from.key"], "HTTP_URL_Encoded_From_Value": ["http.urlencoded-from.value"], },

                          "TLS Layer": {"TLS_Handshake_Type": ["tls.handshake.type"], "TLS_Handshake_Version": ["tls.handshake.version"], "TLS_Handshake_Random": ["tls.handshake.random"], "TLS_Handshake_Random_Time": ["tls.handshake.random_time"],
                                        "TLS_Handshake_Extension_Type": ["tls.handshake.extension_type"], "TLS_Handshake_Extensions_Length": ["tls.handshake.extensions_length"], "TLS_Handshake_Extension_Data": ["tls.handshake.extension.data"],
                                        "TLS_Handshake_Session_ID": ["tls.handshake.session_id"], "TLS_Handshake_Session_ID_Length": ["tls.handshake.session_id_length"],
                                        "TLS_Handshake_Ciphersuite": ["tls.handshake.ciphersuite"], "TLS_Handshake_Ciphersuites_Length": ["tls.handshake.ciphersuites_length"],
                                        "TLS_Handshake_Comp_Method": ["tls.handshake.comp_method"], "TLS_Handshake_Comp_Methods_Length": ["tls.handshake.comp_methods_length"],
                                        "TLS_Handshake_Sig_Hash_Alg": ["tls.handshake.sig_hash_alg"], "TLS_Handshake_Sig_Hash_Alg_Length": ["tls.handshake.sig_hash_alg_length"],
                                        "TLS_Handshake_Extensions_Server_Name": ["tls.handshake.extensions_server_name"], "TLS_Handshake_Extensions_Server_Name_List_Length": ["tls.handshake.extensions_server_name_list_len"],
                                        "TLS_Handshake_Certificate": ["tls.handshake.certificate"], "TLS_Handshake_Certificates_Length": ["tls.handshake.certificates_length"],
                                        "TLS_Handshake_Sig_Hash_Hash": ["tls.handshake.sig_hash_hash"], "TLS_Handshake_Sig_Hash_Sig": ["tls.handshake.sig_hash_sig"],
                                        "TLS_Handshake_Extensions_Alpn_List": ["tls.handshake.extensions_alpn_list"], "TLS_Handshake_Extensions_Alpn_String": ["tls.handshake.extensions_alpn_str"],
                                        "TLS_Handshake_Extensions_Key_Share_Group": ["tls.handshake.extensions_key_share_group"], },

                          "DNS Layer": {"DNS_ID": ["dns.id"], "DNS_Flags_Opcode": ["dns.flags.opcode"], "DNS_Flags_Truncated": ["dns.flags.truncated"], "DNS_Flags_Recdesired": ["dns.flags.recdesired"],
                                        "DNS_Flags_Authoritative": ["dns.flags.authoritative"], "DNS_Flags_Recavail": ["dns.flags.recavail"], "DNS_Flags_Rcode": ["dns.flags.rcode"], "DNS_Count_Queries": ["dns.count.queries"], "DNS_Count_Answers": ["dns.count.answers"],
                                        "DNS_Query_Name": ["dns.query.name"], "DNS_Query_Type": ["dns.query.type"], "DNS_Query_Class": ["dns.query.class"], "DNS_Response_Name": ["dns.resp.name"], "DNS_Response_Type": ["dns.resp.type"], "DNS_Response_Class": ["dns.resp.class"],
                                        "DNS_Response_TimeToLive": ["dns.resp.ttl"], "DNS_A": ["dns.a"], "DNS_Aaaa": ["dns.aaaa"], "DNS_Time": ["dns.resp.time"], },

                          "ARP Layer": {"ARP_HW_Type": ["arp.hw.type"], "ARP_HW_Size": ["arp.hw.size"], "ARP_Proto_Type": ["arp.proto.type"], "ARP_Proto_Size": ["arp.proto.size"],
                                        "ARP_Opcode": ["arp.opcode"], "ARP_Source_HW_MAC": ["arp.src.hw_mac"], "ARP_Source_Proto_IPV4": ["arp.src.proto_ipv4"],
                                        "ARP_Destination_HW_MAC": ["arp.dst.hw_mac"], "ARP_Destination_Proto_IPV4": ["arp.dst.proto_ipv4"], },

                          "STP Layer": {"STP_Protocol": ["stp.protocol"], "STP_Version": ["stp.version"], "STP_Type": ["stp.type"], "STP_Flags": ["stp.flags"],
                                        "STP_Root_Prio": ["stp.root.prio"], "STP_Root_HW": ["stp.root.hw"], "STP_Root_Cost": ["stp.root.cost"], "STP_Bridge_Prio": ["stp.bridge.prio"], "STP_Bridge_HW": ["stp.bridge.hw"],
                                        "STP_Port": ["stp.port"], "STP_Message_Age": ["stp.msg_age"], "STP_Maximum_Age": ["stp.max_age"], "STP_Hello": ["stp.hello"], "STP_Forward": ["stp.forward"], },

                          "DHCP Layer": {"DHCP_ID": ["dhcp.id"], "DHCP_Type": ["dhcp.type"], "DHCP_HW_Type": ["dhcp.hw.type"], "DHCP_Flags": ["dhcp.flags"], "DHCP_Flags_BC": ["dhcp.flags.bc"], "DHCP_IP_Client": ["dhcp.ip.client"], "DHCP_HW_MAC_Address": ["dhcp.hw.mac_addr"],
                                         "DHCP_Cookie": ["dhcp.cookie"], "DHCP_Option_Type": ["dhcp.option.type"], "DHCP_Option_Value": ["dhcp.option.value"], "DHCP_Option_DHCP": ["dhcp.option.dhcp"], "DHCP_Option_End": ["dhcp.option.end"],
                                         "DHCP_Option_DHCP_Maximum_Message_Size": ["dhcp.option.dhcp_max_message_size"], "DHCP_Option_Request_List_Item": ["dhcp.option.request_list_item"], },

                          "ICMP Layer": {"ICMP_Type": ["icmp.type"], "ICMP_Code": ["icmp.code"], "ICMP_Checksum_Status": ["icmp.checksum.status"], "ICMP_Unused": ["icmp.unused"], "ICMP_Itent": ["icmp.ident"], "ICMP_Itent_Le": ["icmp.ident_le"],
                                         "ICMP_Sequence": ["icmp.seq"], "ICMP_Sequence_Le": ["icmp.seq_le"], "ICMP_Response_To": ["icmp.resp_to"], "ICMP_Response_Time": ["icmp.resptime"], },

                          "LLDP Layer": {"LLDP_TLV_Type": ["lldp.tlv.type"], "LLDP_TLV_Length": ["lldp.tlv.len"], "LLDP_Chassis_Subtype": ["lldp.chassis.subtype"], "LLDP_Chassis_ID_MAC": ["lldp.chassis.id.mac"], "LLDP_Port_ID": ["lldp.port.id"], "LLDP_Port_Subtype": ["lldp.port.subtype"],
                                         "LLDP_Timetolive": ["lldp.time_to_live"], "LLDP_Port_Description": ["lldp.port.desc"], "LLDP_TLV_System_Name": ["lldp.tlv.system.name"], "LLDP_TLV_System_Description": ["lldp.tlv.system.desc"], "LLDP_TLV_System_Cap_Bridge": ["lldp.tlv.system_cap.bridge"],
                                         "LLDP_TLV_System_Cap_Router": ["lldp.tlv.system_cap.router"], "LLDP_MGN_Address_IPV4": ["lldp.mgn.addr.ipv4"], "LLDP_MGN_Interface_Number": ["lldp.mgn.Interface.Number"], },

                          "DCERPC Layer": {"DCERPC_Ver": ["dcerpc.ver"], "DCERPC_Ver_Minor": ["dcerpc.ver_minor"], "DCERPC_Packet_Type": ["dcerpc.pkt_type"], "DCERPC_CN_Flags": ["dcerpc.cn_flags"], "DCERPC_CN_Flags_Object": ["dcerpc.cn_flags.object"],
                                           "DCERPC_CN_Flags_First_Fragment": ["dcerpc.cn_flags.first_frag"], "DCERPC_CN_Flags_Last_Fragment": ["dcerpc.cn_flags.last_frag"], "DCERPC_Packet_Drep": ["dcerpc.drep"], "DCERPC_Packet_Drep_Byteorder": ["dcerpc.drep.byteorder"],
                                           "DCERPC_CN_Fragment_Length": ["dcerpc.cn_frag_len"], "DCERPC_CN_Auth_Length": ["dcerpc.cn_auth_len"], "DCERPC_CN_Call_ID": ["dcerpc.cn_call_id"], "DCERPC_CN_Maximum_Xmit": ["dcerpc.cn_max_xmit"],
                                           "DCERPC_CN_Maximum_Receiver": ["dcerpc.cn_max_recv"], "DCERPC_CN_Associated_Group": ["dcerpc.cn_assoc_group"], "DCERPC_CN_Number_CTX_Items": ["dcerpc.cn_num_ctx_items"], "DCERPC_CN_CTX_Item": ["dcerpc.cn_ctx_item"],
                                           "DCERPC_CN_CTX_ID": ["dcerpc.cn_ctx_id"], "DCERPC_CN_CTX_ID": ["dcerpc.cn_ctx_id"], "DCERPC_CN_Number_Transaction_Items": ["dcerpc.cn_trans_items"], "DCERPC_CN_Bind_Abstract_Syntax": ["dcerpc.cn_bind_abstract_syntax"],
                                           "DCERPC_CN_Bind_To_UUID": ["dcerpc.cn_bind_to_uuid"], "DCERPC_CN_Bind_If_Ver": ["dcerpc.cn_bind_if_ver"], "DCERPC_CN_Bind_If_Ver_Minor": ["dcerpc.cn_bind_if_ver_minor"],  "DCERPC_CN_Bind_Transfer": ["dcerpc.cn_bind_trans"],
                                           "DCERPC_CN_Bind_Transfer_ID": ["dcerpc.cn_bind_trans_id"], "DCERPC_CN_Bind_Transfer_Version": ["dcerpc.cn_bind_trans_ver"], "DCERPC_CN_Bind_Transfer_BTFN": ["dcerpc.cn_bind_trans_btfn"], "DCERPC_CN_Bind_Transfer_BTFN01": ["dcerpc.cn_bind_trans_btfn.01"],
                                           "DCERPC_CN_Bind_Transfer_BTFN02": ["dcerpc.cn_bind_trans_btfn.02"], "DCERPC_Referent_ID64": ["dcerpc.referent_id64"]},

                          "EPM Layer": {"EPM_OP_Number": ["epm.opnum"], "EPM_UUID": ["epm.uuid"], "EPM_UUID_Version": ["epm.uuid_version"], "EPM_Tower_Length": ["epm.tower.len"], "EPM_Tower_Number_Floors": ["epm.tower.num_floors"], "EPM_Tower_LHS_Length": ["epm.tower.lhs.len"], "EPM_Tower_RHS_Length": ["epm.tower.rhs.len"],
                                        "EPM_Tower_Protocol_ID": ["epm.tower.proto_id"], "EPM_Ver_Minimum": ["epm.ver_min"], "EPM_Protocol_TCP_Port": ["epm.proto.tcp_port"], "EPM_Protocol_IP": ["epm.proto.ip"], "EPM_HND": ["epm.hnd"], "EPM_Maximum_Towers": ["epm.max_towers"], },

                          "LSARPC layer": {"LSARPC_Opnum": ["lsarpc.opnum"], },

                          "OCSP": {"OCSP_Responder_ID": ["ocsp.responderID"], "OCSP_Serial_Number": ["ocsp.serialNumber"], "OCSP_Response_Status": ["ocsp.responseStatus"], "OCSP_Certificate_Status": ["ocsp.certStatus"], "OCSP_Produced_At": ["ocsp.producedAt"], },

                          "KERBEROS Layer": {"Kerberos_PV_Number": ["kerberos.pvno"], "Kerberos_Message_Type": ["kerberos.msg_type"], "Kerberos_Till": ["kerberos.till"], "Kerberos_Encrypt_Type": ["kerberos.ENCTYPE"], "Kerberos_Realm": ["kerberos.realm"],
                                             "Kerberos_Sname_String": ["kerberos.SNameString"], "Kerberos_KDC_Request_Body_Encrypt_Type": ["kerberos.kdc-req-body.etype"], },

                          "RPC": {"RPC_XID": ["rpc.xid"], "RPC_Version": ["rpc.version"], "RPC_Message_Type": ["rpc.msgtyp"], "RPC_Program": ["rpc.program"], "RPC_Program_Version": ["rpc.programversion"], "RPC_Procedure": ["rpc.procedure"],
                                  "RPC_Auth_Flavor": ["rpc.auth.flavor"], "RPC_Auth_Length": ["rpc.auth.length"], "RPC_Dup": ["rpc.dup"], },

                          "QUIC Layer": {"QUIC_Version": ["quic.version"], "QUIC_DCIL": ["quic.dcil"], "QUIC_DCID": ["quic.dcid"], "QUIC_SCIL": ["quic.scil"], "QUIC_Token_Length": ["quic.token_length"], "QUIC_Packet_Number": ["quic.pcaket_number"], "QUIC_Header_From": ["quic.header_from"],
                                         "QUIC_Long_Packet_Type": ["quic.long.packet_type"], "QUIC_Long_Reserved": ["quic.long.reserved"], "QUIC_Packet_Number_Length": ["quic.pcaket_number_length"], "QUIC_Length": ["quic.length"], "QUIC_Payload": ["quic.payload"], "QUIC_Frame": ["quic.frame"],
                                         "QUIC_Frame_Type": ["quic.frame_type"], "QUIC_Crypto_Length": ["quic.crypto.length"], "QUIC_Decryption_Failed": ["quic.decryption_failed"], "QUIC_Remaining_Payload": ["quic.remaining_payload"],  "QUIC_Acknowledgement": ["quic.ack"],
                                         "QUIC_Short": ["quic.short"], "QUIC_Spin_Bit": ["quic.spin_bit"], },


                          "LLC Layer": {"LLC_DSAP": ["llc.dsap"], "LLC_DSAP_SAP": ["llc.dsap.sap"], "LLC_DSAP_IG": ["llc.dsap.ig"], "LLC_SSAP": ["llc.ssap"], "LLC_SSAP_SAP": ["llc.ssap.sap"], "LLC_SSAP_CR": ["llc.ssap.cr"],
                                        "LLC_Control": ["llc.control"], "LLC_Control_U_Modifier_Command": ["llc.control.u_modifier_cmd"], "LLC_Control_Ftype": ["llc.control.ftype"], },

                          "IGMP Layer": {"IGMP_Version": ["igmp.version"], "IGMP_Type": ["igmp.type"], "IGMP_Maximum_Response": ["igmp.max_resp"], "IGMP_Checksum": ["igmp.checksum"], "IGMP_Checksum_Status": ["igmp.checksum.status"], "IGMP_Maddr": ["igmp.maddr"], },

                          "NBSS Layer": {"NBSS_Type": ["nbss.type"], "NBSS_Length": ["nbss.lengh"], },

                          "SMB Layer": {"SMB_Server_Component": ["smb.server_component"], "SMB_Command": ["smb.cmd"], "SMB_NT_Status": ["smb.nt_status"], "SMB_Flags": ["smb.flags"], "SMB_Flags_Response": ["smb.flags.response"], "SMB_Flags_Receive_Buffer": ["smb.flags.receive_buffer"],
                                        "SMB_PID": ["smb.pid"], "SMB_PID_High": ["smb.pid.high"], "SMB_UID": ["smb.uid"], "SMB_TID": ["smb.tid"], "SMB_MID": ["smb.mid"], "SMB_WCT": ["smb.wct"], "SMB_BCC": ["smb.bcc"], "SMB_Signature": ["smb.signature"],
                                        "SMB_Reserved": ["smb.reserved"], "SMB_Buffer_Format": ["smb.buffer_format"], "SMB_Dialect_Name": ["smb.dialect.name"], },

                          "SMB2 Layer": {"SMB2_Protocol_ID": ["smb2.protocol_id"], "SMB2_Credit_Charge": ["smb2.credit.charge"], "SMB2_Command": ["smb2.cmd"], "SMB2_NT_Status": ["smb2.nt_status"], "SMB2_Flags": ["smb2.flags"], "SMB2_Dialect": ["smb2.dialect"],
                                         "SMB2_Client_Guid": ["smb2.client_guid"], "SMB2_Server_Guid": ["smb2.server_guid"], "SMB2_Security_Blob": ["smb2.security_blob"], "SMB2_Negotiate_Context": ["smb2.negotiate_context"], "SMB2_Pre_Auth_Hash": ["smb2.preauth_hash"],
                                         "SMB2_Net_Name": ["smb2.netname"], "SMB2_Current_Time": ["smb2.current_time"], "SMB2_Boot_Time": ["smb2.boot_time"], },


                          "NBNS Layer": {"NBNS_ID": ["nbns.id"], "NBNS_Name": ["nbns.name"], "NBNS_Type": ["nbns.type"], "NBNS_Class": ["nbns.class"], "NBNS_TimeToLive": ["nbns.ttl"], "NBNS_Flags": ["nbns.flags"], "NBNS_Flags_Response": ["nbns.flags.response"],
                                         "NBNS_Flags_OPCode": ["nbns.flags.opcode"], "NBNS_Flags_Truncated": ["nbns.flags.truncated"], "NBNS_Flags_Recdesired": ["nbns.flags.recdesired"], "NBNS_Flags_Recavilable": ["nbns.flags.recavail"], "NBNS_Flags_Broadcast": ["nbns.flags.broadcast"],
                                         "NBNS_Flags_Authoritative": ["nbns.flags.authoritative"], "NBNS_Flags_Rcode": ["nbns.flags.rcode"], "NBNS_Count_Queries": ["nbns.count.queries"], "NBNS_Count_Answers": ["nbns.count.answers"], "NBNS_Count_Auth_rr": ["nbns.count.auth_rr"],
                                         "NBNS_Count_Add_rr": ["nbns.count.add_rr"], "NBNS_Data_Length": ["nbns.data_length"], "NBNS_Number_Of_Names": ["nbns.number_of_names"], "NBNS_NetBios_Name": ["nbns.netbios_name"], "NBNS_Name_Flags": ["nbns.name_flags"], "NBNS_Name_Flags_Group": ["nbns.name_flags.group"],
                                         "NBNS_Name_Flags_ONT": ["nbns.name_flags.ont"], "NBNS_Name_Flags_DRG": ["nbns.name_flags.drg"], "NBNS_Name_Flags_CNF": ["nbns.name_flags.cnf"], "NBNS_Name_Flags_ACT": ["nbns.name_flags.act"], "NBNS_Name_Flags_PRM": ["nbns.name_flags.prm"],
                                         "NBNS_Unit_ID": ["nbns.unit_id"], "NBNS_Jumpers": ["nbns.jumpers"], "NBNS_Test_Result": ["nbns.test_result"], "NBNS_Version_Number": ["nbns.version_number"], "NBNS_Period_Of_Statistics": ["nbns.period_of_statistics"], "NBNS_Number_CRCS": ["nbns.num_crcs"],
                                         "NBNS_Number_Alignment_Errors": ["nbns.num_alignment_errors"], "NBNS_Number_Collisions": ["nbns.num_collisions"], "NBNS_Number_Send_Aborts": ["nbns.num_send_aborts"], "NBNS_Number_Good_Sends": ["nbns.num_good_sends"], "NBNS_Number_Good_Receives": ["nbns.num_good_receives"],
                                         "NBNS_Number_Retransmits": ["nbns.numretransmits"], "NBNS_Number_No_Resource_Conditions": ["nbns.num_no_resource_conditions"], "NBNS_Number_Command_Blocks": ["nbns.numcommand_blocks"], "NBNS_Number_Pending_Sessions": ["nbns.numpending_sessions"],
                                         "NBNS_Maximum_Number_Pending_Sessions": ["nbns.max_num_pending_sessions"], "NBNS_Maximum_Total_Sessions_Possible": ["nbns.max_total_sessions_possible"], "NBNS_Session_Data_Packet_Size": ["nbns.msession_data_packet_size"], },

                          "RDP Layer": {"RDP_RT_Cookie": ["rdp.rt_cookie"], "RDP_NEG_Type": ["rdp.neg_type"], "RDP_NEG_Length": ["rdp.neg_length"], "RDP_NEG_Request_Flags": ["rdp.negReq.flags"], "RDP_NEG_Request_Flags_Restricted_Admin_Mode_Request": ["rdp.negReq.flags.restricted_admin_mode_req"],
                                        "RDP_NEG_Request_Flags_Redirected_Auth_Request": ["rdp.negReq.flags.redirected_auth_req"], "RDP_NEG_Request_Flags_Correlation_Information_Present": ["rdp.negReq.flags.correction_info_present"],  "RDP_NEG_Request_Requested_Protocols": ["rdp.negReq.requestedProtocols"],
                                        "RDP_NEG_Request_Requested_Protocols_SSL": ["rdp.negReq.requestedProtocols.ssl"], "RDP_NEG_Request_Requested_Protocols_Hybrid": ["rdp.negReq.requestedProtocols.hybrid"], "RDP_NEG_Request_Requested_Protocols_RDSTLS": ["rdp.negReq.requestedProtocols.rdstls"],
                                        "RDP_NEG_Request_Requested_Protocols_Hybrid_Ex": ["rdp.negReq.requestedProtocols.hybrid_ex"], "RDP_NEG_Response_Flags": ["rdp.negRsp.flags"], "RDP_NEG_Response_Flags_Extended_CLient_Data_Supported": ["rdp.negRsp.flags.extended_client_data_supported"],
                                        "RDP_NEG_Response_Flags_Dynvc_GFX_Protocol_Supported": ["rdp.negRsp.flags.dynvc_gfx_protocol_supported"], "RDP_NEG_Response_Flags.Restricted_admin_mode_supported": ["rdp.negRsp.flags.restricted_admin_mode_supported"],
                                        "RDP_NEG_Response_Flags_Restricted_authentication_mode_supported": ["rdp.negRsp.flags.restricted_authentication_mode_supported"], "RDP_NEG_Request_Selected_Protocols": ["rdp.negReq.selectedProtocol"], },

                          "COTP Layer": {"COTP_Li": ["cotp.li"], "COTP_Type": ["cotp.type"], "COTP_Destination_Reference": ["cotp.destref"], "COTP_Source_Reference": ["cotp.srcref"], "COTP_Class": ["cotp.class"], "COTP_OPTS_Extended_Formats": ["cotp.opts.extended_formats"],
                                         "COTP_OPTS_No_Explicit_Flow_Control": ["cotp.opts.no_explicit_flow_contro"], },


                          "TPKT Layer": {"TPKT_Version": ["tpkt.version"], "TPKT_Reserved": ["tpkt.reserved"], "TPKT_Length": ["tpkt.length"], },

                          "SPNEGO Layer": {"SPNEGO_Neg_Token_Init_Element": ["spnego.negTokenInit_element"], "SPNEGO_Mech_Types": ["spnego.mechTypes"], "SPNEGO_Mech_Type": ["spnego.MechType"], "SPNEGO_Mech_Token": ["spnego.mechToken"], },

                          "SSH Layer": {"SSH_Packet_Length": ["ssh.packet_length"], "SSH_Message_Code": ["ssh.message_code"], "SSH_Cookie": ["ssh.cookie"], "SSH_Kex_Algorithms": ["ssh.kex_algorithms"], "SSH_Server_Host_Key_Algorithms": ["ssh.server_host_key_algorithms"],
                                        "SSH_Encryption_Algorithms_Client_To_Server": ["ssh.encryption_algorithms_client_to_server"], "SSH_Encryption_Algorithms_Server_To_Client": ["ssh.encryption_algorithms_server_to_client"],
                                        "SSH_MAC_Algorithms_Client_To_Server": ["ssh.mac_algorithms_client_to_server"], "SSH_MAC_Algorithms_Server_To_Client": ["ssh.mac_algorithms_server_to_client"],
                                        "SSH_compression_Algorithms_Client_To_Server": ["ssh.compression_algorithms_client_to_server"], "SSH_compression_Algorithms_Server_To_Client": ["ssh.compression_algorithms_server_to_client"],
                                        "SSH_First_Kex_Packet_Follows": ["ssh.first_kex_packet_follows"], "SSH_Kex_Hassh_Server": ["ssh.kex.hsshserver"], "SSH_Padding_String": ["ssh.padding_string"], "SSH_Sequence_Number": ["ssh.seq_num"],
                                        "SSH_Host_Key_Type": ["ssh.host_key.type"], "SSH_Host_Key_RSA_N": ["ssh.host_key.rsa.n"], "SSH_Host_sig_Type": ["ssh.host_sig.type"], "SSH_Host_sig_Data": ["ssh.host_sig.data"],
                                        "SSH_Protocol": ["ssh.protocol"], "SSH_Direction": ["ssh.direction"], },

                          "MAILSLOT Layer": {"MAILSLOT_OPCode": ["mailslot.opcode"], "MAILSLOT_Priority": ["mailslot.priority"], "MAILSLOT_Class": ["mailslot.class"], "MAILSLOT_Size": ["mailslot.size"], "MAILSLOT_Name": ["mailslot.name"], },


                          "BROWSER Layer": {"BROWSER_Command": ["browser.command"], "BROWSER_Update_Count": ["browser.update_count"], "BROWSER_Period": ["browser.period"], "BROWSER_Windows_Version": ["browser.windows_version"], "BROWSER_OS_Major": ["browser.os_major"],
                                            "BROWSER_OS_Minor": ["browser.os_minor"], "BROWSER_Server": ["browser.server"], "BROWSER_Server_Type": ["browser.server_type"], "BROWSER_Server_Type_Workstation": ["browser.server_type.workstation"],
                                            "BROWSER_Server_Type_Server": ["browser.server_type.server"], "BROWSER_Server_Type_SQL": ["browser.server_type.sql"],  "BROWSER_Server_Type_Domain_Controller": ["browser.server_type.domain_controller"],
                                            "BROWSER_Server_Type_Backup_Controller": ["browser.server_type.backup_controller"], "BROWSER_Server_Type_Time": ["browser.server_type.time"], "BROWSER_Server_Type_Apple": ["browser.server_type.apple"],
                                            "BROWSER_Server_Type_Novell": ["browser.server_type.novell"], "BROWSER_Server_Type_Member": ["browser.server_type.member"], "BROWSER_Server_Type_Print": ["browser.server_type.print"], "BROWSER_Server_Type_Dialin": ["browser.server_type.dialin"],
                                            "BROWSER_Server_Type_Xenix": ["browser.server_type.xenix"], "BROWSER_Server_Type_NTW": ["browser.server_type.ntw"], "BROWSER_Server_Type_WFW": ["browser.server_type.wfw"], "BROWSER_Server_Type_NTS": ["browser.server_type.nts"],
                                            "BROWSER_Server_Type_Browser_Potential": ["browser.server_type.browser.potential"], "BROWSER_Server_Type_Browser_Backup": ["browser.server_type.browser.backup"], "BROWSER_Server_Type_Browser_Master": ["browser.server_type.browser.master"],
                                            "BROWSER_Server_Type_Browser_Domain_Master": ["browser.server_type.browser.domain_master"], "BROWSER_Server_Type_osf": ["browser.server_type.osf"], "BROWSER_Server_Type_vms": ["browser.server_type.vms"], "BROWSER_Server_Type_w95": ["browser.server_type.w95"],
                                            "BROWSER_Server_Type_DFS": ["browser.server_type.dfs"], "BROWSER_Server_Type_Local": ["browser.server_type.local"], "BROWSER_Server_Type_Domain_Enum": ["browser.server_type.domainenum"], "BROWSER_Protocol_Major": ["browser.proto_major"],
                                            "BROWSER_Protocol_Minor": ["browser.proto_minor"], "BROWSER_Signature": ["browser.sig"], "BROWSER_Comments": ["browser.comment"], },

                          "NBDGM": {"NBDGM_Type": ["nbdgm.type"], "NBDGM_Flags": ["nbdgm.flags"], "NBDGM_First": ["nbdgm.first"], "NBDGM_Next": ["nbdgm.next"], "NBDGM_Node_Type": ["nbdgm.node_type"], "NBDGM_Datagram_ID": ["nbdgm.dgram_id"], "NBDGM_Source_IP": ["nbdgm.src.ip"], "NBDGM_Source_Port": ["nbdgm.src.port"],
                                    "NBDGM_Datagram_Length": ["nbdgm.dgram_len"], "NBDGM_Packet_Offset": ["nbdgm.pkt_offset"], "NBDGM_Source_Name": ["nbdgm.source_name"], "NBDGM_Destination_Name": ["nbdgm.destination_name"], },

                          "NETLOGON Layer": {"NETLOGON_Secchan_NL_Auth_Message_Message_Type": ["netlogon.secchan.nl_auth_message.message_type"], "NETLOGON_Secchan_NL_Auth_Message_Message_Flags": ["netlogon.secchan.nl_auth_message.message_flags"], "NETLOGON_Secchan_NL_Auth_Message_NB_Domain": ["netlogon.secchan.nl_auth_message.nd_domain"],
                                             "NETLOGON_Secchan_NL_Auth_Message_NB_Host": ["netlogon.secchan.nl_auth_message.nb_host"], "NETLOGON_Secchan_NL_Auth_Message_NB_Host_UTF8": ["netlogon.secchan.nl_auth_message.nb_host_utf8"], "NETLOGON_Secchan_NL_Auth_Message_DNS_Domain": ["netlogon.secchan.nl_auth_message.dns_domain"],
                                             "NETLOGON_Secchan_Verifier": ["netlogon.secchan.verifier"], "NETLOGON_Secchan_Sign_Algorithm": ["netlogon.secchan.signalg"], "NETLOGON_Secchan_Seal_Algorithm": ["netlogon.secchan.sealalg"], "NETLOGON_Secchan_Sequence": ["netlogon.secchan.seq"],
                                             "NETLOGON_Secchan_Digest": ["netlogon.secchan.digest"], "NETLOGON_Secchan_Nonce": ["netlogon.secchan.nonce"], },

                          "XML Layer": {"XML_XMLPi_XML_Version": ["xml.xmlpi.xml.version"], "XML_XMLPi_XML_Encoding": ["xml.xmlpi.xml.encoding"], "XML_CData": ["xml.cdata"], },

                          "MSCLDAP": {"MSCLDAP_Ntver_Flags": ["mscldap.ntver.flags"], "MSCLDAP_Ntver_Search_Flags_VGC": ["mscldap.ntver.searchflags.vgc"], "MSCLDAP_Netlogon_OPCode": ["mscldap.netlogon.opcode"], "MSCLDAP_Netlogon_Flags": ["mscldap.netlogon.flags"], "MSCLDAP_Netlogon_Flags_Forest_NC": ["mscldap.netlogon.flags.forestnc"],
                                      "MSCLDAP_Netlogon_Flags_Default_NC": ["mscldap.netlogon.flags.defaultnc"], "MSCLDAP_Netlogon_Flags_DNS_Name": ["mscldap.netlogon.dnsname"], "MSCLDAP_Netlogon_Flags_Writable_DC": ["mscldap.netlogon.flags.writabledc"], "MSCLDAP_Netlogon_Flags_Rodc": ["mscldap.netlogon.flags.rodc"],
                                      "MSCLDAP_Netlogon_Flags.Ndnc": ["mscldap.netlogon.flags.ndnc"], "MSCLDAP_Netlogon_Flags_Good_Timeserv": ["mscldap.netlogon.flags.good_timeserv"], "MSCLDAP_Netlogon_Flags_Writable": ["mscldap.netlogon.flags.writable"], "MSCLDAP_Netlogon_Flags_Closest": ["mscldap.netlogon.flags.closest"],
                                      "MSCLDAP_Netlogon_Flags_Timeserv": ["mscldap.netlogon.flags.timeserv"], "MSCLDAP_Netlogon_Flags_KDC": ["mscldap.netlogon.flags.kdc"], "MSCLDAP_Netlogon_Flags_DS": ["mscldap.netlogon.flags.ds"], "MSCLDAP_Netlogon_Flags.LDAP": ["mscldap.netlogon.flags.ldap"], "MSCLDAP_Netlogon_Flags_GC": ["mscldap.netlogon.flags.gc"],
                                      "MSCLDAP_Netlogon_Flags_PDC": ["mscldap.netlogon.flags.pdc"], "MSCLDAP_Netlogon_LM_Token": ["mscldap.netlogon.lm_token"], "MSCLDAP_Netlogon_NT_Token": ["mscldap.netlogon.nt_token"], "MSCLDAP_Domain": ["mscldap.domain"], "MSCLDAP_Host_Name": ["mscldap.hostname"], "MSCLDAP_NB_Domain": ["mscldap.nb_domain"],
                                      "MSCLDAP_NB_Host_Name": ["mscldap.nb_hostname"], "MSCLDAP_User_Name": ["mscldap.username"], "MSCLDAP_Site_Name": ["mscldap.sitename"], "MSCLDAP_Client_Site_Name": ["mscldap.clientsitename"], },

                          "SAMR Layer": {"SAMR_Operation_Number": ["samr.opnum"], "SAMR_RID": ["samr.rid"], "SAMR_Status": ["samr.status"], "SAMR_Connect.Access_Mask": ["samr.connect.access_mask"], "SAMR_Domain.Access_Mask": ["samr.domain.access_mask"], "SAMR_User.Access_Mask": ["samr.user.access_mask"],
                                         "SAMR_SAMR_Connection5_System_Name": ["samr.samr_Connection5.system_name"], "SAMR_SAMR_SamEntry_Name": ["samr.samr_SamEntry.name"], "SAMR_SAMR_Enum_Domains_Number_of_Entries": ["samr.samr_EnumDomains.num_entries"], "SAMR_SAMR_Lookup_Domain_Domain_Name": ["samr.samr_LookupDomain.domain_name"],
                                         "SAMR_SAMR_Lookup_Names_Names": ["samr.samr_LookupNames.names"], "SAMR_SAMR_Query_User_Info_Level": ["samr.samr_QueryUserInfo.leve"], "SAMR_SAMR_Query_User_Info_Info": ["samr.samr_QueryUserInfo.info"], "SAMR_SAMR_User_Info21_Last_Logon": ["samr.samr_UserInfo21.last_logon"],
                                         "SAMR_SAMR_User_Info21_Last_Logoff": ["samr.samr_UserInfo21.last_logoff"], "SAMR_SAMR_User_Info21_Last_Password_Change": ["samr.samr_UserInfo21.last_password_change"], "SAMR_SAMR_User_Info21_Account_Expiry": ["samr.samr_UserInfo21.acct_expiry"],
                                         "SAMR_SAMR_User_Info21_Allow_Password_Change": ["samr.samr_UserInfo21.allow_password_charnge"], "SAMR_SAMR_User_Info21_Force_Password_Change": ["samr.samr_UserInfo21.force_password_charnge"], "SAMR_SAMR_User_Info21_Full_Name": ["samr.samr_UserInfo21.full_name"],
                                         "SAMR_SAMR_User_Info21_Primary_GID": ["samr.samr_UserInfo21.primary_gid"], "SAMR_SAMR_User_Info21_Account_Flags": ["samr.samr_UserInfo21.acct_flags"], "SAMR_SAMR_User_Info21_Fields_Present": ["samr.samr_UserInfo21.fields_present"], "SAMR_Sec_Description_Buffer_Length": ["samr.sec_desc_buf_len"],
                                         "SAMR_SAMR_Get_Groups_For_User_RIDS": ["samr.samr_GetGroupsForUser.rids"], "SAMR_SAMR_RID_With_Attribute_Array_Count": ["samr.samr_RidWithAttributeArray.count"], "SAMR_SAMR_RID_With_Attribute_Array_RIDS": ["samr.samr_RidWithAttributeArray.rids"], "SAMR_SAMR_RID_With_Attribute_Attributes": ["samr.samr_RidWithAttribute.attributes"],
                                         "SAMR_SAMR_Domain_Access_Mask_SAMR_Domain_Access_Open_Account": ["samr.samr_DomainAccessMask.SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT"],
                                         "SAMR_SAMR_Domain_Access_Mask_SAMR_Domain_Access_Lookup_Alias": ["samr.samr_DomainAccessMask.SAMR_DOMAIN_ACCESS_LOOKUP_ALIAS"],
                                         "SAMR_SAMR_Domain_Access_Mask_SAMR_Domain_Access_Enum_Accounts": ["samr.samr_DomainAccessMask.SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS"],
                                         },


                          }  # "" : {"":[""],},  ---- "QUIC Layer": {"QUIC_Version": ["quic.version"], },
