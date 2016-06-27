'''
1. encoding family (TLV)
2. procedures
3. message templates
4. tag-name maps
'''

family = "TLV"

timers = {
	'Ts5': 30
}

procedures = '''
procedure,location update
MME, SGsAP-LOCATION-UPDATE-REQUEST, MSC1
MSC1, SGsAP-LOCATION-UPDATE-ACCEPT, MME1
'''

message_header_template = [
("message type", 1)
]

#	IE name		Presence	Format		Min Length	Max Length
message_body_template = {
'SGsAP-ALERT-ACK': [
	('IMSI', 'M', 'TLV', '6', '10')
	],
'SGsAP-ALERT-REJECT': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('SGs Cause', 'M', 'TLV', '3', '0')
	],
'SGsAP-ALERT-REQUEST': [
	('IMSI', 'M', 'TLV', '6', '10')
	],
'SGsAP-DOWNLINK-UNITDATA': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('NAS message container', 'M', 'TLV', '4', '253')
	],
'SGsAP-EPS-DETACH-ACK': [
	('IMSI', 'M', 'TLV', '6', '10')
	],
'SGsAP-EPS-DETACH-INDICATION': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('MME name', 'M', 'TLV', '52', '53'),
	('IMSI detach from EPS service type', 'M', 'TLV', '3', '0')
	],
'SGsAP-IMSI-DETACH-ACK': [
	('IMSI', 'M', 'TLV', '6', '10')
	],
'SGsAP-IMSI-DETACH-INDICATION': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('MME name', 'M', 'TLV', '52', '53'),
	('IMSI Detach from non-EPS service type', 'M', 'TLV', '3', '0')
	],
'SGsAP-LOCATION-UPDATE-ACCEPT': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('Location area identifier', 'M', 'TLV', '7', '0'),
	('TMSI', 'O', 'TLV', '6', '10')
	],
'SGsAP-LOCATION-UPDATE-REJECT': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('Reject cause', 'M', 'TLV', '3', '0')
	],
'SGsAP-LOCATION-UPDATE-REQUEST': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('MME name', 'M', 'TLV', '52', '53'),
	('EPS location update type', 'M', 'TLV', '3', '0'),
	('Location area identifier', 'M', 'TLV', '7', '0'),
	('Location area identifier', 'O', 'TLV', '7', '0'),
	('TMSI status', 'O', 'TLV', '3', '0'),
	('IMEISV', 'O', 'TLV', '10', '0')
	],
'SGsAP-MM-INFORMATION-REQUEST': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('MM information', 'M', 'TLV', '3', 'n')
	],
'SGsAP-PAGING-REJECT': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('SGs Cause', 'M', 'TLV', '3', '0')
	],
'SGsAP-PAGING-REQUEST': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('VLR name', 'M', 'TLV', '3', 'n'),
	('Service indicator', 'M', 'TLV', '3', '0'),
	('TMSI', 'O', 'TLV', '6', '0'),
	('CLI', 'O', 'TLV', '3', '14'),
	('Location area identifier', 'O', 'TLV', '7', '0'),
	('Global CN-Id', 'O', 'TLV', '7', '0'),
	('SS code', 'O', 'TLV', '3', '0'),
	('LCS indicator', 'O', 'TLV', '3', '0'),
	('LCS client identity', 'O', 'TLV', '3', 'n'),
	('Channel needed', 'O', 'TLV', '3', '0'),
	('eMLPP Priority', 'O', 'TLV', '3', '0')
	],
'SGsAP-RESET-ACK': [
	('MME name', 'C', 'TLV', '52', '53'),
	('VLR name', 'C', 'TLV', '3', 'n')
	],
'SGsAP-RESET-INDICATION': [
	('MME name', 'C', 'TLV', '52', '53'),
	('VLR name', 'C', 'TLV', '3', 'n')
	],
'SGsAP-SERVICE-REQUEST': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('Service indicator', 'M', 'TLV', '3', '0'),
	('IMEISV', 'O', 'TLV', '10', '0'),
	('UE Time Zone', 'O', 'TLV', '6', '0'),
	('Mobile Station Classmark 2', 'O', 'TLV', '5', '0'),
	('TAI', 'Tracking Area Identity', 'O', 'TLV', '6', '0'),
	('E-CGI', 'E-UTRAN Cell Global Identity', 'O', 'TLV', '6', '0')
	],
'SGsAP-STATUS': [
	('IMSI', 'O', 'TLV', '6', '10'),
	('SGs cause', 'M', 'TLV', '3', '0'),
	('Erroneous message', 'M', 'TLV', '3', 'n')
	],
'SGsAP-TMSI-REALLOCATION-COMPLETE': [
	('IMSI', 'M', 'TLV', '6', '10')
	],
'SGsAP-UE-ACTIVITY-INDICATION': [
	('IMSI', 'M', 'TLV', '6', '10')
	],
'SGsAP-UE-UNREACHABLE': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('SGs cause', 'M', 'TLV', '3', '0')
	],
'SGsAP-UPLINK-UNITDATA': [
	('IMSI', 'M', 'TLV', '6', '10'),
	('NAS message container', 'M', 'TLV', '4', '253'),
	('IMEISV', 'O', 'TLV', '10', '0'),
	('UE Time Zone', 'O', 'TLV', '6', '0'),
	('Mobile Station Classmark 2', 'O', 'TLV', '5', '0'),
	('TAI', 'O', 'TLV', '6', '0'),
	('E-CGI', 'O', 'TLV', '6', '0')
	],
'SGsAP-RELEASE-REQUEST': [
	('IMSI', 'M', 'TLV', '6', '10')
	]
}

message_tag_name_map = {
"01": "SGsAP-PAGING-REQUEST",
"02": "SGsAP-PAGING-REJECT",
"06": "SGsAP-SERVICE-REQUEST",
"07": "SGsAP-DOWNLINK-UNITDATA",
"08": "SGsAP-UPLINK-UNITDATA",
"09": "SGsAP-LOCATION-UPDATE-REQUEST",
"0a": "SGsAP-LOCATION-UPDATE-ACCEPT",
"0b": "SGsAP-LOCATION-UPDATE-REJECT",
"0c": "SGsAP-TMSI-REALLOCATION-COMPLETE",
"0d": "SGsAP-ALERT-REQUEST",
"0e": "SGsAP-ALERT-ACK",
"0f": "SGsAP-ALERT-REJECT",
"10": "SGsAP-UE-ACTIVITY-INDICATION",
"11": "SGsAP-EPS-DETACH-INDICATION",
"12": "SGsAP-EPS-DETACH-ACK",
"13": "SGsAP-IMSI-DETACH-INDICATION",
"14": "SGsAP-IMSI-DETACH-ACK",
"15": "SGsAP-RESET-INDICATION",
"16": "SGsAP-RESET-ACK",
"18": "SGsAP-MM-INFORMATION-REQUEST",
"19": "SGsAP-RELEASE-REQUEST",
"1b": "SGsAP-STATUS",
"1f": "SGsAP-UE-UNREACHABLE"
}

field_tag_name_map = {
"01": "IMSI",
"02": "VLR name",
"03": "TMSI",
"04": "Location area identifier",
"05": "Channel Needed",
"06": "eMLPP Priority",
"07": "TMSI status",
"08": "SGs cause",
"09": "MME name",
"0a": "EPS location update type",
"0b": "Global CN-Id",
"0e": "Mobile identity",
"0f": "Reject cause",
"10": "IMSI detach from EPS service type",
"11": "IMSI detach from non-EPS service type",
"15": "IMEISV",
"16": "NAS message container",
"17": "MM information",
"19": "Erroneous message",
"1a": "CLI",
"1b": "LCS client identity",
"1e": "LCS indicator",
"1f": "SS code",
"20": "Service indicator",
"21": "UE Time Zone",
"22": "Mobile Station Classmark 2",
"23": "Tracking Area Identity",
"24": "E-UTRAN Cell Global Identity"
}

stt = {
        "IDLE,SGSAP-LU": ["af1","af2","ACTIVE"],
        "ACTIVE,SGSAP-RESET": ["IDLE"]
}

