#!/usr/bin/env tst

'''
SGsAP interface regresion test
2016 by thomas
'''

title, sgsap unit test
tags, 3gpp, sgsap, sgs, lte, umts

#include,**.t
import,world

# setup env
create,MSC1,ip="127.0.0.1",import="hello"
create,MME1,ip="127.0.0.1"
real,HLR1,ip="127.0.0.1"
MSC1,MME1,interface,name="sgs",port=29118,stack="sctp/sgsap",CS="S"
MME1,MSC1,interface,name="sgs",port=29119,stack="sctp/sgsap"
MSC1,MME1,listen # listen the socket from MSC1 to MME1
MME1,MSC1,connect,ip="127.0.0.1",port=29118
MSC1,MME1,accept # accept the connect request
#tail,syslog

# common data
#set,UE1_IMSI,0x1234567890123456

case,1,verify component keyword and module keyword
MSC1.print_hello, this is called from component MSC1
world.print_world, this is called from module world

case,2,reset MME1
MSC1,MME1,SGsAP-RESET-INDICATION,MME name="MME1",VLR name="VLR1",rcv=world.print_world
MSC1,MME1,SGsAP-RESET-INDICATION,MME name="MME1",VLR name="VLR1"
MME1,MSC1,SGsAP-RESET-ACK,MME name="MME1",VLR name="VLR1",times=20
check,debug,sys.log

case,3,location update
MME1,MSC1,SGsAP-LOCATION-UPDATE-REQUEST,IMSI=0x1234567890123456, MME name="MME1", EPS location update type=0, Location area identifier=0x10101010101010
MSC1,MME1,SGsAP-LOCATION-UPDATE-ACCEPT,IMSI=0x1234567890123456, Location area identifier=0x10101010101010
check,error,sys.log

case,4,mosms
MME1,MSC1,SGsAP-UPLINK-UNITDATA,IMSI=1234567890123456, NAS message container=1234567890
MSC1,MME1,SGsAP-DOWNLINK-UNITDATA,IMSI=1234567890123456, NAS message container=1234567890
check,thomas,/var/log/syslog

procedure, myproc1
mme1,msc1,SGsAP-UPLINK-UNITDATA,NAS message container=1234567890, IMSI=1234567890123456
msc1,mme1,SGsAP-DOWNLINK-UNITDATA,IMSI=1234567890123456,NAS message container=1234567890

case,5, run user-defined procedure myproc1
myproc1, mme1="MME1", msc1="MSC1"

case,6,mtsms
MME1,MSC1,SGsAP-UPLINK-UNITDATA,IMSI=1234567890123456, NAS message container=1234567890
MSC1,MME1,SGsAP-DOWNLINK-UNITDATA,IMSI=1234567890123456, NAS message container=1234567890
run, ls -l
check,WPAdef,/var/log/syslog

procedure,myloadrun,raw msg test
MSC1,MME1,invoke UPLOC,rawfile="rawmsg.py",delta="1-1:00-100:1|2-3:00-200:10"

case,7,run load test
myloadrun, times=10, duration=10

