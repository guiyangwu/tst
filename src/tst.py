#!/usr/bin/env python3

#  Copyright 2015 GuiYang WU
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

version = "0.1.0"
usage   = '''NAME
    tst - a toolkit for software testing

SYNOPSIS
    tst [OPTION] <FILE|DIRECTORY>

DESCRIPTION
    Run test script(s) and report test result.

    Options:
    --debug     turn on debug option which is same as
                option --loglevel debug
    --loglevel  value can be either of all, critical,
                error, warning or debug.
    --logfile   value can be a file name which a path is
                necessary if no in the current directory.
    --version   print version information.
    --help      display this help and exit

    Arguments:
    FILE        Run test script defined in a .t file
    DIRECTORY   Run all .t files under a directory and
                its sub-directories recursively.
'''

import os
import sys
import getopt
import socket
import binascii
import datetime
import platform
import subprocess
import logging as log

realcomponents = {}
components = {}
procedures = {}
protocols = {}
states = {}
taillogs = {}
syskeywords = {"title", "create", "case", "procedure", "state", "check", "real", "tail", "import", "include", "run", "set", "delete"}

tstpath = os.environ.get("TSTPATH") # get this from which tst?

if tstpath == None:
    print("Please set environment variable TSTPATH to where tst is installed")
    exit()
else:
    # import global modules
    if os.path.exists(tstpath+"/userglobal.py"):
        from userglobal import *
    # import public protocol modules
    protocols_path = tstpath + "/src/protocols"
    if os.path.exists(protocols_path):
        sys.path.append(protocols_path)
        #print("added module path: " + protocols_path)
    # import public tstlib modules
    lib_path = tstpath + "/src/tstlib"
    if os.path.exists(lib_path):
        sys.path.append(lib_path)
        #print("added module path: " + lib_path)

# run testing
def tst(file_path):
    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            if '/' in tfile:
                current_file_path = tfile[:tfile.rfind("/")]
            else:
                current_file_path = os.getcwd()
            sys.path.append(current_file_path) # add module path
            log.info("added module path: " + current_file_path)

            run_tst_file(file_path)
        else:
            run_tst_path(file_path)

# excute testing with a path
def run_tst_path(tpath):
    for step in os.walk(tpath):
        if '/.' in step[0]: continue
        # add local module path
        sys.path.append(step[0]) # add module path
        for afile in step[2]:
            if afile[0] != "." and afile[-2:] == ".t":
                run_tst_file(step[0] + "/" + afile)

# execute testing with a script file
def run_tst_file(tfile):
    log.debug("FILE: start to execute %s", tfile)
    mlc_flag = 0 # multi-line comment flag
    case_id = ""
    case_flag = 0 # 0 idle, 1 in progress
    case_result = 0 # 0 passed, 1 failed
    case_report = "" # test case report in CSV
    procedure_flag = 0 # keyword procedure flag
    procedure_name = ""
    procedure_body = ""
    state_name = 0 
    state_flag = 0 # keyword state flag

    for line in open(tfile):
        # ignore all kinds of spaces at the head and tail
        line = line.strip()
        log.debug("SEQUENCE: " + line)

        # skip multiple line comment block
        if len(line)>=3 and line[0:3] == "'''":
            if mlc_flag == 1:
                mlc_flag = 0
            else:
                mlc_flag = 1
            continue
        if mlc_flag == 1: continue

        # handle blank line
        if line == "":
            # generate test report at end of a test case
            if case_flag == 1:
                # generate case report
                log.debug("CASE: test end")
                if case_result == 0:
                    case_report += ",passed"
                else:
                    case_report += ",failed"
                stop_tail_log(case_id, case_result)
                report.append(case_report)
                case_flag = 0 # mark test case done
                case_result = 0
                case_report = ""
            # save procedure at end of a procedure definition
            if procedure_flag == 1:
                procedure_flag = 0
                procedures[procedure_name] = procedure_body
                log.debug("PROCEDURE: " + procedure_name + "\n" + procedure_body)
            # parse state at the end of a STT definition
            if state_flag == 1:
                state_flag = 0
                log.debug("STATE: " + state_name)
            continue

        # case failed early before end then skip the rest lines
        if case_flag == 1 and case_result == 1: continue
        
        # skip comment line
        if line[0] == "#": continue
        # truncate tailing comment
        if "#" in line:
            line = line[:line.find("#")]                

        if procedure_flag == 1:
            if procedure_body == "":
                procedure_body = line
            else:
                procedure_body += "\n" + line
            continue
        if state_flag == 1:
            continue

        # parse the line
        params, line_args, line_kargs = parse_line(line)
            
        # run MSL or keywords
        kw_type = get_keyword_type(params[0])
        if kw_type in ["system_global", "user_global"]: # keyword
            if params[0] == "title":
                report.append("Test," + params[1] + "," + tfile)
                continue
            if params[0] == "case":
                # a new test case begin so start to collect logs for this case here
                # stop logs when hit a blank line
                case_flag = 1
                case_id = params[1]
                case_result = 0
                case_report = ",".join(params[1:3])
                start_tail_log()
                log.debug("CASE: test start")
                continue
            if params[0] == "procedure":
                procedure_flag = 1
                procedure_name = params[1]
                procedure_body = ""
                continue
            if params[0] == "state":
                state_flag = 1
                state_name = params[1]
                continue
            elif params[0] == "import":
                print(os.getcwd())
                print(params[1])
                exec("sys.modules['__main__']." + params[1] + " = __import__('" + params[1] + "')")
            elif params[0] == "real":
                realcomponents[params[1]] = line_kargs
            elif params[0] == "tail":
                logname = params[1][params[1].rfind("/")+1:]
                taillogs[logname] = [params[1], None]
                log.debug("TAIL: " + params[1])
            elif params[0] == "check":
                status, output = subprocess.getstatusoutput("egrep " + params[1] + " " + params[2])
                if status != 0:
                    case_result = 1
                    log.debug("TEST CASE: failed.")
            elif params[0] == "run":
                status = subprocess.getstatusoutput(params[1])
                if status != 0:
                    case_result = 1
                log.debug("RUN: " + params[1])
            elif params[0] == "create":
                if len(params) > 1 and params[1].strip() != "":
                    comp = params[1].strip()
                    components[comp] = Component(**line_kargs)
                    if "import" in line_kargs:
                        load_kw_to_obj(line_kargs["import"], components[comp])
            else:
                if "." in params[0] and params[0].split(".")[0] in dir(sys.modules["__main__"]):
                    eval(params[0] + "(*" + str(line_args) + ", **" + str(line_kargs) + ")")
                else:
                    log.error("keyword '" + params[0] + "' not found.")
        elif kw_type == "procedure_reference":
            # call a procedure
            log.debug("calling procedure:")
            log.debug(procedures[params[0]])
            # handle times parameter
            count = 0
            interval = 0
            if line_kargs.get("times", None) == None:
                count = 1
            else:
                count = int(line_kargs["times"])
                del line_kargs["times"] # times cannot pass to sub-lines
            # handle duration parameter
            if line_kargs.get("duration", None) == None:
                once_time = 0
            else:
                interval = int(line_kargs["duration"])
                del line_kargs["duration"] # duration cannot pass to sub-lines
            if count > 1 and interval >= 1:
                once_time = interval//count
            else:
                once_time = 0
            if count >= 1:
                hardtime = datetime.datetime(2015, 7, 19, 22, 0, 21, 617478)
                starttime = datetime.datetime.now() - hardtime
                for i in range(count): 
                    run_procedure(procedures[params[0]], **line_kargs)
                    endtime = datetime.datetime.now() - hardtime
                    if starttime.seconds+once_time*i > endtime.seconds:
                        pass
            else:
                log.error("invalid value of times.")
        elif kw_type == "component":
            comp = params[0].split(".")[0]
            func = params[0].split(".")[1]
            if comp in components:
                if len(line_args) > 0 and len(line_kargs) > 0:
                    eval("components['" + comp + "']." + func + "(*" + str(line_args) + ", **" + str(line_kargs) + ")")
                elif len(line_args) > 0 and len(line_kargs) == 0:
                    eval("components['" + comp + "']." + func + "(*" + str(line_args) + ")")
                elif len(line_args) == 0 and len(line_kargs) > 0:
                    eval("components['" + comp + "']." + func + "(**" + str(line_kargs) + ")")
                else:
                    eval("components['" + comp + "']." + func + "()")
            else:
                log.error(params[0] + " not found.")
        else: # MSL
            if len(params) >= 3:
                sequence(params[0], params[1], params[2], **line_kargs)
            else:
                log.debug(params)
                log.error("MSL syntax error!")
    # hit file end when run last case
    if case_flag == 1:
        if case_result == 0:
            case_report += ",passed"
        else:
            case_report += ",failed"
        report.append(case_report)
        case_flag = 0 # mark test case done
        case_result = 0
        case_report = ""
    # file end
    release_sockets()
    if report.report_file != "":
        log.info("completed running test cases in " + tfile + "\n" + "-"*80 + "\n" + open(report.output_path + "/" + report.report_file).read() + "-"*80)

def start_tail_log():
    for logname in taillogs:
        loginfo = taillogs[logname]
        if not os.path.exists(case_output_path + "/log/tail"):
            os.makedirs(case_output_path + "/log/tail")
        status = subprocess.call("tail -f " + loginfo[0] + " >> " + case_output_path + "/log/tail/" + logname + "&", shell=True)
        pid = subprocess.getoutput("echo $$")
        pid = str(int(pid) - 1)
        loginfo[1] = pid

def stop_tail_log(case_id, case_result):
    for logname in taillogs:
        loginfo = taillogs[logname]
        if loginfo[1] != "":
            status, output = subprocess.getstatusoutput("kill -9 " + loginfo[1])
            loginfo[1] = ""
        else:
            log.error("pid of " + logname + " was not found.")
    #if case_result != 0:
    status, output = subprocess.getstatusoutput("mv " + case_output_path + "/log/tail " + case_output_path + "/log/" + case_id)

def split_line(line):
    return line.split(",")
    params = []
    param = ""
    quote = ""
    if '"' in line or "'" in line:
        for char in line:
            if quote == "":
                if char == ",":
                    params.append(param)
                    param = ""
                else:
                    if char == '"' or char == "'":
                        quote = char
                    else:
                        param += char
            else:
                if char == quote:
                    quote = ""
                else:
                    param += char
        if quote != "":
            log.error("quote error.")
    else:
        return line.split(",")
    if param != "":
        params.append(param)
    return params

def parse_line(line, **kargs):
    # split
    params = split_line(line)
    # parse parameters
    for idx in range(0, len(params)):
        params[idx] = params[idx].strip()
    tmp_args = ""
    tmp_kargs = ""
    for kw in params[1:]:
        tidx = 0
        tkey = ""
        tvalue = ""
        if "=" in kw:
            tidx = kw.find("=") # find first one
            tkey = '\"' + kw[:tidx] + '\"'
            tvalue = kw[tidx+1:]
            if tmp_kargs == "":
                tmp_kargs = tkey + ":" + tvalue
            else:
                tmp_kargs += "," + tkey + ":" + tvalue
        else:
                tmp_args = "'" + kw + "',"
    if tmp_kargs != "":
        line_kargs = eval("{" + tmp_kargs + "}")
    else:
        line_kargs = {}
    if tmp_args != "":
        line_args = eval("(" + tmp_args + ")")
    else:
        line_args = tuple()

    # source comp name
    if get_keyword_type(params[0]) == "component":
        if "." in params[0]:
            comp = params[0].split(".")[0]
            if comp in line_kargs:
                params[0] = line_kargs[comp] + "." + params[0].split(".")[1]
        else:
            if params[0] in line_kargs:
                params[0] = line_kargs[comp]
    # target comp name
    if len(params) >= 3 and get_keyword_type(params[2]) == "component":
        if "." in params[2]:
            comp = params[2].split(".")[0]
            if comp in line_kargs:
                params[2] = line_kargs[comp] + "." + params[2].split(".")[1]
        else:
            if params[2] in line_kargs:
                params[2] = line_kargs[comp]

    return params, line_args, line_kargs

def run_procedure(pstr, **kargs):
    global case_result
    log.debug(kargs)
    for arg in kargs:
        pstr = pstr.replace(arg, kargs[arg])
    log.debug("start procedure:\n" + pstr)
    for line in pstr.split("\n"):
        log.debug("RUN PROCEDURE: " + line)
        params, line_args, line_kargs = parse_line(line, **kargs)
        # run MSL and keywords
        kw_type = get_keyword_type(params[0])
        if kw_type in ["system_global", "user_global"]: # keyword
            if params[0] == "real":
                realcomponents[params[1]] = line_kargs
            elif params[0] == "run":
                status = subprocess.getstatusoutput(params[1])
                log.debug("RUN: " + params[1])
                if status != 0:
                    case_result = 1
                    return
            elif params[0] == "create":
                if len(params) > 1 and params[1].strip() != "":
                    comp = params[1].strip()
                    components[comp] = Component(**line_kargs)
                    if "import" in line_kargs:
                        load_kw_to_obj(current_file_path+line_kargs["import"], components[comp])
            else:
                if "." in params[0] and params[0].split(".")[0] in dir(sys.modules["__main__"]):
                    eval(params[0] + "(*" + str(line_args) + ", **" + str(line_kargs) + ")")
                else:
                    log.error("keyword '" + params[0] + "' not found.")
        elif kw_type == "procedure_reference":
            # this is a procedure reference
            log.debug("procedure calling procedure:")
            log.debug(procedures[params[0]])
            nproc = procedures[params[0]]
            run_procedure(nproc, **line_kargs)
        elif kw_type == "component":
            comp = params[0].split(".")[0]
            func = params[0].split(".")[1]
            if comp in components:
                if len(line_args) > 0 and len(line_kargs) > 0:
                    eval("components['" + comp + "']." + func + "(*" + str(line_args) + ", **" + str(line_kargs) + ")")
                elif len(line_args) > 0 and len(line_kargs) == 0:
                    eval("components['" + comp + "']." + func + "(*" + str(line_args) + ")")
                elif len(line_args) == 0 and len(line_kargs) > 0:
                    eval("components['" + comp + "']." + func + "(**" + str(line_kargs) + ")")
                else:
                    eval("components['" + comp + "']." + func + "()")
            else:
                log.error(params[0] + " not found.")
        elif kw_type == "MSL":
            if len(params) >= 3:
                sequence(params[0], params[1], params[2], **dict(kargs, **line_kargs))
            else:
                log.debug(params)
                log.error("MSL syntax error!")
        else:
            log.error("unknown MSL keyword type '" + params[0] + "'")

def get_keyword_type(kw_name):
    kw_type = ""
    if kw_name in components:
        kw_type = "MSL"
    elif kw_name in syskeywords:
        kw_type = "system_global"
    elif kw_name in dir(sys.modules["__main__"]):
        kw_type = "user_global"
    elif kw_name in procedures:
        kw_type = "procedure_reference"
    elif "." in kw_name:
        comp = kw_name.split(".")[0]
        kw = kw_name.split(".")[1]
        if comp in components and kw in dir(components[comp]):
            kw_type = "component"
        else:
            kw_type = "user_global"
    else:
        kw_type = ""
    return kw_type

def sequence(source, target, message, **kargs):
    if message in {'interface', 'listen', 'connect', 'accept'}:
        handle_interface_message(source, message, target, **kargs)
    else:
        if source not in realcomponents and source in components:
            # source is a simulator in components
            components[source].send_message(source, message, target, **kargs)
        if target not in realcomponents and target in components:
            # a target simulator should wait for a message from a real component
            components[target].receive_message(target, message, source, **kargs)

def handle_interface_message(source, message, target, **kargs):
    if message == "interface":
        stack = kargs["stack"].strip().split("/")
        load_protocols(stack[1:])
        ip = kargs.get("ip", components[source].config["ip"])
        sock = create_socket(stack[0], ip, kargs["port"])
        log.debug("SOCKET: created from '" + source + "' to '" + target + "'") 
        if kargs.get("CS", None) == "S":
            components[source].linterfaces[(target, kargs.get("interface", "default"))] = [sock, stack]
        else:
            components[source].interfaces[(target, kargs.get("interface", "default"))] = [sock, stack]
    if message == "listen":
        components[source].linterfaces[(target, kargs.get("interface", "default"))][0].listen(1)
        log.debug("SOCKET: started to listen")
    if message == "connect":
        components[source].interfaces[(target, kargs.get("interface", "default"))][0].connect((kargs["ip"], int(kargs["port"])))
        log.debug("SOCKET: connecting")
    if message == "accept":
        newsock, (ip, port) = components[source].linterfaces[(target, kargs.get("interface", "default"))][0].accept()
        components[source].interfaces[(target, kargs.get("interface", "default"))] = [newsock, components[source].linterfaces[(target, kargs.get("interface", "default"))][1]]
        log.debug("SOCKET: accepted with new socket ")

def load_protocols(stack):
    for pname in stack:
        protocols[pname] = Protocol(pname)

def create_socket(socket_type, ip, port):
    if socket_type == "sctp":
        if platform.platform().split("-")[0] == "Windows":
            log.error("Windows does not support SCTP.")
            exit()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    elif socket_type == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else: # socket_type == "UDP"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if socket_type in ["sctp", "tcp"]:
        sock.bind((ip, int(port)))
    return sock

def release_sockets():
    for comp in components:
        for intf in components[comp].interfaces:
            components[comp].interfaces[intf][0].close()
            log.debug("SOCKET: '" + str(intf) + "' closed")
        for intf in components[comp].linterfaces:
            components[comp].interfaces[intf][0].close()
            log.debug("SOCKET: '" + str(intf) + "' closed")

def load_kw_to_obj(kwfile, obj):
    tmp_mod = __import__(kwfile)
    for attr in dir(tmp_mod):
        if attr[0] != "_" and hasattr(getattr(tmp_mod, attr), "__call__") == True:
            setattr(obj.__class__, attr, staticmethod(getattr(tmp_mod, attr)))
            
class Component:
    def __init__(self, **kargs):
        self.config = {} # config data
        self.userdata = {} # user data

        self.msgdata = {}
        self.incoming = {} # incoming message data
        self.outgoing = {} # outgoing message data

        self.linterfaces = {} # interfaces to listen
        self.interfaces = {} # remote component name: [interface name, socket handler, protocol]

        self.current_state = None
        self.stt = None # state transition tables

        self.config.update(kargs)

        self.config["ip"] = kargs.get("ip", "127.0.0.1")

        if "state" in kargs and kargs["state"] in states:
            self.stt = states[kargs["state"]]
            self.current_state = "START"

    def receive_message(self, source, message, target, **kargs):
        if kargs.get("rawfile", None) != None: return

        buf = self.interfaces[(target, kargs.get("interface", "default"))][0].recv(1024)
        log.debug("MESSAGE: received " + str(len(buf)))
        self.decode_message(self.interfaces[(target, kargs.get("interface", "default"))][1][1:], buf)
        self.msgdata.update(self.incoming)
        if self.incoming.get("decoding result", "FAIL") != "SUCCESS":
            log.error('unexpected message received %s but expecting %s' % (msg_type, message))
        else:
            # check and run catcher
            if kargs.get("rcv", None) != None:
                self.run_catcher(kargs["rcv"], message, source, **kargs)
            # if tst creates a real component with FSM, then run it automatically
            if target in realcomponents and target in components and self.stt != None:
                self.current_state = run_fsm(self.current_state, message)

    def run_fsm(cur_state, message):
        stt_key = cur_state + "," + message
        if stt_key in self.stt:
            action_list = self.stt[stt_key]
            if action_list != "":
                actions = action_list.split(",")
                if len(actions) > 1:
                    # run AFs
                    pass
                self.current_state = actions[0]

    def apply_deltas(self, msgdata, deltas):
        deltas = deltas.split("|")
        for delta in deltas:
            delta = delta.replace("-", ":").split(":")
            for index in range(len(delta)):
                delta[index] = int(delta[index])
            msgdata = self.apply_delta(msgdata, delta)
        return msgdata

    def apply_delta(self, msgdata, delta):
        start = (delta[0]-1)*2
        end = delta[1]*2
        current_hex = msgdata[start:end]
        new_hex = self.get_new_hex(current_hex, delta)
        return msgdata[:start] + new_hex + msgdata[end:]

    def get_new_hex(self, old_hex, delta):
        new_hex = old_hex
        if delta[0] == "number":
            old_num = int(old_hex, 16)
            if (old_num + delta[5]) >= delta[4]:
                new_hex = ("%0" + str(len(old_hex)) +"x") % delta[3]
            else:
                new_num = int(old_hex, 16) + delta[5]
                new_hex = ("%0" + str(len(old_hex)) +"x") % new_num
        return new_hex

    def send_message(self, source, message, target, **kargs):
        rawdata = kargs.get("rawdata", None)
        rawfile = kargs.get("rawfile", None)
        delta = kargs.get("delta", None)
        if rawdata != None:
            pdu = rawdata
            self.outgoing["encoding result"] = "SUCCESS"
        elif rawfile != None:
            rawmodule = __import__(rawfile[:rawfile.rfind(".py")])
            if delta != None:
                pdu = self.apply_deltas(rawmodule.rawmsg[message], kargs["delta"])
                rawmodule.rawmsg[message] = pdu
            else:
                pdu = rawmsg[message]
        else:
            pdu = self.encode_message(self.interfaces[(target, kargs.get("interface", "default"))][1][1:], message, "", **kargs)

        if len(pdu) == 0:
            return
        else:
            self.outgoing["encoded"] = pdu
        if self.outgoing.get("encoding result", "FAIL") == "SUCCESS":
            if "times" in kargs:
                i = 0
                for i in range(0, int(kargs["times"])):
                    self.interfaces[(target, kargs.get("interface", "default"))][0].send(binascii.unhexlify(self.outgoing["encoded"]))
                    log.debug("send message #" + str(i+1))
            else:
                self.interfaces[(target, kargs.get("interface", "default"))][0].send(binascii.unhexlify(self.outgoing["encoded"]))

            log.debug("MESSAGE: sent " + str(len(self.outgoing["encoded"])/2))
            #self.outgoing.clear() # clear outgoing buffer
        else:
            log.debug("RESULT: encoding failed.")
        # check and run catcher
        if kargs.get("snd", None) != None:
            self.run_catcher(kargs["snd"], message, target, **kargs)

    def decode_message(self, stack, buf):
        if len(stack) == 0 or len(buf) == 0:
            self.incoming["decoding result"] = "SUCCESS"
            return
        if protocols[stack[0]].family == "TLV":
            buf = binascii.hexlify(buf)
            hex_str = str(buf, encoding='latin-1')
            pdu = protocols[stack[0]].decode_message_tlv(self, hex_str)
            self.decode_message(stack[1:], pdu) # decode upper layer
        elif protocols[stack[0]].family == "TEXT":
            pdu = protocols[stack[0]].decode_message_text(self, buf.decode())
            self.decode_message(stack[1:], pdu) # decode upper layer
        else:
            log.debug("failed to decode.")

    def encode_message(self, stack, message, pdu, **kargs):
        self.outgoing["encoding result"] = "SUCCESS"
        if len(stack) == 0: return pdu
        if protocols[stack[-1]].family == "TLV":
            pdu = protocols[stack[-1]].encode_message_tlv(self, message, pdu, **kargs)
            return self.encode_message(stack[:-1], message, pdu, **kargs) # encode lower layer
        elif protocols[stack[-1]].family == "TEXT":
            pass
        else:
            log.debug("unknown protocol family.")
            
    def get_field_value(self, field_name):
        # get field value for message encoding
        value = None
        if field_name in self.outgoing:
            value = self.outgoing[field_name]
        elif field_name in self.msgdata:
            value = self.msgdata[field_name]
        elif field_name in self.config:
            value = self.config[field_name]
        else:
            value = None
        return value

    def run_catcher(self, catcher_info, message, remote, **kargs):
        log.debug("CATCHER: " + str(catcher_info) + " " + message + " " + remote)
        s = catcher_info()
        return

class Protocol:
    def __init__(self, pfile):
        prot = __import__(pfile)
        self.family = prot.family
        self.procedures = prot.procedures
        self.message_header_template = prot.message_header_template
        self.message_body_template = prot.message_body_template
        self.message_tag_name_map = prot.message_tag_name_map
        self.field_tag_name_map = prot.field_tag_name_map

    def decode_message_tlv(self, comp, hex_str):
        header = self.header_decode(hex_str)
        body = self.tlv_decode(hex_str[self.get_header_length()*2:])
        comp.incoming["header"] = header
        comp.incoming.update(body)
        return body.get("pdu", "")

    def encode_message_tlv(self, comp, message, pdu, **kargs):
        if self.get_header_length() > 0:
            msg_hdr = self.encode_message_header(message, **kargs)
        else:
            msg_hdr = ""
        msg_body = self.encode_message_body(comp, message, **kargs)
        log.debug("MSG: hdr: " + msg_hdr + " body: " + msg_body)
        return msg_hdr+msg_body

    def header_decode(self, hex_str):
        idx = 0
        header = {}
        for (field_name,field_length) in self.message_header_template:
            value = hex_str[idx:idx+field_length*2]
            header[field_name] = value
            idx = idx + field_length*2
        return header

    def tlv_decode(self, hex_str):
        idx = 0
        temp_dict = {}
        while len(hex_str) > idx:
            tag = hex_str[idx:idx+2]
            length = int(hex_str[idx+2:idx+4], 16)
            value = hex_str[idx+4:idx+4+length*2]
            temp_dict[self.field_tag_name_map[tag]] = value
            idx = idx + 4 + length*2
        return temp_dict

    def encode_message_header(self, message, **kargs):
        header = ''
        for field_name, field_length in self.message_header_template:
            if field_name == 'message type':
                header += self.get_key_by_value(self.message_tag_name_map, message)
            else:
                header += parameters[fied_name] if parameters[field_name] else mydata[field_name]
        return header

    def encode_message_body(self, comp, message, **kargs):
        body = ''
        for ie_name, ie_presence, ie_format, ie_min_length, ie_max_length in self.message_body_template[message]:
            if kargs.get(ie_name, None) != None:
                value = kargs[ie_name]
            else:
                value = comp.get_field_value(ie_name)

            # convert to hex string
            if value != None:
                value = self.convert_to_hex_string(value)
            else:
                value = ""

            if value != "":
                # add IE in TLV format
                tag = self.get_key_by_value(self.field_tag_name_map, ie_name)
                length = ('%02x' %((len(value)+1)/2))
                value = value if len(value)%2==0 else value+'0'
                body += tag + length + value
                log.debug('tag: %s, length: %s, value: %s' % (tag, length, value))
            else:
                if ie_presence == 'M':
                    log.error("No value found for IE: " + ie_name)
                    exit()
        return body

    def get_key_by_value(self, dic, value):
        for key in dic:
            if dic[key]==value:
                return key
        return None

    def get_header_length(self):
        header_len = 0
        for tp in self.message_header_template:
            header_len += tp[1]
        return header_len

    def decode_message_text(self, msg):
        pass

    def convert_to_hex_string(self, value):
        # convert value to hex sting format
        value_type = type(value)
        if value_type == int:
            value = hex(value)[2:]
        else: # string
            #tvalue = tvalue[1:-1]
            value = "".join([hex(x)[2:] for x in value.encode()])
        if len(value) % 2 == 1:
            value = '0' + value
        return value

class Report:
    def __init__(self, report_file="", output_path="", print_result=True):
        self.print_result = print_result 
        self.report_file = report_file
        self.output_path = output_path
        self.case_report = ""
    def append(self, case_report_line):
        self.case_report = case_report_line
        # generate output
        if case_print_result == True:
            # report file not specified then print to stdout
            print(self.case_report)
        os.system("echo " + self.case_report + " >>" + self.output_path + "/" + self.report_file)
        self.case_report = ""
    def clear(self):
        if os.path.exists(self.output_path):
            #print(self.output_path)
            #os.system("rm -rf " + self.output_path + "/*") # danger
            pass
    def setformat(fmt):
        self.report_format = fmt
    def setfile(report_file):
        self.report_file = report_file

if __name__ == "__main__":
    case_report_file = "result"
    log_level = 100
    log_file = os.getcwd() + "/output/debug.log"
    case_print_result = True

    case_output_path = os.getcwd() + "/output"
    if not os.path.exists(case_output_path):
        os.makedirs(case_output_path)
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d", ["debug", "help", "version", "loglevel=", "logfile=", "reportfile="])
        if len(opts) == 0 and len(args) == 0:
            print("No parameter provided. Please refer to the usage:")
            print(usage)
            exit()
        # parse options
        for opt in opts:
            if opt[0] == "--debug" or opt[0] == "-d": log_level = log.DEBUG
            elif opt[0] == "--loglevel":
                if opt[1] == "debug": log_level = log.DEBUG
                elif opt[1] == "error": log_level = log.ERROR
                elif opt[1] == "warning": log_level = log.WARNING
                elif opt[1] == "critical": log_level = log.CRITICAL
                elif opt[1] == "all": log_level = log.NOTSET
                else:
                    print("wrong value for log level.")
            elif opt[0] == "--reportfile":
                case_report_file = opt[1]
            elif opt[0] == "--logfile":
                log_file = opt[1]
            elif opt[0] == "--help":
                print(usage)
                exit()
            elif opt[0] == "--version":
                print("tst v" + version)
                exit()
            else:
                print("wrong option: " + opt)
                exit()
    except getopt.GetoptError:
        print("wrong input. Please try 'tst --help' for usage.")
        exit()
    # set log config
    if log_level != 100:
        log.basicConfig(level=log_level, format='%(asctime)s %(filename)s:%(lineno)04d %(levelname)s: %(message)s', datefmt='%Y%m%d %H:%M:%S', filename=log_file, filemode='w')
    # init report
    report = Report(report_file=case_report_file+".csv", output_path=case_output_path, print_result=case_print_result)
    report.clear()
    # parse arguments and run the testing
    for arg in args:
        tst(arg)
    # generate html report
    os.system(tstpath + "/src/report_gen.py <" + case_output_path + "/" + case_report_file + ".csv >" + case_output_path + "/" + case_report_file + ".html")

