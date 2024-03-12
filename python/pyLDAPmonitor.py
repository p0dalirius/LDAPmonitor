#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : pyLDAPmonitor.py
# Author             : Podalirius (@podalirius_)
# Date created       : 3 Jan 2022


import argparse
import os
import sys
import ssl
import random
from sectools.windows.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import nt_hash, parse_lm_nt_hashes
from ldap3.protocol.formatters.formatters import format_sid
import time
import datetime
import re
from binascii import unhexlify


### Data utils

def dict_get_paths(d):
    paths = []
    for key in d.keys():
        if type(d[key]) == dict:
            paths = [[key] + p for p in dict_get_paths(d[key])]
        else:
            paths.append([key])
    return paths


def dict_path_access(d, path):
    for key in path:
        if key in d.keys():
            d = d[key]
        else:
            return None
    return d

### Logger

class Logger(object):
    def __init__(self, debug=False, logfile=None, nocolors=False):
        super(Logger, self).__init__()
        self.__debug = debug
        self.__nocolors = nocolors
        self.logfile = logfile
        #
        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile+(".%d"%k)):
                    k += 1
                self.logfile = self.logfile + (".%d" % k)
            open(self.logfile, "w").close()

    def print(self, message=""):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(nocolor_message)
        else:
            print(message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(nocolor_message + "\n")
            f.close()

    def info(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[info] %s" % nocolor_message)
        else:
            print("[info] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(nocolor_message + "\n")
            f.close()

    def debug(self, message):
        if self.__debug == True:
            nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
            if self.__nocolors:
                print("[debug] %s" % nocolor_message)
            else:
                print("[debug] %s" % message)
            if self.logfile is not None:
                f = open(self.logfile, "a")
                f.write("[debug] %s" % nocolor_message + "\n")
                f.close()

    def error(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[error] %s" % nocolor_message)
        else:
            print("[error] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write("[error] %s" % nocolor_message + "\n")
            f.close()

### LDAPConsole

class LDAPConsole(object):
    def __init__(self, ldap_server, ldap_session, target_dn, logger, page_size=1000):
        super(LDAPConsole, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.target_dn = target_dn
        self.logger = logger
        self.page_size = page_size
        self.__results = {}
        self.logger.debug("Using dn: %s" % self.target_dn)

    def query(self, query, attributes=['*'], notify=False):
        # controls
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
        LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f
        LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"
        results = {}
        try:
            # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
            paged_response = True
            paged_cookie = None
            while paged_response == True:
                self.ldap_session.search(
                    self.target_dn, query, attributes=attributes,
                    size_limit=0, paged_size=self.page_size, paged_cookie=paged_cookie
                )
                #
                if "controls" in self.ldap_session.result.keys():
                    if LDAP_PAGED_RESULT_OID_STRING in self.ldap_session.result["controls"].keys():
                        next_cookie = self.ldap_session.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                        if len(next_cookie) == 0:
                            paged_response = False
                        else:
                            paged_response = True
                            paged_cookie = next_cookie
                    else:
                        paged_response = False
                else:
                    paged_response = False
                #
                for entry in self.ldap_session.response:
                    if entry['type'] != 'searchResEntry':
                        continue
                    results[entry['dn']] = entry["attributes"]
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results



def diff(last1_query_results, last2_query_results, logger, ignore_user_logon=False):
    ignored_keys = ["dnsRecord", "replUpToDateVector", "repsFrom"]
    if ignore_user_logon:
        ignored_keys.append("lastlogon")
        ignored_keys.append("logoncount")
    dateprompt = "\x1b[0m[\x1b[96m%s\x1b[0m]" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    common_keys = []
    for key in last2_query_results.keys():
        if key in last1_query_results.keys():
            common_keys.append(key)
        else:
            logger.print("%s \x1b[91m'%s' was deleted.\x1b[0m" % (dateprompt, key))
    for key in last1_query_results.keys():
        if key not in last2_query_results.keys() and key not in ignored_keys:
            logger.print("%s \x1b[92m'%s' was added.\x1b[0m" % (dateprompt, key))
    #
    for _dn in common_keys:
        paths_l2 = dict_get_paths(last2_query_results[_dn])
        paths_l1 = dict_get_paths(last1_query_results[_dn])
        #
        attrs_diff = []
        for p in paths_l1:
            if p[-1].lower() not in ignored_keys:
                value_before = dict_path_access(last2_query_results[_dn], p)
                value_after = dict_path_access(last1_query_results[_dn], p)
                if value_after != value_before:
                    attrs_diff.append((p, value_after, value_before))
        #
        if len(attrs_diff) != 0:
            # Print DN
            logger.print("%s \x1b[94m%s\x1b[0m" % (dateprompt, _dn))
            for _ad in attrs_diff:
                path, value_after, value_before = _ad
                attribute_path = "─>".join(["\"\x1b[93m%s\x1b[0m\"" % attr for attr in path])
                if any([ik in path for ik in ignored_keys]):
                    continue
                if type(value_before) == list:
                    value_before = [
                        v.strftime("%Y-%m-%d %H:%M:%S")
                        if isinstance(v, datetime.datetime)
                        else v
                        for v in value_before
                    ]
                if type(value_after) == list:
                    value_after = [
                        v.strftime("%Y-%m-%d %H:%M:%S")
                        if isinstance(v, datetime.datetime)
                        else v
                        for v in value_after
                    ]
                if value_after is not None and value_before is not None:
                    logger.print(" | Attribute %s changed from '\x1b[96m%s\x1b[0m' to '\x1b[96m%s\x1b[0m'" % (attribute_path, value_before, value_after))
                elif value_after is None and value_before is not None:
                    logger.print(" | Attribute %s = '\x1b[96m%s\x1b[0m' was deleted." % (attribute_path, value_before))
                elif value_after is not None and value_before is None:
                    logger.print(" | Attribute %s = '\x1b[96m%s\x1b[0m' was created." % (attribute_path, value_after))


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Monitor LDAP changes live!')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    parser.add_argument("-l", "--logfile", dest="logfile", type=str, default=None, help="Log file to save output to.")
    parser.add_argument("-s", "--page-size", dest="page_size", type=int, default=1000, help="Page size.")
    parser.add_argument("-S", "--search-base", dest="search_base", type=str, default=None, help="Search base.")
    parser.add_argument("-r", "--randomize-delay", dest="randomize_delay", action="store_true", default=False, help="Randomize delay between two queries, between 1 and 5 seconds.")
    parser.add_argument("-t", "--time-delay", dest="time_delay", type=int, default=1, help="Delay between two queries in seconds (default: 1).")
    parser.add_argument("--ignore-user-logon", dest="ignore_user_logon", action="store_true", default=False, help="Ignores user logon events.")
    # parser.add_argument("-n", "--notify", dest="notify", action="store_true", default=False, help="Uses LDAP_SERVER_NOTIFICATION_OID to get only changed objects. (useful for large domains).")

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', dest="dc_ip", action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument('--kdcHost', dest="kdcHost", action='store', metavar="FQDN KDC", help='FQDN of KDC for Kerberos.')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument('--no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument('--aes-key', dest="auth_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    if args.auth_password is None and args.no_pass == False and args.auth_hashes is None:
        print("[+] No password of hashes provided and --no-pass is '%s'" % args.no_pass)
        from getpass import getpass
        if args.auth_domain is not None:
            args.auth_password = getpass("  | Provide a password for '%s\\%s':" % (args.auth_domain, args.auth_username))
        else:
            args.auth_password = getpass("  | Provide a password for '%s':" % args.auth_username)

    return args


def query_all_naming_contexts(ldap_server, ldap_session, logger, page_size, search_base=None):
    results = {}
    if search_base is not None:
        naming_contexts = [search_base]
    else:
        naming_contexts = ldap_server.info.naming_contexts
    for nc in naming_contexts:
        lc = LDAPConsole(ldap_server, ldap_session, nc, logger=logger, page_size=page_size)
        _r = lc.query("(objectClass=*)", attributes=['*'])
        for key in _r.keys():
            if key not in results:
                results[key] = _r[key]
            else:
                print("[debug] key already exists: %s (this shouldn't be possible)" % key)
    return results


if __name__ == '__main__':
    args = parse_args()
    logger = Logger(debug=args.debug, nocolors=args.no_colors, logfile=args.logfile)
    logger.print("[+]======================================================")
    logger.print("[+]    LDAP live monitor v1.3        @podalirius_        ")
    logger.print("[+]======================================================")
    logger.print()

    auth_lm_hash = ""
    auth_nt_hash = ""
    if args.auth_hashes is not None:
        if ":" in args.auth_hashes:
            auth_lm_hash = args.auth_hashes.split(":")[0]
            auth_nt_hash = args.auth_hashes.split(":")[1]
        else:
            auth_nt_hash = args.auth_hashes
    
    if args.auth_key is not None:
        args.use_kerberos = True
    
    if args.use_kerberos is True and args.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()

    try:
        logger.print("[>] Trying to connect to %s ..." % args.dc_ip)
        ldap_server, ldap_session = init_ldap_session(
            auth_domain=args.auth_domain,
            auth_dc_ip=args.dc_ip,
            auth_username=args.auth_username,
            auth_password=args.auth_password,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            auth_key=args.auth_key,
            use_kerberos=args.use_kerberos,
            kdcHost=args.kdcHost,
            use_ldaps=args.use_ldaps
        )

        logger.debug("Authentication successful!")

        last2_query_results = query_all_naming_contexts(ldap_server, ldap_session, logger, args.page_size, args.search_base)
        last1_query_results = last2_query_results

        logger.print("[>] Listening for LDAP changes ...")
        running = True
        while running:
            if args.randomize_delay == True:
                delay = random.randint(1000, 5000) / 1000
            else:
                delay = args.time_delay
            logger.debug("Waiting %s seconds" % str(delay))
            time.sleep(delay)
            #
            last2_query_results = last1_query_results
            last1_query_results = query_all_naming_contexts(ldap_server, ldap_session, logger, args.page_size)
            #
            diff(last1_query_results, last2_query_results, logger=logger, ignore_user_logon=args.ignore_user_logon)

    except Exception as e:
        raise e
