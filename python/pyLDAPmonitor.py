#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldapmonitor.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Oct 2021

import argparse
import os
import sys
import ssl
import random
import ldap
import ldap3
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3.protocol.formatters.formatters import format_sid
import time
import datetime
import re


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

    def query(self, query, attributes=['*'], quiet=False):
        # controls
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
        LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
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


def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)

    if args.use_kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.auth_key, kdcHost=args.dc_ip)
    elif args.auth_hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(logger, args, domain, username, password, lmhash, nthash):
    if args.use_kerberos:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain
    logger.print("[>] Trying to connect to %s ..." % target)
    if args.use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash)


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                print('[debug] Domain retrieved from CCache: %s' % domain)

            print('[debug] Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    print('[debug] Using TGT from cache')
                else:
                    print('[debug] No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                print('[debug] Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                print('[debug] Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                print('[debug] Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


def diff(last1_query_results, last2_query_results, logger, ignore_user_logon=False):
    ignored_keys = []
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
        if key not in last2_query_results.keys():
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
    parser.add_argument("-r", "--randomize-delay", dest="randomize_delay", action="store_true", default=False, help="Randomize delay between two queries, between 1 and 5 seconds.")
    parser.add_argument("-t", "--time-delay", dest="time_delay", type=int, default=1, help="Delay between two queries in seconds (default: 1).")
    parser.add_argument("--ignore-user-logon", dest="ignore_user_logon", action="store_true", default=False, help="Ignores user logon events.")

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', dest="dc_ip", action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
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
    return args


if __name__ == '__main__':
    args = parse_args()
    logger = Logger(debug=args.debug, nocolors=args.no_colors, logfile=args.logfile)
    logger.print("[+]======================================================")
    logger.print("[+]    LDAP live monitor v1.1        @podalirius_        ")
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
    try:
        ldap_server, ldap_session = init_ldap_session(
            logger=logger,
            args=args,
            domain=args.auth_domain,
            username=args.auth_username,
            password=args.auth_password,
            lmhash=auth_lm_hash,
            nthash=auth_nt_hash
        )

        logger.debug("Authentication successful!")
        if "." not in args.auth_domain:
            args.auth_domain += ".local"
        dn = ','.join(["DC=%s" % part for part in args.auth_domain.split('.')])

        lc = LDAPConsole(ldap_server, ldap_session, dn, logger=logger, page_size=args.page_size)

        last2_query_results = lc.query("(objectClass=*)", attributes=['*'])
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
            last1_query_results = lc.query("(objectClass=*)", attributes=['*'])
            diff(last1_query_results, last2_query_results, logger=logger, ignore_user_logon=args.ignore_user_logon)

    except Exception as e:
        raise e
