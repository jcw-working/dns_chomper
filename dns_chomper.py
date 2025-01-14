#!/bin/python3
 
import dns.zone
import dns.resolver
import time
import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #so we don't throw an error when we check the dkim record site
import sys

custy = dns.resolver.Resolver()
custy.nameservers = ['8.8.8.8']

def generic_try(friend,type,timer,dns_out):
    try:
        answer = custy.resolve(friend, type)
        for server in answer:
            dns_out.append([server.to_text(),type,friend])
    except:
        pass
    return dns_out

def inverse_try(friend,type,timer,dns_out):
    try:
        answer = custy.resolve(friend, type)
        for server in answer:
            dns_out.append([friend,type,server.to_text()])
    except:
        pass
    return dns_out
    
def service_try(friend,type,timer,dns_out):
    possible_service = ['_gc._tcp.','_kerberos._tcp.','_kerberos._udp.','_ldap._tcp.','_test._tcp.','_sips._tcp.','_sip._udp.','_sip._tcp.','_aix._tcp.','_aix._tcp.','_finger._tcp.','_ftp._tcp.','_http._tcp.','_nntp._tcp.','_telnet._tcp.','_whois._tcp.','_h323cs._tcp.','_h323cs._udp.','_h323be._tcp.','_h323be._udp.','_h323ls._tcp.','_https._tcp.','_h323ls._udp.','_sipinternal._tcp.','_sipinternaltls._tcp.','_sip._tls.','_sipfederationtls._tcp.','_jabber._tcp.','_xmpp-server._tcp.','_xmpp-client._tcp.','_imap.tcp.','_certificates._tcp.','_crls._tcp.','_pgpkeys._tcp.','_pgprevokations._tcp.','_cmp._tcp.','_svcp._tcp.','_crl._tcp.','_ocsp._tcp.','_PKIXREP._tcp.','_smtp._tcp.','_hkp._tcp.','_hkps._tcp.','_jabber._udp.','_xmpp-server._udp.','_xmpp-client._udp.','_jabber-client._tcp.','_jabber-client._udp.','_kerberos.tcp.dc._msdcs.','_ldap._tcp.ForestDNSZones.','_ldap._tcp.dc._msdcs.','_ldap._tcp.pdc._msdcs.','_ldap._tcp.gc._msdcs.','_kerberos._tcp.dc._msdcs.','_kpasswd._tcp.','_kpasswd._udp.','_imap._tcp.','_imaps._tcp.','_submission._tcp.','_pop3._tcp.','_pop3s._tcp.','_caldav._tcp.','_caldavs._tcp.','_carddav._tcp.','_carddavs._tcp.','_x-puppet._tcp.','_x-puppet-ca._tcp.','_autodiscover._tcp.']
    for service in possible_service:
        friendly = (service + friend)
        try:
            answer = custy.resolve(friendly, type)
            for server in answer:
                dns_out.append([friend,type,(friendly + " " + (server.to_text()).rstrip("."))])
        except:
            pass
        time.sleep(timer/2)
    return dns_out

def cname_try(friend,type,timer,dns_out):
    try:
        answer = custy.resolve(friend, type)
        for server in answer:
            dns_out.append([friend,type,(server.to_text()).rstrip(".")])
    except:
        pass
    return dns_out

def complex_try(friend,type,timer,dns_out):
    zone_transfer_record = []
    try:
        answer = custy.resolve(friend,type)
        for server in answer:
            ip_answer = custy.resolve(server.target,'A')
            for ip in ip_answer:
                dns_out.append([ip.to_text(),type,(server.to_text()).rstrip(".")])
                try:
                    zone_transfer_attempt = dns.zone.from_xfr(dns.query.xfr(str(ip),friend))
                    zone_transfer_record.append([(server.to_text()).rstrip("."),str(ip),"POSSIBLE Zone Transfer"])
                    time.sleep(timer/2)
                except:
                    zone_transfer_record.append([(server.to_text()).rstrip("."),str(ip),"Zone Transfer Unsuccessful"])
            time.sleep(timer/2)

        for server in answer:
            print("[-]   Currently cannot make zone transfer attempts against IPv6.")
            ip_answer = custy.resolve(server.target,'AAAA')
            for ip in ip_answer:
                dns_out.append([ip.to_text(),type,(server.to_text()).rstrip(".")])
                # try:
                #     zone_transfer_attempt = dns.zone.from_xfr(dns.query.xfr(str(ip),friend))
                #     zone_transfer_record.append([(server.to_text()).rstrip("."),str(ip),"POSSIBLE Zone Transfer"])
                #     time.sleep(timer/2)
                # except:
                #     zone_transfer_record.append([(server.to_text()).rstrip("."),str(ip),"Zone Transfer Unsuccessful"])
            time.sleep(timer/2)
    except:
        pass
    return dns_out,zone_transfer_record

def mx_try(friend,type,timer,dns_out):
    try:
        answer = custy.resolve(friend,type)
        for pre_server in answer:
            server = (pre_server.exchange.to_text()).rstrip(".")
            ip_answer = custy.resolve(server,'A')
            for ip in ip_answer:
                dns_out.append([ip.to_text(),type,server])
            time.sleep(timer/2)
       
        for pre_server in answer:
            server = (pre_server.exchange.to_text()).rstrip(".")
            ip_answer = custy.resolve(server,'AAAA')
            for ip in ip_answer:
                dns_out.append([ip.to_text(),type,server])
            time.sleep(timer/2)
    except:
        pass
    return dns_out

def txt_try(domainTarget,type,timer,dns_out):
    rec_types = ['TXT','DS','RRSIG','CAA','DNSKEY','SIG','HINFO']
    for rec in rec_types:
        inverse_try(domainTarget,rec,timer,dns_out)
        time.sleep(timer/2)

    dmarc_target = "_dmarc." + domainTarget
    inverse_try(dmarc_target,'TXT',timer,dns_out)
    return dns_out

def dns_chomper(domainTarget,timer):
    dns_out = []
    zone_transfer_record = []
    
    records = [
    ['A', generic_try],
    ['AAAA', generic_try],
    ['CNAME', cname_try],
    ['MX', mx_try],
    ['SOA', inverse_try],
    ['SRV', service_try],
    ['TXT', txt_try]
    ]

    for record in records:
        print("[+]   Checking {} records".format(record[0]))
        dns_out = record[1](domainTarget,record[0],timer,dns_out)
        time.sleep(timer)
    print("[+]   Checking NS and Zone Transfer records")
    dns_out,zone_transfer_record = complex_try(domainTarget,'NS',timer,dns_out)

    print("\n[+]   DNS Records for {}\n".format(domainTarget))

    dns_out.sort(key=lambda x: (x[1],x[2],x[0]))

    # DMARC line inclusion

    extra_dmarc_line = None
    for record in dns_out:
        if record[0] == ("_dmarc." + domainTarget):
            extra_dmarc_line = '|'.join(record)
        else:
            print('|'.join(record))
    
    if extra_dmarc_line != None:
        print(extra_dmarc_line)

    # Complex procedure for scraping DKIM records off the website
        
    try:
        url = 'https://easydmarc.com/tools/dkim-lookup/status?domain=' + domainTarget + '&selector=auto&is_embed=true'

        pagePull=requests.get(url, verify=False, timeout=30).text
        soup = BeautifulSoup(pagePull, 'html.parser')

        selector_tag = soup.find_all("span", {"class":"fw-bold"})
        dkim_tag = soup.find_all("span", {"class":"font-family-ibm-plex-mono fs-300"})

        for selector, dkim in zip(selector_tag, dkim_tag):
            print("{}._domainkey.{}|TXT|\"{}\"".format(selector.get_text(), domainTarget, dkim.get_text()))

    except:
        print("\n[-]     Call to website for DKIM records failed.")

    print("\n\n[+]     Zone transfer attempts for {}\n".format(domainTarget))
    for record in zone_transfer_record:
        print('|'.join(record))

print("[+]   DNS Record Survey\n")
dns_chomper(sys.argv[1],1)
print("\n")