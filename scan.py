#!/usr/bin/python3
import time
import socket
import sublist3r
import queue
import subprocess
import threading
import argparse
import sys

def gethostname_wrapper(domain):
    try:
        gethostname = socket.gethostbyname_ex(domain)
    except socket.gaierror:
        print("domain %s not known" % domain)
        return []
    return gethostname[2]

def get_sub_domains(domain, threads):
    return [domain] + sublist3r.main(domain, threads, savefile='./'+ domain + '/dns', ports= None, silent=False, verbose= False, enable_bruteforce=False, engines='Bing,Baidu,Yahoo,Virustotal')

def get_ip_from_domains(domains):
    return sum([gethostname_wrapper(domain) for domain in domains], [])


def main(domain, sublist3r_threads, nmap_threads):
    subprocess.run(['mkdir', '-p', domain])
    sem = threading.Semaphore(nmap_threads)
    def nmap_run(domain, ip):
        while True:
            if sem.acquire():
                subprocess.run(['nmap', '-sSV', '-p-', ip, '-oA', './' + domain + '/' + ip, '-T4'])
                sem.release()
                break
            else:
                time.sleep(1)
    for ip in get_ip_from_domains(get_sub_domains(domain, sublist3r_threads)):
        t = threading.Thread(target=nmap_run, args=(domain, ip,))
        t.start()
    while True:
        if threading.activeCount() == 1:
            exit(0)
        else:
            time.sleep(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.add_argument('-d', '--domain', dest='domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-t', '--sublist3r-threads', dest='sublist3r_threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-n', '--nmap-threads', dest='nmap_threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    args = parser.parse_args()
    main(args.domain, args.sublist3r_threads, args.nmap_threads)


