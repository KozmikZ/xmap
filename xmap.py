#!/usr/bin/env python3
import argparse
from lib.crawl import crawl_through
from lib.core import scan_url_parameter,scan_url_parameter_brute
from lib.url import Url
from lib.core import CEND,CGREEN,BOLD
import sys
parser = argparse.ArgumentParser(description=BOLD+CGREEN+"XMAP"+CEND+" - reflected XSS scanner")
parser.add_argument("-t","--target",help="Your attack point, which you would like to test",required=True)
parser.add_argument("-c","--crawl",help="Option to crawl",action="store_true",default=False)
parser.add_argument("-l","--level",help="How deeply do you want to scan?(1-10,default:1)",default=1,type=int)
parser.add_argument("-m","--manual",help="Do you want to wait for user input on decision making?",action="store_true",default=False)
parser.add_argument("-v","--verbose",action="store_true",default=False)
parser.add_argument("-p","--parameter",help="Specific parameter you want to test on your target")
parser.add_argument("-b","--brute",help="Do you want to brute force scan the website?",action="store_true",default=False)
parser.add_argument("--crawl_depth",help="Manually set the amount of pages XMAP can crawl",type=int,default=30)
parser.add_argument("--scan_depth",help="Manually set the amount of payloads that should be tested",type=int,default=100)
parser.add_argument("--log",help="The file to which you would write down XSS vectors")
parser.add_argument("--payload_list",help="Your own list of payloads in a .txt file",type=str,default="lib/payloads/payload_list")
user_args = parser.parse_args()
attack_point = user_args.target

cdepth: int  = 0
sdepth: int = 0

# setting up values by level
if user_args.level!=1:
    if user_args.crawl_depth==30 and user_args.scan_depth==100:
        cdepth=50*user_args.level
        sdepth=100*user_args.level
    else:
        print("You seem to have set scan or crawl depths manually. Please choose a level, or set depth.")
        sys.exit()
else:
    cdepth=user_args.crawl_depth
    sdepth=user_args.scan_depth


if user_args.crawl:
    # Testing a full website scan using our crawler
    injectable_urls : list[str] = crawl_through(attack_point,depth=cdepth)
    if len(injectable_urls)==0:
        print("No injectable urls found")
    elif user_args.verbose:
        print("Found possible attack vectors",*["\n"+i for i in injectable_urls])
    total_xss_vulnerabilities: list = [] # a list of the final vulnerability objects
    
    for link in injectable_urls:
        link = Url(link)
        for p in link.injection_parameters:
            if user_args.brute:
                for v in scan_url_parameter_brute(str(link),p,depth=sdepth,verbose=user_args.verbose,manual=user_args.manual,payload_list_path=user_args.payload_list):
                    total_xss_vulnerabilities.append(v)
            else:
                for v in scan_url_parameter(str(link),p,depth=sdepth,verbose=user_args.verbose,manual=user_args.manual,payload_list_path=user_args.payload_list):
                    total_xss_vulnerabilities.append(v)
    if len(total_xss_vulnerabilities)>0:
        print("Found xss vulnerabilities")
        if user_args.log!=None:
            with open(user_args.log,"w") as fi:
                fi.writelines([str(v)+"\n" for v in total_xss_vulnerabilities])
    else:
        print("No xss vulnerabilities found")
else:
    url = Url(attack_point)
    total_xss_vulnerabilities=[]
    if user_args.parameter!=None: # single parameter scanning
        if user_args.brute:
            for v in scan_url_parameter_brute(str(url),user_args.parameter,depth=sdepth,verbose=user_args.verbose,manual=user_args.manual,payload_list_path=user_args.payload_list):
                total_xss_vulnerabilities.append(v)
        else:
            for v in scan_url_parameter(str(url),user_args.parameter,depth=sdepth,verbose=user_args.verbose,manual=user_args.manual,payload_list_path=user_args.payload_list):
                total_xss_vulnerabilities.append(v)
    else: # all parameter scanning
        for p in url.injection_parameters: 
            if user_args.brute:
                for v in scan_url_parameter_brute(str(url),p,depth=sdepth,verbose=user_args.verbose,manual=user_args.manual,payload_list_path=user_args.payload_list):
                    total_xss_vulnerabilities.append(v)
            else:
                for v in scan_url_parameter(str(url),p,depth=sdepth,verbose=user_args.verbose,manual=user_args.manual,payload_list_path=user_args.payload_list):
                    total_xss_vulnerabilities.append(v)
    if len(total_xss_vulnerabilities)>0:
        print("Found XSS vulnerabilities")
        if user_args.log!=None:
            with open(user_args.log,"w") as fi:
                fi.writelines([str(v)+"\n" for v in total_xss_vulnerabilities])
    else:
        print("No xss vulnerabilities found")
