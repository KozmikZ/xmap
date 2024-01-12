import urllib3
import re,requests
from selenium import webdriver
from lib.url import Url
from lib.utils import rndhead
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from lib.vulnerability import Vulnerability
CGREEN  = '\33[32m' # terminal color pallete
CRED = '\033[91m'
CEND = '\033[0m'
OKBLUE = '\033[94m'
BOLD = '\033[1m'

def pops_alert(url:str,driver:webdriver.Firefox,payload:str)->bool:
    """
    Opens a url in a webdriver and then checks if it can switch its focus to the alert box
    If there is no alert/prompt box, an exception raised and pops_alert returns False
    """
    driver.get(url)
    try: # try to check for an alert, an exception will be raised if no alert is found
        al = driver.switch_to.alert 
        al.dismiss() # to enable more browser get requests
        return True
    except: # no alert found ... testing a different method
        click_triggered = re.findall(r"(onmouseover|onclick|onfocus)",payload) # trying if it is perhaps user triggered
        if click_triggered!=None and payload[0]=="<": # if payload is trigger based and is an html element, not a direct script injection, click it!
            for el in driver.find_elements(by=By.CSS_SELECTOR,value="*"):
                try: # if no alert is present or a different sElEniUUm error occurs 
                    if el.text=="test":
                            el.click()
                            al = driver.switch_to.alert
                            al.dismiss() # to enable more browser get requests
                            return True
                except:
                    pass
        return False




def scan_url_parameter(url:str,p,depth:int=None,manual:bool=False,verbose:bool=False,payload_list_path:str="lib/payloads/payload_list.txt")->list[str]: # returns all working rxss links for a given parameter and url
    """
    I use the payload list file to test every payloads reflection (depending on the depth, a number of payloads is tested)
    I then check for exact reflections in the site, those not tampered with by the back-end/front-end
    After I'm finished, I test every perfectly reflected payload for a popup window. If such window is detected, the software has found a vulnerability
    """
    print(f"Scanning parameter {BOLD+CGREEN+p+CEND} in website: {BOLD+CGREEN+str(url)+CEND}")

    # first test if parameter reflects on site:
    url:Url = Url(url)
    url.inject(p,"rnT3xqw") # injecting the payload into the url
    resp = requests.get(url.__repr__(),headers={"User-Agent":rndhead()})
    reflections = re.finditer(string=str(resp.content),pattern=r"rnT3xqw")
    if len(list(reflections))==0:
        print("No reflections found, exiting")
        return []

    
    vulnerable_to_payloads = [] # only possible reflections, not tested yet, the software needs to examine these reflections
    tolerance=0
    with open(payload_list_path,"r") as p_fi:
        dbg_c = 0
        locator_string = "sL3a" # used to locate reflected payloads with regex
        terminator_string="4jQn"
        stop=False
        payload_list = p_fi.readlines()

        if depth==None:
            depth = len(payload_list)
        else:
            ln = len(payload_list)
            if depth>ln:
                raise "Error: brute force depth exceeded payload list length"
        for payload in payload_list[:depth]:
            if stop:
                break
            dbg_c+=1
            payload = payload[:-1] # removing \n to prevent it getting injected
            if verbose:
                print(f"Testing payload: {CGREEN + payload + CEND}") # verbose log

            url.inject(p,locator_string+payload+terminator_string) # injecting the payload into the url
            resp = requests.get(url.__repr__(),headers={"User-Agent":rndhead()})
            reflections,status = re.finditer(string=str(resp.content),pattern=r"sL3a.*?4jQn"),resp.status_code # find the terminator and locator strings and whatever is in between
            

            if verbose==False and dbg_c%100 == 0 :
                print(f"Tested {CGREEN+str(dbg_c)+CEND} payloads...")
            elif verbose==True and dbg_c%10 == 0:
                print(f"Tested {CGREEN+str(dbg_c)+CEND} payloads...")

            if status==200:
                tolerance=0
                r_list =list(reflections) # necessary to obtain match objects
                r_count = len(r_list)
                if r_count!=0:
                    perfect= False # perfect reflection boolean, prevents clogging the vulnerable_to_payloads list
                    for r in r_list:
                        st,en = r.span() # start and end of the reflection
                        str_reflection = str(resp.content)[st+4:en-4] # the reflection string
                        if str_reflection==payload:
                            if verbose:
                                print(CGREEN+f"Found possible XSS reflection for parameter {BOLD+p}"+CEND) # verbose log
                                print(OKBLUE+f"With payload " + CRED + payload +CEND)
                                if manual:
                                    if input("Do you want to test payloads now?[y/n]")=="y":
                                        stop=True
                            perfect = True
                    if perfect:
                        vulnerable_to_payloads.append(payload)
            else:
                print(CRED+f"Issue? when testing payload {payload}. Network or Security..."+CEND)
                tolerance+=1
                if tolerance>100 and manual==False:
                    print("Site is most likely blocking our requests...")
                    print("Basic tests failed")
                    return [] 
                elif tolerance>100 and manual==True:
                    if input("Do you want to continue scanning, site looks to be blocking our requests. [y/n]")=="y":
                        tolerance=0
                    else:
                        return []     
                
        options = Options() # setting up the webdriver, so we dont have to reopen it everytime the function is ran
        options.add_argument('--headless')
        options.add_argument("--incognito")
        try:
            geckodriver_path = "/snap/bin/geckodriver"  # specify the path to your geckodriver -> unfortunately have to do that since it cannot find it otherwise (firefox is installed with snap, selenium is not used to that)
            driver_service = Service(executable_path=geckodriver_path)
            driver = webdriver.Firefox(options=options,service=driver_service) 
        except:
            driver = webdriver.Firefox(options=options) 
        rxss_vulns: list[Vulnerability] = []

        print(f"Found {len(vulnerable_to_payloads)} reflections")
        print("Analyzing...")

        for payload in vulnerable_to_payloads:
            url.inject(p,payload)
            if pops_alert(str(url),driver,payload):
                print(CRED+BOLD+"FOUND AND CONFIRMED XSS VULNERABILITY, PAYLOAD:"+CEND)
                print(OKBLUE+BOLD+payload+CEND)
                print("Link: "+CGREEN+str(url)+CEND)
                if manual and input("Continue scanning?[y/n]")=="n":
                    return rxss_vulns
                rxss_vulns.append(Vulnerability(p,str(url),payload))
        driver.quit()

    if len(rxss_vulns)==0:
        print("No XSS payloads confirmed")

    return rxss_vulns



def scan_url_parameter_brute(url:str,p,depth:int,manual:bool=False,verbose:bool=False,payload_list_path:str="lib/payloads/payload_list.txt")->list[str]:
    print(f"Testing THOROUGHLY for parameter {BOLD+CGREEN+p+CEND} in website: {BOLD+CGREEN+str(url)+CEND}")
    print("Warning! This method does not check for the site responses, therefore does not prevent the site from banning your IP")
    url:Url = Url(url)

    options = Options() # setting up the webdriver, so we dont have to reopen it everytime the function is ran
    options.add_argument('--headless')
    options.add_argument("--incognito")
    try:
        geckodriver_path = "/snap/bin/geckodriver"  # specify the path to your geckodriver -> unfortunately have to do that since it cannot find it otherwise (firefox is installed with snap, selenium is not used to that)
        driver_service = Service(executable_path=geckodriver_path)
        driver = webdriver.Firefox(options=options,service=driver_service) 
    except:
        try:
            driver = webdriver.Firefox(options=options)
        except:
            raise "It seems that you don't have firefox installed. XMAP cannot definitively prove payloads without it."
    rxss_vulns: list[str] = []

    test_payloads = open(payload_list_path,"r").readlines()
    payloads_tested = 0

    for payload in test_payloads[:depth]:
        payload=payload[:-1]
        payloads_tested+=1
        url.inject(p,payload)
        if verbose==True:
            print(f"Testing {CGREEN+str(url)+CEND}")
        if payloads_tested%10==0:
            print(f"Tested {CGREEN+str(payloads_tested)+CEND} payloads")
        if pops_alert(str(url),driver,payload):
            print(CRED+BOLD+"FOUND AND CONFIRMED XSS VULNERABILITY, PAYLOAD:"+CEND)
            print(OKBLUE+BOLD+payload+CEND)
            print("Link: "+CGREEN+str(url)+CEND)
            if manual and input("Continue scanning?[y/n]")=="n":
                return rxss_vulns
            rxss_vulns.append(Vulnerability(p,str(url),payload))
    driver.quit()
    if len(rxss_vulns)==0:
        print("No XSS payloads confirmed")
    return rxss_vulns


 
    


