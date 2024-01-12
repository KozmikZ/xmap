import requests
import bs4
from lib.utils import rndhead,get_url_parameters
from lib.url import Url


def scrape_links(url:str,domain:str): # scrapes all links on a single page that are part of the domain
    response = requests.get(url,headers={"User-Agent":rndhead()})
    links : list[str] = []
    if response.status_code==200:
        site = bs4.BeautifulSoup(response.content,'html.parser')
        anchors = site.find_all("a" or "li")
        for a in anchors:
            href:str = a.attrs.get("href")
            if href!=None and href!="":
                # first check if there is the domain, or if its a relative link, so we don't leave the domain
                if href.startswith(domain):
                    links.append(href)
                elif href[0]=="/":
                    links.append(domain+href)
    else:
        print(f"! Site blocked us ! : {url} ") # debug log
    return links

def crawl_through(inp_start_page:str,depth=100): # scrapes a domain for sites with parameters
    domain = inp_start_page.split("//")[0]+"//"+inp_start_page.split("//")[1].split("/")[0]
    print(f"Crawling starting from website {inp_start_page}")
    print(f"With max depth of {depth} pages")
    visited = {} # bfs variables...
    queue: list[str] = [inp_start_page]
    injectable_pages = {}
    if len(get_url_parameters(inp_start_page))>0: # To add the input to possible injectable pages, as it often happens to be one
        injectable_pages[inp_start_page]=True
    dpmeter = 0
    while len(queue)>0 and dpmeter<depth:
        print(f"Depth reached: {dpmeter}",end='\r') # update terminal line
        dpmeter+=1
        currently_on = queue.pop(0)
        links = scrape_links(currently_on,domain)
        for x in links:
            try:
                if visited.get(x)!=True: # if we have checked this url, don't add it
                    visited[x]=True 
                    queue.append(x)
                    if "=" in x:
                        inj = Url(x) # Set up a url object
                        for x in inj.injection_parameters: # create a repr with empty parameters
                            inj.inject(x,"")
                        injstr = str(inj)
                        if injectable_pages.get(injstr)!=True: # look if it's already been added
                            injectable_pages[injstr]=True
            except:
                print("Passing on failed attempt to check during crawling")
    return injectable_pages
            
    
    
