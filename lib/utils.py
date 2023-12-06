from random import choice
import time
def get_url_parameters(url:str)->dict[str,str]:
    if "=" not in url:
        return []
    try:
        tmp = url.split("?")
        raw_parameters = tmp[1].split("&")
        if "" in raw_parameters:
            raw_parameters.remove("")
        final_params = {}
        for p in raw_parameters:
            key,value = p.split("=")
            final_params[key]=value
        return final_params
    except:
        print(url)
        raise "What is this ^"

def d_index(one,two):
    score = 0
    for x,y in zip(one,two):
        if x!=y:
            score+=1
    return score

def rndhead()->dict:
    headers_list = [
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0'},
    {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'},
    {'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1'},
    {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0'},
    {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15'},
    {'User-Agent': 'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.14900'}
    ]
    return choice(headers_list)['User-Agent']

def performance(func,*args):
    print("Testing performance of function",func)
    m = time.time()
    func(*args)
    m = time.time() - m
    print(str(m)+" seconds")
