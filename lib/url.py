from lib.utils import get_url_parameters


class Url:
    def __init__(self,url:str):
        self._url = url
        
        #identify injection points:
        self.injection_parameters : dict = get_url_parameters(url)
    def inject(self,p:str,val:str):
        self.injection_parameters[p]=val
        self._build()
    def _build(self):
        new_url = self._url.split("?")[0]+"?"
        for x in self.injection_parameters:
            new_url+=x+"="+self.injection_parameters[x]+"&"
        self._url=new_url
    def __repr__(self) -> str:
        return self._url


