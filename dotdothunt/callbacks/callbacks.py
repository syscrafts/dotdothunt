# dotdothunt/callbacks/callbacks.py
def print_http_result(result):
    status = result['status']
    size = result['size']
    url = result['url']
    
    if status == 200:
        print(f"[200] Size: {size:<6} URL: {url}")
