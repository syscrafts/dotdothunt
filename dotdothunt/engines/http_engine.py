# dotdothunt/engines/http_engine.py
import aiohttp
import asyncio
import re

class HTTPEngine:
    def __init__(self, url, payloads, callbacks, filters=([], [])):
        self.url = url
        self.payloads = payloads
        self.callbacks = callbacks
        self.filter_codes, self.filter_sizes = filters

    async def run(self):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for payload in self.payloads:
                target_url = self.url.replace('FUZZ', payload)
                tasks.append(self._fetch(session, target_url))
            await asyncio.gather(*tasks)

    async def _fetch(self, session, url):
        try:
            async with session.get(url) as response:
                content = await response.text()
                size = len(content.encode('utf-8'))
                status = response.status
                
                if (status == 200 and 
                    self._passes_filters(status, size) and 
                    self._is_valid_passwd_content(content)):
                    result = {
                        'url': url,
                        'status': status,
                        'size': size,
                        'content': content
                    }
                    for callback in self.callbacks:
                        callback(result)
        except Exception as e:
            pass  # Silently handle exceptions for final version

    def _passes_filters(self, status, size):
        if not self.filter_codes and not self.filter_sizes:
            return True
        
        code_pass = True
        size_pass = True
        
        if self.filter_codes:
            code_pass = any(re.match(fc, str(status)) for fc in self.filter_codes)
        if self.filter_sizes:
            min_size = int(self.filter_sizes[0])  # Take first size as minimum
            size_pass = size >= min_size
        
        return code_pass and size_pass

    def _is_valid_passwd_content(self, content):
        return bool(re.search(r'root:[^:]*:[0-9]+:[0-9]+:', content))
