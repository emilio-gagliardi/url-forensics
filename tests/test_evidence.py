import unittest
from unittest.mock import patch, MagicMock
from url_forensics.evidence import payload, header_list, analyze, extract_content
from url_forensics.network import http_probe


class EvidenceTests(unittest.TestCase):
    def test_binary_payload_bounded_hash_scope(self):
        p = payload(b'\x00\xff123', 2)
        self.assertEqual(p['data'], 'AP8=')
        self.assertTrue(p['truncated'])
        self.assertEqual(p['captured_bytes'], 2)
        self.assertEqual(p['hash_scope'], 'captured bytes only')

    def test_duplicate_headers_and_redaction(self):
        h = header_list([('Set-Cookie', 'secret'), ('X-Test', 'a'), ('X-Test', 'b')])
        self.assertEqual(h[0]['value'], '[REDACTED]')
        self.assertEqual([x['value'] for x in h[1:]], ['a', 'b'])

    def test_static_client_redirect_and_commands(self):
        data = extract_content('<meta http-equiv="refresh" content="0;url=/next"><script src="/a.js"></script>powershell', 'https://example.org/')
        self.assertEqual(data['links_and_forms'][1]['url'], 'https://example.org/a.js')
        self.assertEqual(data['patterns'][0]['code'], 'shell_execution_reference')

    def test_empty_observation_never_safe(self):
        a = analyze({'mode': 'passive', 'metadata': {'requests': [], 'stop_reason': 'error'}})
        self.assertEqual(a['risk_level'], 'unknown')
        self.assertTrue(a['collection_gaps'])

    @patch('urllib.request.getproxies', return_value={})
    @patch('url_forensics.network._PinnedHTTPS')
    @patch('url_forensics.network.tls_info', return_value={'status': 'verified'})
    @patch('url_forensics.network.resolve_public', return_value=('8.8.8.8', ['8.8.8.8']))
    def test_get_bounded_read_and_unsafe_redirect(self, resolve, tls, cls, proxies):
        response = cls.return_value.getresponse.return_value
        response.status = 302
        response.reason = 'Found'
        response.getheaders.return_value = [('Location', 'file:///tmp/a'), ('Content-Type', 'text/html')]
        response.read.return_value = b'12345'
        result = http_probe('https://example.org/', max_body_bytes=4)
        response.read.assert_called_once_with(5)
        self.assertEqual(result['stop_reason'], 'error')
        self.assertTrue(result['requests'][0]['http']['payload']['truncated'])
        cls.return_value.close.assert_called_once()

    def test_downgrade_risk_evidence(self):
        a = analyze({'mode': 'http', 'http': {'stop_reason': 'final_response', 'requests': [
            {'url': 'https://example.org/', 'http': {}, 'redirect': {'from': 'https://example.org/',
             'to': 'http://example.org/', 'cross_origin': True, 'https_downgrade': True}}]}})
        self.assertEqual(a['risk_level'], 'high')
        self.assertEqual(a['findings'][-1]['evidence'], '/http/requests/0/redirect')
