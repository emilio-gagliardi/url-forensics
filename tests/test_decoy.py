import unittest

from url_forensics.cli import _cell_summary
from url_forensics.evidence import (analyze, destination_stats, extract_content, payload,
                                    refresh_destination, response_shape)
from url_forensics.network import client_headers

TOKEN = 'ea9a6f9af8724d21abaa3aefaf949fc4'


def decoy(url, extra=''):
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="0;url={url}"><title>Redirecting...</title>'
            f'<script>window.location.replace("{url}");</script></head><body></body></html>{extra}')


def capture(html, status=200):
    data = html.encode()
    body = payload(data, 262144, 'text/html')
    return {'stop_reason': 'final_response', 'requests': [{
        'url': 'https://example.test/x', 'hop': 0,
        'http': {'status': status, 'payload': body,
                 'content_indicators': extract_content(body['data'], 'https://example.test/x')}}]}


class ExtractionTests(unittest.TestCase):
    def test_refresh_destination(self):
        self.assertEqual(refresh_destination('0;url=https://a.test/'), 'https://a.test/')
        self.assertIsNone(refresh_destination('5'))

    def test_js_navigation_extracted(self):
        items = extract_content(decoy('https://www.example.org/'), 'https://x.test/')['links_and_forms']
        self.assertIn('https://www.example.org/', [i.get('js_navigation') for i in items])

    def test_beacon_token_from_attribute(self):
        html = decoy('https://a.test/', f"<script defer src='https://static.cloudflareinsights.com/beacon.min.js/v1' data-cf-beacon='{{\"token\": \"{TOKEN}\"}}'></script>")
        found = extract_content(html, 'https://x.test/')['identifiers']
        self.assertEqual([i['token'] for i in found], [TOKEN])
        self.assertEqual(found[0]['kind'], 'cloudflare_web_analytics_token')

    def test_beacon_token_ignores_non_hex(self):
        html = '<script data-cf-beacon=\'{"token": "not-a-token"}\'></script>'
        self.assertEqual(extract_content(html, 'https://x.test/')['identifiers'], [])

    def test_shape_ignores_destination_and_beacon_but_not_content(self):
        beacon = f"<script src='https://static.cloudflareinsights.com/beacon.min.js/v1' data-cf-beacon='{{\"token\": \"{TOKEN}\"}}'></script>"
        self.assertEqual(response_shape(decoy('https://a.test/')), response_shape(decoy('https://b.test/')))
        self.assertEqual(response_shape(decoy('https://a.test/')), response_shape(decoy('https://b.test/', beacon)))
        self.assertNotEqual(response_shape(decoy('https://a.test/')),
                            response_shape(decoy('https://a.test/') + '<form action="/login"></form>'))


class StatsTests(unittest.TestCase):
    def test_counts_and_estimate_for_report_data(self):
        hosts = (['aljazeera.com'] * 5 + ['theguardian.com'] * 3 + ['euronews.com'] * 3 + ['britannica.com'] * 2
                 + ['nasa.gov'] * 2 + ['weather.com'] * 2 + ['reuters.com'] * 2 + ['bbc.com'])
        stats = destination_stats([f'https://www.{h}/' for h in hosts][:20])
        self.assertEqual(stats['samples'], 20)
        self.assertEqual(stats['distinct'], 8)
        self.assertAlmostEqual(stats['estimated_pool_size'], 8.0, delta=0.5)

    def test_empty(self):
        self.assertEqual(destination_stats([])['estimated_pool_size'], 0)


class TriageTests(unittest.TestCase):
    def report(self, captures, **extra):
        return dict({'mode': 'http', 'http': captures[0], 'http_repeats': captures}, **extra)

    def test_single_decoy_is_inconclusive_not_low(self):
        a = analyze(self.report([capture(decoy('https://a.test/'))]))
        self.assertEqual(a['risk_level'], 'inconclusive')
        self.assertEqual(a['delivery_stage'], 'decoy_redirect_only')

    def test_varying_destinations_flagged_medium_with_token_indicator(self):
        beacon = f"<script data-cf-beacon='{{\"token\": \"{TOKEN}\"}}'></script>"
        a = analyze(self.report([capture(decoy('https://a.test/', beacon)), capture(decoy('https://b.test/'))]))
        codes = {f['code']: f['severity'] for f in a['findings']}
        self.assertEqual(codes['varying_client_redirect'], 'medium')
        self.assertEqual(codes['cloudflare_web_analytics_token'], 'info')
        self.assertEqual(a['risk_level'], 'medium')
        self.assertEqual(a['identifiers'][0]['token'], TOKEN)

    def test_real_content_is_not_decoy(self):
        html = '<html><body><form action="/login"><input type="password"></form></body></html>'
        a = analyze(self.report([capture(html)]))
        self.assertEqual(a['delivery_stage'], 'content_observed')
        self.assertNotEqual(a['risk_level'], 'inconclusive')

    def test_matrix_difference_detected(self):
        decoys = [capture(decoy(f'https://{h}.test/')) for h in 'abc']
        real = [capture('<html><body>' + 'x' * 5000 + '</body></html>') for _ in range(3)]
        cells = [_cell_summary('tool', 'tool', None, decoys), _cell_summary('chrome', 'chrome-windows', None, real)]
        a = analyze(self.report(decoys, matrix={'cells': cells}))
        self.assertIn('matrix_response_difference', [f['code'] for f in a['findings']])

    def test_matrix_no_difference_recorded_as_gap(self):
        cells = [_cell_summary(n, 'tool', None, [capture(decoy(f'https://{h}.test/')) for h in 'ab']) for n in ('one', 'two')]
        a = analyze(self.report([capture(decoy('https://a.test/'))], matrix={'cells': cells}))
        self.assertNotIn('matrix_response_difference', [f['code'] for f in a['findings']])
        self.assertTrue(any('same response shapes' in g['reason'] for g in a['collection_gaps']))


class HeaderTests(unittest.TestCase):
    def test_tool_profile_is_identifying(self):
        h = client_headers('tool')
        self.assertTrue(h['User-Agent'].startswith('URL-Forensics'))
        self.assertNotIn('Referer', h)

    def test_chrome_profile_has_navigation_headers_and_referer(self):
        h = client_headers('chrome-windows', referer='https://mail.google.com/', accept_language='en-CA')
        self.assertIn('Windows NT 10.0', h['User-Agent'])
        self.assertEqual(h['sec-ch-ua-platform'], '"Windows"')
        self.assertEqual(h['Sec-Fetch-Site'], 'cross-site')
        self.assertEqual(h['Referer'], 'https://mail.google.com/')
        self.assertEqual(h['Accept-Encoding'], 'identity')

    def test_no_referer_means_sec_fetch_site_none(self):
        self.assertEqual(client_headers('chrome-linux')['Sec-Fetch-Site'], 'none')

    def test_unknown_profile_and_bad_referer_rejected(self):
        with self.assertRaises(ValueError):
            client_headers('curl')
        with self.assertRaises(ValueError):
            client_headers('chrome-linux', referer='file:///etc/passwd')


def browser_response(url, html, ctype='text/html; charset=utf-8', status=200):
    body = payload(html.encode(), 262144, ctype)
    return {'url': url, 'status': status, 'headers': {'content-type': ctype}, 'payload': body,
            'content_indicators': extract_content(body['data'], url)}


class ReviewRegressionTests(unittest.TestCase):
    def test_browser_landing_page_changes_delivery_stage(self):
        login = '<html><body><form action="/post"><input type="password"></form></body></html>'
        report = {'mode': 'browser', 'http': capture(decoy('https://www.example.org/')),
                  'browser': [{'profile': 'linux', 'requests': [], 'responses': [
                      browser_response('https://landing.test/login', login)]}]}
        a = analyze(report)
        self.assertEqual(a['delivery_stage'], 'content_observed')
        self.assertNotEqual(a['risk_level'], 'inconclusive')

    def test_browser_arrival_at_decoy_target_is_not_a_landing_page(self):
        news = '<html><body><h1>News</h1>' + 'x' * 3000 + '</body></html>'
        report = {'mode': 'browser', 'http': capture(decoy('https://www.example.org/')),
                  'browser': [{'profile': 'linux', 'requests': [], 'responses': [
                      browser_response('https://www.example.org/', news)]}]}
        self.assertEqual(analyze(report)['delivery_stage'], 'decoy_redirect_only')

    def test_malformed_destinations_do_not_abort_analysis(self):
        html = decoy('http://[')
        content = extract_content(html, 'https://x.test/')
        self.assertTrue(content['links_and_forms'])
        stats = destination_stats(['http://[', 'https://ok.test/'])
        self.assertEqual(stats['distinct'], 2)
        a = analyze({'mode': 'http', 'http': capture(html), 'http_repeats': [capture(html), capture(decoy('https://ok.test/'))]})
        self.assertIn('varying_client_redirect', [f['code'] for f in a['findings']])

    def test_binary_and_empty_text_signatures_are_distinct(self):
        def cap(data, ctype):
            return {'requests': [{'http': {'status': 200, 'payload': payload(data, 1000, ctype)}}]}
        image = _cell_summary('a', 'tool', None, [cap(b'\x00\x01', 'application/octet-stream')])['signatures']
        exe = _cell_summary('b', 'tool', None, [cap(b'MZ\x90\x00', 'application/octet-stream')])['signatures']
        empty = _cell_summary('c', 'tool', None, [cap(b'', 'text/html')])['signatures']
        self.assertEqual(len({image[0], exe[0], empty[0]}), 3)
        self.assertTrue(empty[0].startswith('200:text:'))


if __name__ == '__main__':
    unittest.main()

class CloudflareShapeNormalizationTests(unittest.TestCase):
    def test_volatile_error_fields_do_not_change_shape(self):
        from url_forensics.evidence import response_shape
        template = '<h1>Error 520</h1><span>Cloudflare Ray ID: <strong>{ray}</strong></span><span>Your IP: {ip}</span><div>{date} UTC</div>'
        one = template.format(ray='abcde12345abcdef', ip='192.0.2.1', date='2026-11-11 00:20:01')
        two = template.format(ray='12345abcdef12345', ip='198.51.100.1', date='2026-11-11 00:30:02')
        self.assertEqual(response_shape(one), response_shape(two))
        self.assertNotEqual(response_shape(one), response_shape(two.replace('Error 520', 'Error 403')))
