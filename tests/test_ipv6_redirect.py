import unittest
from modules.web_security import WebSecurity
from unittest import mock
class Ipv6RedirectTests(unittest.TestCase):
 def test_ipv6_hosts_are_bracketed_in_http_probe_urls(self):
  with mock.patch('modules.web_security.requests.get',return_value=mock.Mock(url='https://[::1]/')) as get:
   self.assertTrue(WebSecurity('https://[::1]:8443').check_http_redirect())
   self.assertEqual(get.call_args.args[0],'http://[::1]/')
