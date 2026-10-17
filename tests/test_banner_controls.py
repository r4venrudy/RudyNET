import unittest
from modules.port_scanner import clean_banner
class BannerControlTests(unittest.TestCase):
 def test_service_banners_cannot_forward_terminal_controls(self):
  self.assertEqual(clean_banner(b'\x1b[31mSSH-2.0\x1b[0m\x07\x00\r\nnext'),'SSH-2.0')
  self.assertEqual(clean_banner('Örnek'.encode()),'Örnek')
