import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import proxy_harvester as ph


class ParserTests(unittest.TestCase):
    def test_vless_reality(self):
        uri = (
            "vless://00000000-0000-4000-8000-000000000001@example.com:443"
            "?security=reality&type=tcp&sni=vk.com&fp=chrome&pbk=abc123&sid=1234&flow=xtls-rprx-vision#Test"
        )
        node = ph.parse_uri(uri)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "vless")
        self.assertEqual(node.host, "example.com")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.params["security"], "reality")
        self.assertTrue(ph.sni_matches_allowlist(node))

    def test_vmess_base64_json(self):
        content = {"v": "2", "ps": "old name", "add": "example.com", "port": "443", "id": "00000000-0000-4000-8000-000000000002", "aid": "0", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/edge", "tls": "tls", "sni": "cdn.example.com"}
        encoded = base64.b64encode(json.dumps(content).encode()).decode()
        node = ph.parse_uri("vmess://" + encoded)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "vmess")
        self.assertEqual(node.params["type"], "ws")
        self.assertEqual(node.name, "old name")
        renamed = ph.named_uri(node)
        self.assertTrue(renamed.startswith("vmess://"))
        self.assertIn("Unknown", ph._server_name(node))  # unknown country stays English

    def test_shadowsocks_sip002(self):
        creds = base64.b64encode(b"aes-256-gcm:secret").decode()
        node = ph.parse_uri(f"ss://{creds}@example.com:8443#Name")
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "shadowsocks")
        self.assertEqual(node.username, "aes-256-gcm")
        self.assertEqual(node.password, "secret")

    def test_hysteria2(self):
        node = ph.parse_uri("hysteria2://secret@example.com:443?sni=vk.com&obfs=salamander&obfs-password=abc#hy2")
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "hysteria2")
        self.assertTrue(node.is_udp_only)
        self.assertIsNone(ph.build_xray_outbound(node))
        self.assertEqual(ph.build_singbox_outbound(node)["type"], "hysteria2")

    def test_tuic(self):
        node = ph.parse_uri("tuic://00000000-0000-4000-8000-000000000003:secret@example.com:443?sni=example.com#tuic")
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "tuic")
        self.assertEqual(node.username, "00000000-0000-4000-8000-000000000003")
        self.assertEqual(node.password, "secret")
        self.assertEqual(ph.build_singbox_outbound(node)["type"], "tuic")
        self.assertIsNone(ph.build_xray_outbound(node))

    def test_http_proxy_excluded(self):
        self.assertIsNone(ph.parse_uri("http://user:pass@example.com:8080#http-proxy"))
        self.assertIsNone(ph.parse_uri("https://example.com:443#https-proxy"))

    def test_base64_subscription(self):
        raw = "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls#one\n"
        encoded = base64.b64encode(raw.encode()).decode()
        nodes = ph.extract_uris(encoded)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].protocol, "vless")

    def test_country_flag(self):
        self.assertEqual(ph.country_flag("DE"), "🇩🇪")
        self.assertEqual(ph.country_flag("ZZ"), "🏳️")


    def test_core_configs_pin_validated_ip_and_keep_sni(self):
        uri = (
            "vless://00000000-0000-4000-8000-000000000001@example.com:443"
            "?security=reality&type=tcp&sni=vk.com&fp=chrome&pbk=abc123&sid=1234#test"
        )
        node = ph.parse_uri(uri)
        node.ip = "1.1.1.1"
        xray_out = ph.build_xray_outbound(node)
        self.assertEqual(xray_out["settings"]["vnext"][0]["address"], "1.1.1.1")
        self.assertEqual(xray_out["streamSettings"]["realitySettings"]["serverName"], "vk.com")
        sing_out = ph.build_singbox_outbound(node)
        self.assertEqual(sing_out["server"], "1.1.1.1")
        self.assertEqual(sing_out["tls"]["reality"]["public_key"], "abc123")

    def test_public_source_url_guard(self):
        with self.assertRaises(ValueError):
            ph._assert_public_http_url("http://127.0.0.1:8080/source.txt")
        with self.assertRaises(ValueError):
            ph._assert_public_http_url("http://10.1.2.3/config.txt")

    def test_extra_raw_feed_discovery(self):
        text = "See https://raw.githubusercontent.com/example/repo/main/nodes.txt and https://github.com/example/repo/blob/main/sub.txt"
        feeds = ph.extract_feed_urls(text)
        self.assertIn("https://raw.githubusercontent.com/example/repo/main/nodes.txt", feeds)
        self.assertIn("https://raw.githubusercontent.com/example/repo/main/sub.txt", feeds)

    def test_socks_and_shadowsocks_reduction(self):
        nodes = []
        for proto in ("socks", "shadowsocks"):
            for i in range(10):
                n = ph.Node(uri=f"{proto}://placeholder", protocol=proto, host=f"example{i}.com", port=443)
                n.country = "DE"
                n.tcp_ms = 10 + i
                nodes.append(n)
        reduced = ph.apply_low_priority_reduction(nodes)
        self.assertEqual(sum(n.protocol == "socks" for n in reduced), 2)
        self.assertEqual(sum(n.protocol == "shadowsocks" for n in reduced), 2)

    def test_selection_caps_us_canada_and_country_duplicates(self):
        nodes = []
        for country, count in (("US", 6), ("CA", 6), ("DE", 8)):
            for i in range(count):
                n = ph.Node(uri=f"vless://{country}-{i}", protocol="vless", host=f"host-{country}-{i}.example", port=443)
                n.ip = f"1.1.{len(nodes) // 250}.{len(nodes) % 250 + 1}"
                n.country = country
                n.xray_ok = True
                n.tcp_ms = float(i + 1)
                n.speed_mbps = float(100 - i)
                nodes.append(n)
        picked = ph.select_nodes(nodes, limit=20, max_per_ip=1, max_per_country=5, required_core="xray")
        counts = {}
        for node in picked:
            counts[node.country] = counts.get(node.country, 0) + 1
        self.assertEqual(counts.get("US", 0), 2)
        self.assertEqual(counts.get("CA", 0), 2)
        self.assertEqual(counts.get("DE", 0), 5)


    def test_telegram_public_preview_parser(self):
        html = '''<div class="tgme_widget_message_text">vless://00000000-0000-4000-8000-000000000001@example.com:443#node<br/>second line</div>'''
        parser = ph.TelegramPreviewParser()
        parser.feed(html)
        content = "\n".join(parser.text_parts)
        self.assertIn("vless://", content)
        self.assertIn("second line", content)

    def test_public_ip_guard(self):
        self.assertFalse(ph._is_global_ip("127.0.0.1"))
        self.assertFalse(ph._is_global_ip("10.0.0.1"))
        self.assertFalse(ph._is_global_ip("169.254.1.1"))
        self.assertTrue(ph._is_global_ip("1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
