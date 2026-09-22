import unittest


class ThreatHuntingUnitTests(unittest.TestCase):
    def test_search_terms_are_bounded_and_deduplicated(self):
        from src.services import parse_search_terms

        self.assertEqual(
            parse_search_terms('"Volt Typhoon" OR volt,typhoon'),
            ["Volt Typhoon", "OR", "volt", "typhoon"],
        )
        with self.assertRaises(ValueError):
            parse_search_terms('"unclosed phrase')
        with self.assertRaises(ValueError):
            parse_search_terms("x" * 501)

    def test_osint_pivots_validate_indicator_values(self):
        from src.services import get_osint_pivot_link

        self.assertEqual(
            get_osint_pivot_link("IPv4", "192.0.2.10"),
            "https://www.shodan.io/host/192.0.2.10",
        )
        self.assertIsNone(get_osint_pivot_link("IPv4", "not-an-ip"))
        self.assertIsNone(get_osint_pivot_link("CVE", "javascript:alert(1)"))
        self.assertIsNone(get_osint_pivot_link("Domain", "example.com/path"))


if __name__ == "__main__":
    unittest.main()
