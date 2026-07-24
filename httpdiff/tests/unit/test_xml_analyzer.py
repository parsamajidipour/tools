from __future__ import annotations

import unittest

from httpdiff.analyzers.xml_body import analyze_xml


class TestXmlAnalyzer(unittest.TestCase):
    def test_element_value_changed(self):
        b = "<root><role>user</role></root>"
        c = "<root><role>admin</role></root>"
        diffs = analyze_xml(b, c)
        self.assertTrue(any(d.change_type.value == "modified" for d in diffs))

    def test_element_added(self):
        b = "<root><a>1</a></root>"
        c = "<root><a>1</a><b>2</b></root>"
        diffs = analyze_xml(b, c)
        self.assertTrue(any(d.change_type.value == "added" for d in diffs))

    def test_external_entities_never_resolved(self):
        malicious = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            "<root>&xxe;</root>"
        )
        # Must not raise, must not attempt to read the local file; the
        # DOCTYPE/ENTITY declaration is stripped before parsing.
        diffs = analyze_xml(malicious, "<root>safe</root>")
        self.assertIsInstance(diffs, list)

    def test_malformed_xml_does_not_crash(self):
        diffs = analyze_xml("<root><unclosed>", "<root><also-unclosed>")
        self.assertEqual(diffs, [])


if __name__ == "__main__":
    unittest.main()
