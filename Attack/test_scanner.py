import unittest

from scanner import build_nmap_command, clean_options, parse_results


class VulnersOptionTests(unittest.TestCase):
    def test_vulners_enables_version_detection_and_only_selected_script(self):
        options = clean_options({"vulners": True})
        command = build_nmap_command("192.168.1.20", None, options)

        self.assertIn("-sV", command)
        self.assertEqual(command[command.index("--script") + 1], "vulners")
        self.assertNotIn("vuln", command)

    def test_default_scripts_combine_with_vulners(self):
        options = clean_options({"scripts": True, "vulners": True})
        command = build_nmap_command("192.168.1.20", None, options)

        self.assertEqual(command[command.index("--script") + 1], "default,vulners")

    def test_unchecked_vulners_preserves_script_behavior(self):
        options = clean_options({"scripts": True})
        command = build_nmap_command("192.168.1.20", None, options)

        self.assertIn("-sC", command)
        self.assertNotIn("vulners", command)

    def test_parse_results_captures_vulners_output(self):
        xml_data = (
            '<nmaprun><host><ports><port protocol="tcp" portid="443">'
            '<state state="open"/><service name="https" product="Example" version="1.2"/>'
            '<script id="vulners" output="CVE-2024-1234  HIGH  8.0"/>'
            '</port></ports></host></nmaprun>'
        )

        result = parse_results(xml_data)

        self.assertIn("CVE-2024-1234", result["ports"][0]["vulners"])


if __name__ == "__main__":
    unittest.main()
