import unittest
from core.models import AnalysisResult, CaesarCandidate
from reporting.render import render_json, render_markdown


class ReportingTests(unittest.TestCase):
    def test_json_report(self):
        result = AnalysisResult(11, 10, 0.05, [("L", 2)], [CaesarCandidate(3, 1.2, "HELLO")])
        rendered = render_json(result)
        self.assertIn('"shift": 3', rendered)
        self.assertIn('"plaintext": "HELLO"', rendered)

    def test_markdown_report(self):
        result = AnalysisResult(11, 10, 0.05, [("L", 2)], [CaesarCandidate(3, 1.2, "HELLO")])
        rendered = render_markdown(result)
        self.assertIn("shift  3", rendered)
        self.assertIn("HELLO", rendered)


if __name__ == "__main__":
    unittest.main()
