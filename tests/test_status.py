"""Tests for the VERIFIED / PARTIALLY VERIFIED / UNSOLVED labels."""

import unittest

from core.search import run_search
from scoring.scorer import analyze_candidate
from validation.status import (
    get_status,
    VERIFIED,
    PARTIALLY_VERIFIED,
    UNSOLVED,
)


def scores_for(data):
    return analyze_candidate(data, data)


class StatusRuleTests(unittest.TestCase):
    def test_flag_match_and_rerun_is_verified(self):
        data = b"CTF{l4y3r5_0f_c0d3}"
        self.assertEqual(get_status(data, scores_for(data), True, True), VERIFIED)

    def test_flag_match_without_rerun_is_not_verified(self):
        data = b"CTF{l4y3r5_0f_c0d3}"
        self.assertNotEqual(get_status(data, scores_for(data), True, False), VERIFIED)

    def test_readable_english_is_partially_verified(self):
        data = b"the meeting is at dawn near the old bridge"
        self.assertEqual(
            get_status(data, scores_for(data), False), PARTIALLY_VERIFIED
        )

    def test_noise_is_unsolved(self):
        data = b"Xq9vB2kLm8Rt4Zp1"
        self.assertEqual(get_status(data, scores_for(data), False), UNSOLVED)


class SearchStatusTests(unittest.TestCase):
    def test_search_labels_proposal_example_verified(self):
        result = run_search(
            "5545645465336b3062444e6c4e563877633139774d48457a66513d3d",
            max_depth=4,
            flag_pattern=r"CTF\{[^}]+\}",
        )
        self.assertEqual(result["results"][0].status, VERIFIED)


if __name__ == "__main__":
    unittest.main()
