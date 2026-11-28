import unittest
from validation.input import validate_input, validate_top_n


class InputValidationTests(unittest.TestCase):
    def test_valid_input(self):
        self.assertEqual(validate_input("hello"), "hello")

    def test_rejects_non_text(self):
        with self.assertRaises(TypeError):
            validate_input(b"hello")

    def test_rejects_empty_text(self):
        with self.assertRaises(ValueError):
            validate_input("   ")

    def test_rejects_too_long_text(self):
        with self.assertRaises(ValueError):
            validate_input("hello", max_length=4)

    def test_top_n_bounds(self):
        self.assertEqual(validate_top_n(10), 10)
        with self.assertRaises(ValueError):
            validate_top_n(101)


if __name__ == "__main__":
    unittest.main()
