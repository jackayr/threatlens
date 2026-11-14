import unittest
from main import filter_by_vendor


class TestVendorFiltering(unittest.TestCase):

    def test_filter_by_vendor(self):
        sample_data = [
            {"cveID": "CVE-0001", "vendorProject": "Microsoft"},
            {"cveID": "CVE-0002", "vendorProject": "Apple"},
            {"cveID": "CVE-0003", "vendorProject": "Microsoft"}
        ]

        result = filter_by_vendor(sample_data, "Microsoft")

        self.assertEqual(len(result), 2)


    def test_case_insensitive(self):
        sample_data = [
        {"cveID": "CVE-0001", "vendorProject": "Microsoft"}
        ]

        result = filter_by_vendor(sample_data, "microsoft")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cveID"], "CVE-0001")

    def test_unknown_vendor(self):
        sample_data = [
        {"cveID": "CVE-0001", "vendorProject": "Microsoft"},
        {"cveID": "CVE-0002", "vendorProject": "Apple"}
        ]

        result = filter_by_vendor(sample_data, "Google")
        self.assertEqual(result, [])

    def test_missing_vendor_key(self):
        sample_data = [
        {"cveID": "CVE-0001", "vendorProject": "Microsoft"},
        {"cveID": "CVE-0002"}
        ]

        result=filter_by_vendor(sample_data, "Microsoft")
        self.assertEqual(result[0]["cveID"], "CVE-0001")

