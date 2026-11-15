import unittest
import doc_figures


class FigureTest(unittest.TestCase):
    def test_figures_match_measured_data(self):
        doc_figures.generate(check=True)
