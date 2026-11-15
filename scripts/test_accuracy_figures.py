import unittest
import accuracy_figures


class AccuracyFigureTest(unittest.TestCase):
    def test_figures_and_detail_page_match_scored_corpus(self):
        accuracy_figures.generate(check=True)
