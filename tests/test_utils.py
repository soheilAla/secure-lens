import pytest

from securelens.utils.entropy import shannon_entropy
from securelens.utils.masking import mask_secret


def test_mask_secret():
    assert mask_secret("sk_live_4eC39HqLyjWDarjtT1zdp7dc") == "sk_l***dc"
    assert mask_secret("abc") == "***"
    assert mask_secret("abcd12") == "***"


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abab") == pytest.approx(1.0)
    assert shannon_entropy("abcd") == pytest.approx(2.0)
