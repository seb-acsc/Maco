from io import BytesIO
from typing import List, Optional

from maco import extractor, model, yara
from Cryptodome.Cipher import DES


class LibraryCheck(extractor.Extractor):
    """Check interesting libraries work correctly."""

    family = "library_check"
    author = "blue"
    last_modified = "2024-11-14"
    yara_rule = """
        rule LibraryCheck
        {
            strings:
                $self_trigger = "LibraryCheck"
            condition:
                $self_trigger
        }
        """

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        # return config model formatted results
        ret = model.ExtractorModel(family=self.family)

        mode = DES.MODE_CBC
        # uses sys.modules to resolve under the hood
        cipher = DES.new(b"12341234", mode, b"12341234")
        # make sure cipher is used
        ret.campaign_id.append(cipher.decrypt(b'\xac\x01p~^\xb5&\xc5\xa9\x000\xe9\xf6\xe5\xb29'))
        return ret
