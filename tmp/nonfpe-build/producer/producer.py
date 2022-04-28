# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
from typing import Optional
from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, MetaInfo, Component
import logging
import sys
from ndn.utils import timestamp
from ff3 import FF3Cipher
from ctypes import *
import base64
import binascii

SEGMENT_SIZE = 4400

def ff3_cipher(PlainText: str) -> str:
    key = "2DE79D232DF5585D68CE47882AE256D6"
    tweak = "CBD09280979564"
    CipherObj = FF3Cipher(key, tweak, radix=36)

    return CipherObj.encrypt(PlainText)


def NameComponentSplitter(PlainText: str):
    Slash_index = [pos for pos, char in enumerate(PlainText) if char == '/']
    NameComponent_index = PlainText.split('/')

    FinalNameComponent = []

    del NameComponent_index[0]

    for idx in range(len(Slash_index)):
        FinalNameComponent.append('/')
        FinalNameComponent.append(ff3_cipher(NameComponent_index[idx]))

    FinalNameComponent = ''.join(FinalNameComponent)
    return FinalNameComponent

def main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.INFO,
                        style='{')

    app = NDNApp()

    NameFPE = NameComponentSplitter("/cryptography/application/laboratory/video")
    name = Name.normalize(NameFPE)
    name.append(Component.from_version(timestamp()))

    with open(sys.argv[1], 'rb') as f:
        data = f.read()
        seg_cnt = (len(data) + SEGMENT_SIZE - 1) // SEGMENT_SIZE
        packets = [app.prepare_data(name + [Component.from_segment(i)],
                                    data[i*SEGMENT_SIZE:(i+1)*SEGMENT_SIZE],
                                    freshness_period=10000,
                                    final_block_id=Component.from_segment(seg_cnt - 1))
                   for i in range(seg_cnt)]
    print(f'Created {seg_cnt} chunks under name {Name.to_str(name)}')

    @app.route(name)
    def on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        print(f'>> I: {Name.to_str(name)}, {param}')
        content = "Hello, world!".encode()
        app.put_data(name, content=content, freshness_period=10000)
        print(f'<< D: {Name.to_str(name)}')
        print(MetaInfo(freshness_period=10000))
        print(f'Content: (size: {len(content)})')
        print('')

    app.run_forever()

if __name__ == '__main__':
    main()