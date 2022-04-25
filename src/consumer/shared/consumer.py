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
import logging
import ndn.utils
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure
from ndn.encoding import Name, Component, InterestParam
from ff3 import FF3Cipher
from ctypes import *
import base64
import binascii


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


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = NDNApp()


def image_processing(image_data):
    f = open('/usr/src/app/shared/Contents/received.png', 'wb+')
    f.write(binascii.a2b_hex(image_data))
    f.close()
    print("image saved done...")


def video_processing(video_data):
    f = open('/usr/src/app/shared/Contents/received.mp4', 'wb+')
    f.write(binascii.a2b_hex(video_data))
    f.close()
    print("video saved done...")


async def main():
    try:
        NameFPE = NameComponentSplitter("/cryptography/application/laboratory/video/1029121")
        timestamp = ndn.utils.timestamp()

        name = Name.from_str(NameFPE) + [Component.from_timestamp(timestamp)]

        print(f'Sending Interest {Name.to_str(name)}, {InterestParam(must_be_fresh=True, lifetime=6000)}')

        for idx in range(3):
            data_name, meta_info, content = await app.express_interest(
                name, must_be_fresh=True, can_be_prefix=False, lifetime=6000)

            print(f'Received Data Name: {Name.to_str(data_name)}')
            print(meta_info)
            print(bytes(content) if content else None)

    except InterestNack as e:
        print(f'Nacked with reason={e.reason}')
    except InterestTimeout:
        print(f'Timeout')
    except InterestCanceled:
        print(f'Canceled')
    except ValidationFailure:
        print(f'Data failed to validate')
    finally:
        app.shutdown()


if __name__ == '__main__':
    app.run_forever(after_start=main())
