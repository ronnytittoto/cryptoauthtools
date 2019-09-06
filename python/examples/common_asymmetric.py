"""
Common functions for Asymmetric Authentication using TNG devices
"""
# (c) 2015-2019 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.

import time
import unicodedata
import re
import sys
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.utils import int_from_bytes, int_to_bytes
from cryptography.exceptions import InvalidSignature
from cryptoauthlib import *
from common import *

ATCA_SUCCESS = 0x00

def sign_device(digest, slot):
    """
    Sign message using an ATECC508A or ATECC608A
    """
    signature = bytearray(64)
    assert atcab_sign(slot, digest, signature) == ATCA_SUCCESS

    return signature
    
    
def verify_host(digest, signature, public_key_data):
    """
    Verify a signature using the host software
    """
    try:
        r = int_from_bytes(signature[0:32], byteorder='big', signed=False)
        s = int_from_bytes(signature[32:64], byteorder='big', signed=False)
        sig = utils.encode_dss_signature(r, s)

        public_key = ec.EllipticCurvePublicNumbers(
            curve=ec.SECP256R1(),
            x=int_from_bytes(public_key_data[0:32], byteorder='big'),
            y=int_from_bytes(public_key_data[32:64], byteorder='big'),
        ).public_key(default_backend())
        public_key.verify(sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def get_common_name(name):
    """
    Get the common name string from a distinguished name (RDNSequence)
    """
    for attr in name:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            return attr.value
    return None
