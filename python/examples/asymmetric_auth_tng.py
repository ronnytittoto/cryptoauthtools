"""
TNG Certificates
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
#from cryptography.hazmat.backends import default_backend
#from cryptography import x509
#from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
#from cryptography.hazmat.primitives.asymmetric import ec, utils
#from cryptography.hazmat.primitives import hashes
#from cryptography.utils import int_from_bytes, int_to_bytes
#from cryptography.exceptions import InvalidSignature
#from cryptoauthlib import *
from common import *
from common_asymmetric import *

ATCA_SUCCESS = 0x00

def init_device(iface='hid', **kwargs):
    """Initialize CryptoAuthLib for the current device"""
    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    # Get the target default config
    cfg = eval('cfg_ateccx08a_{}_default()'.format(atca_names_map.get(iface)))

    # Set interface parameters
    if kwargs is not None:
        for k, v in kwargs.items():
            icfg = getattr(cfg.cfg, 'atca{}'.format(iface))
            setattr(icfg, k, int(v, 16))

    # Basic Raspberry Pi I2C check
    if 'i2c' == iface and check_if_rpi():
        cfg.cfg.atcai2c.bus = 1

    # Initialize the stack
    assert atcab_init(cfg) == ATCA_SUCCESS

    # Check device type
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    dev_name = get_device_name(info)
    dev_type = get_device_type_id(dev_name)

    # Reinitialize if the device type doesn't match the default
    if dev_type != cfg.devtype:
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    return dev_name

def asymmetric_auth():
    """Read the TNG certificate chain and perform a full authentication """
    
    # Note that we should have a valid trust-store of acceptable root public keys
    # In this script we assume that the TNG device is coming from a trusted CA
    
    #certs = []

    print('TNG Root Certificate:')
    root_cert_der_size = AtcaReference(0)
    assert tng_atcacert_root_cert_size(root_cert_der_size) == ATCA_SUCCESS

    root_cert_der = bytearray(root_cert_der_size.value)
    assert tng_atcacert_root_cert(root_cert_der, root_cert_der_size) == ATCA_SUCCESS

    root_cert = x509.load_der_x509_certificate(root_cert_der, default_backend())
    #certs.insert(0, root_cert)

    print(get_common_name(root_cert.subject))
    print(root_cert.public_bytes(encoding=Encoding.PEM).decode('utf-8'))


    print('TNG Root Public Key:')
    # Note that we could, of course, pull this from the root certificate above.
    # However, this demonstrates the tng_atcacert_root_public_key() function.
    root_public_key_raw = bytearray(64)
    assert tng_atcacert_root_public_key(root_public_key_raw) == ATCA_SUCCESS

    root_public_key = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(),
        x=int_from_bytes(root_public_key_raw[0:32], byteorder='big'),
        y=int_from_bytes(root_public_key_raw[32:64], byteorder='big'),
    ).public_key(default_backend())

    # Prove that cert public key and the public key from the func are the same
    cert_spk_der = root_cert.public_key().public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.DER
    )
    func_spk_der = root_public_key.public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.DER
    )
    assert cert_spk_der == func_spk_der

    print(root_public_key.public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.PEM
    ).decode('utf-8'))


    print('Validate Root Certificate:')
    root_public_key.verify(
        signature=root_cert.signature,
        data=root_cert.tbs_certificate_bytes,
        signature_algorithm=ec.ECDSA(root_cert.signature_hash_algorithm)
    )
    print('OK\n')


    print('TNG Signer Certificate:')
    signer_cert_der_size = AtcaReference(0)
    assert tng_atcacert_max_signer_cert_size(signer_cert_der_size) == ATCA_SUCCESS

    signer_cert_der = bytearray(signer_cert_der_size.value)
    assert tng_atcacert_read_signer_cert(signer_cert_der, signer_cert_der_size) == ATCA_SUCCESS

    signer_cert = x509.load_der_x509_certificate(signer_cert_der, default_backend())
    #certs.insert(0, signer_cert)

    print(get_common_name(signer_cert.subject))
    print(signer_cert.public_bytes(encoding=Encoding.PEM).decode('utf-8'))


    print('TNG Signer Public Key:')
    # Note that we could, of course, pull this from the signer certificate above.
    # However, this demonstrates the tng_atcacert_signer_public_key() function.
    signer_public_key_raw = bytearray(64)
    assert tng_atcacert_signer_public_key(signer_public_key_raw) == ATCA_SUCCESS

    signer_public_key = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(),
        x=int_from_bytes(signer_public_key_raw[0:32], byteorder='big'),
        y=int_from_bytes(signer_public_key_raw[32:64], byteorder='big'),
    ).public_key(default_backend())

    # Prove that cert public key and the public key from the func are the same
    cert_spk_der = signer_cert.public_key().public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.DER
    )
    func_spk_der = signer_public_key.public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.DER
    )
    assert cert_spk_der == func_spk_der

    print(signer_public_key.public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.PEM
    ).decode('utf-8'))


    # Note that this is a simple cryptographic validation and does not check
    # any of the actual certificate data (validity dates, extensions, names,
    # etc...)
    print('Validate Signer Certificate:')
    root_public_key.verify(
        signature=signer_cert.signature,
        data=signer_cert.tbs_certificate_bytes,
        signature_algorithm=ec.ECDSA(signer_cert.signature_hash_algorithm)
    )
    print('OK\n')


    print('TNG Device Certificate:')
    device_cert_der_size = AtcaReference(0)
    assert tng_atcacert_max_device_cert_size(device_cert_der_size) == ATCA_SUCCESS

    device_cert_der = bytearray(device_cert_der_size.value)
    assert tng_atcacert_read_device_cert(device_cert_der, device_cert_der_size) == ATCA_SUCCESS

    device_cert = x509.load_der_x509_certificate(device_cert_der, default_backend())
    #certs.insert(0, device_cert)

    print(get_common_name(device_cert.subject))
    print(device_cert.public_bytes(encoding=Encoding.PEM).decode('utf-8'))


    print('TNG Device Public Key:')
    # Note that we could, of course, pull this from the device certificate above.
    # However, this demonstrates the tng_atcacert_device_public_key() function.
    device_public_key_raw = bytearray(64)
    assert tng_atcacert_device_public_key(device_public_key_raw, device_cert_der) == ATCA_SUCCESS

    device_public_key = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(),
        x=int_from_bytes(device_public_key_raw[0:32], byteorder='big'),
        y=int_from_bytes(device_public_key_raw[32:64], byteorder='big'),
    ).public_key(default_backend())

    # Prove that cert public key and the public key from the func are the same
    cert_spk_der = device_cert.public_key().public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.DER
    )
    func_spk_der = device_public_key.public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.DER
    )
    assert cert_spk_der == func_spk_der

    print(device_public_key.public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo,
        encoding=Encoding.PEM
    ).decode('utf-8'))


    # Note that this is a simple cryptographic validation and does not check
    # any of the actual certificate data (validity dates, extensions, names,
    # etc...)
    print('Validate Device Certificate:')
    signer_public_key.verify(
        signature=device_cert.signature,
        data=device_cert.tbs_certificate_bytes,
        signature_algorithm=ec.ECDSA(device_cert.signature_hash_algorithm)
    )
    print('OK\n')
    
    print('Sign the host random challenge with the device and Verify')
    # Sign - Verify the device with host challenge 
    # Generate a random message
    message = os.urandom(32)

    # Create a digest of the message for signing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message = digest.finalize()

    print('Message Digest:')
    print(pretty_print_hex(message, indent='    '))
    
    # Sign the message
    print("\nSigning the Message Digest with device")
    signature = sign_device(message, key_slot)
    print('Signature:')
    print(pretty_print_hex(signature, indent='    '))

    # Verify the message
    print("\nVerifing the signature with host")
    verified = verify_host(message, signature, device_public_key_raw)

    return verified


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    dev_name = init_device(args.iface, **parse_interface_params(args.params))
    key_slot = 0
    
    verified = asymmetric_auth()
    print('    Signature is %s!' % ('valid' if verified else 'invalid'))
    
    atcab_release()
    print('\nDone')