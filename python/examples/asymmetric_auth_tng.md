TNG Asymmetric Authentication Example
===============================================================================
Some Microchip parts (TNG) comes with pre-provisioned certificates that can be used for a
wide range of purposes. This script demonstrates how to use Cryptoauthlib to implement 
Asymmetric Authentication.

Please note, this example will only work for TNG parts. The same concept can be used with
other devices.

Please note, this is a simple cryptographic validation and does not check
any of the actual certificate data (validity dates, extensions, names, etc...).
Furthermore, the host shall trust the CA to close the chain of trust.

Prerequisites:
-------------------------------------------------------------------------------
See [requirements.txt](requirements.txt) or install via:

    $ pip install -r requirements.txt

Supported devices:
* [ATECC608A-MAHTN-T](https://www.microchip.com/design-centers/security-ics/cryptoauthentication/cloud-authentication/lora-security-with-tti-join-server)

Steps to run the example:
-------------------------------------------------------------------------------
The example can be run by:

    $ python asymmetric_auth_tng.py
