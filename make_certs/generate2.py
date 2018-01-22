#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from cryptography.x509.extensions import Extension, ExtensionType

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from ipaddress import IPv4Address

from pathlib import Path
import subprocess
import datetime
import base64
import shutil
import os


class Config():
    base_path = os.path.abspath('./certs')
    encryptPrivateKeys = True
    refresh = False
    fullrefresh = False


class Authority():

    def __init__(self, d, _type, parent=None):
        self.parent = parent
        self._type = _type
        # auth = {k:v for (k,v) in d.items() if not 'children' in k}
        # for k, v in auth.items():
        for k, v in d.items():
            setattr(self, k, v)
        self._setup()


    def _setup(self):
        """ Start initalization """
        if not hasattr(self, 'name'):
            self.name = self.slugify(self.DN)
        if self.parent == None:
            self.output_path = os.path.join(Config.base_path, self.name)
        else:
            self.output_path = os.path.join(self.parent.output_path, self.name)
        self._filesetup( self.output_path, self.name )

        # >>> Load / Create Certs
        # Need to think out updates / changes to the original yaml.
        if self.key_file.is_file():
            self.load_keypair()
        else:
            self.gen_keypair()


    def _filesetup(self, path, name):
        """ Create default file paths, and create directory structure """
        self.key_file   = Path(os.path.join(path, name + '.key' ))
        self.pkcs8_file = Path(os.path.join(path, name + '.pkcs8.key'))
        self.key_pass   = Path(os.path.join(path, name + '.key.pass'))
        self.cert_file  = Path(os.path.join(path, name + '.crt' ))
        self.p12_file   = Path(os.path.join(path, name + '.p12' ))
        self.p12_pass   = Path(os.path.join(path, name + '.p12.pass' ))
        self.jks_file   = Path(os.path.join(path, name + '.jks'))
        self.chain_file = Path(os.path.join(path, name + '-chain.crt'))

        os.makedirs(path, exist_ok=True)


    def gen_keypair(self):
        """ Start generation of passphrase, private key, and public key """
        self.password = self.gen_pass(self.key_pass)
        self.key = self.gen_key(
            self.key_file,
            self.pkcs8_file,
            self.password if Config.encryptPrivateKeys else None
            )

        # if self.parent == None:
        if self._type == 'root':
            signing_key = self.key
        else:
            signing_key = self.parent.key

        # Make and sign the actual key
        self.cert = self.gen_cert(self.cert_file, signing_key)
        # >>> Make cert chain
        self._gen_chain()
        if self._type == 'node':
            self._pkcs12()
            self._java_keystore()


    def load_keypair(self):
        """ Load passphrase, private key, public cert from file """
        self.password = self.load_pass(self.key_pass)
        self.key = self.load_key(self.key_file, self.password)
        self.cert = self.load_cert(self.cert_file)


    def _gen_chain(self):
        if self._type == 'root':
            self.chain = self.cert.public_bytes(serialization.Encoding.PEM)
        else:
            self.chain = self.cert.public_bytes(serialization.Encoding.PEM) + \
                self.parent.chain
            with open(self.chain_file, "wb") as f:
                f.write(self.chain)


    def gen_pass(self, filename):
        """ Generate a random password to file """
        password = base64.b64encode(os.urandom(32))
        with open(filename, "wb") as f:
            f.write(password)
        return password


    def gen_key(self, filename, pkcs8_file, password=None):
        """ Generate the private key and write to file """
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        if password is not None:
            if type(password) is not bytes:
                password = bytes(password, encoding="ascii")
            encrypt_algo = serialization.BestAvailableEncryption(password)
        else:
            encrypt_algo = serialization.NoEncryption()

        # PEM private key
        with open(filename, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encrypt_algo,
            ))
        # PKCS8 private key
        with open(pkcs8_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encrypt_algo,
            ))
        return key


    def gen_cert(self, cert_file, signing_key):
        """ Create and sign the Certificate """
        if self._type == 'root':
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.name)
            ])
        elif self._type in ('sign', 'node'):
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.name)
            ])
            # print(self.parent.cert.subject)
            issuer = self.parent.cert.subject

        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        # subject = issuer = x509.Name([
        #     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        #     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CO"),
        #     x509.NameAttribute(NameOID.LOCALITY_NAME, u"Golden"),
        #     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Elastic Support"),
        #     x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        # ])


        # cert = x509.CertificateBuilder().subject_name(
        #     subject
        # ).issuer_name(
        #     # Need to put correct name here
        #     issuer
        # ).public_key(
        #     self.key.public_key()
        # ).serial_number(
        #     x509.random_serial_number()
        # ).not_valid_before(
        #     datetime.datetime.utcnow()
        # ).not_valid_after(
        #     # Our certificate will be valid for 10 days
        #     datetime.datetime.utcnow() + datetime.timedelta(days=10)
        # ).add_extension(
        #     x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        #     critical=False
        # ).add_extension(
        #     x509.BasicConstraints(ca=True, path_length=None), critical=True
        # ).add_extension(
        #     x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
        #     critical=False
        # ).add_extension(
        #     x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
        #     critical=False
        # ).sign(
        #     signing_key,
        #     hashes.SHA256(),
        #     default_backend()
        # )


        cert = x509.CertificateBuilder()
        cert = cert.subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        )

        cert = self.load_extensions(cert)

        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
            critical=False
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
            critical=False
        ).sign(
            signing_key,
            hashes.SHA256(),
            default_backend()
        )


        # Write certificate out to disk.
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert


    def load_extensions(self, cert):

        ext = self.x509_extensions if hasattr(self, 'x509_extensions') else dict()

        # print(x509.Extensions.__iter__)
        print(x509.oid.ExtensionOID.__dict__)
        # for k,v in ext.items():
        #     print(k)
        #     z = getattr(x509, k)
        #     print(v)
        #     # if isinstance(v, dict):
        #     #     kk,vv in v.items()
        #     #     print(kk)
        #
        #     print(z)
        #     # print(z.__dict__.keys())
        #     print([i for i in z.__dict__.keys() if i[:1] != '_'])
        #     # variables = [i for i in dir(z) if not callable(i)]
        #     # print(variables)
        #     #     print(k)
        #     # y = getattr(x509, k)

        if 'SubjectAlternativeName' in ext:
            if isinstance(ext['SubjectAlternativeName'], list):
                x = [eval(x) for x in ext['SubjectAlternativeName']]
            print(x)
            # handle array or key
            cert = cert.add_extension(
                x509.SubjectAlternativeName(x), critical=True
            )

        if 'KeyUsage' in ext:
            keyusage = {
                'digital_signature': False,
                'content_commitment': False,
                'key_encipherment': False,
                'data_encipherment': False,
                'key_agreement': False,
                'key_cert_sign': False,
                'crl_sign': False,
                'encipher_only': False,
                'decipher_only': False
            }
            keyusage.update(ext['KeyUsage'])
            cert = cert.add_extension(
                    x509.KeyUsage(
                        **keyusage),
                        critical=True
                    )

        if 'BasicConstraints' in ext:
            basicconstraints = {
                'ca': False,
                'path_length': None
            }
            basicconstraints.update(ext['BasicConstraints'])
            cert = cert.add_extension(
                    x509.BasicConstraints(
                        **basicconstraints),
                        critical=True
                    )

        if 'ExtendedKeyUsage' in ext:
            extendedkeyusage = [ getattr(x509.oid.ExtendedKeyUsageOID, x)
                                    for x in ext['ExtendedKeyUsage']]
            cert = cert.add_extension(
                    x509.ExtendedKeyUsage(
                        extendedkeyusage),
                        critical=True
                    )

        # if 'IssuerAlternativeName' in ext:



        # set sane defaults if not already provided
        if self._type in ('root', 'sign') and 'BasicConstraints' not in ext:
            cert = cert.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
        elif self._type == 'node' and 'BasicConstraints' not in ext:
            cert = cert.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )

        return cert


        # OCSPNoCheck
        # TLSFeature
        # TLSFeatureType
        # NameConstraints

        # AuthorityKeyIdentifier
        # SubjectKeyIdentifier

        # IssuerAlternativeName
        # PrecertificateSignedCertificateTimestamps
        # DeltaCRLIndicator
        # AuthorityInformationAccess
        # AccessDescription
        # FreshestCRL
        # CRLDistributionPoints
        # DistributionPoint
        # ReasonFlags
        # InhibitAnyPolicy
        # PolicyConstraints
        # CRLNumber
        # UnrecognizedExtension
        # CertificatePolicies
        # PolicyInformation
        # UserNotice
        # NoticeReference
        # CertificateIssuer


    def load_key(self, filename, password=b''):
        """ Load the private key file """
        with open(filename, 'rb') as pem_in:
            pemlines = pem_in.read()
        key = serialization.load_pem_private_key(pemlines, password, default_backend())
        return key


    def load_cert(self, filename):
        """ Load the certificate file associated with the private key """
        with open(filename, 'rb') as pem_in:
            pemdata = pem_in.read()
        cert = x509.load_pem_x509_certificate(pemdata, default_backend())
        return cert
        # ski = authority_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)


    def load_pass(self, filename):
        """ Load password needed to read private key file """
        if Path(filename).is_file():
            with open(filename, 'rb') as txt_in:
                password = txt_in.read()
        else:
            password = ''
        return password


    def slugify(self, value):
        """
        Sanatize for filesystem names.
        Normalizes string, converts to lowercase, removes non-alpha characters,
        and converts spaces to hyphens.
        """
        import unicodedata
        import re
        value = re.sub(r'^[Cc][Nn]=(.*?)(;.*$)?(;|$)', r'\1', value)
        value = str(unicodedata.normalize('NFKD', value)
            .encode('ascii', 'ignore'), 'utf-8')
        value = re.sub('[^\w\s-]', '', value).strip().lower()
        value = re.sub('[-\s]+', '-', value)
        return value


    def _pkcs12(self):

        # create keystore password
        self.p12_password = self.gen_pass(self.p12_pass)

        # command = """
        # openssl pkcs12 -export -chain -in "{node_crt}" -inkey "{node_key}" \
        # -out "{node_p12}" -name "{name}" \
        # -passout pass:"{password}" -CAfile "{ca_chain}"
        # """.format(
        #     node_crt = self.cert_file,
        #     node_key = self.key_file,
        #     node_p12 = self.p12_file,
        #     name = self.name,
        #     password = self.password,
        #     ca_chain = self.parent.chain_file
        # )
        command = [
            'openssl', 'pkcs12', '-export', '-chain',
            '-in', self.cert_file,
            '-inkey', self.key_file, '-out', self.p12_file,
            '-name', self.name, '-passin', 'file:{}'.format(self.key_pass),
            '-passout', 'file:{}'.format(self.p12_pass),
            '-CAfile', self.parent.chain_file
        ]

        if shutil.which('openssl'):
            p = subprocess.run(
                # command.split(),
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                )
            if p.returncode != 0:
                print(str(command))
                print(p.stderr.decode("utf-8"))
        else:
            print('No openssl available on the PATH to use')


    def _java_keystore(self):
        """
        keytool -importkeystore -destkeystore "{server}.jks"
        -srckeystore "{server}.p12" -srcstoretype pkcs12
        -alias {server_cn_filename} -srcstorepass {server_pass}
        -deststorepass {server_pass} -noprompt
        """
        command = [
            'keytool', '-importkeystore',
            '-destkeystore', self.jks_file,
            '-srckeystore', self.p12_file,
            '-srcstoretype', 'pkcs12', '-alias', self.name,
            '-srcstorepass', self.p12_password,
            '-deststorepass', self.p12_password,
            '-noprompt'
        ]
        if shutil.which('keytool'):
            p = subprocess.run(
                # command.split(),
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                )
            if p.returncode != 0:
                print(str(command))
                print(p.stderr.decode("utf-8"))
        else:
            print('No java keytool available on the PATH to use')
