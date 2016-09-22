# openssl x509 < id_cert.pem -text
from OpenSSL import crypto as c, SSL
import random
import string


def random_hostname():
    mid = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    return 'www.%s.com' % mid


def create_cert(key, signing_key, cn, issuer_cert):
    cert = c.X509()
    cert.get_subject().CN = random_hostname()
    cert.set_serial_number(random.randint(0, 2**63))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    if issuer_cert:
        cert.set_issuer(issuer_cert.get_subject())
    else:
        cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(signing_key, 'sha256')

    # print( c.dump_certificate(c.FILETYPE_TEXT, cert).decode() )
    # print( c.dump_certificate(c.FILETYPE_PEM, cert).decode() )
    return cert


def verify_cert(cert, signing_cert):
    cert_store = c.X509Store()
    cert_store.add_cert(signing_cert)
    store_ctx = c.X509StoreContext(cert_store, cert)
    try:
        store_ctx.verify_certificate()
    except:
        return False
    else:
        return True


if __name__ == '__main__':
    id_key = c.PKey()
    id_key.generate_key(c.TYPE_RSA, 1024)
    with open('id_key.pem', 'w') as f:
        f.write(c.dump_privatekey(c.FILETYPE_PEM, id_key).decode())

    link_key = c.PKey()
    link_key.generate_key(c.TYPE_RSA, 1024)
    with open('link_key.pem', 'w') as f:
        f.write(c.dump_privatekey(c.FILETYPE_PEM, link_key).decode())

    id_cert = create_cert(id_key, id_key, 'id', None)
    with open('id_cert.pem', 'w') as f:
        f.write(c.dump_certificate(c.FILETYPE_PEM, id_cert).decode())

    link_cert = create_cert(link_key, id_key, 'link', id_cert)
    with open('link_cert.pem', 'w') as f:
        f.write(c.dump_certificate(c.FILETYPE_PEM, link_cert).decode())

    assert verify_cert(id_cert, id_cert)
    print("identity cert is self-signed")
    assert verify_cert(link_cert, id_cert)
    print("link cert is signed by identity cert")
    assert not verify_cert(id_cert, link_cert)
    print("identity cert is NOT signed by link cert (sanity check)")
