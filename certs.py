from OpenSSL import crypto, SSL
import random
import string
 
def random_hostname():
    return 'www.' + ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '.com'
 
def create_cert(key, signing_key, cn, issuer_cert):
    cert = crypto.X509()
    cert.get_subject().CN = random_hostname()
    cert.set_serial_number(random.randint(0,2**63))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    if issuer_cert:
        cert.set_issuer(issuer_cert.get_subject())
    else:
        cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(signing_key, 'sha256')

    #print( crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode() )
    #print( crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode() )
    return cert

def verify_cert(cert, signing_cert):
    cert_store = crypto.X509Store()
    cert_store.add_cert(signing_cert)
    store_ctx = crypto.X509StoreContext(cert_store, cert)
    try:
        store_ctx.verify_certificate()
    except:
        return False
    else:
        return True
 
if __name__ == '__main__':
    id_key = crypto.PKey()
    id_key.generate_key(crypto.TYPE_RSA, 1024)
    with open('id_key.pem', 'w') as f:
        f.write( crypto.dump_privatekey(crypto.FILETYPE_PEM, id_key).decode() )

    link_key = crypto.PKey()
    link_key.generate_key(crypto.TYPE_RSA, 1024)
    with open('link_key.pem', 'w') as f:
        f.write( crypto.dump_privatekey(crypto.FILETYPE_PEM, link_key).decode() )
 
    id_cert = create_cert(id_key, id_key, 'id', None)
    with open('id_cert.pem', 'w') as f:
        f.write( crypto.dump_certificate(crypto.FILETYPE_PEM, id_cert).decode() )

    link_cert = create_cert(link_key, id_key, 'link', id_cert)
    with open('link_cert.pem', 'w') as f:
        f.write( crypto.dump_certificate(crypto.FILETYPE_PEM, link_cert).decode() )

    print(verify_cert(id_cert, id_cert))
    print(verify_cert(link_cert, id_cert))
    print(verify_cert(id_cert, link_cert))
