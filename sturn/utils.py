import hashlib


def saslprep(string):
    #TODO
    return string

def ha1(username, realm, password):
    data = b':'.join((username.encode('utf-8'), realm, saslprep(password.encode('utf-8'))))
    return hashlib.md5(data).digest()
