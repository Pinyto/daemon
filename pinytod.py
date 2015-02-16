#!/usr/bin/env python3
import dbus
from dbus.service import BusName
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GObject
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from hashlib import sha256
from base64 import b64decode, b64encode
from os.path import expanduser
import requests
import json
import os
import sys


PINYTO_PUBLIC_KEY = rsa.RSAPublicNumbers(
    65537,
    int("7829487815098536540163340882101624716263699124284776727331856400402012605068617607074848020780929263286" +
        "1777371795066320667094273729808501496067021755785325385319270032155555860380403694273039781832166222574" +
        "0982623746713760050717491720444401365859377904761509456912858624197383009910897359227163603168055069076" +
        "2988650388634810877021897370043618319224015852080391715109009180201275625896119513840827703345319162546" +
        "4956424352483465726648149599154639222100356593400640583898292902042777225273667494325059986268195514181" +
        "6261927004696811927915492285857001606967204165474930842200356404798932927527349880460038664735604799615" +
        "6575351492978859740957294904746191106691211687301808176923284964142198110073079545921504748367207486987" +
        "3816642503072179364939244345082744417171570594851345415294043745634023662066627610259775478034263984167" +
        "9047815006824885208959469459587070768606268964437819028000766288835526004124480298771987405845901023717" +
        "0023812712182602254669659406038944136636863318312128196609065625793814435451291091924867897181456040979" +
        "3979413614936337848290374830746444999167778857351617508196024135490271644440537219056271178956203994401" +
        "1689062773834284439722273182150964910834681668991726977737508228377398684622376557220679678700827641")
).public_key(default_backend())


class DemoException(dbus.DBusException):
    _dbus_error_name = 'de.pinyto.daemonException'


class BackofficeInterface(dbus.service.Object):
    @dbus.service.method("de.pinyto.daemon.backoffice",
                         in_signature='s', out_signature='as')
    def HelloWorld(self, hello_message):
        print(str(hello_message))
        return ["Hello", " from example-service.py", "with unique name",
                session_bus.get_unique_name()]

    @dbus.service.method("de.pinyto.daemon.backoffice",
                         in_signature='', out_signature='')
    def RaiseException(self):
        raise DemoException('The RaiseException method does what you might '
                            'expect')

    @dbus.service.method("de.pinyto.daemon.backoffice",
                         in_signature='', out_signature='(ss)')
    def GetTuple(self):
        return ("Hello Tuple", " from pinytod.py")

    @dbus.service.method("de.pinyto.daemon.backoffice",
                         in_signature='', out_signature='a{ss}')
    def GetDict(self):
        return {"first": "Hello Dict", "second": " from pinytod.py"}

    @dbus.service.method("de.pinyto.daemon.backoffice",
                         in_signature='', out_signature='')
    def Exit(self):
        mainloop.quit()


class AssemblyCallInterface(dbus.service.Object):
    @dbus.service.method("de.pinyto.daemon.api",
                         in_signature='ssss', out_signature='s')
    def ApiCall(self, assembly_username, assembly_name, function_name, data):
        if not connected:
            return json.dumps({'error': 'No connection to the cloud.'})
        data_dict = json.loads(data)
        data_dict['token'] = token
        data = json.dumps(data_dict)
        response = requests.post(
            cloud_url + assembly_username + '/' + assembly_name + '/' + function_name,
            data=data, headers={'content-type': 'application/json'})
        if response.status_code != 200:
            return json.dumps({'error': 'Unable to connect to the cloud. The daemon is authenticated but ' +
                                        'the request returned the error code: ' + response.status_code})
        return response.text


def generate_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    key_data = {
        'N': str(key.public_key().public_numbers().n),
        'e': key.public_key().public_numbers().e,
        'd': str(key.private_numbers().d),
        'p': str(key.private_numbers().p),
        'q': str(key.private_numbers().q)
    }
    hasher = sha256()
    hasher.update((key_data['N'] + str(key_data['e'])).encode('utf-8'))
    key_data['hash'] = hasher.hexdigest()[:10]
    return key_data


def logout_from_keyserver():
    global token_from_keyserver
    if not token_from_keyserver:
        return False
    logout_response = requests.post(
        cloud_url + 'logout',
        data=json.dumps({'token': token_from_keyserver}),
        headers={'content-type': 'application/json'})
    if logout_response.status_code != 200:
        print('Unable to logout from keyserver: Could not connect. The error code was: ' +
              logout_response.status_code)
    logout_response_json = logout_response.json()
    if 'success' in logout_response_json and logout_response_json['success']:
        return False
    else:
        if 'error' in logout_response_json:
            print('Unable to logout from keyserver. The error was: ' + logout_response_json['error'])
        else:
            print('Unable to logout. The keyserver responded with the following invalid answer: ' +
                  logout_response.text)
        return False


def register_key(username, n, e):
    password = input('Enter password: ')
    keyserver_authenticate_response = requests.post(
        cloud_url + 'keyserver/authenticate',
        data=json.dumps({'name': username, 'password': password}),
        headers={'content-type': 'application/json'})
    if keyserver_authenticate_response.status_code != 200:
        print('Could not connect to keyserver. The error code was: ' +
              str(keyserver_authenticate_response.status_code))
        sys.exit(1)
    keyserver_answer = keyserver_authenticate_response.json()
    if 'token' in keyserver_answer:
        global token_from_keyserver
        token_from_keyserver = keyserver_answer['token']
    else:
        if 'error' in keyserver_answer:
            print('Unable to authenticate at the keyserver. The error was: ' + keyserver_answer['error'])
        else:
            print('Unable to authenticate at the keyserver. It responded with the following invalid answer: ' +
                  keyserver_authenticate_response.text)
        sys.exit(1)
    register_response = requests.post(
        cloud_url + 'register_new_key',
        data=json.dumps({'token': token_from_keyserver, 'public_key': {'N': n, 'e': e}}),
        headers={'content-type': 'application/json'})
    if register_response.status_code != 200:
        print('Unable to register a new key: Could not connect to cloud server. The error code was: ' +
              register_response.status_code)
        sys.exit(1)
    register_response_json = register_response.json()
    if 'success' in register_response_json and register_response_json['success']:
        GObject.timeout_add(1, logout_from_keyserver)
        return True
    if 'error' in register_response_json:
        print('Unable to register a new key. The error was: ' + register_response_json['error'])
        sys.exit(1)
    print('Unable to register a new key. The cloud responded with the following invalid answer: ' +
          register_response.text)
    sys.exit(1)


def get_key_data():
    home = expanduser("~")
    try:
        with open(home + '/.pinyto/key.json', mode='r') as key_file:
            key_data = json.loads(key_file.read())
    except FileNotFoundError:
        print('With this device you are not registered at the Pinyto cloud.')
        print('The daemon will automatically register itself with the cloud ' +
              'but it needs your Pinyto credentials once for that.')
        if not os.path.exists(home + '/.pinyto/'):
            os.mkdir(home + '/.pinyto/', mode=0o700)
        key_data = generate_key()
        key_data['username'] = input('Enter username: ')
        register_key(key_data['username'], n=key_data['N'], e=key_data['e'])
        with open(home + '/.pinyto/key.json', mode='w') as key_file:
            key_file.write(json.dumps(key_data))
    return key_data


def authenticate_at_cloud():
    url = cloud_url + 'authenticate'
    headers = {'content-type': 'application/json'}
    key_data = get_key_data()
    data = {
        'username': key_data['username'],
        'key_hash': key_data['hash']
    }
    authenticate_response = requests.post(url, data=json.dumps(data), headers=headers)
    if authenticate_response.status_code != 200:
        return False, 'Could not connect to cloud server. The error code was: ' + authenticate_response.status_code
    authenticate_response_json = authenticate_response.json()
    if 'encrypted_token' in authenticate_response_json and 'signature' in authenticate_response_json:
        encrypted_token = authenticate_response_json['encrypted_token']
        signature = b64decode(authenticate_response_json['signature'].encode('utf-8'))
        verifier = PINYTO_PUBLIC_KEY.verifier(
            signature,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        verifier.update(encrypted_token.encode('utf-8'))
        try:
            verifier.verify()
        except InvalidSignature:
            print('Pinyto-Cloud signature is wrong. This is a man-in-the-middle-attack!')
            sys.exit(1)
        public_numbers = rsa.RSAPublicNumbers(key_data['e'], int(key_data['N']))
        p = int(key_data['p'])
        q = int(key_data['q'])
        d = int(key_data['d'])
        dmp1 = rsa.rsa_crt_dmp1(key_data['e'], p)
        dmq1 = rsa.rsa_crt_dmq1(key_data['e'], q)
        iqmp = rsa.rsa_crt_iqmp(p, q)
        key = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers).private_key(default_backend())
        token = key.decrypt(
            b64decode(encrypted_token.encode('utf-8')),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None)
        )
        authentication_token = str(b64encode(PINYTO_PUBLIC_KEY.encrypt(
            token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None)
        )), encoding='utf-8')
        return True, authentication_token
    if 'error' in authenticate_response_json:
        return False, authenticate_response_json['error']
    return False, 'The cloud responded with the following invalid answer: ' + authenticate_response.text


def try_to_connect():
    global connected
    global token
    global error_message
    connected, token = authenticate_at_cloud()
    if not connected:
        error_message = token  # If we could not connect the second parameter contains the error message.
        print(error_message)
        return True
    return False


# Load Settings
home = expanduser("~")
try:
    with open(home + '/.pinyto/cloud_url', mode='r') as url_file:
        cloud_url = ''.join(url_file.read().split())
except FileNotFoundError:
    cloud_url = 'https://pinyto.de/'

if __name__ == '__main__':
    DBusGMainLoop(set_as_default=True)

    session_bus = dbus.SessionBus()
    name = dbus.service.BusName("de.pinyto.daemon", session_bus)
    backoffice_interface = BackofficeInterface(session_bus, '/Backoffice')
    assembly_call_interface = AssemblyCallInterface(session_bus, '/Assembly')

    token_from_keyserver = False
    connected, token = authenticate_at_cloud()
    if not connected:
        error_message = token  # If we could not connect the second parameter contains the error message.
        print(error_message)
        GObject.timeout_add(300000, try_to_connect)

    mainloop = GObject.MainLoop()
    print("Pinyto daemon started.")
    mainloop.run()