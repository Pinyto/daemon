#!/usr/bin/env python3
import dbus
from dbus.service import BusName
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GObject
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from base64 import b16decode, b16encode
from os.path import expanduser
import requests
import json
import os
import sys


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
    key = RSA.generate(3072, Random.new().read)
    key_data = {
        'N': str(key.n),
        'e': key.e,
        'd': str(key.d)
    }
    hasher = sha256()
    hasher.update((str(key.n) + str(key.e)).encode('utf-8'))
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
        signature = (int(authenticate_response_json['signature']),)
        hasher = sha256()
        hasher.update(encrypted_token.encode('utf-8'))
        pinyto_public_key = RSA.construct((
            int("352338828109401093003984019495831935971782553824939880555182746966856089430233286534546578391626413" +
                "889711944870759073912120837972163560539068302721433441470599319461830662743105237366621489460749807" +
                "064695106317511851649828802426144511321407267371613900315155373702173982644362916496126265649482466" +
                "673875349489907047908512127914975432839016239992366271779549922103338911663557549622535507034970312" +
                "887582031790221065308884097203719721616172747651142792797058845232091562500374024618481921283765146" +
                "459067479963822779551936787918661317227947726850380461998140456287231079109312171798861513513789080" +
                "346324162225532044317709266220083319146995607428104864657690958344956798558928659127626778976913687" +
                "922038630858294674378500969405467193853683891419773979306334712430415320754994796575136923208255925" +
                "000108833432201573577913512113607190233763574663786408344944398826274620266607863472810162138551510" +
                "9353596589585237881665906747589713"),
            65537))
        if not pinyto_public_key.verify(hasher.hexdigest().encode('utf-8'), signature):
            print('Pinyto-Cloud signature is wrong. This is a man-in-the-middle-attack!')
            sys.exit(1)
        key = RSA.construct((int(key_data['N']), int(key_data['e']), int(key_data['d'])))
        user_cipher = PKCS1_OAEP.new(key)
        real_token = user_cipher.decrypt(b16decode(encrypted_token))
        pinyto_cipher = PKCS1_OAEP.new(pinyto_public_key)
        authentication_token = str(b16encode(pinyto_cipher.encrypt(real_token)), encoding='utf-8')
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


# Settings
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