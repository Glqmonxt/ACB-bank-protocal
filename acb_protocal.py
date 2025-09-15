
import requests
import http.client
import json

import sys
import shutil
import threading

import hashlib
import os
import random
import getopt
import time
import ssl

from Crypto.Cipher import AES
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import utils

import unittest
from hashlib import sha256

from ecdsa import SigningKey,NIST192p,NIST224p,NIST256p,NIST384p,NIST521p,SECP256k1
import binascii
from ecdsa.util import sigencode_der

from cryptography.hazmat.primitives.asymmetric import ec 

from typing_extensions import deprecated
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from ecies import encrypt, decrypt




g_username = b''
g_password = b''
g_repl_img = 'xx.jpg'




t_x = '5557d0d9b05ecb0b'
t_x = list(t_x)
for j in range(len(t_x)):                    
    if (t_x[j]>='0' and t_x[j]<='9') or (t_x[j]>='a' and t_x[j]<='f'):
        t_x[j] = random.choice("0123456789abcdef")
mm_deviceid = ''.join(t_x)
g_deviceId = mm_deviceid.encode("utf-8")
print(g_deviceId)

t_x = 'fdGEOklGRvSZ9HPeVsb4ig:APA91bHPMHeiAgcFt8C4q4dYv7lxw65LZeaYMJREHj0qRzH1fQmgbroZiGUXzzMVfEalQ_zeWzO1X0p6z4vCcH1vvSXZLoGuHcPCz6bNWbvqfcqRcM1nWw'
t_x = list(t_x)
for j in range(len(t_x)):                    
    if (t_x[j]>='0' and t_x[j]<='9') or (t_x[j]>='a' and t_x[j]<='f'):
        t_x[j] = random.choice("0123456789abcdef")
mm_deviceToken = ''.join(t_x)
g_deviceToken = mm_deviceToken.encode("utf-8")
print(g_deviceToken)


mm_device = 0
if mm_device == 0:
    g_app_version = '3.38.2' 
    #g_deviceId = b'5557d0d9b05ecb0b'
    #g_deviceToken = b'fdGEOklGRvSZ9HPeVsb4ig:APA91bHPMHeiAgcFt8C4q4dYv7lxw65LZeaYMJREHj0qRzH1fQmgbroZiGUXzzMVfEalQ_zeWzO1X0p6z4vCcH1vvSXZLoGuHcPCz6bNWbvqfcqRcM1nWw'
    g_deviceName = b'Pixel 6'
    g_brandName = b'google'
    g_osVersion = b'ANDROID 13'
    g_deviceData = g_deviceId+b'|google|Pixel 6|android|13|0|2|'+g_deviceToken
    g_deviceType = b'4'
    g_sync = '{"deviceId":"'+g_deviceId.decode("utf-8")+'","deviceName":"Pixel 6","latitude":"-1","longitude":"-1","devicePushToken":"'+g_deviceToken.decode("utf-8")+'","osType":"ANDROID","grantType":"password","osVersion":"13","deviceModel":"Google_Pixel 6 (oriole)","appVersion":"'+g_app_version+'","status":1,"isAccess":false}'
    g_update_device_token = '{"deviceId":"'+g_deviceId.decode("utf-8")+'","deviceLanguage":"en","deviceModel":"Google_Pixel 6 (oriole)","deviceToken":"'+g_deviceToken.decode("utf-8")+'","deviceName":"Pixel 6","deviceOsType":"ANDROID","osVersion":"13","userName":"'+g_username.decode("utf-8")+'"}'  
    


####################################################################


g_bank_tag = b'ACBBankn0NjMkIX8fvMudHppnp43qfLR'
g_providerCode = b'00017'
    
g_clinet_secretKey = b'acb1e779c503a8cf5b436aca96addb147afd903d'
g_key_from_seed = b'hk$<djuwjwkHDuwp'



g_user_info_dict = {'app_version':g_app_version,
    'username':g_username.decode("utf-8"), 
    'password':g_password.decode("utf-8"),
    'deviceId':g_deviceId.decode("utf-8"),
    'deviceName':g_deviceName.decode("utf-8"),
    'userID':'',
    'tokenID':'',
    'clientID':''
}

context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.load_cert_chain(certfile='acb_cert.crt')

t_x = 'e0374c05-c852875e-bec8-6ebb-d17010287e87'
t_x = list(t_x)
for j in range(len(t_x)):                    
    if (t_x[j]>='0' and t_x[j]<='9') or (t_x[j]>='a' and t_x[j]<='f'):
        t_x[j] = random.choice("0123456789abcdef")
x_conversation_id = ''.join(t_x)
x_conversation_id0 =x_conversation_id + '-0-'
x_conversation_id =x_conversation_id + '-1-'
print(x_conversation_id)

def x_request_id():
    t_x = '357ad54d-e3bb-4bb5-2cd7-0a80b7ad2601'
    t_x = list(t_x)
    for j in range(len(t_x)):                    
        if (t_x[j]>='0' and t_x[j]<='9') or (t_x[j]>='a' and t_x[j]<='f'):
            t_x[j] = random.choice("0123456789abcdef")
    return ''.join(t_x)
    
#################################################################################################
g_folder = g_deviceName.decode("utf-8")+'-'+g_deviceId.decode("utf-8")+'-'+g_username.decode("utf-8")
if os.path.exists(g_folder): 
    shutil.rmtree(g_folder)
os.mkdir(g_folder)
g_folder = g_folder+'/'

shutil.copy('acb_cert.crt', g_folder+'acb_cert.crt')
shutil.copy('ecc_enc_pubkey.pem', g_folder+'ecc_enc_pubkey.pem')
shutil.copy('rsa_enc_pubkey.pem', g_folder+'rsa_enc_pubkey.pem')

shutil.copy('key_lists.txt', g_folder+'key_lists.txt')
shutil.copy('cur_key_cnt.txt', g_folder+'cur_key_cnt.txt')

shutil.copy('random_data.txt', g_folder+'random_data.txt')
shutil.copy('random_data_postion.txt', g_folder+'random_data_postion.txt')

shutil.copy('transfer.py', g_folder+'transfer.py')
shutil.copy('balance.py', g_folder+'balance.py')

shutil.copy(g_repl_img, g_folder+g_repl_img)

with open(g_folder+"appInstanceId.txt", "w+") as f:
    f.write(m_app_instanceId)
    
with open(g_folder+"deviceData.txt", "w+") as f:
    f.write(g_deviceData.decode("utf-8"))

with open(g_folder+"sync.txt", "w+") as f:
    f.write(g_sync)
    
with open(g_folder+"update_device_token.txt", "w+") as f:
    f.write(g_update_device_token)
#################################################################################################

ecc_priv_str = '303E020100301006072A8648CE3D020106052B8104000A042730250201010420BFDC0BB92076D7A76E4A511CA55E97A087FE7EB6503D4E102ECDAF9524F0699F'
ecc_priv_str = list(ecc_priv_str)
for j in range(64,128):                    
    ecc_priv_str[j] = random.choice("0123456789ABCDEF")
ecc_priv_str = ''.join(ecc_priv_str)
ecc_priv_str = bytes.fromhex(ecc_priv_str)
ecc_priv_hex = ecc_priv_str[32:]

ecc_priv_pem = '-----BEGIN PRIVATE KEY-----\n'
ecc_priv_pem = ecc_priv_pem + base64.b64encode(ecc_priv_str).decode('utf-8') + '\n'
ecc_priv_pem = ecc_priv_pem + '-----END PRIVATE KEY-----'

with open(g_folder+"ecc_sign_privkey.pem", "w+") as f:
    f.write(ecc_priv_pem)
    
#print(ecc_priv_pem)
ecc_private_key = serialization.load_pem_private_key(
    ecc_priv_pem.encode("utf-8"),
    password=None,
    backend=default_backend()
    )

ecc_public_key = ecc_private_key.public_key()

serialized_public = ecc_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
serialized_public = serialized_public.split(b'\n')

serialized_public = serialized_public[1]+serialized_public[2]
serialized_ecc_public = serialized_public[:72]+b'\n'+serialized_public[72:]+b'\n'
#print(serialized_ecc_public)

#################################################################################################

f2 = open('rsa_key_position.txt', 'r+',encoding='utf-8')
rsa_key_position = f2.read()
f2.close()

rsa_key_position = int(rsa_key_position.strip())

f2 = open('rsa_key_position.txt', 'w+',encoding='utf-8')
f2.write(str(rsa_key_position+1))
f2.close()


f1 = open('rsa_key_data.txt', 'r+',encoding='utf-8')
ss = f1.readlines()
line_cnt = 0


rsa_priv_key_pem = ''
k=0
while(k<25):        
    rsa_priv_key_pem = rsa_priv_key_pem + ss[rsa_key_position*33+k]
    k = k+1


rsa_pub_key_pem = ''
k=26
while(k<32):        
    rsa_pub_key_pem = rsa_pub_key_pem + ss[rsa_key_position*33+k]
    k = k+1
f1.close()



with open(g_folder+"rsa_sign_privkey.pem", "w+") as f:
    f.write(rsa_priv_key_pem)

#print(rsa_priv_key_pem)
rsa_private_key = serialization.load_pem_private_key(
    rsa_priv_key_pem.encode("utf-8"),
    password=None,
    backend=default_backend()
    )

rsa_public_key = rsa_private_key.public_key()

serialized_public = rsa_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
serialized_public = serialized_public.split(b'\n')


#################################################################################################

def RSA_ENC(plain_text):
    global rsa_private_key
    
    random_key ="".join(
        random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
        for _ in range(16)
    )
    aes_key = random_key.encode("utf-8") 
    
    #aes_key = b'AWOXIsFQTspOg6Jj'
    print(aes_key)   

    iv = b'\x6A\x79\x64\x64\x41\x64\x69\x62\x44\x59\x76\x68\x67\x61\x4A\x6F' # iv偏移量，bytes类型
    
    text =b'\x58\xF2\xB8\x98\x20\xAE\xF5\x2B\x75\x33\x20\x12\xE1\x5F\x8B\xEA'+ plain_text
    #print(text)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    aes_en_text = base64.b64encode(ciphertext)
    #print(aes_en_text)

    #RSA/OAEP-MGF1(SHA-256)
    with open('rsa_enc_pubkey.pem', "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), default_backend())

        # Encrypt the hash with the public key
        encrypted = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        rsa_en_key = base64.b64encode(encrypted)
        #print(rsa_en_key)
    
    return aes_en_text,rsa_en_key
    
def RSA_DEC(ciphertext):  
    global rsa_private_key
    plaintext = rsa_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def RSA_SIGN(text):  
    global rsa_private_key
    
    signature = rsa_private_key.sign(
        text,
        padding.PKCS1v15(),
        hashes.SHA256()        
    )
    
    signature = base64.b64encode(signature)
    signature = signature.decode('utf-8')
    signature = signature[:72]+'\\n'+signature[72:144]+'\\n'+signature[144:216]+'\\n'+signature[216:288]+'\\n'+signature[288:]+'\\n'
    #print(signature)
    return signature

#################################################################################################


data_x_23 = b'WWMKU2QRY5IM2ZXVY37DPV55SAWRO3LIGOOXDWVZEV4QP3RVOBSOAGGTS2YRRMDU'
def calculate_key_with_random(random_v):
    global g_deviceId
    
    data_x_8 = b'@MKgroup&MKTech!@MKgroup&MKTech!'
    data_x_22 = g_deviceId + b'000000000000000000000000'
    
    key = b''
    for i in range(32):
        v0 = (i+
            data_x_8[i]+
            data_x_22[i]+
            random_v[i]+
            data_x_22[39-i]+
            random_v[39-i])&0xff
        key = key + v0.to_bytes(1,'big')

    print(key.hex())
    return key


def ECC_DEC(encrypted):
    global ecc_priv_hex
    
    decrypted = decrypt(ecc_priv_hex, encrypted)
    print("Decrypted:", decrypted)
    return decrypted
    

    
def ECC_ENC(plain_text):
    global ecc_private_key
    
    f2 = open('random_data_postion.txt', 'r+',encoding='utf-8')
    random_data_postion = f2.read()
    f2.close()

    random_data_postion = int(random_data_postion.strip())

    f2 = open('random_data_postion.txt', 'w+',encoding='utf-8')
    f2.write(str(random_data_postion+1))
    f2.close()

    #print(random_data_postion)

    key_line = ""
    f1 = open('random_data.txt', 'r+',encoding='utf-8')
    for i in range(random_data_postion):
        key_line = f1.readline()
    f1.close()

    #print(key_line)
    
    if key_line == b'':
        print("not enough key")
        sys.exit(0)
    
    key_line = key_line.strip()
    key_line = key_line.split(':', 1 )
    random_v = key_line[0]
    ecc_enc_random_v = eval(key_line[1])
    aes_key = calculate_key_with_random(random_v.encode("utf-8"))

    iv = b'\x4B\x71\x55\x51\x67\x4E\x6B\x44\x6D\x69\x30\x4A\x68\x64\x39\x30'
    text =b'\xBD\x96\xA8\x79\xF0\xCB\xA3\xE6\xF9\x9C\xA8\x79\x35\x1F\x5F\x36'+ plain_text

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    en_text = base64.b64encode(ciphertext)
    random_ecc_enc = base64.b64encode(ecc_enc_random_v)
    
    #print(en_text)
    #print(random_ecc_enc)
    
    return en_text,random_ecc_enc


def ECC_SIGN(message): 
    global ecc_private_key
    
    signature = ecc_private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    signature = base64.b64encode(signature)
    
    return signature
    

#################################################################################################




receive_bank = ''
napasBankCode = ''
receive_account = ''
transfer_mount = ''
bankName = 'VPBANK - NH TMCP VIET NAM THINH VUONG'



g_authorization = ''
    
    
def HandleTokenExpire():
    global g_authorization
    global g_deviceId
    global x_conversation_id
    
    print('token expired, refreshing')
    f_refresh = open('RefeshToken.txt', 'r+',encoding='utf-8')
    refresh_token = f_refresh.read()
    f_refresh.close()

    
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    headers311 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'Bearer '+refresh_token,
        #'Content-Length': '0',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }
    
    
    #body31 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body31 = json.dumps(json.loads(data31))
    conn.request("POST", "/mb/v2/auth/refresh",'', headers311)
    response = conn.getresponse()    
    print(response.status, response.reason)
    print('refresh refresh')
    
    if response.status == 200:
        json_data = json.loads(response.read())
        print(json_data)
        new_authorization = json_data["accessToken"]  
        
        words = new_authorization.split('\n')
        new_authorization = "".join(words)       
        
        if new_authorization != "":
            f_autht = open('AuthToken.txt', 'w+',encoding='utf-8')
            f_autht.write(new_authorization)
            f_autht.close()
            
            f_autht = open(g_folder+'AuthToken.txt', 'w+',encoding='utf-8')
            f_autht.write(new_authorization)
            f_autht.close()
            
            g_authorization = new_authorization
            
            print(g_authorization)

    else:
        sys.exit(0)

#################################################################################################
   

conn = http.client.HTTPSConnection("firebaseremoteconfig.googleapis.com")
headers2 = {
    'X-Goog-Api-Key': 'AIzaSyCROjbdnExTSBmH8pwqOOegeTB3kBj82bE',
    'X-Android-Package': 'mobile.acb.com.vn',
    'X-Android-Cert': '9C6D676F07F2583936A1162CB6B5C502264EFA8A',
    'X-Google-GFE-Can-Retry': 'yes',
    'X-Goog-Firebase-Installations-Auth': 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjE6Mjc2OTE1Mzg5MDEyOmFuZHJvaWQ6MzJkNjA0M2ZmNDIzMDAzMyIsImV4cCI6MTc0OTQ1MjE1OSwiZmlkIjoiZnZJWENZWUVUMkNvWFpRWnJnX19fWCIsInByb2plY3ROdW1iZXIiOjI3NjkxNTM4OTAxMn0.AB2LPV8wRQIgEzlQJPjRl6Tp965efptQrF9TCE1MTSUQRTI79aCyDscCIQCRcnJlQ-xNy58JMvHH5B_fNWtGLg4Ihpa-QBCRqEBWyg',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    #'Content-Length': '691',
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Pro Build/TQ3A.230901.001.C2)',
    'Host': 'firebaseremoteconfig.googleapis.com',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip'
}

data2 = r'''{"appVersion":"'''+g_app_version+'''","firstOpenTime":"2025-06-13T09:00:00.000Z","timeZone":"Asia\/Shanghai","appInstanceIdToken":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjE6Mjc2OTE1Mzg5MDEyOmFuZHJvaWQ6MzJkNjA0M2ZmNDIzMDAzMyIsImV4cCI6MTc1MDQwODc4NSwiZmlkIjoiZVZYdENMZnpUa3E4NlduMEgzRWdpYyIsInByb2plY3ROdW1iZXIiOjI3NjkxNTM4OTAxMn0.AB2LPV8wRQIhALl00GUKnu66rJfa8CfUOOiyVayKLVMywJUt4BHUNukBAiBFayJ_39hWnuS-EmOX3d0JaNMig3udcsvFkc2Z91JfGw","languageCode":"en-US","appBuild":"3380203","appInstanceId":"'''+m_app_instanceId+'''","countryCode":"US","analyticsUserProperties":{},"appId":"1:276915389012:android:32d6043ff4230033","platformVersion":"33","sdkVersion":"21.1.1","packageName":"mobile.acb.com.vn"}'''
#body2 = urllib.urlencode({'spam': 1, 'eggs': 2})
body2 = json.dumps(json.loads(data2))
conn.request("POST", "/v1/projects/276915389012/namespaces/firebase:fetch",body2, headers2)
response = conn.getresponse()
print(response.status, response.reason)
print('2 2')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()



conn = http.client.HTTPSConnection("aichatbot.acb.com.vn")
headers3 = {
    'accept': 'application/json, text/plain, */*',
    'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjIwMDYxNzQwMTQsImlhdCI6MTY5MDgxNDAxNCwiaXNzIjoiNjRjN2M2M2VmNTBhNWJmYTBkZTE5YmY4IiwicHVibGljX2lkIjoiNjMyYWQyMzAwODVkYzRhZjFiMGQ0NTBkIiwibmFtZSI6ImNoYXRib3QifQ.Catc4mMpNp7cadBDE4_PSGXJRfjWudkh7yJ8GV9S2jRGVUhq_bNZUxjm4mjR1rytXjb9kOdln8wEh8zeAbuDDHaa7aMk0idFgZeLSNRJ1HX7rzVVDDaTZvGlWW3DiCI6qVXcrJLmtibxEvpicPbqicOxs4Wu7PZ5NsVG43FLM9teeaBu1_KeFTEgyhSX3qGaosAp2WUcVhtGV2zRMmiFH__kfgs0u2YOp2D5vVjjZRfUWqMUWGXgRVfdQW8TIylTOqvMK8H1eyHHdYGhmuV-beDhyNoR_CN8BxWFN4Qi3fdf8NHD7aWPJLPILB3nHo6BIz2j_9K4wJQpIY4097dPnw',
    'Host': 'aichatbot.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body3 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body3 = json.dumps(json.loads(data3))
conn.request("GET", "/api/v1/chatbot_gateway/agents/632ad230085dc4af1b0d450d/channel/64c7c63e405b4ec5dad03e68/setting",'', headers3)
response = conn.getresponse()
print(response.status, response.reason)
print('3 3')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    m_age = response.getheader('Age')
    m_age = response.getheaders()
    print(m_age)



conn = http.client.HTTPSConnection("firebaseremoteconfig.googleapis.com")
headers4 = {
    'If-None-Match': 'etag-276915389012-firebase-fetch-446276012',
    'X-Goog-Api-Key': 'AIzaSyCROjbdnExTSBmH8pwqOOegeTB3kBj82bE',
    'X-Android-Package': 'mobile.acb.com.vn',
    'X-Android-Cert': '9C6D676F07F2583936A1162CB6B5C502264EFA8A',
    'X-Google-GFE-Can-Retry': 'yes',
    'X-Goog-Firebase-Installations-Auth': 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjE6Mjc2OTE1Mzg5MDEyOmFuZHJvaWQ6MzJkNjA0M2ZmNDIzMDAzMyIsImV4cCI6MTc0OTQ1MjE1OSwiZmlkIjoiZnZJWENZWUVUMkNvWFpRWnJnX19fWCIsInByb2plY3ROdW1iZXIiOjI3NjkxNTM4OTAxMn0.AB2LPV8wRQIgEzlQJPjRl6Tp965efptQrF9TCE1MTSUQRTI79aCyDscCIQCRcnJlQ-xNy58JMvHH5B_fNWtGLg4Ihpa-QBCRqEBWyg',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    #'Content-Length': '691',
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Pro Build/TQ3A.230901.001.C2)',
    'Host': 'firebaseremoteconfig.googleapis.com',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip'
}

data4 = r'''{"appVersion":"'''+g_app_version+'''","firstOpenTime":"2025-06-13T09:00:00.000Z","timeZone":"Asia\/Shanghai","appInstanceIdToken":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjE6Mjc2OTE1Mzg5MDEyOmFuZHJvaWQ6MzJkNjA0M2ZmNDIzMDAzMyIsImV4cCI6MTc1MDQwODc4NSwiZmlkIjoiZVZYdENMZnpUa3E4NlduMEgzRWdpYyIsInByb2plY3ROdW1iZXIiOjI3NjkxNTM4OTAxMn0.AB2LPV8wRQIhALl00GUKnu66rJfa8CfUOOiyVayKLVMywJUt4BHUNukBAiBFayJ_39hWnuS-EmOX3d0JaNMig3udcsvFkc2Z91JfGw","languageCode":"en-US","appBuild":"3380203","appInstanceId":"'''+m_app_instanceId+'''","countryCode":"US","analyticsUserProperties":{},"appId":"1:276915389012:android:32d6043ff4230033","platformVersion":"33","sdkVersion":"21.1.1","packageName":"mobile.acb.com.vn"}'''
#body4 = urllib.urlencode({'spam': 1, 'eggs': 2})
body4 = json.dumps(json.loads(data4))
conn.request("POST", "/v1/projects/276915389012/namespaces/firebase:fetch",body4, headers4)
response = conn.getresponse()
print(response.status, response.reason)
print('4 4')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()




conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers5 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id0,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer',
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body5 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body5 = json.dumps(json.loads(data5))
conn.request("GET", "/mb/legacy/ss/cs/login/is-organization?username="+g_username.decode('utf-8')+"",'', headers5)
response = conn.getresponse()
print(response.status, response.reason)
print('5 5')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()


conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers7 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id0,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'Content-Type': 'application/json',
    #'Content-Length': '123',
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}

data7 = r'''{"username":"'''+g_username.decode('utf-8')+'''","password":"'''+g_password.decode('utf-8')+'''","deviceId":"'''+g_deviceId.decode("utf-8")+'''","clientId":"iuSuHYVufIUuNIREV0FB9EoLn9kHsDbm"}'''
#body7 = urllib.urlencode({'spam': 1, 'eggs': 2})
body7 = json.dumps(json.loads(data7))
conn.request("POST", "/mb/v2/auth/tokens",body7, headers7)
response = conn.getresponse()
print(response.status, response.reason)
print('7 7')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()

g_eUserId = ''
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    new_authorization = json_data["accessToken"]
    new_refresh_token = json_data["refreshToken"]
    m_verificationSessionId = json_data["verificationSessionId"]
    m_guid = json_data["identity"]["id"]
    g_eUserId = str(json_data["eUserId"])
    
    if g_eUserId == '' :
        sys.exit(0)
    
    print(new_authorization)
    words = new_authorization.split('\n')
    new_authorization = "".join(words)
    print(new_refresh_token)
    
    
    
    words = new_refresh_token.split('\n')
    new_refresh_token = "".join(words)
    
    f_verf = open(g_folder+'verificationSessionId.txt', 'w+',encoding='utf-8')
    f_verf.write(m_verificationSessionId)
    f_verf.close()
    
    f_guid = open(g_folder+'guid.txt', 'w+',encoding='utf-8')
    f_guid.write(m_guid)
    f_guid.close()
        
    if new_authorization != "":
        f_autht = open('AuthToken.txt', 'w+',encoding='utf-8')
        f_autht.write(new_authorization)
        f_autht.close()
        
        
        f_autht = open(g_folder+'AuthToken.txt', 'w+',encoding='utf-8')
        f_autht.write(new_authorization)
        f_autht.close()
        
        g_authorization = new_authorization
        
    if new_refresh_token != "":    
        f_rfrst = open('RefeshToken.txt', 'w+',encoding='utf-8')
        f_rfrst.write(new_refresh_token)
        f_rfrst.close()
        
        f_rfrst = open(g_folder+'RefeshToken.txt', 'w+',encoding='utf-8')
        f_rfrst.write(new_refresh_token)
        f_rfrst.close()
        
else:
    sys.exit(0)





time.sleep(3)

conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers9 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body9 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body9 = json.dumps(json.loads(data9))
conn.request("GET", "/mb/legacy/ss/cs/bio/information",'', headers9)
response = conn.getresponse()
print(response.status, response.reason)
print('9 9')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
#HandleTokenExpire()





conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
headers10 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json'
    #'Content-Length': '2',
}

data10 = r'''{}'''
#body10 = urllib.urlencode({'spam': 1, 'eggs': 2})
body10 = json.dumps(json.loads(data10))
conn.request("POST", "/bio/sdk/api/common/getECPublicKey",body10, headers10)
response = conn.getresponse()
print(response.status, response.reason)
print('10 10')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)




headers11 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json'
    #'Content-Length': '538',
}

m_request_id ="".join(
    random.choice('0123456789ABCDEF')
    for _ in range(40)
)

text = b''
m_enc_text,m_enc_random = ECC_ENC(text)

m_timestamp = str(int(time.time()*1000000))
# Example usage: sign a message
m_providerCode = ""
m_deviceId = ""
m_deviceType = ""
m_client_session = ''
#message = m_request_id.encode("utf-8")+m_enc_text+m_enc_random+m_timestamp.encode("utf-8")+b'ACBBankn0NjMkIX8fvMudHppnp43qfLR'
message = m_client_session.encode("utf-8")+m_request_id.encode("utf-8")+m_deviceId.encode("utf-8")+m_deviceType.encode("utf-8")+m_enc_text+m_enc_random+m_timestamp.encode("utf-8")+m_providerCode.encode("utf-8")+b'ACBBankn0NjMkIX8fvMudHppnp43qfLR'

m_signature = ECC_SIGN(message)
'''
data = 968159A61837E172079781E73CDBB3F62DBED3E9eHV4TldUWkRKQjVyN2N4NEmIOpVKUAecQupl7Dboi58=BHIgRIBaU3ERMVIvdQhcTxPLoxKPApjfuLROIslmmBdd5ql2tSj2xWbNTYF+yb4hY/8A55nlMD1dC8zeWElcF6z83qQ1/Z4Nvxm8Ys4jdeVroPDMhB1zqgBtDR7MddblqoB06ec3JjTlb5SkZoHTzvpxWfJ1+Uc1Fs+S3XY=1748847430698000ACBBankn0NjMkIX8fvMudHppnp43qfLR
'''


conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers21 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Content-Type': 'application/json',
    #'Content-Length': '50',
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}

data21 = r'''{"authMethod":"OTPA","menu":"81","activated":true}'''
#body21 = urllib.urlencode({'spam': 1, 'eggs': 2})
body21 = json.dumps(json.loads(data21))
conn.request("POST", "/mb/legacy/ss/cs/bankservice/user/safekey/active/submit",body21, headers21)
response = conn.getresponse()
print(response.status, response.reason)
print('21 21')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)




time.sleep(6)

conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers22 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Content-Type': 'application/json',
    #'Content-Length': '25',
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}

data22 = r'''{"password":"'''+g_password.decode("utf-8")+'''"}'''
#body22 = urllib.urlencode({'spam': 1, 'eggs': 2})
body22 = json.dumps(json.loads(data22))
conn.request("POST", "/mb/legacy/ss/cs/bankservice/user/validate/password",data22, headers22)
response = conn.getresponse()
print(response.status, response.reason)
print('22 22')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)



conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers23 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body23 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body23 = json.dumps(json.loads(data23))
conn.request("GET", "/mb/legacy/ss/cs/bankservice/user/auth-method/phones?authMethod=OTPA",'', headers23)
response = conn.getresponse()
print(response.status, response.reason)
print('23 23')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)




conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers24 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Content-Type': 'application/json',
    #'Content-Length': '51',
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}

data24 = r'''{"authMethod":"OTPA","menu":"81","activated":false}'''
#body24 = urllib.urlencode({'spam': 1, 'eggs': 2})
body24 = json.dumps(json.loads(data24))
conn.request("POST", "/mb/legacy/ss/cs/bankservice/user/safekey/active/submit",body24, headers24)
response = conn.getresponse()
print(response.status, response.reason)
print('24 24')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
m_uuid = ''  
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    m_uuid = json_data["data"]["uuid"]    
    print(m_uuid)

if m_uuid == '':
    print('error')
    sys.exit(0)





headers25 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Content-Type': 'application/json',
    #'Content-Length': '101',
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}

while 1:
    m_code = input(">>>>>>>>>>>>>>>>>>input 6 code:")
    if len(m_code) == 6:
        break
data25 = r'''{"uuid":"'''+m_uuid+'''","authMethod":"OTPA","code":"'''+m_code+'''","activated":false}'''
#body25 = urllib.urlencode({'spam': 1, 'eggs': 2})
body25 = json.dumps(json.loads(data25))
conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
conn.request("POST", "/mb/legacy/ss/cs/bankservice/user/safekey/active/verify",body25, headers25)
response = conn.getresponse()
print(response.status, response.reason)
print('25 25')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        #HandleTokenExpire()
        print('token expired')
        sys.exit(0)
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)



conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
headers26 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body26 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body26 = json.dumps(json.loads(data26))
conn.request("GET", "/mb/legacy/ss/cs/bankservice/user/auth-method/phones?authMethod=OTPA",'', headers26)
response = conn.getresponse()
print(response.status, response.reason)
print('26 26')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)




headers29 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json',
    #'Content-Length': '1191',
    'Expect': '100-continue'
}

while 1:
    m_code = input(">>>>>>>>>>>>>>>>>>input 8 active code:")
    if len(m_code) == 8:
        break
        
text = b'{"deviceData":"'+g_deviceData+b'","activationCode":"5200'+m_code.encode("utf-8")+b'","softTokenVersion":"'+g_app_version.encode("utf-8")+b'"}'

m_enc_rsa_text,m_enc_key = RSA_ENC(text)

m_userID = ""
m_token_id = ""

message = g_clinet_secretKey+m_userID.encode("utf-8")+m_token_id.encode("utf-8")+m_clientID.encode("utf-8")+m_enc_rsa_text+m_enc_key


m_signature = RSA_SIGN(message)

data29 = r'''{"userID":"","tokenID":"","clientID":"'''+m_clientID+'''","data":"'''+m_enc_rsa_text.decode('utf-8')+'''","key":"'''+m_enc_key.decode('utf-8')+'''","sign":"'''+m_signature+'''"}'''

#body29 = urllib.urlencode({'spam': 1, 'eggs': 2})
body29 = json.dumps(json.loads(data29))
conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
conn.request("POST", "/keypass.wsmobile.secure/sdk/activate5B",body29, headers29)
response = conn.getresponse()
print(response.status, response.reason)
print('29 29')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
m_tokenSN = '' 
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    m_tokenSN = json_data["tokenSN"]
    print(m_tokenSN)

    m_key = json_data["key"]
    print(m_key)
    
    encrypted = base64.b64decode(m_key)
    m_key = RSA_DEC(encrypted)
    print(m_key)
    m_key = bytes.fromhex(m_key.decode("utf-8"))
    print(m_key)
    
    m_aes_key = g_key_from_seed
    
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    cipher = Cipher(algorithms.AES(m_aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    m_otp_key = decryptor.update(m_key) + decryptor.finalize()
    m_otp_key = m_otp_key[:20]
    print(m_otp_key)
    
    f = open(g_folder+'otp_key.txt', 'w+',encoding='utf-8')
    f.write(m_otp_key.decode("utf-8"))
    f.close()
    
    g_user_info_dict['userID'] = g_eUserId
    g_user_info_dict['tokenID'] = m_tokenID
    g_user_info_dict['clientID'] = m_clientID
    
    f = open(g_folder+'user_info_dict.json', 'w+',encoding='utf-8')
    f.write(json.dumps(g_user_info_dict))
    f.close()
    
    shutil.copy('run9_photo.py', g_folder+'run9_photo.py')
    

if m_tokenSN == '':
    print('error')
    sys.exit(0)



while 1:
    headers32 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Content-Type': 'application/json',
        #'Content-Length': '30',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }
    
    data32 = r'''{"authorizationMethod":"OTPS"}'''
    #body32 = urllib.urlencode({'spam': 1, 'eggs': 2})
    body32 = json.dumps(json.loads(data32))
    
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("DELETE", "/mb/legacy/ss/cs/bankservice/user/safekey/registration",body32, headers32)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('32 32')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break

    

time.sleep(3)

#body33 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body33 = json.dumps(json.loads(data33))
while 1:
    headers33 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/bankservice/user/auth_method?action=&enableAdvSafeKey=true",'', headers33)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('33 33')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break




headers34 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json'
    #'Content-Length': '946',
}

text = b'{"appID":"2","userID":"'+g_eUserId.encode("utf-8")+b'","tokenID":"0000","deviceID":"'+g_deviceId+b'"}'
#text = b'{"appID":"2","userID":"7260399","tokenID":"0000","deviceID":"ce4a052d3c69287b"}'
m_enc_rsa_text,m_enc_key = RSA_ENC(text)

m_userID = g_eUserId
m_token_id = "0000"

message = g_clinet_secretKey+m_userID.encode("utf-8")+m_token_id.encode("utf-8")+m_clientID.encode("utf-8")+m_enc_rsa_text+m_enc_key


m_signature = RSA_SIGN(message)

data34 = r'''{"userID":"'''+m_userID+'''","tokenID":"'''+m_token_id+'''","clientID":"'''+m_clientID+'''","data":"'''+m_enc_rsa_text.decode('utf-8')+'''","key":"'''+m_enc_key.decode('utf-8')+'''","sign":"'''+m_signature+'''"}'''


body34 = json.dumps(json.loads(data34))
conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
conn.request("POST", "/keypass.wsmobile.secure/sdk/checkActiveToken5C",body34, headers34)
response = conn.getresponse()
print(response.status, response.reason)
print('34 34')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
m_tokenID = ''  
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    m_tokenID = json_data["data"]["softTokenInfo"]["tokenID"]
    print(m_tokenID)   


if m_tokenID == '':
    print('error')
    sys.exit(0)


'''
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
X-Test: Filter Test
Content-Length: 231

{"responseCode":0,"message":"Success","data":{"status":3,"softTokenInfo":{"tokenID":"5200010366581","activatedDate":"20250602","activatedTime":"140030","deviceInfo":"google#Pixel 6 Pro#android#13","appID":2,"appVersion":"3.38.1"}}}
'''


while 1:
    headers35 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/internal/setting?key=MAPTRANS_SAFEKEY",'', headers35)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('35 35')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break



headers36 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json'
    #'Content-Length': '979',
}

text = b'{"appID":"2","userID":"'+m_userID.encode("utf-8")+b'","tokenID":"'+m_tokenID.encode("utf-8")+b'","deviceID":"'+g_deviceId+b'"}'
#text = b'{"appID":"2","userID":"7260399","tokenID":"5200010366581","deviceID":"ce4a052d3c69287b"}'
m_enc_rsa_text,m_enc_key = RSA_ENC(text)

m_userID = g_eUserId
m_token_id = m_tokenID

message = g_clinet_secretKey+m_userID.encode("utf-8")+m_token_id.encode("utf-8")+m_clientID.encode("utf-8")+m_enc_rsa_text+m_enc_key

m_signature = RSA_SIGN(message)

data36 = r'''{"userID":"'''+m_userID+'''","tokenID":"'''+m_token_id+'''","clientID":"'''+m_clientID+'''","data":"'''+m_enc_rsa_text.decode('utf-8')+'''","key":"'''+m_enc_key.decode('utf-8')+'''","sign":"'''+m_signature+'''"}'''


body36 = json.dumps(json.loads(data36))
conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
conn.request("POST", "/keypass.wsmobile.secure/sdk/checkActiveToken5C",body36, headers36)
response = conn.getresponse()
print(response.status, response.reason)
print('36 36')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()



'''
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
X-Test: Filter Test
Content-Length: 231

{"responseCode":0,"message":"Success","data":{"status":1,"softTokenInfo":{"tokenID":"5200010366581","activatedDate":"20250602","activatedTime":"140030","deviceInfo":"google#Pixel 6 Pro#android#13","appID":2,"appVersion":"3.38.1"}}}
'''


headers37 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json',
    #'Content-Length': '1319',
    'Expect': '100-continue'
}

text = b'{"os":"android","version":"'+g_app_version.encode("utf-8")+b'","deviceData":"'+g_deviceData+b'","flagUpdate":0,"listUserIDTokenIDs":"[{\\"userID\\":\\"'+m_userID.encode("utf-8")+b'\\",\\"tokenID\\":\\"'+m_tokenID.encode("utf-8")+b'\\"}]"}'

m_enc_rsa_text,m_enc_key = RSA_ENC(text)

m_userID = g_eUserId
m_token_id = m_tokenID

message = g_clinet_secretKey+m_userID.encode("utf-8")+m_token_id.encode("utf-8")+m_clientID.encode("utf-8")+m_enc_rsa_text+m_enc_key


m_signature = RSA_SIGN(message)

data37 = r'''{"userID":"'''+m_userID+'''","tokenID":"'''+m_token_id+'''","clientID":"'''+m_clientID+'''","data":"'''+m_enc_rsa_text.decode('utf-8')+'''","key":"'''+m_enc_key.decode('utf-8')+'''","sign":"'''+m_signature+'''"}'''

#body37 = urllib.urlencode({'spam': 1, 'eggs': 2})
body37 = json.dumps(json.loads(data37))
conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
conn.request("POST", "/keypass.wsmobile.secure/sdk/getServerConfigurations",body37, headers37)
response = conn.getresponse()
print(response.status, response.reason)
print('37 37')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
m_serverTime = ""
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    m_serverTime = json_data["serverTime"]
    print(m_serverTime)



while 1:
    headers38 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Content-Type': 'application/json',
        #'Content-Length': '211',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }
    
    data38 = r'''{"verificationSessionId":"'''+m_verificationSessionId+'''","authMethod":"OTPA","guid":"'''+m_guid+'''","username":"'''+g_username.decode('utf-8')+'''","deviceName":"'''+g_deviceName.decode('utf-8')+'''","osVersion":"'''+g_osVersion.decode('utf-8')+'''"}'''
    #body38 = urllib.urlencode({'spam': 1, 'eggs': 2})
    body38 = json.dumps(json.loads(data38))
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("POST", "/mb/legacy/ss/cs/bio/user/auth/submit",body38, headers38)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('38 38')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else :
        break;
        
m_uuid = ""
m_transactionId = ""
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    m_uuid = json_data["data"]["uuid"]
    m_transactionId = json_data["data"]["transactionId"]
    print(m_uuid)
    print(m_transactionId)

if m_uuid == "" or m_transactionId == "":
    sys.exit(0)


'''
HTTP/1.1 200
Content-Type: application/json
Connection: keep-alive
Date: Mon, 02 Jun 2025 07:00:58 GMT
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Transfer-Encoding: chunked

bb
{"codeStatus":200,"description":"Success","data":{"edtOtp":null,"uuid":"c3018045-ab3f-4172-9fad-2ad9f7d43fe4","transactionId":"FBCC5877-5CF5-4A21-80CC-A9A8C126DD2F","isRequiredOTP":true}}

0


'''


headers39 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json'
    #'Content-Length': '979',
}

text = b'{"userID":"'+m_userID.encode("utf-8")+b'","transactionID":"'+m_transactionId.encode("utf-8")+b'","messageID":""}'
#text = b'{"userID":"7260399","transactionID":"FBCC5877-5CF5-4A21-80CC-A9A8C126DD2F","messageID":""}'
m_enc_rsa_text,m_enc_key = RSA_ENC(text)

m_userID = g_eUserId
m_token_id = m_tokenID

message = g_clinet_secretKey+m_userID.encode("utf-8")+m_token_id.encode("utf-8")+m_clientID.encode("utf-8")+m_enc_rsa_text+m_enc_key

m_signature = RSA_SIGN(message)

data39 = r'''{"userID":"'''+m_userID+'''","tokenID":"'''+m_token_id+'''","clientID":"'''+m_clientID+'''","data":"'''+m_enc_rsa_text.decode('utf-8')+'''","key":"'''+m_enc_key.decode('utf-8')+'''","sign":"'''+m_signature+'''"}'''

body39 = json.dumps(json.loads(data39))
conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
conn.request("POST", "/keypass.wsmobile.secure/sdk/getSignedData5",body39, headers39)
response = conn.getresponse()
print(response.status, response.reason)
print('39 39')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
        
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)
    m_challenge = json_data["challenge"]

#####################################################
otp_auth = m_challenge+"|"+m_transactionId
print(otp_auth)

otp_Q = sha256(otp_auth.encode('utf-8')).hexdigest()
otp_Q = otp_Q.upper()
print(otp_Q)

pin = '2580'

#1747659512 1BC73EA   
#1747975005 1BC8874
#OCRA-1:HOTP-SHA1-6:QA64-T30S
#time_t = int(serverTime)/30
test = {
    'ocrasuite': 'OCRA-1:HOTP-SHA1-6:QA64-T30S',
    'key': m_otp_key,
    'params': {'Q': otp_Q, 'T_precomputed': int(m_serverTime)/30}
}

ocrasuite = str2ocrasuite(test['ocrasuite'])
key = test['key']
params = test['params']
if ocrasuite.data_input.P:
    params['P'] = pin
    print(pin)
opt_code = ocrasuite(key, **params)
print(opt_code)

'''
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
X-Test: Filter Test
Content-Length: 364

{"responseCode":0,"message":"Success","userID":"7260399","transactionID":"FBCC5877-5CF5-4A21-80CC-A9A8C126DD2F","transactionTypeID":233,"transactionData":"Q3NZNXhsaXZIeHlkSVJOeE8EImH0iNWTE1585WQUWZYRrWcvEnPA3GQcW/hNLKK0AkgXzGmKEfi91uJ3NgVmJw==","transactionStatusID":2,"challenge":"92417920","isOnline":0,"eSignerTypeID":1,"channelID":1,"version":0,"authTypeID":2}
'''


time.sleep(9)

headers51 = {
    'Host': 'safekey.acb.com.vn',
    'Accept': '*/*',
    'Content-Type': 'application/json',
    #'Content-Length': '278683',
    'Expect': '100-continue'
}

binfile = open('rep_file3.jpg', 'rb') 
img_data = binfile.read()
binfile.close()
img_data = base64.b64encode(img_data)

m_request_id ="".join(
    random.choice('0123456789ABCDEF')
    for _ in range(40)
)

text = b'{"image":"'+img_data+b'","providerCode":"00017","customerId":"'+m_userID.encode("utf-8")+b'","bankTransactionId":"'+m_transactionId.encode("utf-8")+b'"}'

m_enc_text,m_enc_random = ECC_ENC(text)

m_timestamp = str(int(time.time()*1000000))
m_providerCode = "00017"
m_deviceId = g_deviceId.decode("utf-8")
m_deviceType = "4"

message = m_client_session.encode("utf-8")+m_request_id.encode("utf-8")+m_deviceId.encode("utf-8")+m_deviceType.encode("utf-8")+m_enc_text+m_enc_random+m_timestamp.encode("utf-8")+m_providerCode.encode("utf-8")+b'ACBBankn0NjMkIX8fvMudHppnp43qfLR'

m_signature = ECC_SIGN(message)

data51 = r'''{"requestId":"'''+m_request_id+'''","providerCode":"'''+m_providerCode+'''","deviceId":"'''+m_deviceId+'''","serialNumber":"","time":'''+m_timestamp+''',"deviceType":4,"bankAppId":2,"version":1,"encryptedData":"'''+m_enc_text.decode("utf-8")+'''","encryptedRandomData":"'''+m_enc_random.decode("utf-8")+'''","signature":"'''+m_signature.decode("utf-8")+'''"}'''

'''
k = 0
data51_1 = ''
while k+0x4000 < len(data51):
    data51_1 = data51_1 + data51[k:k+0x4000] + '\n'
    k = k + 0x4000
data51_1 = data51_1 + data51[k:]    
print(data51_1)
'''
#body51 = urllib.urlencode({'spam': 1, 'eggs': 2})
body51 = json.dumps(json.loads(data51))
conn = http.client.HTTPSConnection("safekey.acb.com.vn",context=context)
conn.request("POST", "/bio/sdk/api/biometric/changeDevice",body51, headers51)
response = conn.getresponse()
print(response.status, response.reason)
print('51 51')
if response.status == 401:
    json_data = json.loads(response.read())
    expire = json_data["exp"]
    if expire == 'token expired':
        HandleTokenExpire()
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)




while 1:
    headers57 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Content-Type': 'application/json',
        #'Content-Length': '83',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }

    data57 = r'''{"uuid":"'''+m_uuid+'''","code":"'''+opt_code+'''","authMethod":"OTPA"}'''
    #body57 = urllib.urlencode({'spam': 1, 'eggs': 2})
    body57 = json.dumps(json.loads(data57))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("POST", "/mb/legacy/ss/cs/bio/user/auth/verify",body57, headers57)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('57 57')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        
json_data = json.loads(response.read())
print(json_data)



while 1:
    headers58 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body58 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body58 = json.dumps(json.loads(data58))
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/login/information/id-card-info?checkType=ALL",'', headers58)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('58 58')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break



while 1:
    headers60 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body60 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body60 = json.dumps(json.loads(data60))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/person/bank/class",'', headers60)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('60 60')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break



while 1:
    headers61 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'authorization': 'bearer '+g_authorization,
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'Content-Type': 'application/json',
        #'Content-Length': '406',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }

    data61 = r''''''+g_sync+''''''
    #body61 = urllib.urlencode({'spam': 1, 'eggs': 2})
    body61 = json.dumps(json.loads(data61))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("POST", "/mb/legacy/ss/cs/login/user/sync",body61, headers61)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('61 61')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break



while 1:
    headers62 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        #'Content-Length': '0',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }



    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("PUT", "/mb/legacy/ss/cs/login/tt35/confirm",'', headers62)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('62 62')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        



while 1:
    headers64 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'timeout': '60000',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body64 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body64 = json.dumps(json.loads(data64))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/internal/feature/param?configuration_template=DASHBOARD&format_value=true",'', headers64)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('64 64')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        


'''
HTTP/1.1 200
Content-Type: application/json
Connection: keep-alive
RateLimit-Remaining: 485
RateLimit-Reset: 58
X-RateLimit-Limit-Minute: 500
X-RateLimit-Remaining-Minute: 485
RateLimit-Limit: 500
Date: Mon, 02 Jun 2025 07:03:01 GMT
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Transfer-Encoding: chunked

36
{"codeStatus":200,"description":"Success","data":true}

0


'''

while 1:
    headers65 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body65 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body65 = json.dumps(json.loads(data65))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/configuration/setting/feature-by-group",'', headers65)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('65 65')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break


while 1:
    headers67 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        #'Content-Length': '0',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body67 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body67 = json.dumps(json.loads(data67))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("PUT", "/mb/legacy/ss/cs/login/update-device-language",'', headers67)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('67 67')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        
        
while 1:
    headers68 = {
        'accept': 'application/json, text/plain, */*',
        'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjIwMDYxNzQwMTQsImlhdCI6MTY5MDgxNDAxNCwiaXNzIjoiNjRjN2M2M2VmNTBhNWJmYTBkZTE5YmY4IiwicHVibGljX2lkIjoiNjMyYWQyMzAwODVkYzRhZjFiMGQ0NTBkIiwibmFtZSI6ImNoYXRib3QifQ.Catc4mMpNp7cadBDE4_PSGXJRfjWudkh7yJ8GV9S2jRGVUhq_bNZUxjm4mjR1rytXjb9kOdln8wEh8zeAbuDDHaa7aMk0idFgZeLSNRJ1HX7rzVVDDaTZvGlWW3DiCI6qVXcrJLmtibxEvpicPbqicOxs4Wu7PZ5NsVG43FLM9teeaBu1_KeFTEgyhSX3qGaosAp2WUcVhtGV2zRMmiFH__kfgs0u2YOp2D5vVjjZRfUWqMUWGXgRVfdQW8TIylTOqvMK8H1eyHHdYGhmuV-beDhyNoR_CN8BxWFN4Qi3fdf8NHD7aWPJLPILB3nHo6BIz2j_9K4wJQpIY4097dPnw',
        'Host': 'aichatbot.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2',
        'If-Modified-Since': 'Mon, 02 Jun 2025 06:43:52 GMT'
    }


    #body68 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body68 = json.dumps(json.loads(data68))

    conn = http.client.HTTPSConnection("aichatbot.acb.com.vn")
    conn.request("GET", "/api/v1/chatbot_gateway/agents/632ad230085dc4af1b0d450d/channel/64c7c63e405b4ec5dad03e68/setting",'', headers68)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('68 68')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break


'''
HTTP/1.1 200 OK
Date: Mon, 02 Jun 2025 07:03:02 GMT
Content-Type: text/plain; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
ts: 1748847782072184576
x-envoy-upstream-service-time: 24
content-encoding: gzip
vary: Accept-Encoding
CF-Cache-Status: DYNAMIC
Server: cloudflare
CF-RAY: 949516ad6ebb7abb-SJC

5a
      J4*q2rô
Ë±HrËð4J±ÊóvÌ)
ôJ32
ÏÈI	M15vL3ª0
ò«ÈÈ+÷   ÿÿ éÃo@   

0


'''


while 1:
    headers70 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-channel': 'MAPP',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body70 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body70 = json.dumps(json.loads(data70))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/agreement/customer/biz-confirm/awaiting-confirmation",'', headers70)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('70 70')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break


'''
HTTP/1.1 200 OK
Date: Mon, 02 Jun 2025 07:03:04 GMT
Content-Length: 0
Connection: keep-alive
vary: Origin
x-envoy-upstream-service-time: 0
cf-cache-status: DYNAMIC
Server: cloudflare
CF-RAY: 949516ba0eae7abb-SJC


'''



'''
HTTP/1.1 200
Content-Type: application/json
Connection: keep-alive
X-RateLimit-Remaining-Minute: 389
X-RateLimit-Limit-Minute: 400
RateLimit-Remaining: 389
RateLimit-Limit: 400
RateLimit-Reset: 56
Date: Mon, 02 Jun 2025 07:03:03 GMT
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Transfer-Encoding: chunked

36
{"codeStatus":200,"description":"Success","data":null}

'''

while 1:
    headers71 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'timeout': '60000',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body71 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body71 = json.dumps(json.loads(data71))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/internal/feature/param?configuration_template=DASHBOARD&format_value=true",'', headers71)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('71 71')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        



while 1:
    headers73 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body73 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body73 = json.dumps(json.loads(data73))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mba/authorization/auth/services/screen/permission",'', headers73)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('73 73')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        
        
while 1:
    headers74 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Content-Type': 'application/json',
        #'Content-Length': '346',
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }

    #data74 = r'''{"deviceId":"ce4a052d3c69287b","deviceLanguage":"en","deviceModel":"Google_Pixel 6 Pro (raven)","deviceToken":"fvIXCYYET2CoXZQZrg___X:APA91bEuVTzync5S8gMd8p9bdIZ_7p1vHJ6MxO51DKnI1tw-NXje8ZQxokd9pxKISP98PUKetHnoJqYEVx4lZVYZtYLPXl3CiKZ8fD6P0RmNaJp9zpRhj7w","deviceName":"Pixel 6 Pro","deviceOsType":"ANDROID","osVersion":"13","userName":"15446221"}'''
    data74= r''''''+g_update_device_token+''''''
    #body74 = urllib.urlencode({'spam': 1, 'eggs': 2})
    body74 = json.dumps(json.loads(data74))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("POST", "/mb/legacy/ss/cs/login/update-device-token",body74, headers74)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('74 74')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break



while 1:
    headers75 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body75 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body75 = json.dumps(json.loads(data75))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/internal/setting?key=MBA_FEATURE_CONFIG",'', headers75)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('75 75')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break


while 1:
    headers76 = {
        'accept': 'application/json, text/plain, */*',
        'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
        'x-app-version': g_app_version,
        'cache-control': 'no-cache',
        'x-conversation-id': x_conversation_id,
        'x-device-id': g_deviceId.decode('utf-8'),
        'x-request-id': x_request_id(),
        'accept-language': 'en',
        'authorization': 'bearer '+g_authorization,
        'Host': 'apiapp.acb.com.vn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.9.2'
    }


    #body76 = urllib.urlencode({'spam': 1, 'eggs': 2})
    #body76 = json.dumps(json.loads(data76))

    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/configuration/setting/feature-by-group",'', headers76)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('76 76')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break




headers77 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body77 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body77 = json.dumps(json.loads(data77))
while 1:
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/loyalty-integration/rewards/balance",'', headers77)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('77 77')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break




headers80 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body80 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body80 = json.dumps(json.loads(data80))
while 1:
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/login/push-setting",'', headers80)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('80 80')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break

time.sleep(2)

headers82 = {
    'accept': 'application/json, text/plain, */*',
    'apikey': 'CQk6S5usauGmMgMYLGqCuDtgtqIM8FI1',
    'x-app-version': g_app_version,
    'cache-control': 'no-cache',
    'x-conversation-id': x_conversation_id,
    'x-device-id': g_deviceId.decode('utf-8'),
    'x-request-id': x_request_id(),
    'accept-language': 'en',
    'authorization': 'bearer '+g_authorization,
    'Host': 'apiapp.acb.com.vn',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
}


#body82 = urllib.urlencode({'spam': 1, 'eggs': 2})
#body82 = json.dumps(json.loads(data82))
while 1:
    conn = http.client.HTTPSConnection("apiapp.acb.com.vn")
    conn.request("GET", "/mb/legacy/ss/cs/bankservice/dashboard",'', headers82)
    response = conn.getresponse()
    print(response.status, response.reason)
    print('82 82')
    if response.status == 401:
        json_data = json.loads(response.read())
        expire = json_data["exp"]
        if expire == 'token expired':
            HandleTokenExpire()
    else:
        break
        
if response.status == 200:
    json_data = json.loads(response.read())
    print(json_data)

