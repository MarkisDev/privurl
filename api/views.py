import os
import random
import string
import validators
import datetime
import json
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound, JsonResponse
from django.shortcuts import render, redirect, reverse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import pymongo
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from urllib.parse import unquote

# Initializing database client 
db_client = pymongo.MongoClient(settings.MONGODB_AUTH['connection'])
# Selecting database
db = db_client[settings.MONGODB_AUTH['db_name']]

# Function to check if unique exists
def check_unique(unique):
    # List of resereved words
    reserved = ['api', 'tos', 'join', 'about', 'discord', 'markis', 'github']
    db_unique = db['data'].find_one({'unique':unique})
    if db_unique or unique in reserved:
        return True
    else:
        return False

# Function to recursively generate a unique
def gen_unique():
    # Generating a unique
    unique = gen_password()
    # Checking if unique exists, if it does, generate new one until it is unique
    if check_unique(unique):
        gen_unique()
    else:
        return unique

# Function to generate a random password for encryption
def gen_password(length=random.randint(5,7)):
    # List of strings that can be used for a password
    text = f"{string.ascii_letters}{string.digits}"
    text = list(text)
    # Shuffling the text
    random.shuffle(text)
    # Returning a randomly chosen password
    return ''.join(random.choices(text, k=length))

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


# Home function for the API
def home(request):
    # Getting some important admin data including stats
    admin = db['admin'].find({}, {'_id':0})
    for data in admin:
        if data['name'] == 'count':
            count = data['key']
        elif data['name'] == 'reset_timestamp':
            reset = data['key']

    return render(request, 'api/home.html', {'count':count})

@csrf_exempt
def api(request):
   # Getting some important admin data including stats
    admin = db['admin'].find({}, {'_id':0})
    for data in admin:
        if data['name'] == 'count':
            count = data['key']
        elif data['name'] == 'reset_timestamp':
            reset = data['key']

    # Handling POST request
    if request.method == 'POST':
        # Making sure there is an API key
        if request.POST.get('key'):
            # Decoding the key to check the database
            key = bytes.decode(b64decode(unquote(unquote(request.POST.get('key')))))
            # Checking the database
            key_exists = db['api'].find_one({'key':key})
            # The key exists
            if key_exists:
                # Making sure if theres a link
                if request.POST.get('link'):
                    link = unquote(unquote(request.POST.get('link')))
                    # Checking if there's a unique
                    if request.POST.get('custom'):
                        unique = unquote(unquote(request.POST.get('custom')))
                    # No unique
                    else:
                        unique = gen_unique()

                    # Validating the custom
                    invalid = set(string.punctuation.replace("_", " ").replace('-',''))
                    if (any(char in invalid for char in unique)):
                        # Invalid characters exist
                        response = {'status': 500, 'error':'Invalid characters in custom!'}
                        return JsonResponse(response)
                    # Checking if the custom exists
                    elif(check_unique(unique)):
                        response = {'status': 500, 'error':'Custom already exists'}
                        return JsonResponse(response)

                    # User did not set a password
                    if not request.POST.get('password'):
                        # Making a random password to encrypt link
                        password = gen_password()
                    else:
                        # Using users password
                        password = unquote(unquote(request.POST.get('password')))
                
                    # Checking if the link is set to never expire
                    if request.POST.get('expire'):
                        if str(unquote(unquote(request.POST.get('expire')))).lower() == 'true':
                            expire = True
                        else:
                            expire = False
                    else:
                        expire = True

                    # Encrypting the link
                    encrypted_link = encrypt(link, password)

                    # Adding unique to dict
                    encrypted_link['unique'] = unique

                    # Storing password if it's a custom with no system-gen password and also the final url
                    if request.POST.get('custom'):
                        # Custom without password
                        if not request.POST.get('password'):
                            encrypted_link['clearpass'] = password
                            url = unique
                        # Custom with password
                        else:
                            url = f'{unique};{password}'
                    else:
                        url = f'{unique};{password}'
                    # Storing timestamp for the url
                    encrypted_link['timestamp'] = datetime.datetime.utcnow()
                    
                    # Storing the API key of the request
                    encrypted_link['key'] = key
                    
                    #Storing expiry date
                    encrypted_link['expire'] = expire

                    # Storing the entry in database
                    db['data'].insert_one(encrypted_link)
                    # Incrementing the value in db
                    query = {'$inc':{'key':1}}
                    db['admin'].update({'name':'count'}, query)

                    # Returning the response
                    response = {'status': 200, 'link':url}
                    return JsonResponse(response)

                # No link to shorten
                else:
                    response = {'status': 500, 'error':'No link to shorten!'}
                    return JsonResponse(response)
            # Invalid Key
            else:
                response = {'status': 403, 'error':'Invalid API key'}
                return JsonResponse(response)
            
        # No API key
        else:
            response = {'status': 403, 'error':'No API key'}
            return JsonResponse(response)

    # Handling all other requests
    else:
        response = {'status': 500, 'error':'Only POST request is accepted to this endpoint.'}
        return JsonResponse(response)