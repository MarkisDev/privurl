import os
import random
import string
import validators
import datetime
import json
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
from django.shortcuts import render, redirect, reverse
from django.conf import settings
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

def home(request):
    # Getting some important admin data including stats
    admin = db['admin'].find({}, {'_id':0})
    for data in admin:
        if data['name'] == 'count':
            count = data['key']
        elif data['name'] == 'reset_timestamp':
            reset = data['key']

    # Handling POST request
    if request.method == 'POST':
        # Making sure a link has been entered
        if not request.POST.get('link'):
            return render(request, 'home/home.html', {'error': True, 'msg': 'Please enter a link!', 'count':count})
        else:
            # Making sure the link is valid
            if not validators.url(request.POST.get('link')):
                return render(request, 'home/home.html', {'error': True, 'msg': 'Please enter a valid link!', 'count':count})
            else:
                # Making sure user doesn't want his own custom
                if not request.POST.get('custom'):
                    # Generating a unique identifier for the link
                    unique = gen_unique()

                # User wants his own custom
                else:
                    # Using user's custom name
                    unique = request.POST.get('custom')
                    # Validating the custom
                    invalid = set(string.punctuation.replace("_", " ").replace('-',''))
                    if (any(char in invalid for char in unique)):
                        # Invalid characters exist
                        return render(request, 'home/home.html', {'error': True, 'msg': 'No invalid characters in custom!', 'count':count})
                    # Checking if the custom exists
                    elif(check_unique(unique)):
                        return render(request, 'home/home.html', {'error': True, 'msg': 'That custom is taken!', 'count':count})

                # User did not set a password
                if not request.POST.get('password'):
                    # Making a random password to encrypt link
                    password = gen_password()
                else:
                    # Using users password
                    password = request.POST.get('password')

                # Checking if the link is set to never expire
                if request.POST.get('expire'):
                    if str(unquote(unquote(request.POST.get('expire')))).lower() == 'true':
                        expire = True
                    else:
                        expire = False
                else:
                    expire = True

        # Encrypting the link
        encrypted_link = encrypt(request.POST.get('link'), password)

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
        # Storing expiry date
        encrypted_link['expire'] = expire
        # Storing the entry in database
        db['data'].insert_one(encrypted_link)
        # Incrementing the value in db
        query = {'$inc':{'key':1}}
        db['admin'].update({'name':'count'}, query)
        return render(request, 'home/success.html', {'error': False, 'msg': 'Your link has been shortened!', 'url':url, 'count':count+1})

    # Handling any other request
    else:
        return render(request, 'home/home.html', {'count':count})

# Function to redirect the user
def redirect(request, unique=None):
    # Making sure a unique exists
    if unique and unique != 'favicon.ico' and unique !='/favicon.ico/':
        # Decoding the URL encoded string
        unique = unquote(unquote(unique))
        # Checking if unique has no password
        if unique.find(';') < 0:
            custom = unique
        # Fetching password and unique from the url
        else:
            custom = unique[:unique.find(';')]
            password = unique[unique.find(';')+1:]
        # Finding the entry with the unique
        link = db['data'].find_one({'unique':custom}, {'_id':0, 'timestamp':0})

        # Authenticating the unique
        if link is None:
            return HttpResponseRedirect(reverse('home'))
        # Checking if the unique is a custom with no password
        if 'clearpass' in link and unique.find(';') < 0:
            password = link['clearpass']     

        # Decrypting the link and redirecting if fake password
        try:
            link = bytes.decode(decrypt(link, password))
            return HttpResponseRedirect(link)
        except:
            return HttpResponseRedirect(reverse('home'))
    else:
        # Link doesn't exist
        return HttpResponseNotFound('The link is invalid')
            

# Function to show the about page
def about(request):
    # Getting some important admin data including stats
    admin = db['admin'].find({}, {'_id':0})
    for data in admin:
        if data['name'] == 'count':
            count = data['key']
        elif data['name'] == 'reset_timestamp':
            reset = data['key']

    return render(request, 'home/about.html', {'count':count})

# Function to show the tos page
def tos(request):
    # Getting some important admin data including stats
    admin = db['admin'].find({}, {'_id':0})
    for data in admin:
        if data['name'] == 'count':
            count = data['key']
        elif data['name'] == 'reset_timestamp':
            reset = data['key']

    return render(request, 'home/tos.html', {'count':count})

def msg(request):
    return render(request, 'home/privmsg.html')