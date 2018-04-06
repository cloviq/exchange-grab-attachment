# Written By: Carlo Viqueira
# Purpose: Connect to Exchange Mailbox to download attachment
# Tested in Python 2.7

from exchangelib import Account, Credentials, Configuration, FileAttachment, UTC_NOW
from Cryptodome.Cipher import AES
from Cryptodome import Random
from datetime import timedelta
import csv
from logging import handlers
import logging
import hashlib
import base64
import os

conf_input = './input/parse_mailbox.conf'
log_file = './parse_mailbox-logs/parse_mailbox-log.txt'
smtp_address = 'yourname@domain.com'
message_folder = 'TestingFolder'  # This is the name of the folder to search for the message
exchange_endpoint = 'https://outlook.office365.com/EWS/Exchange.asmx'
subject_search = 'Check out'  # This is the string to search for in the subject of the message


class AESCipher(object):
    # This class handles the encryption and decryption of the credentials

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def log_to_file():
    # This is what makes the logs for this script
    if not os.path.exists('./parse_mailbox-logs'):
        os.mkdir('./parse_mailbox-logs')
    logger = logging.getLogger(__name__)
    hdlr = handlers.RotatingFileHandler(log_file, maxBytes=100000, backupCount=10, encoding='UTF-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    return logger


def connect_exchange():
    # Connects to Exchange through Exchange Web Services (EWS)
    # using the smtp_address var declared at the top and credentials provided at first runtime
    global smtp_address
    global exchange_endpoint

    uname = cred_set[0]['username']
    pwd = decrypter.decrypt(cred_set[0]['ePassword']).encode('utf-8')
    credentials = Credentials(username=uname, password=pwd)
    config = Configuration(service_endpoint=exchange_endpoint, credentials=credentials)
    account = Account(primary_smtp_address=smtp_address, config=config, credentials=credentials)
    return account


def save_attachments(in_folder):
    # Saves attachments from messages in the global message_folder var
    # in_folder var is the start point to search for message_folder
    global message_folder
    global subject_search

    tn = UTC_NOW()
    earliest = tn - timedelta(days=30)
    for dirname, dirnames, filenames in os.walk('./tmp'):
        for filename in filenames:
            os.remove(os.path.join(dirname, filename))
    search_folder = [f for f in in_folder.walk() if f.name == message_folder][0]
    filtered_folder = search_folder.filter(subject__contains=subject_search)
    if not os.path.exists('./tmp'):
        os.mkdir('./tmp')
    for item in filtered_folder:
        if item.datetime_received >= earliest:
            for attachment in item.attachments:
                if isinstance(attachment, FileAttachment):
                    local_path = os.path.join('./tmp', attachment.name)
                    with open(local_path, 'wb') as f:
                        f.write(attachment.content)
                    print('Saved attachment to', local_path)
        item.is_read = True
        item.save()


def store_creds(filename=conf_input):
    # Stores the credentials provided at first run time
    num_creds = int(input('How many credential sets do you want to enter?: '))
    creds_list = [None] * num_creds
    for x in range(num_creds):
        username = raw_input('Enter the username: ')
        password = raw_input('Enter the password: ')
        ePassword = encrypter.encrypt(password)
        # ePassword = encrypt_password(password).decode('utf-8')
        creds_list[x] = {'username': username, 'ePassword': ePassword}
    with open(filename, 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, creds_list[0].keys())
        writer.writeheader()
        for cred in creds_list:
            writer.writerow(cred)
    csvfile.close()


def get_creds():
    # Pulls credentials from the global conf_input file
    global conf_input

    dicts_from_file = []
    with open(conf_input, 'rb') as inf:
        reader = csv.DictReader(inf)
        for row in reader:
            dicts_from_file.append(row)
    return dicts_from_file

logger = log_to_file()

try:
    if not os.path.exists(conf_input):
        if not os.path.exists('./input'):
            os.makedirs('./input')
        config = open(conf_input, 'w+')
        config.close
        SECRET_KEY = raw_input('Enter a passphrase to store the credentials: ')
        encrypter = AESCipher(key=SECRET_KEY)
        store_creds()
        logger.info('Credentials stored with new Secret key.')
    else:
        SECRET_KEY = raw_input('Enter the passphrase: ')
        decrypter = AESCipher(key=SECRET_KEY)
        cred_set = get_creds()
        account = connect_exchange()
        inbox = account.inbox
        save_attachments(inbox)
        logger.info('Credentials Used.')
except Exception as err:
    logger.error(err)
