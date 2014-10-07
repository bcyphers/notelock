#!/usr/bin/env python

ABOUT = '''
Notelock: A simple terminal note encryption service.

Use: `notelock [OPTION]... [NOTEBOOK] [message]`

Notelock stores notes in "notebooks." Each notebook has entries stored in
chronological order. To add an entry to a type `notelock [book name] [message]`,
and it will be appended to the notebook with the notebook's password, without
the need for password re-entry. If [book name] does not exist, then the
user will be prompted to create it [y/n] and asked for an encryption password
(twice). `notelock -f [book name] [filename]` will accept the contents of a
file. It will not check for the type of data in the file, so be careful.

To read from a book, put `notelock -r [book name]`. This will prompt the user
for the book's password, and print entries from the book for the last day. The
`-F` option will start looking from the [F]ront of the file, so the first entry
will be printed last (and be visible first). The `-a` option prints all entries.

There is no way to delete entries, and currently no way to edit them.

Features to add:
    - Editing: It seems reasonable to edit entries, at least by appending. This
      will mean some way to access individual notes.
        * Maybe the -r command will let the user scroll through notes using
        * up/down, and whichever note s/he is currently on can be edited by
        * hitting Enter?

    - Tags: Each note can be stored with a #tag, and books can be searched by
      tag.

    - Range search: Notes can be filtered by range, with `notelock --range
      [start date] [end date]`. Or maybe `notelock --start [start date] --end
      [end date]`, to allow open-ended ranges.

    - Summary: `notelock -l [book name]` will list all the days for which there
      are entries, along with the number of entries for each day.

Implementation:
    - Each day stored in a file, YYYY-MM-DD
    - Each entry encrypted seperately, preceeded by auth signiture
    - Each notebook stored in a directory
    - Text stored as unicode
'''

import sys, os, base64
from datetime import datetime
from getpass import getpass
from os import listdir
from os.path import isdir, join
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256 as SHA
from Crypto import Random

class bcolors:
    SKYBLUE = '\033[96m'
    MAGENTA = '\033[95m'
    DARKBLUE = '\033[94m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    GRAY = '\033[90m'
    ENDC = '\033[0m'

LOCKER_PATH = 'lockers/'
PUBLIC = 'public.der'
PRIVATE = 'private.pem'
RSA_BITS = 2048
AES_BITS = 128
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s : s[0:-ord(s[-1])]
rand = Random.new()


# Shortcut to get a reproducible, secure hash of an input
def shash(inp, chars=16):
    h = SHA.new()
    h.update(inp)
    return h.hexdigest()[:chars]

# Given a list, remove duplicates without destroying the order.
def uniquify(seq):
    seen = set()
    seen_add = seen.add
    return [ x for x in seq if x not in seen and not seen_add(x)]


def make_new_book(book, path):
    # get the book's password
    pwd = getpass('Enter a password for notebook "' + book + '": ')
    pwd_conf = getpass('Confirm password: ')
    if pwd != pwd_conf:
        make_new_book(book, path)

    # make new directory for the book
    os.mkdir(path)

    # generate a new RSA key
    rsakey = RSA.generate(RSA_BITS)

    # serialize key, save to files
    with open(join(path, PRIVATE), 'w+') as pvtfile:
        # Private key is encrypted with the user-defined password
        pvtfile.write(rsakey.exportKey(passphrase=pwd))
    with open(join(path, PUBLIC), 'w+') as pubfile:
        # Public key is in plaintext
        pubfile.write(rsakey.publickey().exportKey())


def write(book, message, options):
    # the book name is hashed to create the file names
    bookname = shash(book)
    bookpath = join(LOCKER_PATH, bookname)

    # create the locker dir if it doesn't exist
    if not os.path.isdir(LOCKER_PATH):
        os.makedirs(LOCKER_PATH)

    notebooks = [d for d in listdir(LOCKER_PATH) if isdir(join(LOCKER_PATH, d))]

    # if the notebook does not exist, create it.
    if bookname not in notebooks:
        make_new_book(book, bookpath)

    # rebuild the message
    message = ' '.join(message)

    # get public key
    public_key = RSA.importKey(open(join(bookpath, PUBLIC), 'r').read())

    now = datetime.now()
    today = now.strftime('%Y-%m-%d')
    timestamp = now.strftime('%H:%M')
    message = timestamp + '\n' + message

    # encrypt the message:
    # first, generate a new AES key and encrypt the plaintext with CBC
    aes_key = rand.read(AES_BITS / 8)
    aes_iv = rand.read(AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted_msg = base64.b64encode(aes_iv + aes_cipher.encrypt(pad(message)))

    # now, encrypt the AES key with the public RSA key
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = base64.b64encode(rsa_cipher.encrypt(aes_key))

    # create new notebook file or append to current file.
    filename = shash(bookname + today)
    with open(join(bookpath, filename), 'a+') as notebook:
        # write the encrypted AES key
        notebook.write(encrypted_key + ' - ')
        # write the message
        notebook.write(encrypted_msg + '\n')

    # append date to the ledger - this is encrypted with RSA
    datecipher = base64.b64encode(rsa_cipher.encrypt(today))
    with open(join(bookpath, 'ledger'), 'a+') as ledger:
        ledger.write(datecipher + '\n')


def read(book, options):
    bookname = shash(book)
    bookpath = join(LOCKER_PATH, bookname)

    # get password first
    pwd = getpass('Enter password for notebook "' + book + '": ')

    # load private RSA key, create decryptor
    private_key = RSA.importKey(open(join(bookpath, PRIVATE), 'r').read(),
                        passphrase=pwd)
    rsa_cipher = PKCS1_OAEP.new(private_key)

    # load the list of dates which have entries
    ledger_file = open(join(bookpath, 'ledger'), 'r')
    dates = []
    for line in ledger_file:
        date = base64.b64decode(line[:-1])
        dates.append(rsa_cipher.decrypt(date))

    dates = uniquify(dates)

    # The '-F' option prints from the [F]ront of the file
    if 'F' in options:
        dates = reversed(dates)

    # The '-a' option prints all notes. The default behavior prints all notes
    # from the last day. More options to be added later.
    if 'a' not in options:
        dates = dates[-1:]

    messages = []
    while dates:
        # load the note page from the last day
        date = dates.pop(0)
        filename = shash(bookname + date)
        note_file = open(join(bookpath, filename), 'r')
        messages.append((date, None))

        # decompose file into messages
        for line in note_file:
            k64, m64 = line.split(' - ')
            # decrypt aes key
            aes_key = rsa_cipher.decrypt(base64.b64decode(k64))
            # decode message ciphertext
            enc = base64.b64decode(m64)
            iv = enc[:BLOCK_SIZE]
            ciphertext = enc[BLOCK_SIZE:]
            # create AES decryptor
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            # decrypt
            msg = unpad(aes_cipher.decrypt(ciphertext))
            # pull off timestamp
            time = msg.split('\n')[0]
            msg = '\n'.join(msg.split('\n')[1:])
            messages.append((time, msg))

    for time, msg in messages:
        if len(time) > 9:
            print bcolors.SKYBLUE + time + bcolors.ENDC
        else:
            if 'v' in options:
                print bcolors.GRAY + time + ':' + bcolors.ENDC,
            print msg


def set_remote(uid):
    r = requests.get('https://localhost:8000/login' + uid)
    # if the user already exists, try to log in
    if r.status_code == 200:
        login(uid)

    elif r.status_code == 100:
        create_user(uid)


'''
The user features do not work yet -- I planned to build a web server backend
which will allow remote storage of notes by username. WIP
'''
def login(uid):
    pwd = getpass('Enter the password for username "' + uid + '": ')
    # hashit & send it out
    packet = shash(uid + pwd)


def create_user(uid):
    pw1 = getpass('Creating user "' + uid + '". Enter a new password: ')
    pw2 = getpass('Confirm password: ')
    if pw1 != pw2:
        print 'Passwords do not match. Try again.'
        create_user(uid)

    r = requests.post('https://localhost:8000/create' + uid)


def verify_login(*args):
    uid = args[0]
    signature = args[1]
    pub_key = open(join(uid, PUBLIC), 'r').read()

# END OF THINGS THAT DO NOT WORK #

def parse_prefs():
    actions = {
            'current_user': verify_login
            }
    with open(prefs_path) as prefs:
        for line in prefs:
            cmd, args = line.split()[0], line.split()[1:]
            fn = actions[cmd]

def run(args):
    # if no args, print readme
    if not args:
        print ABOUT

    # first, load prefs from the default file
    # parse_prefs()

    # parse out the options passed in, like '-o' or '--option'
    options = []
    while args[0][0] == '-':
        optstr = args.pop(0)[1:]
        if optstr[0] == '-':
            options.append(optstr[1:])
            continue

        for s in optstr:
            options.append(s)

    # next string is the notebook name
    notebook = args.pop(0)

    ''' Again, setid is not actually functional
    if 'setid' in options: # or not user:
        set_remote(notebook)
    '''
    if 'r' in options: # handle reads
        read(notebook, options)
    else: # otherwise, write, with args.
        write(notebook, args, options)

if __name__ == '__main__':
    args = sys.argv[1:]
    run(args)
