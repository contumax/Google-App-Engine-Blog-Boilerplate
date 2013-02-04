import re
import hashlib
import hmac
import random
from string import letters


#
# Cookies hashing
#

SECRET = 'fart'


def make_cookie_hash(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_cookie_hash(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_cookie_hash(val):
        return val


#
# Passwords hashing
#

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def check_pw_hash(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


#
# Input Validity checking
#

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)
