import os
import string 
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import exc
from cryptography.fernet import Fernet
from random import randint, choice
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous.exc import SignatureExpired
import getpass
import base64
import click
import hashlib
from functools import wraps

version = "1.0.0"
pwm_config_dir = "~/.pwm"
user_name = getpass.getuser()
quote_start_line = 0 
quote_end_line = 102

# DB config and classes
def get_db_file():
    return os.path.expanduser(pwm_config_dir) + "/pwm.db"


Base = declarative_base()
query_string = "sqlite:///" + get_db_file()
engine = create_engine(query_string)
Session = sessionmaker(bind = engine)


class Auth(Base):
    __tablename__ = "auth"
    id = Column("id", Integer, primary_key = True)
    name = Column("name", String(50), unique = True)
    value = Column("value", String(200))

    def __init__(self, name, value):
        self.name = name
        self.value = value 


class Passwords(Base):
    __tablename__ = "passwords"
    id = Column("id", Integer, primary_key = True)
    alias = Column("alias", String(50), unique = True)
    key = Column("key", String(50))
    password = Column("password", String(120), nullable = False)

    def __init__(self, password, alias="", key="" ):
        self.alias = alias
        self.key = key 
        self.password = password


def initialize_db():
    try:
        db_file_name = get_db_file()
        db_file = open(db_file_name, "w+")
        db_file.close()
        Base.metadata.create_all(bind=engine)
        return True
    except:
        return False


def auth_sanity_check():
    req_fields = ["username", "passcode", "password", "secret", "refresh_token_sec"]
    missing_fields = []
    for field in req_fields:
        val = get_from_auth(field)
        if len(val) == 0:
            missing_fields.append(field)
    return missing_fields


def hash_passwd(passwd):
    salt = bcrypt.gensalt(rounds=8)
    hashed = bcrypt.hashpw(passwd.encode(), salt)
    return hashed


def is_configured():
    dir_name = os.path.expanduser(pwm_config_dir)
    resp = {"missing_fields": ["username", "passcode", "password", "secret", "refresh_token_sec"]}
    if  os.path.isdir(dir_name) and os.path.isfile(dir_name + "/pwm.db"):
        resp["configured"] = True
        missing_fields = auth_sanity_check()
        resp["missing_fields"] = missing_fields
    else:
        resp["configured"] = False
    return resp


def get_symm_key():
    username = get_from_auth("username")[0].value
    key = hashlib.sha512(username.encode())
    req_key = key.hexdigest()[:32]
    base_key = base64.urlsafe_b64encode(req_key.encode())
    return base_key
    

def push_to_auth(attr, value):
    db_file = get_db_file()
    try:
        session = Session()
        record = session.query(Auth).filter_by(name = attr).all()
        if len(record) == 0:
            record = Auth(name = attr, value = value)
            session.add(record)
        else:
            record[0].value = value
        session.flush()
        session.commit()  
        session.close()
    except:
        return False
    return True


def update_password(attr, value, alias):
    db_file = get_db_file()
    session = Session()
    record_by_alias = session.query(Passwords).filter_by(alias = alias).all()
    try:
        record_by_alias[0].key = attr
        record_by_alias[0].password = value
        session.flush()
        session.commit()
        session.close()
        return (True, "Successfully updated the password")
    except: 
        return (False, "Error while updating password ")
    


def push_to_password(attr, value, alias):
    db_file = get_db_file()

    try:
        session = Session()
        record = Passwords(alias = alias, key = attr, password = value)
        session.add(record)
        session.commit()
        session.close()
    except exc.IntegrityError:
        return (False, "The alias already exists...")
    return (True, "The password is put successfully...")


def get_from_auth(value):
    session = Session()
    record = session.query(Auth).filter_by(name = value).all()
    session.close()
    return record


def get_pass_from_auth(value):
    session = Session()
    record = session.query(Auth).filter_by(name = value).first()
    session.close()
    return record


def get_from_pass(value):
    session = Session()
    record = session.query(Passwords).filter_by(alias = value).all()
    session.close()
    return record
    

def get_all_passwords():
    session = Session()
    records = session.query(Passwords).filter_by().all()
    session.close()
    return records


def get_random_secret(length = 17):
    lwr = string.ascii_lowercase
    upr = string.ascii_uppercase
    dgt = string.digits
    smb = string.punctuation
    all = lwr + upr + dgt + smb 
    password = ""
    password = password + choice(lwr) + choice(upr) + choice(dgt) + choice(smb)    
    for i in range(length-4):
        password += choice(all)
    return password


def encrypt_symm_secret(msg):
    final_secret = get_symm_key()
    fernet = Fernet(final_secret)
    enc_secret = fernet.encrypt(msg.encode())
    return enc_secret


def decrypt_symm_secret(msg):
    final_secret = get_symm_key()
    fernet = Fernet(final_secret)
    dec_secret = fernet.decrypt(msg)
    return dec_secret


def get_random_quote():
    rand_int = randint(quote_start_line,quote_end_line)
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    quotes_file = open(os.path.join(__location__, 'quotes.txt'))
    quotes = quotes_file.readlines()
    quote = quotes[rand_int]
    return quote 


def get_refresh_token(expires_sec):
    s = Serializer(user_name, expires_sec)
    return s.dumps({'username': user_name}).decode('utf-8')


def is_authenticated():
    records = get_from_auth("refresh_token")
    if len(records)>0:
        token = records[0].value
    else:
        return False
    s = Serializer(user_name)
    try:
        username = s.loads(token)['username']
    except:
        return False
    return True
    

def authenticate(password):
    password_in_db = get_pass_from_auth("password").value
    check_passwd = bcrypt.checkpw(password.encode(), password_in_db)

    if not check_passwd:
        return False
    
    refresh_token_sec = int(get_from_auth("refresh_token_sec")[0].value)
    refresh_token = get_refresh_token(refresh_token_sec)
    x = push_to_auth("refresh_token", refresh_token)
    return True


def configure_dec(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        resp = is_configured()
        if not resp["configured"] or len(resp["missing_fields"])>0:
            click.echo(click.style("PWM is not configured, you can try running below cmd to configure it", fg='red'))
            click.echo(click.style('\n\t # pwm configure\n', fg='green'))
            exit()
        function(*args, **kwargs)
    return wrapper


def authenticate_dec(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        authenticated = is_authenticated()
        if authenticated:
            function(*args, **kwargs)
        else:
            click.echo(click.style("You are not authenticated...", fg = "red"))
            count = 0 
            while count<3:
                password = getpass.getpass(prompt="Please enter Password: ")
                corrct = authenticate(password)
                if not corrct:
                    click.echo(click.style("Incorrect password", fg = "red"))
                    count +=1
                    continue
                break
            if count <3:
                function(*args, **kwargs)
            else:
                click.echo(click.style("Exiting...", fg = "red"))
    return wrapper


def get_passwords(alias):
    if alias == "":
        records = get_all_passwords()
    else:
        records = get_from_pass(alias)
    return records
    