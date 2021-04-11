from flask import Flask 
from flask import render_template, redirect, url_for, session, request, flash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import pwm.functions as funcs

user_name = funcs.user_name
app = Flask(__name__)

def validate_token(token):
    s = Serializer(user_name)
    try:
        username = s.loads(token)['username']
    except SignatureExpired:
        return False
    return True


@app.route("/")
def index():
    is_configured = funcs.is_configured()
    if not is_configured["configured"] or len(is_configured["missing_fields"]) > 0:
        return redirect(url_for('configure'))
    
    is_authenticated = funcs.is_authenticated()
    if not is_authenticated:
        return redirect(url_for("login"))
    
    if "refresh_token" not in session:
        return redirect(url_for('login'))

    return redirect(url_for('get'))


@app.route("/login", methods = ["GET"])
def login():
    configurd = funcs.is_configured()
    if configurd["configured"] and len(configurd["missing_fields"]) == 0:
        return render_template("login.html")
    return redirect(url_for('configure'))

@app.route("/validate", methods = ["POST"])
def validate():
    password = request.form["password"]
    resp = funcs.authenticate(password)
    if resp:
        session["refresh_token"] = funcs.get_from_auth("refresh_token")[0].value
        return redirect(url_for('get'))
    else:
        flash("Incorrect Password...")
        return redirect(url_for('login'))


@app.route("/configure", methods = ["GET"])
def configure():
    return render_template("configure.html")

@app.route("/configured", methods = ["POST"])
def configured():

    passcode = request.form["passcode"]
    refresh_token_sec = request.form["refresh-token-sec"]
    password = request.form["password"]
    secret = request.form["secret"]
    
    dir_name = os.path.expanduser(funcs.pwm_config_dir)
    resp = funcs.is_configured()
    if not resp["configured"]:
        os.mkdir(dir_name)
        file_name = dir_name + "/pwm.db"
        response = funcs.initialize_db()
        if not response:
            flash("Error initializing DB, contact Support")
            return redirect(url_for('configure'))  
    
    missing_fields = resp["missing_fields"]
    if "refresh_token_sec" in missing_fields:
        resp = funcs.push_to_auth("refresh_token_sec", refresh_token_sec)
        if not resp:
            flash("Error while configuring creds, Try again.")
            return redirect(url_for('configure'))  

    if "username" in missing_fields:
        resp = funcs.push_to_auth("username", funcs.user_name)
        if not resp:
            flash("Error while configuring creds, Try again.")
            return redirect(url_for('configure'))
            
    if "passcode" in missing_fields:
        resp = funcs.push_to_auth("passcode", funcs.hash_passwd(passcode))
        if not resp:
            flash("Error while configuring creds, Try again.")
            return redirect(url_for('configure'))
        
    if "password" in missing_fields:        
        hash_pass = funcs.hash_passwd(password)
        resp = funcs.push_to_auth("password", hash_pass)
        if not resp:
            flash("Error while configuring creds, Try again.")
            return redirect(url_for('configure'))

    if "secret" in missing_fields:
        enc_secret = funcs.encrypt_symm_secret(secret)
        resp = funcs.push_to_auth("secret", enc_secret)
        if resp:
            flash("Error while configuring creds, Try again.")
            return redirect(url_for('configure'))
    
    secret = funcs.get_from_auth("secret")[0].value
    app.config['SECRET_KEY']= secret
    
    response = funcs.authenticate(password)
    if response:
        flash("Authentication token set.!")
        return redirect(url_for('get'))
    else:
        flash("Something wrong while setting the auth token")
        return redirect(url_for('configure'))


@app.route("/put")
def put():
    is_configured = funcs.is_configured()
    if not is_configured["configured"] or len(is_configured["missing_fields"]) > 0:
        return redirect(url_for('configure'))

    if "refresh_token" in session and validate_token(session["refresh_token"]):
        return render_template("put.html")    
    return redirect(url_for("login"))
    


@app.route("/get")
def get():
    is_configured = funcs.is_configured()
    if not is_configured["configured"] or len(is_configured["missing_fields"]) > 0:
        return redirect(url_for('configure'))
    
    if "refresh_token" in session and validate_token(session["refresh_token"]):
        passwords = funcs.get_all_passwords()
        return render_template("get.html", passwords = passwords)    
    return redirect(url_for("login"))
    

@app.route("/logout")
def logout():
    session.pop("refresh_token", None)

    return redirect(url_for("login"))

def run():
    app.run(host="localhost", port = 5001)