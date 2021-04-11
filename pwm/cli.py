import click
from sys import exit
import os 
import getpass
import pyperclip
import pwm.functions as funcs
import pwm.app as app
from tabulate import tabulate

pwm_config_dir = funcs.pwm_config_dir

@click.group(name='main', invoke_without_command=True)
@click.version_option(version=funcs.version)
def main():
    """
    The utiility for management of the passwords 
    """

    ctx = click.get_current_context()
    if ctx.invoked_subcommand is None:
        print("\n", end = "")
        print("#"*25)
        print("Welcome to pwm utility, ", end = "")
        click.echo(click.style(funcs.user_name, fg="green", bold=True))
        quote = funcs.get_random_quote()
        click.echo(click.style("A random quote:", fg = "magenta"))
        click.echo(click.style("\t" + quote, fg="yellow"))   
        print("#"*25, end = "\n\n")
        resp = funcs.is_configured()
        if not resp["configured"]:
            click.echo(click.style("the datastore directory is not present, you can try running below cmd to configure it", fg='red'))
            click.echo(click.style('\n\t # pwm configure\n', fg='green'))
            click.echo(ctx.get_help())
            ctx.exit()
        
        if len(resp["missing_fields"]) > 0:
            click.echo(click.style("Some configuration fields are missing, you can try running below cmd to configure it", fg='red'))
            click.echo(click.style('\n\t # pwm configure\n', fg='green'))

        click.echo(ctx.get_help())
        ctx.exit()
        
    return


@main.command("frontend")
def frontend():
    """Run frontend on localhost port 5001 """
    app.run()


@main.command("configure")
@click.option("--refresh-token-sec", default=3600, type=int, show_default=True, prompt='Refresh seconds')
def configure(refresh_token_sec):
    """ Configure the pwm utility and DB """
    dir_name = os.path.expanduser(pwm_config_dir)
    resp = funcs.is_configured()
    if not resp["configured"]:
        os.mkdir(dir_name)
        click.echo("the directory " +  dir_name + " is created to store db data")
        file_name = dir_name + "/pwm.db"
        response = funcs.initialize_db()
        if response:
            click.echo(click.style("The DB is successfully initialized", fg="green"))
        else:
            click.echo(click.style("Error initializing DB, contact Support", fg = "red"))  
    
    missing_fields = resp["missing_fields"]
    if "refresh_token_sec" in missing_fields:
        resp = funcs.push_to_auth("refresh_token_sec", refresh_token_sec)
        if resp:
            content = "Refresh token seconds is configured successfully"
            color = "green" 
        else:
            content = "Error while configuring..."
            color = "red"
        click.echo(click.style(content, fg = color))
    
    if "username" in missing_fields:
        resp = funcs.push_to_auth("username", funcs.user_name)
        if resp:
            content = "Username is configured successfully" 
            color = "green"
        else: 
            content = "Error while configuring..."
            color = "red"
        click.echo(click.style(content, fg = color))

    if "passcode" in missing_fields:
        dob = click.prompt("Enter passcode used when you want to reset password ", hide_input=True, default="19091995", show_default=True)
        resp = funcs.push_to_auth("passcode", funcs.hash_passwd(dob))
        if resp:
            content = "Passcode is configured successfully"
            color = "green" 
        else:
            content = "Error while configuring..."
            color = "red"
        click.echo(click.style(content, fg = color))
        
    if "password" in missing_fields:        
        password = click.prompt("Enter Password: ", hide_input=True, confirmation_prompt=True)
        hash_pass = funcs.hash_passwd(password)
        resp = funcs.push_to_auth("password", hash_pass)
        if resp:
            content = "Password is configured successfully"
            color = "green"
        else:
            content = "Error while configuring..."
            color = "red"
        click.echo(click.style(content, fg = color))

    if "secret" in missing_fields:   
        rand_secret = funcs.get_random_secret()
        secret = click.prompt("Enter a secret: ", hide_input=True, default=rand_secret, show_default=True)
        if secret == "":
            secret = rand_secret
        enc_secret = funcs.encrypt_symm_secret(secret)
        resp = funcs.push_to_auth("secret", enc_secret)
        if resp:
            content = "Secret is configured successfully"
            color = "green"
        else: 
            content = "Error while configuring..."
            color = "red"
        click.echo(click.style(content, fg = color))
    
    response = funcs.authenticate(password)
    if response:
        click.echo(click.style("Authentication token set.!", fg = "green"))
        click.echo(click.style("\nALL GOOD TO GO!!!\n", fg = "green"))
    else:
        click.echo(click.style("Something wrong while setting the auth token\n\
        run the command 'pwm auth' to authenticate", fg = "red"))


@main.command("grp")
@click.option("--length", default = 17, type = int, show_default = True, prompt = 'Length of the password')
def grp(length):
    """Generate  random password"""
    if length<8:
        click.echo(click.style("Length of password cannot be less than eight", fg = "red")) 
        exit()
    
    click.echo("Generating a random password with length of " + str(length) + " characters")
    pas = funcs.get_random_secret(length)
    click.echo("The password is: "+ click.style(pas, fg="green")+ "\n")


@main.command("ls")
@click.option("--alias", default = "", help = "Alias of the password")
@funcs.configure_dec
@funcs.authenticate_dec
def get(alias):
    """ Get the password of a key """
    passwords = []
    records = funcs.get_passwords(alias)
    if len(records) == 0:
        if alias != "": 
            click.echo(click.style("Could not find the alias", fg = "red"))
            exit()
    for i in records:
        passwords.append([i.id, i.alias, i.key])
    print(tabulate(passwords, headers=['id', 'Alias', 'Key']))

    exit()  


@main.command("get")
@click.option("--alias", default = "", help = "Alias of the password")
@funcs.configure_dec
@funcs.authenticate_dec
def cp(alias):
    """Copy the password to the clipboard"""
    if alias == "":
        click.echo(click.style("Please provide an alias", fg = "red"))
        exit()
    get_password = funcs.get_from_pass(alias)
    if len(get_password) == 0:
        click.echo(click.style("Could not find the alias", fg = "red"))
        exit()
    password = get_password[0].password
    unencrypt_password = funcs.decrypt_symm_secret(password)
    unencrypt_password = unencrypt_password.decode()

    pyperclip.copy(unencrypt_password)
    click.echo(click.style("Password copied to clipboard", fg = "green"))


@main.command("put")
@click.option("--alias", default = "", help = "Alias for the password")
@click.option("--key", default = "", help = "Username or email id of the password ")
@funcs.configure_dec
@funcs.authenticate_dec
def put(alias, key):
    """ Store a password for the account """
    is_configured = funcs.is_configured()
    if not is_configured:
        click.echo(click.style("the datastore directory is not present, you can try running below cmd to configure it", fg='red'))
        click.echo(click.style('\n\t # pwm configure\n', fg='green'))
        exit()
    
    is_authenticated = funcs.is_authenticated()
    if is_authenticated:
        alias = click.prompt("Enter an alias for the password ")
        alias = alias.strip()
        key = click.prompt("Enter a key for the password ")
        key = key.strip()
        password = click.prompt("Enter Password: ", hide_input=True, confirmation_prompt=True)
        password = password.strip()

        enc_password = funcs.encrypt_symm_secret(password)
        status = funcs.push_to_password(attr=key, value = enc_password, alias = alias)
        fg = "green" if status[0] else "red"
        click.echo(click.style(status[1], fg=fg))


@main.command("update")
@click.option("--alias", default = "", help = "Alias for the password")
@funcs.configure_dec
@funcs.authenticate_dec
def update(alias):
    """Update the key and password using alias"""
    if alias == "":
        alias = click.prompt("Enter the alias you want to update ")
        alias = alias.strip()
    
    record = funcs.get_from_pass(alias)
    if len(record) == 0:
        click.echo(click.style("No such alias exists", fg = "red"))
        exit()
    
    key = click.prompt("Enter key for the alias ", default=record[0].key, show_default=True)
    password = click.prompt("Enter Password ", hide_input=True, confirmation_prompt=True)

    enc_password = funcs.encrypt_symm_secret(password)
    status = funcs.update_password(attr=key, value = enc_password, alias = alias)
    fg = "green" if status[0] else "red"
    click.echo(click.style(status[1], fg=fg))
