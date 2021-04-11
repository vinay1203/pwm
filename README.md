## pwm

Password manager utility to store and retrieve passwords using cli or from browser.

` # pwm configure`

To configure the pwm utility 

`# pwm frontend `

To run it in the browser, usually runs on port 5001 of localhost.

`# pwm`

To get help on different commands supported

How to test it:

1. Clone the repository 
2. Install the pwm utility from local git repo by running the below command by navigating into the directory in which the setup.py file exists:

`# pip3 install -e .`

Note: If you are using older versions of pip3 ( 10 or older), cryptography module that is used to encrypt the passwords will fail. So, upgrade your pip3 by using the command :

` # pip3 install --upgrade pip`

3. Verify the installation by invoking the version command:

` # pwm --version`