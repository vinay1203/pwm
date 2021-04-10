from setuptools import setup, find_packages

setup(
    name='pwm',
    version='1.0.0',
    description='Script that handles password get and put',
    author='Srinivasa Vinay',
    maintainer='Srinivasa Vinay',
    entry_points={
        'console_scripts': [
            'pwm = pwm.cli:main'
        ]
    },
    packages=find_packages(),
    install_requires=['click', 'pyperclip', 'bcrypt', 'itsdangerous', 'cryptography', 'sqlalchemy', 'tabulate'],
    platforms=['macOS', 'linux'],
    keywords=['password', 'utility', 'util', 'cli']
)