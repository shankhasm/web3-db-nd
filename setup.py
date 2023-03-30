'''
Setup script for Web3DB package.

This script automates the installation process for this repository
by downloading and setting up go-threads as well as configuring
settings in web3-db-uga

Note:
Users must have golang, Node.js, and NPM installed as well as ruamel.yaml

If you do not have ruamel.yaml installed already, try running
pip install ruamel.yaml
or if issue persists
conda install ruamel.yaml
'''

import os
import subprocess
import sys
from ruamel.yaml import YAML

DEFAULT_YAML_VALUES = {
    'http_port': 3001,
    'threaddb_addr': '127.0.0.1:6006',
    'private_key': None,
    'https_port': 0,
    'tls_cert_path': None,
    'tls_pk_path': None,
    'bootstrap_multiaddr': None,
    'bootstrap_comms_port': 8234,
    'master_node_comms_port': 5678,
    'log_directory': './logs/',
    'dev_mode': True,
}

SOURCE_YAML_FILE = 'config.example.yaml'
DEST_YAML_FILE = 'config.yaml'

def run_command(command):
    print(f'Running command: {command}')
    result = subprocess.run(command, shell=True, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f'Command failed with error code: {result.returncode}')
        print(f'stderr: {result.stderr.decode("utf-8").strip()}')

def change_directory(path):
    print(f'Changing directory to {os.path.abspath(path)}')
    os.chdir(path)

def update_yaml():
    ''' Updates the example yaml file with default values '''

    print('Updating config.yaml')
    # Load the YAML file
    yaml = YAML()
    config = yaml.load(open(SOURCE_YAML_FILE))

    # Fill in the YAML file with the defined values
    for key, value in DEFAULT_YAML_VALUES.items():
        config[key] = value

    # Replace SOURCE yaml with new DEST yaml
    print('Updating with this YAML file...')
    yaml.dump(config, sys.stdout)
    print()
    yaml.dump(config, open(DEST_YAML_FILE, 'w'))
    run_command(f'rm {SOURCE_YAML_FILE}')

def main():
    # Ensure script is being run from web3-db-uga
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)
    if script_dir != os.getcwd():
        print('Script must be run from web3-db-uga: eg. `python3 setup.py`')
        exit(1)

    # Clone go-threads repository in same directory as web3-db-uga
    change_directory('..')
    run_command('git clone https://github.com/textileio/go-threads')
    print()

    # Run go get on go-threads
    change_directory('go-threads')
    run_command('go get ./threadsd')
    print()

    # Setup the web3db directory by updating YAML file and running main.go
    change_directory('../web3-db-uga/web3db')
    update_yaml()

    # Setup the web3dbadmin directory
    change_directory('../web3dbadmin')
    run_command('npm install --legacy-peer-deps') # for resolving dependencies

if __name__ == '__main__':
    main()
