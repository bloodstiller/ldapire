from ldap3 import *
import re
import argparse
import logging
import getpass

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

# Setup logging
logging.basicConfig(filename='ldap_test.log', level=logging.INFO)

# Command-line argument parsing
parser = argparse.ArgumentParser(description="LDAP Anonymous Bind Test")
parser.add_argument('dc_ip', help="IP address of the Domain Controller")
parser.add_argument('-u', '--user', help="Username for authentication", default='')
parser.add_argument('-p', '--password', help="Password for authentication", default='')

args = parser.parse_args()

# Validate IP address
srver = args.dc_ip
if not is_valid_ip(srver):
    print("Invalid IP address format.")
    logging.error(f"Invalid IP address format: {srver}")
    exit(1)

# Handle secure password input
user = args.user
password = args.password
if not password and user:
    password = getpass.getpass("Enter password: ")

# Function to attempt LDAP connection
def attempt_connection(use_ssl):
    try:
        s = Server(srver, use_ssl=use_ssl, get_info=ALL)
        c = Connection(s, user, password)
        checkserver = c.bind()
        return s, c, checkserver
    except Exception as e:
        logging.error(f"Error connecting to the server with SSL={use_ssl}: {e}")
        return None, None, False

# Attempt to connect with SSL first
print(f"Attempting to connect to {srver} with SSL...")
logging.info(f"Attempting to connect to {srver} with SSL")
s, c, checkserver = attempt_connection(use_ssl=True)

# If SSL connection fails, retry without SSL
if not checkserver:
    print("Failed to connect with SSL. Retrying without SSL...")
    logging.warning("Failed to connect with SSL. Retrying without SSL...")
    s, c, checkserver = attempt_connection(use_ssl=False)

# Final status check
if checkserver:
    print("Connected successfully. Retrieving server information...")
    logging.info("Connected successfully")
    print(s.info)
else:
    print("Failed to connect: Server does not allow LDAP Anonymous bind or invalid credentials.")
    logging.error("Failed to connect: Server does not allow LDAP Anonymous bind or invalid credentials.")
