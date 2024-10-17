#!/usr/bin/env python3

from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException
import re
import argparse
import logging
import getpass
import sys

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
def attempt_connection(server, use_ssl, user, password):
    protocol = "ldaps" if use_ssl else "ldap"
    port = 636 if use_ssl else 389
    try:
        s = Server(server, port=port, use_ssl=use_ssl, get_info=ALL)
        c = Connection(s, user, password, auto_bind=True)
        return s, c, True
    except LDAPException as e:
        logging.error(f"Error connecting to the server with {protocol}://{server}:{port}: {e}")
        return None, None, False

def perform_ldap_search(connection, base_dn, search_filter, attribute):
    try:
        connection.search(search_base=base_dn,
                          search_filter=search_filter,
                          search_scope=SUBTREE,
                          attributes=[attribute])
        return [entry[attribute].value for entry in connection.entries if attribute in entry]
    except LDAPException as e:
        logging.error(f"Error performing LDAP search: {e}")
        return []

def write_results_to_file(results, filename):
    with open(filename, 'w') as f:
        for item in results:
            f.write(f"{item}\n")
    print(f"Results written to {filename}\n")

def perform_ldap_search_all_attributes(connection, base_dn, search_filter):
    try:
        connection.search(search_base=base_dn,
                          search_filter=search_filter,
                          search_scope=SUBTREE,
                          attributes=['*'])
        return connection.entries
    except LDAPException as e:
        logging.error(f"Error performing LDAP search: {e}")
        return []

def write_detailed_results_to_file(results, filename):
    with open(filename, 'w') as f:
        for entry in results:
            f.write(f"DN: {entry.entry_dn}\n")
            for attribute in entry.entry_attributes:
                values = entry[attribute].values
                if len(values) == 1:
                    f.write(f"{attribute}: {values[0]}\n")
                else:
                    f.write(f"{attribute}:\n")
                    for value in values:
                        f.write(f"  {value}\n")
            f.write("\n")
    print(f"Detailed results written to {filename}\n")

def main():
    # Attempt to connect with SSL first, then without SSL
    for use_ssl in [True, False]:
        protocol = "SSL" if use_ssl else "non-SSL"
        print(f"Attempting to connect to {args.dc_ip} with {protocol}...")
        logging.info(f"Attempting to connect to {args.dc_ip} with {protocol}")

        s, c, checkserver = attempt_connection(args.dc_ip, use_ssl, user, password)

        if checkserver:
            print("Connected successfully. Retrieving server information...")
            logging.info("Connected successfully")
            print(s.info)

            # Extract domain components from the server's info
            domain_components = s.info.other['defaultNamingContext'][0].split(',')
            base_dn = ','.join(dc for dc in domain_components if dc.startswith('DC='))

            # Search for users (sAMAccountName only)
            print("Searching for users (sAMAccountName)...")
            users = perform_ldap_search(c, base_dn, '(&(objectclass=user))', 'sAMAccountName')
            write_results_to_file(users, 'usersLdap.txt')

            # Search for users (all attributes)
            print("Searching for users (all attributes)...")
            users_detailed = perform_ldap_search_all_attributes(c, base_dn, '(&(objectclass=user))')
            write_detailed_results_to_file(users_detailed, 'usersLdap_detailed.txt')

            # Search for groups
            print("Searching for groups...")
            groups = perform_ldap_search(c, base_dn, '(&(objectclass=group))', 'sAMAccountName')
            write_results_to_file(groups, 'groupsLdap.txt')

            # Search for groups (all attributes)
            print("Searching for groups (all attributes)...")
            groups_detailed = perform_ldap_search_all_attributes(c, base_dn, '(&(objectclass=group))')
            write_detailed_results_to_file(groups_detailed, 'groupsLdap_detailed.txt')


            break



        else:
            print(f"Failed to connect with {protocol}.")
            logging.warning(f"Failed to connect with {protocol}.")

    if not checkserver:
        print("Failed to connect: Server does not allow LDAP bind or invalid credentials.")
        logging.error("Failed to connect: Server does not allow LDAP bind or invalid credentials.")

if __name__ == "__main__":
    main()
