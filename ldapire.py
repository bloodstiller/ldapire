#!/usr/bin/env python3

from ldap3 import Server, Connection, ALL, SUBTREE, ANONYMOUS
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

def get_domain_from_dc_ip(dc_ip):
    try:
        import socket
        domain = socket.gethostbyaddr(dc_ip)[0]
        return '.'.join(domain.split('.')[1:])  # Remove the hostname part
    except:
        return None

def construct_user_string(user, dc_ip):
    if '\\' in user or ',' in user:  # Already in DOMAIN\user or DN format
        return user
    
    domain = get_domain_from_dc_ip(dc_ip)
    if domain:
        return f"{domain}\\{user}"
    else:
        return user  # Fallback to just the username if domain can't be determined

def attempt_connection(server, use_ssl, user, password):
    """
    Attempt to connect to LDAP server and verify read access
    
    Args:
        server (str): Server IP or hostname
        use_ssl (bool): Whether to use SSL/TLS
        user (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        tuple: (Server object, Connection object, bool indicating success)
    """
    protocol = "ldaps" if use_ssl else "ldap"
    port = 636 if use_ssl else 389
    try:
        s = Server(server, port=port, use_ssl=use_ssl, get_info=ALL)
        if user and password:
            user_string = construct_user_string(user, server)
            c = Connection(s, user=user_string, password=password, authentication='SIMPLE', auto_bind=True)
        else:
            c = Connection(s, auto_bind=True)
            
        # Test for read access
        if hasattr(s.info, 'other') and 'defaultNamingContext' in s.info.other:
            base_dn = s.info.other['defaultNamingContext'][0]
            c.search(base_dn, '(objectClass=*)', attributes=['cn'], size_limit=1)
            if c.entries:
                return s, c, True
            
        return s, c, False
            
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
    print(f"[+] Results written to {filename}\n")

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

def sid_to_str(sid):
    """
    Convert a binary SID (Security Identifier) to its string representation.
    Format: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx
    
    Args:
        sid (bytes): Binary SID data
        
    Returns:
        str: String representation of the SID or error message
    """
    try:
        # Check if SID is empty or all zeros
        if all(b == 0 for b in sid):
            return "<all zeros>"

        # Get revision number (first byte)
        revision = int(sid[0])
        # Get count of sub-authorities (second byte)
        sub_authorities = int(sid[1])
        # Get identifier authority (bytes 2-7, big endian)
        identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
        
        # Convert authority to hex if it's a large number
        if identifier_authority >= 2 ** 32:
            identifier_authority = hex(identifier_authority)

        # Extract sub-authorities (remaining bytes in 4-byte chunks, little endian)
        sub_authority = '-' + '-'.join([
            str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little'))
            for i in range(sub_authorities)
        ])
        
        return 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority
    except Exception as e:
        if all(b == 0 for b in sid):
            return "<all zeros>"
        return f"<error converting SID: 0x{sid.hex()}>"

def convert_guid(binary_guid):
    """
    Convert binary GUID to standard string format.
    Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    
    Args:
        binary_guid (bytes): Binary GUID data
        
    Returns:
        str: String representation of the GUID
    """
    try:
        hex_guid = binary_guid.hex()
        return f"{hex_guid[6:8]}{hex_guid[4:6]}{hex_guid[2:4]}{hex_guid[0:2]}-" \
               f"{hex_guid[10:12]}{hex_guid[8:10]}-" \
               f"{hex_guid[14:16]}{hex_guid[12:14]}-" \
               f"{hex_guid[16:20]}-" \
               f"{hex_guid[20:]}"
    except Exception:
        return f"<invalid GUID format: {binary_guid.hex()}>"

def convert_exchange_binary(attribute_name, binary_value):
    """
    Convert various Exchange and AD binary attributes to readable format.
    Handles different types of binary data based on attribute name.
    
    Args:
        attribute_name (str): Name of the attribute being converted
        binary_value (bytes): Binary data to convert
        
    Returns:
        str: Converted string representation of the binary data
    """
    try:
        # Handle empty or all zero values
        if not binary_value or all(b == 0 for b in binary_value):
            return "<all zeros>"
            
        # Convert based on attribute type
        if attribute_name.lower() in ['msexchmailboxguid', 'msexcharchiveguid']:
            # Exchange GUIDs use standard GUID format
            return convert_guid(binary_value)
        elif attribute_name.lower() in ['objectsid', 'msexchmasteraccountsid']:
            # SIDs need special conversion
            return sid_to_str(binary_value)
        elif attribute_name.lower() in ['msexchmailboxsecuritydescriptor', 'repluptodatevector', 
                                      'dsasignature', 'auditingpolicy']:
            # These attributes are displayed in hex format
            return f"0x{binary_value.hex()}"
        else:
            # Unknown binary attributes show their length
            return f"<binary data length={len(binary_value)}>"
    except Exception as e:
        return f"<error converting {attribute_name}: {str(e)}>"

def write_detailed_results_to_file(results, filename):
    # Track which attributes were converted to hex
    hex_converted_attrs = set()
    
    with open(filename, 'w', encoding='utf-8', errors='replace') as f:
        for entry in results:
            try:
                f.write(f"DN: {entry.entry_dn}\n")
                for attribute in entry.entry_attributes:
                    try:
                        values = entry[attribute].values
                        # Handle different types of values
                        if isinstance(values, (list, set)):
                            cleaned_values = []
                            for value in values:
                                if isinstance(value, bytes):
                                    # Special handling for different binary attributes
                                    if attribute.lower() == 'objectsid':
                                        cleaned_values.append(sid_to_str(value))
                                    elif attribute.lower() == 'objectguid':
                                        cleaned_values.append(convert_guid(value))
                                    elif attribute.lower() in ['msexchmailboxguid', 'msexcharchiveguid', 
                                                            'msexchmailboxsecuritydescriptor', 'repluptodatevector',
                                                            'msexchmasteraccountsid', 'dsasignature', 'auditingpolicy']:
                                        result = convert_exchange_binary(attribute, value)
                                        cleaned_values.append(result)
                                        # Track hex converted attributes
                                        if result.startswith('0x'):
                                            hex_converted_attrs.add(attribute)
                                    else:
                                        try:
                                            cleaned_values.append(value.decode('utf-8', errors='replace'))
                                        except:
                                            cleaned_values.append(f"<binary data length={len(value)}>")
                                else:
                                    cleaned_values.append(str(value))
                            
                            if len(cleaned_values) == 1:
                                f.write(f"{attribute}: {cleaned_values[0]}\n")
                            else:
                                f.write(f"{attribute}:\n")
                                for value in cleaned_values:
                                    f.write(f"  {value}\n")
                        else:
                            if isinstance(values, bytes):
                                # Special handling for different binary attributes
                                if attribute.lower() == 'objectsid':
                                    value_str = sid_to_str(values)
                                elif attribute.lower() == 'objectguid':
                                    value_str = convert_guid(values)
                                elif attribute.lower() in ['msexchmailboxguid', 'msexcharchiveguid', 
                                                        'msexchmailboxsecuritydescriptor', 'repluptodatevector',
                                                        'msexchmasteraccountsid', 'dsasignature', 'auditingpolicy']:
                                    value_str = convert_exchange_binary(attribute, values)
                                    # Track hex converted attributes
                                    if value_str.startswith('0x'):
                                        hex_converted_attrs.add(attribute)
                                else:
                                    try:
                                        value_str = values.decode('utf-8', errors='replace')
                                    except:
                                        value_str = f"<binary data length={len(values)}>"
                            else:
                                value_str = str(values)
                            f.write(f"{attribute}: {value_str}\n")
                    except Exception as e:
                        f.write(f"{attribute}: <error reading value: {str(e)}>\n")
                f.write("\n")
            except Exception as e:
                f.write(f"<error processing entry: {str(e)}>\n\n")
        
        # Write summary of hex-converted attributes
        if hex_converted_attrs:
            f.write("\n=== CONVERSION SUMMARY ===\n")
            f.write("The following attributes were converted to hexadecimal format:\n")
            for attr in sorted(hex_converted_attrs):
                f.write(f"- {attr}\n")
            
    print(f"[+] Detailed results written to {filename}")

def write_groups_to_file(results, filename):
    """
    Write LDAP group query results to a file with proper attribute formatting.
    Handles binary data conversion for special attributes like SIDs and GUIDs.
    
    Args:
        results: LDAP query results containing group entries
        filename (str): Output file path
    """
    with open(filename, 'w', encoding='utf-8', errors='replace') as f:
        for entry in results:
            try:
                f.write(f"DN: {entry.entry_dn}\n")
                for attribute in entry.entry_attributes:
                    try:
                        values = entry[attribute].values
                        # Handle multi-valued attributes
                        if isinstance(values, (list, set)):
                            if len(values) == 1:
                                # Single value in a list
                                if isinstance(values[0], bytes):
                                    # Handle binary attributes
                                    if attribute.lower() == 'objectsid':
                                        f.write(f"{attribute}: {sid_to_str(values[0])}\n")
                                    elif attribute.lower() == 'objectguid':
                                        f.write(f"{attribute}: {convert_guid(values[0])}\n")
                                    else:
                                        try:
                                            f.write(f"{attribute}: {values[0].decode('utf-8')}\n")
                                        except:
                                            f.write(f"{attribute}: <binary data length={len(values[0])}>\n")
                                else:
                                    f.write(f"{attribute}: {values[0]}\n")
                            else:
                                # Multiple values
                                f.write(f"{attribute}:\n")
                                for value in values:
                                    if isinstance(value, bytes):
                                        try:
                                            f.write(f"  {value.decode('utf-8')}\n")
                                        except:
                                            f.write(f"  <binary data length={len(value)}>\n")
                                    else:
                                        f.write(f"  {value}\n")
                        else:
                            # Single value attributes
                            if isinstance(values, bytes):
                                if attribute.lower() == 'objectsid':
                                    f.write(f"{attribute}: {sid_to_str(values)}\n")
                                elif attribute.lower() == 'objectguid':
                                    f.write(f"{attribute}: {convert_guid(values)}\n")
                                else:
                                    try:
                                        f.write(f"{attribute}: {values.decode('utf-8')}\n")
                                    except:
                                        f.write(f"{attribute}: <binary data length={len(values)}>\n")
                            else:
                                f.write(f"{attribute}: {values}\n")
                    except Exception as e:
                        f.write(f"{attribute}: <error reading value: {str(e)}>\n")
                f.write("\n")
            except Exception as e:
                f.write(f"<error processing entry: {str(e)}>\n\n")
    print(f"[+] Groups written to {filename}")

def write_all_descriptions_to_file(results_list, filename):
    """
    Extract and write description fields from all LDAP objects to a single file.
    Only writes entries that have a description field.
    
    Args:
        results_list: List of LDAP query results (users, groups, computers)
        filename (str): Output file path
    """
    with open(filename, 'w', encoding='utf-8', errors='replace') as f:
        for results in results_list:
            for entry in results:
                try:
                    # Check if description exists
                    if 'description' in entry.entry_attributes:
                        f.write(f"DN: {entry.entry_dn}\n")
                        
                        # Get name (try different attributes)
                        name = None
                        for name_attr in ['name', 'sAMAccountName', 'cn']:
                            if name_attr in entry.entry_attributes:
                                name = entry[name_attr].value
                                break
                        f.write(f"Name: {name if name else '<no name>'}\n")
                        
                        # Get object class
                        if 'objectClass' in entry.entry_attributes:
                            obj_classes = entry['objectClass'].values
                            if obj_classes:
                                f.write(f"Object Class: {obj_classes[-1]}\n")
                        
                        # Get description
                        descriptions = entry['description'].values
                        if isinstance(descriptions, (list, set)):
                            if len(descriptions) == 1:
                                f.write(f"Description: {descriptions[0]}\n")
                            else:
                                f.write("Description:\n")
                                for desc in descriptions:
                                    f.write(f"  {desc}\n")
                        else:
                            f.write(f"Description: {descriptions}\n")
                        f.write("\n")
                except Exception as e:
                    f.write(f"<error processing entry {entry.entry_dn}: {str(e)}>\n\n")
    print(f"[+] All descriptions written to {filename}")

def write_computers_to_file(results, filename):
    """
    Write LDAP computer query results to a file with proper attribute formatting.
    Similar to group handling but specific to computer objects.
    
    Args:
        results: LDAP query results containing computer entries
        filename (str): Output file path
    """
    with open(filename, 'w', encoding='utf-8', errors='replace') as f:
        for entry in results:
            try:
                f.write(f"DN: {entry.entry_dn}\n")
                for attribute in entry.entry_attributes:
                    try:
                        values = entry[attribute].values
                        # Handle multi-valued attributes
                        if isinstance(values, (list, set)):
                            if len(values) == 1:
                                # Single value in a list
                                if isinstance(values[0], bytes):
                                    # Handle binary attributes
                                    if attribute.lower() == 'objectsid':
                                        f.write(f"{attribute}: {sid_to_str(values[0])}\n")
                                    elif attribute.lower() == 'objectguid':
                                        f.write(f"{attribute}: {convert_guid(values[0])}\n")
                                    else:
                                        try:
                                            f.write(f"{attribute}: {values[0].decode('utf-8')}\n")
                                        except:
                                            f.write(f"{attribute}: <binary data length={len(values[0])}>\n")
                                else:
                                    f.write(f"{attribute}: {values[0]}\n")
                            else:
                                # Multiple values
                                f.write(f"{attribute}:\n")
                                for value in values:
                                    if isinstance(value, bytes):
                                        try:
                                            f.write(f"  {value.decode('utf-8')}\n")
                                        except:
                                            f.write(f"  <binary data length={len(value)}>\n")
                                    else:
                                        f.write(f"  {value}\n")
                        else:
                            # Single value attributes
                            if isinstance(values, bytes):
                                if attribute.lower() == 'objectsid':
                                    f.write(f"{attribute}: {sid_to_str(values)}\n")
                                elif attribute.lower() == 'objectguid':
                                    f.write(f"{attribute}: {convert_guid(values)}\n")
                                else:
                                    try:
                                        f.write(f"{attribute}: {values.decode('utf-8')}\n")
                                    except:
                                        f.write(f"{attribute}: <binary data length={len(values)}>\n")
                            else:
                                f.write(f"{attribute}: {values}\n")
                    except Exception as e:
                        f.write(f"{attribute}: <error reading value: {str(e)}>\n")
                f.write("\n")
            except Exception as e:
                f.write(f"<error processing entry: {str(e)}>\n\n")
    print(f"[+] Computers written to {filename}")

def write_basic_names_to_file(results, filename, name_attribute='sAMAccountName'):
    """
    Write just the SAM account names to a file.
    
    Args:
        results: LDAP query results
        filename (str): Output file path
        name_attribute (str): Attribute to use for names (default: sAMAccountName)
    """
    with open(filename, 'w', encoding='utf-8', errors='replace') as f:
        for entry in results:
            try:
                if name_attribute in entry.entry_attributes:
                    name = entry[name_attribute].value
                    if name:  # Only write if name exists
                        f.write(f"{name}\n")
            except Exception as e:
                f.write(f"<error processing entry: {str(e)}>\n")
    print(f"[+] Basic names written to {filename}")

def print_banner():
    """Print a banner with script information"""
    print("\n" + "="*60)
    print(" "*20 + "LDAP Information Retrieval")
    print(" "*22 + "Domain Enumeration")
    print("="*60 + "\n")

def print_section_header(section):
    """Print a section header"""
    print("\n" + "-"*60)
    print(f" {section}")
    print("-"*60)

def find_service_accounts(output_file='ServiceAccounts.txt'):
    """
    Search through all generated files for potential service account information.
    Looks for 'svc' and 'service' in the content.
    
    Args:
        output_file (str): Name of the file to write results to
    """
    print("\n-----------------------------------------------------------")
    print(" Searching for Service Accounts")
    print("------------------------------------------------------------")
    
    # List of files to search through
    files_to_search = [
        'Users.txt', 'UsersDetailed.txt',
        'Groups.txt', 'GroupsDetailed.txt',
        'Objects.txt', 'ObjectsDetailedLdap.txt',
        'AllObjectDescriptions.txt'
    ]
    
    service_accounts = set()  # Use set to avoid duplicates
    matches_found = 0
    
    # Search patterns
    patterns = ['svc', 'service', 'srvc', 'svc_', 'service_']
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write("=== Potential Service Accounts Found ===\n\n")
        
        for filename in files_to_search:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    print(f"  🔍 Searching {filename}")
                    lines = f.readlines()
                    
                    # Track if we found anything in this file
                    found_in_file = False
                    
                    for line_num, line in enumerate(lines, 1):
                        if any(pattern.lower() in line.lower() for pattern in patterns):
                            # Get context (few lines before and after)
                            context_start = max(0, line_num - 3)
                            context_end = min(len(lines), line_num + 2)
                            context = lines[context_start:context_end]
                            
                            # Format the entry
                            entry = f"\n--- Found in {filename} around line {line_num} ---\n"
                            entry += "".join(context) + "\n"
                            
                            if entry not in service_accounts:  # Avoid duplicates
                                service_accounts.add(entry)
                                found_in_file = True
                                matches_found += 1
                    
                    if found_in_file:
                        print(f"  ✓ Found matches in {filename}")
                    else:
                        print(f"  - No matches in {filename}")
                        
            except FileNotFoundError:
                print(f"  - Skipping {filename} (not found)")
                continue
        
        # Write all unique findings to the output file
        if service_accounts:
            outfile.writelines(sorted(service_accounts))
            outfile.write("\n=== End of Service Accounts Search ===\n")
            print(f"\n  ✓ Service account findings written to {output_file}")
            print(f"  ✓ Found {matches_found} potential matches\n")
        else:
            outfile.write("No service accounts found.\n")
            print("\n  - No service accounts found\n")

def check_anonymous_bind(server_ip):
    """
    Test if anonymous bind is enabled on the LDAP server
    
    Args:
        server_ip (str): IP address of the LDAP server
        
    Returns:
        bool: True if anonymous bind is enabled, False otherwise
    """
    try:
        # Try to bind anonymously
        server = Server(server_ip, get_info=ALL)
        conn = Connection(server, authentication=ANONYMOUS)
        if conn.bind():
            return True
        return False
    except Exception:
        return False

def get_host_and_domain_info(dc_ip):
    """
    Get hostname and domain information for the DC
    
    Args:
        dc_ip (str): IP address of the Domain Controller
        
    Returns:
        tuple: (hostname, domain_name) or (None, None) if lookup fails
    """
    try:
        import socket
        fqdn = socket.gethostbyaddr(dc_ip)[0]
        hostname = fqdn.split('.')[0]
        domain_name = '.'.join(fqdn.split('.')[1:])
        return hostname, domain_name
    except:
        return None, None

def get_domain_info_from_ldap(server_info):
    """
    Extract domain and hostname information from LDAP server info
    
    Args:
        server_info: LDAP server info object
        
    Returns:
        tuple: (hostname, domain_name) or (None, None) if not found
    """
    try:
        # Try to get from serverName first
        if hasattr(server_info, 'other') and 'serverName' in server_info.other:
            server_name = server_info.other['serverName'][0]
            # Extract hostname from CN=FOREST,CN=Servers,...
            hostname = server_name.split(',')[0].replace('CN=', '')
            
        # Try to get from ldapServiceName if serverName failed
        elif hasattr(server_info, 'other') and 'ldapServiceName' in server_info.other:
            service_name = server_info.other['ldapServiceName'][0]
            # Format: domain:hostname$@DOMAIN
            hostname = service_name.split(':')[1].split('@')[0].replace('$', '')
        else:
            hostname = None

        # Get domain from naming context
        if hasattr(server_info, 'other') and 'defaultNamingContext' in server_info.other:
            naming_context = server_info.other['defaultNamingContext'][0]
            # Extract DC components and join them
            domain_parts = [dc.replace('DC=', '') for dc in naming_context.split(',') if dc.startswith('DC=')]
            domain_name = '.'.join(domain_parts)
        else:
            domain_name = None

        return hostname, domain_name
    except:
        return None, None

def process_ldap_results(conn, base_dn, server_ip):
    """
    Process LDAP query results and write to various output files.
    """
    print_banner()
    
    # Get and display host/domain information
    hostname, domain_name = get_host_and_domain_info(server_ip)
    
    # If DNS resolution fails, try getting info from LDAP
    if not hostname or not domain_name:
        hostname, domain_name = get_domain_info_from_ldap(conn.server.info)
    
    print_section_header("Target Information")
    print(f"  • IP Address  : {server_ip}")
    if hostname:
        print(f"  • Hostname    : {hostname}")
    if domain_name:
        print(f"  • Domain Name : {domain_name}")
    if not hostname and not domain_name:
        print("  • Could not resolve hostname and domain name")
    
    # Users Section
    print_section_header("Processing Users")
    users_filter = '(objectClass=user)'
    conn.search(base_dn, users_filter, attributes=['*'])
    users = conn.entries
    write_detailed_results_to_file(users, 'UsersDetailed.txt')
    write_basic_names_to_file(users, 'Users.txt')
    print(f"  ✓ Basic user names    → Users.txt")
    print(f"  ✓ Detailed user info  → UsersDetailed.txt")

    # Groups Section
    print_section_header("Processing Groups")
    groups_filter = '(objectClass=group)'
    conn.search(base_dn, groups_filter, attributes=['*'])
    groups = conn.entries
    write_groups_to_file(groups, 'GroupsDetailed.txt')
    write_basic_names_to_file(groups, 'Groups.txt')
    print(f"  ✓ Basic group names   → Groups.txt")
    print(f"  ✓ Detailed group info → GroupsDetailed.txt")

    # Computers Section
    print_section_header("Processing Computers")
    computers_filter = '(objectClass=computer)'
    conn.search(base_dn, computers_filter, attributes=['*'])
    computers = conn.entries
    write_computers_to_file(computers, 'ComputersDetailed.txt')
    write_basic_names_to_file(computers, 'Computers.txt')
    print(f"  ✓ Basic computer names    → Computers.txt")
    print(f"  ✓ Detailed computer info  → ComputersDetailed.txt")

    # All Objects Section
    print_section_header("Processing All Objects")
    all_objects_filter = '(objectClass=*)'
    conn.search(base_dn, all_objects_filter, attributes=['*'])
    all_objects = conn.entries
    write_detailed_results_to_file(all_objects, 'ObjectsDetailedLdap.txt')
    write_basic_names_to_file(all_objects, 'Objects.txt')
    print(f"  ✓ Basic object names     → Objects.txt")
    print(f"  ✓ Detailed object info   → ObjectsDetailedLdap.txt")
    
    # Descriptions Section
    print_section_header("Processing Descriptions")
    write_all_descriptions_to_file([users, groups, computers], 'AllObjectDescriptions.txt')
    print(f"  ✓ All object descriptions → AllObjectDescriptions.txt")

    # Search for service accounts
    find_service_accounts()
    
    # Security check
    print_section_header("Security Check")
    anon_bind = check_anonymous_bind(server_ip)
    if anon_bind:
        print("  ⚠️  WARNING: Anonymous Bind is ENABLED")
        print("  ⚠️  This is a security risk and should be disabled\n")
    else:
        print("  ✓ Anonymous Bind is DISABLED")
        print("  ✓ This is the recommended secure configuration\n")

    # Summary
    print("=" * 60)
    print(" " * 20 + "Enumeration Complete!")
    print("=" * 60 + "\n")

def get_basic_server_info(dc_ip):
    """
    Get basic server information that's typically available without authentication
    """
    try:
        server = Server(dc_ip, get_info=ALL)
        conn = Connection(server)
        conn.bind()
        
        print("\n------------------------------------------------------------")
        print(" Server Information")
        print("------------------------------------------------------------")
        
        if hasattr(server.info, 'other'):
            info = server.info.other
            
            # Get naming context
            if 'defaultNamingContext' in info:
                domain_parts = [dc.replace('DC=', '') for dc in info['defaultNamingContext'][0].split(',') 
                              if dc.startswith('DC=')]
                print(f"  • Domain Name : {'.'.join(domain_parts)}")
            
            # Get server name
            if 'serverName' in info:
                hostname = info['serverName'][0].split(',')[0].replace('CN=', '')
                print(f"  • Server Name : {hostname}")
            elif 'ldapServiceName' in info:
                hostname = info['ldapServiceName'][0].split(':')[1].split('@')[0].replace('$', '')
                print(f"  • Server Name : {hostname}")
            
            # Get forest functional level if available
            if 'forestFunctionality' in info:
                print(f"  • Forest Level: {info['forestFunctionality'][0]}")
            
            # Get domain functional level if available
            if 'domainFunctionality' in info:
                print(f"  • Domain Level: {info['domainFunctionality'][0]}")
            
        print()  # Empty line for spacing
        
    except Exception as e:
        print("  • Could not retrieve server information")
        logging.error(f"Error getting server info: {str(e)}")

def main():
    """Main function to handle LDAP enumeration"""
    # Get basic server information first (usually available without auth)
    get_basic_server_info(args.dc_ip)
    
    # Check if anonymous bind is enabled
    anon_enabled = check_anonymous_bind(args.dc_ip)
    
    # If no credentials provided and anonymous bind is disabled, exit early
    if not user and not anon_enabled:
        print("------------------------------------------------------------")
        print(" Access Denied")
        print("------------------------------------------------------------")
        print("  ✓ Anonymous Bind is DISABLED (Secure Configuration)")
        print("  • No credentials provided")
        print("  • Please provide valid credentials to enumerate")
        print("  • Use: -u USERNAME -p PASSWORD\n")
        sys.exit(1)

    # Connection attempts header
    print("------------------------------------------------------------")
    print(" Connection Attempts")
    print("------------------------------------------------------------")

    # Attempt to connect with SSL first, then without SSL
    for use_ssl in [True, False]:
        protocol = "SSL" if use_ssl else "non-SSL"
        print(f"  • Attempting {protocol} connection...")
        logging.info(f"Attempting to connect to {args.dc_ip} with {protocol}")
        
        s, c, checkserver = attempt_connection(args.dc_ip, use_ssl, user, password)
        
        if checkserver:
            print(f"  ✓ Connected successfully using {'authenticated' if user else 'anonymous'} bind")
            logging.info(f"Connected successfully using {'authenticated' if user else 'anonymous'} bind")
            
            # Show anonymous bind warning if using anonymous bind
            if not user:
                print("\n------------------------------------------------------------")
                print(" Security Warning")
                print("------------------------------------------------------------")
                print("  ⚠️  WARNING: Connected using Anonymous Bind")
                print("  ⚠️  This is a security risk and should be disabled\n")
            
            # We have confirmed access, proceed with enumeration
            process_ldap_results(c, base_dn, args.dc_ip)
            return  # Exit after successful enumeration
            
        elif c:  # We got a connection but no read access
            print("  ⚠️  Connection established but no read access")
            logging.warning("Connected but no read access")
        else:
            print(f"  ✗ Failed to connect with {protocol}")
            logging.warning(f"Failed to connect with {protocol}")
    
    print()  # Add spacing before final message
    
    # If we get here, all connection attempts failed
    print("------------------------------------------------------------")
    print(" Connection Failed")
    print("------------------------------------------------------------")
    print("  ⚠️  Could not establish LDAP connection")
    print("  • Anonymous bind may be disabled (good security practice)")
    print("  • Credentials may be incorrect")
    print("  • Server may be unreachable")
    print("  • LDAP/LDAPS ports may be filtered\n")
    logging.error("All connection attempts failed")
    sys.exit(1)

if __name__ == "__main__":
    main()
