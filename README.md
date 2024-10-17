# LDAPire LDAP Enumeration Tool

## Description

LDAPire is designed to connect to an LDAP server (such as Active Directory), perform authentication, and enumerate users and groups. It attempts connections with and without SSL, supports both anonymous and authenticated binds, and outputs detailed information about users and groups to separate files.

## Features

- Attempts LDAP connection with SSL first, then without SSL if SSL fails
- Supports both anonymous and authenticated binds
- Authenticates with provided credentials
- Enumerates users and groups
- Outputs basic (sAMAccountName) and detailed information for both users and groups
- Input validation for IP address
- Secure password handling
- Comprehensive logging for troubleshooting

## Requirements

- Python 3.x
- python3-ldap library

## Installation

1. Ensure you have Python 3.x installed on your system.
2. Install the required library:

   ```
   sudo apt-get install python3-ldap
   ```

   Or if you're using pip:

   ```
   pip3 install python3-ldap
   ```

Note: The installation method may vary depending on your operating system and package manager. The above commands are typically used on Debian-based systems (like Ubuntu or Kali Linux).

## Usage

Run the script from the command line with the following syntax:

```
python3 pythonldap.py [DC_IP] [-u USERNAME] [-p PASSWORD]
```

- `[DC_IP]`: The IP address of the Domain Controller (required)
- `-u USERNAME`: The username for LDAP authentication (optional)
- `-p PASSWORD`: The password for LDAP authentication (optional)

If you don't provide a username or password, the script will attempt an anonymous bind.

Examples:
- Authenticated bind: `python3 pythonldap.py 192.168.1.1 -u "DOMAIN\\username"`
- Anonymous bind: `python3 pythonldap.py 192.168.1.1`

If no password is provided via the -p option, the script will prompt you to securely enter the password.

## Output Files

The script generates four output files:

1. `usersLdap.txt`: List of user sAMAccountNames
2. `usersLdap_detailed.txt`: Detailed information about each user
3. `groupsLdap.txt`: List of group sAMAccountNames
4. `groupsLdap_detailed.txt`: Detailed information about each group

## Logging

Logs are created in `ldap_test.log`, capturing key events such as connection attempts, errors, and success messages.

## Security Note

This script is intended for authorized use only. Ensure you have permission to perform LDAP queries on the target server before using this tool.

## Disclaimer

This tool is for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this program.

## Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or submit a pull request for any improvements or features you would like to add.

## License

This project is licensed under the MIT License.

## Author

Bloodstiller
