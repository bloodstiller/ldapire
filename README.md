# LDAP Connection Script
This Python script attempts to connect to a Domain Controller (DC) using LDAP, first with SSL enabled and then, if SSL is not supported, it retries the connection without SSL. The script supports anonymous bind and can also authenticate with a username and password.

## Features
- SSL and Non-SSL Connection Attempts: The script initially attempts to connect using SSL. If that fails, it retries without SSL.
- Anonymous and Authenticated Bind: Supports both anonymous LDAP binds and authenticated binds with a username and password.
- Input Validation: Ensures that the IP address provided is in a valid format.
- Logging: Logs connection attempts, successes, and failures to ldap_test.log for troubleshooting.
- Secure Password Handling: Prompts for a password securely without echoing it to the console.

### Prerequisites
- Python 3.x
- ldap3 library (Install via pip: pip install ldap3)

### Usage
**Command-Line Arguments**
- dc_ip: The IP address of the Domain Controller.
- -u, --user: (Optional) Username for LDAP authentication.
- -p, --password: (Optional) Password for LDAP authentication.
**Example Command**
- `python3 ldap_connect.py 192.168.1.1 -u "DOMAIN\\username"`
  - If no password is provided via the -p option, the script will prompt you to securely enter the password.

**Example Command with Anonymous Bind**
- `python3 ldap_connect.py 192.168.1.1`

### Output
- The script will print whether the connection was successful or not.
- If successful, it will display the server's information.
- Logs are stored in ldap_test.log.

### Script Details
**Input Validation**
The script checks the validity of the provided IP address using a regular expression.

### Connection Attempts
- SSL Connection: The script first tries to connect using SSL.
- Non-SSL Connection: If the SSL connection fails, it retries without SSL.

### Logging
- Logs are created in `ldap_test.log`, capturing key events such as connection attempts, errors, and success messages.

### Error Handling
- The script handles common exceptions, such as connection errors, and provides feedback to the user. All exceptions are also logged.

### Contributing
- Contributions are welcome! Please open an issue or submit a pull request for any improvements or features you would like to add.

### License
- This project is licensed under the MIT License. 

