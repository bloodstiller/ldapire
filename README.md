# LDAPire LDAP Enumeration Tool

## Description

LDAPire is a comprehensive LDAP enumeration tool designed for Active Directory environments. It performs detailed enumeration of domain objects, including users, groups, and computers, with advanced handling of binary attributes and service account detection.

## Features

### Connection Handling
- SSL/TLS support with fallback to non-SSL
- Anonymous and authenticated bind support
- Secure credential handling

### Enumeration Capabilities
- Complete enumeration of:
  - Users
  - Groups
  - Computers
  - All domain objects
- Binary attribute conversion:
  - Security Identifiers (SIDs)
  - GUIDs
  - Exchange attributes
  - Other binary data

### Output Files
#### Basic Information
- `Users.txt`: User SAM account names
- `Groups.txt`: Group SAM account names
- `Computers.txt`: Computer SAM account names
- `Objects.txt`: All object SAM account names

#### Detailed Information
- `UsersDetailed.txt`: Comprehensive user attributes
- `GroupsDetailed.txt`: Comprehensive group attributes
- `ComputersDetailed.txt`: Comprehensive computer attributes
- `ObjectsDetailedLdap.txt`: All domain object details

#### Special Reports
- `AllObjectDescriptions.txt`: Consolidated descriptions from all objects
- `ServiceAccounts.txt`: Potential service accounts identified

## Console Output

The tool provides a clear, organized console output showing progress:

```
============================================================
                LDAP Information Retrieval
                  Domain Enumeration
============================================================

------------------------------------------------------------
 Processing Users
------------------------------------------------------------
  ✓ Basic user names    → Users.txt
  ✓ Detailed user info  → UsersDetailed.txt

------------------------------------------------------------
 Processing Groups
------------------------------------------------------------
  ✓ Basic group names   → Groups.txt
  ✓ Detailed group info → GroupsDetailed.txt

------------------------------------------------------------
 Processing Computers
------------------------------------------------------------
  ✓ Basic computer names    → Computers.txt
  ✓ Detailed computer info  → ComputersDetailed.txt

------------------------------------------------------------
 Processing All Objects
------------------------------------------------------------
  ✓ Basic object names     → Objects.txt
  ✓ Detailed object info   → ObjectsDetailedLdap.txt

------------------------------------------------------------
 Processing Descriptions
------------------------------------------------------------
  ✓ All object descriptions → AllObjectDescriptions.txt

------------------------------------------------------------
 Searching for Service Accounts
------------------------------------------------------------
  🔍 Searching Users.txt
  ✓ Found matches in Users.txt
  🔍 Searching UsersDetailed.txt
  ✓ Found matches in UsersDetailed.txt
  🔍 Searching Groups.txt
  - No matches in Groups.txt
  ✓ Service account findings written to ServiceAccounts.txt
  ✓ Found 5 potential matches

============================================================
                  Enumeration Complete!
============================================================
```

## Requirements

- Python 3.x
- ldap3 library

## Installation

1. Install Python 3.x
2. Install required library:
```bash
pip3 install ldap3
```

## Usage

Basic syntax:
```bash
python3 ldapire.py [DC_IP] [-u USERNAME] [-p PASSWORD]
```

Arguments:
- `DC_IP`: Domain Controller IP (required)
- `-u USERNAME`: Authentication username (optional)
- `-p PASSWORD`: Authentication password (optional)

Examples:
```bash
# Authenticated enumeration
python3 ldapire.py 192.168.1.1 -u "DOMAIN\\username" -p "password"

# Anonymous enumeration
python3 ldapire.py 192.168.1.1
```

## Output Format

### Basic Files
Contains one entry per line:
```
user1
user2
user3
```

### Detailed Files
Contains comprehensive attribute information:
```
DN: CN=User1,CN=Users,DC=domain,DC=local
objectSid: S-1-5-21-xxxxxxxxx
objectGUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
...
```

### Description File
Contains formatted object descriptions:
```
DN: CN=Object1,DC=domain,DC=local
Name: Object1
Object Class: user
Description: This is a description
```

### Service Accounts File
Contains potential service account findings with context:
```
=== Potential Service Accounts Found ===
--- Found in UsersDetailed.txt around line 45 ---
DN: CN=svc_backup,CN=Users,DC=domain,DC=local
...
```

## Security Features

### Anonymous Bind Detection
The tool automatically checks and reports if anonymous bind is enabled:
```
------------------------------------------------------------
 Security Check
------------------------------------------------------------
  ⚠️  WARNING: Anonymous Bind is ENABLED
  ⚠️  This is a security risk and should be disabled
```

### Service Account Detection
- Searches through all output files for potential service accounts
- Looks for common patterns: 'svc', 'service', 'srvc', 'svc_', 'service_'
- Provides context around matches for better analysis
- Consolidates findings in ServiceAccounts.txt

## Binary Data Handling

The tool properly formats various binary attributes:
- Security Identifiers (SIDs)
- GUIDs
- Exchange-specific attributes
- Other binary data types

## Error Handling

- Graceful handling of connection failures
- Proper handling of binary data conversion
- Fallback mechanisms for SSL/TLS connections
- Informative error messages for troubleshooting

## Best Practices

### Usage Recommendations
1. Always use authenticated access when possible
2. Run with minimal privileges necessary
3. Be mindful of network bandwidth and server load
4. Review output files for sensitive information

### Security Considerations
1. Avoid storing credentials in scripts
2. Use secure channels for transferring output files
3. Clean up output files after analysis
4. Monitor and log tool usage in sensitive environments

## Troubleshooting

Common issues and solutions:
1. Connection failures
   - Verify DC IP address
   - Check network connectivity
   - Ensure LDAP/LDAPS ports are accessible

2. Authentication issues
   - Verify username format (DOMAIN\username)
   - Check credential validity
   - Ensure user has appropriate permissions

3. Output issues
   - Check write permissions in output directory
   - Verify disk space availability
   - Ensure no file locks from other processes

## Future Enhancements

Planned features for future releases:
- Additional binary attribute handling
- Enhanced service account detection patterns
- Output in multiple formats (JSON, CSV)
- Integration with other security tools
- Custom attribute filtering options

## Security Note

This tool should only be used with proper authorization. Unauthorized LDAP enumeration may violate security policies or laws.

## Contributing

Contributions welcome! Please submit issues and pull requests via GitHub.

## License

MIT License

## Author

Bloodstiller

## Version History

- 2.0: Added comprehensive binary attribute handling, service account detection, and expanded output options
- 1.0: Initial release with basic LDAP enumeration
