# Active Directory Administration Scripts
This repository contains a collection of PowerShell scripts designed to automate and simplify the administration of Active Directory environments. These scripts are intended for IT administrators and system engineers who manage Windows Server infrastructures.

## Contents
- script.ps1 : Comprehensive deployment script that sets up a complete Active Directory environment including domain controller, users, groups, shared resources, GPOs, DHCP, and WSUS.
## Features
The scripts in this repository provide functionality for:

- Domain controller deployment and configuration
- User and group management
- Shared resource creation with proper permissions
- Group Policy implementation
- DHCP server configuration
- WSUS deployment and update management
- Bulk user creation from CSV files
## Requirements
- Windows Server 2016 or newer
- PowerShell 5.1 or newer
- Administrative privileges
- Active Directory module for PowerShell
- DHCP and WSUS server roles (for relevant scripts)
## Usage
### Domain Setup Script
The main deployment script ( script.ps1 ) can be run to set up a complete Active Directory environment:

```powershell
.\script.ps1
 ```

This script is idempotent - it checks for existing components before attempting installation, making it safe to run multiple times.

## Security Considerations
- The scripts contain default passwords that should be changed before use in production
- Review all scripts before execution in your environment
- Consider modifying security settings to match your organization's policies
## Contributing
Contributions to this repository are welcome. Please ensure that:

1. Scripts are well-documented with comments
2. Error handling is implemented
3. Scripts are tested in a non-production environment
4. A description of the script's purpose and functionality is included
## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer
These scripts are provided as-is with no warranty. Always test in a non-production environment before using in production.
