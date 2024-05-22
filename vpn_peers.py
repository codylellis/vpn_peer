import os
import csv
import sys
import time
import logging
import argparse
from argparse import RawTextHelpFormatter
import subprocess
import traceback

#PSK for external peers
global secret 
secret = ''

#filepaths
global gwpath,gwbin,gwout
gwpath = os.path.dirname(os.path.abspath(__file__))
gwbin = f'{gwpath}/scripts'
gwout = f'{gwpath}/output'

#configuration files
addconfig = []
delconfig = []


#logging
logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
            datefmt='%a, %d %b %Y %H:%M:%S',
            filename=f"{gwpath}/log.log",
            filemode='w')

class Log:
    @classmethod
    def debug(cls, msg):
        logging.debug(msg)

    @classmethod
    def info(cls, msg):
        logging.info(msg)

    @classmethod
    def error(cls, msg):
        logging.error(msg)
        

class vpn_peers: 
    
    def __init__(self):
        # Prepare Environment
        self.encdom = {}
        self.csvfile = []
        self.setup()
        self.configure()

    def setup(self): 
        self.args()
        self.mkdir()
        self.parse_csv()
        
    def configure(self): 
        self.create_networks()
        self.create_interoperable()
    
    
    def args(self): 
        parser = argparse.ArgumentParser(add_help=False,
            formatter_class=RawTextHelpFormatter, 
            prog=f'python3 {os.path.basename(__file__)}',
            description='Configure IPSEC Gateways',
            epilog=f'''
[Instructions]

1. Runs script with path to CSV file. 
# python3 vpn_peers.py [-h] [-d] -i /path/to/some/file.csv

2. Monitor script with provided tail command. 

3. If script fails, utilize del_vpn_config.sh to revert changes. 
You will have to run the script twice to delete group objects. 

4. Make sure to set gateways to community manually by copying commands. 
add_vpn_config.sh

[Example CSV File]
CMA,Peer IP,Encryption Domain,FW Name,Community
12.1.12.1,1.9.1.9,192.168.9.0/24,TEST-GW-9,DNE-test-1
13.1.13.1,1.10.1.10,192.168.10.0/24,TEST-GW-10,DNE-test-2

[Paths]
Main Path: {gwpath}
Script Output: {gwout}
Add Configuration: {gwout}/add_vpn_config.sh
Delete Configuration: {gwout}/del_vpn_config.sh
Note: Make sure to make file executable. 

[Notes]
Configure IPSEC between Check Point Firewalls. 

[Scope]
Check Point Software - MDM or SMS 

[Support]
cellis@checkpoint.com
''')
        
            
        # require filename
        parser.add_argument('-i', '--infile', type=argparse.FileType('r', encoding='UTF-8'), required=True)
        parser.add_argument('-d', '--debug', action='store_true') # enable debugging in logs
        parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='')
        arguments = vars(parser.parse_args())
        
        if arguments['debug']: 
            Log.debug("Debug Enabled")
            self.debug = 1
        else: 
            self.debug = 0 
        
        if arguments['infile']: 
            self.file = arguments['infile']
            Log.info(f'[File] : {self.file.name}')
        
        print(f'''\n[ Monitor progress in separate session ]\n
# tail -F {gwpath}/log.log''') 

    # make log directory / clear old log files
    def mkdir(self):

        if os.path.isdir(gwpath) and os.path.isdir(gwbin) and os.path.isdir(gwout):
            Log.info(f'[Make Directories]... Exists!\n')
        else:
            Log.info(f'[Make Directories]... Does not exist\n')
            os.system(f'mkdir -v {gwpath} {gwbin} {gwout}')
            
            
        # create bash scripts
    
    def runcmd(self, cmd, script):
        
        shell = '#!/bin/bash'
        cpprofile = '''source /etc/profile.d/CP.sh
source /etc/profile.d/vsenv.sh
source $MDSDIR/scripts/MDSprofile.sh
source $MDS_SYSTEM/shared/mds_environment_utils.sh
source $MDS_SYSTEM/shared/sh_utilities.sh
'''
        script = f'{gwbin}/{script}'
        bash=f"""{shell} 
{cpprofile} 

{cmd} 
exit 0
"""

        if self.debug == 1:
            Log.debug(f'''[ contents ]\n{bash}\n[ script]\n{script}''')

        with open(script, 'w') as f: 
            f.write(bash)

        os.system(f"chmod +x {script}")
        
        try:
            response = subprocess.check_output(script, shell=True, text=True, timeout=60)
            if response is not None:
                cmdout = response
            else: 
                return
        except subprocess.TimeoutExpired as e:
            Log.error(traceback.print_exc())
            Log.error(f"[runcmd] : Error : {e}")

        if self.debug == 1: 
            Log.debug(f"[runcmd]\n{cmdout}\n\n")
        
        return cmdout


    def parse_csv(self): 
        input_file = csv.DictReader(self.file)

        for row in input_file:
            if row['Encryption Domain']: 
                row['Encryption Domain'] = row['Encryption Domain'].split('\n')
                self.csvfile.append(row)

        if self.debug == 1: 
            Log.debug(f'[CSV File]\n{self.csvfile}')
        Log.info(f"[Parse CSV]... Done")
    
    
    def create_network_group(self, name, netgroup):
        # Called by create_networks to create network group of networks. 
        try:
            for x,y in netgroup.items():
                # add group
                cmd = f'mgmt_cli -r true -d {x} add group name {name}'
                Log.info(f'[Add Network Groups] : {cmd}')
                self.runcmd(cmd, f'{name}_add_group.sh')
                #append to configuration files
                addconfig.append(cmd + "\n")
                delcmd = f'mgmt_cli -r true -d {x} delete group name {name} ignore-errors true'
                delconfig.append(delcmd + "\n")
                for net in y: 
                    # set members of group
                    cmd = f'mgmt_cli -r true -d {x} set group name {name} members.add {net}'
                    Log.info(f'[Set Network Groups] : {cmd}')
                    self.runcmd(cmd, f'{name}_set_group.sh')


        except Exception as e:
            Log.error(f'[Create Network Group] : {e}')
            Log.error(traceback.print_exc())
    
    
    def create_networks(self):
        try:
            for item in self.csvfile: 
                # skip incomplete entries
                if item['FW Name'] == None: 
                    Log.info(f'[Pass] : No FW Name')
                    pass
                else:
                    netgroup = {}
                    netgroup[item['CMA']] = []
                    
                    for net in item['Encryption Domain']:
                        #  parse encryption domain and create groupname
                        netname = f"{item['FW Name'].strip('FW_')}_{net}".replace(' ', '')
                        groupname = f"{item['FW Name'].strip('FW_')}_Encrypt".replace(' ','')
                        netlist = net.split('/')
                        #add network name
                        cmd = f'''mgmt_cli -r true -d {item['CMA']} add network name {netname} subnet4 {netlist[0]} mask-length4 {netlist[1]}'''
                        Log.info(f'[Create Networks] : {cmd}')
                        self.runcmd(cmd, f'''{item['CMA']}_add_net_{netlist[0]}-{netlist[1]}.sh'''.replace(' ',''))
                        #append to configuration files
                        addconfig.append(cmd + "\n")
                        delcmd = f"mgmt_cli -r true -d {item['CMA']} delete network name {netname} ignore-errors true"
                        delconfig.append(delcmd + "\n")
                        #CMA to encryption domain mapping
                        netgroup[item['CMA']].append(netname)
                    
                    #build encryption domain to groupname mapping
                    self.encdom[item['FW Name']] = groupname
                    if self.debug == 1: 
                        Log.debug(f'[Encryption Domain]\n{self.encdom}')
                    #send list of networks to create network group
                    self.create_network_group(groupname, netgroup)



        except Exception as e: 
            Log.error(f'[Create Networks] : {e}')
            Log.error(traceback.print_exc())
            
            
    def create_interoperable(self): 
        try: 
            for item in self.csvfile: 
                # add interoperable device 
                Log.info(f"[Create Interoperable] : {item['FW Name']} : {self.encdom[item['FW Name']]}")
                cmd = f'''mgmt_cli -r true -d {item['CMA']} add interoperable-device name {item['FW Name']} ip-address {item['Peer IP']} vpn-settings.vpn-domain {self.encdom[item['FW Name']]} vpn-settings.vpn-domain-type manual'''
                self.runcmd(cmd, f"{item['FW Name']}_add_interoperable.sh".replace(' ',''))
                #append to configuration files
                addconfig.append(cmd + "\n")
                delcmd = f"mgmt_cli -r true -d {item['CMA']} delete interoperable-device name {item['FW Name']} ignore-errors true"
                delconfig.append(delcmd + "\n")
                self.star_community(item['FW Name'], item['CMA'], item['Community'])
        except Exception as e: 
            Log.error(f'[Create Interoperable] : {e}')
            Log.error(traceback.print_exc())
            
            
    def star_community(self, fw, domain, vpncommunity):
        try:
            # add vpn community
            Log.info(f'[Add Community] : {domain} : {vpncommunity}')
            cmd = f'''mgmt_cli -r true -d {domain} add vpn-community-star name {vpncommunity} use-shared-secret true'''
            self.runcmd(cmd, f"add_star_community_{domain}_{vpncommunity}.sh".replace(' ',''))
            #append to configuration files
            addconfig.append(cmd + "\n")
            delcmd = f"mgmt_cli -r true -d {domain} delete vpn-community-star name {vpncommunity} ignore-errors true"
            delconfig.append(delcmd + "\n")
        
            #set vpn community
            Log.info(f'[Set Community] : {domain} : {vpncommunity} : {fw}')
            cmd = f'''mgmt_cli -r true -d {domain} set vpn-community-star name {vpncommunity} satellite-gateways.add {fw} shared-secrets.add.1.external-gateway {fw} shared-secrets.add.1.shared-secret "{secret}"'''
            self.runcmd(cmd, f"set_star_community_{domain}_{vpncommunity}_{fw}.sh".replace(' ',''))
            addconfig.append(cmd + "\n")
        except Exception as e: 
            Log.error(f'[Star Community] : {e}')
            Log.error(traceback.print_exc())


def cleanup():
    # remove undeleted tmp scripts
    os.system(f"rm {gwbin}/*")
    

# script exit 
def end(): 
    sys.exit(0)
    
    
def create_configs(): 
    with open(f'{gwout}/add_vpn_config.sh', 'w') as a, open(f'{gwout}/del_vpn_config.sh', 'w') as d: 
        a.writelines(addconfig)
        d.writelines(delconfig)
        
        
def main(): 
    
    start = vpn_peers()


if __name__ == "__main__": 
    try:
        starttime = time.time()
        main()
    except Exception as e:
        Log.error(e)
        Log.error(traceback.format_exc())
    finally:
        endtime = time.time()
        totaltime = endtime - starttime
        Log.info(f"\n Total Run Time : {totaltime} seconds")
        create_configs()
        cleanup() 
        end()