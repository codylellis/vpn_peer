### Instructions

0. Adjust 'secret' to be secret used between vpn peers. 
```
secret = 'secret'
```

1. Run script with path to CSV file. 
```
python3 vpn_peers.py [-h] [-d] -i /path/to/some/file.csv
```

2. Monitor script with provided tail command. 

3. If script fails, utilize del_vpn_config.sh to revert changes. 
You will have to run the script twice to delete group objects. 

4. Make sure to set gateways to community manually by copying commands. 
add_vpn_config.sh

### Example CSV File
```
CMA,Peer IP,Encryption Domain,FW Name,Community
12.1.12.1,1.9.1.9,192.168.9.0/24,TEST-GW-9,DNE-test-1
13.1.13.1,1.10.1.10,192.168.10.0/24,TEST-GW-10,DNE-test-2
```

### Paths
* Add Configuration: add_vpn_config.sh
* Delete Configuration: del_vpn_config.sh

### Notes
Configure IPSEC between Check Point Firewalls. 

### Scope
Check Point Software - MDM or SMS 

### Support
cellis@checkpoint.com
