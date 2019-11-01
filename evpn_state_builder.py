import yaml
import requests
import json
from cvplibrary import CVPGlobalVariables, GlobalVariableNames
from cvplibrary import Device

############################################################
######################Global Variables######################
############################################################
device_ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
username = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
password = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)

  
  
############################################################
#######################EVPN Variables#######################
############################################################
vrfs = { 
        'A': { 'vni': '50001', 'id': '1', 'nat_source_if': 'Loopback201', 'nat_ip': '201.0.0.2', 'nat_ip_mask': '/32'  },
        'B': { 'vni': '50002', 'id': '2', 'nat_source_if': 'Loopback202', 'nat_ip': '202.0.0.2', 'nat_ip_mask': '/32' },
}
vlans = { 
        '10': { 'name': 'ten', 'is_l3': True, 'vrf': 'A', 'ip': '10.10.10.1/24'},
        '20': { 'name': 'twenty', 'is_l3': True, 'vrf': 'A', 'ip': '20.20.20.1/24'},
        '30': { 'name': 'thirty', 'is_l3': True, 'vrf': 'A', 'ip': '30.30.30.1/24' },
        '40': { 'name': 'forty', 'is_l3': False },
        '50': { 'name': 'fifty', 'is_l3': False },
}
vlan_aware_bundles = { 
        'TENANT-A': { 'id': '1', 'vlan_list': '10,20,30' },
        'TENANT-B': { 'id': '2', 'vlan_list': '' },
        'L2': { 'id': '3', 'vlan_list': '40,50' },
}
############################################################
############################################################
############################################################

def get_device_info():
  #Get information for loopback0 and bgp
  cmd_list = ['enable', 'show interfaces loopback0', 'show ip bgp']
  device = Device(device_ip,username,password)
  device_info = device.runCmds(cmd_list)
  
  #Get Loopback IP from dictionary
  loopback_ip = device_info[1]['response']['interfaces']['Loopback0']['interfaceAddress'][0]['primaryIp']['address']
  
  #Get BGP AS from Dictionary
  bgp_as = device_info[2]['response']['vrfs']['default']['asn']
  
  return(loopback_ip,bgp_as)
  

def build_vlan_config():
  for vlan in vlans:
    vlan_info = vlans[vlan]
    print('vlan %s' % vlan)
    print(' name %s' % vlan_info['name'])
    print('!')
    
def build_vrfs():
  for vrf in vrfs:
    vrf_info = vrfs[vrf]
    print('vrf definition %s' % vrf)
    print('!')
    print('ip routing vrf %s' % vrf)
    print('!')
    # if 'nat_source_if' or 'nat_ip' or 'nat_ip_mask' in vrf_info:
    #   try:
    #     nat_ip = vrf_info['nat_ip']
    #   except:
    #     print('NAT IP Not Present for vrf: %s' % vrf)
    #   try:
    #     nat_source = vrf_info['nat_source_if']
    #   except:
    #     print('NAT Source Not Present for vrf: %s' % vrf)
    #   try:
    #     nat_ip_mask = vrf_info['nat_ip_mask']
    #   except:
    #     print('NAT IP MASK Not Present for vrf: %s' % vrf)
        
    #   print('interface %s' % nat_source)
    #   print(' vrf forwarding %s' % vrf)
    #   print(' ip address %s%s' % (nat_ip,nat_ip_mask))
    #   print('!')
    #   print('ip address virtual source-nat vrf %s address %s' % (vrf,nat_ip))
    #   print('!')

def build_svis():
  for vlan in vlans:
    vlan_info = vlans[vlan]
    if vlan_info['is_l3'] == True:
      print('interface vlan%s' % vlan)
      if 'vrf' in vlan_info:
        if 'ip' in vlan_info:
          print(' no autostate')
          print(' mtu 9214')
          print(' vrf forwarding %s' % vlan_info['vrf'])
          print(' ip address virtual %s' % vlan_info['ip'])
        else:
          print('Error: IP address not present for vlan: %s' % vlan)
      else:
        print('Error: VRF not present for vlan' % vlan)
    print('!')
    
def build_l3_vnis():
  print('interface vxlan1')
  for vrf in vrfs:
    vrf_info = vrfs[vrf]
    if 'vni' in vrf_info:
      print('vxlan vrf %s vni %s' % (vrf,vrf_info['vni']))
    else:
      print('VNI not present in vrf: %s' % vrf)
  print('!')
    
def build_vlan_aware_bundles(loopback_ip):
  for bundle in vlan_aware_bundles:
    bundle_info = vlan_aware_bundles[bundle]
    if 'id' in bundle_info:
      if 'vlan_list' in bundle_info:
        if bundle_info['vlan_list'] == '':
          bundle_id = bundle_info['id']
          print(' vlan-aware-bundle %s' % bundle)
          print('  rd %s:%s' % (loopback_ip,bundle_id))
          print('  route-target both %s:%s' % (bundle_id,bundle_id))
          print('  redistribute learned')
          print('!')
        else:
          bundle_id = bundle_info['id']
          print(' vlan-aware-bundle %s' % bundle)
          print('  rd %s:%s' % (loopback_ip,bundle_id))
          print('  route-target both %s:%s' % (bundle_id,bundle_id))
          print('  vlan %s' % bundle_info['vlan_list'])
          print('  redistribute learned')
          print('!')
      else:
        print('Vlan list not present in bundle: %s' % bundle)
    else:
      print('ID not present in bundle: %s' % bundle)

def build_ip_vrfs(loopback_ip):
  for vrf in vrfs:
    vrf_info = vrfs[vrf]
    if 'id' in vrf_info:
      vrf_id = vrf_info['id']
      print(' vrf %s' % vrf)
      print('  rd %s:%s' % (loopback_ip,vrf_id))
      print('  route-target import evpn %s:%s' % (vrf_id,vrf_id))
      print('  route-target export evpn %s:%s' % (vrf_id,vrf_id))
      print('  redistribute connected')
      print('!')
    else:
      print('ID not present in bundle: %s' % vrf)
      

def build_evpn_state(loopback_ip,bgp_as):
  print('router bgp %s' % bgp_as)
  build_vlan_aware_bundles(loopback_ip)
  build_ip_vrfs(loopback_ip)
    
def main():
  loopback_ip,bgp_as = get_device_info()
  build_vlan_config()
  print('!')
  build_vrfs()
  print('!')
  build_svis()
  build_l3_vnis()
  build_evpn_state(loopback_ip,bgp_as)
  
if __name__ == '__main__':
    main()
    