#cvp_port from cvplibrary import CVPGlobalVariables, GlobalVariableNames
#cvp_port from cvplibrary import Device
import requests
import urllib3
import json
import yaml
import jinja2
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#python only
import jsonrpclib
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

###################Define Global Variables###################
username = 'cvpadmin'
password = 'arista'
cvp_server = '10.0.0.14'
api_headers = {
    'Content-Type': "application/json",
    'cache-control': "no-cache",
    }
api_root = 'https://{0}/web'.format(cvp_server)
#cvp_port device_ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
device_ip = '10.255.255.202'
client_url = 'https://{0}:{1}@{2}/command-api'.format(username,password,device_ip)
client = jsonrpclib.Server(client_url)
#############################################################

class switch():
    def __init__(self,dc_inventory):
    
        for dc in dc_inventory:
            if dc != 'global':
                self.datacenter = dc_inventory[dc]
                
                #Spines
                for spine in self.datacenter['spines']:
                    self.device = self.datacenter['spines'][spine]
                    if device_ip == self.device['device_ip']:
                        self.bgp_as =  self.datacenter['bgp_as_start']
                        self.id = self.device['device_id']
                        self.bgp_password = dc_inventory['global']['bgp_password']
                        self.loopback_ip = '10.' + str(self.datacenter['id']) + '.0.' + str(self.device['device_id'])
                        self.overlay_listen_range = '10.' + str(self.datacenter['id']) + '.0.' + '0/24'
                        self.device_type = 'spine'
                        self.dc_id = self.datacenter['id']
                        self.device_name = spine
                        self.device_ip = self.device['device_ip']
                        self.device_dc = dc
                        self.bgp_as_start = self.datacenter['bgp_as_start']

                #Leafs
                for leaf_pair in self.datacenter['leafs']:
                    for leaf in self.datacenter['leafs'][leaf_pair]:
                        self.device = self.datacenter['leafs'][leaf_pair][leaf]
                        if device_ip == self.device['device_ip']:
                            self.bgp_as = '65' + str(leaf_pair)
                            self.id = self.device['device_id']
                            self.bgp_password =  dc_inventory['global']['bgp_password']
                            self.loopback_ip = '10.' + str(self.datacenter['id']) + '.0.' + str(self.device['device_id'])
                            self.device_type = 'leaf'
                            self.dc_id = self.datacenter['id']
                            self.device_name = leaf
                            self.device_ip = self.device['device_ip']
                            self.device_dc = dc
                            self.mlag_id = self.device['mlag_id']
                            self.leaf_pair = leaf_pair
                            self.bgp_as_start = self.datacenter['bgp_as_start']
                            self.vtep_ip = '10.' + str(self.datacenter['id']) + '.255.' + str(leaf_pair)
                    

def authenticate():

    url_path = api_root+'/login/authenticate.do'
    payload = { "userId": username,
                "password" : password
    }

    response = requests.request('POST', url_path, data=json.dumps(payload), headers=api_headers, verify=False)
    return(response.cookies)

def get_dc_inventory(auth_info):
    vars_path = 'dc_inventory.yaml'
    url_path = api_root+"/configlet/getConfigletByName.do?name=%s" % vars_path
    response = requests.request('GET', url_path, headers=api_headers, cookies=auth_info, verify=False)
    inventory = yaml.safe_load(json.loads(response.content)['config'])
    return(inventory)
    
def get_lldp_neighbors():
    #Get lldp neighbors
    lldp_interface_dict = {}
    cmd_list = ['enable', 'show lldp neighbors detail']
    #cvp_port   device = Device(device_ip,username,password)
    #cvp_port   lldp_neighbors = device.runCmds(cmd_list)[1]['response']['lldpNeighbors']
    lldp_neighbors = client.runCmds(1, cmd_list)[1]['lldpNeighbors']
  
    for interface in lldp_neighbors:
        if interface != 'Management1':
            neighbor_info = lldp_neighbors[interface]['lldpNeighborInfo']
            for neighbor in neighbor_info:
                neighbor_ip = neighbor['managementAddresses'][0]['address']
                lldp_interface_dict[interface] = neighbor_ip
        
    return(lldp_interface_dict)
      

def get_point_to_point_links_spines(lldp_neighbors, dc_inventory, device_variables):
  point_to_point_links = {}
  for interface in lldp_neighbors:
    for leaf_pair in dc_inventory[device_variables['device_dc']]['leafs']:
      for leaf in dc_inventory[device_variables['device_dc']]['leafs'][leaf_pair]:
        if dc_inventory[device_variables['device_dc']]['leafs'][leaf_pair][leaf]['device_ip'] == lldp_neighbors[interface]:
          leaf_id = dc_inventory[device_variables['device_dc']]['leafs'][leaf_pair][leaf]['device_id']
          spine_id = device_variables['id']
          point_to_point_links[interface] = '10.%s.%s.0/31' % (spine_id, leaf_id)
  return(point_to_point_links)
  
def get_point_to_point_links_leafs(lldp_neighbors, dc_inventory, device_variables):
  point_to_point_links = {}
  for interface in lldp_neighbors:
    for spine in dc_inventory[device_variables['device_dc']]['spines']:
      if dc_inventory[device_variables['device_dc']]['spines'][spine]['device_ip'] == lldp_neighbors[interface]:
        spine_id = dc_inventory[device_variables['device_dc']]['spines'][spine]['device_id']
        leaf_id = device_variables['id']
        point_to_point_links[interface] = '10.%s.%s.1/31' % (spine_id, leaf_id)
  return(point_to_point_links)
  
def get_bgp_underlay_neighbors(device_variables):
  bgp_neighbors = []
  for interface in device_variables['point_to_point_links']:
    bgp_neighbors.append(device_variables['point_to_point_links'][interface][:-4] + '0')
  return(bgp_neighbors)
  
def get_bgp_overlay_neighbors(device_variables, dc_inventory):
  bgp_neighbors = []
  for spine in dc_inventory[device_variables['device_dc']]['spines']:
    neighbor = '10.' + str(dc_inventory[device_variables['device_dc']]['id']) + '.0.' + str(dc_inventory[device_variables['device_dc']]['spines'][spine]['device_id'])
    bgp_neighbors.append(neighbor)
    
  return(bgp_neighbors)

def get_mlag_port_channel_interfaces(lldp_neighbors, device_variables, dc_inventory):
  ports = []
  for neighbor in lldp_neighbors:
    # print(dc_inventory[device_variables['device_dc']]['leafs'][device_variables['leaf_pair']])
    for leaf in dc_inventory[device_variables['device_dc']]['leafs'][device_variables['leaf_pair']]:
      if dc_inventory[device_variables['device_dc']]['leafs'][device_variables['leaf_pair']][leaf]['device_ip'] == lldp_neighbors[neighbor]:
        ports.append(neighbor)
  return(ports)

def get_mlag_info(device_variables):
  domain_id = device_variables['leaf_pair']
  if device_variables['mlag_id'] == 1:
    peer_address = '192.168.255.255'
    local_address = '192.168.255.254'
    bgp_peer_address = '192.168.254.255'
    bgp_local_address = '192.168.254.254'
  
  elif device_variables['mlag_id'] == 2:
    peer_address = '192.168.255.254'
    local_address = '192.168.255.255'
    bgp_peer_address = '192.168.254.254'
    bgp_local_address = '192.168.254.255'
    
  mlag_info = {'domain_id': domain_id,
               'peer_address': peer_address,
               'local_address': local_address,
               'bgp_peer_address': bgp_peer_address,
               'bgp_local_address': bgp_local_address,
              }
  
  return(mlag_info)



def render_config_template(device_variables, auth_info):
    template = get_jinja_template(device_variables, auth_info)
    env = jinja2.Environment(
        loader=jinja2.BaseLoader(),
        trim_blocks=True,
        extensions=['jinja2.ext.do'])
    templategen = env.from_string(template)
    if templategen:
        config = templategen.render(device_variables)
        return(config)
    return(None)

def get_jinja_template(device_variables, auth_info):
    if device_variables['device_type'] == 'spine':
        template_path = './jinja/EVPN_Auto_Build_Spine_Template.j2'
    elif device_variables['device_type'] == 'leaf':
        template_path = './jinja/EVPN_Auto_Build_Leaf_Template.j2'
    with open(template_path, 'r') as template_file:
        template = template_file.read()
    return(template)


def check_configlet(device_variables, auth_info):
    configlet = '%s_EVPN_BUILD' % device_variables['device_name']
    url_path = api_root+"/configlet/getConfiglets.do?startIndex=0&endIndex=0"
    response = requests.request('GET', url_path, headers=api_headers, cookies=auth_info, verify=False)
    configlet_data = json.loads(response.content)['data']
    configlet_found = False
    for item in configlet_data:
        if item['name'] == configlet:
            configlet_found = True

    if configlet_found:
        return(True)
    else:
        return(False)

def update_configlet(configuration, configlet_info, auth_info):
    url_path = api_root+"/configlet/updateConfiglet.do"
    payload = {
                "config": configuration,
                "key": configlet_info['key'],
                "name": configlet_info['name'],
                "waitForTaskIds": True,
                "reconciled": False
    }
    response = requests.request('POST', url_path, data=json.dumps(payload), headers=api_headers, cookies=auth_info, verify=False)


def create_configlet(device_variables, configuration, auth_info):
    url_path = api_root+"/configlet/addConfiglet.do"
    configlet_name = '%s_EVPN_BUILD' % device_variables['device_name']
    payload = { 'config': configuration,
             'name': configlet_name
    }
    response = requests.request('POST', url_path, data=json.dumps(payload), headers=api_headers, cookies=auth_info, verify=False)
    
def get_device_info(device_variables, auth_info):
  url_path = api_root+'/inventory/devices'
  response = requests.request('GET', url_path, headers=api_headers, cookies=auth_info, verify=False)
  devices = json.loads(response.content)
  for device in devices:
      if device['ipAddress'] == device_variables['device_ip']:
        return(device)

def get_configlet_info(device_variables, auth_info):
    configlet = '%s_EVPN_BUILD' % device_variables['device_name']
    url_path = api_root+"/configlet/getConfiglets.do?startIndex=0&endIndex=0"
    response = requests.request('GET', url_path, headers=api_headers, cookies=auth_info, verify=False)
    configlet_data = json.loads(response.content)['data']

    for item in configlet_data:
        if item['name'] == configlet:
            return(item)


def get_current_configlets(device_info, auth_info, start=0, end=0):
    url_path = api_root+'/provisioning/getConfigletsByNetElementId.do?netElementId=%s&queryParam=&startIndex=%d&endIndex=%d' % (device_info['systemMacAddress'], start, end)
    response = requests.request('GET', url=url_path, headers=api_headers, cookies=auth_info, verify=False)
    return(json.loads(response.content)['configletList'])



def apply_configlet_to_device(device_variables, device_info, configlet_info, current_configlets, auth_info):
    url_path = api_root+'/provisioning/addTempAction.do?format=topology&queryParam=&nodeId=root'
    
    ################API Data################
    #Configlet List
    configlet_list = []
    configlet_key_list = []
    for configlet in current_configlets:
        configlet_list.append(configlet['name'])
        configlet_key_list.append(configlet['key'])
    configlet_list.append(configlet_info['name'])
    configlet_key_list.append(configlet_info['key'])

    #Information
    configlet_name = '%s_EVPN_BUILD' % device_variables['device_name']
    info = 'Assign Configlet {0}: to Device {1}'.format(configlet_name, device_info['fqdn'])
    info_preview = '<b>Assign Configlet {0}: to Device {1}</b>'.format(configlet_name, device_info['fqdn'])



    payload = json.dumps({'data': [{'info': info,
                    'infoPreview': info_preview,
                    'note': '',
                    'action': 'associate',
                    'nodeType': 'configlet',
                    'nodeId': '',
                    'configletList': configlet_key_list,
                    'configletNamesList': configlet_list,
                    'ignoreConfigletNamesList': [],
                    'ignoreConfigletList': [],
                    'configletBuilderList': [],
                    'configletBuilderNamesList': [],
                    'ignoreConfigletBuilderList': [],
                    'ignoreConfigletBuilderNamesList': [],
                    'toId': device_info['systemMacAddress'],
                    'toIdType': 'netelement',
                    'fromId': '',
                    'nodeName': '',
                    'fromName': '',
                    'toName': device_info['fqdn'],
                    'nodeIpAddress': device_info['ipAddress'],
                    'nodeTargetIpAddress': device_info['ipAddress'],
                    'childTasks': [],
                    'parentTask': ''}]})

    response = requests.request('POST', url_path, headers=api_headers, data=payload, cookies=auth_info, verify=False)

def save_topology(auth_info):
  url_path = api_root+'/provisioning/saveTopology.do'
  data = '[]'
  response = requests.request('POST', url_path, data=data, headers=api_headers, cookies=auth_info, verify=False)

def main():

    auth_info = authenticate()
    dc_inventory = get_dc_inventory(auth_info)
    device_variables = vars(switch(dc_inventory))
    lldp_neighbors = get_lldp_neighbors()
    if device_variables['device_type'] == 'spine':
      device_variables['point_to_point_links'] = get_point_to_point_links_spines(lldp_neighbors, dc_inventory, device_variables)
    elif device_variables['device_type'] == 'leaf':
      device_variables['point_to_point_links'] = get_point_to_point_links_leafs(lldp_neighbors, dc_inventory, device_variables)
      device_variables['bgp_underlay_neighbors'] = get_bgp_underlay_neighbors(device_variables)
      device_variables['bgp_overlay_neighbors'] = get_bgp_overlay_neighbors(device_variables, dc_inventory)
      device_variables['mlag_port_channel_ports'] = get_mlag_port_channel_interfaces(lldp_neighbors, device_variables, dc_inventory)
      device_variables['mlag_info'] = get_mlag_info(device_variables)
    configuration = render_config_template(device_variables, auth_info)
    configlet_exists = check_configlet(device_variables, auth_info)
    if configlet_exists:
        print(configuration)
        # configlet_info = get_configlet_info(device_variables, auth_info)
        # update_configlet(configuration, configlet_info, auth_info)
    else:
        print(configuration)
    #     create_configlet(device_variables, configuration, auth_info)
    #     device_info = get_device_info(device_variables, auth_info)
    #     configlet_info = get_configlet_info(device_variables, auth_info)
    #     current_configlets = get_current_configlets(device_info, auth_info)
    #     apply_configlet_to_device(device_variables, device_info, configlet_info, current_configlets, auth_info)
    #     save_topology(auth_info)


                
if __name__ == '__main__':
    main()