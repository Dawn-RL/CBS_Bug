

from cyberbattle.simulation.model_pivot import Identifiers, NodeID, CredentialID, PortName, FirewallConfiguration, FirewallRule, RulePermission
import numpy as np
import networkx as nx
from cyberbattle.simulation import model_pivot as m
import random
from typing import List, Optional, Tuple, DefaultDict

from collections import defaultdict


ENV_IDENTIFIERS = Identifiers(
    properties=[
        'breach_node'
    ],
  
    ports=['SMB', 'RDP', 'HTTP'],
    
    local_vulnerabilities=[
        'ScanWindowsCredentialManagerForRDP',
        'ScanWindowsExplorerRecentFiles',
        'ScanWindowsCredentialManagerForSMB',
        'Knows_on_capture'
        
    ],
    
    remote_vulnerabilities=[
        'Traceroute',
    ],

)

def cyberbattle_model_from_traffic_graph(
    traffic_graph: nx.DiGraph,
    cached_smb_password_probability=0.75,
    cached_rdp_password_probability=0.8,
    cached_accessed_network_shares_probability=0.6,
    cached_password_has_changed_probability=0.1,
    traceroute_discovery_probability=0.5,
    probability_two_nodes_use_same_password_to_access_given_resource=0.8
) -> nx.DiGraph:
    """Generate a random CyberBattle network model from a specified traffic (directed multi) graph.
    The input graph can for instance be generated with `generate_random_traffic_network`.
    Each edge of the input graph indicates that a communication took place
    between the two nodes with the protocol specified in the edge label.
    Returns a CyberBattle network with the same nodes and implanted vulnerabilities
    to be used to instantiate a CyverBattleSim gym.
    Arguments:
    cached_smb_password_probability, cached_rdp_password_probability:
        probability that a password used for authenticated traffic was cached by the OS for SMB and RDP
    cached_accessed_network_shares_probability:
        probability that a network share accessed by the system was cached by the OS
    cached_password_has_changed_probability:
        probability that a given password cached on a node has been rotated on the target node
        (typically low has people tend to change their password infrequently)
    probability_two_nodes_use_same_password_to_access_given_resource:
        as the variable name says
    traceroute_discovery_probability:
        probability that a target node of an SMB/RDP connection get exposed by a traceroute attack
    """
    # convert node IDs to string
    graph = nx.relabel_nodes(traffic_graph, {i: str(i) for i in traffic_graph.nodes})

    password_counter: int = 0

    def generate_password() -> CredentialID:
        nonlocal password_counter
        password_counter = password_counter + 1
        return f'unique_pwd{password_counter}'

    def traffic_targets(source_node: NodeID, protocol: str) -> List[NodeID]:
        neighbors = [t for (s, t) in graph.edges()
                     if s == source_node and protocol in graph.edges[(s, t)]['protocol']]
        return neighbors

    # Map (node, port name) -> assigned pwd
    assigned_passwords: DefaultDict[Tuple[NodeID, PortName],
                                    List[CredentialID]] = defaultdict(list)

    def assign_new_valid_password(node: NodeID, port: PortName) -> CredentialID:
        pwd = generate_password()
        assigned_passwords[node, port].append(pwd)
        return pwd

    def reuse_valid_password(node: NodeID, port: PortName) -> CredentialID:
        """Reuse a password already assigned to that node an port, if none is already
         assigned create and assign a new valid password"""
        if (node, port) not in assigned_passwords:
            return assign_new_valid_password(node, port)

        # reuse any of the existing assigne valid password for that node/port
        return random.choice(assigned_passwords[node, port])

    def create_cached_credential(node: NodeID, port: PortName) -> CredentialID:
        if random.random() < cached_password_has_changed_probability:
            # generate a new invalid password
            return generate_password()
        else:
            if random.random() < probability_two_nodes_use_same_password_to_access_given_resource:
                return reuse_valid_password(node, port)
            else:
                return assign_new_valid_password(node, port)

    def add_leak_neighbors_vulnerability(
            node_id: m.NodeID,
            library: m.VulnerabilityLibrary = {}) -> m.VulnerabilityLibrary:
        """Create random vulnerabilities
        that reveals immediate traffic neighbors from a given node"""

        # BUG FIX - Thanks to Git: SherdenCooper for raising the issue
        library = None
        if library is None:
            library = {}

        rdp_neighbors = traffic_targets(node_id, 'RDP')

        if len(rdp_neighbors) > 0:
            library['ScanWindowsCredentialManagerForRDP'] = m.VulnerabilityInfo(
                description="Look for RDP credentials in the Windows Credential Manager",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node=target_node, port='RDP',
                                       credential=create_cached_credential(target_node, 'RDP'))
                    for target_node in rdp_neighbors
                    if random.random() < cached_rdp_password_probability
                ]),
                reward_string="Discovered creds in the Windows Credential Manager",
                cost=2.0
            )

        smb_neighbors = traffic_targets(node_id, 'SMB')

        if len(smb_neighbors) > 0:
            library['ScanWindowsExplorerRecentFiles'] = m.VulnerabilityInfo(
                description="Look for network shares in the Windows Explorer Recent files",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(
                    [target_node
                     for target_node in smb_neighbors
                     if random.random() < cached_accessed_network_shares_probability
                     ]
                ),
                reward_string="Windows Explorer Recent Files revealed network shares",
                cost=1.0
            )

            library['ScanWindowsCredentialManagerForSMB'] = m.VulnerabilityInfo(
                description="Look for network credentials in the Windows Credential Manager",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node=target_node, port='SMB',
                                       credential=create_cached_credential(target_node, 'SMB'))
                    for target_node in smb_neighbors
                    if random.random() < cached_smb_password_probability
                ]),
                reward_string="Discovered SMB creds in the Windows Credential Manager",
                cost=2.0
            )

        if len(smb_neighbors) > 0 and len(rdp_neighbors) > 0:
            library['Traceroute'] = m.VulnerabilityInfo(
                description="Attempt to discvover network nodes using Traceroute",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(
                    [target_node
                     for target_node in smb_neighbors or rdp_neighbors
                     if random.random() < traceroute_discovery_probability
                     ]
                ),
                reward_string="Discovered new network nodes via traceroute",
                cost=5.0
            )
      

 


        knows_neighbors = traffic_targets(node_id, 'Knows_on_capture')

        if len(knows_neighbors) > 0:
            library['Knows_on_capture'] = m.VulnerabilityInfo(
                description="Attempt to discover human employee associated with node",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedGuyId([target_node for target_node in knows_neighbors])
                ,
                
                reward_string="Discovered new entity - Human",
                cost=5.0
            )
            

        return library

    def create_vulnerabilities_from_traffic_data(node_id: m.NodeID):
        return add_leak_neighbors_vulnerability(node_id=node_id)

    firewall_conf = FirewallConfiguration(
        [FirewallRule("RDP", RulePermission.ALLOW), FirewallRule("SMB", RulePermission.ALLOW)],

        [FirewallRule("RDP", RulePermission.ALLOW), FirewallRule("SMB", RulePermission.ALLOW)])

    firewall_conf_deny = FirewallConfiguration(
        [FirewallRule("RDP", RulePermission.BLOCK), FirewallRule("SMB", RulePermission.BLOCK), FirewallRule("HTTP", RulePermission.BLOCK)],
        [FirewallRule("RDP", RulePermission.BLOCK), FirewallRule("SMB", RulePermission.BLOCK), FirewallRule("HTTP", RulePermission.BLOCK)])

    # Pick a random node as the agent entry node
    entry_node_index = random.randrange(len(graph.nodes))
    entry_node_id, entry_node_data = list(graph.nodes(data=True))[entry_node_index]
    graph.nodes[entry_node_id].clear()
    graph.nodes[entry_node_id].update(
        {'data': m.NodeInfo(services=[],
                            value=0,
                            properties=["breach_node"],
                            vulnerabilities=create_vulnerabilities_from_traffic_data(entry_node_id),
                            agent_installed=True,
                            firewall=firewall_conf,
                            reimagable=False)})

    def create_node_data(node_id: m.NodeID):
        return m.NodeInfo(
            services=[m.ListeningService(name=port, allowedCredentials=assigned_passwords[(target_node, port)])
                      for (target_node, port) in assigned_passwords.keys()
                      if target_node == node_id
                      ],
            value=random.randint(0, 100),
            vulnerabilities=create_vulnerabilities_from_traffic_data(node_id),
            agent_installed=False,
            firewall=firewall_conf
        )

    def create_node_data_two(node_id: m.NodeID):
        return m.NodeInfo(
            services=[m.ListeningService(name=port, allowedCredentials=assigned_passwords[(target_node, port)])
                      for (target_node, port) in assigned_passwords.keys()
                      if target_node == node_id
                      ],
            value=random.randint(0, 100),
            vulnerabilities=create_vulnerabilities_from_traffic_data(node_id),
            agent_installed=False,
            firewall=firewall_conf_deny
        )
    j: int = 0
    for node in list(graph.nodes):
        
       # print(j)
        if j < 15:
            if node != entry_node_id:
 
                
                graph.nodes[node].clear()
                graph.nodes[node].update({'data': create_node_data(node)})
        else:
            if node != entry_node_id:
                 graph.nodes[node].clear()
                 graph.nodes[node].update({'data': create_node_data_two(node)}) 
        
        j += 1
       
    return graph


def new_environment(n_servers_per_protocol: int):
    """Create a new simulation environment based on
    a randomly generated network topology.
    NOTE: the probabilities and parameter values used
    here for the statistical generative model
    were arbirarily picked. We recommend exploring different values for those parameters.
    """
#    traffic = generate_random_traffic_network(seed=None,
#                                              n_clients=50,
#                                              n_servers={
#                                                  "SMB": n_servers_per_protocol,
#                                                  "HTTP": n_servers_per_protocol,
#                                                  "RDP": n_servers_per_protocol,
#                                              },
#                                              alpha=[(1, 1), (0.2, 0.5)],
#                                              beta=[(1000, 10), (10, 100)])
#


    protocols = ['HTTP', 'SMB', 'RDP']

    edges_labels = defaultdict(set)

    for protocol in protocols:
    
        h = nx.fast_gnp_random_graph(15, 
                                     0.5, 
                                     seed     = None, 
                                     directed = True
                                     )
        for edge in h.edges:
        
            edges_labels[edge].add(protocol)


    h1 = nx.fast_gnp_random_graph(15, 
                                   0, 
                                   seed     = 1, 
                                   directed = True 
                                   )
    i          : int = 0
    num_players: int = 3
    
    node_list = random.sample(h1.nodes, num_players)
    
    for comp_Nodes in node_list:
        
        next_node: int = 15 + i
        last_node: int = 15 + len(node_list) + i
            
        h1.add_node( next_node )
        h1.add_node( last_node )
        
        # Add pivot
        h1.add_edge(comp_Nodes, next_node)
        edges_labels[(comp_Nodes, next_node)].add('Knows_on_capture')
   
        h1.add_edge(next_node, last_node)
        edges_labels[(next_node, last_node)].add('Bad')

        
        i += 1 

    traffic = nx.DiGraph()

    for (u, v), port in list(edges_labels.items()):
    
        traffic.add_edge(u, 
                         v, 
                         protocol = port)  
 
    colour_map = []

    for (u,v), proto in list(edges_labels.items()):

        if len(proto) == 1 and 'HTTP' in proto:
            col = 'blue'
        elif len(proto) == 1 and 'RDP' in proto:
            col = 'red'
        elif len(proto) == 1 and 'SMB' in proto:
            col = 'green'
        elif 'VPN' in proto:
            col = 'pink'
        elif 'Bad' in proto:
            col = 'orange'
        elif len(proto) == 2:
            col = 'purple'
        else:
            col = 'black'
    
        colour_map.append(col)

    nx.draw_networkx(traffic, 
                 edge_color = colour_map,
                 node_size   = 15200,
                 arrowstyle  = '->',
                 arrowsize   = 80,
                 font_size   = 40,
                 font_weight = "bold",
                 )

    

    network = cyberbattle_model_from_traffic_graph(
        traffic,
        cached_rdp_password_probability=0.8,
        cached_smb_password_probability=0.7,
        cached_accessed_network_shares_probability=0.8,
        cached_password_has_changed_probability=0.01,
        probability_two_nodes_use_same_password_to_access_given_resource=0.9)

    return m.Environment(network=network,
                         vulnerability_library=dict([]),
                         identifiers=ENV_IDENTIFIERS)
