# CBS_Bug
Repo to validate CBS bug 

Changelog

CommandControl_pivot.py

Line: 194-199 

# This fixes the data['kind'] issue, however this is only a temp fix

            if 'kind' in data:
                name: str = data['kind'].name
            else:
                
                name: str = ""
            return name
            
actions_pivot.py
- Added -

        elif isinstance(outcome, model.LeakedGuyId):
            for node_id in outcome.nodes:
                self.__mark_node_as_owned(node_id)
                
                if self.__mark_node_as_owned(node_id):
                    newly_discovered_nodes += 1
                    newly_discovered_nodes_value += self._environment.get_node(node_id).value
                    
                self.__annotate_edge(reference_node, node_id, EdgeAnnotation.KNOWS)
                
model_pivot.py

- Added LeakedGuyId

VulnerabilityOutcomes = Union[
    LeakedCredentials, LeakedNodesId, PrivilegeEscalation, AdminEscalation,
    SystemEscalation, CustomerData, LateralMove, ExploitFailed, LeakedGuyId]
    
generate_pivot_network.py

- Added Known_on_capture neighbors + library

        knows_neighbors = traffic_targets(node_id, 'Knows_on_capture')

        if len(knows_neighbors) > 0:
            library['Knows_on_capture'] = m.VulnerabilityInfo(
                description="Attempt to discover further info associated with node",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedGuyId([target_node for target_node in knows_neighbors])
                ,
                
                reward_string="Discovered new networked node",
                cost=5.0
            )

generate_pivot_network.py
protocols = ['HTTP', 'SMB', 'RDP']

    edges_labels = defaultdict(set)

    for protocol in protocols:
    # Create one graph for each protocol as per nx.stochastic_block_model
    
        h = nx.fast_gnp_random_graph(15, 
                                     0.5, 
                                     seed     = None, 
                                     directed = True
                                     )
        for edge in h.edges:
        
            edges_labels[edge].add(protocol)

# Create additional nodes, with no random connections to other nodes except selected targets
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
 
