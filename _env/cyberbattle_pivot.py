
"""A CyberBattle simulation over a randomly generated network"""

from cyberbattle.simulation import generate_pivot_network
from . import cyberbattle_env_pivot

class CyberBattlePivot(cyberbattle_env_pivot.CyberBattleEnv):
    """A sample CyberBattle environment"""

    def __init__(self):
        super().__init__(initial_environment=generate_pivot_network.new_environment(n_servers_per_protocol=3),
                         maximum_discoverable_credentials_per_action=15)
