from mininet.topo import Topo

class AttackTopo(Topo):
    def build(self):
        # Switch
        s1 = self.addSwitch('s1')

        # Hosts
        h1 = self.addHost('h1')  # normal client
        h2 = self.addHost('h2')  # normal client
        h3 = self.addHost('h3')  # attacker
        h4 = self.addHost('h4')  # server

        # Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

topos = {
    'attacktopo': (lambda: AttackTopo())
}
