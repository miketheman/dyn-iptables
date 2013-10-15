default['iptables_apply_for_real'] = 0

default['iptables']['cookbook']['static_inbound'] = {
  'lo accept from anywhere' => {
    'proto' => 'all',
    'source' => '0.0.0.0/0',
    'interface' => 'lo'
  },  
  'eth0 accept icmp from anywhere' => {
    'interface' => 'eth0',
    'source' => '0.0.0.0/0',
    'proto' => 'icmp'
  },
  'eth0 accept ssh from anywhere' => {
    'interface' => 'eth0',
    'source' => '0.0.0.0/0',  
    'proto' => 'tcp',
    'dest_ports' => [ '22' ],
  }
}

default['iptables']['cookbook']['static_outbound'] = {
  'lo outbound to anywhere' => {
    'proto' => 'all',
    'source' => '0.0.0.0/0',
    'interface' => 'lo'
  },
  'eth0 outbound to anywhere' => {
    'proto' => 'all',
    'source' => '0.0.0.0/0',
    'interface' => 'eth0'
  }
}

default['iptables']['cookbook']['dynamic_inbound'] = {}
default['iptables']['cookbook']['dynamic_outbound'] = {}
