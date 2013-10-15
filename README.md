Description
===========
The iptables cookbook uses and embedded library to generate a ruleset
in memory, then manage a persistence files on disk. Rules are
described as JSON, processed into rules, passed as parameters into
template resource. 

There are four kinds of rules: static_inbound, static_outbound,
dynamic_inbound and dynamic_outbound.

Rules can come from three sources:
Node attributes, the iptables_hostname databag, and the iptables_hostclass databag.

Static Rule Types
=================
Static rules require the user to supply a source address/range.
Additionally, they can include an interface, network protocol and
destination ports.

static_inbound rule example
---------------------------
```
'eth0 accept ssh from anywhere' => {
  'interface' => 'eth0',
  'source' => '0.0.0.0/0',  
  'proto' => 'tcp',
  'dest_ports' => [ '22' ]
}
```

static_outbound rule example
----------------------------
```
'outbound from 172.16.1.0/16' => {
  'proto' => 'tcp',
  'source' => '172.16.1.0/16',
  'dest' => '172.16.2.0/16',
  'dest_ports' => [ '80' ],
}
```

Dynamic Rule Types
==================
Dynamic rules work like static rules, except the source or dest parameters are
replaced with a search term for chef-server.

dynamic_inbound rule example
---------------------------
```
'allow icmp from *:*' => {
  'search_term' => '*:*',
  'interface' => 'eth0',
  'remote_interface' => 'eth0',
  'proto' => 'icmp'
}
```

dynamic_outbound rule example
-----------------------------
```
'allow outgoing udp to port 53 at role:dns' => {
  'search_term' => '*:*',
  'remote_interface' => 'eth1',  
  'proto' => 'tcp',
  'dest_ports' => [ '53 ']
}
```

Rules From Node Attributes
==========================
Rules are stored as attributes under the keyspace node['iptables'].

```
node['iptables']['cookbook']['static_inbound'] = {}
node['iptables']['cookbook']['static_outbound'] = {}
node['iptables']['cookbook']['dymanic_inbound'] = {}
node['iptables']['cookbook']['dymanic_outbound'] = {}
```

Cookbook Default Attributes
===========================
The default setting shipped with this cookbook found in the
attributes/default.rb file. You'll need to override
node['iptables_apply_for_real'] to make rules be applied. This is a
safety feature in case people blindly apply the cookbook without
understanding how it works.

```
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
```

Setting rule attributes from a recipe
=====================================
```
node.default['iptables']['cookbook']['dynamic_inbound'] = {
  'eth0 accept ssh and http from anywhere' => {
    'interface' => 'eth0',
    'source' => '0.0.0.0/0',  
    'proto' => 'tcp',
    'dest_ports' => [ '22', '80' ],
  }
}
```

Setting rule attributes from a role or environment file
=======================================================
```
default_attributes(
  :iptables => {
    :cookbook => {
      :dynamic_inbound => {
        'eth0 accept ssh from anywhere' => {
          'interface' => 'eth0',
          'source' => '0.0.0.0/0',  
          'proto' => 'tcp',
          'dest_ports' => [ '22', '80' ],
         },
         'eth0 accept port 80 and 43 from role:workernode => {         
           'interface' => 'eth0',
           'search_term' => 'role:workernode'
           'proto' => 'tcp',
           'dest_ports' => [ '22', '80' ],
         }
       }
     }
   }
 )
```

# Rules from Data bags
======================
Loading rules is supported from two databag sources. When present,
they will be loaded into the nodes attributes into their own key space
and be added to their respective rule type

iptables_hostname
-----------------
If present, the ```iptables_hostname``` databag is searched for a record
that matches the node's ```hostname``` at the time of the chef_run.
Rules will then be loaded into the following attribute space:

```
node['iptables']['hostname']['static_inbound'] = {}
node['iptables']['hostname']['static_outbound'] = {}
node['iptables']['hostname']['dymanic_inbound'] = {}
node['iptables']['hostname']['dymanic_outbound'] = {}
```

An example can be found at ```example_data_bags/iptables_hostname/hostname-example-1.json```

iptables_hostclass
------------------
If present, the ```iptables_class``` databag is searched for a record
that matches the the first tag present on the node object that matches
the pattern ```iptables-hostclass-*```. Rules will then be loaded into
the following attribute space:

```
node['iptables']['hostclass']['static_inbound'] = {}
node['iptables']['hostclass']['static_outbound'] = {}
node['iptables']['hostclass']['dymanic_inbound'] = {}
node['iptables']['hostclass']['dymanic_outbound'] = {}
```

An example can be found at ```example_data_bags/iptables_hostclass/hostclass-example-1.json```

Recipes
=======

default.rb
----------
Manages ```template[/etc/sysconfig/iptables]``` and restarts the iptables service if it changes

TODO
====
- [ ] Sanity Checking - Make sure rule sources match a regexse
- [ ] Sanity Checking - Make sure dynamic rules have search terms, not sources

Author
======
Sean OMeara <someara@opscode.com>

LICENSE
=======
Apachev2
