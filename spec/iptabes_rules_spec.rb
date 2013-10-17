require_relative 'spec_helper'
require_relative '../libraries/iptables_rules.rb'
require File.expand_path("../../..//partial_search/libraries/partial_search.rb", __FILE__)
#require 'pry'
#require 'chefspec'

describe 'IptablesRules' do
  # stub the partial_search method to simulate a chef-server with some
  # node objects populated.
  
  before do
    Object.any_instance.stub(:partial_search).with( :node, '*:*',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.2.3.4',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '1.2.3.4' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.2.3.255' } } },
              'eth1' => { 'addresses' => { '10.9.8.7' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '10.9.8.255' } } } 
            },
          },
          'cloud' => ''
        },
        {
          'ipaddress' => '1.2.3.5',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '1.2.3.5' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.2.3.255' } } },
              'eth1' => { 'addresses' => { '10.9.8.6' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '10.9.8.255' } } } 
            }
          },
          'cloud' => ''
        },
        {
          'ipaddress' => '1.2.3.6',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '1.2.3.6' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.2.3.255' } } },
              'eth1' => { 'addresses' => { '10.9.8.5' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '10.9.8.255' } } } 
            }
          },
          'cloud' => ''
        }
      ] )
    
    Object.any_instance.stub(:partial_search).with( :node, 'role:dns_client',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '10.11.12.13',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '10.11.12.13' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '10.11.12.255' } } }
            },
          },
          'cloud' => ''
        }
      ])

    Object.any_instance.stub(:partial_search).with( :node, 'role:lorax',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.2.1.2',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '1.2.1.2' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.2.1.255' } } }
            },
          },
          'cloud' => ''
        }
      ])

    Object.any_instance.stub(:partial_search).with( :node, 'zozzfozzle:true',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.3.1.3',
          'network' => {
            'interfaces' => {
              'eth1' => { 'addresses' => { '1.3.1.3' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.3.1.255' } } }
            },
          },
          'cloud' => ''
        }
      ])

    Object.any_instance.stub(:partial_search).with( :node, 'role:ralph',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.4.1.4',
          'network' => {
            'interfaces' => {
              'eth1' => { 'addresses' => { '1.4.1.4' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.4.1.255' } } }
            },
          },
          'cloud' => ''
        }
      ])

    Object.any_instance.stub(:partial_search).with( :node, 'something_eltz:true',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.5.1.5',
          'network' => {
            'interfaces' => {
              'eth1' => { 'addresses' => { '1.5.1.5' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.5.1.255' } } }
            },
          },
          'cloud' => ''
        }
      ])   

    Object.any_instance.stub(:partial_search).with( :node, 'asdasd:true',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.6.1.6',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '1.6.1.6' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.6.1.255' } } }
            },
          },
          'cloud' => ''
        }
      ])

    Object.any_instance.stub(:partial_search).with( :node, 'role:ades',
      keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }
      ).and_return( [
        {
          'ipaddress' => '1.7.1.7',
          'network' => {
            'interfaces' => {
              'eth0' => { 'addresses' => { '1.7.1.7' => { 'family' => 'inet', 'prefixlen' => '24', 'netmask' => '255.255.255.0', 'broadcast' => '1.7.1.255' } } }
            },
          },
          'cloud' => ''
        }
      ])  
    
    # Because reasons.
    class Chef::Search::Query
      def initialize
      end
      def search
      end
    end
    
    # Stub the regular seach for iptables_hostname databag items
    Chef::Search::Query.any_instance.stub(:search).with(:iptables_hostname, "id:iptables-1").and_return([
        [
          Chef::DataBagItem.from_hash(
            {
              "id" => "iptables-1",
              "static_inbound"=> {
                "eth1 accept connections to port 1234 from 5.4.3.2" => {
                  "interface" => "eth1",
                  "source" => "5.4.3.2/32",
                  "proto" => "tcp",
                  "dest_ports" => ["1234"]
                }
              },
              "static_outbound" => {
                "accept icmp to anywhere" => {
                  "proto"=> "icmp",
                  "dest"=> "0.0.0.0/0"
                }
              },
              "dynamic_inbound" => {
                "allow udp to port 2345 from role:lorax" => {
                  "search_term"=> "role:lorax",
                  "interface"=> "eth0",
                  "remote_interface"=> "eth0",
                  "proto"=> "udp",
                  "dest_ports"=> ["2345"]
                }
              },
              "dynamic_outbound" => {
                "allow outgoing to zozzfozzle:true" => {
                  "search_term" => "zozzfozzle:true",
                  "interface" => "eth1",
                  "remote_interface" => "eth1",
                  "proto"=> "tcp"
                }
              }
            }
            ),],
        0,1]
      )    
    
    # Stub the regular seach for iptables_hostclass databag items
    Chef::Search::Query.any_instance.stub(:search).with(:iptables_hostclass, "id:hostclass-example-1").and_return([
        [
          Chef::DataBagItem.from_hash(
            {
              "id" => "iptables-1",
              "static_inbound"=> {
                "eth1 accept connections to port 1234 from 6.5.4.3" => {
                  "interface" => "eth1",
                  "source" => "6.5.4.3/32",
                  "proto" => "tcp",
                  "dest_ports" => ["1234"]
                }
              },
              "static_outbound" => {
                "accept icmp to anywhere" => {
                  "proto"=> "icmp",
                  "dest"=> "0.0.0.0/0"
                }
              },
              "dynamic_inbound" => {
                "allow udp to port 2345 from role:ralph" => {
                  "search_term"=> "role:ralph",
                  "interface"=> "eth0",
                  "remote_interface"=> "eth0",
                  "proto"=> "udp",
                  "dest_ports"=> ["2345"]
                }
              },
              "dynamic_outbound" => {
                "allow outgoing to something_eltz:true" => {
                  "search_term" => "something_eltz:true",
                  "interface" => "eth1",
                  "remote_interface" => "eth1",
                  "proto"=> "tcp"
                }
              }
            }
            ),],
        0,1]
      )    
  end # before do

  # empty cookbook rulesets
  context "empty static rulesets" do
    before do
      node = Chef::Node.new
      node.set['iptables']['cookbook']['static_inbound'] = {}
      node.set['iptables']['cookbook']['static_outbound'] = {}
      node.set['iptables']['cookbook']['dynamic_inbound'] = {}
      node.set['iptables']['cookbook']['dynamic_outbound'] = {}    
      @ruleset = IptablesRules.new node
    end
    
    it 'should create an empty static_inbound_rules' do
      expect(@ruleset.static_inbound_rules).to be_empty
    end
    
    it 'should create an empty static_outbound_rules' do
      expect(@ruleset.static_inbound_rules).to be_empty
    end
    
    it 'should create an empty dynamic_inbound_rules' do
      expect(@ruleset.dynamic_inbound_rules).to be_empty
    end
    
    it 'should create an empty dynamic_outbound_rules' do
      expect(@ruleset.dynamic_outbound_rules).to be_empty
    end    
  end

  # populated cookbook static_inbound
  context "populated cookbook static_inbound" do    
    before do
      node = Chef::Node.new
      node.default['iptables']['cookbook']['static_inbound'] =  {      
        'lo accept from anywhere' => {
          'interface' => 'lo',
          'proto' => 'all',
          'source' => '0.0.0.0/0'
        },
        'eth0 accept icmp from anywhere' => {
          'interface' => 'eth0',
          'proto' => 'icmp',
          'source' => '0.0.0.0/0'
        },
        'eth1 accept ssh from anywhere' => {
          'interface' => 'eth1',
          'proto' => 'tcp',
          'source' => '0.0.0.0/0',
          'dest_ports' => [ '22', '80' ]
        }
      }      
      @ruleset = IptablesRules.new node
    end
    
    it 'should contain the proper rules' do
      expect(@ruleset.static_inbound_rules).to eq [
        "-A INPUT -i lo -s 0.0.0.0/0 -j ACCEPT",
        "-A INPUT -i eth0 -p icmp -s 0.0.0.0/0 -j ACCEPT",
        "-A INPUT -i eth1 -m state --state NEW -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT",
        "-A INPUT -i eth1 -m state --state NEW -p tcp -s 0.0.0.0/0 --dport 80 -j ACCEPT"
      ]
    end    
  end
  
  # populated cookbook static_onbound rules
  context "multiple static outbound rules" do
    before do
      node = Chef::Node.new      
      node.default['iptables']['cookbook']['static_outbound'] =  {
        'outbound to 192.168.1.0/24' => {
          'proto' => 'all',
          'dest' => '192.168.1.0/24',
        },
        'outbound to 192.168.2.0/24' => {
          'proto' => 'tcp',
          'dest' => '192.168.2.0/24',
        },
        'outbound to 192.168.3.0/24' => {
          'proto' => 'udp',
          'dest' => '192.168.3.0/24',
          'dest_ports' => [ '53' ]
        },
        'outbound to 8.8.8.8/32' => {
          'proto' => 'udp',
          'dest' => '8.8.8.8/32',
          'dest_ports' => [ '53', '1337' ]
        },
      }    
      @ruleset = IptablesRules.new node
    end
    
    it 'should contain the proper rules' do
      expect(@ruleset.static_outbound_rules).to eq [
        "-A OUTPUT -d 192.168.1.0/24 -j ACCEPT",
        "-A OUTPUT -m state --state NEW -p tcp -d 192.168.2.0/24 -j ACCEPT",
        "-A OUTPUT -p udp -d 192.168.3.0/24 --dport 53 -j ACCEPT",
        "-A OUTPUT -p udp -d 8.8.8.8/32 --dport 53 -j ACCEPT",
        "-A OUTPUT -p udp -d 8.8.8.8/32 --dport 1337 -j ACCEPT",
      ]
    end    
  end

  # populated cookbook dynamic_inbound rules
  context "populated cookbook dynamic_inbound rules" do
    before do
      node = Chef::Node.new    
      node.default['iptables']['cookbook']['dynamic_inbound'] =  {
        'allow icmp from *:*' => {
          'search_term' => '*:*',
          'interface' => 'eth0',
          'remote_interface' => 'eth0',
          'proto' => 'icmp'
        },
        'allow http and https from *:*' => {
          'search_term' => '*:*',
          'interface' => 'eth0',
          'remote_interface' => 'eth1',
          'proto' => 'tcp',
          'dest_ports' => [ '80', '443' ]
        },
        'allow udp 53 and 1337 from role:dns_client' => {
          'search_term' => 'role:dns_client',
          'interface' => 'eth1',
          'remote_interface' => 'eth0',
          'proto' => 'udp',
          'dest_ports' => [ '53', '1337' ]
        }
      }
      @ruleset = IptablesRules.new node
    end

    it 'should contain the proper rules' do      
      expect(@ruleset.dynamic_inbound_rules).to eq [
        "-A INPUT -i eth0 -p icmp -s 1.2.3.4 -j ACCEPT",
        "-A INPUT -i eth0 -p icmp -s 1.2.3.5 -j ACCEPT",
        "-A INPUT -i eth0 -p icmp -s 1.2.3.6 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 10.9.8.7 --dport 80 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 10.9.8.7 --dport 443 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 10.9.8.6 --dport 80 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 10.9.8.6 --dport 443 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 10.9.8.5 --dport 80 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 10.9.8.5 --dport 443 -j ACCEPT",
        "-A INPUT -i eth1 -p udp -s 10.11.12.13 --dport 53 -j ACCEPT",
        "-A INPUT -i eth1 -p udp -s 10.11.12.13 --dport 1337 -j ACCEPT",
      ]
    end
  end

  # populated cookbook dynamic_outbound rules
  context "populated cookbook dynamic_outbound rules" do
    before do
      node = Chef::Node.new          
      node.default['iptables']['cookbook']['dynamic_outbound'] =  {
        'allow outgoing to port 1234 at *:*' => {
          'search_term' => '*:*',
          'remote_interface' => 'eth1',
          'proto' => 'tcp',
        }
      }
      @ruleset = IptablesRules.new node      
    end

    it 'should contain the proper rules' do      
      expect(@ruleset.dynamic_outbound_rules).to eq [
        "-A OUTPUT -m state --state NEW -p tcp -d 10.9.8.7 -j ACCEPT",
        "-A OUTPUT -m state --state NEW -p tcp -d 10.9.8.6 -j ACCEPT",
        "-A OUTPUT -m state --state NEW -p tcp -d 10.9.8.5 -j ACCEPT"
      ]
    end    
  end

  # hostname databag
  context "When iptables_hostname data_bags exist and a record matches the hostname" do
    before do
      node = Chef::Node.new
      node.default['hostname'] = "iptables-1"
      node.default['iptables']
      @ruleset = IptablesRules.new node      
    end

    it "adds the static_inbound rules" do
      expect(@ruleset.static_inbound_rules).to eq [
        "-A INPUT -i eth1 -m state --state NEW -p tcp -s 5.4.3.2/32 --dport 1234 -j ACCEPT"
      ]
    end

    it "adds the static_outbound rules" do
      expect(@ruleset.static_outbound_rules).to eq [
        "-A OUTPUT -p icmp -d 0.0.0.0/0 -j ACCEPT"
      ]
    end

    it "adds the dynamic_inbound rules" do
      expect(@ruleset.dynamic_inbound_rules).to eq [
        "-A INPUT -i eth0 -p udp -s 1.2.1.2 --dport 2345 -j ACCEPT"
      ]
    end

    it "adds the dynamic_outbound rules" do
      expect(@ruleset.dynamic_outbound_rules).to eq [
        "-A OUTPUT -m state --state NEW -p tcp -d 1.3.1.3 -j ACCEPT"
      ]
    end    
  end

  # hostclass databag
  context "When a databag record matching a node's hostclass tag exists" do
    before do
      node = Chef::Node.new
      node.normal['tags'] = ["hostclass-example-1" ]
      node.default['iptables']
      @ruleset = IptablesRules.new node      
    end

    it "adds the static_inbound rules" do
      expect(@ruleset.static_inbound_rules).to eq [
        "-A INPUT -i eth1 -m state --state NEW -p tcp -s 6.5.4.3/32 --dport 1234 -j ACCEPT"
      ]
    end

    it "adds the static_outbound rules" do
      expect(@ruleset.static_outbound_rules).to eq [
        "-A OUTPUT -p icmp -d 0.0.0.0/0 -j ACCEPT"
      ]
    end

    it "adds the dynamic_inbound rules" do
      expect(@ruleset.dynamic_inbound_rules).to eq [
        "-A INPUT -i eth0 -p udp -s 1.4.1.4 --dport 2345 -j ACCEPT"
      ]
    end

    it "adds the dynamic_outbound rules" do
      expect(@ruleset.dynamic_outbound_rules).to eq [
        "-A OUTPUT -m state --state NEW -p tcp -d 1.5.1.5 -j ACCEPT"
      ]
    end    
  end

  # multiple inputs
  context "When rules are defined from all three input sources" do
    before do
      node = Chef::Node.new

      node.default['iptables']['cookbook']['static_inbound'] =  {
        "eth0 accept connections to port 1234 from 42.42.42.1" => {
          "interface" => "eth0",
          "proto" => "tcp",
          "source" => "42.42.42.1/32",
          "dest_ports" => ["4321"]
        }
      }
      
      node.default['iptables']['cookbook']['static_outbound'] =  {
        'outbound from 172.16.1.0/16' => {
          'proto' => 'tcp',
          'source' => '172.16.1.0/16',
          'dest' => '172.16.2.0/16',
          'dest_ports' => [ '80' ],
        },
      }
      
      node.default['iptables']['cookbook']['dynamic_inbound'] =  {
        'eth0 inbound from asdasd:true' => {
          "search_term" => "asdasd:true",
          "interface" => "eth0",
          "remote_interface"=> "eth0",
          'proto' => 'tcp',
          'dest_ports' => [ '80', '443' ],
        }
      }
      
      node.default['iptables']['cookbook']['dynamic_outbound'] =  {
        "outbound from role:ades" => {
          "search_term" => "role:ades",
          "interface" => "eth0",
          "remote_interface" => "eth0",
          "proto" => "tcp",
          "dest_ports" => [ "22" ]
        }
      }

      node.default['hostname'] = "iptables-1"      
      node.normal['tags'] = ["hostclass-example-1" ]

      @ruleset = IptablesRules.new node      
    end

    it "adds the static_inbound rules" do
      expect(@ruleset.static_inbound_rules).to eq [
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 42.42.42.1/32 --dport 4321 -j ACCEPT",
        "-A INPUT -i eth1 -m state --state NEW -p tcp -s 5.4.3.2/32 --dport 1234 -j ACCEPT",
        "-A INPUT -i eth1 -m state --state NEW -p tcp -s 6.5.4.3/32 --dport 1234 -j ACCEPT"
      ]
    end
    
    it "adds the static_outbound rules" do
      expect(@ruleset.static_outbound_rules).to eq [
        "-A OUTPUT -m state --state NEW -p tcp -s 172.16.1.0/16 -d 172.16.2.0/16 --dport 80 -j ACCEPT",
        "-A OUTPUT -p icmp -d 0.0.0.0/0 -j ACCEPT",
        "-A OUTPUT -p icmp -d 0.0.0.0/0 -j ACCEPT"
      ]
    end

    it "adds the dynamic_inbound rules" do
      expect(@ruleset.dynamic_inbound_rules).to eq [
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 1.6.1.6 --dport 80 -j ACCEPT",
        "-A INPUT -i eth0 -m state --state NEW -p tcp -s 1.6.1.6 --dport 443 -j ACCEPT",
        "-A INPUT -i eth0 -p udp -s 1.2.1.2 --dport 2345 -j ACCEPT",
        "-A INPUT -i eth0 -p udp -s 1.4.1.4 --dport 2345 -j ACCEPT"
      ]
    end

    it "adds the dynamic_outbound rules" do
      expect(@ruleset.dynamic_outbound_rules).to eq [
        "-A OUTPUT -m state --state NEW -p tcp -d 1.7.1.7 --dport 22 -j ACCEPT",
        "-A OUTPUT -m state --state NEW -p tcp -d 1.3.1.3 -j ACCEPT",
        "-A OUTPUT -m state --state NEW -p tcp -d 1.5.1.5 -j ACCEPT"
      ]
    end
  end
  
end
