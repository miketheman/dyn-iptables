#
# Cookbook Name:: iptables
# library:: iptables_rules.rb
#
# Copyright 2013-2014, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

class IptablesRules
  attr_reader :static_inbound_rules
  attr_reader :dynamic_inbound_rules
  attr_reader :static_outbound_rules
  attr_reader :dynamic_outbound_rules
  
  def initialize(node)
    @rule_types = []
    @static_inbound_rules = []
    @dynamic_inbound_rules = []
    @static_outbound_rules = []
    @dynamic_outbound_rules = []
    
    IptablesRules.set_attributes node
    
    if node['iptables'].nil? then
      Chef::Log.warn("node['iptables'] returns nil. Something is seriously wrong. Please check the attributes in your wrapper cookbook, role, or environment definition. Bailing.")
    else
      node['iptables'].each do |rule_source, types|
        types.each do |type,ruledefs|
          @rule_types << type
        end
      end

      # register methods
      @rule_types.each do |type|
        IptablesRules.define_component(type)
      end
      
      # do work
      node['iptables'].keys.each do | rule_source |
        node['iptables']["#{rule_source}"].each do |type,ruledefs|
          self.send(type,ruledefs)
        end
      end
    end    
  end # initialize
  
  def self.define_component(name)
    define_method(name) do |ruledefs|
      if ! ruledefs.empty? then

        __method__.to_s =~ /inbound/ ? @direction = "INPUT" : @direction = "OUTPUT"
        
        ruledefs.each do |rule_name,rule_data|          
          (rule_data['interface'].nil? || @direction == 'OUTPUT' ) ? @interface = "" : @interface = "-i " + rule_data['interface']
          (rule_data['proto'].nil? || rule_data['proto'] == 'all') ? @proto = "" : @proto = "-p " + rule_data['proto']
          rule_data['source'].nil? ? @source = "" : @source = "-s " + rule_data['source']
          rule_data['dest'].nil? ? @dest = "" : @dest = "-d " + rule_data['dest']
          rule_data['proto'] == 'tcp' ? @state_rule = "-m state --state NEW" : @state_rule = ""
          
          # static
          if __method__.to_s =~ /static/ then          
            if rule_data['dest_ports'].nil? then
              eval("@#{__method__}_rules") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} #{@dest} -j ACCEPT".squeeze(" ")
            else
              rule_data['dest_ports'].each do |port|
                eval("@#{__method__}_rules") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} #{@dest} --dport #{port} -j ACCEPT".squeeze(" ")
              end
            end            
          end
                   
          # dynamic
          if __method__.to_s =~ /dynamic/ then
            if ! rule_data['search_term'].nil?
              partial_search(:node, rule_data['search_term'], keys: { ip: [ 'ipaddress' ], network: ['network'], cloud: ['cloud'] }).each do |host|
                @host_ip=""
                if rule_data['remote_interface'] == 'eth0' then
                  @host_ip = host['ipaddress']
                else
                  if ! (host['network'].nil? || host['network']['interfaces']["#{rule_data['remote_interface']}"].nil?)
                    @host_ip = host['network']['interfaces']["#{rule_data['remote_interface']}"]['addresses'].select { |address, data| data['family'] == 'inet' }.keys[0]
                  end
                end
                
                if @host_ip.empty? then
                  Chef::Log.warn("Search results for #{rule_data['search_term']} in rule #{rule_name} contains no data for interface #{rule_data['remote_interface']}. Skipping.")
                else
                  case @direction                   
                  when "INPUT"
                    @target = "-s " + @host_ip
                  when "OUTPUT"
                    @target = "-d " + @host_ip
                  end
                  if rule_data['dest_ports'].nil? then
                    eval("@#{__method__}_rules") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@target} -j ACCEPT".squeeze(" ")
                  else
                    rule_data['dest_ports'].each do |port|
                      eval("@#{__method__}_rules") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@target} --dport #{port} -j ACCEPT".squeeze(" ")
                    end
                  end
                end
              end # search.each
            end # if ! rule_data['search_term'].nil?
          end # __method__.to_s =~ /dynamic/ then
        end # rule_defs.each
      end # if ! rule_defs.empty?
    end # define_method
  end # self.define_component

  def self.set_attributes(node)
    # # set node attributes from databags
    
    hostname = node['hostname']
    if ! hostname.nil? then
      begin
        Chef::Search::Query.new.search(:iptables_hostname, "id:#{hostname}")[0].each do |result|
          Chef::Log.info("setting iptables_hostname")
          node.default['iptables']['hostname']['static_inbound'] = result['static_inbound'] unless result['static_inbound'].nil?
          node.default['iptables']['hostname']['static_outbound'] = result['static_outbound'] unless result['static_outbound'].nil?
          node.default['iptables']['hostname']['dynamic_inbound'] = result['dynamic_inbound'] unless result['dynamic_inbound'].nil?
          node.default['iptables']['hostname']['dynamic_outbound'] = result['dynamic_outbound'] unless result['dynamic_outbound'].nil?
        end
      rescue => exception
        Chef::Log.info("Caught #{exception}. Databag iptables_hostname could not be searched.")
      end
    end
      
      # next, override default cookbook rules based on hostclass tag
      if ! node['tags'].nil?
        hostclass = node['tags'].grep(/hostclass.*/).first
        if ! hostclass.nil? then
          begin
            Chef::Search::Query.new.search(:iptables_hostclass, "id:#{hostclass}")[0].each do |result|
              Chef::Log.info("setting iptables_hostclass")
              node.default['iptables']['hostclass']['static_inbound'] = result['static_inbound'] unless result['static_inbound'].nil?
              node.default['iptables']['hostclass']['static_outbound'] = result['static_outbound'] unless result['static_inbound'].nil?
              node.default['iptables']['hostclass']['dynamic_inbound'] = result['dynamic_inbound'] unless result['static_inbound'].nil?
              node.default['iptables']['hostclass']['dynamic_outbound'] = result['dynamic_outbound'] unless result['static_inbound'].nil?
            end
          rescue => exception
            Chef::Log.info("Caught #{exception}. Databag iptables_hostclass could not be searched.")
          end
        end
      end
    
  end # self.set_attributes  
end  # class IptablesRules
