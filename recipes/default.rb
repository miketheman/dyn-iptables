#
# Cookbook Name:: iptables
# Recipe:: default
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

#if node['iptables_apply_for_real'] then
  template node['iptables']['persistence_file'] do
    source "chef_iptables_ruleset.erb"
    owner = "root"
    mode "0600"
    notifies :restart, "service[iptables]"
  end
# else
#   template "/tmp/chef_iptables_ruleset" do
#     source "chef_iptables_ruleset.erb"
#     owner = "root"
#     mode "0644"
#   end
# end

service "iptables" do
  action :start
end
