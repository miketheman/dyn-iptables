require 'chefspec'

describe 'iptables::default' do
  let(:lib) { double('library', static_inbound: x, dynamic_inbound: x, static_outbound: x, dynamic_outbound: x) }
  
  let(:ubuntu_1004_run) { ChefSpec::ChefRunner.new(platform: 'ubuntu', version: '10.04' ).converge(described_recipe) }
  let(:ubuntu_1204_run) { ChefSpec::ChefRunner.new(platform: 'ubuntu', version: '10.04' ).converge(described_recipe) }
  let(:centos5_run) { ChefSpec::ChefRunner.new(platform: 'centos', version: '5.9' ).converge(described_recipe) }
  let(:centos6_run) { ChefSpec::ChefRunner.new(platform: 'centos', version: '6.4' ).converge(described_recipe) }

  before do
    IptablesRules.stub(:new).and_return(lib)
  end

  it 'creates enclosing directory for persistence file' do
    expect(chef_run).to create_file_with_content('/etc', 'content')
  end
end
