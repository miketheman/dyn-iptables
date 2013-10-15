require 'chefspec'

describe 'iptables::default' do
  let(:chef_run) { ChefSpec::ChefRunner.new.converge(described_recipe) }
  let(:lib) { double('library', static_inbound: x, dynamic_inbound: x, static_outbound: x, dynamic_outbound: x) } 

  before do
    IptablesRules.stub(:new).and_return(lib)
  end

  it 'writes the template' do
    expect(chef_run).to create_file_with_content('/path/to/template', 'content')
  end
end
