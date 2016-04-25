require 'spec_helper'
describe 'osd_secure' do

  context 'with defaults for all parameters' do
    it { should contain_class('osd_secure') }
  end
end
