require 'pxp-agent/config_helper.rb'

test_name 'Service Start stop/start, with configuration)'
@agent1 = agents[0]
@pxp_temp_file = '~/pxp-agent.conf'

# On teardown, restore configuration file
teardown do
  if @agent1.file_exist?(@pxp_temp_file)
    on(@agent1, "mv #{@pxp_temp_file} #{pxp_agent_config_file(@agent1)}")
  end
end

step 'Setup - Add base certs and config file'
test_ssl_dir = configure_standard_certs_in_tmpdir(@agent1, 1)

def stop_service
  on(@agent1, puppet('resource service pxp-agent ensure=stopped'))
end

def start_service
  on(@agent1, puppet('resource service pxp-agent ensure=running'))
end

def assert_stopped
  on(@agent1, puppet('resource service pxp-agent ')) do |result|
    assert_match(/ensure => .stopped.,/, result.stdout,
                 "pxp-agent not in expected stopped state")
  end
end

def assert_running
  on(@agent1, puppet('resource service pxp-agent ')) do |result|
    assert_match(/ensure => .running.,/, result.stdout,
                 "pxp-agent not in expected running state")
  end
end

step 'C93070 - Service Start (from stopped, with configuration)'
stop_service
assert_stopped
start_service
assert_running

step 'C93069 - Service Stop (from running, with configuration)'
stop_service
assert_stopped

# Solaris service administration will prevent the service from starting
# if it is un-configured because it has been defined as required.
# See: https://github.com/puppetlabs/pxp-agent/blob/stable/ext/solaris/smf/pxp-agent.xml#L10-L12
#
# Therefore, the un-configured test steps need to be skipped on Solaris
unless (@agent1['platform'] =~ /solaris/) then
  step 'Remove configuration'
  stop_service
  on(@agent1, "mv #{pxp_agent_config_file(@agent1)} #{@pxp_temp_file}")

  step 'C94686 - Service Start (from stopped, un-configured)'
  start_service
  assert_running

  step 'C94687 - Service Stop (from running, un-configured)'
  stop_service
  assert_stopped

  step 'Restore configuration'
  on(@agent1, "mv #{@pxp_temp_file} #{pxp_agent_config_file(@agent1)}")
end
