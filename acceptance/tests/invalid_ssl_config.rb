require 'pxp-agent/config_helper.rb'

test_name 'Attempt to start pxp-agent with invalid SSL config'

agent1 = agents[0]

# @param host the host to check the logile on
# @param logfile path to log file
# @param expected the string or pattern expected in the log
def wait_for_log_entry(host, logfile, expected)
  # If the expected log entry does not appear in log within 30 seconds, then do an
  # explicit assertion so we get a test fail (not an unhandled error),
  # and see the log contents in the test failure output
  begin
    retry_on(host, "grep '#{expected}' #{logfile}", {:max_retries => 30,
                                                     :retry_interval => 1})
  rescue
    on(host, "cat #{logfile}") do |result|
      assert_match(expected, result.stdout,
                  "Expected error '#{expected}' did not appear in pxp-agent.log")
    end
  end
end

step 'Setup - Add base certs and config file'
test_ssl_dir = agent1.tmpdir('test-ssl')
scp_to(agent1, '../test-resources/ssl', test_ssl_dir)
test_ssl_dir = File.join(test_ssl_dir, 'ssl')
create_remote_file(agent1, pxp_agent_config_file(agent1), pxp_config_json_using_test_certs(master, agent1, 1, test_ssl_dir).to_s)
if agent1['platform'] =~ /windows/
  on agent1, "chmod -R 744 #{test_ssl_dir.gsub('C:/cygwin64', '')}"
end

# On teardown, restore valid config file
teardown do
  on agent1, puppet('resource service pxp-agent ensure=stopped')
  create_remote_file(agent1, pxp_agent_config_file(agent1), pxp_config_json_using_test_certs(master, agent1, 1, test_ssl_dir).to_s)
  on agent1, puppet('resource service pxp-agent ensure=running')
end

step 'Setup - Stop pxp-agent service'
on agent1, puppet('resource service pxp-agent ensure=stopped')

step "Setup - Wipe pxp-agent log"
on(agent1, "rm -rf #{logfile(agent1)}")

step "Setup - Change pxp-agent config to use a cert that doesn't match private key"
invalid_config_mismatching_keys = {:broker_ws_uri => broker_ws_uri(master),
                                   :ssl_key => ssl_key_file(agent1, 1, test_ssl_dir),
                                   :ssl_ca_cert => ssl_ca_file(agent1, test_ssl_dir),
                                   :ssl_cert => ssl_cert_file(agent1, 1, test_ssl_dir, true)}
create_remote_file(agent1, pxp_agent_config_file(agent1), pxp_config_json(master, agent1, invalid_config_mismatching_keys).to_s)

step 'C94730 - Attempt to run pxp-agent with mismatching SSL cert and private key'
expected_private_key_error=
on agent1, puppet('resource service pxp-agent ensure=running')
wait_for_log_entry(agent1, logfile(agent1), 'failed to load private key')
assert(on(agent1, "grep 'pxp-agent will start unconfigured' #{logfile(agent1)}"),
       "pxp-agent should log that is will start unconfigured")
on agent1, puppet('resource service pxp-agent') do |result|
  assert_match(/running/, result.stdout, "pxp-agent service should be running (unconfigured)")
end

step "Stop service and wipe log"
on agent1, puppet('resource service pxp-agent ensure=stopped')
on(agent, "rm -rf #{logfile(agent1)}")

step "Change pxp-agent config so the cert and key match but they are of a different ca than the broker"
invalid_config_wrong_ca = {:broker_ws_uri => broker_ws_uri(master),
                           :ssl_key => ssl_key_file(agent1, 1, test_ssl_dir, true),
                           :ssl_ca_cert => ssl_ca_file(agent1, test_ssl_dir),
                           :ssl_cert => ssl_cert_file(agent1, 1, test_ssl_dir, true)}
create_remote_file(agent1, pxp_agent_config_file(agent1), pxp_config_json(master, agent1, invalid_config_wrong_ca).to_s)

step 'C94729 - Attempt to run pxp-agent with SSL keypair from a different ca'
on agent1, puppet('resource service pxp-agent ensure=running')
wait_for_log_entry(agent1, logfile(agent1), 'TLS handshake failed')
wait_for_log_entry(agent1, logfile(agent1), 'retrying in')
on agent1, puppet('resource service pxp-agent') do |result|
  assert_match(/running/, result.stdout, "pxp-agent service should be running (failing handshake)")
end
on agent1, puppet('resource service pxp-agent ensure=stopped')
on agent1, puppet('resource service pxp-agent') do |result|
  assert_match(/stopped/, result.stdout,
               "pxp-agent service should stop cleanly when it is running in a loop retrying invalid certs")
end
