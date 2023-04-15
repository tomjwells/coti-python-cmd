from cmd_tx.create_cmd_transfer import read_env_file, get_nodes, tx_manager_logger, launch_transactions


def main():
  # env_filepath = ".env.local"
  env_filepath = ".env"

  node_manager_address, full_node_address, trust_score_address, source_seed, source_address_index, fee_included, \
      transaction_description, currency_hash, amount, logging_module_in_out, logging_api_call_times, \
      destination_addresses_file_name, transaction_type = read_env_file(env_filepath)

  if not str(node_manager_address) == 'None':
    trust_score_node, full_node, financial_server = get_nodes(node_manager_address)
    trust_score_address = trust_score_node['url']
    full_node_address = full_node['url']
    financial_server_address = financial_server['url']
    tx_manager_logger.info("fullnode: " + full_node_address + ", trustscore:" + trust_score_address)

  launch_transactions(full_node_address, trust_score_address, source_seed, source_address_index,
                      fee_included, transaction_description, currency_hash, amount, destination_addresses_file_name,
                      transaction_type)


main()
