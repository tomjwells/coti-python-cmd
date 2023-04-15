import logging
import random

from coti_wallet.crypto_helper import *
from coti_wallet.node_actions import *

tx_manager_logger = logging.getLogger("tx_manager_logger")
modules_in_out_logger = logging.getLogger("modules_in_out")


def create_input_base_transactions_CMD(address_private, currency_hash_COTI, currency_hash_CMD, full_node_fee,
                                       instant_time, instant_time_millisecond, network_fee_data,
                                       receiver_base_transaction, source_address, context):
  start_time = time.time()

#   if currency_hash is None:
#     currency_hash = full_node_fee["currencyHash"]

  # COTI
  full_amount_COTI = (
      Decimal(full_node_fee['amount']) +
      Decimal(network_fee_data['amount'])).normalize(context)
  input_base_transaction_amount_COTI = format(-full_amount_COTI, "f")
  ibt_msg_COTI = bytearray.fromhex(source_address) \
      + str(input_base_transaction_amount_COTI).encode() \
      + instant_time_millisecond.to_bytes(8, byteorder='big') + bytearray.fromhex(currency_hash_COTI)
  ibt_hash_COTI = HashKeccak256(ibt_msg_COTI)

  # CMD
  full_amount_CMD = (Decimal(full_node_fee['originalAmount'])).normalize(context)
  input_base_transaction_amount_CMD = format(-full_amount_CMD, "f")
  ibt_msg_CMD = bytearray.fromhex(source_address) \
      + str(input_base_transaction_amount_CMD).encode() \
      + instant_time_millisecond.to_bytes(8, byteorder='big') + bytearray.fromhex(currency_hash_CMD)
  ibt_hash_CMD = HashKeccak256(ibt_msg_CMD)

  transaction_hash_bytes = ibt_hash_COTI + ibt_hash_CMD + full_node_fee["hash"] + network_fee_data["hash"] + receiver_base_transaction["hash"]
  transaction_hash = HashKeccak256(bytearray.fromhex(transaction_hash_bytes))
  address_signed_transaction_hash = SignDigest(bytearray.fromhex(address_private), bytearray.fromhex(transaction_hash))
  ibt_signature_data = {"r": address_signed_transaction_hash[0], "s": address_signed_transaction_hash[1]}

  ibt_coti = {
      "hash": ibt_hash_COTI,
      "amount": input_base_transaction_amount_COTI,
      "createTime": instant_time,
      "currencyHash": currency_hash_COTI,
      "addressHash": source_address,
      "name": "IBT",
      "signatureData": ibt_signature_data
  }
  ibt_cmd = {
      "hash": ibt_hash_CMD,
      "amount": input_base_transaction_amount_CMD,
      "createTime": instant_time,
      "currencyHash": currency_hash_CMD,
      "addressHash": source_address,
      "name": "IBT",
      "signatureData": ibt_signature_data
  }

  api_call_times_logger.info("\t\t---> create_input_base_transaction: %s seconds <---" % round((time.time() - start_time), 3))

  return ibt_coti, ibt_cmd, transaction_hash


def call_apis_to_prepare_a_CMD_tx(source_address_public_key_crc, destination_address, amount, currency_hash_coti, currency_hash_cmd, seed,
                                  address_private, transaction_description, full_node_address, trust_score_address,
                                  fee_included):
  start_time = time.time()

  instant_time = int(datetime.datetime.now().timestamp())
  instant_time_millisecond = instant_time * 1000

  context = init_context()

  private_key = PrivateKeyFromSeed(bytearray.fromhex(str(seed)))
  public_key, _ = PublicKeyFromPrivateKey(bytearray.fromhex(str(private_key)))

  full_node_fee = create_full_node_fee(full_node_address, public_key, private_key, currency_hash_cmd, amount,
                                       fee_included)
  for i in range(0, 100):
    try:
      # do stuff
      create_network_fee_response = create_network_fee(trust_score_address, public_key, full_node_fee)
    except Exception as e:
      print(f"Rate limit reached. Sleeping before trying again")
      # print(f"{e=}")
      time.sleep(10)
      continue
    break

  validate_network_fee_1st_response = validate_network_fee(trust_score_address, public_key, full_node_fee,
                                                           create_network_fee_response)
  network_fee_data = validate_network_fee(trust_score_address, public_key, full_node_fee,
                                          validate_network_fee_1st_response)

  receiver_base_transaction = build_receiver_base_transaction(instant_time, instant_time_millisecond, amount,
                                                              currency_hash_cmd, destination_address)

  input_base_transaction_coti, input_base_transaction_cmd, transaction_hash = create_input_base_transactions_CMD(
      address_private, currency_hash_coti, currency_hash_cmd, full_node_fee,
      instant_time, instant_time_millisecond,
      network_fee_data,
      receiver_base_transaction, source_address_public_key_crc, context)

  transaction_trust_score_data = get_trust_score_data(trust_score_address, public_key, private_key,
                                                      transaction_hash)

  api_call_times_logger.info(
      "\t\t---> call_apis_to_prepare_a_tx : %s seconds <---" % round((time.time() - start_time), 3))

  return full_node_fee, input_base_transaction_coti, input_base_transaction_cmd, instant_time, instant_time_millisecond, network_fee_data, \
      private_key, public_key, receiver_base_transaction, transaction_description, transaction_hash, \
      transaction_trust_score_data


def create_CMD_transaction(full_node_address, full_node_fee, input_base_transaction_COTI, input_base_transaction_CMD, instant_time, instant_time_millisecond,
                           network_fee_data,
                           private_key, public_key, receiver_base_transaction, transaction_description, transaction_hash,
                           transaction_trust_score_data, transaction_type):
  start_time = time.time()

  base_transaction = [input_base_transaction_COTI, input_base_transaction_CMD, full_node_fee, network_fee_data, receiver_base_transaction]
  tx_bytes = bytearray.fromhex(transaction_hash) \
      + str(transaction_type).encode() \
      + instant_time_millisecond.to_bytes(8, byteorder='big') \
      + str(transaction_description).encode()
  st, _ = HashAndSign(bytearray.fromhex(private_key), tx_bytes)
  transaction_signature_data = {"r": st[0], "s": st[1]}
  body = {
      "hash": transaction_hash,
      "baseTransactions": base_transaction,
      "transactionDescription": transaction_description,
      "createTime": instant_time,
      "senderHash": public_key,
      "senderSignature": transaction_signature_data,
      "type": transaction_type,
      "trustScoreResults": [transaction_trust_score_data]
  }
  headers = {'Content-Type': "application/json"}

  res = http_pool_manager.request('PUT', full_node_address + "/transaction",
                                  body=json.dumps(body), headers=headers)
  if res.status not in http_ok_codes:
    raise Exception('error return code: ' + str(res.status) + ', data: ' + str(res.data))

  data = json.loads(res.data.decode("utf-8"))
  if data.get('status') == 'Error':
    raise Exception(data)

  api_call_times_logger.info("\t\t---> create_transaction: %s seconds <---" % round((time.time() - start_time), 3))

  return data
