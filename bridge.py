from web3 import Web3
from web3.providers.rpc import HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware #Necessary for POA chains
from datetime import datetime
import json
import pandas as pd


def connect_to(chain):
    if chain == 'source':  # The source contract chain is avax
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc" #AVAX C-chain testnet

    if chain == 'destination':  # The destination contract chain is bsc
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/" #BSC testnet

    if chain in ['source','destination']:
        w3 = Web3(Web3.HTTPProvider(api_url))
        # inject the poa compatibility middleware to the innermost layer
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_contract_info(chain, contract_info):
    """
        Load the contract_info file into a dictionary
        This function is used by the autograder and will likely be useful to you
    """
    try:
        with open(contract_info, 'r')  as f:
            contracts = json.load(f)
    except Exception as e:
        print( f"Failed to read contract info\nPlease contact your instructor\n{e}" )
        return 0
    return contracts[chain]



def scan_blocks(chain, contract_info="contract_info.json"):
    """
        chain - (string) should be either "source" or "destination"
        Scan the last 5 blocks of the source and destination chains
        Look for 'Deposit' events on the source chain and 'Unwrap' events on the destination chain
        When Deposit events are found on the source chain, call the 'wrap' function the destination chain
        When Unwrap events are found on the destination chain, call the 'withdraw' function on the source chain
    """

    # This is different from Bridge IV where chain was "avax" or "bsc"
    if chain not in ['source','destination']:
        print( f"Invalid chain: {chain}" )
        return 0
    
    try:
        with open(contract_info, "r") as f:
            info = json.load(f)
    except Exception as e:
        print(f"Failed to read {contract_info}: {e}")
        return 0

    # private key must be provided INSIDE contract_info.json under one of these:
    #   info["warden"]["private_key"]  OR  info["private_key"]
    # (No extra imports allowed, so we don't read env vars here.)
    privkey = None
    if isinstance(info.get("warden"), dict):
        privkey = info["warden"].get("private_key")
    if not privkey:
        privkey = info.get("private_key")
    if not privkey:
        print("Missing warden private key in contract_info.json (expected at warden.private_key or private_key).")
        return 0

    # connect to both chains
    w3_src = connect_to('source')
    w3_dst = connect_to('destination')

    # build contract objects
    try:
        src_addr = Web3.to_checksum_address(info["source"]["address"])
        dst_addr = Web3.to_checksum_address(info["destination"]["address"])
        src_abi  = info["source"]["abi"]
        dst_abi  = info["destination"]["abi"]
    except Exception as e:
        print(f"Bad contract_info structure: {e}")
        return 0

    src = w3_src.eth.contract(address=src_addr, abi=src_abi)
    dst = w3_dst.eth.contract(address=dst_addr, abi=dst_abi)

    # signer (same EOA across both EVM testnets)
    try:
        acct_src = w3_src.eth.account.from_key(privkey)
        acct_dst = w3_dst.eth.account.from_key(privkey)
    except Exception as e:
        print(f"Invalid private key: {e}")
        return 0

    # simple nonce managers (no extra imports)
    nonce_src = w3_src.eth.get_transaction_count(acct_src.address)
    nonce_dst = w3_dst.eth.get_transaction_count(acct_dst.address)

    def send_tx(w3, acct, built_tx, use_src: bool):
        nonlocal nonce_src, nonce_dst

        # start from the tx built by .build_transaction(...)
        tx = dict(built_tx)
        tx["from"] = acct.address
        tx["nonce"] = nonce_src if use_src else nonce_dst
    
        # ---- estimate gas on a clean copy (NO fee/chain fields here) ----
        est = dict(tx)
        # make sure none of these leak into estimate:
        for k in ("chainId", "chain_id", "gasPrice", "gas_price", "maxFeePerGas", "max_fee_per_gas", "maxPriorityFeePerGas", "max_priority_fee_per_gas"):
            est.pop(k, None)
        try:
            tx["gas"] = w3.eth.estimate_gas(est)
        except Exception:
            tx["gas"] = 600_000
    
        # ---- ADD FEE + CHAIN FIELDS AFTER ESTIMATE (web3 v6 names) ----
        tx["gas_price"] = w3.eth.gas_price         # legacy gas works on BSC & Fuji
        tx["chain_id"]  = w3.eth.chain_id
    
        # sign & send
        signed = w3.eth.account.sign_transaction(tx, private_key=privkey)
        txh = w3.eth.send_raw_transaction(signed.rawTransaction)
        rcpt = w3.eth.wait_for_transaction_receipt(txh, timeout=120)
    
        if use_src:
            nonce_src += 1
        else:
            nonce_dst += 1
    
        return rcpt

    made = 0

    if chain == 'source':
        # scan Fuji for Deposit(token, recipient, amount)
        latest = w3_src.eth.block_number
        from_block = max(0, latest - 5)
        try:
            events = src.events.Deposit.create_filter(from_block=from_block, to_block='latest').get_all_entries()
        except Exception:
            events = src.events.Deposit().get_logs(from_block=from_block, to_block='latest')

        if not events:
            print("No Deposit events found on source in last 5 blocks.")
            return 0

        for e in events:
            a = e["args"]
            token     = Web3.to_checksum_address(a["token"])
            recipient = Web3.to_checksum_address(a["recipient"])
            amount    = int(a["amount"])
            
            tx = dst.functions.wrap(token, recipient, amount).build_transaction({"from": acct_dst.address})
            rcpt = send_tx(w3_dst, acct_dst, tx, use_src=False)

            print(f"wrap() -> {rcpt.transactionHash.hex()}")
            made += 1

        return 1 if made else 0

    # chain == 'destination'
    latest = w3_dst.eth.block_number
    from_block = max(0, latest - 5)
    try:
        events = dst.events.Unwrap.create_filter(from_block=from_block, to_block='latest').get_all_entries()
    except Exception:
        events = dst.events.Unwrap().get_logs(from_block=from_block, to_block='latest')

    if not events:
        print("No Unwrap events found on destination in last 5 blocks.")
        return 0

    for e in events:
        a = e["args"]
        underlying = Web3.to_checksum_address(a["underlying_token"])
        to_addr    = Web3.to_checksum_address(a["to"])
        amount     = int(a["amount"])
        
        tx = src.functions.withdraw(underlying, to_addr, amount).build_transaction({"from": acct_src.address})
        rcpt = send_tx(w3_src, acct_src, tx, use_src=True)

        print(f"withdraw() -> {rcpt.transactionHash.hex()}")
        made += 1

    return 1 if made else 0
