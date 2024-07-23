import argparse
import json
import logging
import os
import shutil
import time

import numpy as np

import global_params
from contract import Contract
from graph.call_graph import CallGraph
from identifier import AttackIdentifier

magic_callback = [
    "0x10d1e85c",
    "0xf04f2707",
    "0xe9cbafb0",
    "0x84800812",
    "0xa1d48336",
    "0xeb2021c3",
    "0x7ed1f1dd",
    "0x920f5c84",
    "0x23e30c8b",
]


def convert_types(obj):
    if isinstance(obj, np.int64):
        return int(obj)
    elif isinstance(obj, np.float64):
        return float(obj)
    elif isinstance(obj, list):
        return [convert_types(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_types(item) for item in obj)
    elif isinstance(obj, dict):
        return {key: convert_types(value) for key, value in obj.items()}
    return obj


if __name__ == "__main__":
    # Main Body
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-bp",
        "--blockchain_platform",
        help="The blockchain platform where the test contract is deployed",
        action="store",
        dest="platform",
        type=str,
        default="ETH",
    )
    parser.add_argument(
        "-la",
        "--logic_address",
        help="Contract address for storing business logic",
        action="store",
        dest="logic_addr",
        type=str,
    )
    parser.add_argument(
        "-sa",
        "--storage_address",
        help="Contract address for storing business data",
        action="store",
        dest="storage_addr",
        type=str,
        default="",
    )
    parser.add_argument(
        "-bn",
        "--block_number",
        help="Blockchain snapshot",
        action="store",
        dest="block_number",
        type=int,
        default=16000000,
    )
    parser.add_argument(
        "-fs",
        "--function_signature",
        help="The function signature to be analyzed",
        action="store",
        dest="func_sign",
        type=str,
        default="",
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose output, print everything.", action="store_true"
    )
    parser.add_argument(
        "-d",
        "--directory",
        help="contract directory.",
        action="store",
        dest="contract_dir",
        type=str,
        default="",
    )
    args = parser.parse_args()

    file_handler = logging.FileHandler("logs/{}.log".format(args.logic_addr), mode="w")
    file_handler.setLevel(logging.INFO if args.verbose else logging.WARNING)
    formatter = logging.Formatter(
        fmt="[%(levelname)s][%(filename)s:%(lineno)d]: %(message)s",
        datefmt="%Y.%m.%d. %H:%M:%S",
    )
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.addHandler(file_handler)

    root_logger.setLevel(logging.INFO if args.verbose else logging.WARNING)

    log = logging.getLogger(__name__)

    contracts = {}
    # default: storage_addr is the same as logic_addr
    storage_addr = ""
    if args.storage_addr == "":
        storage_addr = args.logic_addr
    else:
        storage_addr = args.storage_addr
    if args.contract_dir != "":
        # global_params.CONTRACT_PATH = "../get_x_code/output/" + args.contract_dir + "/"
        global_params.CONTRACT_PATH = "./contracts/" + args.contract_dir + "/"
        print(f"Contract path: {global_params.CONTRACT_PATH}")
        # global_params.CONTRACT_DIR = (
        #     "../../get_x_code/output/" + args.contract_dir + "/"
        # )
        global_params.CONTRACT_DIR = "../contracts/" + args.contract_dir + "/"
    log.info("testing function signature {}...".format(args.func_sign))
    source = {
        "platform": args.platform,
        "logic_addr": args.logic_addr,
        "storage_addr": storage_addr,
        "func_sign": "",
        "block_number": args.block_number,
        "caller": "msg.sender",  # assume the attacker EOA
        "caller_func_sign": "",  # default trace all functions (with external calls)
        "call_site": "",  # default blank
        "level": 0,  # trace depth
        "callArgVals": {},
    }
    begin = time.perf_counter()

    call_paths = []

    original_contract = Contract(
        source["platform"],
        source["logic_addr"],
        source["storage_addr"],
        source["func_sign"],
        source["block_number"],
        source["caller"],
        source["call_site"],
        source["level"],
        source["callArgVals"],
    )
    result = {
        "is_attack": False,
        "warning": "medium",
        "attack_matrix": {},
        "analysis_loc": "",
        "platform": args.platform,
        "block_number": args.block_number,
        "time": None,
        "semantic_features": {
            "op_creation": {
                "op_multicreate": False,
                "op_solecreate": False,
            },
            "op_selfdestruct": False,
            "op_env": False,
        },
        "external_call": {
            "externalcall_inhook": False,
            "externalcall_infallback": False,
        },
        "call_paths": [],
        "visited_contracts": [],
        "visited_contracts_num": 0,
        "visited_funcs": [],
        "visited_funcs_num": 0,
        "max_call_depth": 0,
    }

    func_sign_list = original_contract.get_func_sign_list()
    if len(list(set(func_sign_list).intersection(set(magic_callback)))) == 0:
        log.info("no flashloan callback implemented!")
        end = time.perf_counter()

        res = {}
        res[args.logic_addr] = result
        result["time"] = end - begin

        print(res)

        store_path = global_params.JSON_PATH + args.logic_addr + ".json"
        # uncomment if not need to rewrite
        # if not os.path.exists(store_path):
        with open(store_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(res, indent=2, ensure_ascii=False))
        if os.path.exists(global_params.TEMP_WORKING_DIR + args.logic_addr):
            shutil.rmtree(global_params.TEMP_WORKING_DIR + args.logic_addr)
        exit(0)

    if args.func_sign == "":
        external_call_in_func_sigature = (
            original_contract.get_external_call_in_func_sigature()
        )
    else:
        external_call_in_func_sigature = [args.func_sign]

    # store the signatures of functions that contain external calls
    store_external_call_in_func_sigature_list = []
    for i in external_call_in_func_sigature:
        store_external_call_in_func_sigature_list.append(i)

    visited_contracts = []
    visited_funcs = []
    # the max call depths of a contract
    m_call_depth = 0

    # if no runtime bin, just run __function_selector__ for the createbin
    is_createbin = original_contract.is_createbin()
    call_graph_str = ""
    if is_createbin:
        max_call_depth = 0
        source = {
            "platform": args.platform,
            "logic_addr": args.logic_addr,
            "storage_addr": storage_addr,
            "func_sign": "",
            "block_number": args.block_number,
            "caller": "msg.sender",
            "caller_func_sign": "",
            "call_site": "",
            "level": 0,
        }
        source["func_sign"] = "__function_selector__"
        cross_contract_call_graph = CallGraph(source, contracts, source["platform"])
        cross_contract_call_graph.construct_cross_contract_call_graph()
        visited_contracts = (
            visited_contracts + cross_contract_call_graph.visited_contracts
        )
        visited_funcs = visited_funcs + cross_contract_call_graph.visited_funcs
        m_call_depth = cross_contract_call_graph.max_level

        call_graph_str = cross_contract_call_graph.get_output()
        call_paths.append(call_graph_str)
    else:
        # run all pub funs and remove function selector
        if "__function_selector__" in external_call_in_func_sigature:
            external_call_in_func_sigature.remove("__function_selector__")

        # external_call_in_func_sigature = ["0xa1d48336"]
        max_call_depth = 0
        # for every functions that contains external calls
        while len(external_call_in_func_sigature) > 0:
            source = {
                "platform": args.platform,
                "logic_addr": args.logic_addr,
                "storage_addr": storage_addr,
                "func_sign": "",
                "block_number": args.block_number,
                "caller": "msg.sender",
                "caller_func_sign": "",
                "call_site": "",
                "level": 0,
                "callArgVals": {},
            }
            source["func_sign"] = external_call_in_func_sigature.pop(0)
            cross_contract_call_graph = CallGraph(source, contracts, source["platform"])
            cross_contract_call_graph.construct_cross_contract_call_graph()
            visited_contracts = (
                visited_contracts + cross_contract_call_graph.visited_contracts
            )
            visited_funcs = visited_funcs + cross_contract_call_graph.visited_funcs
            call_depth = cross_contract_call_graph.max_level

            if call_depth > max_call_depth:
                max_call_depth = call_depth

            call_graph_str = cross_contract_call_graph.get_output()
            call_paths.append(call_graph_str)

        m_call_depth = max_call_depth

    detector = AttackIdentifier(
        source["logic_addr"],
        contracts,
        func_sign_list,
        store_external_call_in_func_sigature_list,
        visited_contracts,
        visited_funcs,
    )

    result["is_attack"], result["attack_matrix"] = detector.detect()
    result["call_paths"] = call_paths

    result["max_call_depth"] = m_call_depth

    result["visited_contracts"] = list(set(visited_contracts))
    result["visited_contracts_num"] = len(list(set(visited_contracts)))
    result["visited_funcs"] = list(set(visited_funcs))
    result["visited_funcs_num"] = len(list(set(visited_funcs)))

    result["semantic_features"]["op_creation"][
        "op_multicreate"
    ] = detector.semantic_analysis.op_multicreate_analysis()
    result["semantic_features"]["op_creation"][
        "op_solecreate"
    ] = detector.semantic_analysis.op_solecreate_analysis()
    result["semantic_features"][
        "op_selfdestruct"
    ] = detector.semantic_analysis.op_selfdestruct_analysis()

    result["external_call"][
        "externalcall_inhook"
    ] = detector.semantic_analysis.externalcall_inhook()
    result["external_call"][
        "externalcall_infallback"
    ] = detector.semantic_analysis.externalcall_infallback()

    if is_createbin:
        result["analysis_loc"] = "createbin"
    else:
        result["analysis_loc"] = "runtimebin"

    end = time.perf_counter()

    res = {}
    res[args.logic_addr] = result
    result["time"] = end - begin

    print(res)

    store_path = global_params.JSON_PATH + args.logic_addr + ".json"
    # uncomment if not need to rewrite
    # if not os.path.exists(store_path):
    converted_data = convert_types(res)
    with open(store_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(converted_data, indent=2, ensure_ascii=False))

    # uncomment if need remove temp files
    # for contract in list(set(visited_contracts)):
    #     if os.path.exists(global_params.TEMP_WORKING_DIR + contract):
    #         shutil.rmtree(global_params.TEMP_WORKING_DIR + contract)
