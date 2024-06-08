import logging
import os

from flow.token_flow import TokenFlowAnalysis
import global_params
import pandas as pd

log = logging.getLogger(__name__)


class FlowAnalysis:

    def __init__(
        self,
        input_contract,
        contracts,
    ):
        self.contracts = contracts
        self.input_contract = input_contract
        self.token_flow_analysis = TokenFlowAnalysis(input_contract, contracts)
        self.token_flow_analysis.set_token_flows()

    # helper
    def find_executed_pp(self, caller, callsite, contract_addr, func_sign):
        addr = ""
        level = -1
        for key in self.contracts.keys():
            temp = key.split("_")
            if (temp[0] == caller) and (temp[1] == callsite) and (temp[3] == func_sign):
                if addr == "":
                    # temp[2] is the logic address
                    addr = temp[2]
                    level = self.contracts[key].level
                else:
                    if self.contracts[key].level > level:
                        addr = temp[2]
                        level = self.contracts[key].level
        return addr

    def new_pp(
        self, caller, callsite, contract_addr, func_sign, index, caller_funcSign, type
    ):
        # find the contract address that the current program point executes (with the highest level)
        addr = self.find_executed_pp(caller, callsite, contract_addr, func_sign)
        return {
            "caller": caller,
            "callsite": callsite,
            "contract_addr": addr,
            "func_sign": func_sign,
            "index": index,
            "caller_funcSign": caller_funcSign,
            "type": type,
        }

    def is_same(self, pp1, pp2):
        pp1_str = (
            pp1["caller"]
            + "_"
            + pp1["callsite"]
            + "_"
            + pp1["func_sign"]
            + "_"
            + str(pp1["index"])
            + "_"
            + pp1["type"]
        )
        pp2_str = (
            pp2["caller"]
            + "_"
            + pp2["callsite"]
            + "_"
            + pp2["func_sign"]
            + "_"
            + str(pp2["index"])
            + "_"
            + pp2["type"]
        )
        if pp1_str == pp2_str:
            return True
        else:
            return False

    # find which contract call the logic_addr contract
    def find_parent(self, logic_addr, funcSign, caller, call_site):
        for key in self.contracts.keys():
            for external_call in self.contracts[key].external_calls:
                if (
                    (external_call["logic_addr"] == logic_addr)
                    and (external_call["funcSign"] == funcSign)
                    and (external_call["caller"] == caller)
                    and (external_call["call_site"] == call_site)
                ):
                    return self.contracts[key]
        return None

    # find the corresponding contract
    def find_contract(
        self, caller, callsite, contract_addr, func_sign, caller_funcSign
    ):
        return self.contracts[
            caller
            + "_"
            + callsite
            + "_"
            + contract_addr
            + "_"
            + func_sign
            + "_"
            + caller_funcSign
        ]

    # get the external call from the callsite
    def get_external_call_info(self, call_site, external_calls):
        for external_call in external_calls:
            if external_call["call_site"] == call_site:
                return (
                    external_call["caller"],
                    external_call["logic_addr"],
                    external_call["funcSign"],
                )
        return (None, None, None)

    def get_external_call_known_arg_info(self, call_site, external_calls):
        for external_call in external_calls:
            if external_call["call_site"] == call_site:
                log.info(external_call["known_args"])
                return {call_site: external_call["known_args"]}  # {index: value}
        return

    # define the source of the input contract (attacker contract context)
    def get_source_pps(self):
        pps_near_source = []
        for key in self.contracts.keys():
            temp_caller = key.split("_")[0]
            temp_callsite = key.split("_")[1]
            temp_address = key.split("_")[2]
            temp_funcSign = key.split("_")[3]

            # only mark the input contract's source
            if self.contracts[key].level == 0:
                # get the caller function of the main contract (attack-initiate contract)
                temp_caller_funcSign = self.contracts[key].func_sign

                # get the taint source: function arguments of the function
                temp_call_args = self.get_tainted_callargs_initiated_by_source(
                    temp_address, temp_caller_funcSign
                )
                # log.info(temp_call_args)
                if len(temp_call_args) > 0:
                    # get details of the external call
                    for temp_call_arg in temp_call_args:
                        (
                            temp_external_call_caller,
                            temp_external_call_logic_addr,
                            temp_external_call_func_sign,
                        ) = self.get_external_call_info(
                            temp_call_arg["callStmt"],
                            self.contracts[key].external_calls,
                        )
                        pps_near_source.append(
                            self.new_pp(
                                temp_external_call_caller,
                                temp_call_arg["callStmt"],
                                temp_external_call_logic_addr,
                                temp_external_call_func_sign,
                                temp_call_arg["callArgIndex"],
                                temp_caller_funcSign,
                                "call_arg",
                            )
                        )
        log.info("sources initiated by input contract: {}".format(pps_near_source))
        return pps_near_source

    def get_sink_pps(self):
        pps_near_sink = []

        for key in self.contracts.keys():
            temp_caller = key.split("_")[0]
            temp_callsite = key.split("_")[1]
            temp_address = key.split("_")[2]
            temp_funcSign = key.split("_")[3]
            # the function that sink site lies in
            temp_caller_funcSign = key.split("_")[4]
            # log.info(temp_caller_funcSign)
            # get the taint sink: function arguments of the call arg to callee address

            if self.contracts[key].level > 0:  # not the caller itself
                temp_callsites = self.get_callsites_flow_from_func_arg(
                    temp_address, temp_funcSign
                )
                if len(temp_callsites) > 0:
                    for temp_callsite in temp_callsites:
                        (
                            temp_external_call_caller,
                            temp_external_call_logic_addr,
                            temp_external_call_func_sign,
                        ) = self.get_external_call_info(
                            temp_callsite["callStmt"],
                            self.contracts[key].external_calls,
                        )
                        pps_near_sink.append(
                            self.new_pp(
                                temp_external_call_caller,
                                temp_callsite["callStmt"],
                                temp_external_call_logic_addr,
                                temp_external_call_func_sign,
                                temp_callsite["callArgIndex"],
                                self.contracts[key].func_sign,
                                "call_arg",
                            )
                        )
        print("sinks that transfer to the input contract: {}".format(pps_near_sink))
        return pps_near_sink

    def get_tainted_callargs_initiated_by_source(self, contract_addr, func_sign):
        call_args = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_SM_TaintedSourceCallArg.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = ["funcSign", "callStmt", "callArgIndex"]
            df = df.loc[df["funcSign"] == func_sign]
            for i in range(len(df)):
                call_args.append(
                    {
                        "callStmt": df.iloc[i]["callStmt"],
                        "callArgIndex": df.iloc[i]["callArgIndex"],
                    }
                )
        return call_args

    def get_callsites_flow_to_sink(self, contract_addr, func_sign):
        callsites = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_SM_CallRetToSensitiveVar.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "funcSign",
                "callStmt",
                "callRetVar",
                "callRetIndex",
                "sensitiveVar",
            ]
            df = df.loc[df["funcSign"] == func_sign]
            for i in range(len(df)):
                callsites.append(
                    {
                        "callStmt": df.iloc[i]["callStmt"],
                        "callRetIndex": df.iloc[i]["callRetIndex"],
                    }
                )
        return callsites

    def get_func_rets_flow_from_states(self, contract_addr, func_sign):
        slot_index = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_SM_StateVarToFuncReturn.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = ["funcSign", "slot", "var", "retIndex", "ret"]
            df = df.loc[df["funcSign"] == func_sign]
            if len(df) != 0:
                for i in range(len(df)):
                    slot_index.append(df.iloc[i]["slot"])
                return list(df["retIndex"]), slot_index
            else:
                return [], []
        else:
            return [], []

    def get_pps_near_state_source(self, contract_addr):
        pps_near_source = []
        slot_index = {}
        for key in self.contracts.keys():
            temp_caller = key.split("_")[0]
            temp_callsite = key.split("_")[1]
            temp_address = key.split("_")[2]
            temp_funcSign = key.split("_")[3]
            temp_caller_funcSign = key.split("_")[4]

            if self.contracts[key].level > 0 and temp_address == contract_addr:
                temp_indexes, read_states = self.get_func_rets_flow_from_states(
                    temp_address, temp_funcSign
                )
                slot_index[temp_funcSign] = list(set(read_states))
                if len(temp_indexes) > 0:
                    for temp_index in temp_indexes:
                        pps_near_source.append(
                            self.new_pp(
                                temp_caller,
                                temp_callsite,
                                temp_address,
                                temp_funcSign,
                                temp_index,
                                temp_caller_funcSign,
                                "func_ret",
                            )
                        )
        return pps_near_source, (contract_addr, slot_index)

    # state sink
    def get_pps_near_state_sink(self, contract_addr):
        pps_near_sink = []
        for key in self.contracts.keys():
            temp_caller = key.split("_")[0]
            temp_callsite = key.split("_")[1]
            temp_address = key.split("_")[2]
            temp_funcSign = key.split("_")[3]
            temp_caller_funcSign = key.split("_")[4]

            if self.contracts[key].level > 0 and temp_address == contract_addr:
                temp_callsites = self.get_callsites_flow_to_sink(
                    temp_address, temp_funcSign
                )
                if len(temp_callsites) > 0:
                    for temp_callsite in temp_callsites:
                        (
                            temp_external_call_caller,
                            temp_external_call_logic_addr,
                            temp_external_call_func_sign,
                        ) = self.get_external_call_info(
                            temp_callsite["callStmt"],
                            self.contracts[key].external_calls,
                        )
                        pps_near_sink.append(
                            self.new_pp(
                                temp_external_call_caller,
                                temp_callsite["callStmt"],
                                temp_external_call_logic_addr,
                                temp_external_call_func_sign,
                                temp_callsite["callRetIndex"],
                                self.contracts[key].func_sign,
                                "func_ret",
                            )
                        )

    def get_state_flow_to_amount_by_callsite(self, contract_addr, callsite, funcSign):
        states = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_SM_SensitiveCall.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = ["funcSign", "callStmt", "recipient", "amount"]
            df = df.loc[(df["funcSign"] == funcSign)]
            for i in range(len(df)):
                if df.iloc[i]["callStmt"] == callsite:
                    states.extend(
                        self.intra_analysis_sensitive_var_flow_from_tainted_state(
                            contract_addr, df.iloc[i]["amount"], funcSign
                        )
                    )
        return list(set(states))

    def intra_analysis_sensitive_var_flow_from_tainted_state(
        self, contract_addr, amount, funcSign
    ):
        state_read = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_SM_SensitiveVar.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = ["funcSign", "slot", "recipient", "amount"]
            df = df.loc[df["amount"] == amount]
            for i in range(len(df)):
                if df.iloc[i]["funcSign"] == funcSign:
                    state_read.append(df.iloc[i]["slot"])
        return state_read

    # another sink: func arg to sensitive var
    def get_callsites_flow_from_func_arg(self, contract_addr, func_sign):
        callsites = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_SM_SensitiveSink.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "funcSign",
                "callStmt",
                "recipient",
                "recipientIndex",
                "amount",
            ]
            df = df.loc[df["funcSign"] == func_sign]
            for i in range(len(df)):
                callsites.append(
                    {
                        "callStmt": df.iloc[i]["callStmt"],
                        "callArgIndex": df.iloc[i]["recipientIndex"],
                    }
                )

        return callsites

    # spread: only functions as variable pass and transfer
    def spread_callRet_funcRet(self, contract_addr, call_stmt, func_sign, ret_index):
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_Spread_CallRetToFuncRet.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "callStmt",
                "callRet",
                "callRetIndex",
                "funcSign",
                "funcRetIndex",
                "funcRet",
            ]
            df = df.loc[
                (df["callStmt"] == call_stmt)
                & (df["callRetIndex"] == ret_index)
                & (df["funcSign"] == func_sign)
            ]
            if len(df) != 0:
                return list(df["funcRetIndex"])
            else:
                return []
        else:
            return []

    def spread_callRet_CallArg(self, contract_addr, call_stmt, ret_index):
        callArgs = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_Spread_CallRetToCallArg.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "callStmt1",
                "callRet",
                "callRetIndex",
                "callStmt2",
                "callArgIndex",
                "callArg",
            ]
            df = df.loc[
                (df["callStmt1"] == call_stmt) & (df["callRetIndex"] == ret_index)
            ]
            for i in range(len(df)):
                callArgs.append(
                    {
                        "callStmt": df.iloc[i]["callStmt2"],
                        "callArgIndex": df.iloc[i]["callArgIndex"],
                    }
                )
        return callArgs

    def spread_funcArg_callArg(self, contract_addr, funcSign, funcArgIndex):
        callArgs = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_Spread_FuncArgToCallArg.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "funcSign",
                "funcArgIndex",
                "funcArg",
                "callStmt",
                "callArgIndex",
                "callArg",
            ]
            df = df.loc[
                (df["funcSign"] == funcSign) & (df["funcArgIndex"] == funcArgIndex)
            ]
            for i in range(len(df)):
                callArgs.append(
                    {
                        "callStmt": df.iloc[i]["callStmt"],
                        "callArgIndex": df.iloc[i]["callArgIndex"],
                    }
                )
        return callArgs

    def spread_funcArg_callee(self, contract_addr, funcSign, funcArgIndex):
        callArgs = []
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_Spread_FuncArgToCalleeVar.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "funcSign",
                "funcArgIndex",
                "funcArg",
                "callStmt",
                "callArgIndex",
            ]
            df = df.loc[
                (df["funcSign"] == funcSign) & (df["funcArgIndex"] == funcArgIndex)
            ]
            for i in range(len(df)):
                # funcarg flows to themselves, must be true
                callArgs.append(
                    {
                        "callStmt": df.iloc[i]["callStmt"],
                        "callArgIndex": df.iloc[i]["funcArgIndex"],
                    }
                )
        return callArgs

    def spread_funcArg_funcRet(self, contract_addr, funcSign, funcArgIndex):
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_Spread_FuncArgToFuncRet.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "funcSign",
                "funcArgIndex",
                "funcArg",
                "funcRetIndex",
                "funcRet",
            ]
            df = df.loc[
                (df["funcSign"] == funcSign) & (df["funcArgIndex"] == funcArgIndex)
            ]
            if len(df) != 0:
                return list(df["funcRetIndex"])
            else:
                return []
        else:
            return []

    def spread_funcArg_taintedVar(self, contract_addr, funcSign, funcArgIndex):
        loc = (
            global_params.OUTPUT_PATH
            + ".temp/"
            + contract_addr
            + "/out/Leslie_Spread_FuncArgToTaintedVar.csv"
        )
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = [
                "funcSign",
                "funcArgIndex",
                "funcArg",
                "slot",
                "taintedVar",
            ]
            df = df.loc[
                (df["funcSign"] == funcSign) & (df["funcArgIndex"] == funcArgIndex)
            ]
            if len(df) != 0:
                return list(df["slot"])  # label the influenced slot
            else:
                return []
        else:
            return []

    # from tainted source flows to sink
    def transfer(self, pp):
        # log.info(pp)
        next_pps = []
        # log.info(pp["caller_funcSign"])
        parent_contract = self.find_parent(
            pp["contract_addr"], pp["func_sign"], pp["caller"], pp["callsite"]
        )
        # log.info(parent_contract.logic_addr)
        # log.info(parent_contract.caller)
        # log.info(parent_contract.func_sign)
        try:
            child_contract = self.find_contract(
                pp["caller"],
                pp["callsite"],
                pp["contract_addr"],
                pp["func_sign"],
                pp["caller_funcSign"],
            )
            # log.info(child_contract.logic_addr)
            # log.info(child_contract.caller)
            # log.info(child_contract.func_sign)
        except Exception:
            return next_pps

        # apply spread transfer for func_ret and call_arg, respectively
        if pp["type"] == "func_ret":
            if parent_contract is not None:
                # find the return context's caller
                parent_of_parent_contract = self.find_parent(
                    parent_contract.logic_addr,
                    parent_contract.func_sign,
                    parent_contract.caller,
                    parent_contract.call_site,
                )
                indexes = self.spread_callRet_funcRet(
                    pp["caller"], pp["callsite"], parent_contract.func_sign, pp["index"]
                )
                for index in indexes:
                    next_pps.append(
                        self.new_pp(
                            parent_contract.caller,
                            parent_contract.call_site,
                            parent_contract.logic_addr,
                            parent_contract.func_sign,
                            index,
                            parent_of_parent_contract.func_sign,
                            "func_ret",
                        )
                    )

            callArgs = self.spread_callRet_CallArg(
                pp["caller"], pp["callsite"], pp["index"]
            )
            # print(pp["caller"])
            # print(callArgs)
            # print(child_contract.logic_addr)
            # print(child_contract.caller)
            # print(child_contract.external_calls)
            # print(parent_contract.logic_addr)
            # print(parent_contract.caller)
            for callArg in callArgs:
                (
                    temp_caller,
                    temp_logic_addr,
                    temp_func_sign,
                ) = self.get_external_call_info(
                    callArg["callStmt"], parent_contract.external_calls
                )
                if (
                    temp_caller is not None
                    and temp_logic_addr is not None
                    and temp_func_sign is not None
                ):
                    next_pps.append(
                        self.new_pp(
                            temp_caller,
                            callArg["callStmt"],
                            temp_logic_addr,
                            # temp func sign is the called function that lies in the attacker contract
                            temp_func_sign,
                            callArg["callArgIndex"],
                            pp["caller_funcSign"],
                            "call_arg",
                        )
                    )
            # print("----from one pp to next pps------")
            # print(pp)
            # print(next_pps)
            # log.info(next_pps)

        if pp["type"] == "call_arg":
            callArgs = []
            # function arg to call arg and callee var
            callArgs += self.spread_funcArg_callArg(
                pp["contract_addr"], pp["func_sign"], pp["index"]
            )

            for callArg in callArgs:
                temp_result = self.get_external_call_info(
                    callArg["callStmt"], child_contract.external_calls
                )
                # log.info(temp_result)
                if temp_result is not None:
                    temp_caller, temp_logic_addr, temp_func_sign = temp_result
                else:
                    continue
                next_pps.append(
                    self.new_pp(
                        pp["contract_addr"],
                        callArg["callStmt"],
                        temp_logic_addr,
                        temp_func_sign,
                        callArg["callArgIndex"],
                        pp["func_sign"],
                        "call_arg",
                    )
                )
                # log.info(next_pps)
            # the return index of the function call
            indexes = self.spread_funcArg_funcRet(
                pp["contract_addr"], pp["func_sign"], pp["index"]
            )
            for index in indexes:
                next_pps.append(
                    self.new_pp(
                        pp["caller"],
                        pp["callsite"],
                        pp["contract_addr"],
                        pp["func_sign"],
                        index,
                        pp["caller_funcSign"],
                        "func_ret",
                    )
                )
        return next_pps

    def is_reachable(self, pp1, pp2):
        if self.is_same(pp1, pp2):
            return True
        pending = [pp1]
        while len(pending) > 0:
            temp_pp = pending.pop()
            for pp in self.transfer(temp_pp):
                if self.is_same(pp, pp2):
                    # log.info(pp)
                    # log.info(pp2)
                    return True
                else:
                    pending.append(pp)
        return False
