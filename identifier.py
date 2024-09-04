import logging
from semantic import semantic_feature
from flow import data_flow

log = logging.getLogger(__name__)


class AttackIdentifier:

    def __init__(
        self,
        input_contract,
        contracts,
        main_contract_sign_list,
        external_call_in_func_sigature,
        visited_contracts,
        visited_funcs,
    ):
        self.contracts = contracts
        self.main_contract_sign_list = main_contract_sign_list
        self.external_call_in_func_sigature = external_call_in_func_sigature
        self.intra_callsigs = []
        self.sensitive_callsigs = []
        self.attack_matrix = {
            "sm": False,
            "intra": False,
            "intra_info": [],
            "inter": False,
            "inter_info": [],
        }
        self.visited_contracts = visited_contracts
        self.visited_funcs = visited_funcs
        self.victim_callback_info = {}
        self.attack_reenter_info = {}
        self.input_contract = input_contract
        self.flow_analysis = data_flow.FlowAnalysis(input_contract, contracts)

        self.semantic_analysis = semantic_feature.AttackSemantics(contracts)

    def detect(self):
        cross_contract = False
        for key in self.contracts.keys():
            if self.contracts[key].level != 0:
                cross_contract = True

        if not cross_contract:
            return False, self.attack_matrix

        result = False

        if self.semantic_analysis.op_externalcall_callback_analysis():
            self.attack_matrix["price_manipulation"] = True

        # so how to define the tainted source
        # !the tainted source should only be from the analyzed contracts (i.e., input contract)
        pps_near_source = self.flow_analysis.get_source_pps()
        # and how to define the sentive sink
        pps_near_sink = self.flow_analysis.get_sink_pps()

        # set call sigs in the sink site
        self.sensitive_callsigs = []

        reachable = False

        intra_analysis = False
        intra_info = []
        inter_analysis = False
        inter_info = []

        tainted_pps = []
        source_taint_trace = []

        visited = set()
        # for the source to taint
        for pp1 in pps_near_source:
            pending = [pp1]
            log.info("analyzing tainted source: {}".format(pp1))
            while len(pending) > 0:
                temp_pp = pending.pop()
                # Create a unique identifier for the dictionary
                temp_pp_id = (
                    temp_pp["contract_addr"],
                    temp_pp["func_sign"],
                    temp_pp["index"],
                )

                if temp_pp_id in visited:
                    continue  # Skip already visited program points
                visited.add(temp_pp_id)

                next_pps = self.flow_analysis.transfer(temp_pp)
                if len(next_pps) > 0:
                    for pp in next_pps:
                        tainted_slot = self.flow_analysis.spread_funcArg_taintedVar(
                            pp["contract_addr"], pp["func_sign"], pp["index"]
                        )
                        if len(tainted_slot) > 0:
                            trace = (pp1, pp, list(set(tainted_slot)))
                            tainted_pps.append(pp)
                            source_taint_trace.append(trace)
                            log.info(
                                "tainted trace that changes states by source: {}".format(
                                    trace
                                )
                            )
                        # Create a unique identifier for the dictionary
                        pp_id = (pp["contract_addr"], pp["func_sign"], pp["index"])
                        if pp_id not in visited:
                            pending.append(pp)
                else:  # current pp has no transfer node
                    tainted_slot = self.flow_analysis.spread_funcArg_taintedVar(
                        temp_pp["contract_addr"], temp_pp["func_sign"], temp_pp["index"]
                    )
                    if len(tainted_slot) > 0:
                        trace = (pp1, temp_pp, list(set(tainted_slot)))
                        tainted_pps.append(temp_pp)
                        source_taint_trace.append(trace)
                        log.info(
                            "tainted trace that changes states by source: {}".format(
                                trace
                            )
                        )
        log.info("finish analyzing source to taint states traces")
        log.info("source to taint states traces: {}".format(source_taint_trace))
        log.info("tainted pps: {}".format(tainted_pps))

        # from the source to sink
        # for every source, find whether one sink can be reached
        if not pps_near_source:
            log.warning("pps_near_source is empty")
        if not pps_near_sink:
            log.warning("pps_near_sink is empty")
        log.info("pps_near_source: {}".format(pps_near_source))
        log.info("pps_near_sink: {}".format(pps_near_sink))
        log.info("begin to analyze the source flow to sink")
        # for every source, find whether one sink (the afterward callStmt) can be reached
        for pp1 in pps_near_source:
            log.info(
                "analyzing source: {}, the call stmt is: {}".format(
                    pp1, pp1["callsite"]
                )
            )
            for pp2 in pps_near_sink:
                # log.info("Comparing pp1: {} with pp2: {}".format(pp1, pp2))
                if self.flow_analysis.is_same(pp1, pp2):
                    log.info("found same pp {}, {}".format(pp1, pp2))
                    involved_states = (
                        self.flow_analysis.get_state_flow_to_amount_by_callsite(
                            pp2["caller"], pp2["callsite"], pp2["caller_funcSign"]
                        )
                    )
                    log.info(
                        "the sink site read states from itself involved: {}".format(
                            involved_states
                        )
                    )
                    for trace in source_taint_trace:
                        # judge the source=>taint and source=>sink trace
                        is_after = self.flow_analysis.is_after(
                            pp1["caller"],
                            pp1["caller_funcSign"],
                            trace[0]["callsite"],
                            pp1["callsite"],
                        )
                        if is_after:
                            log.info(
                                "the source to sink call {} is after the source to taint call {}".format(
                                    pp1["callsite"], trace[0]["callsite"]
                                )
                            )
                        if trace[1]["contract_addr"] == pp2["caller"] and is_after:
                            bool = list(
                                set(involved_states).intersection(set(trace[2]))
                            )
                            if bool:
                                log.info(
                                    "(intra) the read states are influenced by the source=>taint trace: {}".format(
                                        trace
                                    )
                                )
                                log.info(
                                    "intra state manipulation in the same contract"
                                )
                                intra_analysis = True
                                intra_info.append([trace, pp2, bool])

                elif self.flow_analysis.is_reachable(pp1, pp2):
                    log.info("found reachable pp {}, {}".format(pp1, pp2))
                    involved_states = (
                        self.flow_analysis.get_state_flow_to_amount_by_callsite(
                            pp2["caller"], pp2["callsite"], pp2["caller_funcSign"]
                        )
                    )
                    log.info(
                        "the sink site read states from itself involved: {}".format(
                            involved_states
                        )
                    )
                    # intra analysis
                    for trace in source_taint_trace:
                        is_after = self.flow_analysis.is_after(
                            pp1["caller"],
                            pp1["caller_funcSign"],
                            trace[0]["callsite"],
                            pp1["callsite"],
                        )
                        if is_after:
                            log.info(
                                "the source to sink call {} is after the source to taint call {}".format(
                                    pp1["callsite"], trace[0]["callsite"]
                                )
                            )
                        if trace[1]["contract_addr"] == pp2["caller"] and is_after:
                            bool = list(
                                set(involved_states).intersection(set(trace[2]))
                            )
                            if bool:
                                log.info(
                                    "(intra) the read states are influenced by the source=>taint trace: {}".format(
                                        trace
                                    )
                                )
                                log.info(
                                    "intra state manipulation in the same contract"
                                )
                                intra_analysis = True
                                intra_info.append([trace, pp2, bool])
                    # then we should check the whether the states are influenced by the source=>taint flow
                    # inter analysis
                    log.info("begin inter procedure analysis")
                    # source: influenced state by source
                    # sink: the ret2sink site of the sink contract
                    # set the sink as the transfer amount
                    if pp2["func_sign"] == "0xa9059cbb":
                        pp2["index"] = (
                            1  # magically for test of standard transfer function
                        )
                    for trace in source_taint_trace:
                        contract_to_analysis = trace[1]
                        log.info(
                            "contract to analysis: {}".format(contract_to_analysis)
                        )
                        # find whether the tainted contract by precalls is called again for reading states
                        sources, slot = self.flow_analysis.get_pps_near_state_source(
                            contract_to_analysis["contract_addr"]
                        )

                        log.info(
                            "the pre influenced contracts with their return states info: {}".format(
                                slot
                            )
                        )
                        for source in sources:
                            # log.info("analyzing source: {}".format(source))
                            if self.flow_analysis.is_same(source, pp2):
                                is_after = self.flow_analysis.is_after(
                                    pp1["caller"],
                                    pp1["caller_funcSign"],
                                    trace[0]["callsite"],
                                    pp1["callsite"],
                                )
                                if is_after:
                                    log.info(
                                        "the source to sink call {} is after the source to taint call {}".format(
                                            pp1["callsite"], trace[0]["callsite"]
                                        )
                                    )
                                    reachable = True
                                    log.info(
                                        "tainted states flow to sink from source: {}".format(
                                            source
                                        )
                                    )
                                    log.critical(
                                        "can be affected by state at slot {} of contract {} at the return of function {}".format(
                                            slot[1][source["func_sign"]],
                                            slot[0],
                                            source["func_sign"],
                                        )
                                    )
                                    inter_analysis = True
                                    inter_info.append(
                                        [
                                            trace,
                                            pp2,
                                            source,
                                            (
                                                slot[1][source["func_sign"]],
                                                slot[0],
                                                source["func_sign"],
                                            ),
                                        ]
                                    )
                            elif self.flow_analysis.is_reachable(source, pp2):
                                is_after = self.flow_analysis.is_after(
                                    pp1["caller"],
                                    pp1["caller_funcSign"],
                                    trace[0]["callsite"],
                                    pp1["callsite"],
                                )
                                if is_after:
                                    log.info(
                                        "the source to sink call {} is after the source to taint call {}".format(
                                            pp1["callsite"], trace[0]["callsite"]
                                        )
                                    )
                                    reachable = True
                                    log.info(
                                        "tainted states flow to sink from source: {}".format(
                                            source
                                        )
                                    )
                                    log.critical(
                                        "can be affected by state at slot {} of contract {} at the return of function {}".format(
                                            slot[1][source["func_sign"]],
                                            slot[0],
                                            source["func_sign"],
                                        )
                                    )
                                    inter_analysis = True
                                    inter_info.append(
                                        [
                                            trace,
                                            pp2,
                                            source,
                                            (
                                                slot[1][source["func_sign"]],
                                                slot[0],
                                                source["func_sign"],
                                            ),
                                        ]
                                    )

        if reachable:
            # print("reachable")
            log.info("reachable")
            self.attack_matrix["is_attack"] = True
            # print(result)
            # print(self.attack_matrix)
            self.attack_matrix["sm"] = True
            self.attack_matrix["intra"] = intra_analysis
            self.attack_matrix["inter"] = inter_analysis
            self.attack_matrix["intra_info"] = intra_info
            self.attack_matrix["inter_info"] = inter_info
        return result, self.attack_matrix

    def get_reen_info(self):
        return self.victim_callback_info, self.attack_reenter_info

    def get_sig_info(self):
        return self.sensitive_callsigs

    def get_attack_matric(self):
        return self.attack_matrix
