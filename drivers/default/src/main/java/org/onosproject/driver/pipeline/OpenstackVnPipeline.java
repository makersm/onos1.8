/*
 * Copyright 2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.driver.pipeline;

import com.sun.org.apache.bcel.internal.generic.Instruction;
import org.onlab.osgi.ServiceDirectory;
import org.onlab.packet.EthType;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.PipelinerContext;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.*;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.Collections;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Driver for CSDNCM OpenVSwitch.
 */
public class OpenstackVnPipeline extends DefaultSingleTablePipeline
        implements Pipeliner {

    private static final String CSDNCM_APP_ID = "org.iris4sdn.csdncm";
    private static final String APP_ID = "org.onosproject.driver.OpenstackVnPipeline";
    private final Logger log = getLogger(getClass());
    private CoreService coreService;
    private ServiceDirectory serviceDirectory;
    protected FlowObjectiveStore flowObjectiveStore;
    protected DeviceId deviceId;
    protected ApplicationId appId;
    protected FlowRuleService flowRuleService;
    private static final int TIME_OUT = 0;
    private enum TABLE {
        CLASSIFIER(0), ARP(10), L3FWD(20), MAC(30);
        int value;
        TABLE(int value){
            this.value = value;
        }
        public int getValue() {
            return value;
        }
    }
    private static final int TABLE_MISS_PRIORITY = 0;

    @Override
    public void init(DeviceId deviceId, PipelinerContext context) {
        super.init(deviceId, context);
        this.serviceDirectory = context.directory();
        this.deviceId = deviceId;

        coreService = serviceDirectory.get(CoreService.class);
        flowRuleService = serviceDirectory.get(FlowRuleService.class);
        flowObjectiveStore = context.store();
        appId = coreService.registerApplication(APP_ID);

        initializePipeline();
        log.info("Started");
    }

    @Override
    public void filter(FilteringObjective filteringObjective) {
        super.filter(filteringObjective);
    }

    @Override
    public void forward(ForwardingObjective fwd) {
        if (!(fwd.appId().name().startsWith(CSDNCM_APP_ID))) {
            super.forward(fwd);
            return;
        }

        Collection<FlowRule> rules;
        FlowRuleOperations.Builder flowOpsBuilder = FlowRuleOperations.builder();

        rules = processForward(fwd);
        switch (fwd.op()) {
            case ADD:
                rules.stream().filter(rule -> rule != null).forEach(flowOpsBuilder::add);
                break;
            case REMOVE:
                rules.stream().filter(rule -> rule != null).forEach(flowOpsBuilder::remove);
                break;
            default:
                fail(fwd, ObjectiveError.UNKNOWN);
                log.warn("Unknown forwarding type {}", fwd.op());
        }

        flowRuleService.apply(flowOpsBuilder.build(
                new FlowRuleOperationsContext() {
                    @Override
                    public void onSuccess(FlowRuleOperations ops) {
                        pass(fwd);
                    }

                    @Override
                    public void onError(FlowRuleOperations ops) {
                        fail(fwd, ObjectiveError.FLOWINSTALLATIONFAILED);
                    }
                })
        );
    }

    @Override
    public void next(NextObjective nextObjective) {
        super.next(nextObjective);
    }

    private void initializePipeline() {
        processFlowTables(true);
    }

    private void processFlowTables(boolean install) {
        for(TABLE table : TABLE.values())
            processFlowTable(table.getValue(), install);
    }

    private void processFlowTable(int table, boolean install) {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();

        if(table == TABLE.MAC.getValue())
            treatment.drop();
        else
            treatment.transition(TABLE.MAC.getValue());

        FlowRule rule;
        rule = DefaultFlowRule.builder().forDevice(deviceId)
                .withSelector(selector.build())
                .withTreatment(treatment.build())
                .withPriority(TABLE_MISS_PRIORITY).fromApp(appId)
                .makePermanent().forTable(table).build();

        applyRules(install, rule);
    }

    private void applyRules(boolean install, FlowRule rule) {
        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();

        ops = install ? ops.add(rule) : ops.remove(rule);
        flowRuleService.apply(ops.build(new FlowRuleOperationsContext() {
            @Override
            public void onSuccess(FlowRuleOperations ops) {
                log.info("CSDNCM provisioned " + rule.tableId() + " table");
            }

            @Override
            public void onError(FlowRuleOperations ops) {
                log.info("CSDNCM failed to provision " + rule.tableId() + " table");
            }
        }));
    }

    private Collection<FlowRule> processForward(ForwardingObjective fwd) {
        switch (fwd.flag()) {
            case SPECIFIC:
                return processSpecific(fwd);
            case VERSATILE:
                return processVersatile(fwd);
            default:
                fail(fwd, ObjectiveError.UNKNOWN);
                log.warn("Unknown forwarding flag {}", fwd.flag());
        }
        return Collections.emptySet();
    }

    private Collection<FlowRule> processVersatile(ForwardingObjective fwd) {
        return Collections.emptyList();
    }

    private Collection<FlowRule> processSpecific(ForwardingObjective fwd) {
        TrafficSelector selector = fwd.selector();
        TrafficTreatment treatment = fwd.treatment();

        FlowRule.Builder ruleBuilder = DefaultFlowRule.builder()
                .fromApp(fwd.appId()).withPriority(fwd.priority())
                .forDevice(deviceId).withSelector(selector)
                .withTreatment(treatment).makeTemporary(fwd.timeout())
                .withPriority(fwd.priority());

        if (fwd.permanent()) {
            ruleBuilder.makePermanent();
        }

        Integer transition = null;
        Integer forTable = null;

        // MAC table flow rules
        if ((selector.getCriterion(Type.TUNNEL_ID) != null && selector.getCriterion(Type.ETH_DST) != null)
                // TODO drop
                || treatment.allInstructions().contains(Instructions.createNoAction())){
            forTable = TABLE.MAC.getValue();
            return reassemblyFlowRule(ruleBuilder, treatment, transition, forTable);
        }

        // CLASSIFIER table flow rules
        if (selector.getCriterion(Type.IN_PORT) != null) {
            forTable = TABLE.CLASSIFIER.getValue();
            transition = TABLE.MAC.getValue();
            if (selector.getCriterion(Type.ETH_SRC) != null && selector.getCriterion(Type.ETH_DST) != null) {
                transition = TABLE.L3FWD.getValue();
            } else if (selector.getCriterion(Type.ETH_SRC) != null || selector.getCriterion(Type.TUNNEL_ID) != null) {
                transition = TABLE.MAC.getValue();
            } else if (selector.getCriterion(Type.ETH_TYPE) != null && selector.getCriterion(Type.ETH_TYPE).equals(
                    Criteria.matchEthType(EthType.EtherType.ARP.ethType().toShort())
            )) {
                transition = null;
            }
            return reassemblyFlowRule(ruleBuilder, treatment, transition, forTable);
        }

        if (selector.getCriterion(Type.ETH_TYPE) != null
                && selector.getCriterion(Type.ETH_TYPE).equals(Criteria
                                                                       .matchEthType(EthType.EtherType.ARP.ethType().toShort()))) {
            // CLASSIFIER table arp flow rules
            if (selector.getCriterion(Type.TUNNEL_ID) == null) {
                transition = TABLE.ARP.getValue();
                forTable = TABLE.CLASSIFIER.getValue();
            } else {
                // ARP table flow rules
                transition = null;
                forTable = TABLE.ARP.getValue();
            }
            return reassemblyFlowRule(ruleBuilder, treatment, transition, forTable);
        }

        // L3FWD table flow rules
        if (selector.getCriterion(Type.TUNNEL_ID) != null) {
            forTable = TABLE.L3FWD.getValue();
            if (selector.getCriterion(Type.IPV4_DST) != null) {
                transition = TABLE.MAC.getValue();
            } else {
                transition = null;
            }
            return reassemblyFlowRule(ruleBuilder, treatment, transition, forTable);
        }

        return Collections.singletonList(ruleBuilder.build());
    }

    private Collection<FlowRule> reassemblyFlowRule(FlowRule.Builder ruleBuilder,
                                                    TrafficTreatment treatment,
                                                    Integer transition,
                                                    Integer forTable) {
        if (transition != null) {
            TrafficTreatment.Builder newTraffic = DefaultTrafficTreatment.builder();
            treatment.allInstructions().forEach(newTraffic::add);
            newTraffic.transition(transition);
            ruleBuilder.withTreatment(newTraffic.build());
        } else {
            ruleBuilder.withTreatment(treatment);
        }
        if (forTable != null) {
            ruleBuilder.forTable(forTable);
        }
        return Collections.singletonList(ruleBuilder.build());
    }

    private void fail(Objective obj, ObjectiveError error) {
        if (obj.context().isPresent()) {
            obj.context().get().onError(obj, error);
        }
    }

    private void pass(Objective obj) {
        if (obj.context().isPresent()) {
            obj.context().get().onSuccess(obj);
        }
    }
}
