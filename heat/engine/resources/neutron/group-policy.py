# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from heat.engine import clients
from heat.openstack.common import log as logging
from heat.engine import resource
from heat.engine import properties


if clients.neutronclient is not None:
    import neutronclient.common.exceptions as neutron_exp

logger = logging.getLogger(__name__)


class Endpoint(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, ENDPOINT_GROUP_ID
    ) = (
        'tenant_id', 'name', 'description', 'endpoint_group_id'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the endpoint.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the endpoint.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the endpoint.'),
            update_allowed=True
        ),
        ENDPOINT_GROUP_ID: properties.Schema(
            properties.Schema.STRING,
            _('Endpoint group id of the endpoint.'),
            required=True,
            update_allowed=True
        )
    }

    attributes_schema = {
        'neutron_port_id': _("Neutron port id of this endpoint")
    }

    def __init__(self, name, json_snippet, stack):
        super(Endpoint, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        ep = client.create_endpoint({'endpoint': props})['endpoint']

        self.resource_id_set(ep['id'])

    def _resolve_attribute(self, name):
        client = self.neutron()
        ep_id = self.resource_id
        if name == 'neutron_port_id':
            return client.show_endpoint(ep_id)['endpoint']['neutron_port_id']
        return super(Endpoint, self)._resolve_attribute(name)

    def handle_delete(self):

        client = self.neutron()
        ep_id = self.resource_id

        try:
            client.delete_endpoint(ep_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class EndpointGroup(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, BRIDGE_DOMAIN_ID, PROVIDED_CONTRACTS,
        CONSUMED_CONTRACTS
    ) = (
        'tenant_id', 'name', 'description', 'bridge_domain_id',
        'provided_contracts', 'consumed_contracts'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the endpoint group.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the endpoint group.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the endpoint group.'),
            update_allowed=True
        ),
        BRIDGE_DOMAIN_ID: properties.Schema(
            properties.Schema.STRING,
            _('Bridge domain id of the endpoint group.'),
            update_allowed=True
        ),
        PROVIDED_CONTRACTS: properties.Schema(
            properties.Schema.LIST,
            _('Provided contracts for the endpoint group.'),
            update_allowed=True
        ),
        CONSUMED_CONTRACTS: properties.Schema(
            properties.Schema.LIST,
            _('Consumed contracts for the endpoint group.'),
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(EndpointGroup, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        provided_contracts_list = {}
        consumed_contracts_list = {}
        props_provided_contracts = props.get('provided_contracts', [])
        props_consumed_contracts = props.get('consumed_contracts', [])

        for prop_prov_contract in props_provided_contracts:
            contract_id = prop_prov_contract['contract_id']
            contract_scope = prop_prov_contract['contract_scope']
            provided_contracts_list.update({contract_id: contract_scope})

        for prop_cons_contract in props_consumed_contracts:
            contract_id = prop_cons_contract['contract_id']
            contract_scope = prop_cons_contract['contract_scope']
            consumed_contracts_list.update({contract_id: contract_scope})

        if provided_contracts_list:
            props['provided_contracts'] = provided_contracts_list
        if consumed_contracts_list:
            props['consumed_contracts'] = consumed_contracts_list

        epg = client.create_endpoint_group(
            {'endpoint_group': props})['endpoint_group']

        self.resource_id_set(epg['id'])

    def handle_delete(self):

        client = self.neutron()
        epg_id = self.resource_id

        try:
            client.delete_endpoint_group(epg_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class Contract(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, CHILD_CONTRACTS, POLICY_RULES
    ) = (
        'tenant_id', 'name', 'description', 'child_contracts', 'policy_rules'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the contract.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the contract.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the contract.'),
            update_allowed=True
        ),
        CHILD_CONTRACTS: properties.Schema(
            properties.Schema.LIST,
            _('Child contracts list of the contract.'),
            required=True,
            update_allowed=True
        ),
        POLICY_RULES: properties.Schema(
            properties.Schema.LIST,
            _('Policy rules list for the contract.'),
            required=True,
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(Contract, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        contract = client.create_contract({'contract': props})['contract']

        self.resource_id_set(contract['id'])

    def handle_delete(self):

        client = self.neutron()
        contract_id = self.resource_id

        try:
            client.delete_contract(contract_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class ContractProvidingScope(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, ENDPOINT_GROUP_ID, SELECTOR_ID,
        CAPABILITIES
    ) = (
        'tenant_id', 'name', 'description', 'endpoint_group_id', 'selector_id',
        'capabilities'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the contract providing scope.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the contract providing scope.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the contract providing scope.'),
            update_allowed=True
        ),
        ENDPOINT_GROUP_ID: properties.Schema(
            properties.Schema.STRING,
            _('endpoint group id of the contract providing scope.'),
            required=True,
            update_allowed=True
        ),
        SELECTOR_ID: properties.Schema(
            properties.Schema.STRING,
            _('Selector id of the contract providing scope.'),
            required=True,
            update_allowed=True
        ),
        CAPABILITIES: properties.Schema(
            properties.Schema.LIST,
            _('Capabilities of the contract providing scope.'),
            required=True,
            update_allowed=True
        )

    }

    def __init__(self, name, json_snippet, stack):
        super(ContractProvidingScope, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        cps = client.create_contract_providing_scope(
            {'contract_providing_scope': props})['contract_providing_scope']

        self.resource_id_set(cps['id'])

    def handle_delete(self):

        client = self.neutron()
        cps_id = self.resource_id

        try:
            client.delete_contract_providing_scope(cps_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class ContractConsumingScope(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, ENDPOINT_GROUP_ID, SELECTOR_ID,
        ROLES
    ) = (
        'tenant_id', 'name', 'description', 'endpoint_group_id', 'selector_id',
        'roles'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the contract consuming scope.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the contract consuming scope.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the contract consuming scope.'),
            update_allowed=True
        ),
        ENDPOINT_GROUP_ID: properties.Schema(
            properties.Schema.STRING,
            _('endpoint group id of the contract consuming scope.'),
            required=True,
            update_allowed=True
        ),
        SELECTOR_ID: properties.Schema(
            properties.Schema.STRING,
            _('Selector id of the contract consuming scope.'),
            required=True,
            update_allowed=True
        ),
        ROLES: properties.Schema(
            properties.Schema.LIST,
            _('Roles of the contract consuming scope.'),
            required=True,
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(ContractConsumingScope, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        ccs = client.create_contract_consuming_scope(
            {'contract_consuming_scope': props})['contract_consuming_scope']

        self.resource_id_set(ccs['id'])

    def handle_delete(self):

        client = self.neutron()
        ccs_id = self.resource_id

        try:
            client.delete_contract_consuming_scope(ccs_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class PolicyRule(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, ENABLED, CONTRACT_FILTER_ID,
        POLICY_CLASSIFIER_ID, POLICY_ACTIONS
    ) = (
        'tenant_id', 'name', 'description', 'enabled', 'contract_filter_id',
        'policy_classifier_id', 'policy_actions'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the policy rule.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the policy rule.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the policy rule.'),
            update_allowed=True
        ),
        ENABLED: properties.Schema(
            properties.Schema.STRING,
            _('State of policy rule.'),
            update_allowed=True
        ),
        CONTRACT_FILTER_ID: properties.Schema(
            properties.Schema.STRING,
            _('Contract filter id of the policy rule.'),
            update_allowed=True
        ),
        POLICY_CLASSIFIER_ID: properties.Schema(
            properties.Schema.STRING,
            _('Classifier id attached to the policy rule.'),
            required=True,
            update_allowed=True
        ),
        POLICY_ACTIONS: properties.Schema(
            properties.Schema.LIST,
            _('Classifier id attached to the policy rule.'),
            required=True,
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(PolicyRule, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        policy_rule = client.create_policy_rule(
            {'policy_rule': props})['policy_rule']

        self.resource_id_set(policy_rule['id'])

    def handle_delete(self):

        client = self.neutron()
        policy_rule_id = self.resource_id

        try:
            client.delete_policy_rule(policy_rule_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class ContractFilter(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, PROVIDER_CAPABILITIES, CONSUMER_ROLES
    ) = (
        'tenant_id', 'name', 'description', 'provider_capabilities',
        'consumer_roles'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the contract filter.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the contract filter.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the contract filter.'),
            update_allowed=True
        ),
        PROVIDER_CAPABILITIES: properties.Schema(
            properties.Schema.LIST,
            _('Provider capabilities of the contract filter.'),
            required=True,
            update_allowed=True
        ),
        CONSUMER_ROLES: properties.Schema(
            properties.Schema.LIST,
            _('Consumer roles of the contract filter.'),
            required=True,
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(ContractFilter, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        contract_filter = client.create_contract_filter(
            {'contract_filter': props})['contract_filter']

        self.resource_id_set(contract_filter['id'])

    def handle_delete(self):

        client = self.neutron()
        contract_filter_id = self.resource_id

        try:
            client.delete_contract_filter(contract_filter_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class PolicyClassifier(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, PROTOCOL, PORT_RANGE, DIRECTION
    ) = (
        'tenant_id', 'name', 'description', 'protocol', 'port_range',
        'direction'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the policy classifier.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the policy classifier.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the policy classifier.'),
            update_allowed=True
        ),
        PROTOCOL: properties.Schema(
            properties.Schema.STRING,
            _('Protocol of the policy classifier.'),
            update_allowed=True
        ),
        PORT_RANGE: properties.Schema(
            properties.Schema.STRING,
            _('Port range of the policy classifier.'),
            update_allowed=True
        ),
        DIRECTION: properties.Schema(
            properties.Schema.STRING,
            _('Direction of the policy classifier.'),
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(PolicyClassifier, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        policy_classifier = client.create_policy_classifier(
            {'policy_classifier': props})['policy_classifier']

        self.resource_id_set(policy_classifier['id'])

    def handle_delete(self):

        client = self.neutron()
        classifier_id = self.resource_id

        try:
            client.delete_policy_classifier(classifier_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class PolicyAction(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, ACTION_TYPE, ACTION_VALUE
    ) = (
        'tenant_id', 'name', 'description', 'action_type', 'action_value'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the policy action.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the policy action.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the policy action.'),
            update_allowed=True
        ),
        ACTION_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('Type of the policy action.'),
            update_allowed=True
        ),
        ACTION_VALUE: properties.Schema(
            properties.Schema.STRING,
            _('Value of the policy action.'),
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(PolicyAction, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        policy_action = client.create_policy_action(
            {'policy_action': props})['policy_action']

        self.resource_id_set(policy_action['id'])

    def handle_delete(self):

        client = self.neutron()
        policy_action_id = self.resource_id

        try:
            client.delete_policy_action(policy_action_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class EndpointGroupSelector(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, SCOPE, VALUE
    ) = (
        'tenant_id', 'name', 'description', 'scope', 'value'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the endpoint group selector.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the endpoint group selector.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the endpoint group selector.'),
            update_allowed=True
        ),
        SCOPE: properties.Schema(
            properties.Schema.STRING,
            _('Scope of the endpoint group selector.'),
            update_allowed=True
        ),
        VALUE: properties.Schema(
            properties.Schema.STRING,
            _('Value of the endpoint group selector.'),
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(EndpointGroupSelector, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        egs = client.create_endpoint_group_selector(
            {'endpoint_group_selector': props})['endpoint_group_selector']

        self.resource_id_set(egs['id'])

    def handle_delete(self):

        client = self.neutron()
        egs_id = self.resource_id

        try:
            client.delete_endpoint_group_selector(egs_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class PolicyLabel(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, NAMESPACE
    ) = (
        'tenant_id', 'name', 'description', 'namespace'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the policy label.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the policy label.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the policy label.'),
            update_allowed=True
        ),
        NAMESPACE: properties.Schema(
            properties.Schema.STRING,
            _('Namespace of the policy label.'),
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(PolicyLabel, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        policy_label = client.create_policy_label(
            {'policy_label': props})['policy_label']

        self.resource_id_set(policy_label['id'])

    def handle_delete(self):

        client = self.neutron()
        policy_label_id = self.resource_id

        try:
            client.delete_policy_label(policy_label_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class BridgeDomain(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, ROUTING_DOMAIN_ID
    ) = (
        'tenant_id', 'name', 'description', 'routing_domain_id'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the bridge domain.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the bridge domain.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the bridge domain.'),
            update_allowed=True
        ),
        ROUTING_DOMAIN_ID: properties.Schema(
            properties.Schema.STRING,
            _('Routing domain id of the bridge domain.'),
            required=True,
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(BridgeDomain, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        bridge_domain = client.create_bridge_domain(
            {'bridge_domain': props})['bridge_domain']

        self.resource_id_set(bridge_domain['id'])

    def handle_delete(self):

        client = self.neutron()
        bridge_domain_id = self.resource_id

        try:
            client.delete_bridge_domain(bridge_domain_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


class RoutingDomain(resource.Resource):

    PROPERTIES = (
        TENANT_ID, NAME, DESCRIPTION, IP_VERSION, IP_SUPERNET,
        SUBNET_PREFIX_LENGTH
    ) = (
        'tenant_id', 'name', 'description', 'ip_version', 'ip_supernet',
        'subnet_prefix_length'
    )

    properties_schema = {
        TENANT_ID: properties.Schema(
            properties.Schema.STRING,
            _('Tenant id of the routing domain.')
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the routing domain.'),
            update_allowed=True
        ),
        DESCRIPTION: properties.Schema(
            properties.Schema.STRING,
            _('Description of the routing domain.'),
            update_allowed=True
        ),
        IP_VERSION: properties.Schema(
            properties.Schema.STRING,
            _('IP version of the routing domain.'),
            update_allowed=False
        ),
        IP_SUPERNET: properties.Schema(
            properties.Schema.STRING,
            _('IP super of routing domain.'),
            update_allowed=False
        ),
        SUBNET_PREFIX_LENGTH: properties.Schema(
            properties.Schema.INTEGER,
            _('Subnet prefix length of routing domain.'),
            update_allowed=True
        )
    }

    def __init__(self, name, json_snippet, stack):
        super(RoutingDomain, self).__init__(name, json_snippet, stack)

    def handle_create(self):
        client = self.neutron()

        props = {}
        for key in self.properties:
            if self.properties.get(key) is not None:
                props[key] = self.properties.get(key)

        routing_domain = client.create_routing_domain(
            {'routing_domain': props})['routing_domain']

        self.resource_id_set(routing_domain['id'])

    def handle_delete(self):

        client = self.neutron()
        routing_domain_id = self.resource_id

        try:
            client.delete_routing_domain(routing_domain_id)
        except neutron_exp.NeutronClientException as ex:
            self._handle_not_found_exception(ex)

    def handle_update(self, json_snippet):
        return self.UPDATE_REPLACE


def resource_mapping():

    if clients.neutronclient is None:
        return {}

    return {
        'OS::Neutron::Endpoint': Endpoint,
        'OS::Neutron::EndpointGroup': EndpointGroup,
        'OS::Neutron::Contract': Contract,
        'OS::Neutron::ContractProvidingScope': ContractProvidingScope,
        'OS::Neutron::ContractConsumingScope': ContractConsumingScope,
        'OS::Neutron::PolicyRule': PolicyRule,
        'OS::Neutron::ContractFilter': ContractFilter,
        'OS::Neutron::PolicyClassifier': PolicyClassifier,
        'OS::Neutron::PolicyAction': PolicyAction,
        'OS::Neutron::EndpointGroupSelector': EndpointGroupSelector,
        'OS::Neutron::PolicyLabel': PolicyLabel,
        'OS::Neutron::BridgeDomain': BridgeDomain,
        'OS::Neutron::RoutingDomain': RoutingDomain,
    }
