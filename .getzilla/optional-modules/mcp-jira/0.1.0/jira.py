"""Bounded Jira source adapter. Official Atlassian HTTP/OAuth remains unqualified."""
import json


class Jira:
    def __init__(self, *, site, project, resources, manifest, runtime, access, effects=None):
        self.site, self.project, self.resources = site, project, frozenset(resources)
        self.manifest, self.runtime, self.access, self.effects = manifest, runtime, access, effects

    def normalize(self, tool, arguments):
        for _ in range(8):
            if tool not in {'executeWrite', 'executeRead'}:
                break
            if isinstance(arguments, str):
                if len(arguments.encode()) > 65536:
                    raise ValueError('jira_argument_limit')
                arguments = json.loads(arguments)
            if not isinstance(arguments, dict) or set(arguments) != {'operation', 'arguments'}:
                raise ValueError('jira_dispatcher_schema')
            tool, arguments = arguments['operation'], arguments['arguments']
        else:
            raise ValueError('jira_dispatcher_depth')
        capability = self.manifest.get(tool)
        if (not isinstance(capability, dict) or capability.get('class') not in {'read', 'write'}
                or any(name in tool.lower() for name in ('unified', 'enriched', 'teamworkgraph'))):
            raise ValueError('jira_capability_unqualified')
        if not isinstance(arguments, dict) or arguments.get('site') != self.site or arguments.get('project') != self.project:
            raise ValueError('jira_target_scope')
        resource = arguments.get('resource')
        if resource not in self.resources:
            raise ValueError('jira_resource_scope')
        operation = capability['operation']
        self.access.authorize(dict(site=self.site, project=self.project, resource=resource), operation)
        return tool, arguments, capability

    def read(self, tool, arguments, *, intent_key, hard_timeout_seconds=30):
        tool, arguments, capability = self.normalize(tool, arguments)
        if capability['class'] != 'read':
            raise ValueError('jira_read_only')
        result = self.runtime.call(tool=tool, arguments=arguments, intent_key=intent_key,
                                   hard_timeout_seconds=hard_timeout_seconds)
        # The access port admits each returned source before exposing even its
        # title/link/metadata. A broad service token is never an admission proof.
        return self.access.admit_result(result, site=self.site, project=self.project)

    def write(self, tool, arguments, *, execution_id, operation_id, baseline, acceptance=None):
        tool, arguments, capability = self.normalize(tool, arguments)
        if capability['class'] != 'write' or self.effects is None:
            raise ValueError('jira_write_unqualified')
        if capability['operation'] == 'close':
            self.access.validate_closure(arguments['resource'], acceptance)
        target = dict(site=self.site, project=self.project, resource=arguments['resource'])
        intent = self.effects.intent(execution_id, operation_id, target=target, operation=capability['operation'],
                            arguments=arguments, baseline=baseline)
        return self.effects.apply(intent['execution_id'], operation_id, arguments=arguments)
