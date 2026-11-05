"""Public values only: internal construction never establishes native authority."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
import unittest

from getzilla import execution


class ContextConstructionTests(unittest.TestCase):
    def values(self):
        return {'workspace': '/public/value-only', 'session_id': 'public-session',
                'route_id': 'public-route', 'logical_task_id': 'task:public', 'authority_epoch': 0,
                'agent_id': None, 'agent_generation': None, '_observation_id': None,
                '_issuer': execution._ISSUER}

    def constructor_token(self):
        # The old implementation lacks this gate. Keep its positive RED an
        # intended assertion, not an import/setup error.
        return getattr(execution, '_CONSTRUCTION_TOKEN', None)

    def construct(self, **changes):
        values = {**self.values(), '_construction_token': self.constructor_token(), **changes}
        try:
            return execution.CallerContext(**values)
        except TypeError:
            self.fail('mandatory-capability value construction is unavailable')

    def test_valid_private_capabilities_produce_exact_initialized_public_values(self):
        context = self.construct()
        self.assertIs(type(context), execution.CallerContext)
        self.assertEqual(context.workspace, '/public/value-only')
        self.assertEqual(context.session_id, 'public-session')
        self.assertEqual(context.route_id, 'public-route')
        self.assertEqual(context.logical_task_id, 'task:public')
        self.assertEqual(context.authority_epoch, 0)
        self.assertIsNone(context.agent_id)
        self.assertIsNone(context.agent_generation)
        self.assertIsNone(context._observation_id)
        self.assertIs(context._issuer, execution._ISSUER)

    def test_initialized_context_rejects_normal_assignment_and_deletion(self):
        context = self.construct()
        with self.assertRaises(FrozenInstanceError):
            context.route_id = 'other-public-route'
        with self.assertRaises(FrozenInstanceError):
            del context.session_id
        self.assertEqual(context.route_id, 'public-route')
        self.assertEqual(context.session_id, 'public-session')

    def test_wrong_or_missing_issuer_value_has_fixed_refusal(self):
        for issuer in (None, object(), 'public-not-an-issuer'):
            with self.subTest(issuer_type=type(issuer).__name__):
                with self.assertRaises(execution.ExecutionError) as caught:
                    self.construct(_issuer=issuer)
                self.assertEqual(caught.exception.code, 'execution_forbidden')
                self.assertEqual(str(caught.exception), 'execution_forbidden')

    def test_constructor_token_is_distinct_and_wrong_values_refuse(self):
        self.assertIsNot(self.constructor_token(), execution._ISSUER)
        for token in (None, object(), execution._ISSUER):
            with self.subTest(token_type=type(token).__name__):
                with self.assertRaises(execution.ExecutionError) as caught:
                    self.construct(_construction_token=token)
                self.assertEqual(caught.exception.code, 'execution_forbidden')

    def test_both_capabilities_are_required_without_autoissue_defaults(self):
        values = self.values()
        with self.assertRaises(TypeError):
            execution.CallerContext(**values)
        values.pop('_issuer')
        with self.assertRaises(TypeError):
            execution.CallerContext(**values, _construction_token=self.constructor_token())
        with self.assertRaises(TypeError):
            execution.CallerContext(**values)

    def test_nonstored_token_cannot_be_reconstructed_from_stored_fields(self):
        context = self.construct()
        names = {item.name for item in fields(context)}
        self.assertEqual(names, {'workspace', 'session_id', 'route_id', 'logical_task_id',
                                'authority_epoch', 'agent_id', 'agent_generation',
                                '_observation_id', '_issuer'})
        self.assertFalse(hasattr(context, '_construction_token'))
        self.assertNotIn('_issuer=', repr(context))
        stored = {item.name: getattr(context, item.name) for item in fields(context)}
        with self.assertRaises(TypeError):
            execution.CallerContext(**stored)
        with self.assertRaises(execution.ExecutionError):
            execution.CallerContext(**stored, _construction_token=context._issuer)

    def test_replace_cannot_implicitly_clone_changed_scope_or_reuse_stored_issuer(self):
        context = self.construct()
        with self.assertRaises(ValueError):
            replace(context, route_id='other-public-route')
        with self.assertRaises(execution.ExecutionError):
            replace(context, route_id='other-public-route', _construction_token=context._issuer)
        self.assertEqual(context.route_id, 'public-route')

    def test_copy_preserves_value_without_recovering_nonstored_capability(self):
        context = self.construct()
        shallow = copy.copy(context)
        self.assertEqual(shallow, context)
        self.assertIs(shallow._issuer, context._issuer)
        self.assertFalse(hasattr(shallow, '_construction_token'))
        with self.assertRaises(ValueError):
            replace(shallow, agent_id='other-public-agent')
        deep = copy.deepcopy(context)
        self.assertEqual(deep.route_id, context.route_id)
        self.assertIsNot(deep._issuer, execution._ISSUER)
        self.assertFalse(hasattr(deep, '_construction_token'))
