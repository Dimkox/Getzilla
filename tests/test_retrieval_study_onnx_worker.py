import importlib
import builtins
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class StudyOnnxWorkerTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_onnx_worker')
        except ModuleNotFoundError:
            self.fail('fixed ONNX worker data plane is missing')

    def setup_runtime(self, *, output_shape=None, providers=None, input_type='tensor(int64)'):
        seen = {}
        class Session:
            def get_inputs(self):
                return [SimpleNamespace(name=name, type=input_type, shape=['batch', 'seq'])
                        for name in ('input_ids', 'attention_mask', 'token_type_ids')]

            def get_outputs(self):
                return [SimpleNamespace(name='hidden', type='tensor(float)',
                                        shape=output_shape or ['batch', 'seq', 384])]

            def get_providers(self):
                return providers or ['CPUExecutionProvider']
        def create(path, *, sess_options, providers):
            seen.update(path=path, options=sess_options, providers=providers)
            return Session()
        ort = SimpleNamespace(SessionOptions=SimpleNamespace, InferenceSession=create)
        return ort, seen

    def contract(self, owner):
        return owner.ModelContract('minilm', ('input_ids', 'attention_mask', 'token_type_ids'),
                                   'hidden', ('batch', 'seq'), ('batch', 'seq', 384))

    def test_fixed_cpu_single_thread_and_exact_inspected_signature(self):
        owner = self.owner()
        ort, seen = self.setup_runtime()
        owner._open_session('/model/onnx/model.onnx', self.contract(owner), ort)
        self.assertEqual(seen['providers'], ['CPUExecutionProvider'])
        self.assertEqual(seen['options'].intra_op_num_threads, 1)
        self.assertEqual(seen['options'].inter_op_num_threads, 1)
        self.assertEqual(seen['path'], '/model/onnx/model.onnx')

    def test_already_pooled_wrong_dtype_or_provider_refuse(self):
        owner = self.owner()
        for kwargs in ({'output_shape': ['batch', 384]}, {'input_type': 'tensor(int32)'},
                       {'providers': ['CUDAExecutionProvider']}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, 'onnx_contract_mismatch'):
                ort, _ = self.setup_runtime(**kwargs)
                owner._open_session('/model/onnx/model.onnx', self.contract(owner), ort)

    def test_missing_signature_does_not_infer_names_or_dimension(self):
        owner = self.owner()
        with self.assertRaises(ValueError):
            owner.ModelContract('bge_m3', ('input_ids',), 'hidden', ('batch', 'seq'),
                                ('batch', 'seq', 384))

    def test_bge_binds_both_actual_outputs_selecting_only_raw_token_states(self):
        owner = self.owner()
        shape = ('batch_size', 'sequence_length')
        pooled = ('batch_size', 'Divsentence_embedding_dim_1')
        contract = owner.ModelContract('bge_m3', ('input_ids', 'attention_mask'),
            'token_embeddings', shape, shape + (1024,),
            (('sentence_embedding', 'tensor(float)', pooled),))
        session = SimpleNamespace(
            get_providers=lambda: ['CPUExecutionProvider'],
            get_inputs=lambda: [SimpleNamespace(name=name, type='tensor(int64)', shape=list(shape))
                                for name in contract.inputs],
            get_outputs=lambda: [SimpleNamespace(name='token_embeddings', type='tensor(float)',
                                                 shape=list(shape) + [1024]),
                                 SimpleNamespace(name='sentence_embedding', type='tensor(float)',
                                                 shape=list(pooled))])
        ort = SimpleNamespace(SessionOptions=SimpleNamespace,
                              InferenceSession=lambda *args, **kwargs: session)
        self.assertIs(owner._open_session('/model/onnx/model.onnx', contract, ort), session)

    def test_import_is_inert_and_no_optional_package_is_loaded_by_status(self):
        owner = self.owner()
        original = builtins.__import__
        def deny_optional(name, *args, **kwargs):
            if name.split('.')[0] in {'numpy', 'onnxruntime', 'tokenizers', 'tiktoken',
                                      'socket', 'subprocess'}:
                self.fail('disabled worker imported an execution dependency')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=deny_optional):
            owner = importlib.reload(owner)
            self.assertEqual(owner.runtime_status(), {'status': 'unavailable',
                             'reason': 'owned_runtime_admission_required', 'model_loaded': False})

    def test_actual_output_rank_and_finiteness_refuse_before_pooling(self):
        owner = self.owner()
        contract = self.contract(owner)
        counter = SimpleNamespace(encode_one=lambda text: SimpleNamespace(
            ids=(1, 2), raw_tokens=2, truncated=False))
        for shape, finite in (((1, 384), True), ((1, 2, 384), False)):
            result = SimpleNamespace(dtype='float32', ndim=len(shape), shape=shape)
            session = SimpleNamespace(run=lambda names, inputs: [result])
            fake = SimpleNamespace(int64='int64', float32='float32',
                asarray=lambda data, dtype: object(), ones_like=lambda data: object(),
                zeros_like=lambda data: object(),
                isfinite=lambda data: SimpleNamespace(all=lambda: finite))
            with self.subTest(shape=shape), self.assertRaisesRegex(ValueError,
                                                                 'onnx_output_contract_mismatch'):
                owner._encode_one(session, contract, counter, 'tiny', fake)
