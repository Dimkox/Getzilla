"""Closed ONNX data plane for a separately admitted, owned offline process.

This leaf never launches a worker or grants execution. Optional modules are
imported only by the supervisor's guarded worker entry, not on import/status.
ModelContract is inspected data, not Phase B, source or resource authority.
"""
from __future__ import annotations

from concurrent.futures import CancelledError
from dataclasses import dataclass

from .budget import RetrievalError


def runtime_status():
    return {'status': 'unavailable', 'reason': 'owned_runtime_admission_required',
            'model_loaded': False}


def _shape(value):
    return (type(value) is tuple and len(value) in {2, 3}
            and all(item is None or type(item) is int and item > 0
                    or type(item) is str and 0 < len(item) <= 128
                    and item.isascii() and item.isprintable() for item in value))


@dataclass(frozen=True)
class ModelContract:
    model: str
    inputs: tuple[str, ...]
    output: str
    input_shape: tuple
    output_shape: tuple
    additional_outputs: tuple = ()

    def __post_init__(self):
        if (type(self.model) is not str or self.model not in {'minilm', 'bge_m3'}
                or type(self.inputs) is not tuple
                or not self.inputs or any(type(name) is not str for name in self.inputs)
                or len(set(self.inputs)) != len(self.inputs)
                or set(self.inputs) - {'input_ids', 'attention_mask', 'token_type_ids'}
                or not {'input_ids', 'attention_mask'} <= set(self.inputs)
                or type(self.output) is not str or not 0 < len(self.output) <= 128
                or not self.output.isascii() or not self.output.isprintable()
                or not _shape(self.input_shape) or len(self.input_shape) != 2
                or not _shape(self.output_shape) or len(self.output_shape) != 3
                or self.output_shape[:2] != self.input_shape
                or self.output_shape[2] != {'minilm': 384, 'bge_m3': 1024}[self.model]
                or type(self.additional_outputs) is not tuple or len(self.additional_outputs) > 1):
            raise RetrievalError('onnx_contract_mismatch')
        names = {self.output}
        for item in self.additional_outputs:
            if (type(item) is not tuple or len(item) != 3 or type(item[0]) is not str
                    or not item[0] or len(item[0]) > 128 or not item[0].isascii()
                    or not item[0].isprintable() or item[0] in names
                    or item[1] != 'tensor(float)' or not _shape(item[2])):
                raise RetrievalError('onnx_contract_mismatch')
            names.add(item[0])


def _open_session(graph_path, contract, ort):
    if type(contract) is not ModelContract or graph_path != '/model/onnx/model.onnx':
        raise RetrievalError('onnx_contract_mismatch')
    try:
        options = ort.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        session = ort.InferenceSession(graph_path, sess_options=options,
                                       providers=['CPUExecutionProvider'])
        inputs, outputs = session.get_inputs(), session.get_outputs()
        if (session.get_providers() != ['CPUExecutionProvider']
                or tuple(item.name for item in inputs) != contract.inputs
                or any(item.type != 'tensor(int64)' or tuple(item.shape) != contract.input_shape
                       for item in inputs)
                or len(outputs) != 1 + len(contract.additional_outputs)
                or outputs[0].name != contract.output
                or outputs[0].type != 'tensor(float)'
                or tuple(outputs[0].shape) != contract.output_shape
                or any((actual.name, actual.type, tuple(actual.shape)) != expected
                       for actual, expected in zip(outputs[1:], contract.additional_outputs))):
            raise RetrievalError('onnx_contract_mismatch')
        return session
    except (CancelledError, RetrievalError):
        raise
    except Exception:
        raise RetrievalError('onnx_runtime_unavailable') from None


def _encode_one(session, contract, counter, text, np):
    """Fixed batch1 FP32 publisher pooling; supervisor owns wall-clock kill.

NumPy performs the same operations/dtypes as the published mean implementation;
the scalar reference helper is deliberately not used for model inference.
"""
    encoded = counter.encode_one(text)
    inputs = np.asarray([encoded.ids], dtype=np.int64)
    mask = np.ones_like(inputs)
    available = {'input_ids': inputs, 'attention_mask': mask,
                 'token_type_ids': np.zeros_like(inputs)}
    try:
        result = session.run([contract.output], {name: available[name] for name in contract.inputs})[0]
        dimension = contract.output_shape[2]
        if (result.dtype != np.float32 or result.ndim != 3
                or tuple(result.shape) != (1, len(encoded.ids), dimension)
                or not np.isfinite(result).all()):
            raise RetrievalError('onnx_output_contract_mismatch')
        if contract.model == 'minilm':
            pooled = (result * mask[:, :, None]).sum(axis=1) / mask.sum(axis=1)[:, None]
        else:
            pooled = result[:, 0, :]
        pooled = pooled / np.maximum(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-12)
        vector = pooled.astype(np.float32)
        if tuple(vector.shape) != (1, dimension) or not np.isfinite(vector).all():
            raise RetrievalError('onnx_output_contract_mismatch')
        return {'vector': vector[0].tolist(), 'raw_tokens': encoded.raw_tokens,
                'truncated': encoded.truncated}
    except (CancelledError, RetrievalError):
        raise
    except Exception:
        raise RetrievalError('onnx_encoder_unavailable') from None
