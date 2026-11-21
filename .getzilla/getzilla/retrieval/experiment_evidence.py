"""Research promotion boundary. Actual native publication is not attached yet.

Local lifecycle/report hashes, reviewer labels and historical seals are facts,
not independence. There is deliberately no issuer or fixture production path.
"""
from .budget import RetrievalError


class _UnavailableRef:
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        raise TypeError('actual native publication reference required')


class ReviewedInputsRef(_UnavailableRef):
    __slots__ = ()


class PhaseARef(_UnavailableRef):
    __slots__ = ()


class PhaseBRef(_UnavailableRef):
    __slots__ = ()


def verify_phase_a(_observations=None):
    """Refuse until fixed composition observes real native launch and delivery."""
    raise RetrievalError('native_publication_unbound')


def verify_phase_b(_observations=None):
    """Source consistency cannot substitute for reviewed actual artifact facts."""
    raise RetrievalError('native_publication_unbound')


def status():
    return {'status': 'unavailable', 'reason': 'native_publication_unbound',
            'ranking_permitted': False, 'phase_a': 'unavailable', 'phase_b': 'unavailable'}
