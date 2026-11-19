"""Mock only the Factory boundary in existing transport/parser unit tests.

These isolated tests do not qualify authorization, source ownership, stop state,
or credentials. test_factory_stop uses the real service, PostgreSQL, SQLite and
API to qualify those boundaries. No production code imports this fixture.
"""
import hashlib
from unittest.mock import AsyncMock, Mock, patch


def mock_transport_factory_boundary(case):
    brief = ('Create an English landing page for a fictional local gardening club. '
             'One hero section. No links, prices, contacts or factual claims.')
    digest = hashlib.sha256(brief.encode()).hexdigest()
    def admitted(value, *, input_digest=None):
        return Mock(input_digest=input_digest or digest, content_sha256=digest,
                    check=Mock(return_value=None), check_async=AsyncMock(return_value=None))
    case.enterContext(patch('getzilla_factory.factory_stop.require_stop_capability', side_effect=admitted))
    case.enterContext(patch('getzilla_factory.factory_stop.require_factory_service', return_value=None))
