import unittest

from getzilla.security_image_producer import PG, require_factory_pin


class FactoryDigestTests(unittest.TestCase):
    def test_factory_requires_the_reviewed_immutable_postgres_image(self):
        pins = {"postgres": {"reference": "postgres@sha256:" + PG}}
        row = {"manifest": "factory/compose.yaml", "source_reference": "postgres:17-alpine@sha256:" + PG}
        require_factory_pin([row], pins)
        for invalid in ("postgres:17-alpine", "postgres:17-alpine@sha256:" + "a" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                require_factory_pin([dict(row, source_reference=invalid)], pins)
