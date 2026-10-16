from .models import Order, sum_items
from . import models as m
import json

MARKER = "fixture-literal-must-not-be-exported"


async def checkout(order):
    def audit():
        return json.dumps({})
    audit()
    Order()
    m.sum_items(order)
    return sum_items(order)
