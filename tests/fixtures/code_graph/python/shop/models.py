class Order:
    def total(self):
        return sum_items(self)

    class Line:
        def total(self):
            return 0


def sum_items(order):
    return 0
