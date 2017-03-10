"""Functions for interacting with devices."""
import time
import uuid


def _wrap_binary(binary):
    """Add a signifier to the beginning and end of a binary block."""
    return b'qS' + binary + b'EL'


def write_vendor_card(minigrid_id, vendor):
    """Write information to a vendor ID card."""
    block_4 = _wrap_binary(b''.join((
        b'A',  # A for vendor
        vendor.vendor_user_id.encode(),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    )))
    block_5 = _wrap_binary(uuid.UUID(minigrid_id).bytes)
    block_6 = _wrap_binary(bytes(16))  # other information

    # TODO write to device
    print('=' * 60)
    print(block_4.hex())
    print(block_5.hex())
    print(block_6.hex())
    print('=' * 60)


def write_customer_card(minigrid_id, customer):
    """Write information to a customer ID card."""
    block_4 = _wrap_binary(b''.join((
        b'B',  # B for customer
        customer.customer_user_id.encode(),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    )))
    block_5 = _wrap_binary(uuid.UUID(minigrid_id).bytes)
    block_6 = _wrap_binary(bytes(16))  # other information

    # TODO write to device
    print('=' * 60)
    print(block_4.hex())
    print(block_5.hex())
    print(block_6.hex())
    print('=' * 60)


def write_credit_card(minigrid_id, credit_amount, day_tariff, night_tariff):
    """Write information to a credit card."""
    block_4 = _wrap_binary(b''.join((
        b'C',  # C for credit
        b'\1',  # 1 for int
        credit_amount.to_bytes(4, 'big'),  # 4 byte unsigned int
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(2),  # intentionally empty
        bytes(4),  # card read time TODO
    )))
    block_5 = _wrap_binary(uuid.uuid4().bytes)
    block_6 = _wrap_binary(uuid.UUID(minigrid_id).bytes)
    block_8 = _wrap_binary(b''.join((
        b'\1',  # 1 for int
        bytes(4),  # tariff 1 validate time??? TODO
        (int(day_tariff * 100)).to_bytes(4, 'big'),  # day tariff in cents
        bytes(7),  # intentionally empty
    )))
    block_9 = _wrap_binary(b''.join((
        b'\1',  # 1 for int
        bytes(4),  # tariff 2 validate time??? TODO
        (int(night_tariff * 100)).to_bytes(4, 'big'),  # night tariff in cents
        bytes(7),  # intentionally empty
    )))
    block_10 = _wrap_binary(b''.join((
        bytes(4),  # time of these 2 tariff was created??? TODO
        bytes(4),  # time to start use tariff??? TODO
        bytes(8),  # intentionally empty
    )))

    # TODO write to device
    print('=' * 60)
    print(block_4.hex())
    print(block_5.hex())
    print(block_6.hex())
    print(block_8.hex())
    print(block_9.hex())
    print(block_10.hex())
    print('=' * 60)
