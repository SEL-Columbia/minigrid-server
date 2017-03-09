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
