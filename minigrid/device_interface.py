"""Functions for interacting with devices."""
import time
import uuid


def _wrap_binary(binary):
    """Add a signifier to the beginning and end of a binary block."""
    return b'qS' + binary + b'EL'


def write_vendor_card(minigrid_id, vendor):
    """Write information to a vendor ID card."""
    block_4 = b''.join((
        b'A',  # A for vendor
        vendor.vendor_user_id.encode(),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    ))
    block_5 = uuid.UUID(minigrid_id).bytes
    block_6 = bytes(16)  # other information

    message = _wrap_binary(block_4 + block_5 + block_6)

    # TODO write to device
    print('=' * 60)
    print(message.hex())
    print('=' * 60)


def write_customer_card(cache, minigrid_id, customer):
    """Write information to a customer ID card."""
    block_4 = b''.join((
        b'B',  # B for customer
        customer.customer_user_id.encode(),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    ))
    block_5 = uuid.UUID(minigrid_id).bytes
    block_6 = bytes(16)  # other information

    message = _wrap_binary(block_4 + block_5 + block_6)

    cache.set('device_info', message, 5)

    # TODO write to device
    print('=' * 60)
    print(cache.get('device_active'))
    print(cache.get('device_info'))
    print(cache.get('received_info'))
    print(message.hex())
    print('=' * 60)


def _hour_on_epoch_day(hour_int):
    return (hour_int * 3600).to_bytes(4, 'big')


def write_credit_card(
        minigrid_id, credit_amount,
        day_tariff, day_tariff_start,
        night_tariff, night_tariff_start):
    """Write information to a credit card."""
    block_4 = b''.join((
        b'C',  # C for credit
        b'\1',  # 1 for int
        credit_amount.to_bytes(4, 'big'),  # 4 byte unsigned int
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(2),  # intentionally empty
        bytes(4),  # card read time TODO
    ))
    block_5 = uuid.uuid4().bytes
    block_6 = uuid.UUID(minigrid_id).bytes
    block_8 = b''.join((
        b'\1',  # 1 for int
        _hour_on_epoch_day(day_tariff_start),  # tariff 1 validate time
        (int(day_tariff * 100)).to_bytes(4, 'big'),  # day tariff in cents
        bytes(7),  # intentionally empty
    ))
    block_9 = b''.join((
        b'\1',  # 1 for int
        _hour_on_epoch_day(night_tariff_start),  # tariff 2 validate time
        (int(night_tariff * 100)).to_bytes(4, 'big'),  # night tariff in cents
        bytes(7),  # intentionally empty
    ))
    block_10 = b''.join((
        bytes(4),  # time of these 2 tariff was created??? TODO
        bytes(4),  # time to start use tariff??? TODO
        bytes(8),  # intentionally empty
    ))

    message = _wrap_binary(
        block_4 + block_5 + block_6 + block_8 + block_9 + block_10
    )

    # TODO write to device
    print('=' * 60)
    print(message.hex())
    print('=' * 60)
