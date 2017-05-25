"""Functions for interacting with devices."""
from binascii import unhexlify
import time
import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


AES = algorithms.AES


def _wrap_binary(binary):
    """Add a signifier to the beginning and end of a binary block."""
    return b'qS' + binary.hex().encode('ascii') + b'EL'


def write_vendor_card(cache, key, minigrid_id, payment_id, vendor):
    """Write information to a vendor ID card."""
    sector_1 = b''.join((
        b'SI',  # System ID
        b'AI',  # Application ID
        b'A',  # A for vendor
        b'O',  # Offset
        b'Le',  # Length
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time TODO
        uuid.UUID(payment_id).bytes,
    ))
    sector_2 = b''.join((
        vendor.vendor_user_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        #unhexlify(uuid.UUID(minigrid_id).bytes).hex().upper().encode()
        bytes(12),
    ))
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    sector_2_enc = encryptor.update(sector_2) + encryptor.finalize()
    payload = sector_1 + sector_2_enc
    cache.set('device_info', payload, 5)


def write_vendor_card_bak(cache, key, minigrid_id, payment_id, vendor):
    """Write information to a vendor ID card."""
    block_4 = b''.join((
        b'A',  # A for vendor
        vendor.vendor_user_id.encode('ascii'),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    ))
    #block_5 = uuid.UUID(minigrid_id).bytes
    block_5 = unhexlify(uuid.UUID(minigrid_id).bytes).hex().upper().encode()
    #block_6 = bytes(16)  # other information
    block_6 = uuid.UUID(payment_id).bytes

    #message = _wrap_binary(block_4 + block_5 + block_6)
    message = block_4 + block_5
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    payload = _wrap_binary(ciphertext + block_6)

    cache.set('device_info', payload, 5)

    # TODO write to device
    print('=' * 60)
    print(message.hex())
    print('=' * 60)


def write_customer_card(cache, key, minigrid_id, payment_id, customer):
    """Write information to a customer ID card."""
    block_4 = b''.join((
        b'B',  # B for customer
        customer.customer_user_id.encode('ascii'),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    ))
    #block_5 = uuid.UUID(minigrid_id).bytes
    block_5 = unhexlify(uuid.UUID(minigrid_id).bytes).hex().upper().encode()
    #block_6 = bytes(16)  # other information
    block_6 = uuid.UUID(payment_id).bytes

    #message = _wrap_binary(block_4 + block_5 + block_6)
    message = block_4 + block_5
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    payload = _wrap_binary(ciphertext + block_6)

    cache.set('device_info', payload, 5)

    # TODO write to device
    print('=' * 60)
    print(cache.get('device_active'))
    print(cache.get('device_info'))
    print(cache.get('received_info'))
    print(message.hex())
    print('=' * 60)


def write_maintenance_card_card(cache, key, payment_system_id, maintenance_card):
    """Write information to a maintenance card card."""
    block_4 = b''.join((
        b'D',  # D for maintenance card
        maintenance_card.maintenance_card_card_id.encode('ascii'),  # 0000-9999 ASCII
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(3),  # intentionally empty
        bytes(4),  # card read time TODO
    ))
    block_5 = bytes(16)
    #block_6 = bytes(16)  # other information
    block_6 = uuid.UUID(payment_system_id).bytes

    #message = _wrap_binary(block_4 + block_5 + block_6)
    message = block_4
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    payload = _wrap_binary(ciphertext + block_5 + block_6)

    cache.set('device_info', payload, 5)

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
        cache, key,
        payment_id, credit_amount,
        day_tariff, day_tariff_start,
        night_tariff, night_tariff_start,
        tariff_creation_timestamp, tariff_activation_timestamp):
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
    block_6 = uuid.UUID(payment_id).bytes
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
        int(tariff_creation_timestamp.timestamp()).to_bytes(4, 'big'),
        int(tariff_activation_timestamp.timestamp()).to_bytes(4, 'big'),
        bytes(8),  # intentionally empty
    ))

    #message = _wrap_binary(
    #    block_4 + block_5 + block_6 + block_8 + block_9 + block_10
    #)

    #message = (
    #    block_4 + block_5 + block_6 + block_8 + block_9 + block_10
    #)
    #encryptor = cipher.encryptor()
    #ciphertext = encryptor.update(message) + encryptor.finalize()
    #payload = _wrap_binary(ciphertext)

    message_1 = block_4 + block_5
    message_2 = block_8 + block_9 + block_10
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor_1 = cipher.encryptor()
    ciphertext_1 = encryptor_1.update(message_1) + encryptor_1.finalize()
    encryptor_2 = cipher.encryptor()
    ciphertext_2 = encryptor_2.update(message_2) + encryptor_2.finalize()
    payload = _wrap_binary(ciphertext_1 + block_6 + ciphertext_2)

    cache.set('device_info', payload, 5)

    # TODO write to device
    print('=' * 60)
    print(message_1.hex())
    print(block_6.hex())
    print(message_2.hex())
    print('=' * 60)
