"""Functions for interacting with devices."""
import time
import uuid

from collections import OrderedDict

from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from tornado.escape import json_encode

import logging

AES = algorithms.AES


def _wrap_binary(binary):
    """Add a signifier to the beginning and end of a binary block."""
    return b'qS' + binary.hex().encode('ascii') + b'EL'


def erase_card(session, cache):
    """Erase card."""
    sector_1 = b''.join((
        bytes(45),
    ))
    sector_2 = b''.join((
        bytes(32),
    ))
    naive_payload = sector_1 + sector_2
    actual_payload = b''.join((
        naive_payload[:15],
        (sum(naive_payload[:15]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[15:30],
        (sum(naive_payload[15:30]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[30:45],
        (sum(naive_payload[30:45]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[45:60],
        (sum(naive_payload[45:60]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[60:75],
        (sum(naive_payload[60:75]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[75:77],
        bytes(13),
        (sum(naive_payload[75:77]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 30)
    write_result = OrderedDict()
    write_result['card_type'] = 'Blank Card'
    write_result['future_time'] = str(int(time.time())+30)
    cache.set('write_info', json_encode(write_result), 30)
    notify = OrderedDict()
    notify['notification'] = 'Erasing Card...'
    notify['type'] = 'alert-warning'
    cache.set('notification', json_encode(notify), 30)
    cache.delete('received_info')


def write_vendor_card(session, cache, key, minigrid_id, payment_id, vendor):
    """Write information to a vendor ID card."""
    card_produce_time = int(time.time())
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'A',  # A for vendor
        b'\x08',  # Offset
        b'\x00\x14',  # Length
        card_produce_time.to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time, set as zeros
        uuid.UUID(payment_id).bytes,
        b'\x00',  # Application Flag, has the card been used? Initially no
        bytes(12),
    ))
    vendor_id = vendor.vendor_user_id
    sector_2_content = b''.join((
        vendor_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        bytes(11),
    ))
    sector_2 = b''.join((
        sector_2_content,
        (sum(sector_2_content) & 0xFF).to_bytes(1, 'big'),
    ))
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    sector_2_enc = encryptor.update(sector_2) + encryptor.finalize()
    naive_payload = sector_1 + sector_2_enc
    actual_payload = b''.join((
        naive_payload[:15],
        (sum(naive_payload[:15]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[15:30],
        (sum(naive_payload[15:30]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[30:45],
        (sum(naive_payload[30:45]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[45:60],
        (sum(naive_payload[45:60]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[60:75],
        (sum(naive_payload[60:75]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[75:77],
        bytes(13),
        (sum(naive_payload[75:77]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 30)
    write_result = OrderedDict()
    write_result['card_type'] = 'Vendor ID Card'
    write_result['user_id'] = str(vendor_id)
    write_result['creation_time'] = \
        datetime.fromtimestamp(card_produce_time).isoformat()
    write_result['minigrid_id'] = str(minigrid_id)
    write_result['vendor_id'] = vendor.vendor_id
    cache.set('write_info', json_encode(write_result), 30)
    notify = OrderedDict()
    notify['notification'] = 'Writing Vendor Card...'
    notify['type'] = 'alert-warning'
    cache.set('notification', json_encode(notify), 30)
    cache.delete('received_info')


def write_customer_card(
        session, cache, key, minigrid_id, payment_id, customer):
    """Write information to a customer ID card."""
    card_produce_time = int(time.time())
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'B',  # B for customer
        b'\x08',  # Offset
        b'\x00\x14',  # Length
        card_produce_time.to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time, set as zeros
        uuid.UUID(payment_id).bytes,
        b'\x00',  # Application Flag, has the card been used? Initially no
        bytes(12),
    ))
    customer_id = customer.customer_user_id
    sector_2_content = b''.join((
        customer_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        int(customer.customer_current_limit).to_bytes(4, 'big'),  # Limit mA
        int(customer.customer_energy_limit).to_bytes(4, 'big'),   # Limit Wh
        bytes(3),
    ))
    sector_2 = b''.join((
        sector_2_content,
        (sum(sector_2_content) & 0xFF).to_bytes(1, 'big'),
    ))
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    sector_2_enc = encryptor.update(sector_2) + encryptor.finalize()
    naive_payload = sector_1 + sector_2_enc
    actual_payload = b''.join((
        naive_payload[:15],
        (sum(naive_payload[:15]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[15:30],
        (sum(naive_payload[15:30]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[30:45],
        (sum(naive_payload[30:45]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[45:60],
        (sum(naive_payload[45:60]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[60:75],
        (sum(naive_payload[60:75]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[75:77],
        bytes(13),
        (sum(naive_payload[75:77]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 30)
    write_result = OrderedDict()
    write_result['card_type'] = 'Customer ID Card'
    write_result['user_id'] = str(customer_id)
    write_result['creation_time'] = \
        datetime.fromtimestamp(card_produce_time).isoformat()
    write_result['minigrid_id'] = str(minigrid_id)
    write_result['customer_id'] = customer.customer_id
    cache.set('write_info', json_encode(write_result), 30)
    notify = OrderedDict()
    notify['notification'] = 'Writing Customer Card...'
    notify['type'] = 'alert-warning'
    cache.set('notification', json_encode(notify), 30)
    cache.delete('received_info')


def write_maintenance_card_card(
        session, cache, key, minigrid_id, payment_id, maintenance_card):
    """Write information to a maintenance card card."""
    card_produce_time = int(time.time())
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'D',  # D for maintenance card
        b'\x08',  # Offset
        b'\x00\xd0',  # Length
        card_produce_time.to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time, set as zeros
        uuid.UUID(payment_id).bytes,
        b'\x00',  # Application Flag, has the card been used?
        bytes(12),
    ))
    mc_id = maintenance_card.maintenance_card_card_id
    sector_2_content = b''.join((
        mc_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        bytes(11),
    ))
    sector_2 = b''.join((
        sector_2_content,
        (sum(sector_2_content) & 0xFF).to_bytes(1, 'big'),
    ))
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    sector_2_enc = encryptor.update(sector_2) + encryptor.finalize()
    naive_payload = sector_1 + sector_2_enc
    actual_payload = b''.join((
        naive_payload[:15],
        (sum(naive_payload[:15]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[15:30],
        (sum(naive_payload[15:30]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[30:45],
        (sum(naive_payload[30:45]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[45:60],
        (sum(naive_payload[45:60]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[60:75],
        (sum(naive_payload[60:75]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[75:77],
        bytes(13),
        (sum(naive_payload[75:77]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 30)
    write_result = OrderedDict()
    write_result['card_type'] = 'Maintenance Card'
    write_result['maintenance_id'] = str(mc_id)
    write_result['creation_time'] = \
        datetime.fromtimestamp(card_produce_time).isoformat()
    write_result['minigrid_id'] = str(minigrid_id)
    mmci = maintenance_card.maintenance_card_id
    write_result['mc_maintenance_card_id'] = mmci
    cache.set('write_info', json_encode(write_result), 30)
    notify = OrderedDict()
    notify['notification'] = 'Writing Maintenance Card...'
    notify['type'] = 'alert-warning'
    cache.set('notification', json_encode(notify), 30)
    cache.delete('received_info')


def _hour_on_epoch_day(hour_int):
    return (hour_int * 3600).to_bytes(4, 'big')


def write_credit_card(
        session,
        cache, key,
        minigrid_id,
        payment_id, credit_amount,
        day_tariff, day_tariff_start,
        night_tariff, night_tariff_start,
        tariff_creation_timestamp, tariff_activation_timestamp):
    """Write information to a credit card."""
    logging.info('write_credit_card()')
    card_produce_time = int(time.time()).to_bytes(4, 'big')
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'C',  # C for credit
        b'\x08',  # Offset
        b'\x00\xf4',  # Length
        b'\x00\x00\x00\x00',  # old card produce time section
        bytes(4),  # card read time, set as zeros
        uuid.UUID(payment_id).bytes,
        b'\x00',  # Application Flag, has the card been used?
        bytes(12),
    ))
    credit_card_id = uuid.uuid4()
    sector_2_content = b''.join((
        credit_amount.to_bytes(4, 'big'),  # 4 byte unsigned int
        credit_card_id.bytes,
        card_produce_time,  # check for expiration
        bytes(7),
    ))
    sector_2 = b''.join((
        sector_2_content,
        (sum(sector_2_content) & 0xFF).to_bytes(1, 'big'),
    ))
    sector_3_content = b''.join((
        _hour_on_epoch_day(day_tariff_start),  # tariff 1 validate time
        (int(day_tariff)).to_bytes(4, 'big'),  # day tariff in cents
        _hour_on_epoch_day(night_tariff_start),  # tariff 2 validate time
        (int(night_tariff)).to_bytes(4, 'big'),  # night tariff in cents
        int(tariff_creation_timestamp.timestamp()).to_bytes(4, 'big'),
        int(tariff_activation_timestamp.timestamp()).to_bytes(4, 'big'),
        bytes(7),
    ))
    sector_3 = b''.join((
        sector_3_content,
        (sum(sector_3_content) & 0xFF).to_bytes(1, 'big'),
    ))
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor2 = cipher.encryptor()
    sector_2_enc = encryptor2.update(sector_2) + encryptor2.finalize()
    encryptor3 = cipher.encryptor()
    sector_3_enc = encryptor3.update(sector_3) + encryptor3.finalize()
    naive_payload = sector_1 + sector_2_enc + sector_3_enc
    actual_payload = b''.join((
        naive_payload[:15],
        (sum(naive_payload[:15]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[15:30],
        (sum(naive_payload[15:30]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[30:45],
        (sum(naive_payload[30:45]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[45:60],
        (sum(naive_payload[45:60]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[60:75],
        (sum(naive_payload[60:75]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[75:77],
        bytes(13),
        (sum(naive_payload[75:77]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[77:92],
        (sum(naive_payload[77:92]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[92:107],
        (sum(naive_payload[92:107]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[107:109],
        bytes(13),
        (sum(naive_payload[107:109]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 30)
    write_result = OrderedDict()
    write_result['card_type'] = 'Credit Card'
    write_result['credit_card_id'] = str(credit_card_id)
    write_result['credit_amount'] = credit_amount
    write_result['minigrid_id'] = str(minigrid_id)
    write_result['day_tariff'] = str(day_tariff)
    write_result['day_tariff_start'] = str(day_tariff_start)
    write_result['night_tariff'] = str(night_tariff)
    write_result['night_tariff_start'] = str(night_tariff_start)
    write_result['tariff_creation_timestamp'] = str(tariff_creation_timestamp)
    write_result['tariff_activation_timestamp'] = \
        str(tariff_activation_timestamp)
    cache.set('write_info', json_encode(write_result), 30)
    notify = OrderedDict()
    notify['notification'] = 'Writing Credit Card...'
    notify['type'] = 'alert-warning'
    cache.set('notification', json_encode(notify), 30)
    cache.delete('received_info')
