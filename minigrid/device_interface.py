"""Functions for interacting with devices."""
from binascii import unhexlify
import time
import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from sqlalchemy.dialects.postgresql import insert

import minigrid.models as models


AES = algorithms.AES


def _wrap_binary(binary):
    """Add a signifier to the beginning and end of a binary block."""
    return b'qS' + binary.hex().encode('ascii') + b'EL'


def write_vendor_card(session, cache, key, minigrid_id, payment_id, vendor):
    """Write information to a vendor ID card."""
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'A',  # A for vendor
        b'\x08',  # Offset
        b'\x00\x14',  # Length
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time TODO
        uuid.UUID(payment_id).bytes,
    ))
    sector_2 = b''.join((
        vendor.vendor_user_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        bytes(12),
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
        naive_payload[30:32],
        bytes(13),
        (sum(naive_payload[30:32]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[32:47],
        (sum(naive_payload[32:47]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[47:62],
        (sum(naive_payload[47:62]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[62:64],
        bytes(13),
        (sum(naive_payload[62:64]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 5)
    with models.transaction(session) as tx_session:
        tx_session.add(models.VendorCardHistory(
            vendor_card_minigrid_id=minigrid_id,
            vendor_card_vendor_id=vendor.vendor_id,
            vendor_card_user_id=vendor.vendor_user_id,
        ))


def write_customer_card(session, cache, key, minigrid_id, payment_id, customer):
    """Write information to a customer ID card."""
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'B',  # B for customer
        b'\x08',  # Offset
        b'\x00\x14',  # Length
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time TODO
        uuid.UUID(payment_id).bytes,
    ))
    sector_2 = b''.join((
        customer.customer_user_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        bytes(12),
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
        naive_payload[30:32],
        bytes(13),
        (sum(naive_payload[30:32]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[32:47],
        (sum(naive_payload[32:47]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[47:62],
        (sum(naive_payload[47:62]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[62:64],
        bytes(13),
        (sum(naive_payload[62:64]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 5)
    with models.transaction(session) as tx_session:
        tx_session.add(models.CustomerCardHistory(
            customer_card_minigrid_id=minigrid_id,
            customer_card_customer_id=customer.customer_id,
            customer_card_user_id=customer.customer_user_id,
        ))


def write_maintenance_card_card(session, cache, key, minigrid_id, payment_id, maintenance_card):
    """Write information to a maintenance card card."""
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'D',  # D for maintenance card
        b'\x08',  # Offset
        b'\x00\xd0',  # Length
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time TODO
        uuid.UUID(payment_id).bytes,
    ))
    sector_2 = b''.join((
        maintenance_card.maintenance_card_card_id.encode('ascii'),  # 0000-9999 ASCII
        uuid.UUID(minigrid_id).bytes,
        bytes(12),
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
        naive_payload[30:32],
        bytes(13),
        (sum(naive_payload[30:32]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[32:47],
        (sum(naive_payload[32:47]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[47:62],
        (sum(naive_payload[47:62]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[62:64],
        bytes(13),
        (sum(naive_payload[62:64]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 5)
    with models.transaction(session) as tx_session:
        tx_session.add(models.MaintenanceCardHistory(
            mc_minigrid_id=minigrid_id,
            mc_maintenance_card_id=maintenance_card.maintenance_card_id,
            mc_maintenance_card_card_id=maintenance_card.maintenance_card_card_id,
        ))


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
    sector_1 = b''.join((
        b'\x00\x01',  # System ID
        b'\x00\x01',  # Application ID
        b'C',  # C for credit
        b'\x08',  # Offset
        b'\x00\xf4',  # Length
        int(time.time()).to_bytes(4, 'big'),  # card produced time
        bytes(4),  # card read time TODO
        uuid.UUID(payment_id).bytes,
    ))
    credit_card_id = uuid.uuid4()
    sector_2 = b''.join((
        credit_amount.to_bytes(4, 'big'),  # 4 byte unsigned int
        credit_card_id.bytes,
        bytes(12),
    ))
    sector_3 = b''.join((
        _hour_on_epoch_day(day_tariff_start),  # tariff 1 validate time
        (int(day_tariff * 100)).to_bytes(4, 'big'),  # day tariff in cents
        _hour_on_epoch_day(night_tariff_start),  # tariff 2 validate time
        (int(night_tariff * 100)).to_bytes(4, 'big'),  # night tariff in cents
        int(tariff_creation_timestamp.timestamp()).to_bytes(4, 'big'),
        int(tariff_activation_timestamp.timestamp()).to_bytes(4, 'big'),
        bytes(8),
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
        naive_payload[30:32],
        bytes(13),
        (sum(naive_payload[30:32]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[32:47],
        (sum(naive_payload[32:47]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[47:62],
        (sum(naive_payload[47:62]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[62:64],
        bytes(13),
        (sum(naive_payload[62:64]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[64:79],
        (sum(naive_payload[64:79]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[79:94],
        (sum(naive_payload[79:94]) & 0xFF).to_bytes(1, 'big'),
        naive_payload[94:96],
        bytes(13),
        (sum(naive_payload[94:96]) & 0xFF).to_bytes(1, 'big'),
    ))
    cache.set('device_info', _wrap_binary(actual_payload), 5)
    data = {
        'credit_card_id': str(credit_card_id),
        'credit_minigrid_id': minigrid_id,
        'credit_amount': credit_amount,
        'credit_day_tariff': day_tariff,
        'credit_day_tariff_start': day_tariff_start,
        'credit_night_tariff': night_tariff,
        'credit_night_tariff_start': night_tariff_start,
        'credit_tariff_creation_timestamp': tariff_creation_timestamp,
        'credit_tariff_activation_timestamp': tariff_activation_timestamp,
    }
    statement = (
        insert(models.CreditCardHistory)
        .values(**data)
        .on_conflict_do_nothing())
    with models.transaction(session) as tx_session:
        tx_session.execute(statement)
