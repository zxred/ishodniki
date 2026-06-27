#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║   BigWorld LoginApp + BaseApp stub  ·  WoT/Mir Tankov 1.23     ║
║   Full rewrite · всё исправлено на основе wg-toolkit-rs анализа ║
╠══════════════════════════════════════════════════════════════════╣
║  ИСПРАВЛЕНЫ БАГИ:                                                ║
║  #1 Element length: FIXED uint32 → Variable32 (wg-toolkit-rs)  ║
║  #2 Payload: нет prereqs как строк, правильный binary формат   ║
║  #3 Variable32 алгоритм: (val>>7) а не (val>>8)                ║
║  #4 Footer: seq_num=0, last_reliable=0 (LoginApp stateless)    ║
║  #5 Все payload варианты покрыты (с/без prereqs, с/без msg)    ║
║  #6 BaseApp stub: правильный EntityDetails reply               ║
║  #7 RequestID offset: исправлено извлечение из пакета (offset 8)║
╠══════════════════════════════════════════════════════════════════╣
║  Структура LOGIN SUCCESS пакета (server → client):              ║
║  [prefix:4][flags:2][0xFF:1][var32(len):1-4][req_id:4]         ║
║  [0x01:status][BF_PCBC( inner )][checksum:4]                   ║
║                                                                  ║
║  inner = IP:4BE + Port:2BE + Salt:2LE + LoginKey:4LE           ║
║          + [optional: prereq_count:1 + reason:1]                ║
╚══════════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import os
import sys
import time
import json
import traceback
import threading

from pathlib import Path
from src.manager import DefManager
from handlers.baseapp_handler import BaseAppHandler
from bw_crypto import reencrypt_existing_packet
# types_parser (DefSchemaParser) больше НЕ используется для Account — он падал
# на unbound-prefix. Импортируем мягко: если модуль есть, оставим BASIC_TYPES/
# pack_primitive для возможного легаси-кода, но сервер от него не зависит.
try:
    from types_parser import BASIC_TYPES, pack_primitive  # noqa: F401
except Exception:
    BASIC_TYPES, pack_primitive = {}, None
       
# ── per-client channel state ──────────────────────────────────────
class ClientChannel:
    """Состояние reliable-канала одного клиента (wg-toolkit ClientChannel)."""
    def __init__(self):
        self.established       = False   # пришёл ли on-channel SessionKey (0x01)
        self.our_seq           = 0       # наш счётчик исходящих reliable-пакетов
        self.client_seq        = 0       # последний seq, полученный от клиента
        self.first_channel_pkt = True    # нужен FLAG_CREATE_CHANNEL на 1-м пакете
        self.prefix_offset     = 0       # per-connection offset (из prefix клиента)
        # Blowfish канального шифрования
        # Ключ = session_key из SessionKey reply (4 байта, паддинг до 8).
        # После установки SessionKey ВСЕ on-channel тела шифруются BF.
        self.bf_key: bytes | None = None # None = не установлен (до SessionKey)
        self._bf_enc: object | None = None  # BlowfishLesta instance
        self._bf_dec: object | None = None

    def setup_blowfish(self, session_key: int):
        """Инициализировать BF после согласования SessionKey."""
        # Ключ = session_key (4B LE) дополнен зеркально до 8 байт.
        # wg-toolkit: key = session_key_bytes * 2 (repeat 4B twice → 8B).
        sk = struct.pack('<I', session_key)
        # FIX: use the REAL 16-byte client Blowfish key established at login
        # (parsed from RSA blob in LoginApp). The old sk*2 was a fake 8B key.
        if BASEAPP_BF_KEY:
            self.bf_key = BASEAPP_BF_KEY
        else:
            self.bf_key = sk * 2   # fallback (diagnostic only)
        self._bf_enc = BlowfishLesta(self.bf_key)
        self._bf_dec = BlowfishLesta(self.bf_key)

    # ── Канальный шифр по валидированному референсу (socket.rs) ──
    # Свежий BlowfishLesta на КАЖДЫЙ пакет: prev_pt обязан стартовать с 0.
    _ENC_MAGIC = bytes.fromhex('efbeadde')   # 0xDEADBEEF LE

    def encrypt_packet(self, clear_pkt: bytes) -> bytes:
        """Encrypt ENTIRE packet from byte 0 (per encryption_filter.cpp).
        NO plaintext prefix. Append MAGIC+wastage, then encrypt all."""
        if self.bf_key is None:
            return clear_pkt
        BLOCK = 8
        pkt_len = len(clear_pkt) + 4          # +4 for MAGIC
        wastage = ((BLOCK - ((pkt_len + 1) % BLOCK)) % BLOCK) + 1
        data = clear_pkt + b'\x00' * (wastage - 1) + self._ENC_MAGIC + bytes([wastage])
        return BlowfishLesta(self.bf_key).encrypt(data)

    def decrypt_packet(self, enc_pkt: bytes) -> bytes:
        """Decrypt entire packet from byte 0, strip MAGIC+wastage."""
        if self.bf_key is None:
            return enc_pkt
        dec = BlowfishLesta(self.bf_key).decrypt(enc_pkt)
        wastage = dec[-1]
        if dec[-5:-1] != self._ENC_MAGIC:
            raise ValueError('bad enc magic: ' + dec[-5:].hex())
        footer_size = wastage + 4
        return dec[:len(dec) - footer_size]

    def next_seq(self) -> int:
        s = self.our_seq
        self.our_seq += 1
        return s


FLAG_HAS_REQUESTS = 0x0001
FLAG_IS_ON_CHANNEL = 0x0008
FLAG_CREATE_CHANNEL = 0x0200   # ← КЛЮЧЕВОЙ флаг для первого канального пакета


def _client_seq_from_packet(data: bytes, hdr_off: int = 4) -> int:
    """Вытащить seq клиента из on-channel пакета (footer: last_rel:4, seq:4)."""
    flags = struct.unpack_from('<H', data, hdr_off)[0]
    has_cs = bool(flags & 0x0100)
    end = len(data) - (4 if has_cs else 0)
    return struct.unpack_from('<I', data, end - 4)[0]

# ── Entity stream serializer (createBasePlayer) ──────────────────────────
# Кладём entity_streaming.py рядом с этим файлом; добавляем его каталог в
# sys.path, чтобы импорт работал независимо от cwd.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from entity_streaming import build_account_create_base_player_element
from account_properties import send_receive_properties, build_receive_properties_element   # stats/inventory/serverSettings
from show_gui import build_show_gui_payload   # Account.showGUI -> Hangar

sys.stdout.reconfigure(line_buffering=True)

HOST       = '0.0.0.0'
LOGIN_PORT = 20014
BASE_PORT  = 20017
BASEAPP_IP = '127.0.0.1'

PRIVKEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_privkey.pem')
LOG_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

from Crypto.PublicKey import RSA
from Crypto.Cipher   import PKCS1_OAEP
from Crypto.Cipher   import Blowfish as BF_ECB
from Crypto.Hash     import SHA1

# Инициализация парсера
app_root = Path(__file__).resolve().parent
def_manager = DefManager(app_root)
def_manager.load() # Это та самая функция, которая выводит [DEF] ... - is found
print(f"[OK] DefManager готов: {len(def_manager)} сущностей в реестре")

handler = BaseAppHandler(def_manager=def_manager)

# ── Entity System ──
try:
    from entity_addon import EntitySystemAddon
    ENTITY_ADDON = True
    print('[OK] EntitySystemAddon загружен')
except ImportError:
    ENTITY_ADDON = False
    print('[WARN] EntitySystemAddon не загружен (опционально)')

# ── Логика авторизации вынесена в auth_logic.py (тот же каталог) ──
from auth_logic import (
    generate_full_auth_packet,
    generate_login_success_packet,
    generate_login_redirect_packet,
    generate_baseapp_login_reply,
    BaseAppHandshake,
    FRAME_VARIANTS,
)

# ── Тумблеры эксперимента (крути их, чтобы подобрать формат под клиент) ──
SEND_SEPARATE_REDIRECT = False   # True = слать LoginRedirect вторым пакетом
REDIRECT_DELAY_SEC     = 0.08    # задержка перед redirect (клиенту на расшифровку)
ENCRYPT_SUCCESS        = True    # False = LoginSuccess без Blowfish (диагностика)
BASEAPP_BF_KEY        = None    # FIX: real 16B client Blowfish key, shared LoginApp->BaseApp
BASEAPP_USE_CHECKSUM  = True    # EVIDENCE: the ONLY reply the client accepted (LoginApp) had flags=0x0100 + checksum; mirror that framing
LOGIN_KEY              = 0x00000001  # FIX #19 DONE: структура LoginReplyRecord подтверждена (salt 2B)

# Источник Blowfish-ключа для шифрования LoginSuccess:
# Источник Blowfish-ключа для шифрования LoginSuccess:
#   'blob'     — ПРАВИЛЬНО: 16-байтовый blowfish_key, распарсенный из RSA-блоба
#                (поле после username+password). ДЕФОЛТ.
#   'session'  — ключ = bytes.fromhex(session) из JSON (оказалось НЕВЕРНО)
#   'first16'/'prejson'/'postjson' — сырые срезы блоба (диагностика)
# ⚠ Клиент шифрует свой blowfish_key ТВОИМ public-ключом (loginapp_wot.pubkey).
BF_KEY_SOURCE          = 'blob'

# ───────────────────────────────────────────────────────────────
#  RSA
# ───────────────────────────────────────────────────────────────
PRIVATE_KEY = None
try:
    with open(PRIVKEY_PATH, 'r') as f:
        PRIVATE_KEY = RSA.importKey(f.read())
    print('[OK] RSA private key loaded')
except Exception as e:
    print(f'[WARN] RSA key not loaded: {e}')

RSA_BLOCK_SIZE = 256

# FIX #5: reply_id (request correlation id) читается со смещения 9, не 8.
# Раскладка login-request элемента: prefix(4)+flags(2)+msg_id(1)+len16(2)+reply_id(4)
#   = байты 0..5 заголовок, 6 msg_id, 7..8 длина (Variable16), 9..12 reply_id.
# ⚠ Сверь с СВОИМ дампом: если login использует другую ElementLength,
#   подвинь это значение (частые варианты: 7 для Fixed, 9 для Variable16).
REPLY_ID_OFFSET = 9

# На BaseApp baseAppLogin reply_id лежит со смещения 9
# (после 2-байтного счётчика/длины). Подтверждено из логов.
BASEAPP_REPLYID_OFFSET = 9

# ───────────────────────────────────────────────────────────────
#  BigWorld пакетные флаги
# ───────────────────────────────────────────────────────────────
FLAG_HAS_REQUESTS   = 0x0001   # в пакете есть request-элементы
FLAG_HAS_PIGGYBACKS = 0x0002
FLAG_HAS_CHECKSUM   = 0x0100   # в footer есть XOR checksum

# ───────────────────────────────────────────────────────────────
#  Blowfish  ·  Lesta PCBC:  C[i] = E(P[i] ⊕ P[i-1] ⊕ C[i-1])
#  IV = 0,0,…,0  (нулевой вектор)
# ───────────────────────────────────────────────────────────────
class BlowfishLesta:
    """
    Нестандартный PCBC режим Lesta:
        C[0] = ECB(P[0])
        C[i] = ECB(P[i] ⊕ P[i-1] ⊕ C[i-1])
    """
    def __init__(self, key: bytes):
        self._ecb        = BF_ECB.new(key, BF_ECB.MODE_ECB)
        self._prev_pt    = b'\x00' * 8
        self._prev_ct    = b'\x00' * 8

    def encrypt(self, data: bytes) -> bytes:
        # FIX #4: режим wg-toolkit — C[i] = E(P[i] ⊕ P[i-1]), P[-1]=0.
        out = b''
        for i in range(0, len(data), 8):
            block  = data[i:i+8]
            xored  = bytes(a ^ b for a, b in zip(block, self._prev_pt))
            ct     = self._ecb.encrypt(xored)
            out   += ct
            self._prev_pt = block
        return out

    def decrypt(self, data: bytes) -> bytes:
        # P[i] = D(C[i]) ⊕ P[i-1], P[-1]=0.
        out = b''
        for i in range(0, len(data), 8):
            ct    = data[i:i+8]
            dec   = self._ecb.decrypt(ct)
            pt    = bytes(a ^ b for a, b in zip(dec, self._prev_pt))
            out  += pt
            self._prev_pt = pt
        return out


# ───────────────────────────────────────────────────────────────
#  Variable32 (wg-toolkit-rs bundle.rs реализация)
#  val 0..=0x7F        → 1 байт
#  val 0x80..=0x3FFF   → 2 байта  (0x80 | val>>7, val&0x7F)
#  val 0x4000..=0x1FFFFF → 3 байта
#  val ≥ 0x200000      → 1+4 байта (0xE0 + uint32 LE)
# ───────────────────────────────────────────────────────────────
def encode_var32(val: int) -> bytes:
    if val <= 0x7F:
        return bytes([val])
    elif val <= 0x3FFF:
        return bytes([0x80 | (val >> 7), val & 0x7F])
    elif val <= 0x1FFFFF:
        return bytes([0xC0 | (val >> 14), (val >> 7) & 0x7F, val & 0x7F])
    else:
        return bytes([0xE0]) + struct.pack('<I', val)


def pack_string(s: bytes) -> bytes:
    """BigWorld packed string: len<255 → [len:1], иначе [0xFF][len:4LE]"""
    n = len(s)
    if n < 0xFF:
        return bytes([n]) + s
    return b'\xFF' + struct.pack('<I', n) + s


# ───────────────────────────────────────────────────────────────
#  BigWorld packet builders
# ───────────────────────────────────────────────────────────────
# ── BigWorld Mercury Blowfish EncryptionFilter (проверено, см. bw_crypto.py) ──
import os as _bw_os, sys as _bw_sys
_bw_sys.path.insert(0, _bw_os.path.dirname(_bw_os.path.abspath(__file__)))
import bw_crypto


def _prefix_hash(body: bytes, offset: int = 0) -> int:
    """Префикс = нелинейный hash первых 8 байт body + channel offset.

    Формула выверена по wg-toolkit packet.rs::update_prefix. КЛЮЧЕВОЕ:
    `offset` — per-connection «соль» канала. Для LoginApp offset=0, но для
    BaseApp клиент использует НЕнулевой offset (выдан при логине). Если
    строить prefix с offset=0, клиент посчитает другой ожидаемый prefix и
    ДРОПНЕТ пакет ⇒ LOGIN_REJECTED_NO_BASEAPP_RESPONSE.
    Offset восстанавливается из входящего пакета (см. _recover_prefix_offset).
    """
    M  = 0xFFFFFFFF
    b  = body[:8].ljust(8, b'\x00')
    p0 = struct.unpack_from('<I', b, 0)[0]
    p1 = struct.unpack_from('<I', b, 4)[0]
    a  = (offset + p0 + p1) & M
    b2 = (a << 13)          & M
    c  = (b2 ^ a) >> 17
    e  = (c ^ b2 ^ a)
    d  = (e ^ ((e << 5) & M)) & M
    return d


def _invert_prefix(d: int) -> int:
    """Обратная к prefix-формуле: по значению prefix вернуть промежуточное `a`.

    Позволяет восстановить channel offset из чужого пакета:
        a = _invert_prefix(prefix);  offset = (a - p0 - p1) mod 2^32
    """
    M = 0xFFFFFFFF
    def bits(n): return [(n >> i) & 1 for i in range(32)]
    def frb(bl): return sum(x << i for i, x in enumerate(bl)) & M
    db = bits(d)
    e = [0]*32
    for i in range(32):
        e[i] = db[i] ^ (e[i-5] if i >= 5 else 0)
    eb = bits(frb(e))
    x = [0]*32
    for i in range(31, -1, -1):
        x[i] = eb[i] ^ (x[i+17] if i+17 < 32 else 0)
    xb = bits(frb(x))
    a = [0]*32
    for i in range(32):
        a[i] = xb[i] ^ (a[i-13] if i >= 13 else 0)
    return frb(a)


def _recover_prefix_offset(packet: bytes) -> int:
    """Восстановить channel offset из входящего пакета клиента.

    Клиент сам сообщает offset через свой prefix. Мы инвертируем формулу и
    вычитаем p0/p1 (первые 8 байт после prefix). Затем используем этот же
    offset при сборке наших ответов, чтобы prefix сошёлся у клиента.
    """
    M = 0xFFFFFFFF
    prefix = struct.unpack_from('<I', packet, 0)[0]
    body = packet[4:]
    p0 = struct.unpack_from('<I', body, 0)[0]
    p1 = struct.unpack_from('<I', body, 4)[0]
    a = _invert_prefix(prefix)
    return (a - p0 - p1) & M


def _xor_cs(data: bytes) -> int:
    """XOR checksum: только полные 4-байтовые слова (хвост игнорируется)."""
    cs = 0
    for i in range(0, len(data) - len(data) % 4, 4):
        cs ^= struct.unpack_from('<I', data, i)[0]
    return cs


def build_reply_element(request_id: int, payload: bytes) -> bytes:
    """
    Reply element (wg-toolkit-rs bundle.rs):
      [0xFF : 1B]
      [var32(len(req_id+payload)) : 1-4B]   ← VARIABLE32, не Fixed4!
      [request_id : 4B LE]
      [payload]

    КРИТИЧНО: клиент читает длину как Variable32 (1 байт если <128).
    Fixed4 (08 00 00 00) сдвигает req_id на 3 байта → клиент дропает пакет.
    Для SessionKey: content=8 байт → var32=0x08 (1 байт).
    """
    content = struct.pack('<I', request_id) + payload
    # FIX (wg-toolkit element.rs): Reply uses ElementLength::Variable32 =
    # a FIXED 4-byte LE length field (read_u32), NOT a 7-bit varint.
    # Prev session wrongly used encode_var32 (1 byte for 8) -> client read
    # length as 4 bytes (08 61 07 01) = garbage -> dropped packet -> retry.
    return b'\xFF' + struct.pack('<I', len(content)) + content


def build_bw_packet(
    elements: bytes,
    is_on_channel: bool = False,
    seq_num: int = 0,
    last_rel: int = 0,
    extra_flags: int = 0,
    prefix_offset: int = 0,
    raw_prefix: int | None = None,
) -> bytes:
    """
    Собирает BigWorld UDP пакет.

    OFF-CHANNEL (is_on_channel=False):
      flags = HAS_CHECKSUM(0x0100) | extra_flags
      body  = flags(2) + elements + checksum(4)
      Итого для SessionKey reply = 4+2+1+1+4+4+4 = 20 байт.

    ON-CHANNEL (is_on_channel=True):
      flags = HAS_CHECKSUM | FLAG_IS_ON_CHANNEL(0x0008) | extra_flags
      body  = flags(2) + elements + last_rel(4) + seq_num(4) + checksum(4)

    prefix = _prefix_hash(body, prefix_offset)
    prefix_offset — per-connection offset клиента (восстанавливается из входящего prefix).
    НЕЛЬЗЯ использовать offset=0 для BaseApp — клиент дропнет пакет.
    """
    FLAG_HAS_CHECKSUM  = 0x0100
    FLAG_IS_ON_CHANNEL = 0x0008

    flags = (FLAG_HAS_CHECKSUM if BASEAPP_USE_CHECKSUM else 0) | extra_flags
    if is_on_channel:
        flags |= FLAG_IS_ON_CHANNEL | 0x0040 | 0x1000  # +HAS_SEQUENCE_NUMBER +UNK_1000(last_rel) so client parses footer

    body = bytearray()
    body += struct.pack('<H', flags)
    body += elements

    if is_on_channel:
        body += struct.pack('<I', last_rel if last_rel else 0xFFFFFFFF)  # initial channel value = -1
        body += struct.pack('<I', seq_num)

    if BASEAPP_USE_CHECKSUM:
        # FIX #18 (Frida ground-truth): НЕ добавляем выравнивающий паддинг на провод!
        # wg-toolkit packet.rs: диапазон checksum = [prefix .. len-4] (flags+body),
        # а calc_checksum читает read_u32 в цикле и ИГНОРИРУЕТ хвост <4 байт.
        # Старый паддинг вставлял лишний 0x00 (BaseApp reply 24B вместо 23B) →
        # клиент читал checksum со сдвига → дроп → ретрансмит req 0x8e→0xc8 → таймаут.
        # LoginApp проходил только потому, что его body уже был кратен 4 (28B).
        cs = _xor_cs(bytes(body))
        body += struct.pack('<I', cs)

    if raw_prefix is not None:
        prefix = raw_prefix
    else:
        prefix = _prefix_hash(bytes(body), prefix_offset)
    return struct.pack('<I', prefix) + bytes(body)


def _build_bw_packet_no_checksum(
    elements: bytes,
    is_on_channel: bool = False,
    prefix_offset: int = 0,
    raw_prefix: int | None = None,
) -> bytes:
    """Build a BW packet WITHOUT HAS_CHECKSUM flag (for diagnostic variants)."""
    flags = 0
    if is_on_channel:
        flags |= 0x0008  # ON_CHANNEL

    body = bytearray()
    body += struct.pack('<H', flags)
    body += elements

    if is_on_channel:
        body += struct.pack('<I', 0)  # last_rel
        body += struct.pack('<I', 0)  # seq_num

    # NO checksum appended
    if raw_prefix is not None:
        prefix = raw_prefix
    else:
        prefix = _prefix_hash(bytes(body), prefix_offset)
    return struct.pack('<I', prefix) + bytes(body)


# ───────────────────────────────────────────────────────────────
#  LOGIN SUCCESS payload
# ───────────────────────────────────────────────────────────────
def _bf_key(session: str) -> bytes:
    if len(session) == 32:
        try:
            return bytes.fromhex(session)
        except ValueError:
            pass
    return session[:16].encode().ljust(16, b'\x00')


def build_login_success_payload(session: str, login_key: int = 0x00000001,
                                 server_msg: str = '') -> bytes:
    """
    Правильная структура LOGIN SUCCESS inner (по wg-toolkit-rs):

        IP      : 4B  big-endian   (127.0.0.1 → 7f 00 00 01)
        Port    : 2B  big-endian   (20017 → 4e 31)
        Salt    : 2B  little-endian (0 → 00 00)
        LoginKey: 4B  little-endian

    Опционально (если сервер присылает строку):
        server_msg: pack_string(msg)

    Без поля prereqs — prereqs это ответ BaseApp, не LoginApp!

    Всё шифруется Blowfish PCBC (Lesta mode), padded к кратному 8.
    Перед шифротекстом идёт байт-статус 0x01 (LOGIN_SUCCESS).
    """
    inner = bytearray()
    inner += socket.inet_aton(BASEAPP_IP)          # IP  4B BE
    inner += struct.pack('>H', BASE_PORT)           # Port 2B BE
    # FIX #3: salt убран — Addr(IP4+Port2) + Key(u32).
    inner += struct.pack('<I', login_key)            # Key  4B LE
    if server_msg:
        inner += pack_string(server_msg.encode())

    raw     = bytes(inner)
    pad     = (8 - len(raw) % 8) % 8
    padded  = raw + b'\x00' * pad

    key = _bf_key(session)
    ct  = BlowfishLesta(key).encrypt(padded)

    return b'\x01' + ct


# ───────────────────────────────────────────────────────────────
#  Набор payload вариантов — чтобы перебрать при повторных попытках
# ───────────────────────────────────────────────────────────────
def _make_variants(session: str):
    return [
        # (описание, payload_bytes)
        ("V1 standard: IP+Port+Salt+Key, no msg",
         build_login_success_payload(session, login_key=0x00000001, server_msg='')),

        ("V2 key=0",
         build_login_success_payload(session, login_key=0x00000000, server_msg='')),

        ("V3 key=DEADBEEF",
         build_login_success_payload(session, login_key=0xDEADBEEF, server_msg='')),

        ("V4 with server_msg='offline'",
         build_login_success_payload(session, login_key=0x00000001, server_msg='offline')),

        ("V5 no Blowfish (raw inner)",
         _raw_payload(session)),

        ("V6 key=CAFEBABE, msg='ok'",
         build_login_success_payload(session, login_key=0xCAFEBABE, server_msg='ok')),
    ]


def _raw_payload(session: str) -> bytes:
    """Без шифрования — для диагностики."""
    inner = bytearray()
    inner += socket.inet_aton(BASEAPP_IP)
    inner += struct.pack('>H', BASE_PORT)
    inner += struct.pack('<I', 0x00000001)   # FIX #3: без salt
    return b'\x01' + bytes(inner)


# ───────────────────────────────────────────────────────────────
#  RSA брутфорс (фиксированные offsets 20 и 276 — быстро)
# ───────────────────────────────────────────────────────────────
_KNOWN_RSA_OFFSETS = (20, 276)   # подтверждено из логов

def rsa_decrypt_login(packet: bytes) -> dict | None:
    """
    Расшифровывает два RSA-блока логина и парсит JSON.
    Быстрый путь: фиксированные offsets 20+276.
    Запасной: полный брутфорс.
    """
    if not PRIVATE_KEY:
        return None
    oaep = PKCS1_OAEP.new(PRIVATE_KEY, hashAlgo=SHA1, label=b'')

    # Быстрый путь
    raw = b''
    for off in _KNOWN_RSA_OFFSETS:
        if off + RSA_BLOCK_SIZE <= len(packet):
            try:
                raw += oaep.decrypt(packet[off:off+RSA_BLOCK_SIZE])
            except Exception:
                raw = b''
                break
    if not raw:
        # Брутфорс
        blocks = []
        for off in range(0, len(packet) - RSA_BLOCK_SIZE + 1):
            try:
                dec = oaep.decrypt(packet[off:off+RSA_BLOCK_SIZE])
                nz  = sum(1 for b in dec if b != 0)
                if nz > 15:
                    blocks.append((nz, off, dec))
            except Exception:
                pass
        blocks.sort(reverse=True)
        for _, _, dec in blocks[:2]:
            raw += dec

    js_raw = raw.decode('ascii', errors='replace')
    js = js_raw.find('{')
    je = -1
    if js >= 0:
        depth = 0
        for i in range(js, len(js_raw)):
            if js_raw[i] == '{':
                depth += 1
            elif js_raw[i] == '}':
                depth -= 1
                if depth == 0:
                    je = i
                    break
    if js >= 0 and je > js:
        try:
            parsed = json.loads(js_raw[js:je+1])
        except Exception:
            return None
        # FIX (blowfish_key): кладём сырые расшифрованные байты и кандидатов на
        # симметричный ключ. В wg-toolkit blowfish_key пишется ПЕРЕД телом логина,
        # поэтому самый вероятный кандидат — первые 16 байт raw. Второй кандидат —
        # 16 байт, идущих прямо перед JSON. Оба логируем, чтобы ты сверил с дампом.
        parsed['__raw_hex__']   = raw.hex()
        parsed['__bf_first16__'] = raw[:16].hex()
        pre = raw[:js] if js >= 0 else b''
        parsed['__bf_prejson__'] = pre[-16:].hex() if len(pre) >= 16 else pre.hex()
        post = raw[je+1:] if je >= 0 else b''
        parsed['__bf_postjson__'] = post[:16].hex()
        # НАСТОЯЩИЙ ключ: BigWorld LoginRequest = flag(1) + username(pstr) +
        # password(pstr) + blowfish_key(pblob, 16B). Парсим length-prefixed поля.
        parsed['__bf_blob__'] = _extract_blowfish_blob(raw)
        return parsed
    return None


def _read_pstr(buf: bytes, i: int):
    """BigWorld packed string/blob: [len:1] либо [0xFF][len:4LE], затем bytes."""
    L = buf[i]; i += 1
    if L == 0xFF:
        L = struct.unpack_from('<I', buf, i)[0]; i += 4
    return buf[i:i+L], i + L


def _extract_blowfish_blob(raw: bytes) -> str:
    """raw = flag(1) + username(pstr) + password(pstr) + blowfish_key(pblob)."""
    try:
        i = 1                       # пропускаем flag-байт (0x01)
        _user, i = _read_pstr(raw, i)   # username (JSON)
        _pwd,  i = _read_pstr(raw, i)   # password
        key,   i = _read_pstr(raw, i)   # blowfish key (16 байт)
        return key.hex()
    except Exception:
        return ''


# ───────────────────────────────────────────────────────────────
#  Вспомогательные парсеры входящего пакета
# ───────────────────────────────────────────────────────────────
def _parse_incoming(packet: bytes) -> dict:
    """Разбираем входящий клиентский пакет."""
    info = {
        'prefix': 0, 'flags': 0,
        'elem_id': -1, 'request_id': 0, 'client_seq': 0,
    }
    if len(packet) < 6:
        return info
    info['prefix'] = struct.unpack_from('<I', packet, 0)[0]
    info['flags']  = struct.unpack_from('<H', packet, 4)[0]
    if len(packet) > 6:
        info['elem_id'] = packet[6]

    # request_id: извлекаем со смещения REPLY_ID_OFFSET (см. FIX #5).
    if len(packet) >= REPLY_ID_OFFSET + 4:
        info['request_id'] = struct.unpack_from('<I', packet, REPLY_ID_OFFSET)[0]

    # client_seq из footer (только если HAS_REQUESTS и нет HAS_CHECKSUM у клиента)
    # Клиент: flags=0x0001 (HAS_REQUESTS), нет checksum
    # Footer клиента (с конца): first_request_offset (2B) — только это!
    # seq_num/last_rel отсутствуют в Login пакетах (connectionless)
    info['client_seq'] = 0   # LoginApp stateless, seq не нужен

    return info


# ───────────────────────────────────────────────────────────────
#  LoginApp  (UDP 20014)
# ───────────────────────────────────────────────────────────────
class LoginApp:

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, LOGIN_PORT))
        self.sock.settimeout(0.5)

        self._log_path    = os.path.join(LOG_DIR, 'loginapp.log')
        self._login_count = 0
        self._server_seq  = 0
        self._sessions    = {}   # addr → {'session', 'variant', variants[]}

        print(f'[LOGIN] Listening  UDP {HOST}:{LOGIN_PORT}')

    # ── log ──────────────────────────────────────────────────
    def _log(self, msg: str, addr=None, level: str = 'INFO'):
        tag  = f'[{addr[0]}:{addr[1]}]' if addr else ''
        line = f'[{level}]{tag} {msg}'
        print(f'[LOGIN] {line}')
        try:
            with open(self._log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception:
            pass

    # ── main loop ────────────────────────────────────────────
    def run(self):
        with open(self._log_path, 'w', encoding='utf-8') as f:
            f.write(f'=== Started {time.strftime("%Y-%m-%d %H:%M:%S")} ===\n')
        self._log('Server started')
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._dispatch(data, addr)
            except socket.timeout:
                continue
            except Exception:
                traceback.print_exc()

    # ── dispatch ─────────────────────────────────────────────
    def _dispatch(self, data: bytes, addr):
        # ── Дамп ПОЛНОГО входящего пакета (для крекинга prefix-алгоритма) ──
        # Пишем prefix отдельно от тела: prefix(hex) | full_packet(hex) | len
        try:
            prefix = data[:4].hex()
            with open(os.path.join(LOG_DIR, 'client_packets.hex'), 'a', encoding='utf-8') as f:
                f.write(f'{prefix} | {data.hex()} | {len(data)}\n')
        except Exception:
            pass

        # Маленький пакет = ping/probe
        if len(data) <= 64:
            self._handle_ping(data, addr)
            return

        self._handle_login(data, addr)

    # ── ping ─────────────────────────────────────────────────
    def _handle_ping(self, data: bytes, addr):
        # Клиент шлёт 16-байтовые probe пакеты
        num    = data[11] if len(data) > 11 else 0
        # NB: ping (16B) — другая раскладка, чем login. Если pong не матчится,
        #     попробуй REPLY_ID_OFFSET (9) вместо 8.
        req_id = struct.unpack_from('<I', data, 8)[0] if len(data) >= 12 else 0
        
        # Pong: reply element с payload [0x02, 0x01, num]
        ping_pl = bytes([0x02, 0x01, num & 0xFF])
        elem    = build_reply_element(req_id, ping_pl)
        pkt = build_bw_packet(elem, is_on_channel=False)
        self._server_seq += 1
        self.sock.sendto(pkt, addr)
        self._log(f'<< ping {len(data)}B >> pong', addr)

    # ── login ────────────────────────────────────────────────
    def _handle_login(self, data: bytes, addr):
        self._login_count += 1
        info = _parse_incoming(data)
        self._log(
            f'<< Login #{self._login_count} {len(data)}B '
            f'flags=0x{info["flags"]:04X} req_id={info["request_id"]}',
            addr
        )
        self._log(f'   hex={data[:24].hex(" ")}', addr)

        # RSA + JSON
        login_data = rsa_decrypt_login(data)
        if login_data is None:
            self._log('   RSA/JSON parse FAILED', addr, 'WARN')
            return

        session = login_data.get('session', '')
        login   = login_data.get('login',   '?')
        self._log(f'   login={login}  session={session[:8]}…{session[-8:]}', addr)

        # Кандидаты на реальный blowfish_key из RSA-блоба (сверь с дампом!)
        bf_first16 = login_data.get('__bf_first16__', '')
        bf_prejson = login_data.get('__bf_prejson__', '')
        bf_postjson = login_data.get('__bf_postjson__', '')
        bf_blob     = login_data.get('__bf_blob__', '')
        raw_hex     = login_data.get('__raw_hex__', '')
        self._log(f'   bf_key BLOB (parsed) ={bf_blob}', addr)
        self._log(f'   bf_key cand: session={session}', addr)
        self._log(f'   bf_key cand: first16={bf_first16} prejson={bf_prejson} postjson={bf_postjson}', addr)
        if   BF_KEY_SOURCE == 'blob'     and bf_blob:
            bf_key = bytes.fromhex(bf_blob)
            globals()['BASEAPP_BF_KEY'] = bf_key   # FIX: share real key with BaseApp
        elif BF_KEY_SOURCE == 'first16'  and bf_first16:
            bf_key = bytes.fromhex(bf_first16)
        elif BF_KEY_SOURCE == 'prejson'  and bf_prejson:
            bf_key = bytes.fromhex(bf_prejson)
        elif BF_KEY_SOURCE == 'postjson' and bf_postjson:
            bf_key = bytes.fromhex(bf_postjson)
        else:
            bf_key = None   # 'session': derive_bf_key(session) внутри генератора

        # Кешируем варианты для этого addr
        key = addr
        if key not in self._sessions or self._sessions[key]['session'] != session:
            self._sessions[key] = {
                'session':  session,
                'variants': _make_variants(session),
                'vi':       0,
            }
        s = self._sessions[key]
        vi    = s['vi'] % len(s['variants'])
        desc, payload = s['variants'][vi]
        s['vi'] += 1

        req_id = info['request_id']

        # ── ШАГ 1: LoginSuccess, перебор ВАРИАНТОВ ФРЕЙМА по retry ───
        # Клиент ретраит Login #N — используем это как стенд: на каждую
        # попытку шлём следующий вариант обёртки. По логу увидим, на каком
        # (если на каком-то) клиент перестанет ретраить.
        # Frame-вариант A (checksum+prefix_hash+encrypted) ПОДТВЕРЖДЁН логом:
        # клиент дошёл до stage=1, значит обёртка верная. Пинуем его, чтобы все
        # retry слали один и тот же корректный фрейм (а не перебор вариантов).
        fi = 0
        wc, pmode, enc, fdesc = FRAME_VARIANTS[fi]
        success_pkt = generate_login_success_packet(
            req_id, session,
            baseapp_ip=BASEAPP_IP,
            baseapp_port=BASE_PORT,
            login_key=LOGIN_KEY,
            encrypt_success=enc,
            with_checksum=wc,
            prefix_mode=pmode,
            bf_key=bf_key,
        )
        self._server_seq += 1
        self._log(f'   >> LoginSuccess [{fdesc}] {len(success_pkt)}B', addr)
        self._log(f'      success hex = {success_pkt.hex(" ")}', addr)
        self.sock.sendto(success_pkt, addr)

        # ── ШАГ 2 (опц.): LoginRedirect отдельным пакетом ────────────
        if SEND_SEPARATE_REDIRECT:
            time.sleep(REDIRECT_DELAY_SEC)   # клиенту время на расшифровку
            redirect_pkt = generate_login_redirect_packet(
                req_id,
                baseapp_ip=BASEAPP_IP,
                baseapp_port=BASE_PORT,
                login_key=LOGIN_KEY,
            )
            self._server_seq += 1
            self._log(f'   >> LoginRedirect {len(redirect_pkt)}B  (+{int(REDIRECT_DELAY_SEC*1000)}ms)', addr)
            self._log(f'      redirect hex = {redirect_pkt.hex(" ")}', addr)
            self.sock.sendto(redirect_pkt, addr)


# ───────────────────────────────────────────────────────────────
#  BaseApp stub  (UDP 20017)
#  Клиент подключается сюда ПОСЛЕ успешного LoginApp.
#  Нам нужно ответить на initial handshake чтобы C++ создал
#  Account entity через onBecomePlayer.
# ───────────────────────────────────────────────────────────────
class BaseAppStub:

    def __init__(self, def_manager=None, *args, **kwargs):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, BASE_PORT))
        self.sock.settimeout(0.5)
        self._log_path  = os.path.join(LOG_DIR, 'baseapp.log')
        self._seq       = 0
        self._clients   = {}  # addr → BaseAppHandshake (SYN→ACK автомат)
        self.def_manager = def_manager  # ← .def registry reference
        self._entity_stream_sent = set()
        self._channels = {}
        self._sessions = {}

        # ── Параметры Account entity (createBasePlayer) ──────────────────
        # required_version ОБЯЗАН совпасть с версией, которую ждёт клиент,
        # иначе python-слой клиента отвергнет аккаунт. Подставь свою.
        self.required_version = 'eu_1.19.1_4'
        self.account_name     = 'OfflinePlayer'
        self.account_entity_id = 0x00000001
        self.database_id       = 10001        # ctx['databaseID'] for showGUI -> Hangar
        self._show_gui_sent    = set()        # addr -> showGUI отправлен один раз
        self._sessions = {}              # addr -> session_key (u32)
        self._prefix_offsets = {}        # addr -> channel prefix offset (u32)
        self._entity_streams_sent = set()
        
        # ── Account schema: берём из ОБЩЕГО DefManager ───────────────────
        # DefManager использует src/parser.py (parse_def_file), который ЧИНИТ
        # unbound-prefix (<ref:Type> без xmlns). Старый DefSchemaParser из
        # types_parser.py УДАЛЁН отсюда — именно он падал с
        # «[DEF] ❌ XML ошибка ... unbound prefix» и «папка не найдена».
        # NB: createBasePlayer(Account) не зависит от схемы — она нужна лишь
        # для будущих сущностей (Vehicle и т.п.).
        self.account_schema = def_manager.get('Account') if def_manager else None
        if self.account_schema:
            print(f'[BASE] ✅ Account: {len(self.account_schema.properties)} '
                  f'свойств (через src/parser.py)')
        else:
            print('[BASE] ⚠️  Account.def не найден в DefManager '
                  '(createBasePlayer всё равно работает)')
        
        # Entity System
        if ENTITY_ADDON:
            self.entity_system = EntitySystemAddon()
            self.entity_system.initialize()
        
        print(f'[BASE]  Listening  UDP {HOST}:{BASE_PORT}')
    
    def _send_on_channel(self, addr, ch, element: bytes):
        """On-channel пакет по валидированному формату (RUN21).

        prefix(4, клир) + ENC[ flags(2) + element + seq(4) + [create ver+id] + checksum(4) ]
        Шифруется ВСЯ зона после префикса (socket.rs::encrypt_packet_raw),
        канал ключуется login bf_key."""
        # Пока клиент не подтвердил канал (не пришёл ClientSessionKey, elt_id=0x01),
        # КАЖДЫЙ ответ на ретрансмит ClientAuth = «первый пакет»: CREATE_CHANNEL + seq=0.
        if not getattr(ch, 'established', False):
            extra = FLAG_CREATE_CHANNEL          # 0x0200
            seq   = 0
            ch.our_seq = 1
        else:
            extra = 0
            seq   = ch.next_seq()
        # ON_CHANNEL(0x0008) | IS_RELIABLE(0x0010) | HAS_CHECKSUM(0x0100) | CREATE_CHANNEL
        flags  = 0x0008 | 0x0010 | (0x0100 if BASEAPP_USE_CHECKSUM else 0) | extra
        offset = getattr(ch, 'prefix_offset', 0)

        body = bytearray()
        body += struct.pack('<H', flags)         # flags
        body += bytes(element)                    # message element(s)
        body += struct.pack('<I', seq)           # sequence_num footer [IS_RELIABLE]
        if extra:
            body += struct.pack('<I', 0)         # CREATE_CHANNEL: version
            body += struct.pack('<I', 0)         # CREATE_CHANNEL: id
        if BASEAPP_USE_CHECKSUM:
            cs = _xor_cs(bytes(body))
            body += struct.pack('<I', cs)        # XOR checksum footer

        clear_pkt = bytes(body)                       # flags+element+seq+checksum
        enc       = ch.encrypt_packet(clear_pkt)      # шифр всей зоны (encryption_filter.cpp)
        prefix    = _prefix_hash(enc, offset)         # ПРЕФИКС над ШИФРОТЕКСТОМ + соль канала
        pkt       = struct.pack('<I', prefix) + enc   # wire = prefix(4 клир) + ENC[...]

        self.sock.sendto(pkt, addr)
        self._log(
            f'>> on-channel seq={seq} flags=0x{flags:04X} {len(pkt)}B '
            f'bf={"ON" if ch.bf_key else "OFF"} hex={pkt[:24].hex(" ")}',
            addr)
        return pkt

    def _send_player_bootstrap(self, addr, ch):
        # 1) createBasePlayer(Account)
        el = build_account_create_base_player_element(
            entity_id=self.account_entity_id,
            required_version=self.required_version,
            name=self.account_name,
        )
        self._send_on_channel(addr, ch, el)

        # 2) receiveProperties (stats/inventory/serverSettings)
        rp_elem, _ = build_receive_properties_element(self.account_entity_id)
        self._send_on_channel(addr, ch, rp_elem)

        # 3) showGUI(ctx) → Ангар
        payload, _ = build_show_gui_payload(
            database_id=self.database_id,
            account_schema=self.account_schema, root_path='.')
        self._send_on_channel(addr, ch, payload)

    def _log(self, msg: str, addr=None, level: str = 'INFO'):
        tag  = f'[{addr[0]}:{addr[1]}]' if addr else ''
        line = f'[{level}]{tag} {msg}'
        print(f'[BASE]  {line}')
        try:
            with open(self._log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception:
            pass

    def run(self):
        with open(self._log_path, 'w', encoding='utf-8') as f:
            f.write(f'=== Started {time.strftime("%Y-%m-%d %H:%M:%S")} ===\n')
        # Очистить дампы пакетов
        try:
            with open(os.path.join(LOG_DIR, 'baseapp_packets.hex'), 'w', encoding='utf-8') as f:
                f.write(f'=== Started {time.strftime("%Y-%m-%d %H:%M:%S")} ===\n')
        except Exception:
            pass
        self._log('BaseApp stub started')
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._dispatch(data, addr)
            except socket.timeout:
                continue
            except Exception:
                traceback.print_exc()

    def _dispatch(self, data: bytes, addr):
        """BaseApp packet handler.
        Per BigWorld 14.4.1 OSE (proxy.cpp + encryption_filter.cpp):
        - LoginKey arrives OFF-CHANNEL, plaintext
        - Server reply goes ON-CHANNEL, ENCRYPTED (Blowfish BLOB key)
        - Encryption covers ENTIRE packet from byte 0 (NO plaintext prefix)
        - MAGIC 0xDEADBEEF + wastage appended before encryption
        """
        if not hasattr(self, '_channels'):
            self._channels = {}
        if not hasattr(self, '_sessions'):
            self._sessions = {}
        if not hasattr(self, '_login_attempt'):
            self._login_attempt = {}

        # ── Dump raw incoming packet ──
        try:
            with open(os.path.join(LOG_DIR, 'baseapp_packets.hex'), 'a', encoding='utf-8') as f:
                f.write(f'{data[:4].hex()} | {data.hex()} | {len(data)}\n')
        except Exception:
            pass
        self._log(f'<< RECV {len(data)}B hex={data[:24].hex(" ")}', addr)

        ch = self._channels.setdefault(addr, ClientChannel())

        # ── Try to decrypt if channel has Blowfish set up ──
        # For plaintext off-channel packets (LoginKey): client sends prefix(4) first,
        # so flags are at offset 4.
        # For decrypted on-channel packets: NO prefix (encryption removed it),
        # so flags are at offset 0.
        # We detect by checking if data came from decryption (bf_key set and was decrypted).
        is_decrypted = False
        if ch.bf_key is not None and len(data) >= 8 and len(data) % 8 == 0:
            try:
                decrypted = ch.decrypt_packet(data)
                self._log(f'   [DECRYPTED] {len(decrypted)}B hex={decrypted[:24].hex(" ")}', addr)
                data = decrypted
                is_decrypted = True
            except Exception as e:
                self._log(f'   decrypt failed: {e}', addr)
                # Fall through — plaintext off-channel packet

        # For plaintext: skip 4-byte client prefix. For decrypted: no prefix.
        hdr_off = 0 if is_decrypted else 4
        if len(data) < hdr_off + 2:
            return
        flags = struct.unpack_from('<H', data, hdr_off)[0]
        self._log(f'   flags=0x{flags:04X} (hdr_off={hdr_off})', addr)

        # ── LEARN channel prefix salt from client's off-channel packet ──
        # Клиент шлёт ClientAuth с префиксом = _prefix_hash(body, channel_salt).
        # Инвертируем префикс → узнаём соль канала → используем её в наших ответах.
        if hdr_off == 4 and len(data) >= 6:
            try:
                learned = _recover_prefix_offset(data)
                if learned != getattr(ch, 'prefix_offset', 0):
                    ch.prefix_offset = learned
                    self._log(f'   [LEARN] channel prefix_offset=0x{learned:08X}', addr)
            except Exception as e:
                self._log(f'   prefix offset learn failed: {e}', addr)

        # ── PHASE 1: Off-channel LoginKey (first packet, plaintext) ──
        if (flags & FLAG_HAS_REQUESTS) and len(data) >= hdr_off + 9:
            elt_id = data[hdr_off + 6] if len(data) > hdr_off + 6 else 0xFF
            # Extract request_id from request header: request_id(4) + next_link(2) + elt_id(1)
            request_id = struct.unpack_from('<I', data, hdr_off + 6)[0]
            self._log(f'   request_id=0x{request_id:08X} elt_id=0x{elt_id:02X}', addr)

            if elt_id in (0x00, 0x02):  # LoginKey
                attempt = self._login_attempt.get(addr, 0)
                self._login_attempt[addr] = attempt + 1

                login_key_client = struct.unpack_from('<I', data, hdr_off + 13)[0] if len(data) >= hdr_off + 17 else 0
                self._log(f'   login_key=0x{login_key_client:08X} attempt={attempt}', addr)

                # Generate session key (anti-spoof token, u32 timestamp in real server)
                session_key = self._sessions.get(addr)
                if session_key is None:
                    session_key = int(time.time()) & 0xFFFFFFFF
                    if session_key == 0:
                        session_key = 1
                    self._sessions[addr] = session_key

                # ── Setup Blowfish on channel using BLOB key ──
                ch.setup_blowfish(session_key)
                self._log(f'   Blowfish setup: bf_key={ch.bf_key.hex() if ch.bf_key else None}', addr)

                # ── Build ON-CHANNEL ENCRYPTED reply ──
                # per proxy.cpp:672-680:
                #   bundle.startReply(loginReplyID)  → REPLY element with reply_id
                #   bundle << sessionKey_            → u32 session key
                #   sendBundleToClient()             → through EncryptionFilter
                #
                # Plaintext packet layout:
                #   flags(2) + reply_element(13) + checksum(4) = off-channel plaintext
                #
                # Flags: ON_CHANNEL | IS_RELIABLE | HAS_SEQUENCE_NUMBER | HAS_CHECKSUM
                reply_flags = 0x0100   # PATH-A: HAS_CHECKSUM only (off-channel)
                seq_num = ch.next_seq()

                sk_payload = struct.pack('<I', session_key)
                reply_elt = build_reply_element(request_id, sk_payload)

                offset = getattr(ch, 'prefix_offset', 0)
                body = bytearray()
                body += struct.pack('<H', reply_flags)
                body += reply_elt
                # PATH-A: off-channel — без seq footer

                # Checksum = XOR u32 (BE or LE — same wire bytes)
                cs = _xor_cs(bytes(body))
                body += struct.pack('<I', cs)

                self._log(f'   plaintext body ({len(body)}B): {bytes(body).hex(" ")}', addr)

                # ── PATH-A: OFF-CHANNEL PLAINTEXT send (prefix над клиртекстом + соль) ──
                _off = struct.pack('<I', _prefix_hash(bytes(body), offset)) + bytes(body)
                self.sock.sendto(_off, addr)

                self._log(
                    f'>> [OFF-CH PLAIN] SessionKey key=0x{session_key:08X} '
                    f'req_id=0x{request_id:08X} '
                    f'plain={len(body)}B wire={len(_off)}B off=0x{offset:08X}', addr)
                self._log(f'   wire hex={_off.hex(" ")}', addr)

            elif elt_id == 0x01:  # authenticate (client echoes sessionKey)
                self._log('<< authenticate (sessionKey echo)', addr)
                ch.established = True
                # After authenticate, send player bootstrap
                try:
                    self._send_player_bootstrap(addr, ch)
                    self._log('>> player bootstrap sent', addr)
                except Exception as e:
                    self._log(f'   bootstrap error: {e}', addr)
                return

            else:
                self._log(f'   ⚠ Unknown elt_id=0x{elt_id:02X}', addr, 'WARN')
                return

        # ── PHASE 2: On-channel packets (after channel established) ──
        if (flags & FLAG_IS_ON_CHANNEL):
            ch.client_seq = _client_seq_from_packet(data, hdr_off)
            self._send_ack(addr, ch)
            return


    def _generate_account_entity_stream(self, request_id: int, client_seq: int,
                                        prefix_offset: int = 0) -> bytes:
        """createBasePlayer(Account) — правильный BigWorld entity stream.

        Раскладка (wg-toolkit client/element.rs + account.rs):
            [0x05][u16 len] u32 entity_id, u16 type(=1), blob_variable(b""),
            string(required_version), string(name),
            python_pickle(server_settings), u8 components=0

        ВАЖНО: это НЕ reply (0xFF). Обычный server-initiated элемент id=0x05,
        длина Variable16. Кадрируется build_account_create_base_player_element
        и кладётся в build_bw_packet напрямую (НЕ через build_reply_element).
        prefix_offset обязателен — иначе клиент дропнет канальный пакет.
        """
        # 1. Закадрированный элемент [0x05][u16 len][payload].
        element = build_account_create_base_player_element(
            entity_id=self.account_entity_id,
            required_version=self.required_version,
            name=self.account_name,
        )

        # 2. Кадрируем в channel-bundle твоим builder'ом (seq/last_rel/checksum).
        pkt = build_bw_packet(
            element,
            is_on_channel=True,
            seq_num=self._seq,
            last_rel=client_seq,
            prefix_offset=prefix_offset,
        )
        self._seq += 1

        return pkt

    def _send_show_gui(self, addr, prefix_offset: int = 0, client_seq: int = 0):
        """Account.showGUI(ctx) — переводит клиент в Ангар.

        Шлётся ОДИН раз на клиента, сразу после createBasePlayer и до пинг-цикла.
        Кадрируется тем же build_bw_packet (on-channel, seq/checksum/prefix), что и
        createBasePlayer. Индекс showGUI и число client-методов резолвятся
        автоматически из Account-схемы (или из Account.def) внутри show_gui.py.
        """
        if addr in self._show_gui_sent:
            return
        try:
            from show_gui import build_show_gui_payload
        except Exception as e:
            self._log(f'⚠️  show_gui.py не найден рядом с server_stub.py: {e}',
                      addr, level='WARN')
            return

        try:
            payload, dbg = build_show_gui_payload(
                database_id=self.database_id,
                account_schema=self.account_schema,
                root_path='.',
            )
        except Exception as e:
            self._log(f'⚠️  showGUI: не удалось определить индекс метода: {e}',
                      addr, level='WARN')
            traceback.print_exc()
            return

        pkt = build_bw_packet(
            payload,
            is_on_channel=True,
            seq_num=self._seq,
            last_rel=client_seq,
            prefix_offset=prefix_offset,
        )
        self._seq += 1
        self._show_gui_sent.add(addr)
        self.sock.sendto(pkt, addr)
        self._log(
            f'>> showGUI(ctx) ({len(pkt)}B) src={dbg["source"]} '
            f'idx={dbg["method_index"]}/{dbg["exposed_count"]} '
            f'element_id=0x{dbg["element_id"]:02X} sub_id={dbg["sub_id"]} '
            f'db_id={self.database_id} hex={pkt[:48].hex(" ")}', addr)

    def _send_ack(self, addr, ch):
        """Пустой ACK — подтверждаем что пакет получен."""
        pkt = build_bw_packet(b'', is_on_channel=True,
                              seq_num=ch.next_seq(), last_rel=ch.client_seq,
                              prefix_offset=getattr(ch,'prefix_offset',0))  # FIX(prefix-chain): ACK тоже с client offset
        self.sock.sendto(pkt, addr)

    def _send_prereq_reply(self, addr, req_id: int, client_seq: int):
        """
        Ответ на prerequisite запрос клиента.
        Структура: [prereq_count:1][str0...strN][reason:1]
        prereq_count=0 → нет prerequisites, reason=0 → OK.
        """
        prereq_payload = bytearray()
        prereq_payload.append(0)   # prereq_count = 0  (пустой список)
        prereq_payload.append(0)   # reason = 0 (success)

        elem = build_reply_element(req_id, bytes(prereq_payload))
        pkt = build_bw_packet(elem, is_on_channel=True, seq_num=self._seq, last_rel=client_seq)
        self._seq += 1
        self.sock.sendto(pkt, addr)
        self._log(f'>> PrereqReply ({len(pkt)}B) req_id={req_id} hex={pkt.hex(" ")}', addr)


# ───────────────────────────────────────────────────────────────
#  Точка входа
# ───────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────
# Точка входа
# ───────────────────────────────────────────────────────────────
def main():
    print()
    print('╔' + '═' * 58 + '╗')
    print('║  WoT/Mir Tankov 1.23 · BigWorld LoginApp+BaseApp stub   ║')
    print('║  Fixed: Variable32 element len · correct payload fmt    ║')
    print('╚' + '═' * 58 + '╝')
    print()

    # 1. Инициализация DefManager (парсер данных)
    print('[SYSTEM] Loading .def files...')
    def_manager = DefManager(root_path='.')
    def_manager.load()  # Загружаем структуры данных
    print(f'[SYSTEM] DefManager loaded with {len(def_manager)} entities')

    # 2. Инициализация BaseAppStub с передачей def_manager
    # Теперь конструктор BaseAppStub принимает наш def_manager
    base_stub = BaseAppStub(def_manager=def_manager)
    
    # 3. Запуск BaseApp в отдельном потоке
    base_thread = threading.Thread(target=base_stub.run, daemon=True, name='BaseApp')
    base_thread.start()

    # 4. Запуск LoginApp (блокирующий вызов)
    login_app = LoginApp()
    login_app.run() 


if __name__ == '__main__':
    main()