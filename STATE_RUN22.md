# STATE_RUN22 — ПАТЧ ПРИМЕНЁН И ВЕРИФИЦИРОВАН (2026-06-26)
Бэкап: server_stub (12).py

## ПРИМЕНЁННЫЕ ПРАВКИ (server_stub.py):
1. ClientChannel.encrypt_packet / decrypt_packet — полный wrapper по socket.rs:
   prefix(4) клиром; clear[4:] + pad + DEADBEEF + (pad+1); BlowfishLesta СВЕЖИЙ на пакет (prev=0).
   Старые encrypt_body/decrypt_body (обрезали паддинг, без magic) УДАЛЕНЫ.
2. _send_on_channel — переписан:
   flags = ON_CHANNEL|IS_RELIABLE|HAS_CHECKSUM (+CREATE_CHANNEL на 1-м) = 0x0318 / 0x0118
   body = flags + element + seq(4) + [create ver+id если 1-й] + xor_checksum(4)
   prefix=_prefix_hash(body,offset); pkt = encrypt_packet(prefix+body). Шифруется всё после префикса.
3. ClientAuth handler — ServerSessionKey шлётся ON-CHANNEL как reply (было off-channel plaintext).
   setup_blowfish() ставит bf_key=BASEAPP_BF_KEY (login blob).
4. Диспетчер входящих — добавлена расшифровка: если ch.bf_key и (len-4)%8==0, пробуем
   decrypt_packet; валидный DEADBEEF => on-channel, парсим чистые байты; иначе сырой (off-channel).

## ВЕРИФИКАЦИЯ (_test_live_path.py через реальные классы):
clear=168d12da1803ff0800000001000000bebafeca000000000000000000000000a2fd35b7
enc  =168d12daacb43b39686580678ce520ccb0eca65b3409a5a1074c69d2d69ed4db9414c4e68220e2382cb9acce (44B)
ROUNDTRIP OK = True. Совпадает с кандидатом RUN21 байт-в-байт.

## ОСТАЁТСЯ (НЕ КРИТИЧНО ДЛЯ HANDSHAKE):
- build_bw_packet (старый формат 0x0040|0x1000, clear footers) ещё используется для bootstrap/ACK
  (CreateBasePlayer/showGUI, строки ~1124/1164/1179/1194). Это ПОСЛЕ шага 2 — чинить позже,
  переведя их тоже через _send_on_channel/encrypt_packet.

## ЖИВОЙ ТЕСТ (СЛЕДУЮЩИЙ ШАГ):
1. Запустить server_stub.py.
2. find_pid.bat + Frida (hook_login_capture.js) на WorldOfTanks.exe.
3. Войти в игру.
4. УСПЕХ = request_id перестаёт расти + в логе '[ON-CHANNEL DECRYPTED] elt_id=0x01'
   (клиент прислал ClientSessionKey echo — шаг 2). Тогда сервер шлёт bootstrap.
5. Если bootstrap отвергнут — чинить build_bw_packet (см. выше).
