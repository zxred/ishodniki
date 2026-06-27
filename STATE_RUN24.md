# STATE_RUN24 — ServerSessionKey OFF-CHANNEL PLAINTEXT (2026-06-26)

## ДОКАЗАННАЯ БАЗА (изменила стратегию):
- encrypt = BlowfishLesta режим C[i]=E(P[i]^P[i-1]) (FIX#4) — wg-toolkit BlowfishWriter.
- ЭТИМ ЖЕ BlowfishLesta + bf_key (blob) шифруется LoginApp LoginSuccess.
- LoginApp РАБОТАЕТ 100% (salt-fix: клиент читает login_key верно) =>
  => КЛЮЧ канала ВЕРЕН, РЕЖИМ шифра ВЕРЕН. Гипотезы "не тот ключ"/"не тот режим" ОТПАЛИ.
- Оффлайн round-trip нашего 44B пакета: расшифровался в валидный
  ff|len=8|req_id=0x16a3c|sess=0xF04424E5|footer|cs — структура цельная.

## КОРЕНЬ (гипотеза #3, единственная оставшаяся):
Клиент шлёт ClientAuth ОТКРЫТЫМ текстом (flags=0x0001, без ON_CHANNEL) =>
его EncryptionFilter ЕЩЁ НЕ ВКЛЮЧЁН => он НЕ МОЖЕТ расшифровать наш
on-channel ServerSessionKey => дроп => 59 ретрансмитов (req 0x16a3c->0x16a76).
Последовательность BigWorld:
  ClientAuth(plaintext) -> ServerSessionKey(plaintext) -> [оба вкл EncryptionFilter] -> bootstrap(enc)

## ПАТЧ RUN24 (server_stub.py, обработчик elt_id 0x00/0x02):
ServerSessionKey теперь OFF-CHANNEL plaintext:
  elem = build_reply_element(request_id, struct.pack('<I', session_key))
  pkt  = build_bw_packet(elem, is_on_channel=False)   # flags=0x0100 + checksum, как рабочий LoginApp/ping
  sock.sendto(pkt, addr); ch.setup_blowfish(session_key)  # канал готов к bootstrap
Бэкап: server_stub (13).py.

## ТЕСТ:
1. Перезапусти сервер (server_stub.py).
2. Запусти клиент, войди.
3. Признак УСПЕХА: req_id ПЕРЕСТАЁТ расти + в логе сервера появляется
   '<< Client SessionKey confirmation (ШАГ 2)' (elt_id=0x01, ch.established=True).
4. Если шаг2 ОК но bootstrap падает — это ожидаемо (bootstrap на on-channel encrypted, шаг 3).

## ЕСЛИ И ЭТО НЕ СРАБОТАЕТ:
Тогда — и только тогда — Frida-хук BlowfishDecrypt в клиенте (вариант 2):
find_blowfish.js -> RVA функции (НЕ P-array 0x28dc430!) -> hook_crypto.js DECRYPT.
