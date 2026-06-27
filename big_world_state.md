# BIG_WORLD_STATE.md — Разбор исходников движка BigWorld 14.4.1 OSE
(анализ для offline-эмулятора WoT 1.23.0.6 · обновлено 2026-06-27)

Источник: programming/bigworld/lib/network/ (encryption_filter.cpp, packet.cpp, udp_bundle.cpp)
Это движок 2014 г. Сетевое ядро (Mercury) с тех пор почти не менялось → релевантно клиенту 1.23.

================================================================================
## ГЛАВНЫЙ ВЫВОД (отвечает на загадку 24 прогонов)
================================================================================
Канальное шифрование (EncryptionFilter) шифрует **ВЕСЬ ПАКЕТ ЦЕЛИКОМ с байта 0**.
НИКАКОГО plaintext-префикса НЕ существует (слова "prefix" нет ни в packet.cpp,
ни в network_interface.cpp). Наш 4-байтовый plaintext-префикс на канале = ЛИШНИЙ.
Он сдвигал данные → MAGIC не на месте → клиент дропал (recv строка "invalid magic").

ВАЖНО: LoginApp и канал BaseApp — РАЗНЫЕ механизмы. LoginApp имел свою login-крипту
(там префикс был ок). Канал = EncryptionFilter (без префикса). Мы по ошибке
применили логику LoginApp к каналу.

================================================================================
## 1. encryption_filter.cpp — КАНАЛЬНОЕ ШИФРОВАНИЕ
================================================================================
MAGIC = 0xdeadbeef (uint32). BLOCK_SIZE = 8 (Blowfish).

### send() — как сервер/клиент ШИФРУЕТ исходящий пакет:
1. len = pPacket->totalSize()              // весь готовый пакет (flags+body+footers+checksum)
2. len += 4                                 // место под MAGIC
3. wastage = ((BLOCK - ((len+1) % BLOCK)) % BLOCK) + 1   // 1..BLOCK, выравнивание
4. len += wastage                           // итоговая len КРАТНА BLOCK
5. startWastage = len - 1                    // последний байт
6. startMagic   = startWastage - 4
7. data[startWastage] = wastage              // записать счётчик wastage в конец
8. *(u32*)(data + startMagic) = 0xdeadbeef   // записать MAGIC перед wastage
9. encrypt(data, out, len)                   // ШИФРОВАТЬ ВСЁ от байта 0 на len байт

   => Финальный датаграм на проводе (всё зашифровано, БЕЗ открытого префикса):
   ENC[ flags(2) + messages + footers + checksum(4) + (zero-pad) + MAGIC(4) + wastage(1) ]
   ВАЖНО: MAGIC и wastage ВНУТРИ шифрования (шифруются вместе со всем).
   ВАЖНО: отдельного zero-padding НЕТ — выравнивание делает сам wastage
          (байты между checksum и MAGIC, если есть, = padding, их съедает len).

### recv() — как клиент ПРИНИМАЕТ наш пакет (где дропает):
1. decrypt(data, data, totalSize)            // дешифр ВСЕГО пакета с байта 0, in-place
   - если totalSize % BLOCK != 0 → -1 → REASON_CORRUPTED_PACKET (DROP #1)
2. startWastage = totalSize - 1
3. startMagic   = startWastage - 4
4. wastage = data[startWastage]
5. packetMagic = *(u32*)(data + startMagic)
6. if (packetMagic != 0xdeadbeef) → DROP #2 "invalid magic"   <<< НАШ СЛУЧАЙ
7. footerSize = wastage + 4
8. if (wastage > BLOCK || footerSize > totalSize) → DROP #3 "illegal wastage"
9. shrink(footerSize)                         // отрезать MAGIC+wastage+pad → чистый пакет

### encrypt() — цепочка (ПОДТВЕРЖДАЕТ нашу BlowfishLesta):
- C[0] = encryptBlock(P[0])                            // первый блок без XOR
- C[i] = encryptBlock( combineBlocks(P[i], P[i-1]) )   // XOR с ПРЕДЫДУЩИМ PLAINTEXT
- pPrevBlock = src+i (т.е. PLAINTEXT предыдущего, НЕ ciphertext!)
  => это НЕ стандартный CBC. prev = открытый текст. Наш код верен.

### decrypt() — инверсия:
- P[i] = decryptBlock(C[i]); if prev: P[i] = combineBlocks(prev, P[i]); prev = P[i]
- combineBlocks = XOR.

ВЫВОД по крипте: наш режим/ключ/footer БЫЛИ ВЕРНЫ всегда. Ошибка только в префиксе.

================================================================================
## 2. packet.cpp — CHECKSUM и структура пакета
================================================================================
### writeChecksum(pChecksum) — как считается checksum:
    sum = 0
    for (pData = data(); pData < pChecksum; pData++)   // от начала пакета до checksum
        sum ^= BW_NTOHL(*pData)                         // XOR 32-битных слов, читать BE
    *pChecksum = BW_HTONL(sum)                           // записать BE

    => CHECKSUM = XOR всех u32-слов (big-endian) от flags до позиции checksum.
       НЕ additive sum. НЕ little-endian. Считается ДО шифрования.
       Поле checksum при расчёте = 0 (обнуляется перед суммированием).

### validateChecksum() — как клиент проверяет: то же самое (XOR u32 BE), обнуляя поле.

### Структура заголовка:
- flags: Packet::Flags (uint16). HEADER_SIZE начинается с flags.
- Поля флагов (из кода): FLAG_HAS_REQUESTS, FLAG_IS_RELIABLE, FLAG_IS_FRAGMENT,
  FLAG_HAS_SEQUENCE_NUMBER, FLAG_HAS_ACKS, FLAG_HAS_CHECKSUM, FLAG_HAS_PIGGYBACKS,
  FLAG_INDEXED_CHANNEL.
- addRequest: firstRequestOffset_ = offset первого request (BW_HTONS, big-endian!).
  next-request link тоже BW_HTONS. => request offsets в СЕТЕВОМ (big-endian) порядке.

================================================================================
## 3. udp_bundle.cpp — СБОРКА ПАКЕТА (порядок footer'ов!)
================================================================================
### preparePackets() — ТОЧНЫЙ порядок записи (footers пишутся НАЗАД от конца):
Для каждого пакета:
1. if shouldUseChecksums: reserveFooter(4); enableFlag(FLAG_HAS_CHECKSUM)
2. writeFlags(packet)             // выставить флаги бандла
3. if channel: channel->writeFlags(packet)
4. if (channel external || RELIABLE || FRAGMENT): reserveFooter(SeqNum); FLAG_HAS_SEQUENCE_NUMBER
5. grow(footerSize); затем packFooter в ТАКОМ порядке (первый packFooter = САМЫЙ КОНЕЦ):
   a. packFooter(Checksum 0)      -> checksum в самом конце (старший offset), pChecksum=back
   b. piggybacks (если есть)
   c. channel->writeFooter(packet)  ИЛИ  (acks: packFooter(AckCount=1); packFooter(ack))
   d. if FLAG_HAS_SEQUENCE_NUMBER: packFooter(seq)
   e. if FLAG_HAS_REQUESTS: packFooter(firstRequestOffset)
   f. if FLAG_IS_FRAGMENT: packFooter(lastSeq); packFooter(firstSeq)
6. writeChecksum(pChecksum)        // ПОСЛЕ всех footer'ов, ДО шифрования

   => РАСКЛАДКА в памяти от младшего к старшему offset:
   [flags(2)] [messages...] [frag:firstSeq,lastSeq] [firstReqOffset] [seq] [acks] [checksum(4)]
   (то, что packFooter'ится ПЕРВЫМ — в конце; checksum всегда последний/старший)

### startReply(id, reliable):
- curIE = InterfaceElement::REPLY (системный REPLY_MESSAGE_IDENTIFIER)
- (*this) << id  — replyID стримится как часть тела (4 байта). Это ответ на request.

### Замечания:
- Внешний канал (isExternal) ВСЕГДА reliable → ВСЕГДА FLAG_HAS_SEQUENCE_NUMBER.
- Off-channel send: seq берётся из seqNumAllocator (nub), не из канала.

================================================================================
## ИТОГ: ПРАВИЛЬНЫЙ WIRE-ФОРМАТ ON-CHANNEL ПАКЕТА (что слать клиенту)
================================================================================
ШАГ A. Собрать ОТКРЫТЫЙ пакет:
   flags(2, BE) + [messages: msgId + payload ...] + footers(в порядке выше) + checksum(4,BE)
   - checksum = XOR u32 BE по всему до поля checksum (поле=0 при расчёте)
ШАГ B. Зашифровать ВЕСЬ открытый пакет EncryptionFilter::send:
   - len = size + 4(magic); wastage=((8-((len+1)%8))%8)+1; len+=wastage
   - дописать MAGIC(0xdeadbeef) и wastage в хвост, encrypt(all, len) с байта 0
ШАГ C. Отправить как есть. БЕЗ открытого префикса.

================================================================================
## ЧТО ПРОВЕРИТЬ В НАШЕМ server_stub.py (вероятные баги)
================================================================================
1. [ГЛАВНОЕ] Убрать plaintext-префикс(4) на канале. Шифровать с flags (байт 0).
2. checksum: XOR u32 BIG-ENDIAN (НЕ additive, НЕ LE). Считать ДО шифрования,
   поле checksum=0 при расчёте. Checksum ВНУТРИ зашифрованной зоны.
3. wastage сам выполняет выравнивание — НЕ делать отдельный zero-padding перед wastage,
   кроме того, что входит в len (zero-pad между checksum и magic допустим, его съедает len).
4. Цепочка: prev = PLAINTEXT предыдущего блока (не ciphertext). C[0] без XOR. (уже верно)
5. Порядок footer: ...[seq][checksum] — seq ПЕРЕД checksum (checksum самый последний).
6. firstRequestOffset и request-links — big-endian (BW_HTONS).

================================================================================
## ОТКРЫТЫЕ ВОПРОСЫ (нужны для финала)
================================================================================
- LoginHandler::login (нет файла): что именно сервер отвечает на baseAppLogin и
  КОГДА ставит EncryptionFilter на клиентский канал. Нужен login_handler.cpp + proxy.cpp.
- baseapp.cpp подтвердил: authenticate() требует pChannel != NULL (приходит ON-CHANNEL),
  сверяет proxy.sessionKey() == args.key. Поиск proxy по channel.addr() + salt(UDP=0).
- Проверить Frida-капчей клиентский ClientAuth: есть ли у НЕГО префикс (ожидаем — нет).
