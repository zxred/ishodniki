# BIG_WORLD_HANDSHAKE.md — ФИНАЛЬНЫЙ разбор логина (login_handler.cpp + proxy.cpp)
(BigWorld 14.4.1 OSE · 2026-06-27 · ЗАКРЫВАЕТ ЗАГАДКУ 24 ПРОГОНОВ)

================================================================================
## 🎯 ГЛАВНОЕ: reply ДОЛЖЕН быть ON-CHANNEL ENCRYPTED — но БЕЗ plaintext-префикса
================================================================================
Направление RUN21 (on-channel encrypted) БЫЛО ВЕРНЫМ.
Падало из-за БАГА с plaintext-префиксом (см. encryption_filter.cpp: шифр идёт
с байта 0 на весь пакет; наш 4-байтный открытый префикс сдвигал MAGIC → дроп).

ДОКАЗАТЕЛЬСТВО — proxy.cpp::attachToClient, комментарий строки 664-671 ДОСЛОВНО:
"the login message is off-channel (because we don't know client's address until
we get it), we want to send back the reply ON THE CHANNEL ... if we send this
off-channel the PacketFilters won't work. Also - all downstream traffic to the
client is filtered (i.e. ENCRYPTED)."

================================================================================
## ПОЛНЫЙ ПОТОК ЛОГИНА (точно по коду)
================================================================================
### Шаг 1. Client → baseAppLogin  [OFF-CHANNEL, plaintext]
   - Клиент шлёт off-channel, т.к. канала ещё нет (сервер не знает его адрес).
   - login_handler.cpp::login (стр.109) → ищет/создаёт Proxy →
     pProxy->attachToClient( srcAddr, header.replyID, pChannel )  [стр.148]

### Шаг 2. Server: Proxy::attachToClient  [proxy.cpp:584]
   ПОРЯДОК ОПЕРАЦИЙ (критично!):
   a. [613] pBlockCipher = SymmetricBlockCipher::create( encryptionKey_ )
            encryptionKey_ = BLOB-ключ из логина (Blowfish-ключ канала, 16 байт)
   b. [630] pChannel = new UDPChannel( extInterface, clientAddr, EXTERNAL, ... )
   c. [639] pChannel->setEncryption( pBlockCipher )   ← ШИФР СТАВИТСЯ НА КАНАЛ
   d. [642] setClientChannel( pChannel )
   e. [655] baseApp.addProxy( this )   ← proxy регистрируется по адресу
   f. [672-680] ОТПРАВКА REPLY ON-CHANNEL (УЖЕ ШИФРОВАННОГО):
        bundle = pClientChannel_->bundle()
        bundle.startReply( loginReplyID )    ← REPLY на request клиента (его replyID!)
        bundle << sessionKey_                 ← тело = u32 sessionKey_
        sendBundleToClient()                  ← уходит через канал → EncryptionFilter::send

### Шаг 3. Client получает зашифрованный reply
   - Дешифрует блоб-ключом (весь пакет с байта 0), читает sessionKey_.
   - Теперь у клиента есть шифрованный канал к серверу.

### Шаг 4. Client → authenticate( sessionKey_ )  [ON-CHANNEL, encrypted]
   - baseapp.cpp::authenticate (стр.2997):
     if (header.pChannel == NULL) return;          ← обязан прийти ON-CHANNEL
     proxy = proxies_.find( channel.addr()+salt )  ← salt: UDP=0
     if (proxy.sessionKey() != args.key) → "CHEAT: wrong session key"
   - Совпало → клиент аутентифицирован → дальше bootstrap (createBasePlayer и т.д.)

================================================================================
## ДВА РАЗНЫХ "КЛЮЧА" — НЕ ПУТАТЬ
================================================================================
1. encryptionKey_ (BLOB, 16 байт, string)
   - Blowfish-ключ КАНАЛА. Из RSA-расшифровки при логине.
   - Им шифруется ВЕСЬ канальный трафик (reply, authenticate, bootstrap).
2. sessionKey_ (u32)
   - proxy.cpp:568  sessionKey_ = uint32( timestamp() ); (do/while пока !=0)
   - Генерится СЕРВЕРОМ, шлётся в ТЕЛЕ reply (bundle << sessionKey_).
   - Клиент ЭХАЕТ его в authenticate(args.key). Сервер сверяет.
   - ЭТО НЕ ключ шифрования! Это анти-spoof токен.

ВАЖНО про наш лог login_key=0x00000001 из клиента:
   - Это НЕ sessionKey и НЕ блоб. Скорее attempt/loginAttempts или поле baseAppLoginArgs.
   - Реальная сверка ключа — в authenticate (шаг 4), ПОСЛЕ поднятия канала.
   - Мы её никогда не достигали, т.к. канал не поднимался (префикс-баг).

================================================================================
## ✅ ИТОГ: ЧТО СЕРВЕР ШЛЁТ В ОТВЕТ НА baseAppLogin
================================================================================
ON-CHANNEL пакет, зашифрованный блоб-ключом (encryptionKey_):
  ОТКРЫТЫЙ пакет (до шифрования):
    flags(2,BE) [+FLAG_HAS_REQUESTS? нет — это REPLY] [+FLAG_IS_RELIABLE +HAS_SEQUENCE]
    + REPLY-элемент: REPLY_MESSAGE_IDENTIFIER + replyID(4) + length + sessionKey_(u32)
    + footers: [seq(4)] [checksum(4)]   (checksum последний, XOR u32 BE)
  ЗАШИФРОВАТЬ ЦЕЛИКОМ с байта 0 (EncryptionFilter::send):
    len += 4(MAGIC); wastage=((8-((len+1)%8))%8)+1; len+=wastage
    дописать MAGIC=0xdeadbeef и wastage в хвост; encrypt(all, len)
  ОТПРАВИТЬ. БЕЗ открытого префикса.

================================================================================
## ИСПРАВЛЕНИЯ В server_stub.py (полный список)
================================================================================
1. [ГЛАВНОЕ] Убрать plaintext-префикс(4) с канального пакета. Шифровать с flags(байт0).
2. Reply на baseAppLogin = ON-CHANNEL ENCRYPTED (блоб-ключ), НЕ plaintext (отменить RUN24!).
   ВНИМАНИЕ: RUN24 (off-channel plaintext) был НЕВЕРЕН — откатить к on-channel,
   но БЕЗ префикса (вот почему RUN21 падал).
3. Reply = startReply(loginReplyID) + body(sessionKey_ u32). Это REPLY-элемент,
   reply_id == replyID запроса клиента (не наш request_id!).
4. setEncryption на канал ДО отправки reply (ключ = блоб encryptionKey_).
5. sessionKey_ = u32 (любой ненулевой, по коду = timestamp). Сохранить в proxy,
   сверять в authenticate(args.key).
6. checksum = XOR u32 BIG-ENDIAN, до шифрования, поле=0 при расчёте.
7. wastage сам выравнивает — без отдельного zero-padding.
8. Канал EXTERNAL ⇒ reliable ⇒ всегда FLAG_HAS_SEQUENCE_NUMBER. Footer: [seq][checksum].
9. authenticate приходит ON-CHANNEL (pChannel!=NULL). Proxy ищется по addr+salt(UDP=0).

================================================================================
## ПОЧЕМУ ВСЕ ПРОГОНЫ ПАДАЛИ (единая причина)
================================================================================
RUN<=21: on-channel encrypted, НО с plaintext-префиксом(4) → MAGIC сдвинут → дроп.
RUN24:   off-channel plaintext → клиент ждёт ШИФРОВАННЫЙ канал → дроп.
ИСТИНА:  on-channel encrypted, БЕЗ префикса, весь пакет с байта 0.
         = RUN21 минус префикс. Один-единственный баг (лишние 4 байта).

КРИПТА (ключ/режим/footer/checksum-логика) — была верна. Ошибка чисто в обрамлении.
