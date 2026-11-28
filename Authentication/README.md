# Authentication Cheat Sheet (OSWE odaklı)

> **Kural:** Enumeration/brute-force → Intruder (Pro) ya da Python yeter; OSWE'de asıl değer **mantık/token kusurları**nda (2FA bypass, password reset, zayıf token). Login brute-force OSWE'nin merkezi değil, referans olarak tut.

---

## 1. Username enumeration (geçerli kullanıcı adını bul)
Amaç: uygulamanın geçerli vs geçersiz username'e **farklı tepki** vermesini yakalamak. Üç sinyal:

### 1a. Content / status farkı (belirgin)
Geçersiz user ile geçerli user (yanlış şifre) **farklı hata mesajı / status / uzunluk** döndürüyorsa:
- Intruder → Sniper, username pozisyonu, şifre sabit yanlış
- **Length** ya da **Status** sütununda sırıtan satır = geçerli username
- Giriş başarısı genelde **302 redirect** + farklı uzunluk

### 1b. Subtly different (minik fark)
Hata mesajı neredeyse aynı — fark **tek karakter** (nokta `.`, boşluk, ufak kelime farkı):
- Gözle kaçar → **Length** sütununa bak, 1 karakter bile uzunluğu değiştirir
- "Neyin farklı" için: iki cevabı **Burp Comparer**'a at (words/bytes diff)

### 1c. Response timing (içerik aynı, süre farklı)
Geçerli username → sunucu şifreyi **gerçekten hash'leyip kontrol eder** → **yavaş**. Geçersiz → hemen döner → **hızlı**.
- **IP block tuzağı:** çok istek → brute-force koruması engeller. Her isteğe **farklı `X-Forwarded-For`** ekle (sunucu farklı IP sanır).
- **Timing'i büyüt:** **uzun şifre** (~100 karakter) gönder → geçerli user'da hash süresi uzar, fark belirginleşir.
- Intruder: **Pitchfork** → pos1 = XFF sayısı (Numbers), pos2 = username (wordlist), şifre sabit uzun. **"Response received"** (ms) sütununa göre sırala → **en yavaş = geçerli**.
  - Kısa trick: username'i hem XFF hem username'e koy, **Battering ram** (her istek farklı "IP").
- Verilen `wiener:peter` = **kalibrasyon**: bilinen geçerli user'ın süresini görüp eşiği çıkar (saldırı hedefi o değil, wordlist'teki başka user).

Python (timing):
```python
for i, user in enumerate(usernames):
    headers["X-Forwarded-For"] = f"1.1.1.{i}"   # her istek farklı IP
    r = login(user, "a"*100)                      # uzun şifre
    print(user, r.elapsed.total_seconds())        # en yavaş = geçerli
```

### Altın kural: enumerate → SONRA brute-force
Cluster bomb (user × pass = 101×101 = 10100) **israf**. İki aşama:
1. Username bul (101 istek, sabit yanlış şifre)
2. O username'e şifre brute-force (101 istek)
→ Toplam ~202 istek.

---

## 2. Brute-force koruması atlatma

### 2a. IP block (N art arda başarısızlıkta IP engellenir)
İki yol:
- **XFF rotasyonu:** uygulama `X-Forwarded-For`'a güveniyorsa her isteğe farklı XFF → farklı IP sanılır (timing lab'ında bu işe yaradı).
- **Counter-reset (logic flaw):** başarılı giriş sayacı sıfırlıyorsa, araya **kendi geçerli girişini** (wiener:peter) serpiştir → art arda limite ulaşma.
  - Intruder **Pitchfork**, interleaved listeler: username = `wiener,carlos,wiener,carlos...` / password = `peter,pw1,peter,pw2...`
  - **ŞART: Resource pool → Maximum concurrent requests = 1.** Sıra bozulmasın — paralel giderse araya wiener girmeden birkaç carlos-fail üst üste gelir → blok. (Delay değil, **concurrent=1**.)
  - Interleave listesini script'le üret: her candidate pw için önce `(wiener,peter)` sonra `(carlos,pw)` satırı.

### 2b. Account lock (N denemede HESAP kilitlenir)
- **Enumeration sinyali:** "account locked" mesajı **sadece geçerli** user'da çıkar (var olmayan hesap kilitlenemez). Her username'e birkaç başarısız deneme → geçerli olan kilitlenir → **farklı Length**.
  - Intruder **Cluster bomb**: pos1 = username, pos2 = **Null payloads → Generate 5** → her username 5 kez denenir.
  - **GOTCHA: şifre BOŞ olamaz.** Null payload password'ü boşaltırsa sunucu `"Missing parameter"` (400) döner → deneme sayılmaz, kilit tetiklenmez. Çözüm: `password=wrongpass§§` → **sabit dolu** yanlış şifre + sonuna **boş** payload işareti (imleç sona, **Add §** iki kez). Null payload tekrar ettirir, şifre dolu kalır.
- **Kilitli hesabın şifresini bul:** username sabit, Sniper password wordlist → çoğu cevap "locked" (aynı Length) ama **doğru şifre farklı Length** verir → anomaliyi yakala. (Kilitliyken bile doğru şifre sırıtır.)
- **Password spraying (kilidi HİÇ tetiklemeden):** az sayıda şifre (**≤ kilit limiti**) × çok username. Tek bir user o yaygın şifrelerden birini kullanırsa girersin, hiçbir hesap kilitlenmez.
- **Credential stuffing:** sızmış `user:pass` çiftleri, her hesap bir kez denenir → kilit tetiklenmez.

### 2c. User rate limit → multiple credentials per request (EXPERT)
Rate limit **IP'den giden istek SAYISINI** sayıyorsa, tek istekte birden çok şifre dene → limit anlamsızlaşır.
- Login **JSON** ise, `password` alanını tek string yerine **ARRAY** yap:
  ```json
  {"username":"carlos","password":["123456","password","qwerty"]}
  ```
- Backend array'i döngüyle gezer, biri tutarsa **302 + session cookie** → **tek istekte** giriş.
- **Neden çalışır (type confusion):** backend gevşek tipli (Node/JS/Python) + **tip doğrulaması yok** → string beklerken array'i sızdırır, iterate eder. Güçlü tipleme + strict binding (.NET `string Password`) bunu **reddederdi**.
- Form-urlencoded ise JSON'a çevir: `Content-Type: application/json` + body'yi JSON yap.
- Hangi şifrenin tuttuğunu bilmezsin (giriş oldu, yeter); merak → array'i ikiye böl (binary search).
- **Cookie ile içeri girme:** tekrar **LOGIN OLMA** (yeni session basıp carlos'u ezer). Taze carlos session'ını `/` path cookie'sine koy, ya da Repeater'da `GET /my-account?id=carlos` + o cookie → solved. (`/resources/lab...` path'li cookie = lab header'ın kendi session'ı, boşver.)

## 3. Multi-factor (2FA) bypass (OSWE-gold)
- **Simple bypass:** 2FA adımını atlayıp doğrudan sonraki sayfaya git (akış zorlanmıyorsa)
- **Broken logic:** 2FA kodu bir user'a bağlıyken başka user'ın hesabına uygulanıyorsa / kod client-side doğrulanıyorsa
- Kod brute-force (4 hane = 10000) → XFF + script

## 4. Diğer mekanizmalar (OSWE-gold)
- **Stay-logged-in / remember-me cookie:** zayıf token (ör. `base64(username:md5(password))`) → **offline cracking** → **Python'luk iş**
- **Password reset:** token tahmin edilebilir / user'a bağlı değil / **Host header poisoning** (reset linki `X-Forwarded-Host`'a göre üretiliyorsa)
- **Password change:** mevcut şifre kontrolü atlanıyor mu, başka user'ın şifresi değişiyor mu

---

## OSWE Notları
- Enumeration/brute-force → Intruder/Python, hızlı geç. **Asıl kas: mantık/token lab'ları.**
- Zayıf token / reset akışı → **kaynak kod review** refleksi (token nasıl üretiliyor, neye bağlı).
- Her başarıda anomaliyi tanımla: status (302), uzunluk (Length), süre, cookie.
- Brute-force korumaları: "farklı IP olabilir miyim?" (XFF) / "sayacı sıfırlayabilir / kilidi es geçebilir / tek istekte çok deneme yapabilir miyim?" (counter-reset, spraying, stuffing, array).
- **Type confusion refleksi (OSWE-gold):** her girdi için "beklenen tipten FARKLI bir tip gönderirsem?" — array, object, null, number. Tip doğrulanmamışsa açık: multiple-creds array, NoSQL `{"$ne":""}`, PHP type juggling. Güçlü tipleme kapatır; gevşek tip + validation yoksa açılır.
