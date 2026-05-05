# TTLock Passcode Generator (Go + Gin)

Layanan HTTP kecil (Gin) untuk membuat keyboard passcode TTLock. Struktur dipisah antara handler controller (`internal/handlers`) dan service/logic TTLock (`internal/ttlock`).

## Swagger/OpenAPI
- Swagger UI tersedia di `http://localhost:8088/swagger` (hanya menampilkan endpoint `/passcodes`, memuat `docs/swagger.yaml`).
- Spesifikasi mentah ada di `docs/swagger.yaml` (bisa di-import ke Swagger UI/Insomnia/Postman).

## Konfigurasi
1) Salin `.env.example` menjadi `.env` lalu isi kredensial:
```
DATABASE_URL=postgres://postgres:postgres@localhost:5432/mokos?sslmode=disable
# TTLOCK_BASE_URL=https://api.ttlock.com  # opsional jika pakai endpoint regional
```
2) Pastikan Go 1.20+ terpasang.

## Menjalankan
```
go run ./cmd/server
```
Server akan listen di `:8088`.

## MD5 Generator (CLI)
Untuk generate nilai `TTLOCK_PASSWORD_MD5` tanpa menjalankan server:

```bash
go run ./cmd/md5gen -password 'your-plain-password'
```

Output adalah hash MD5 lowercase hex.

## Endpoint
`POST /auth/verify-account`

Body JSON:
```json
{
  "username": "you@example.com",
  "password": "5ebe2294ecd0e0f08eab7690d2a6ee69",
  "md5": true
}
```

Respon contoh:
```json
{
  "verified": true,
  "message": "ttlock account verified"
}
```

`POST /passcodes`

Body JSON:
```json
{
  "kost_id": "6f89a499-3018-45f0-b90f-9906f4c77cca",
  "lock_id": "123456789",
  "passcode": "12331242",
  "passcode_id": "52877108",
  "card_number": "1550390851",
  "name": "Tamu",
  "start_at": "2024-12-24T12:00:00Z",
  "end_at": "2024-12-25T12:00:00Z"
}
```

Respon contoh:
```json
{
  "passcode_id": 987654,
  "passcode": "12331242",
  "start_at": 1735041600000,
  "end_at": 1735128000000
}
```

## Catatan
- `TTLOCK_CLIENT_ID` dan `TTLOCK_CLIENT_SECRET` diambil dari `.env`.
- Service mengambil `email` dan `password` TTLock dari tabel `public.ttlock_integrations` berdasarkan `kost_id` (status `active`).
- Service akan otomatis meng-hit `/oauth2/token` untuk mendapatkan access token.
- Jika `passcode_id` kosong, service memanggil `/v3/keyboardPwd/add` (buat passcode baru).
- Jika `passcode_id` diisi, service memanggil `/v3/keyboardPwd/change` (update passcode existing).
- Jika `card_number` diisi, service juga akan mencari kartu berdasarkan nomor kartu tersebut lalu update `start_at`/`end_at` kartu ke TTLock (`/v3/identityCard/changePeriod`).
- `start_at` dan `end_at` harus format RFC3339 dan `end_at` > `start_at`.

### Replace Passcode
`POST /passcodes/replace`

Payload sama dengan `POST /passcodes`.
- Jika `passcode_id` diisi: service delete dulu passcode lama (`/v3/keyboardPwd/delete`, `deleteType=2`), lalu create ulang (`/v3/keyboardPwd/add`).
- Jika `passcode_id` kosong: langsung create passcode baru.

### Delete Passcode
`DELETE /passcodes?kost_id=6f89a499-3018-45f0-b90f-9906f4c77cca&lock_id=25040769&passcode_id=52877108`

Respon contoh:
```json
{
  "deleted": true,
  "kost_id": "6f89a499-3018-45f0-b90f-9906f4c77cca",
  "lock_id": 25040769,
  "passcode_id": 52877108
}
```

### Add Card
`POST /cards`

Body JSON:
```json
{
  "lock_id": "123456789",
  "card_number": "1550390851",
  "card_name": "Kartu Tamu",
  "start_at": "2024-12-24T12:00:00Z",
  "end_at": "2024-12-25T12:00:00Z"
}
```

`POST /cards` menggunakan `TTLOCK_USERNAME` dan `TTLOCK_PASSWORD_MD5` dari `.env` (tidak pakai `kost_id`).

### Delete Card
`DELETE /cards?kost_id=6f89a499-3018-45f0-b90f-9906f4c77cca&lock_id=25040769&card_number=1550390851`

### MD5 Hash Utility
`POST /hash/md5`

Body:
```json
{ "password": "secret" }
```

Respon:
```json
{ "hash": "5ebe2294ecd0e0f08eab7690d2a6ee69" }
```

## Struktur Data Integrasi
Pastikan tabel berikut ada dan data integration sudah terisi (`email` dan `password` wajib dipakai service):

```sql
CREATE TABLE public.ttlock_integrations (
	id uuid NOT NULL,
	kostid uuid NOT NULL,
	client_id varchar(255) NOT NULL,
	secret_key varchar(255) NOT NULL,
	email varchar(255) NOT NULL,
	"password" varchar(255) NOT NULL,
	status public.enum_ttlock_integrations_status DEFAULT 'active'::enum_ttlock_integrations_status NOT NULL,
	"createdAt" timestamptz NOT NULL,
	"updatedAt" timestamptz NOT NULL,
	CONSTRAINT ttlock_integrations_pkey PRIMARY KEY (id),
	CONSTRAINT ttlock_integrations_kostid_fkey FOREIGN KEY (kostid) REFERENCES public.kosts(id) ON DELETE CASCADE ON UPDATE CASCADE
);
```

# mokos-lockdoor
# mokos-ttlock
