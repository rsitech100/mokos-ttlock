# TTLock Passcode Generator (Go + Gin)

Layanan HTTP kecil (Gin) untuk membuat keyboard passcode TTLock. Struktur dipisah antara handler controller (`internal/handlers`) dan service/logic TTLock (`internal/ttlock`).

## Swagger/OpenAPI
- Swagger UI tersedia di `http://localhost:8088/swagger` (hanya menampilkan endpoint `/passcodes`, memuat `docs/swagger.yaml`).
- Spesifikasi mentah ada di `docs/swagger.yaml` (bisa di-import ke Swagger UI/Insomnia/Postman).

## Konfigurasi
1) Salin `.env.example` menjadi `.env` lalu isi kredensial:
```
TTLOCK_CLIENT_ID=...
TTLOCK_CLIENT_SECRET=...
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
`POST /passcodes`

Body JSON:
```json
{
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
- Service akan otomatis meng-hit `/oauth2/token` untuk mendapatkan access token.
- Jika `passcode_id` kosong, service memanggil `/v3/keyboardPwd/add` (buat passcode baru).
- Jika `passcode_id` diisi, service memanggil `/v3/keyboardPwd/change` (update passcode existing).
- `start_at` dan `end_at` harus format RFC3339 dan `end_at` > `start_at`.

### Replace Passcode
`POST /passcodes/replace`

Payload sama dengan `POST /passcodes`.
- Jika `passcode_id` diisi: service delete dulu passcode lama (`/v3/keyboardPwd/delete`, `deleteType=2`), lalu create ulang (`/v3/keyboardPwd/add`).
- Jika `passcode_id` kosong: langsung create passcode baru.

### Delete Passcode
`DELETE /passcodes?lock_id=25040769&passcode_id=52877108`

Respon contoh:
```json
{
  "deleted": true,
  "lock_id": 25040769,
  "passcode_id": 52877108
}
```

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

## Otomatisasi Auth
Isi `.env` dengan `TTLOCK_USERNAME` dan `TTLOCK_PASSWORD_MD5` (password sudah di-MD5). Service akan otomatis memanggil `/oauth2/token` menggunakan grant_type `password` di belakang layar sebelum membuat passcode, sehingga endpoint `/passcodes` tidak perlu access_token dari klien.
# mokos-lockdoor
# mokos-ttlock
