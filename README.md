# eyazisma-imza

Dernek portalının yazışma modülü için **imza köprüsü**: imzacının bilgisayarında çalışır, portalın verdiği özeti akıllı kart ya da token'daki e-imzayla imzalar ve imzayı portala geri gönderir.

> **Durum: deneysel.** Gerçek bir e-imza kartıyla ve resmî bir doğrulayıcıyla henüz denenmedi.

| Ne | Durum |
|---|---|
| CAdES-BES imza (içerik imzanın içinde, `signing-certificate-v2` ile) | Var; OpenSSL ve ikinci bir CMS kütüphanesiyle doğrulanıyor |
| Zaman damgalı imza (CAdES-T, RFC 3161) | Var; sınama zaman damgası hizmetiyle doğrulanıyor |
| Akıllı kart / token (PKCS#11), RSA ve eliptik eğri | Var; yazılımsal token (SoftHSM) ile sınanıyor, gerçek kartla denenmedi |
| Uzun dönemli imza (CAdES-X Long) ve arşiv imzası (CAdES-A) | **Yok.** e-Yazışma rehberi imzada X Long, mühürde A ister |
| İmza ilkesi (profil) tanımlayıcısı | Yok |
| Kamu SM zaman damgası hizmetinin kendine özgü kimlik doğrulaması | Yok; HTTP temel kimlik doğrulaması kullanan hizmetler desteklenir |

Portal uzun dönemli imza istediğinde uygulama ulaşabildiği en yüksek düzeyde (zaman damgalı) imza atar ve bunu imzacıya söyler.

## Nasıl çalışır

1. Portalda yazı sayfasındaki "İmza uygulamasıyla imzala" düğmesi tek kullanımlık, 15 dakika geçerli bir imza bağlantısı üretir ve bu uygulamayı açar.
2. Uygulama bağlantıyla portaldan imzalanacak özeti (ve tanımlıysa zaman damgası hizmetinin bilgisini) alır; yazının sayısını ve konusunu gösterir.
3. İmzacı PIN'ini yazar. İmza bu bilgisayarda atılır ve portala gönderilir; bağlantı harcanır.

Uygulama hiçbir şeyi saklamaz: PIN, imza bağlantısı ve zaman damgası bilgisi yalnız o imza sırasında bellekte durur. Diske yazılan tek şey güvenilen portalların adresleridir.

## Çalıştırma

```bash
eyazisma-imza
```

Uygulama `http://127.0.0.1:51515/` adresinde açılır ve tarayıcıda sayfasını gösterir. Seçenekler:

| Seçenek | Anlamı |
|---|---|
| `--port 51515` | Dinlenecek port; portal varsayılanı bekler |
| `--no-browser` | Sayfayı kendiliğinden açma |
| `--config <dosya>` | Güvenilen portalların tutulduğu dosya |
| `--pkcs11 <dosya>` | Akıllı kart sürücüsünün yolu; verilmezse bilinen yerler denenir (`EYAZISMA_IMZA_PKCS11` ile de verilebilir) |
| `--pfx` | Sınama için sertifikanın dosyadan (PFX) yüklenmesine izin ver |

Akıllı kart için sertifika sağlayıcısının sürücüsü (PKCS#11) kurulu olmalıdır. Kartta birden fazla sertifika varsa belge imzalamaya ayrılmış olan (inkâr edilemezlik) seçilir. PIN yalnız imza sertifikasını taşıyan karta gönderilir.

## Güvenlik

- Yalnız `127.0.0.1` üzerinde dinler; başka bilgisayarlar erişemez.
- Sayfanın çağırdığı API, sayfaya gömülü rastgele bir anahtar ister ve yalnız bu bilgisayara yöneltilmiş, kendi sayfasından gelen istekleri kabul eder. Başka bir web sitesi imza isteği gönderemez.
- İmza bağlantıları `https` olmalıdır ve yalnız kullanıcının açıkça güvendiği portallardan kabul edilir; güvenilmeyen portala istek bile gönderilmez.
- Her imza PIN ile onaylanır.

## Derleme

Go 1.27 ve C derleyicisi gerekir (akıllı kart erişimi yerel kütüphane kullanır); her işletim sistemi kendi üzerinde derlenir.

```bash
git clone https://github.com/bahricanli/eyazisma-imza.git
cd eyazisma-imza
go build ./cmd/eyazisma-imza
go test ./...
```

Kart erişimi testi yazılımsal bir token ister (Debian/Ubuntu: `apt-get install softhsm2 opensc`):

```bash
./scripts/softhsm-test.sh
```

## Yapı

| Paket | İşi |
|---|---|
| `internal/cades` | CAdES imzasını (CMS SignedData) kurar, zaman damgasını alır |
| `internal/token` | Kartın sürücüsü üzerinden imza sertifikasını bulur ve kartta imzalatır |
| `internal/engine` | Anahtarı açma ve imzalama arayüzü; köprü yalnız buna bağlıdır |
| `internal/portal` | İmza bağlantısıyla portaldan özeti alır, imzayı geri gönderir |
| `internal/server` | Bu bilgisayardaki sayfa ve onun API'si |

## Lisans

MIT
