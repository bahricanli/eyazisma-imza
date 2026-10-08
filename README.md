# eyazisma-imza

Dernek portalının yazışma modülü için **imza köprüsü**: imzacının bilgisayarında çalışır, portalın verdiği özeti akıllı kart ya da token'daki e-imzayla imzalar ve imzayı portala geri gönderir.

> **Durum: deneysel, gerçek kullanıma hazır değil.**
> Köprünün kendisi (portal bağlantısı, yerel sayfa, güvenlik denetimleri) çalışıyor ve sınanıyor. İmza motoru olarak kullanılan [eimza-go](https://github.com/KilimcininKorOglu/eimza-go) ise attığı imzaya CAdES'in zorunlu tuttuğu "signing-certificate-v2" özniteliğini eklemiyor; çıkan imza geçerli bir CMS imzası ama CAdES-BES değil. Uzun dönem profilleri (CAdES-X Long, CAdES-A) ve akıllı kart erişimi gerçek sertifikayla hiç denenmedi. Motor değiştirilene ya da düzeltilene kadar üretilen imzalar resmî doğrulamadan geçmeyebilir.

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
| `--pfx` | Sınama için sertifikanın dosyadan (PFX) yüklenmesine izin ver |

Akıllı kart için sertifika sağlayıcısının sürücüsü (PKCS#11) kurulu olmalıdır.

## Güvenlik

- Yalnız `127.0.0.1` üzerinde dinler; başka bilgisayarlar erişemez.
- Sayfanın çağırdığı API, sayfaya gömülü rastgele bir anahtar ister ve yalnız bu bilgisayara yöneltilmiş, kendi sayfasından gelen istekleri kabul eder. Başka bir web sitesi imza isteği gönderemez.
- İmza bağlantıları `https` olmalıdır ve yalnız kullanıcının açıkça güvendiği portallardan kabul edilir; güvenilmeyen portala istek bile gönderilmez.
- Her imza PIN ile onaylanır.

## Derleme

Go 1.26 ve C derleyicisi gerekir (akıllı kart erişimi yerel kütüphane kullanır); her işletim sistemi kendi üzerinde derlenir.

```bash
git clone --recurse-submodules https://github.com/bahricanli/eyazisma-imza.git
cd eyazisma-imza
go build ./cmd/eyazisma-imza
go test ./...
```

`eimza-go` belirli bir commit'e sabitlenmiş alt modüldür (`third_party/eimza-go`). Köprü ona yalnız `internal/engine` içindeki `Engine` arayüzü üzerinden bağlıdır; motor bu arayüzün başka bir uygulamasıyla değiştirilebilir.

## Lisans

MIT. `third_party/eimza-go` kendi (MIT) lisansıyla gelir.
