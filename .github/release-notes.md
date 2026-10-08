**Deneysel sürüm.** Gerçek e-imza kartıyla yalnız macOS'ta (AKİS kart, Intel derlemesi) denendi; Windows'ta kart erişimi hiç denenmedi.

## Hangi dosya

| Sistem | Dosya |
|---|---|
| Windows 64 bit | `eyazisma-imza-windows-amd64.exe` |
| Linux 64 bit | `eyazisma-imza-linux-amd64` |
| macOS, Apple Silicon sürücüsü olan kartlar | `eyazisma-imza-macos-arm64` |
| macOS, yalnız Intel sürücüsü olan kartlar (Rosetta ile) | `eyazisma-imza-macos-intel` |

Kart sürücüsü ile uygulama aynı işlemci mimarisinde olmalıdır. macOS ve Linux'ta dosyayı çalıştırılabilir yapın (`chmod +x <dosya>`). Uygulama kod imzalı değildir; Windows ve macOS ilk açılışta uyarı verir. İndirdiğiniz dosyayı `SHA256SUMS` ile karşılaştırabilirsiniz.

## İlk adımlar

```
eyazisma-imza --cards      # takılı kartı ve sertifikayı gösterir, PIN istemez
eyazisma-imza --install    # oturum açılışında arka planda başlatır
eyazisma-imza --https      # bu bilgisayara özel HTTPS sertifikasını üretir ve tanıtır
```

Ne yaptığı, seçenekleri ve bilinen eksikleri için [README](https://github.com/bahricanli/eyazisma-imza#readme).
