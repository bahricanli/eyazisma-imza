module github.com/bahricanli/eyazisma-imza

go 1.26.1

require (
	github.com/kilimcininkoroglu/eimza-go v0.0.0
	software.sslmate.com/src/go-pkcs12 v0.7.1
)

require (
	github.com/KilimcininKorOglu/kamusm-go v1.2.0 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	go.mozilla.org/pkcs7 v0.9.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
)

replace github.com/kilimcininkoroglu/eimza-go => ./third_party/eimza-go/eimza-go
