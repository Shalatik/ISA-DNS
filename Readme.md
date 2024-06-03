# Projekt ISA - DNS tunelování
Autor: Simona Češková (xcesko00)
## Popis projektu:
Cíl projektu je DNS klient a server, kteří budou navzájem spolu komunikovat a tato komunikace bude probíhat díky DNS na portu 53
## Způsob zpuštění projektu:
Pro spuštění na jiném než virtuálním systému s předpřipraveným nastavením pro port 53 je nutno ho vyměnit na 8080, případně ho správně nastavit.
### Kompilace
Pro kompilaci zdrojového kódu je možné použít `Makefile` příkazem `make`.
### Spouštění
```
./dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]
./dns_receiver {BASE_HOST} {DST_DIRPATH}
```
## Použití:
### dns_sender:
`-u` slouží k vynucení vzdáleného DNS serveru, pokud není specifikováno, program využije výchozí DNS server nastavený v systému
`{BASE_HOST}` slouží k nastavení bázové domény všech přenosů (tzn. dotazy budou odesílány na adresy *.{BASE_HOST}, tedy např. edcba.32.1.example.com)
`{DST_FILEPATH}` cesta pod kterou se data uloží na serveru
`[SRC_FILEPATH]` cesta k souboru který bude odesílán, pokud není specifikováno pak program čte data ze STDIN
### dns_receiver:
`{BASE_HOST}` slouží k nastavení bázové domény k příjmu dat
`{DST_DIRPATH}` cesta pod kterou se budou všechny příchozí data/soubory ukládat (cesta specifikovaná klientem bude vytvořena pod tímto adresářem)
