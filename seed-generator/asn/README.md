# Generated ASN.1 sources

These files are the generated NGAP APER runtime used by the seed example. They are intentionally shipped as source, not as prebuilt objects. The directory contains a dependency-closed public subset (985 NGAP `.c`/`.h` pairs plus the required asn1c runtime). NGAP open-type and protocol-IE descriptors have transitive references across the schema, so the retained set was computed from the generator's link graph and verified in a clean build. Do not delete additional files based only on the fields set in `main.c`.

`asn1c/converter-example.c` is the one exception and is omitted by the Makefile because it is an optional demo that requires a user-selected `-DPDU`. Do not edit generated files by hand; change `../main.c` instead.
