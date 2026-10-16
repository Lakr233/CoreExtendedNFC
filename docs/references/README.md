# Vendored reference documents

Unmodified copies of the freely redistributable specifications CoreExtendedNFC
implements. Everything else the library relies on (ICAO, BSI, ISO/IEC, NFC
Forum, JIS, Sony, NXP, KS, SS) is copyrighted, so it is linked rather than
copied. See [`docs/research/references.html`](../research/references.html)
for the full list.

All files were retrieved on 2026-10-16 and are byte-for-byte the publisher's
copy. Do not edit them. To refresh one, download it again from the source URL
below and update the retrieval date and checksum.

| File | Document | Source URL | Size (bytes) | SHA-256 | Licence basis |
| ---- | -------- | ---------- | ------------ | ------- | ------------- |
| `rfc4493.txt` | RFC 4493, The AES-CMAC Algorithm (June 2006) | https://www.rfc-editor.org/rfc/rfc4493.txt | 38751 | `252850ac038a44e931fdce6cb02b444a18ed1da0c9e212bfdd1da0ed3366fc1c` | IETF (see below) |
| `rfc5280.txt` | RFC 5280, Internet X.509 PKI Certificate and CRL Profile (May 2008) | https://www.rfc-editor.org/rfc/rfc5280.txt | 352580 | `a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d` | IETF (see below) |
| `rfc5652.txt` | RFC 5652, Cryptographic Message Syntax (CMS) (September 2009) | https://www.rfc-editor.org/rfc/rfc5652.txt | 126813 | `dbd209ae7844031f51722c4d9e2d1fa3fff3081319851d581f914f5f0147f918` | IETF (see below) |
| `NIST.FIPS.197-upd1.pdf` | FIPS 197, Advanced Encryption Standard (AES), published 2001-11-26, updated 2023-05-09 | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf | 1184436 | `62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1` | NIST (see below) |
| `NIST.FIPS.180-4.pdf` | FIPS 180-4, Secure Hash Standard (SHS), August 2015 | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf | 833315 | `0455b406d89648d20cbde375561e19c245b9815e894164c2670772e3d54deb82` | NIST (see below) |
| `NIST.SP.800-38b.pdf` | SP 800-38B, Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication (May 2005, updates as of 2016-10-06) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf | 253317 | `da9dc0f1e1f08af917caf4a831a7497cf18997b8046353af89570a812f1ec5a2` | NIST (see below) |

RFC 2119 is not cited anywhere in the repository, so it is not vendored.

## Licence basis

### IETF RFCs

The IETF Trust FAQ, "Reproducing RFCs"
(https://trustee.ietf.org/about/faq/, retrieved 2026-10-16):

> Am I allowed to reproduce whole RFCs? Yes. Since the beginning of the RFC
> series, reproduction of whole RFCs (including translation into a language
> other than English) has been allowed and encouraged. The IETF Trust and the
> RFC Editor place no restrictions on this.

For RFCs published under the Trust Legal Provisions (TLP), such as RFC 5652,
TLP §3.c (https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/,
retrieved 2026-10-16) grants:

> c. Licenses For Use Outside the IETF Standards Process. [...] the IETF Trust
> hereby grants to each person who wishes to exercise such rights, to the
> greatest extent that it is permitted to do so, a non-exclusive,
> royalty-free, worldwide right and license under all copyrights and rights of
> authors: i. to copy, publish, display and distribute IETF Contributions and
> IETF Documents in full and without modification, [...]

TLP 5.0 §2.c says documents published before its effective date (2015-03-25)
"remain subject to the licensing provisions of the IETF copyright policy
document in effect at the time of their contribution or publication". RFC 4493
(2006) and RFC 5280 (May 2008) predate RFC 5378 and carry the BCP 78 notice;
RFC 5652 (September 2009) carries the TLP notice. All three are covered by the
FAQ statement on whole-RFC reproduction above. Each file keeps its original
copyright notice and legends, and none is modified.

### NIST publications

NIST, "Copyright, Fair Use, and Licensing Statements for SRD, Data, Software,
and Technical Series Publications"
(https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications,
retrieved 2026-10-16), section "NIST Technical Series Publications":

> Works authored by NIST employees are not subject to Copyright protection
> within the United States; foreign rights are reserved. To the extent NIST may
> assert rights outside of the United States, the public is granted the
> non-exclusive, perpetual, paid-up, royalty-free, worldwide right to reprint
> works in all formats including print, electronically, and online, and in all
> subsequent editions, and derivative works. Please use the recommended
> citation format below followed by "Republished courtesy of the National
> Institute of Standards and Technology."

This follows 17 U.S.C. §105 (works of the US Government are not subject to
copyright in the US). SP 800-38B also states on its own page iii that it "is
not subject to copyright in the United States".

Citations, as NIST requests:

- National Institute of Standards and Technology (2001, updated 2023),
  Advanced Encryption Standard (AES), Federal Information Processing Standards
  Publication (FIPS) 197-upd1, https://doi.org/10.6028/NIST.FIPS.197-upd1
  (Accessed October 16, 2026). Republished courtesy of the National Institute
  of Standards and Technology.
- National Institute of Standards and Technology (2015), Secure Hash Standard
  (SHS), Federal Information Processing Standards Publication (FIPS) 180-4,
  https://doi.org/10.6028/NIST.FIPS.180-4 (Accessed October 16, 2026).
  Republished courtesy of the National Institute of Standards and Technology.
- Dworkin, M. (2005, updated 2016), Recommendation for Block Cipher Modes of
  Operation: The CMAC Mode for Authentication, NIST Special Publication (SP)
  800-38B, https://doi.org/10.6028/NIST.SP.800-38B (Accessed October 16, 2026).
  Republished courtesy of the National Institute of Standards and Technology.
