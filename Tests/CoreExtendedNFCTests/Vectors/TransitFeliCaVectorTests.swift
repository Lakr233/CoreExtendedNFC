// Recorded-card and reference-test vectors for the FeliCa, ISO/IEC 15693 and
// transit parsers. Every input below is copied from a reference project's test
// suite or sample dump; the expectations are the values that project's own test
// asserts, translated to this library's model.
//
// ## Sources
// - [FB-FLIP]  FareBot app/src/commonTest/kotlin/com/codebutler/farebot/test/FlipperIntegrationTest.kt
//              @ dc09f6f014: testSuicaFromFlipper (L264-L340), testPasmoFromFlipper (L501-L643),
//              testIcocaFromFlipper (L645-L860). Inputs: Flipper dumps
//              app/src/commonMain/composeResources/files/samples/{Suica,PASMO,ICOCA}.nfc
//              https://github.com/codebutler/farebot
// - [FB-OCT]   FareBot app/src/commonTest/kotlin/com/codebutler/farebot/test/OctopusTransitTest.kt
//              @ dc09f6f014, test2018Card (L101-L110), test2016Card (L113-L120)
// - [MD-OCT]   Metrodroid src/commonTest/kotlin/au/id/micolous/metrodroid/test/OctopusTest.kt
//              @ b910c1806f, test2018Card (L71-L79), test2016Card (L81-L87)
//              https://github.com/metrodroid/metrodroid
// - [MD-TM]    Metrodroid TransitDataSerializedTest.kt L316-L321: dump
//              src/commonTest/assets/tmoney/oldtmoney.json, expected parsed/oldtmoney.json
// - [MD-CEPAS] Metrodroid TransitDataSerializedTest.kt L305-L308: dump
//              src/commonTest/assets/cepas/legacy.xml, expected parsed/cepaslegacy.json
// - [NFCPY]    nfcpy tests/test_tag_tt3.py @ 8a195262fe: TestBlockCode.test_pack (L111-L119),
//              TestServiceCode.test_pack (L69-L70), ndef_data_1 (L135-L136),
//              test_read_without_encryption (L313-L316), test_format_nbr_3_and_nbw_2_and_wipe
//              (L524-L527), test_ndef_read (L633-L686)
//              https://github.com/nfcpy/nfcpy
// - [NEARD]    neard plugins/nfctype5.c t5_get_sys_info_resp (L805-L850): GET SYSTEM
//              INFORMATION info-flag decoding (ISO/IEC 15693-3 §10.4.12)
//              https://git.kernel.org/pub/scm/network/nfc/neard.git
//
// ## Deliberate differences from the references
// - Japan IC balance: FareBot reports `trips[0].balance`, but FareBot builds its trip list
//   oldest-first (SuicaTransitFactory iterates `blocks.indices.reversed()`), so its "balance"
//   is the *oldest* history record's balance (Suica 870, PASMO 500, ICOCA 827). This library
//   reads the 0x008B balance block, which on all three dumps equals the *newest* history
//   record's balance (Suica 10, PASMO 0, ICOCA 175). Both values are asserted below.
// - Japan IC fares: FareBot derives fare = previous record balance − this record balance.
//   The reader does not compute fares (`amount == nil`), so the test derives the same
//   difference from consecutive `balanceAfter` values. FareBot's fare for its first trip
//   compares against a slot outside the parsed list and is skipped.
// - Japan IC tap times: FareBot merges entry/exit times from service 0x108F; this reader
//   only decodes the history date, so for gate trips only the Asia/Tokyo calendar day is compared.
// - Octopus offset: Metrodroid/FareBot pick 350 before 2017-10-01 HKT and 500 after, by scan
//   date. This library defaults to 350 (OctopusConstants.defaultBalanceRawOffset) and takes an
//   explicit `balanceOffset`; the reference values are reproduced with the matching offset.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct TransitFeliCaVectorTests {
    // MARK: - Japan IC (FareBot Flipper dumps)

    @Test
    func `Suica Flipper dump matches FareBot fares, kinds and timestamps`() async throws {
        // [FB-FLIP] Suica.nfc, UID 01 01 02 14 FB 0B 39 06, services 0x008B / 0x090F.
        let result = try await Self.readJapanIC(
            uid: "01 01 02 14 FB 0B 39 06",
            balanceBlock: "00 00 00 00 00 00 00 00 20 00 00 0A 00 00 01 E3",
            history: [
                "16 01 00 02 16 6C E3 3B E6 21 0A 00 00 01 E3 00",
                "16 01 00 02 16 6B E3 36 E3 38 AA 00 00 01 E1 00",
                "16 01 00 02 16 6B E3 3B E3 36 4A 01 00 01 DF 00",
                "16 01 00 02 16 6A E5 37 E3 3D EA 01 00 01 DD 00",
                "16 01 00 02 16 6A E3 3E E5 37 A8 02 00 01 DB 00",
                "16 01 00 02 16 6A E3 3B E3 3E 66 03 00 01 D9 00",
                "16 01 00 02 16 69 F1 01 F2 18 06 04 00 01 D7 00",
                "16 01 00 02 16 69 F2 1A F1 01 D8 04 00 01 D5 00",
                "16 01 00 02 16 64 16 03 25 07 82 05 00 01 D3 00",
                "16 01 00 05 16 64 F0 38 F1 08 54 06 00 01 D1 00",
                "C8 46 00 00 16 64 7B 80 27 40 B8 06 00 01 D0 00",
                "16 01 00 02 16 64 E3 3B E6 29 30 07 00 01 CE 00",
                "08 02 00 00 16 64 E3 3B 00 00 D0 07 00 01 CC 00",
                "08 03 00 00 16 63 E5 2B 00 00 00 00 00 01 CB 00",
                "16 01 00 02 15 3B 03 12 03 0D 6E 00 00 01 CA 00",
                "16 01 00 02 15 39 03 0D 03 12 04 01 00 01 C8 00",
                "16 01 00 02 15 39 03 12 03 0D 9A 01 00 01 C6 00",
                "1A 01 00 02 15 39 25 07 03 12 30 02 00 01 C4 00",
                "16 01 00 02 15 38 CE 1F CE 26 D0 02 00 01 C2 00",
                "16 01 00 02 15 38 CE 26 CE 1F 66 03 00 01 C0 00",
            ]
        )

        // FareBot: JPY(870) = oldest record; the card's 0x008B block and newest record hold 10.
        #expect(result.balanceRaw == 10)
        #expect(result.transactions.first?.balanceAfter == 10)
        #expect(result.transactions.last?.balanceAfter == 870)
        #expect(result.currencyCode == "JPY")
        #expect(result.serialNumber == "01010214FB0B3906")

        Self.check(result.transactions, against: [
            .metro(0), .metro(150), .metro(160), .metro(150), .metro(150), .metro(150),
            .ticketMachine(110), .ticketMachine(-2000), .metro(160),
            .vending(120, at: "2011-03-04T06:28:00Z"),
            .metro(100), .metro(210), .metro(170), .metro(210), .metro(160), .metro(190),
            .metro(190), .metro(160),
            .metro(160, day: "2011-03-10T15:00:00Z"),
            .metro(160, day: "2011-03-12T03:42:00Z"),
        ])

        // Trip 6 (console 0x08, process 0x03 ticket purchase): a ticket machine records one station.
        let oldestFirst = Array(result.transactions.reversed())
        #expect(oldestFirst[6].entryStation == "E52B")
        #expect(oldestFirst[6].exitStation == nil)
    }

    @Test
    func `PASMO Flipper dump matches FareBot fares, kinds and timestamps`() async throws {
        // [FB-FLIP] PASMO.nfc. Slots 11-19 are unused: five hold `00 00 00 80 00 ...`, four are zero.
        let unusedFlagged = "00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00"
        let zero = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        let result = try await Self.readJapanIC(
            uid: "01 01 04 10 D0 0F 59 06",
            balanceBlock: "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 11",
            history: [
                "C7 46 00 00 16 CE 7F 60 48 9F 00 00 00 00 11 00",
                "C7 46 00 00 16 CE 7C E0 48 9F A4 01 00 00 10 00",
                "16 01 00 02 16 CD 82 05 03 0D CA 03 00 00 0F 00",
                "03 02 00 00 16 CD 03 0D 00 00 AA 05 00 00 0E 00",
                "16 01 00 02 16 CD 82 41 82 4C C2 01 00 00 0C 00",
                "16 01 00 02 16 CD EF 03 EF 0B 34 03 00 00 0A 00",
                "16 01 00 02 16 CD F2 0E F3 07 06 04 00 00 08 00",
                "1F 02 00 00 16 CD F2 0E 00 00 D8 04 00 00 06 00",
                "16 01 00 05 16 CD F2 1A F2 0E F0 00 00 00 05 00",
                "16 01 00 02 16 CD E3 3E E3 3B 54 01 00 00 03 00",
                "08 07 00 00 16 CD 00 00 00 00 F4 01 00 00 01 00",
                unusedFlagged, zero, unusedFlagged, zero, unusedFlagged,
                zero, unusedFlagged, zero, unusedFlagged,
            ]
        )

        // FareBot: JPY(500) = oldest record (new issue); the 0x008B block and newest record hold 0.
        #expect(result.balanceRaw == 0)

        // FareBot (like Metrodroid SuicaTrip) drops slots without a valid date: 11 trips.
        // Fixed: dateless (unused) history slots are dropped, as in Metrodroid SuicaTransitData.
        #expect(result.transactions.count == 11)
        let dated = result.transactions.filter { $0.date != nil }
        #expect(dated.count == 11)
        #expect(dated.first?.balanceAfter == 0)
        #expect(dated.last?.balanceAfter == 500)

        // Trip 0 is the new-issue record (console 0x08, process 0x07): it credits the purse
        // (FareBot fare -500, balance 0 -> 500), so a credit kind is expected.
        Self.check(dated, against: [
            .ticketMachine(-500),
            .metro(160), .metro(100), .ticketMachine(-1000), .metro(210), .metro(210),
            .metro(370, day: "2011-06-12T15:00:00Z"),
            .ticketMachine(-1000),
            .metro(480, day: "2011-06-13T07:37:00Z"),
            .pos(550, at: "2011-06-14T06:39:00Z"),
            .pos(420, at: "2011-06-14T06:59:00Z"),
        ])
    }

    @Test
    func `ICOCA Flipper dump matches FareBot fares, kinds, timestamps and stations`() async throws {
        // [FB-FLIP] ICOCA.nfc, UID 01 01 02 12 0E 0F 32 17.
        let result = try await Self.readJapanIC(
            uid: "01 01 02 12 0E 0F 32 17",
            balanceBlock: "00 00 00 00 00 00 00 00 32 00 00 AF 00 00 00 2A",
            history: [
                "16 01 00 02 25 31 8B A5 8A A5 AF 00 00 00 2A A0",
                "C8 46 00 00 16 CE 62 63 DE 43 B3 01 00 00 28 00",
                "C8 46 00 00 16 CB 84 03 92 C7 17 02 00 00 27 00",
                "C8 46 00 00 16 CB 72 A0 40 E3 AD 02 00 00 26 00",
                "05 0D 00 0F 16 CB 0E 51 00 51 3D 04 00 00 25 A0",
                "16 01 00 02 16 C9 E7 01 E8 1F 05 05 00 00 24 A0",
                "16 01 00 02 16 C9 81 1F 81 24 21 07 00 00 22 A0",
                "16 01 00 02 16 C8 81 1C 81 23 E9 07 00 00 20 A0",
                "16 01 00 02 16 C8 5B 06 0C 03 CF 08 00 00 1E 00",
                "1F 02 00 00 16 C8 5B 06 00 00 79 09 00 00 1C 00",
                "C7 46 00 00 16 C8 84 60 2B 7F A9 01 00 00 1B 00",
                "16 01 00 02 16 C8 81 24 84 19 65 04 00 00 1A A0",
                "16 01 00 02 16 C8 81 17 81 24 4B 05 00 00 18 A0",
                "16 01 00 02 16 C8 8A A5 8B AB 59 06 00 00 16 A0",
                "21 02 00 00 16 C8 8A A5 00 00 53 07 00 00 15 80",
                "16 01 00 02 16 C7 C5 50 C5 5C 6B 03 00 00 13 A0",
                "C7 46 00 00 16 C7 4F 20 2B 59 6F 04 00 00 11 00",
                "08 02 00 00 16 C7 01 CC 00 00 2D 08 00 00 10 00",
                "C7 46 00 00 16 C7 4C 20 2B 51 5D 00 00 00 0F 00",
                "C8 46 00 00 16 C6 45 C0 29 4C 3B 03 00 00 0E 00",
            ]
        )

        // FareBot: JPY(827) = oldest record; the 0x008B block and newest record hold 175.
        #expect(result.balanceRaw == 175)
        #expect(result.transactions.first?.balanceAfter == 175)
        #expect(result.transactions.last?.balanceAfter == 827)

        Self.check(result.transactions, against: [
            .vending(0, at: "2011-06-05T23:46:00Z"),
            .pos(734, at: "2011-06-07T00:33:00Z"),
            .ticketMachine(-2000),
            .pos(958, at: "2011-06-07T00:57:00Z"),
            .metro(260, stations: ("C550", "C55C")), // Tofukuji -> Demachiyanagi
            .ticketMachine(-1000), // console 0x21 charge
            .metro(250, stations: ("8AA5", "8BAB")), // Kyoto -> Nijojomae
            .metro(270, stations: ("8117", "8124")), // Shin-Osaka -> Namba
            .metro(230, stations: ("8124", "8419")), // Namba -> Bentencho
            .pos(700, at: "2011-06-08T07:35:00Z"),
            .ticketMachine(-2000), // simple deposit machine charge
            .metro(170, stations: ("5B06", "0C03")), // Bentencho -> (Osaka Loop)
            .metro(230, stations: ("811C", "8123")), // Umeda -> Shinsaibashi
            .metro(200, stations: ("811F", "8124")), // Yodoyabashi -> Namba
            .metro(540, stations: ("E701", "E81F")),
            .bus(200),
            .vending(400, at: "2011-06-11T05:21:00Z"),
            .vending(150, at: "2011-06-11T07:32:00Z"),
            .vending(100, at: "2011-06-14T03:19:00Z"),
            .metro(260, day: "2018-09-17T00:11:00Z"),
        ])

        // FareBot trip 15 (BUS): console 0x05 carries line/stop codes, not rail stations.
        let bus = Array(result.transactions.reversed())[15]
        #expect(bus.metadata["busLineCode"] == "0E51")
        #expect(bus.metadata["busStopCode"] == "0051")
        #expect(bus.entryStation == nil)
        #expect(bus.exitStation == nil)
    }

    // MARK: - Octopus (Metrodroid / FareBot OctopusTest)

    @Test
    func `Octopus 2018 card reproduces the reference balance with offset 500`() async throws {
        // [MD-OCT] / [FB-OCT] test2018Card: block 0x0117 #0, scannedAt 2017-10-02 -> offset 500.
        // Raw 0x164 = 356; (356 - 500) * 10 = -1440 cents (HKD -14.40).
        let block = "00000164000000000000000000000021"
        let result = try await OctopusReader(transport: Self.octopusTransport(block), balanceOffset: 500).readBalance()
        #expect(result.balanceRaw == -1440)
        #expect(result.currencyCode == "HKD")
        #expect(result.cardName == "Octopus")

        // Documented difference: the default offset is 350 whatever the scan date, so the
        // same block reads +HKD 0.60 where Metrodroid/FareBot report -HKD 14.40.
        let defaulted = try await OctopusReader(transport: Self.octopusTransport(block)).readBalance()
        #expect(OctopusConstants.defaultBalanceRawOffset == 350)
        #expect(defaulted.balanceRaw == 60)
    }

    @Test
    func `Octopus 2016 card reproduces the reference balance with offset 350`() async throws {
        // [MD-OCT] / [FB-OCT] test2016Card: scannedAt 2016-01-01 -> offset 350.
        // Raw 0x152 = 338; (338 - 350) * 10 = -120 cents (HKD -1.20).
        let block = "000001520000000000000000000086B1"
        let explicit = try await OctopusReader(transport: Self.octopusTransport(block), balanceOffset: 350).readBalance()
        let defaulted = try await OctopusReader(transport: Self.octopusTransport(block)).readBalance()
        #expect(explicit.balanceRaw == -120)
        #expect(defaulted.balanceRaw == -120)
        #expect(explicit.formattedBalance == "HK$-1.20")
    }

    // MARK: - KS X 6924 T-Money (Metrodroid oldtmoney)

    @Test
    func `T-Money oldtmoney dump matches Metrodroid parsed output`() async throws {
        // [MD-TM] tmoney/oldtmoney.json: appFci, "balance": "000044f2", SFI 4 records 1-8, SFI 3 records 1-4.
        let fci = try Self.hex("6f31b02f0010010810100300001234560319835994201607272021072601000007a120d0000000000000000000000000000000")
        let records = try [
            "012c000044f200000008000034bc07200900200191370003b5422016121111262700000000000000000000000000",
            "012c000079ae00000007000000640720090020006928000ecf202016120918332400000000000000200458080000",
            "012c00007a1200000006000004e20720090020003558001096132016120917511200000000000000300188050000",
            "012c00007ef400000005000034bc0720090020045808000044ab2016120819383600000000000000000000000000",
            "022c0000b3b0000000040000b3b0072009003001880500003efeffffffffffffffffffffffffffffffffffffffff",
            "012c00000000000000040000000007200100200010080040547effffffffffffffffffffffffffffffffffffffff",
            "012c00000000000000020000000007200100200010080040547dffffffffffffffffffffffffffffffffffffffff",
            "012c000000000000000100000000072009002002380000128497ffffffffffffffffffffffffffffffffffffffff",
        ].map(Self.hex)
        let tapRecords = try [
            "0132000003000060000334201612111126270000000034bc08a60dcf0101000000000546c00700002189942c0000000000000000",
            "01320100020000029000c92189942c0000000032640005460000001f010100000000000ac000000004e200000b06054600000000",
            "01320000020000095000c921898e660000000000000004e200000004010100000000007dc000000004e200000b0504e200000000",
            "0132000001400173000334201612081938360000000034bc08a60d750000000000000546c0040000000000000000000000000000",
        ].map(Self.hex)

        let balance = try Self.hex("000044f2")
        let transport = MockTransport()
        transport.apduResponses =
            [
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // Hyundai AID not present
                ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // T-Money AID
                ResponseAPDU(data: balance, sw1: 0x90, sw2: 0x00), // GET BALANCE
            ]
            + records.map { ResponseAPDU(data: $0, sw1: 0x90, sw2: 0x00) }
            + [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83)]
            + tapRecords.map { ResponseAPDU(data: $0, sw1: 0x90, sw2: 0x00) }
            + [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83)]

        let result = try await KSX6924Reader(transport: transport).readBalanceAndHistory()

        // parsed/oldtmoney.json: KRW 17650, serial "1010 0300 0012 3456",
        // validFrom daysSinceEpoch 17009 (2016-07-27), validTo 18834 (2021-07-26).
        #expect(result.cardName == "T-Money")
        #expect(result.currencyCode == "KRW")
        #expect(result.balanceRaw == 17650)
        #expect(result.serialNumber == "1010030000123456")
        #expect(Self.day(result.validFrom, in: "Asia/Seoul") == "2016-07-27")
        #expect(Self.day(result.validUntil, in: "Asia/Seoul") == "2021-07-26")

        // Five trips; records 6-8 have zero cost and an FF timestamp and are dropped.
        // Metrodroid fare is signed (top-up -46000); the library reports magnitude + kind.
        let expected: [(ms: Int64?, fare: Int, balance: Int, type: TransactionType)] = [
            (1_481_423_187_000, 13500, 17650, .trip),
            (1_481_276_004_000, 100, 31150, .trip),
            (1_481_273_472_000, 1250, 31250, .trip),
            (1_481_193_516_000, 13500, 32500, .trip),
            (nil, 46000, 46000, .topup),
        ]
        try #require(result.transactions.count == expected.count)
        for (tx, ref) in zip(result.transactions, expected) {
            #expect(tx.amount == ref.fare)
            #expect(tx.balanceAfter == ref.balance)
            #expect(tx.type == ref.type)
            #expect(tx.date == ref.ms.map { Date(timeIntervalSince1970: Double($0) / 1000) })
        }

        // SFI 3 tap records: the times match SFI 4 records 1-4, as BCD for the airport bus
        // (KOTRIS 820) and packed for Seoul Metro (KOTRIS 201). The Seoul Metro tap off
        // (record 2) ends the journey that record 3 began, 12.9 km later.
        let expectedTaps: [(ms: Int64, event: TransitTapEvent, mode: TransitMode, station: String, distance: Int?)] = [
            (1_481_423_187_000, .tapOn, .bus, "00006000", nil),
            (1_481_276_004_000, .tapOff, .rail, "00000290", 12900),
            (1_481_273_472_000, .tapOn, .rail, "00000950", nil),
            (1_481_193_516_000, .tapOn, .bus, "40017300", nil),
        ]
        try #require(result.tapEvents.count == expectedTaps.count)
        for (index, (tap, ref)) in zip(result.tapEvents, expectedTaps).enumerated() {
            #expect(tap.type == .trip)
            #expect(tap.amount == nil)
            #expect(tap.date == Date(timeIntervalSince1970: Double(ref.ms) / 1000))
            #expect(tap.event == ref.event)
            #expect(tap.mode == ref.mode)
            #expect((ref.event == .tapOn ? tap.entryStation : tap.exitStation) == ref.station)
            #expect(tap.distanceMeters == ref.distance)
            #expect(tap.recordNumber == index + 1)
        }
        #expect(transport.sentAPDUs.last?.bytes == Data([0x00, 0xB2, 0x05, 0x1C, 0x00]))
    }

    // MARK: - CEPAS (Metrodroid cepas/legacy)

    @Test
    func `CEPAS legacy dump matches Metrodroid parsed output`() async throws {
        // [MD-CEPAS] legacy.xml stores decoded fields, not raw APDUs; they are re-encoded
        // here in the CEPAS 2 purse / log layout the reader parses:
        // purse 3: version 2, status 1, balance 897, CAN 1123456789123456,
        // CSN a1b2c3d4e5f60123, expiry 1893427200000 ms, creation 1262188800000 ms,
        // issuer data (32 bytes) 0200000001000002020000...; log records type/amount/date/user-data.
        // The dump holds 4 log records (its logfile-record-count says 5), so the count is 4 here.
        let epoch = 788_889_600 // 1995-01-01 00:00 SGT
        func cepasDay(_ ms: Int) -> [UInt8] {
            let days = (ms / 1000 - epoch) / 86400
            return [UInt8(days >> 8), UInt8(days & 0xFF)]
        }
        func record(type: UInt8, amount: Int, ms: Int, userData: [UInt8]) -> [UInt8] {
            let raw = amount & 0xFF_FFFF
            let seconds = ms / 1000 - epoch
            return [type, UInt8(raw >> 16), UInt8((raw >> 8) & 0xFF), UInt8(raw & 0xFF),
                    UInt8(seconds >> 24), UInt8((seconds >> 16) & 0xFF), UInt8((seconds >> 8) & 0xFF), UInt8(seconds & 0xFF)]
                + userData
        }
        let mrt = record(type: 48, amount: -169, ms: 1_262_275_200_000, userData: Array("BFT-CGA ".utf8))
        let busRefund = record(type: 118, amount: 30, ms: 1_262_361_600_000, userData: Array("BUS106 ".utf8) + [0])
        let bus = record(type: 49, amount: -30, ms: 1_262_361_600_000, userData: Array("BUS106 ".utf8) + [0])
        let firstUse = record(type: 0xF0, amount: 65536, ms: 1_262_188_800_000, userData: Array(repeating: 0, count: 8))

        var purse: [UInt8] = [0x02, 0x01, 0x00, 0x03, 0x81, 0x00, 0x00, 0x00]
        purse += [0x11, 0x23, 0x45, 0x67, 0x89, 0x12, 0x34, 0x56] // CAN
        purse += [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x01, 0x23] // CSN
        purse += cepasDay(1_893_427_200_000) + cepasDay(1_262_188_800_000) // expiry, creation
        purse += [0x00, 0x00, 0x00, 0x01] + Array(repeating: 0, count: 8) // last credit TRP + header
        purse += [0x04, 0x20, 0x00, 0x00, 0x00, 0x04] // record count, issuer data length, last TRP
        purse += mrt + [0x00] // last transaction record, debit options
        purse += try Array(Self.hex("0200000001000002020000000000000000000000000000000000000000000000"))
        #expect(purse.count == 63 + 32)

        let transport = MockTransport()
        transport.apduResponses = [Data(), Data(purse), Data(mrt + busRefund + bus + firstUse)]
            .map { ResponseAPDU(data: $0, sw1: 0x90, sw2: 0x00) }
        let result = try await CEPASReader(transport: transport).readBalanceAndHistory()

        // parsed/cepaslegacy.json: SGD 8.97, serial 1123456789123456, cardName "CEPAS".
        #expect(result.balanceRaw == 897)
        #expect(result.currencyCode == "SGD")
        #expect(result.serialNumber == "1123456789123456")
        #expect(result.cardName == "CEPAS")
        #expect(result.validFrom == Date(timeIntervalSince1970: 1_262_188_800))
        #expect(result.validUntil == Date(timeIntervalSince1970: 1_893_427_200))
        try #require(result.transactions.count == 4)

        // MRT BFT -> CGA, fare 1.69 (SMRT).
        let trip = result.transactions[0]
        #expect(trip.type == .trip)
        #expect(trip.amount == 169)
        #expect(trip.entryStation == "BFT")
        #expect(trip.exitStation == "CGA")
        #expect(trip.date == Date(timeIntervalSince1970: 1_262_275_200))

        // "Bus refund", fare -0.30.
        #expect(result.transactions[1].type == .topup)
        #expect(result.transactions[1].amount == 30)
        #expect(result.transactions[1].date == Date(timeIntervalSince1970: 1_262_361_600))

        // "Bus #106", fare 0.30.
        #expect(result.transactions[2].type == .trip)
        #expect(result.transactions[2].amount == 30)
        #expect(result.transactions[2].metadata["busRoute"] == "106")

        // "First use" (type -16 = 0xF0), mode OTHER, no fare.
        #expect(result.transactions[3].type == .unknown)
        #expect(result.transactions[3].amount == nil)
        #expect(result.transactions[3].date == Date(timeIntervalSince1970: 1_262_188_800))
    }

    // MARK: - FeliCa Type 3 (nfcpy)

    @Test
    func `Block list and service code encodings match nfcpy`() {
        // [NFCPY] TestBlockCode.test_pack: BlockCode(n, access=0, service=s).
        #expect(FeliCaFrame.blockListElement(blockNumber: 12) == Data([0x80, 0x0C]))
        #expect(FeliCaFrame.blockListElement(blockNumber: 255) == Data([0x80, 0xFF]))
        #expect(FeliCaFrame.blockListElement(blockNumber: 256) == Data([0x00, 0x00, 0x01]))
        #expect(FeliCaFrame.blockListElement(blockNumber: 0xFFFF) == Data([0x00, 0xFF, 0xFF]))
        // test_read_without_encryption: BlockCode(1, 0, 1) -> 81 01 in '... 0280008101'.
        #expect(FeliCaFrame.blockListElement(blockNumber: 1, serviceIndex: 1) == Data([0x81, 0x01]))
        // TestServiceCode.test_pack: ServiceCode(number 4, attribute 11) -> 0B 01.
        #expect(FeliCaCommands.encodeServiceCode(4 << 6 | 11) == Data([0x0B, 0x01]))
        #expect(FeliCaType3Reader.readServiceCode == FeliCaCommands.encodeServiceCode(0 << 6 | 11))
        #expect(FeliCaType3Reader.writeServiceCode == FeliCaCommands.encodeServiceCode(0 << 6 | 9))
    }

    @Test
    func `Attribute information blocks from nfcpy decode with valid checksums`() throws {
        // ndef_data_1 block 0: Ver 1.0, Nbr 1, Nbw 1, Nmaxb 5, RW 1, Ln 16, Check 0x0028.
        let a = try FeliCaAttributeInfo(data: Self.hex("10 01 01 00 05 00 00 00 00 00 01 00 00 10 00 28"))
        #expect((a.version, a.nbr, a.nbw, a.nmaxb) == (0x10, 1, 1, 5))
        #expect((a.writeFlag, a.rwFlag, a.ndefLength, a.checksum) == (0, 1, 16, 0x28))

        // test_read_without_encryption block 0: Nmaxb 1, RW 0 (read-only), Check 0x0023.
        let b = try FeliCaAttributeInfo(data: Self.hex("10 01 01 00 01 00 00 00 00 00 00 00 00 10 00 23"))
        #expect((b.nmaxb, b.rwFlag, b.ndefLength, b.checksum) == (1, 0, 16, 0x23))

        // test_format_nbr_3_and_nbw_2_and_wipe: the attribute block nfcpy writes.
        let formatted = try Self.hex("1f 03 02 0007 00000000 00 01 000000 002c")
        let c = try FeliCaAttributeInfo(data: formatted)
        #expect((c.version, c.nbr, c.nbw, c.nmaxb, c.rwFlag, c.ndefLength) == (0x1F, 3, 2, 7, 1, 0))
        #expect(c.encoded() == formatted)
    }

    @Test
    func `nfcpy test_ndef_read message is read with Nbr-sized CHECK commands`() async throws {
        // [NFCPY] test_ndef_read: Nbr 2, Nmaxb 3, Ln 0x27 (39). nfcpy reads block 0, then
        // blocks 1-2 in one CHECK, then block 3, and returns data[16:16+39].
        let data = try Self.hex(
            "10 02 02 00 03 00 00 00 00 00 01 00 00 27 00 3f"
                + "d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f"
                + "72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46"
                + "43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00"
        )
        let blocks = stride(from: 0, to: data.count, by: 16).map { Data(data[$0 ..< $0 + 16]) }
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [:],
            serviceBlocks: [FeliCaType3Reader.readServiceCode: blocks]
        )
        let ndef = try await FeliCaType3Reader(transport: transport).readNDEF()
        #expect(ndef == Data(data[16 ..< 16 + 39]))
        #expect(transport.readLog == [["0B00:0"], ["0B00:1", "0B00:2"], ["0B00:3"]])

        // "readonly tag without content": Ln 0, RW 0 -> empty message, no further reads.
        let empty = MockFeliCaServiceTransport(
            serviceVersions: [:],
            serviceBlocks: [FeliCaType3Reader.readServiceCode: [try Self.hex("10 02 02 00 03 00 00 00 00 00 00 00 00 00 00 17")]]
        )
        #expect(try await FeliCaType3Reader(transport: empty).readNDEF() == Data())
        #expect(empty.readLog == [["0B00:0"]])
    }

    // MARK: - ISO/IEC 15693 GET SYSTEM INFORMATION (neard decoding rules)

    @Test
    func `makeSystemInfo normalises fields decoded with neard's info-flag rules`() throws {
        // Response = flags, info flags, UID (8, LSB first), then DSFID / AFI / memory size /
        // IC ref present per info-flag bits b1-b4 ([NEARD] L829-L846; memory size bytes are
        // "count - 1" and "(size - 1) & 0x1F"). Absent fields become -1, as CoreNFC reports them.
        // Geometry: ICODE SLIX 32 x 4-byte blocks (as in ISO15693Tests); UID bytes are illustrative.
        let full = try Self.decodeSystemInfo(Self.hex("00 0F 78 56 34 12 01 04 01 E0 00 00 1F 03 01"))
        let fullInfo = ISO15693Transport.makeSystemInfo(
            uid: full.uid, dsfid: full.dsfid, afi: full.afi,
            blockSize: full.blockSize, totalBlocks: full.blocks, icReference: full.icRef
        )
        #expect(fullInfo.dsfid == 0x00)
        #expect(fullInfo.afi == 0x00)
        #expect(fullInfo.blockCount == 32)
        #expect(fullInfo.blockSize == 4)
        #expect(fullInfo.icReference == 0x01)
        #expect(fullInfo.uid == Data([0x78, 0x56, 0x34, 0x12, 0x01, 0x04, 0x01, 0xE0]))

        // Only memory size (info flags 0x04), 16-bit block count (b5 = 0x10): 0x07FF + 1 = 2048 blocks.
        let sparse = try Self.decodeSystemInfo(Self.hex("00 14 78 56 34 12 01 04 01 E0 FF 07 03"))
        let sparseInfo = ISO15693Transport.makeSystemInfo(
            uid: sparse.uid, dsfid: sparse.dsfid, afi: sparse.afi,
            blockSize: sparse.blockSize, totalBlocks: sparse.blocks, icReference: sparse.icRef
        )
        #expect(sparseInfo.dsfid == nil)
        #expect(sparseInfo.afi == nil)
        #expect(sparseInfo.icReference == nil)
        #expect(sparseInfo.blockCount == 2048)
        #expect(sparseInfo.blockSize == 4)
    }

    // MARK: - Helpers

    private enum FareBotMode {
        case metro, bus, pos, vending, ticketMachine
    }

    /// One FareBot trip assertion: mode, signed fare, and the timestamp it asserted.
    private struct FareBotTrip {
        let mode: FareBotMode
        let fare: Int
        /// Exact instant (product sales carry hh:mm in bytes 6-7).
        var at: String?
        /// FareBot instant whose Asia/Tokyo calendar day must match (gate trips).
        var day: String?
        var stations: (String, String)?

        static func metro(_ fare: Int, day: String? = nil, stations: (String, String)? = nil) -> Self {
            Self(mode: .metro, fare: fare, day: day, stations: stations)
        }
        static func bus(_ fare: Int) -> Self { Self(mode: .bus, fare: fare) }
        static func pos(_ fare: Int, at: String) -> Self { Self(mode: .pos, fare: fare, at: at) }
        static func vending(_ fare: Int, at: String) -> Self { Self(mode: .vending, fare: fare, at: at) }
        static func ticketMachine(_ fare: Int) -> Self { Self(mode: .ticketMachine, fare: fare) }
    }

    /// Compare reader output (card order, newest first) with FareBot trips (oldest first).
    private static func check(
        _ transactions: [TransitTransaction],
        against reference: [FareBotTrip],
        knownTypeIssues: [Int: String] = [:]
    ) {
        let oldestFirst = Array(transactions.reversed())
        #expect(oldestFirst.count == reference.count)
        let iso = ISO8601DateFormatter()
        for (index, (tx, ref)) in zip(oldestFirst, reference).enumerated() {
            if index > 0, let previous = oldestFirst[index - 1].balanceAfter, let current = tx.balanceAfter {
                #expect(previous - current == ref.fare, "trip \(index) fare")
            }

            let expectedType: TransactionType = switch ref.mode {
            case .metro, .bus: .trip
            case .pos, .vending: .purchase
            case .ticketMachine: ref.fare < 0 ? .topup : .trip
            }
            if let reason = knownTypeIssues[index] {
                withKnownIssue(Comment(rawValue: reason)) {
                    #expect(tx.type == expectedType, "trip \(index) kind")
                }
            } else {
                #expect(tx.type == expectedType, "trip \(index) kind")
            }

            if let at = ref.at {
                #expect(tx.date == iso.date(from: at), "trip \(index) timestamp")
            }
            if let day = ref.day {
                #expect(Self.day(tx.date, in: "Asia/Tokyo") == Self.day(iso.date(from: day), in: "Asia/Tokyo"), "trip \(index) day")
            }
            switch ref.mode {
            case .metro:
                if case let (entry, exit)? = ref.stations {
                    #expect(tx.entryStation == entry, "trip \(index) entry")
                    #expect(tx.exitStation == exit, "trip \(index) exit")
                } else {
                    #expect(tx.entryStation != nil && tx.exitStation != nil, "trip \(index) stations")
                }
            case .pos, .vending:
                #expect(tx.entryStation == nil && tx.exitStation == nil, "trip \(index) stations")
            case .ticketMachine where tx.metadata["processType"] == "02":
                // Charges carry no station (FareBot SuicaTrip.parse: no station for process 0x02).
                // PASMO's new-issue record (process 0x07) holds station code 0000, which FareBot
                // resolves to no station via its station table; the reader keeps the raw code.
                #expect(tx.entryStation == nil && tx.exitStation == nil, "trip \(index) stations")
            case .ticketMachine, .bus:
                break
            }
        }
    }

    private static func readJapanIC(uid: String, balanceBlock: String, history: [String]) async throws -> TransitBalance {
        let balanceService = JapanICConstants.balanceServiceCode
        let historyService = JapanICConstants.historyServiceCode
        let transport = try MockFeliCaServiceTransport(
            serviceVersions: [balanceService: Data([0x00, 0x00]), historyService: Data([0x00, 0x00])],
            serviceBlocks: [balanceService: [hex(balanceBlock)], historyService: history.map(hex)],
            systemCode: JapanICConstants.systemCode,
            identifier: hex(uid)
        )
        return try await JapanICReader(transport: transport).readBalanceAndHistory()
    }

    private static func octopusTransport(_ block: String) throws -> MockFeliCaServiceTransport {
        try MockFeliCaServiceTransport(
            serviceVersions: [OctopusConstants.balanceServiceCode: Data([0x00, 0x00])],
            serviceBlocks: [OctopusConstants.balanceServiceCode: [hex(block)]],
            systemCode: OctopusConstants.systemCode
        )
    }

    /// Decode a raw GET SYSTEM INFORMATION response the way neard's t5_get_sys_info_resp does,
    /// producing CoreNFC-shaped fields (absent = -1).
    private static func decodeSystemInfo(_ response: Data) throws
        -> (uid: Data, dsfid: Int, afi: Int, blocks: Int, blockSize: Int, icRef: Int)
    {
        let bytes = [UInt8](response)
        let infoFlags = bytes[1]
        var offset = 10
        func next() -> Int {
            defer { offset += 1 }
            return Int(bytes[offset])
        }
        let dsfid = infoFlags & 0x01 != 0 ? next() : -1
        let afi = infoFlags & 0x02 != 0 ? next() : -1
        var blocks = -1
        var blockSize = -1
        if infoFlags & 0x04 != 0 {
            blocks = infoFlags & 0x10 != 0 ? (next() | next() << 8) + 1 : next() + 1
            blockSize = (next() & 0x1F) + 1
        }
        let icRef = infoFlags & 0x08 != 0 ? next() : -1
        return (Data(bytes[2 ..< 10]), dsfid, afi, blocks, blockSize, icRef)
    }

    private static func day(_ date: Date?, in zone: String) -> String? {
        guard let date, let timeZone = TimeZone(identifier: zone) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    private static func hex(_ string: String) throws -> Data {
        try #require(Data(hexString: string))
    }
}
