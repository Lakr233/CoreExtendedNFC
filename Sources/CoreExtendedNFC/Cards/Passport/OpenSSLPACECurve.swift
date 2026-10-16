import Foundation

#if canImport(OpenSSL)
    import OpenSSL
#endif

#if canImport(OpenSSL)
    final class OpenSSLPACECurve {
        private let group: OpaquePointer
        private let order: OpaquePointer
        private let ctx: OpaquePointer
        private let coordinateLength: Int
        private let scalarLength: Int

        init(parameterID: PACEHandler.DomainParameterID) throws {
            guard let group = EC_GROUP_new_by_curve_name(parameterID.opensslNID) else {
                throw NFCError.cryptoError("PACE: failed to create elliptic-curve group")
            }
            guard let order = BN_new() else {
                EC_GROUP_free(group)
                throw NFCError.cryptoError("PACE: failed to allocate OpenSSL bignum for curve order")
            }
            guard let ctx = BN_CTX_new() else {
                BN_free(order)
                EC_GROUP_free(group)
                throw NFCError.cryptoError("PACE: failed to allocate OpenSSL bignum context")
            }
            guard EC_GROUP_get_order(group, order, ctx) == 1 else {
                BN_free(order)
                BN_CTX_free(ctx)
                EC_GROUP_free(group)
                throw NFCError.cryptoError("PACE: failed to query curve order")
            }

            self.group = group
            self.order = order
            self.ctx = ctx
            coordinateLength = (Int(EC_GROUP_get_degree(group)) + 7) / 8
            scalarLength = (Int(BN_num_bits(order)) + 7) / 8
        }

        deinit {
            BN_free(order)
            BN_CTX_free(ctx)
            EC_GROUP_free(group)
        }

        func generatePrivateScalar() throws -> Data {
            while true {
                var random = Data(count: scalarLength)
                let status = random.withUnsafeMutableBytes { bytes in
                    SecRandomCopyBytes(kSecRandomDefault, scalarLength, bytes.baseAddress!)
                }
                guard status == errSecSuccess else {
                    throw NFCError.cryptoError("PACE: failed to generate random scalar")
                }

                let scalar = try makeScalar(random)
                defer { BN_free(scalar) }
                if BN_num_bits(scalar) > 0, BN_cmp(scalar, order) < 0 {
                    return random
                }
            }
        }

        func publicPoint(privateScalar: Data, generator: Data?) throws -> Data {
            let scalar = try makeScalar(privateScalar)
            defer { BN_free(scalar) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate public point")
            }
            defer { EC_POINT_free(result) }

            if let generator {
                let mappedGenerator = try makePoint(generator)
                defer { EC_POINT_free(mappedGenerator) }

                guard EC_POINT_mul(group, result, nil, mappedGenerator, scalar, ctx) == 1 else {
                    throw NFCError.cryptoError("PACE: failed to compute public point")
                }
            } else {
                guard EC_POINT_mul(group, result, scalar, nil, nil, ctx) == 1 else {
                    throw NFCError.cryptoError("PACE: failed to compute mapping public point")
                }
            }

            return try exportPoint(result)
        }

        func sharedPoint(privateScalar: Data, peerPublic: Data) throws -> Data {
            let scalar = try makeScalar(privateScalar)
            defer { BN_free(scalar) }

            let peerPoint = try makePoint(peerPublic)
            defer { EC_POINT_free(peerPoint) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate shared point")
            }
            defer { EC_POINT_free(result) }

            guard EC_POINT_mul(group, result, nil, peerPoint, scalar, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute shared point")
            }

            return try exportPoint(result)
        }

        func mappedGenerator(nonce: Data, sharedPoint: Data) throws -> Data {
            let nonceScalar = try makeReducedScalar(nonce)
            defer { BN_free(nonceScalar) }

            let hPoint = try makePoint(sharedPoint)
            defer { EC_POINT_free(hPoint) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate mapped generator")
            }
            defer { EC_POINT_free(result) }

            guard EC_POINT_mul(group, result, nonceScalar, nil, nil, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute nonce contribution for mapped generator")
            }
            guard EC_POINT_add(group, result, result, hPoint, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute mapped generator")
            }

            return try exportPoint(result)
        }

        func sharedSecretXCoordinate(privateScalar: Data, peerPublic: Data) throws -> Data {
            let scalar = try makeScalar(privateScalar)
            defer { BN_free(scalar) }

            let peerPoint = try makePoint(peerPublic)
            defer { EC_POINT_free(peerPoint) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate shared-secret point")
            }
            defer { EC_POINT_free(result) }

            guard EC_POINT_mul(group, result, nil, peerPoint, scalar, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute shared secret")
            }

            return try exportXCoordinate(result)
        }

        /// Whether two encoded points are the same curve point, whatever their encoding.
        ///
        /// - Throws: `NFCError.cryptoError` when either encoding is not a valid point.
        func isSamePoint(_ lhs: Data, _ rhs: Data) throws -> Bool {
            let lhsPoint = try makePoint(lhs)
            defer { EC_POINT_free(lhsPoint) }
            let rhsPoint = try makePoint(rhs)
            defer { EC_POINT_free(rhsPoint) }
            return EC_POINT_cmp(group, lhsPoint, rhsPoint, ctx) == 0
        }

        private func makeScalar(_ data: Data) throws -> OpaquePointer {
            let scalar = data.withUnsafeBytes { bytes in
                BN_bin2bn(
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(data.count),
                    nil
                )
            }
            guard let scalar else {
                throw NFCError.cryptoError("PACE: failed to decode scalar value")
            }
            return scalar
        }

        private func makeReducedScalar(_ data: Data) throws -> OpaquePointer {
            let input = try makeScalar(data)
            guard let reduced = BN_new() else {
                BN_free(input)
                throw NFCError.cryptoError("PACE: failed to allocate reduced scalar")
            }
            guard BN_div(nil, reduced, input, order, ctx) == 1 else {
                BN_free(reduced)
                BN_free(input)
                throw NFCError.cryptoError("PACE: failed to reduce nonce modulo curve order")
            }
            BN_free(input)
            return reduced
        }

        private func makePoint(_ data: Data) throws -> OpaquePointer {
            guard let point = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate EC point")
            }

            let loaded = data.withUnsafeBytes { bytes in
                EC_POINT_oct2point(
                    group,
                    point,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    data.count,
                    ctx
                )
            }
            guard loaded == 1,
                  EC_POINT_is_at_infinity(group, point) == 0,
                  EC_POINT_is_on_curve(group, point, ctx) == 1
            else {
                EC_POINT_free(point)
                throw NFCError.cryptoError("PACE: invalid elliptic-curve point")
            }
            return point
        }

        private func exportPoint(_ point: OpaquePointer) throws -> Data {
            let form = POINT_CONVERSION_UNCOMPRESSED
            let length = EC_POINT_point2oct(group, point, form, nil, 0, ctx)
            guard length > 0 else {
                throw NFCError.cryptoError("PACE: failed to export EC point")
            }

            var output = Data(count: length)
            let written = output.withUnsafeMutableBytes { bytes in
                EC_POINT_point2oct(
                    group,
                    point,
                    form,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    length,
                    ctx
                )
            }
            guard written == length else {
                throw NFCError.cryptoError("PACE: failed to encode EC point")
            }
            return output
        }

        private func exportXCoordinate(_ point: OpaquePointer) throws -> Data {
            guard let x = BN_new(), let y = BN_new() else {
                throw NFCError.cryptoError("PACE: failed to allocate affine coordinates")
            }
            defer {
                BN_free(x)
                BN_free(y)
            }

            guard EC_POINT_get_affine_coordinates(group, point, x, y, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to read shared-secret coordinates")
            }

            var output = Data(count: coordinateLength)
            let written = output.withUnsafeMutableBytes { bytes in
                BN_bn2binpad(
                    x,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(coordinateLength)
                )
            }
            guard written == coordinateLength else {
                throw NFCError.cryptoError("PACE: failed to encode shared-secret x-coordinate")
            }
            return output
        }
    }

    private extension PACEHandler.DomainParameterID {
        var opensslNID: Int32 {
            switch self {
            case .secp256r1:
                Int32(NID_X9_62_prime256v1)
            case .secp384r1:
                Int32(NID_secp384r1)
            case .secp521r1:
                Int32(NID_secp521r1)
            default:
                Int32(NID_undef)
            }
        }
    }
#endif
