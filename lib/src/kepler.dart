import "dart:typed_data";
import "dart:math";
import 'dart:convert' as convert;
import "package:pointycastle/export.dart";
import 'package:hex/hex.dart';
import 'package:base58check/base58.dart';
import 'operator.dart';
import 'package:pointycastle/src/impl/secure_random_base.dart';
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

class NullSecureRandom extends SecureRandomBase {
  static final FactoryConfig factoryConfig =
      StaticFactoryConfig(SecureRandom, "Null", () => NullSecureRandom());

  var _nextValue = 0;

  String get algorithmName => "Null";

  void seed(CipherParameters params) {}

  int nextUint8() => clip8(_nextValue++);
}

class Kepler {
  static final SHA3Digest sha3digest = SHA3Digest(256 ~/ 8 * 8);

  /// return a hex string version privateKey
  static String strinifyPrivateKey(ECPrivateKey privateKey) {
    assert(privateKey.d != null);
    return privateKey.d!.toRadixString(16);
  }

  static String leftPadding(String s, int width) {
    final paddingData = '000000000000000';
    final paddingWidth = width - s.length;
    if (paddingWidth < 1) {
      return s;
    }
    return "${paddingData.substring(0, paddingWidth)}$s";
  }

  /// return a BTC Address
  static String btcAddress(ECPublicKey pubkey) {
    assert(pubkey.Q != null);
    Digest sha256 = Digest("SHA-256");
    Digest ripemd = RIPEMD160Digest();
    final pubBytes = pubkey.Q!.getEncoded(false);
    final shaHash = sha256.process(pubBytes);
    final ripHash = ripemd.process(shaHash);
    final networkHash = [0x00] + ripHash.toList();
    final check1 = sha256.process(Uint8List.fromList(networkHash));
    final check2 = sha256.process(check1);
    final finalCheck = check2.sublist(0, 4);
    final codeList = networkHash + finalCheck;
    Base58Encoder b58 = Base58Encoder(
      '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    );
    return b58.convert(codeList);
  }

  /// return a ETH Address
  static String ethAddress(ECPublicKey pubkey) {
    assert(pubkey.Q != null);
    sha3digest.reset();
    final pubBytes = pubkey.Q!.getEncoded(false);
    final addressBytes = sha3digest.process(pubBytes);
    final hexString = HEX.encode(addressBytes);
    return '0x${hexString.substring(24)}';
  }

  /// return a hex string version publicKey
  static String strinifyPublicKey(ECPublicKey publicKey) {
    assert(publicKey.Q != null);
    Uint8List compressedKey = publicKey.Q!.getEncoded(true);
    final codeList = compressedKey.toList();
    return codeList.map((w) {
      final hx = w.toRadixString(16);
      if (hx.length < 2) {
        return '0$hx';
      }
      return hx;
    }).join('');
    //print('bytes:${raw_bytes}');
    //var x_str = left_padding(publicKey.Q.x.toBigInteger().toRadixString(16), 64);
    //var y_str = left_padding(publicKey.Q.y.toBigInteger().toRadixString(16), 64);
    //return "${x_str}${y_str}";
  }

  static String privateSign(String strPrivateKey, String message) {
    ECPrivateKey privateKey = loadPrivateKey(strPrivateKey);
    ECDSASigner singer = ECDSASigner(SHA512Digest(), Mac('SHA-512/HMAC'));
    var privParams =
        PrivateKeyParameter(ECPrivateKey(privateKey.d, privateKey.parameters));
    var signParams = () => ParametersWithRandom(privParams, NullSecureRandom());
    singer.init(true, signParams());
    ECSignature signature = singer.generateSignature(
        Uint8List.fromList(convert.utf8.encode(message))) as ECSignature;
    final xs = signature.r.toRadixString(16);
    final ys = signature.s.toRadixString(16);
    final hexX = leftPadding(xs, 64);
    final hexY = leftPadding(ys, 64);
    return hexX + hexY;
  }

  static bool publicVerify(
    String strPublicKey,
    String message,
    String strSignature,
  ) {
    ECPublicKey publicKey = loadPublicKey(strPublicKey);
    ECDSASigner verifySinger = ECDSASigner(SHA512Digest(), Mac('SHA-512/HMAC'));
    var pubkeyParam =
        PublicKeyParameter(ECPublicKey(publicKey.Q, publicKey.parameters));

    final strR = strSignature.substring(0, 64);
    final strS = strSignature.substring(64, 128);
    final r = BigInt.parse(strR, radix: 16);
    final s = BigInt.parse(strS, radix: 16);

    ECSignature signature = ECSignature(r, s);
    verifySinger.init(false, pubkeyParam);
    return verifySinger.verifySignature(
        Uint8List.fromList(convert.utf8.encode(message)), signature);
  }

  /// return a privateKey from hex string
  static ECPrivateKey loadPrivateKey(String storedkey) {
    final d = BigInt.parse(storedkey, radix: 16);
    final param = ECCurve_secp256k1();
    return ECPrivateKey(d, param);
  }

  /// return a publicKey from hex string
  static ECPublicKey loadPublicKey(String storedkey) {
    final param = ECCurve_secp256k1();
    if (storedkey.length < 120) {
      List<int> codeList = [];
      for (var _idx = 0; _idx < storedkey.length - 1; _idx += 2) {
        final hexStr = storedkey.substring(_idx, _idx + 2);
        codeList.add(int.parse(hexStr, radix: 16));
      }
      final Q = param.curve.decodePoint(codeList);
      return ECPublicKey(Q, param);
    } else {
      final x = BigInt.parse(storedkey.substring(0, 64), radix: 16);
      final y = BigInt.parse(storedkey.substring(64), radix: 16);
      final Q = param.curve.createPoint(x, y);
      return ECPublicKey(Q, param);
    }
  }

  /// return a ECPoint data secret
  static ECPoint rawSecret(String privateString, String publicString) {
    final privateKey = loadPrivateKey(privateString);
    final publicKey = loadPublicKey(publicString);
    assert(privateKey.d != null && publicKey.Q != null);
    final secret = scalarMultiple(
      privateKey.d!,
      publicKey.Q!,
    );
    return secret;
  }

  /// return a Bytes data secret
  static List<List<int>> byteSecret(String privateString, String publicString) {
    final secret = rawSecret(privateString, publicString);
    assert(secret.x != null && secret.y != null);
    final xs = secret.x!.toBigInteger()!.toRadixString(16);
    final ys = secret.y!.toBigInteger()!.toRadixString(16);
    final hexX = leftPadding(xs, 64);
    final hexY = leftPadding(ys, 64);
    final secretBytes = Uint8List.fromList(HEX.decode('$hexX$hexY'));
    final pair = [
      secretBytes.sublist(0, 32),
      secretBytes.sublist(32, 40),
    ];
    return pair;
  }

  /// Encrypt data using target public key
  static Map pubkeyEncrypt(
    String privateString,
    String publicString,
    String message,
  ) {
    convert.Utf8Encoder encoder = convert.Utf8Encoder();
    final enced = pubkeyEncryptRaw(privateString, publicString,
        Uint8List.fromList(encoder.convert(message)));
    return {'enc': convert.base64.encode(enced['enc']), 'iv': enced['iv']};
  }

  static Map pubkeyEncryptRaw(
    String privateString,
    String publicString,
    Uint8List data,
  ) {
    final secretIV = byteSecret(privateString, publicString);
    final secret = Uint8List.fromList(secretIV[0]);
    final iv = Uint8List.fromList(secretIV[1]);
    Salsa20Engine _cipher = Salsa20Engine();
    _cipher.reset();
    _cipher.init(true, _buildParams(secret, iv));
    final Uint8List encData = _cipher.process(data);
    return {'enc': encData, 'iv': convert.base64.encode(iv)};
  }

  /// Decrypt data using self private key
  static String privateDecrypt(
      String privateString, String publicString, String b64encoded,
      [String b64IV = ""]) {
    Uint8List encdData = convert.base64.decode(b64encoded);
    final rawData =
        privateDecryptRaw(privateString, publicString, encdData, b64IV);
    convert.Utf8Decoder decode = convert.Utf8Decoder();
    return decode.convert(rawData.toList());
  }

  static Uint8List privateDecryptRaw(
      String privateString, String publicString, Uint8List encdData,
      [String b64IV = ""]) {
    final secretIV = byteSecret(privateString, publicString);
    final secret = Uint8List.fromList(secretIV[0]);
    final iv = b64IV.length > 6
        ? convert.base64.decode(b64IV)
        : Uint8List.fromList(secretIV[1]);
    Salsa20Engine _cipher = Salsa20Engine();
    _cipher.reset();
    _cipher.init(false, _buildParams(secret, iv));
    return _cipher.process(encdData);
  }

  static ParametersWithIV<KeyParameter> _buildParams(
      Uint8List key, Uint8List iv) {
    return ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
  }

  /// Generate Keypair
  static AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair({
    Uint8List? seed,
  }) {
    var keyParams = ECCurve_secp256k1();
    var random = FortunaRandom();
    if (seed == null) {
      random.seed(KeyParameter(_seed(32)));
    } else {
      random.seed(KeyParameter(seed));
    }
    BigInt n = keyParams.n;
    int nBitLength = n.bitLength;
    BigInt d;
    do {
      d = random.nextBigInteger(nBitLength);
    } while (d == BigInt.zero || (d >= n));
    ECPoint q = scalarMultiple(d, keyParams.G);
    return AsymmetricKeyPair(
      ECPublicKey(q, keyParams),
      ECPrivateKey(d, keyParams),
    );
  }

  static Uint8List _seed(length) {
    var random = Random.secure();
    var seed = List<int>.generate(length, (_) => random.nextInt(256));
    return Uint8List.fromList(seed);
  }
}
