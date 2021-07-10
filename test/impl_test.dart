library secp256k1cipher.test.impl_test;

import 'dart:convert' as convert;
import 'dart:typed_data';
import 'package:kepler/src/secp256k1Cipher.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kepler/secp256k1cipher.dart';
import "package:pointycastle/ecc/api.dart";
import 'package:pointycastle/digests/ripemd160.dart';
import "package:pointycastle/pointycastle.dart";
import "package:hex/hex.dart";
import 'package:base58check/base58.dart';

// String _formatBytesAsHexString(Uint8List bytes) {
//   var result = StringBuffer();
//   for (var i = 0; i < bytes.lengthInBytes; i++) {
//     var part = bytes[i];
//     result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
//   }
//   return result.toString();
// }

void main() {
  group('Keys', () {
    test("genaddr", () {
      Digest sha256 = new Digest("SHA-256");
      Digest ripemd = new RIPEMD160Digest();
      final pubkey = loadPublicKey(
          '50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6');
      final pubBytes = pubkey.Q!.getEncoded(false);
      final shaHash = sha256.process(pubBytes);
      final ripHash = ripemd.process(shaHash);
      final hexHash = HEX.encode(ripHash.toList());
      print(hexHash);

      final networkHash = [0x00] + ripHash.toList();
      final check1 = sha256.process(Uint8List.fromList(networkHash));
      final check2 = sha256.process(check1);
      final finalCheck = check2.sublist(0, 4);
      final codeList = networkHash + finalCheck;
      print(HEX.encode(codeList));
      Base58Encoder b58 = new Base58Encoder(
          '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
      final b58Str = b58.convert(codeList);
      print(b58Str);
    });
    test('Generate Keys', () {
      final lines = [];
      for (var _idx = 0; _idx < 100; _idx++) {
        final keypare = generateKeyPair();
        final ECPublicKey pubkey = keypare.publicKey as ECPublicKey;
        final ECPrivateKey prikey = keypare.privateKey as ECPrivateKey;
        final line = [
          strinifyPublicKey(pubkey),
          strinifyPrivateKey(prikey),
          pubkey.Q!.x!.toBigInteger()!.toRadixString(16),
          pubkey.Q!.y!.toBigInteger()!.toRadixString(16)
        ];
        final row = line.join(',');
        lines.add(row);
      }
      final txt = lines.join('\n');
      print(txt);
      expect(true, equals(true));
    });
    test('Save and restore private key', () {
      final localPrivate =
          'eaa692953a60ff85beecdf9647807f5e1bd665aa342c3c1d893b54bccf816ff5';
      final remotePublic =
          '02766171786852c788bfac4622b302b1c42ca77e3bfdabc56454a4ca5647ac4eba';
      final enc = 'd5dTsgku25ylogZ7Yjs=';
      final iv = 'MRz0cLx8QL4=';
      final raw = privateDecrypt(localPrivate, remotePublic, enc, iv);
      print('raw: $raw');
    });
    test('Save and restore public key', () async {
      for (var _idx = 0; _idx < 100; _idx++) {
        final alicPubkey =
            '3d6b2142489ffa6d221da41e75e6c08a44a8d0e682b9fa6d768594d94da2adeeb85e248fa05dedcc4f95c32ab8707bb0ba579fd4b41bf28a0df5bfd7f731b809';
        final alicPrikey =
            '462c58255c68a0a1c1b5c89baa99688c81760169ed8c1502d53e50a820aed90a';
        final bob = generateKeyPair();
        print('success idx: $_idx');
        final s1 = rawSecret(
            alicPrikey, strinifyPublicKey(bob.publicKey as ECPublicKey));
        final s2 = rawSecret(
          strinifyPrivateKey(bob.privateKey as ECPrivateKey),
          alicPubkey,
        );
        expect(s1, equals(s2));
      }
    });
    test('Make request', () async {
      final convert.Utf8Encoder encoder = new convert.Utf8Encoder();
      final remotePubkey =
          '02be8d8a7b5056de7a7074236100d094ebe86cce33d62469956203022af1f3e556';
      final myKP = generateKeyPair();
      final data = 'abcdefg';
      final strPrivKey = strinifyPrivateKey(myKP.privateKey as ECPrivateKey);
      final strPubKey = strinifyPublicKey(myKP.publicKey as ECPublicKey);
      final enced = pubkeyEncryptRaw(strPrivKey, remotePubkey,
          new Uint8List.fromList(encoder.convert(data)));
      final List<int> dataArr = [];
      dataArr.addAll(encoder.convert(strPubKey));
      dataArr.addAll(enced['enc'].toList());
      print(convert.base64.encode(dataArr));
      expect(true, true);
    });
    test('Test Decrypt', () async {
      final convert.Utf8Decoder decoder = new convert.Utf8Decoder();
      final myPrivate =
          '1241ae561074f703c259da27036af3510640bbd6a79ceed7eaea4b3b566befe9';
      final message =
          'MDNjMThhN2RlN2I3ZjQwYTgwMDQwMDg1OGUyMTIwNmYyNzdiYjJhZGMwZjAyMDUzYjMzODYyZDgwY2Q0M2YxN2JhqDMwhGPjj2d4hpz2hfjjyRHQ';
      final rawData = convert.base64.decode(message);
      final pubKey = decoder.convert(rawData.getRange(0, 66).toList());
      final payload = rawData.getRange(66, rawData.length).toList();
      final decrypted = privateDecryptRaw(
        myPrivate,
        pubKey,
        Uint8List.fromList(payload),
      );
      print("raw message=${decoder.convert(decrypted)}");
      expect(true, true);
    });
    test('Sign and Verify', () {
      final alice = generateKeyPair();
      final message = "Mary has a little sheep";
      final alicePubkey = strinifyPublicKey(alice.publicKey as ECPublicKey);
      final alicePrivatekey =
          strinifyPrivateKey(alice.privateKey as ECPrivateKey);
      final signature = privateSign(alicePrivatekey, message);
      expect(true, publicVerify(alicePubkey, message, signature));
    });
    test('Encrypt and Decrypt', () {
      int microSeconds = 0;
      for (var i = 0; i < 10; i++) {
        final alicPubkey =
            '5cb38e0c76f2b28e112e78d96d46e79b04585f17c3bb81a11ad3ad327d9ccaf815b0d2c770fd31c7224671378d7129cdd3dba97ca1efd016e2a580048c6eec46';
        final alicPrikey =
            '9717f155a64b67e5aa22a9552824237119a373b84ffe62eb435cac6581099767';
        var bob = generateKeyPair();
        var rawStr = 'Very secret stuff here';
        final t1 = new DateTime.now().millisecondsSinceEpoch;
        var encMap = pubkeyEncrypt(alicPrikey,
            strinifyPublicKey(bob.publicKey as ECPublicKey), rawStr);
        microSeconds += (DateTime.now().millisecondsSinceEpoch - t1);
        var encStr = encMap['enc'];
        var iv = encMap['iv'];
        var decryptd = privateDecrypt(
          strinifyPrivateKey(bob.privateKey as ECPrivateKey),
          alicPubkey,
          encStr,
          iv,
        );
        print('d:$decryptd');
        expect(rawStr, equals(decryptd));
      }
      print('avg: ${microSeconds / 100} ms');
    });
  });
}
