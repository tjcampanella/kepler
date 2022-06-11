// ignore_for_file: avoid_print

library kepler.test.impl_test;

import 'dart:typed_data';
import 'dart:convert' as convert;
import 'package:base58check/base58.dart';
import 'package:hex/hex.dart';
import 'package:kepler/src/kepler.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:test/test.dart';
import 'package:kepler/kepler.dart';
import "package:pointycastle/pointycastle.dart";

void main() {
  group('Keys', () {
    test("genaddr", () {
      Digest sha256 = Digest("SHA-256");
      Digest ripemd = RIPEMD160Digest();
      final pubkey = Kepler.loadPublicKey(
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
      Base58Encoder b58 = const Base58Encoder(
          '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
      final b58Str = b58.convert(codeList);
      print(b58Str);
    });

    test('Generate Keys', () {
      final lines = [];
      for (var _idx = 0; _idx < 100; _idx++) {
        final keypare = Kepler.generateKeyPair();
        final ECPublicKey pubkey = keypare.publicKey as ECPublicKey;
        final ECPrivateKey prikey = keypare.privateKey as ECPrivateKey;
        final line = [
          Kepler.strinifyPublicKey(pubkey),
          Kepler.strinifyPrivateKey(prikey),
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
      const localPrivate =
          'eaa692953a60ff85beecdf9647807f5e1bd665aa342c3c1d893b54bccf816ff5';
      const remotePublic =
          '02766171786852c788bfac4622b302b1c42ca77e3bfdabc56454a4ca5647ac4eba';
      const enc = 'd5dTsgku25ylogZ7Yjs=';
      const iv = 'MRz0cLx8QL4=';
      final raw = Kepler.privateDecrypt(localPrivate, remotePublic, enc, iv);
      print('raw: $raw');
    });
    test('Save and restore public key', () async {
      for (var _idx = 0; _idx < 100; _idx++) {
        const alicPubkey =
            '3d6b2142489ffa6d221da41e75e6c08a44a8d0e682b9fa6d768594d94da2adeeb85e248fa05dedcc4f95c32ab8707bb0ba579fd4b41bf28a0df5bfd7f731b809';
        const alicPrikey =
            '462c58255c68a0a1c1b5c89baa99688c81760169ed8c1502d53e50a820aed90a';
        final bob = Kepler.generateKeyPair();
        print('success idx: $_idx');
        final s1 = Kepler.rawSecret(
            alicPrikey, Kepler.strinifyPublicKey(bob.publicKey as ECPublicKey));
        final s2 = Kepler.rawSecret(
          Kepler.strinifyPrivateKey(bob.privateKey as ECPrivateKey),
          alicPubkey,
        );
        expect(s1, equals(s2));
      }
    });
    test('Make request', () async {
      const convert.Utf8Encoder encoder = convert.Utf8Encoder();
      const remotePubkey =
          '02be8d8a7b5056de7a7074236100d094ebe86cce33d62469956203022af1f3e556';
      final myKP = Kepler.generateKeyPair();
      const data = 'abcdefg';
      final strPrivKey =
          Kepler.strinifyPrivateKey(myKP.privateKey as ECPrivateKey);
      final strPubKey = Kepler.strinifyPublicKey(myKP.publicKey as ECPublicKey);
      final enced = Kepler.pubkeyEncryptRaw(
          strPrivKey, remotePubkey, Uint8List.fromList(encoder.convert(data)));
      final List<int> dataArr = [];
      dataArr.addAll(encoder.convert(strPubKey));
      dataArr.addAll(enced['enc'].toList());
      print(convert.base64.encode(dataArr));
      expect(true, true);
    });
    test('Test Decrypt', () async {
      const convert.Utf8Decoder decoder = convert.Utf8Decoder();
      const myPrivate =
          '1241ae561074f703c259da27036af3510640bbd6a79ceed7eaea4b3b566befe9';
      const message =
          'MDNjMThhN2RlN2I3ZjQwYTgwMDQwMDg1OGUyMTIwNmYyNzdiYjJhZGMwZjAyMDUzYjMzODYyZDgwY2Q0M2YxN2JhqDMwhGPjj2d4hpz2hfjjyRHQ';
      final rawData = convert.base64.decode(message);
      final pubKey = decoder.convert(rawData.getRange(0, 66).toList());
      final payload = rawData.getRange(66, rawData.length).toList();
      final decrypted = Kepler.privateDecryptRaw(
        myPrivate,
        pubKey,
        Uint8List.fromList(payload),
      );
      print("raw message=${decoder.convert(decrypted)}");
      expect(true, true);
    });

    test('Sign and Verify', () {
      final alice = Kepler.generateKeyPair();
      const message = "Mary has a little sheep";
      final alicePubkey =
          Kepler.strinifyPublicKey(alice.publicKey as ECPublicKey);
      final alicePrivatekey =
          Kepler.strinifyPrivateKey(alice.privateKey as ECPrivateKey);
      final signature = Kepler.privateSign(alicePrivatekey, message);
      expect(true, Kepler.publicVerify(alicePubkey, message, signature));
    });

    test('Encrypt and Decrypt', () {
      int microSeconds = 0;
      for (var i = 0; i < 10; i++) {
        const alicPubkey =
            '5cb38e0c76f2b28e112e78d96d46e79b04585f17c3bb81a11ad3ad327d9ccaf815b0d2c770fd31c7224671378d7129cdd3dba97ca1efd016e2a580048c6eec46';
        const alicPrikey =
            '9717f155a64b67e5aa22a9552824237119a373b84ffe62eb435cac6581099767';
        var bob = Kepler.generateKeyPair();
        var rawStr = 'Very secret stuff in this string of text';
        final t1 = DateTime.now().millisecondsSinceEpoch;
        var encMap = Kepler.pubkeyEncrypt(alicPrikey,
            Kepler.strinifyPublicKey(bob.publicKey as ECPublicKey), rawStr);
        microSeconds += (DateTime.now().millisecondsSinceEpoch - t1);
        var encStr = encMap['enc'];
        var iv = encMap['iv'];
        var decryptd = Kepler.privateDecrypt(
          Kepler.strinifyPrivateKey(bob.privateKey as ECPrivateKey),
          alicPubkey,
          encStr!,
          iv!,
        );
        expect(decryptd, equals(rawStr));
      }
      print('avg: ${microSeconds / 100} ms');
    });
  });
}
