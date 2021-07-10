import 'package:pointycastle/pointycastle.dart';
import 'package:kepler/kepler.dart';

void main() {
  // Create Alice's keypair

  var alice = generateKeyPair();

  print(
    "alice private key: " +
        strinifyPrivateKey(alice.privateKey as ECPrivateKey),
  );
  print(
    "alice public key: " + strinifyPublicKey(alice.publicKey as ECPublicKey),
  );

  // Create Bob's keypair
  var bob = generateKeyPair();

  // This is what alice wants to say to bob
  var rawStr = 'Encrypt and decrypt data using secp256k1';

  // use alic's privatekey and bob's publickey means alice says to bob
  var encMap = pubkeyEncrypt(
    strinifyPrivateKey(alice.privateKey as ECPrivateKey),
    strinifyPublicKey(bob.publicKey as ECPublicKey),
    rawStr,
  );

  // Get encrypted base64 string
  var encStr = encMap['enc'];
  print("encrypted text: " + encStr);

  // Get random IV
  var iv = encMap['iv'];
  print("iv: " + iv);
  // Now, you can send enc_str and IV to Bob

  // Use bob's privatekey and alice's publickey to decrypt alices message, for Bob to read.
  var decryptd = privateDecrypt(
    strinifyPrivateKey(bob.privateKey as ECPrivateKey),
    strinifyPublicKey(alice.publicKey as ECPublicKey),
    encStr,
    iv,
  );
  print('decrypted text: $decryptd');
}
