import 'package:pointycastle/pointycastle.dart';
import 'package:secp256k1cipher/secp256k1cipher.dart';

void main() {
  var alic = generateKeyPair(); // Create Alic keypair
  print("priv: " + strinifyPrivateKey(alic.privateKey as ECPrivateKey));
  print("pub: " + strinifyPublicKey(alic.publicKey as ECPublicKey));
  var bob = generateKeyPair(); // Create Bob keypair
  var rawStr =
      'Encrypt and decrypt data use secp256k1'; // This is what alic want to say to bob
  var encMap = pubkeyEncrypt(
      strinifyPrivateKey(alic.privateKey as ECPrivateKey),
      strinifyPublicKey(bob.publicKey as ECPublicKey),
      rawStr); // use alic's privatekey and bob's publickey means alic say to bob
  var encStr = encMap['enc']; // Get encrypted base64 string
  print(encStr);
  var iv = encMap['iv']; // Get random IV
  // next thing, you can send enc_str and IV via internet to bob
  var decryptd = privateDecrypt(
    strinifyPrivateKey(bob.privateKey as ECPrivateKey),
    strinifyPublicKey(alic.publicKey as ECPublicKey),
    encStr,
    iv,
  ); // use bob's privatekey and alic's publickey means bob can read message from alic
  print('alice says: $decryptd');
}
