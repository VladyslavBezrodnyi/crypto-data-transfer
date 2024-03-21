using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Crypto
{
    public class KeyExchange
    {
        private readonly ECKeyPairGenerator _keyGenerator;

        public KeyExchange(
            string curvename = "secp256k1")
        {
            var domainParams = ECNamedCurveTable.GetByName(curvename);
            var curveParams = new ECDomainParameters(
                curve: domainParams.Curve, 
                g: domainParams.G, 
                n: domainParams.N, 
                h: domainParams.H, 
                seed: domainParams.GetSeed());
            var random = new SecureRandom();
            var keygenParams = new ECKeyGenerationParameters(curveParams, random);
            var generator = new ECKeyPairGenerator();
            generator.Init(keygenParams);
            _keyGenerator = generator;
        }

        public IKeyPair GenerateKeyPair()
        {
            var keyPair = _keyGenerator.GenerateKeyPair();
            return new KeyPair(keyPair);
        }

        public interface IKeyPair
        {
            string GetSubjectPublicKeyInfo();
            byte[] GenerateSecretKey(string otherPubKeyBase64);
        }

        private class KeyPair : IKeyPair
        {
            private const int _keySize = 256; // bits
            private readonly AsymmetricCipherKeyPair _keyPair;
            private readonly ECDHBasicAgreement _agreement;

            public KeyPair(AsymmetricCipherKeyPair keyPair)
            {
                _keyPair = keyPair;
                _agreement = new ECDHBasicAgreement();
                _agreement.Init(keyPair.Private);
            }

            public string GetSubjectPublicKeyInfo()
            {
                var pubKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keyPair.Public).GetEncoded();
                return Convert.ToBase64String(pubKey);
            }

            public byte[] GenerateSecretKey(string otherPubKeyBase64)
            {
                var agreement = new ECDHBasicAgreement();
                agreement.Init(_keyPair.Private);
                
                var otherPubKeyBytes = Convert.FromBase64String(otherPubKeyBase64);
                var otherPubKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(otherPubKeyBytes);
                var secret = agreement.CalculateAgreement(otherPubKey).ToByteArray();

                return KeyDerivationFunction(secret);
            }

            private byte[] KeyDerivationFunction(
                byte[] key,
                byte[]? salt = null,
                byte[]? info = null)
            {
                var hkdf = new HkdfBytesGenerator(new Sha256Digest());
                hkdf.Init(new HkdfParameters(key, salt, info));
                var derivedKey = new byte[_keySize / 8];
                hkdf.GenerateBytes(derivedKey, 0, derivedKey.Length);
                return derivedKey;
            }
        }
    }
}
