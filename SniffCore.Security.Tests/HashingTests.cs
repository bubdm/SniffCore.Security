using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace SniffCore.Security.Tests
{
    [TestFixture]
    public class HashingTests
    {
        private Hashing _target;

        [SetUp]
        public void Setup()
        {
            _target = new Hashing();
        }

        [Test]
        public void SetCustomHashingMethod_CalledWithNull_ThrowsException()
        {
            Func<HashAlgorithm> factory = null;

            var action = new TestDelegate(() => _target.SetCustomHashingMethod(factory));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSecureHash_CalledWithNull_ThrowsException()
        {
            string value = null;

            var action = new TestDelegate(() => _target.GenerateSecureHash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSecureHash_Called_GeneratesSecureData()
        {
            var value = "Peter";

            var data = _target.GenerateSecureHash(value);

            Assert.That(data.Salt.Length, Is.EqualTo(32));
            Assert.That(string.IsNullOrWhiteSpace(data.Value), Is.False);
            Assert.That(data.Value, Is.Not.EqualTo(value));
        }

        [Test]
        public void GenerateSecureHash_CalledThreeTimes_GeneratesAlwaysDifferentSecureData()
        {
            var value = "Peter";

            var data1 = _target.GenerateSecureHash(value);
            var data2 = _target.GenerateSecureHash(value);
            var data3 = _target.GenerateSecureHash(value);

            Assert.That(data1.Salt, Is.Not.EqualTo(data2.Salt));
            Assert.That(data2.Salt, Is.Not.EqualTo(data3.Salt));
            Assert.That(data1.Salt, Is.Not.EqualTo(data3.Salt));
            Assert.That(data1.Value, Is.Not.EqualTo(data2.Value));
            Assert.That(data2.Value, Is.Not.EqualTo(data3.Value));
            Assert.That(data1.Value, Is.Not.EqualTo(data3.Value));
        }

        [Test]
        public void GenerateSecureHash_CalledWithNullValue_ThrowsException()
        {
            string value = null;
            var salt = Encoding.UTF8.GetBytes("Salt");

            var action = new TestDelegate(() => _target.GenerateSecureHash(value, salt));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSecureHash_CalledWithNullSalt_ThrowsException()
        {
            string value = "Value";
            byte[] salt = null;

            var action = new TestDelegate(() => _target.GenerateSecureHash(value, salt));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSecureHash_Called_HashesTheStringWithTheSalt()
        {
            var value = "Value";
            var salt = Encoding.UTF8.GetBytes("Salt");

            var hashedValue = _target.GenerateSecureHash(value, salt);

            Assert.That(string.IsNullOrWhiteSpace(hashedValue), Is.False);
            Assert.That(hashedValue, Is.Not.EqualTo(value));
        }

        [Test]
        public void GenerateSecureHash_CalledThreeTimes_ReturnsAlwaysTheSameHash()
        {
            var value = "Value";
            var salt = Encoding.UTF8.GetBytes("Salt");

            var hashedValue1 = _target.GenerateSecureHash(value, salt);
            var hashedValue2 = _target.GenerateSecureHash(value, salt);
            var hashedValue3 = _target.GenerateSecureHash(value, salt);

            Assert.That(hashedValue1, Is.EqualTo(hashedValue2));
            Assert.That(hashedValue2, Is.EqualTo(hashedValue3));
            Assert.That(hashedValue1, Is.EqualTo(hashedValue3));
        }
        
        [Test]
        public void GenerateSHA256Hash_CalledWithNullString_ThrowsException()
        {
            string value = null;

            var action = new TestDelegate(() => _target.GenerateSHA256Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA256Hash_CalledWithString_HashesTheString()
        {
            var value = "Peter";

            var result = _target.GenerateSHA256Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result, Is.Not.EqualTo(value));
            Assert.That(result.Length, Is.EqualTo(64));
        }

        [Test]
        public void GenerateSHA256Hash_CalledThreeTimesWithString_ReturnsAlwaysSameHash()
        {
            var value = "Franz";

            var result1 = _target.GenerateSHA256Hash(value);
            var result2 = _target.GenerateSHA256Hash(value);
            var result3 = _target.GenerateSHA256Hash(value);

            Assert.That(result1.Length, Is.EqualTo(64));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSHA256Hash_CalledWithNullByte_ThrowsException()
        {
            byte[] value = null;

            var action = new TestDelegate(() => _target.GenerateSHA256Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA256Hash_CalledWithBytes_HashesTheString()
        {
            var value = Encoding.UTF8.GetBytes("Peter");

            var result = _target.GenerateSHA256Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(64));
        }

        [Test]
        public void GenerateSHA256Hash_CalledThreeTimesWithBytes_ReturnsAlwaysSameHash()
        {
            var value = Encoding.UTF8.GetBytes("Franz");

            var result1 = _target.GenerateSHA256Hash(value);
            var result2 = _target.GenerateSHA256Hash(value);
            var result3 = _target.GenerateSHA256Hash(value);

            Assert.That(result1.Length, Is.EqualTo(64));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSHA256Hash_CalledWithNullStream_ThrowsException()
        {
            Stream value = null;

            var action = new TestDelegate(() => _target.GenerateSHA256Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA256Hash_CalledWithStream_HashesTheString()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));

            var result = _target.GenerateSHA256Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(64));
        }

        [Test]
        public void GenerateSHA256Hash_CalledThreeTimesWithStream_ReturnsAlwaysSameHash()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Franz"));

            var result1 = _target.GenerateSHA256Hash(value);
            var result2 = _target.GenerateSHA256Hash(value);
            var result3 = _target.GenerateSHA256Hash(value);

            Assert.That(result1.Length, Is.EqualTo(64));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }
        
        [Test]
        public void GenerateSHA384Hash_CalledWithNullString_ThrowsException()
        {
            string value = null;

            var action = new TestDelegate(() => _target.GenerateSHA384Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA384Hash_CalledWithString_HashesTheString()
        {
            var value = "Peter";

            var result = _target.GenerateSHA384Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result, Is.Not.EqualTo(value));
            Assert.That(result.Length, Is.EqualTo(96));
        }

        [Test]
        public void GenerateSHA384Hash_CalledThreeTimesWithString_ReturnsAlwaysSameHash()
        {
            var value = "Franz";

            var result1 = _target.GenerateSHA384Hash(value);
            var result2 = _target.GenerateSHA384Hash(value);
            var result3 = _target.GenerateSHA384Hash(value);

            Assert.That(result1.Length, Is.EqualTo(96));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSHA384Hash_CalledWithNullByte_ThrowsException()
        {
            byte[] value = null;

            var action = new TestDelegate(() => _target.GenerateSHA384Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA384Hash_CalledWithBytes_HashesTheString()
        {
            var value = Encoding.UTF8.GetBytes("Peter");

            var result = _target.GenerateSHA384Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(96));
        }

        [Test]
        public void GenerateSHA384Hash_CalledThreeTimesWithBytes_ReturnsAlwaysSameHash()
        {
            var value = Encoding.UTF8.GetBytes("Franz");

            var result1 = _target.GenerateSHA384Hash(value);
            var result2 = _target.GenerateSHA384Hash(value);
            var result3 = _target.GenerateSHA384Hash(value);

            Assert.That(result1.Length, Is.EqualTo(96));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSHA384Hash_CalledWithNullStream_ThrowsException()
        {
            Stream value = null;

            var action = new TestDelegate(() => _target.GenerateSHA384Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA384Hash_CalledWithStream_HashesTheString()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));

            var result = _target.GenerateSHA384Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(96));
        }

        [Test]
        public void GenerateSHA384Hash_CalledThreeTimesWithStream_ReturnsAlwaysSameHash()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Franz"));

            var result1 = _target.GenerateSHA384Hash(value);
            var result2 = _target.GenerateSHA384Hash(value);
            var result3 = _target.GenerateSHA384Hash(value);

            Assert.That(result1.Length, Is.EqualTo(96));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }
        
        [Test]
        public void GenerateSHA512Hash_CalledWithNullString_ThrowsException()
        {
            string value = null;

            var action = new TestDelegate(() => _target.GenerateSHA512Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA512Hash_CalledWithString_HashesTheString()
        {
            var value = "Peter";

            var result = _target.GenerateSHA512Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result, Is.Not.EqualTo(value));
            Assert.That(result.Length, Is.EqualTo(128));
        }

        [Test]
        public void GenerateSHA512Hash_CalledThreeTimesWithString_ReturnsAlwaysSameHash()
        {
            var value = "Franz";

            var result1 = _target.GenerateSHA512Hash(value);
            var result2 = _target.GenerateSHA512Hash(value);
            var result3 = _target.GenerateSHA512Hash(value);

            Assert.That(result1.Length, Is.EqualTo(128));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSHA512Hash_CalledWithNullByte_ThrowsException()
        {
            byte[] value = null;

            var action = new TestDelegate(() => _target.GenerateSHA512Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA512Hash_CalledWithBytes_HashesTheString()
        {
            var value = Encoding.UTF8.GetBytes("Peter");

            var result = _target.GenerateSHA512Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(128));
        }

        [Test]
        public void GenerateSHA512Hash_CalledThreeTimesWithBytes_ReturnsAlwaysSameHash()
        {
            var value = Encoding.UTF8.GetBytes("Franz");

            var result1 = _target.GenerateSHA512Hash(value);
            var result2 = _target.GenerateSHA512Hash(value);
            var result3 = _target.GenerateSHA512Hash(value);

            Assert.That(result1.Length, Is.EqualTo(128));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSHA512Hash_CalledWithNullStream_ThrowsException()
        {
            Stream value = null;

            var action = new TestDelegate(() => _target.GenerateSHA512Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateSHA512Hash_CalledWithStream_HashesTheString()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));

            var result = _target.GenerateSHA512Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(128));
        }

        [Test]
        public void GenerateSHA512Hash_CalledThreeTimesWithStream_ReturnsAlwaysSameHash()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Franz"));

            var result1 = _target.GenerateSHA512Hash(value);
            var result2 = _target.GenerateSHA512Hash(value);
            var result3 = _target.GenerateSHA512Hash(value);

            Assert.That(result1.Length, Is.EqualTo(128));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }
        
        [Test]
        public void GenerateMD5Hash_CalledWithNullString_ThrowsException()
        {
            string value = null;

            var action = new TestDelegate(() => _target.GenerateMD5Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateMD5Hash_CalledWithString_HashesTheString()
        {
            var value = "Peter";

            var result = _target.GenerateMD5Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result, Is.Not.EqualTo(value));
            Assert.That(result.Length, Is.EqualTo(32));
        }

        [Test]
        public void GenerateMD5Hash_CalledThreeTimesWithString_ReturnsAlwaysSameHash()
        {
            var value = "Franz";

            var result1 = _target.GenerateMD5Hash(value);
            var result2 = _target.GenerateMD5Hash(value);
            var result3 = _target.GenerateMD5Hash(value);

            Assert.That(result1.Length, Is.EqualTo(32));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateMD5Hash_CalledWithNullByte_ThrowsException()
        {
            byte[] value = null;

            var action = new TestDelegate(() => _target.GenerateMD5Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateMD5Hash_CalledWithBytes_HashesTheString()
        {
            var value = Encoding.UTF8.GetBytes("Peter");

            var result = _target.GenerateMD5Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(32));
        }

        [Test]
        public void GenerateMD5Hash_CalledThreeTimesWithBytes_ReturnsAlwaysSameHash()
        {
            var value = Encoding.UTF8.GetBytes("Franz");

            var result1 = _target.GenerateMD5Hash(value);
            var result2 = _target.GenerateMD5Hash(value);
            var result3 = _target.GenerateMD5Hash(value);

            Assert.That(result1.Length, Is.EqualTo(32));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateMD5Hash_CalledWithNullStream_ThrowsException()
        {
            Stream value = null;

            var action = new TestDelegate(() => _target.GenerateMD5Hash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateMD5Hash_CalledWithStream_HashesTheString()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));

            var result = _target.GenerateMD5Hash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(32));
        }

        [Test]
        public void GenerateMD5Hash_CalledThreeTimesWithStream_ReturnsAlwaysSameHash()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Franz"));

            var result1 = _target.GenerateMD5Hash(value);
            var result2 = _target.GenerateMD5Hash(value);
            var result3 = _target.GenerateMD5Hash(value);

            Assert.That(result1.Length, Is.EqualTo(32));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateCustomHash_CalledWithNullString_ThrowsException()
        {
            string value = null;

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithStringWithoutSetFactory_ThrowsException()
        {
            var value = "Peter";

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<NullReferenceException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithStringWithFactoryWhichReturnsNull_ThrowsException()
        {
            var value = "Peter";
            _target.SetCustomHashingMethod(() => null);

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<NullReferenceException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithString_HashesTheString()
        {
            var value = "Peter";
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var result = _target.GenerateCustomHash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result, Is.Not.EqualTo(value));
            Assert.That(result.Length, Is.EqualTo(32));
        }
        [Test]
        public void GenerateCustomHash_CalledThreeTimesWithString_ReturnsAlwaysSameHash()
        {
            var value = "Franz";
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var result1 = _target.GenerateCustomHash(value);
            var result2 = _target.GenerateCustomHash(value);
            var result3 = _target.GenerateCustomHash(value);

            Assert.That(result1.Length, Is.EqualTo(32));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateCustomHash_CalledWithNullByte_ThrowsException()
        {
            byte[] value = null;
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithBytesWithoutSetFactory_ThrowsException()
        {
            var value = Encoding.UTF8.GetBytes("Peter");

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<NullReferenceException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithBytesWithFactoryWhichReturnsNull_ThrowsException()
        {
            var value = Encoding.UTF8.GetBytes("Peter");
            _target.SetCustomHashingMethod(() => null);

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<NullReferenceException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithBytes_HashesTheString()
        {
            var value = Encoding.UTF8.GetBytes("Peter");
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var result = _target.GenerateCustomHash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(32));
        }

        [Test]
        public void GenerateCustomHash_CalledThreeTimesWithBytes_ReturnsAlwaysSameHash()
        {
            var value = Encoding.UTF8.GetBytes("Franz");
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var result1 = _target.GenerateCustomHash(value);
            var result2 = _target.GenerateCustomHash(value);
            var result3 = _target.GenerateCustomHash(value);

            Assert.That(result1.Length, Is.EqualTo(32));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateCustomHash_CalledWithNullStream_ThrowsException()
        {
            Stream value = null;
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<ArgumentNullException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithStreamWithoutSetFactory_ThrowsException()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<NullReferenceException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithStreamWithFactoryWhichReturnsNull_ThrowsException()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));
            _target.SetCustomHashingMethod(() => null);

            var action = new TestDelegate(() => _target.GenerateCustomHash(value));

            Assert.Throws<NullReferenceException>(action);
        }

        [Test]
        public void GenerateCustomHash_CalledWithStream_HashesTheString()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Peter"));
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var result = _target.GenerateCustomHash(value);

            Assert.That(string.IsNullOrWhiteSpace(result), Is.False);
            Assert.That(result.Length, Is.EqualTo(32));
        }

        [Test]
        public void GenerateCustomHash_CalledThreeTimesWithStream_ReturnsAlwaysSameHash()
        {
            var value = new MemoryStream(Encoding.UTF8.GetBytes("Franz"));
            _target.SetCustomHashingMethod(() => new MD5CryptoServiceProvider());

            var result1 = _target.GenerateCustomHash(value);
            var result2 = _target.GenerateCustomHash(value);
            var result3 = _target.GenerateCustomHash(value);

            Assert.That(result1.Length, Is.EqualTo(32));
            Assert.That(result1, Is.EqualTo(result2));
            Assert.That(result2, Is.EqualTo(result3));
            Assert.That(result1, Is.EqualTo(result3));
        }

        [Test]
        public void GenerateSalt_Called_Generates32CharLongSalt()
        {
            var result = _target.GenerateSalt();

            Assert.That(result.Length, Is.EqualTo(32));
        }

        [Test]
        public void GenerateSalt_CalledThreeTimes_GeneratesAlwaysDifferentSalts()
        {
            var result1 = _target.GenerateSalt();
            var result2 = _target.GenerateSalt();
            var result3 = _target.GenerateSalt();

            Assert.That(result1, Is.Not.EqualTo(result2));
            Assert.That(result2, Is.Not.EqualTo(result3));
            Assert.That(result1, Is.Not.EqualTo(result3));
        }
    }
}