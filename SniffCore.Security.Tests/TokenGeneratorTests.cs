using NUnit.Framework;

namespace SniffCore.Security.Tests
{
    [TestFixture]
    public class TokenGeneratorTests
    {
        [SetUp]
        public void Setup()
        {
            _target = new TokenGenerator();
        }

        private TokenGenerator _target;

        [Test]
        public void Generate_Called_Generates44CharLongToken()
        {
            var token = _target.Generate();

            Assert.That(string.IsNullOrWhiteSpace(token), Is.False);
            Assert.That(token.Length, Is.EqualTo(44)); // internal its called with 32 but 88 because of base64
        }

        [Test]
        public void Generate_CalledThreeTimes_GeneratesAlwaysDifferentTokens()
        {
            var token1 = _target.Generate();
            var token2 = _target.Generate();
            var token3 = _target.Generate();

            Assert.That(string.IsNullOrWhiteSpace(token1), Is.False);
            Assert.That(string.IsNullOrWhiteSpace(token2), Is.False);
            Assert.That(string.IsNullOrWhiteSpace(token3), Is.False);
            Assert.That(token1, Is.Not.EqualTo(token2));
            Assert.That(token2, Is.Not.EqualTo(token3));
            Assert.That(token1, Is.Not.EqualTo(token3));
        }

        [Test]
        public void Generate_CalledWithLength_GeneratesGivenCharLongToken()
        {
            var token = _target.Generate(64);

            Assert.That(string.IsNullOrWhiteSpace(token), Is.False);
            Assert.That(token.Length, Is.EqualTo(88)); // 88 because of base64
        }

        [Test]
        public void Generate_CalledWithLengthThreeTimes_GeneratesAlwaysDifferentTokens()
        {
            var token1 = _target.Generate(64);
            var token2 = _target.Generate(64);
            var token3 = _target.Generate(64);

            Assert.That(string.IsNullOrWhiteSpace(token1), Is.False);
            Assert.That(string.IsNullOrWhiteSpace(token2), Is.False);
            Assert.That(string.IsNullOrWhiteSpace(token3), Is.False);
            Assert.That(token1, Is.Not.EqualTo(token2));
            Assert.That(token2, Is.Not.EqualTo(token3));
            Assert.That(token1, Is.Not.EqualTo(token3));
        }
    }
}