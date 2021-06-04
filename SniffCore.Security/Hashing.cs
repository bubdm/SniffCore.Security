//
// Copyright (c) David Wendland. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SniffCore.Security
{
    /// <summary>
    ///     Provides methods to hash data.
    /// </summary>
    /// <example>
    ///     <code lang="csharp">
    /// <![CDATA[
    /// public void ViewModel : ObservableObject
    /// {
    ///     public IHashing _hashing;
    /// 
    ///     public ViewModel(IHashing hashing)
    ///     {
    ///         _hashing = hashing;
    ///     }
    /// 
    ///     public string SavePassword(string userName, string password)
    ///     {
    ///         var data = _hashing.GenerateSecureHash(password);
    ///         using var userRepo = Context.GetRepo<UserRepository>();
    ///         var entity = userRepo.GetUser(userName);
    ///         entity.Password = data.Value;
    ///         entity.Salt = data.Salt;
    ///         userRepo.SubmitChanges();
    ///     }
    /// 
    ///     public bool ValidatePassword(string userName, string password)
    ///     {
    ///         using var userRepo = Context.GetRepo<UserRepository>();
    ///         using var userRepo = Context.GetRepo<UserRepository>();
    ///         var entity = userRepo.GetUser(userName);
    ///         var hashedPassword = _hashing.GenerateSecureHash(password, entity.Salt);
    ///         return hashedPassword == entity.Password;
    ///     }
    /// }
    /// ]]>
    /// </code>
    /// </example>
    public class Hashing : IHashing
    {
        private Func<HashAlgorithm> _factory;

        /// <summary>
        ///     Sets the custom hashing algorithm for <see cref="GenerateCustomHash(string)" /> and the other.
        /// </summary>
        /// <param name="factory">The factory priding the hashing algorithm to use for the GenerateCustom methods.</param>
        /// <exception cref="ArgumentNullException">The factory cannot be null.</exception>
        public void SetCustomHashingMethod(Func<HashAlgorithm> factory)
        {
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        }

        /// <summary>
        ///     Generates a secure hash (SHA256) with a 32 char long salt.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashing data.</returns>
        public HashData GenerateSecureHash(string value)
        {
            var salt = GenerateSalt();
            var hashedValue = GenerateSHA256Hash(value + Convert.ToBase64String(salt));
            return new HashData
            {
                Value = hashedValue,
                Salt = salt
            };
        }

        /// <summary>
        ///     Generates a secure hash (SHA256) with the given salt.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <param name="salt">The salt to use when hashing.</param>
        /// <returns>The hashed value.</returns>
        public string GenerateSecureHash(string value, byte[] salt)
        {
            return GenerateSHA256Hash(value + Convert.ToBase64String(salt));
        }

        /// <summary>
        ///     Hashes the value using the SHA256 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        public string GenerateSHA256Hash(string value)
        {
            return GenerateSHA256Hash(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        ///     Hashes the bytes using the SHA256 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        public string GenerateSHA256Hash(byte[] bytes)
        {
            return GenerateCustomHash(SHA256.Create(), bytes);
        }

        /// <summary>
        ///     Hashes the stream content using the SHA256 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        public string GenerateSHA256Hash(Stream stream)
        {
            return GenerateCustomHash(SHA256.Create(), stream);
        }

        /// <summary>
        ///     Hashes the value using the SHA384 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        public string GenerateSHA384Hash(string value)
        {
            return GenerateSHA384Hash(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        ///     Hashes the bytes using the SHA384 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        public string GenerateSHA384Hash(byte[] bytes)
        {
            return GenerateCustomHash(SHA384.Create(), bytes);
        }

        /// <summary>
        ///     Hashes the stream content using the SHA384 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        public string GenerateSHA384Hash(Stream stream)
        {
            return GenerateCustomHash(SHA384.Create(), stream);
        }

        /// <summary>
        ///     Hashes the value using the SHA512 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        public string GenerateSHA512Hash(string value)
        {
            return GenerateSHA512Hash(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        ///     Hashes the bytes using the SHA512 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        public string GenerateSHA512Hash(byte[] bytes)
        {
            return GenerateCustomHash(SHA512.Create(), bytes);
        }

        /// <summary>
        ///     Hashes the stream content using the SHA512 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        public string GenerateSHA512Hash(Stream stream)
        {
            return GenerateCustomHash(SHA512.Create(), stream);
        }

        /// <summary>
        ///     Hashes the value using the MD5 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        public string GenerateMD5Hash(string value)
        {
            return GenerateMD5Hash(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        ///     Hashes the bytes using the MD5 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        public string GenerateMD5Hash(byte[] bytes)
        {
            return GenerateCustomHash(MD5.Create(), bytes);
        }

        /// <summary>
        ///     Hashes the stream content using the MD5 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        public string GenerateMD5Hash(Stream stream)
        {
            return GenerateCustomHash(MD5.Create(), stream);
        }

        /// <summary>
        ///     Hashes the value using the algorithm provided by <see cref="SetCustomHashingMethod" />.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        /// <exception cref="NullReferenceException">
        ///     The custom hash algorithm is not set. <see cref="SetCustomHashingMethod" />
        ///     needs to be called first.
        /// </exception>
        /// <exception cref="NullReferenceException">The factory set by <see cref="SetCustomHashingMethod" /> returns null.</exception>
        public string GenerateCustomHash(string value)
        {
            return GenerateCustomHash(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        ///     Hashes the bytes using the algorithm provided by <see cref="SetCustomHashingMethod" />.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        /// <exception cref="NullReferenceException">
        ///     The custom hash algorithm is not set. <see cref="SetCustomHashingMethod" />
        ///     needs to be called first.
        /// </exception>
        /// <exception cref="NullReferenceException">The factory set by <see cref="SetCustomHashingMethod" /> returns null.</exception>
        public string GenerateCustomHash(byte[] bytes)
        {
            if (_factory == null)
                throw new NullReferenceException("The custom hash algorithm is not set. SetCustomHashingMethod needs to be called first.");

            var algorithm = _factory();
            if (algorithm == null)
                throw new NullReferenceException("The factory set by SetCustomHashingMethod returns null.");

            return GenerateCustomHash(algorithm, bytes);
        }

        /// <summary>
        ///     Hashes the stream content using the algorithm provided by <see cref="SetCustomHashingMethod" />.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        /// <exception cref="NullReferenceException">
        ///     The custom hash algorithm is not set. <see cref="SetCustomHashingMethod" />
        ///     needs to be called first.
        /// </exception>
        /// <exception cref="NullReferenceException">The factory set by <see cref="SetCustomHashingMethod" /> returns null.</exception>
        public string GenerateCustomHash(Stream stream)
        {
            if (_factory == null)
                throw new NullReferenceException("The custom hash algorithm is not set. SetCustomHashingMethod needs to be called first.");

            var algorithm = _factory();
            if (algorithm == null)
                throw new NullReferenceException("The factory set by SetCustomHashingMethod returns null.");

            return GenerateCustomHash(algorithm, stream);
        }

        /// <summary>
        ///     Generates a salt with the length of 32 characters.
        /// </summary>
        /// <returns>The generated salt.</returns>
        public byte[] GenerateSalt()
        {
            return GenerateSalt(32);
        }

        /// <summary>
        ///     Generates a salt with the given length.
        /// </summary>
        /// <param name="length">The length of the salt to generate.</param>
        /// <returns>The generated salt.</returns>
        public byte[] GenerateSalt(int length)
        {
            var salt = new byte[length];
            using var random = new RNGCryptoServiceProvider();
            random.GetNonZeroBytes(salt);
            return salt;
        }

        private string GenerateCustomHash(HashAlgorithm algorithm, byte[] bytes)
        {
            var hash = algorithm.ComputeHash(bytes);
            return HexHash(hash);
        }

        private string GenerateCustomHash(HashAlgorithm algorithm, Stream stream)
        {
            stream.Position = 0;
            var hash = algorithm.ComputeHash(stream);
            return HexHash(hash);
        }

        private string HexHash(IEnumerable<byte> hash)
        {
            var sb = new StringBuilder();
            foreach (var character in hash)
                sb.Append(character.ToString("X2"));

            return sb.ToString();
        }
    }
}