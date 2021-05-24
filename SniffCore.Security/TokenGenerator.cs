//
// Copyright (c) David Wendland. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
//

using System;
using System.Security.Cryptography;

namespace SniffCore.Security
{
    /// <summary>
    ///     Generates a security token.
    /// </summary>
    public class TokenGenerator : ITokenGenerator
    {
        /// <summary>
        ///     Generates a 32 character long security token.
        /// </summary>
        /// <returns>The generated security token.</returns>
        public string Generate()
        {
            return Generate(32);
        }

        /// <summary>
        ///     Generates a security token with the given length.
        /// </summary>
        /// <param name="length">The length of the security token.</param>
        /// <returns>The generated security token.</returns>
        public string Generate(int length)
        {
            var randomNumber = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}