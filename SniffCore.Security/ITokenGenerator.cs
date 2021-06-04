//
// Copyright (c) David Wendland. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
//

namespace SniffCore.Security
{
    /// <summary>
    ///     Generates a security token.
    /// </summary>
    public interface ITokenGenerator
    {
        /// <summary>
        ///     Generates a 32 character long security token.
        /// </summary>
        /// <returns>The generated security token.</returns>
        string Generate();

        /// <summary>
        ///     Generates a security token with the given length.
        /// </summary>
        /// <param name="length">The length of the security token.</param>
        /// <returns>The generated security token.</returns>
        string Generate(uint length);
    }
}