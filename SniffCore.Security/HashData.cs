//
// Copyright (c) David Wendland. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
//

namespace SniffCore.Security
{
    /// <summary>
    ///     Contains a generated hash with the used salt.
    /// </summary>
    public class HashData
    {
        /// <summary>
        ///     The used salt.
        /// </summary>
        public byte[] Salt { get; set; }

        /// <summary>
        ///     The hash value.
        /// </summary>
        public string Value { get; set; }
    }
}