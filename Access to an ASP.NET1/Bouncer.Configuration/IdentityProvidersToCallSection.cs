//-----------------------------------------------------------------------
// <copyright file="IdentityProvidersToCallSection.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//        you may not use this file except in compliance with the License.
//        You may obtain a copy of the License at
//            http://www.apache.org/licenses/LICENSE-2.0
//        Unless required by applicable law or agreed to in writing, software
//        distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//        See the License for the specific language governing permissions and
//        limitations under the License.
// </copyright>
//-----------------------------------------------------------------------
namespace Bouncer.Configuration
{
    using System.Collections.Generic;
    using System.Configuration;
    using System.Linq;

    /// <summary>
    /// Custom config section for listing identity providers to call.
    /// </summary>
    public class IdentityProvidersToCallSection : ConfigurationSection
    {
        /// <summary>
        /// Gets the identity providers to call.
        /// </summary>
        /// <value>
        /// The identity providers to call.
        /// </value>
        [ConfigurationProperty("identityProviders",
            IsDefaultCollection = false)]
        public IdentityProvidersToCallCollection IdentityProvidersToCall
        {
            get
            {
                IdentityProvidersToCallCollection identityProvidersToCall = (IdentityProvidersToCallCollection)base["identityProviders"];

                return identityProvidersToCall;
            }
        }

        /// <summary>
        /// Gets the ordered identity providers call chain.
        /// </summary>
        /// <returns>The call chain.</returns>
        public Queue<string> GetOrderedIdentityProvidersCallChain()
        {
            return new Queue<string>(from element in this.IdentityProvidersToCall.Cast<IdentityProviderToCallConfigurationElement>().OrderBy(i => i.CallSequenceNumber).ToList()
                                              select element.ServiceName);            
        }
    }
}