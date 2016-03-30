//-----------------------------------------------------------------------
// <copyright file="IdentityProviderToCallConfigurationElement.cs" company="Microsoft Corporation">
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
    using System.Configuration;

    /// <summary>
    /// Configuration element class to support config section detailing identity providers to call.
    /// </summary>
    public class IdentityProviderToCallConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Gets or sets the name of the service.
        /// </summary>
        /// <value>
        /// The name of the service.
        /// </value>
        [ConfigurationProperty("serviceName", IsRequired = true)]
        public string ServiceName
        {
            get
            {
                return (string)this["serviceName"];
            }

            set
            {
                this["remoteOnly"] = value;
            }
        }

        /// <summary>
        /// Gets or sets the call sequence number.
        /// </summary>
        /// <value>
        /// The call sequence number.
        /// </value>
        [ConfigurationProperty("callSequenceNumber", IsRequired = true)]
        public int CallSequenceNumber
        {
            get
            {
                return (int)this["callSequenceNumber"];
            }

            set
            {
                this["callSequenceNumber"] = value;
            }
        }

        /// <summary>
        /// Gets or sets the authenticated.
        /// </summary>
        /// <value>
        /// The authenticated.
        /// </value>
        public int Authenticated
        {
            get
            {
                return (int)this["callSequenceNumber"];
            }

            set
            {
                this["callSequenceNumber"] = value;
            }
        }
    }
}