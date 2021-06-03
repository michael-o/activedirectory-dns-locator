/*
 * Copyright 2016–2021 Michael Osipov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sf.michaelo.activedirectory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

import javax.naming.NamingException;
import com.sun.jndi.ldap.spi.LdapDnsProvider;
import com.sun.jndi.ldap.spi.LdapDnsProviderResult;

import net.sf.michaelo.activedirectory.ActiveDirectoryDnsLocator.HostPort;

import org.apache.commons.lang3.Validate;

/**
 * A {@link LdapDnsProvider} for the Active Directory. This implementation hooks into Sun's/Oracle's
 * LDAP implementation with JNDI to autodiscover Active Directory servers for LDAP via DNS.
 * <br>
 * This provider receives all environment properties via JNDI. It recornizes the following properties:
 * <ul>
 * <li>{@code net.sf.michaelo.activedirectory.site}: The Active Directory site your client resides.</li>
 * <li>{@code dns.*}: Passthrough properties to the underlying JNDI DNS Provider. (prefix will be stripped)</li>
 * </ul>
 */
@SuppressWarnings("restriction")
public class ActiveDirectoryLdapDnsProvider extends LdapDnsProvider {

	public static final String SITE_PROPERTY = "net.sf.michaelo.activedirectory.site";

	@Override
	public Optional<LdapDnsProviderResult> lookupEndpoints(String url, Map<?, ?> env)
			throws NamingException {
		Validate.notEmpty(url, "url cannot be null or empty");
		Validate.notNull(env, "env cannot be null");

		URI ldapUri = null;

		try {
			ldapUri = URI.create(url);
		} catch (IllegalArgumentException e) {
			NamingException ne = new NamingException("URL '" + url + "' is invalid");
			ne.initCause(e);
			throw ne;
		}

		ActiveDirectoryDnsLocator.Builder builder = new ActiveDirectoryDnsLocator.Builder();
		Map<String, Object> typedEnv = (Map<String, Object>) env;
		for (Entry<String, Object> entry : typedEnv.entrySet()) {
			String key = entry.getKey();
			if (key.startsWith("dns.")) {
				key = key.substring(4);
				builder.additionalProperty(key, entry.getValue());
			}
		}

		ActiveDirectoryDnsLocator locator = builder.build();

		String domainName = ldapUri.getHost();
		String site = (String) env.get(SITE_PROPERTY);

		HostPort[] hostPorts = locator.locate("ldap", site, domainName);

		if (hostPorts != null) {
			List<String> endpoints = new ArrayList<>(hostPorts.length);

			for (HostPort hostPort : hostPorts) {
				try {
					URI endpointUri = new URI(ldapUri.getScheme(), null, hostPort.getHost(),
							ldapUri.getPort(), ldapUri.getPath(), ldapUri.getQuery(),
							ldapUri.getFragment());
					endpoints.add(endpointUri.toASCIIString());
				} catch (URISyntaxException e) {
					NamingException ne = new NamingException("failed to construct endpoint URL");
					ne.initCause(e);
					throw ne;
				}
			}

			return Optional.of(new LdapDnsProviderResult(domainName, endpoints));
		}

		return Optional.empty();
	}

}
