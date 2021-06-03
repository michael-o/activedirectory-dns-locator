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

import java.util.Arrays;
import java.util.Hashtable;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.commons.lang3.Validate;

/**
 * A locator for various Active Directory services like LDAP, Global Catalog, Kerberos, etc. via DNS
 * SRV resource records. This is a lightweight implementation of
 * <a href="https://www.rfc-editor.org/rfc/rfc2782.html">RFC 2782</a> for the resource records
 * depicted
 * <a href="https://technet.microsoft.com/en-us/library/cc759550%28v=ws.10%29.aspx">here</a>, but
 * with the limitation that only TCP is queried and the {@code _msdcs} subdomain is ignored. The
 * server selection algorithm for failover is fully implemented.
 * <p>
 * Here is a minimal example how to create a {@code ActiveDirectoryDnsLocator} with the supplied
 * builder:
 *
 * <pre>
 * ActiveDirectoryDnsLocator.Builder builder = new ActiveDirectoryDnsLocator.Builder();
 * ActiveDirectoryDnsLocator locator = builder.build();
 * HostPort[] servers = locator.locate("ldap", "ad.example.com");
 * </pre>
 *
 * An {@code ActiveDirectoryDnsLocator} object will be initially preconfigured by its builder for
 * you:
 * <ol>
 * <li>The context factory is set by default to {@code com.sun.jndi.dns.DnsContextFactory}.</li>
 * </ol>
 *
 * A complete overview of all {@code DirContext} properties can be found
 * <a href= "https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-dns.html">here</a>.
 * Make sure that you pass reasonable/valid values only otherwise the behavior is undefined.
 *
 * <p>
 * <b>Note</b>: This class uses JULI to print log messages, enable at least level {@code FINE}
 * to see output.
 */
public class ActiveDirectoryDnsLocator {

	private static class SrvRecord implements Comparable<SrvRecord> {

		static final String UNAVAILABLE_SERVICE = ".";

		private int priority;
		private int weight;
		private int sum;
		private int port;
		private String target;

		public SrvRecord(int priority, int weight, int port, String target) {
			Validate.inclusiveBetween(0, 0xFFFF, priority, "priority must be between 0 and 65535");
			Validate.inclusiveBetween(0, 0xFFFF, weight, "weight must be between 0 and 65535");
			Validate.inclusiveBetween(0, 0xFFFF, port, "port must be between 0 and 65535");
			Validate.notEmpty(target, "target cannot be null or empty");

			this.priority = priority;
			this.weight = weight;
			this.port = port;
			this.target = target;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof SrvRecord))
				return false;

			SrvRecord that = (SrvRecord) obj;

			return priority == that.priority && weight == that.weight && port == that.port
					&& target.equals(that.target);
		}

		@Override
		public int hashCode() {
			return Objects.hash(priority, weight, port, target);
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder("SRV RR: ");
			builder.append(priority).append(' ');
			builder.append(weight).append(' ');
			if (sum != 0)
				builder.append('(').append(sum).append(") ");
			builder.append(port).append(' ');
			builder.append(target);
			return builder.toString();
		}

		@Override
		public int compareTo(SrvRecord that) {
			// Comparing according to the RFC
			if (priority > that.priority) {
				return 1;
			} else if (priority < that.priority) {
				return -1;
			} else if (weight == 0 && that.weight != 0) {
				return -1;
			} else if (weight != 0 && that.weight == 0) {
				return 1;
			} else {
				return 0;
			}
		}

	}

	/**
	 * A mere container for a host along with a port.
	 */
	public static class HostPort {

		private String host;
		private int port;

		public HostPort(String host, int port) {
			Validate.notEmpty(host, "host cannot be null or empty");
			Validate.inclusiveBetween(0, 0xFFFF, port, "port must be between 0 and 65535");

			this.host = host;
			this.port = port;
		}

		public String getHost() {
			return host;
		}

		public int getPort() {
			return port;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof HostPort))
				return false;

			HostPort that = (HostPort) obj;

			return host.equals(that.host) && port == that.port;
		}

		@Override
		public int hashCode() {
			return Objects.hash(host, port);
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(host).append(':').append(port);
			return builder.toString();
		}

	}

	private static final String SRV_RR_FORMAT = "_%s._tcp.%s";
	private static final String SRV_RR_WITH_SITES_FORMAT = "_%s._tcp.%s._sites.%s";

	private static final String SRV_RR = "SRV";
	private static final String[] SRV_RR_ATTR = new String[] { SRV_RR };

	private static final Logger LOGGER = Logger
			.getLogger(ActiveDirectoryDnsLocator.class.getName());

	private final Hashtable<String, Object> env;

	private ActiveDirectoryDnsLocator(Builder builder) {
		env = new Hashtable<String, Object>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, builder.contextFactory);
		env.putAll(builder.additionalProperties);
	}

	/**
	 * A builder to construct an {@link ActiveDirectoryDnsLocator} with a fluent interface.
	 *
	 * <p>
	 * <strong>Notes:</strong>
	 * <ol>
	 * <li>This class is not thread-safe. Configure the builder in your main thread, build the
	 * object and pass it on to your forked threads.</li>
	 * <li>An {@code IllegalStateException} is thrown if a property is modified after this builder
	 * has already been used to build an {@code ActiveDirectoryDnsLocator}, simply create a new
	 * builder in this case.</li>
	 * <li>All passed arrays will be defensively copied and null/empty values will be skipped except
	 * when all elements are invalid, an exception will be raised.</li>
	 * </ol>
	 */
	public static final class Builder {

		// Builder properties
		private String contextFactory;
		private Hashtable<String, Object> additionalProperties;

		private boolean done;

		/**
		 * Constructs a new builder for {@link ActiveDirectoryDnsLocator}.
		 */
		public Builder() {
			// Initialize default values first as mentioned in the class' Javadoc
			contextFactory("com.sun.jndi.dns.DnsContextFactory");
			additionalProperties = new Hashtable<String, Object>();
		}

		/**
		 * Sets the context factory for this service locator.
		 *
		 * @param contextFactory
		 *            the context factory class name
		 * @throws NullPointerException
		 *             if {@code contextFactory} is null
		 * @throws IllegalArgumentException
		 *             if {@code contextFactory} is empty
		 * @return this builder
		 */
		public Builder contextFactory(String contextFactory) {
			check();
			this.contextFactory = validateAndReturnString("contextFactory", contextFactory);
			return this;
		}

		/**
		 * Sets an additional property not available through the builder interface.
		 *
		 * @param name
		 *            name of the property
		 * @param value
		 *            value of the property
		 * @throws NullPointerException
		 *             if {@code name} is null
		 * @throws IllegalArgumentException
		 *             if {@code value} is empty
		 * @return this builder
		 */
		public Builder additionalProperty(String name, Object value) {
			check();
			Validate.notEmpty(name, "additional property's name cannot be null or empty");
			this.additionalProperties.put(name, value);
			return this;
		}

		/**
		 * Builds an {@code ActiveDirectoryDnsLocator} and marks this builder as non-modifiable for
		 * future use. You may call this method as often as you like, it will return a new
		 * {@code ActiveDirectoryDnsLocator} instance on every call.
		 *
		 * @throws IllegalStateException
		 *             if a combination of necessary attributes is not set
		 * @return an {@code ActiveDirectoryDnsLocator} object
		 */
		public ActiveDirectoryDnsLocator build() {

			ActiveDirectoryDnsLocator serviceLocator = new ActiveDirectoryDnsLocator(this);
			done = true;

			return serviceLocator;
		}

		private void check() {
			if (done)
				throw new IllegalStateException("cannot modify an already used builder");
		}

		private String validateAndReturnString(String name, String value) {
			return Validate.notEmpty(value, "property '%s' cannot be null or empty", name);
		}

	}

	private SrvRecord[] lookUpSrvRecords(DirContext context, String name) throws NamingException {
		Attributes attrs = null;

		try {
			attrs = context.getAttributes(name, SRV_RR_ATTR);
		} catch (InvalidNameException e) {
			NamingException ne = new NamingException("name '" + name + "' is invalid");
			ne.initCause(ne);
			throw ne;
		} catch (NameNotFoundException e) {
			return null;
		}

		Attribute srvAttr = attrs.get(SRV_RR);
		if (srvAttr == null)
			return null;

		NamingEnumeration<?> records = null;

		SrvRecord[] srvRecords = new SrvRecord[srvAttr.size()];

		try {
			records = srvAttr.getAll();

			int recordCnt = 0;
			while (records.hasMoreElements()) {
				String record = (String) records.nextElement();
				try (Scanner scanner = new Scanner(record)) {
					scanner.useDelimiter(" ");

					int priority = scanner.nextInt();
					int weight = scanner.nextInt();
					int port = scanner.nextInt();
					String target = scanner.next();
					SrvRecord srvRecord = new SrvRecord(priority, weight, port, target);

					srvRecords[recordCnt++] = srvRecord;
				}
			}
		} catch (NoSuchElementException e) {
			throw new IllegalStateException("The supplied SRV RR is invalid", e);
		} finally {
			if (records != null)
				try {
					records.close();
				} catch (NamingException e) {
					; // ignore
				}
		}

		/*
		 * No servers returned or explicitly indicated by the DNS server that this service is not
		 * provided as described by the RFC.
		 */
		if (srvRecords.length == 0 || srvRecords.length == 1
				&& srvRecords[0].target.equals(SrvRecord.UNAVAILABLE_SERVICE))
			return null;

		return srvRecords;
	}

	private HostPort[] sortByRfc2782(SrvRecord[] srvRecords) {
		if (srvRecords == null)
			return null;

		// Apply the server selection algorithm
		Arrays.sort(srvRecords);

		HostPort[] sortedServers = new HostPort[srvRecords.length];
		for (int i = 0, start = -1, end = -1, hp = 0; i < srvRecords.length; i++) {

			start = i;
			while (i + 1 < srvRecords.length
					&& srvRecords[i].priority == srvRecords[i + 1].priority) {
				i++;
			}
			end = i;

			for (int repeat = 0; repeat < (end - start) + 1; repeat++) {
				int sum = 0;
				for (int j = start; j <= end; j++) {
					if (srvRecords[j] != null) {
						sum += srvRecords[j].weight;
						srvRecords[j].sum = sum;
					}
				}

				int r = sum == 0 ? 0 : ThreadLocalRandom.current().nextInt(sum + 1);
				for (int k = start; k <= end; k++) {
					SrvRecord srvRecord = srvRecords[k];

					if (srvRecord != null && srvRecord.sum >= r) {
						String host = srvRecord.target.substring(0, srvRecord.target.length() - 1);
						sortedServers[hp++] = new HostPort(host, srvRecord.port);
						srvRecords[k] = null;
					}
				}
			}
		}

		return sortedServers;
	}

	/**
	 * Locates a desired service via DNS within an Active Directory site and domain, sorted and
	 * selected according to RFC 2782.
	 *
	 * @param service
	 *            the service to be located
	 * @param site
	 *            the Active Directory site the client resides in
	 * @param domainName
	 *            the desired domain name. Can be any naming context name.
	 * @return the located servers or null if none found
	 * @throws NullPointerException
	 *             if service or domain name is null
	 * @throws IllegalArgumentException
	 *             if service or domain name is empty
	 * @throws NamingException
	 *             if an error has occurred while creating or querying the DNS directory context
	 * @throws IllegalStateException
	 *             if any of the DNS returned RRs not adhere to the RFC
	 */
	public HostPort[] locate(String service, String site, String domainName)
			throws NamingException {
		Validate.notEmpty(service, "service cannot be null or empty");
		Validate.notEmpty(domainName, "domainName cannot be null or empty");

		DirContext context = null;
		try {
			context = new InitialDirContext(env);
		} catch (NamingException e) {
			NamingException ne = new NamingException("failed to create DNS directory context");
			ne.initCause(e);
			throw ne;
		}

		SrvRecord[] srvRecords = null;

		String lookupName;
		if (site != null && !site.isEmpty())
			lookupName = String.format(SRV_RR_WITH_SITES_FORMAT, service, site, domainName);
		else
			lookupName = String.format(SRV_RR_FORMAT, service, domainName);

		try {
			LOGGER.log(Level.FINE, "Looking up SRV RRs for ''{0}''", lookupName);

			srvRecords = lookUpSrvRecords(context, lookupName);
		} catch (NamingException e) {
			LOGGER.log(Level.SEVERE,
					String.format("Failed to look up SRV RRs for '%s'", lookupName), e);

			throw e;
		} finally {
			try {
				context.close();
			} catch (NamingException e) {
				; // ignore
			}
		}

		if (srvRecords == null)
			LOGGER.log(Level.FINE, "No SRV RRs for ''{0}'' found", lookupName);
		else {
			if (LOGGER.isLoggable(Level.FINER))
				LOGGER.log(Level.FINER, "Found {0} SRV RRs for ''{1}'': {2}", new Object[] {
						srvRecords.length, lookupName, Arrays.toString(srvRecords) });
			else
				LOGGER.log(Level.FINE, "Found {0} SRV RRs for ''{1}''",
						new Object[] { srvRecords.length, lookupName });
		}

		HostPort[] servers = sortByRfc2782(srvRecords);

		if (servers == null)
			return null;

		if (LOGGER.isLoggable(Level.FINER))
			LOGGER.log(Level.FINER, "Selected {0} servers for ''{1}'': {2}",
					new Object[] { servers.length, lookupName, Arrays.toString(servers) });
		else
			LOGGER.log(Level.FINE, "Selected {0} servers for ''{1}''",
					new Object[] { servers.length, lookupName });

		return servers;
	}

	/**
	 * Locates a desired service via DNS within an Active Directory domain, sorted and selected
	 * according to RFC 2782.
	 *
	 * @param service
	 *            the service to be located
	 * @param domainName
	 *            the desired domain name. Can be any naming context name.
	 * @return the located servers or null if none found
	 * @throws NullPointerException
	 *             if service or domain name is null
	 * @throws IllegalArgumentException
	 *             if service or domain name is empty
	 * @throws NamingException
	 *             if an error has occurred while creating or querying the DNS directory context
	 * @throws IllegalStateException
	 *             if any of the DNS returned RRs not adhere to the RFC
	 */
	public HostPort[] locate(String service, String domainName) throws NamingException {
		return locate(service, null, domainName);
	}

}
