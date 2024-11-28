package io.statnett.k3a.authz.ldap;

import com.yammer.metrics.Metrics;
import com.yammer.metrics.core.Histogram;
import com.yammer.metrics.core.Meter;
import com.yammer.metrics.core.MetricName;

import io.statnett.k3a.authz.ldap.utils.LdapConnectionSpec;
import io.statnett.k3a.authz.ldap.utils.UsernamePasswordAuthenticator;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public final class LdapAuthenticateCallbackHandler
implements AuthenticateCallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticateCallbackHandler.class);
    private static final String CONFIG_LDAP_HOST = "authz.ldap.host";
    private static final String CONFIG_LDAP_PORT = "authz.ldap.port";
    private static final String CONFIG_LDAP_BASE_DN = "authz.ldap.base.dn";
    private static final String CONFIG_LDAP_USER_DN = "authz.ldap.user.dn";
    private static final String CONFIG_LDAP_USER_PASSWORD = "authz.ldap.user.password";
    private static final String CONFIG_LDAP_USERNAME_TO_DN_FORMAT = "authz.ldap.username.to.dn.format";
    private static final String CONFIG_LDAP_USERNAME_TO_UNIQUE_SEARCH_FORMAT = "authz.ldap.username.to.unique.search.format";
    private static final String SASL_PLAIN = "PLAIN";
    private UsernamePasswordAuthenticator authenticator;
    private final UsernamePasswordAuthenticatorFactory usernamePasswordAuthenticatorFactory;

    private static LdapAuthenticateMetrics metrics = new LdapAuthenticateMetrics();

    private static class TaggedMeter {

        private final ConcurrentMap<Tag, Meter> taggedMeters = new ConcurrentHashMap<>();
        private final String shortname;

        private TaggedMeter(String shortname) {
            this.shortname = shortname;
        }

        void mark(Tag tag) {
            Meter counter = taggedMeters.computeIfAbsent(tag, key ->
                    Metrics.newMeter(LdapAuthenticateMetrics.metricName(shortname, tag), "auth", TimeUnit.SECONDS)
            );
            counter.mark();
        }
    }

    private static class Tag {
        private final String key;
        private final String value;

        private Tag(String key, String value) {
            this.key = escape(key);
            this.value = escape(value);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(key) + Objects.hashCode(value);
        }

        @Override
        public boolean equals(Object other) {
            if (other instanceof Tag) {
                Tag otherTag = (Tag) other;
                return Objects.equals(key, otherTag.key) && Objects.equals(value, otherTag.value);
            }
            return false;
        }

        private static String escape(String origin) {
            return origin.replaceAll(":", "_");
        }
    }

    private static class LdapAuthenticateMetrics {
        private static final String METRIC_GROUP = "kafka.security.ldap";
        private static final String METRIC_TYPE = LdapAuthenticateCallbackHandler.class.getSimpleName();

        private Histogram validationLatencyMillis = Metrics.newHistogram(metricName("ValidationLatencyMillis"), true);
        private Meter calls = Metrics.newMeter(metricName("CallsPerSec"), "auth", TimeUnit.SECONDS);
        // Counter for internal errors
        private Meter internalErrors = Metrics.newMeter(metricName("ErrorsPerSec"), "auth", TimeUnit.SECONDS);
        // Counter for invalid/unparsable creds
        private TaggedMeter failedAuthentication = new TaggedMeter("FailedAuthenticationPerSec");
        // Counters for valid creds
        private TaggedMeter successfulAuthentication = new TaggedMeter("SuccessfulAuthenticationPerSec");


        private static MetricName metricName(String shortname) {
            return metricName(shortname, null);
        }

        private static MetricName metricName(String shortname, Tag tag) {
            StringBuilder beanName = new StringBuilder(METRIC_GROUP)
                    .append(":type=").append(METRIC_TYPE)
                    .append(",name=").append(shortname);
            if (tag != null) {
                beanName.append(",key=").append(tag.key);
                beanName.append(",value=").append(tag.value);
            }
            return new MetricName(METRIC_GROUP, METRIC_TYPE, shortname, null, beanName.toString());
        }
    }

    public interface UsernamePasswordAuthenticatorFactory {

        UsernamePasswordAuthenticator create(LdapConnectionSpec spec, String usernameToDnFormat, String usernameToUniqueSearchFormat, String userDn, String userPassword);

    }

    public LdapAuthenticateCallbackHandler() {
        usernamePasswordAuthenticatorFactory = LdapUsernamePasswordAuthenticator::new;
    }

    public LdapAuthenticateCallbackHandler(final UsernamePasswordAuthenticatorFactory usernamePasswordAuthenticatorFactory) {
        this.usernamePasswordAuthenticatorFactory = Objects.requireNonNull(usernamePasswordAuthenticatorFactory);
    }

    @Override
    public void configure(final Map<String, ?> configs, final String saslMechanism, final List<AppConfigurationEntry> jaasConfigEntries) {
        if (!SASL_PLAIN.equals(saslMechanism)) {
            metrics.internalErrors.mark();
            throw new IllegalArgumentException("Only SASL mechanism \"" + SASL_PLAIN + "\" is supported.");
        }
        configure(configs);
    }

    private void configure(final Map<String, ?> configs) {
        final String host = getRequiredStringProperty(configs, CONFIG_LDAP_HOST);
        final int port = getRequiredIntProperty(configs, CONFIG_LDAP_PORT);
        final String baseDn = getRequiredStringProperty(configs, CONFIG_LDAP_BASE_DN);
        final String usernameToDnFormat = getRequiredStringProperty(configs, CONFIG_LDAP_USERNAME_TO_DN_FORMAT);
        final String usernameToUniqueSearchFormat = getStringProperty(configs, CONFIG_LDAP_USERNAME_TO_UNIQUE_SEARCH_FORMAT);
        final String userDn = getStringProperty(configs, CONFIG_LDAP_USER_DN);
        final String userPassword = getStringProperty(configs, CONFIG_LDAP_USER_PASSWORD);
        authenticator = usernamePasswordAuthenticatorFactory.create(new LdapConnectionSpec(host, port, port == 636, baseDn), usernameToDnFormat, usernameToUniqueSearchFormat, userDn, userPassword);
        LOG.info("Configured.");
    }

    private int getRequiredIntProperty(final Map<String, ?> configs, final String name) {
        final String stringValue = getRequiredStringProperty(configs, name);
        try {
            return Integer.parseInt(stringValue);
        } catch (final NumberFormatException e) {
            metrics.internalErrors.mark();
            throw new IllegalArgumentException("Value must be numeric in configuration property \"" + name + "\".");
        }
    }

    private String getStringProperty(final Map<String, ?> configs, final String name) {
        final Object value = configs.get(name);
        return value == null ? null : value.toString();
    }

    private String getRequiredStringProperty(final Map<String, ?> configs, final String name) {
        final Object value = configs.get(name);
        if (value == null) {
            metrics.internalErrors.mark();
            throw new IllegalArgumentException("Missing required configuration property \"" + name + "\".");
        }
        return value.toString();
    }

    @Override
    public void close() {
        LOG.info("Closed.");
    }

    @Override
    public void handle(final Callback[] callbacks)
    throws UnsupportedCallbackException {
        if (authenticator == null) {
            metrics.internalErrors.mark();
            throw new IllegalStateException("Handler not properly configured.");
        }

        long start = System.currentTimeMillis();

        String username = null;
        PlainAuthenticateCallback plainAuthenticateCallback = null;
        for (final Callback callback : callbacks) {
            metrics.calls.mark();
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getDefaultName();
            } else if (callback instanceof PlainAuthenticateCallback) {
                plainAuthenticateCallback = (PlainAuthenticateCallback) callback;
            } else {
                metrics.internalErrors.mark();
                throw new UnsupportedCallbackException(callback);
            }
        }
        if (username == null) {
            metrics.internalErrors.mark();
            throw new IllegalStateException("Expected NameCallback was not found.");
        }
        if (plainAuthenticateCallback == null) {
            metrics.internalErrors.mark();
            throw new IllegalStateException("Expected PlainAuthenticationCallback was not found.");
        }
        final boolean authenticated = authenticator.authenticate(username, plainAuthenticateCallback.password());
        if (authenticated) {
            metrics.successfulAuthentication.mark(new Tag("username", username));
            LOG.info("User \"" + username + "\" authenticated.");
        } else {
            metrics.failedAuthentication.mark(new Tag("username", username));
            LOG.warn("Authentication failed for user \"" + username + "\".");
        }
        plainAuthenticateCallback.authenticated(authenticated);

        long end = System.currentTimeMillis();
        metrics.validationLatencyMillis.update(end - start);
    }

}
