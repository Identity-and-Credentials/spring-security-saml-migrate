package example;

import java.util.Arrays;
import java.util.List;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfFilter;

@Configuration
public class SecurityConfiguration {
    // configure login

    // configure logout

    // configure metadata endpoint

    @Bean
    SecurityFilterChain web(HttpSecurity http,
                            AuthenticationProvider samlAuthenticationProvider,
                            SAMLProcessor samlProcessor,
                            SAMLContextProvider contextProvider) throws Exception {
        SAMLProcessingFilter filter = new SAMLProcessingFilter();
        filter.setAuthenticationManager(samlAuthenticationProvider::authenticate);
        filter.setSAMLProcessor(samlProcessor);
        filter.setContextProvider(contextProvider);
        filter.setFilterProcessesUrl("/login/saml2/sso/one");

        // @formatter:off
        http
            .authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
            .addFilterBefore(filter, CsrfFilter.class);
        // @formatter:on

        return http.build();
    }

    @Bean
    AuthenticationProvider samlAuthenticationProvider(WebSSOProfileConsumer consumer, SAMLLogger samlLogger) {
        SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
        provider.setConsumer(consumer);
        //provider.setHokConsumer(hokConsumer);
        provider.setSamlLogger(samlLogger);
        return provider;
    }

    @Bean
    SAMLLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    SAMLContextProvider contextProvider(MetadataManager assertingPartyMetadata) {
        SAMLContextProviderImpl contextProvider = new SAMLContextProviderImpl();
        contextProvider.setMetadata(assertingPartyMetadata);
        return contextProvider;
    }

    @Bean("webSSOprofileConsumer")
    public WebSSOProfileConsumer webSsoProfileConsumer(SAMLProcessor samlProcessor, MetadataManager assertingPartyMetadata) {
        return new WebSSOProfileConsumerImpl(samlProcessor, assertingPartyMetadata);
    }

    @Bean
    public SAMLProcessor samlProcessor(ParserPool parserPool, VelocityEngine velocityEngine) {
        SAMLBinding post = new HTTPPostBinding(parserPool, velocityEngine);
        return new SAMLProcessorImpl(post);
    }

    @Bean
    public VelocityEngine velocity() {
        return VelocityFactory.getEngine();
    }

    @Bean
    public MetadataManager assertingPartyMetadata(KeyManager keyManager, ParserPool pool) throws MetadataProviderException {
        HTTPMetadataProvider http = new HTTPMetadataProvider(new Timer(), new HttpClient(),
                "https://dev-05937739.okta.com/app/exk46xofd8NZvFCpS5d7/sso/saml/metadata");
        http.setParserPool(pool);
        List<MetadataProvider> providers = Arrays.asList(http);
        MetadataManager manager = new CachingMetadataManager(providers);
        manager.setKeyManager(keyManager);
        return manager;
    }

    @Bean
    public ParserPool parserPool() throws XMLParserException {
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        parserPool.initialize();
        return parserPool;
    }

    @Bean
    SAMLBootstrap bootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    public KeyManager keyManager() {
        return new EmptyKeyManager();
    }
}
