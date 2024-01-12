package example;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;

@Configuration
public class SecurityConfiguration {

    @Bean
    SecurityFilterChain web(HttpSecurity http,
                            AuthenticationProvider samlAuthenticationProvider,
                            SAMLProcessor samlProcessor,
                            SAMLContextProvider contextProvider,
                            AuthenticationEntryPoint samlEntryPoint,
                            MetadataManager assertingPartyMetadata,
                            KeyManager keyManager,
                            LogoutSuccessHandler logoutSuccessHandler,
                            LogoutHandler logoutHandler,
                            SAMLLogger samlLogger) throws Exception {
        SAMLProcessingFilter filter = new SAMLProcessingFilter();
        filter.setAuthenticationManager(samlAuthenticationProvider::authenticate);
        filter.setSAMLProcessor(samlProcessor);
        filter.setContextProvider(contextProvider);
        // Set the Okta Application SAML Settings Single Sign On URL to this,
        // i.e., http://localhost:8080/login/saml2/sso/one
        filter.setFilterProcessesUrl("/login/saml2/sso/one");

        SingleLogoutProfileImpl singleLogoutProfile = new SingleLogoutProfileImpl();
        singleLogoutProfile.setMetadata(assertingPartyMetadata);
        singleLogoutProfile.setProcessor(samlProcessor);

        SAMLLogoutFilter samlLogoutFilter = samlLogoutFilter(logoutSuccessHandler, logoutHandler);
        samlLogoutFilter.setProfile(singleLogoutProfile);
        samlLogoutFilter.setContextProvider(contextProvider);
        samlLogoutFilter.setSamlLogger(samlLogger);

        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = samlLogoutProcessingFilter(logoutSuccessHandler, logoutHandler);
        samlLogoutProcessingFilter.setSAMLProcessor(samlProcessor);
        samlLogoutProcessingFilter.setLogoutProfile(singleLogoutProfile);
        samlLogoutProcessingFilter.setContextProvider(contextProvider);
        samlLogoutProcessingFilter.setSamlLogger(samlLogger);

        MetadataGenerator metadataGenerator = new MetadataGenerator();
        // Set the Okta Application SAML Settings Audience Restriction to this entityId
        metadataGenerator.setEntityId("http://localhost:8080/saml2/service-provider-metadata/one");
        metadataGenerator.setKeyManager(keyManager);
        metadataGenerator.setRequestSigned(false);
        metadataGenerator.setSamlWebSSOFilter(filter);
        metadataGenerator.setSamlLogoutProcessingFilter(samlLogoutProcessingFilter);
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        MetadataGeneratorFilter metadataFilter = new MetadataGeneratorFilter(metadataGenerator);
        metadataFilter.setManager(assertingPartyMetadata);

        // @formatter:off
        http
            .authorizeHttpRequests((requests) -> requests
                .antMatchers("/logged-out").permitAll()
                .anyRequest().authenticated()
            )
            .exceptionHandling((exception) -> exception.authenticationEntryPoint(samlEntryPoint))
            .addFilterBefore(filter, CsrfFilter.class)
            .addFilterBefore(metadataFilter, ChannelProcessingFilter.class)
            .addFilterBefore(samlLogoutFilter, LogoutFilter.class)
            .addFilterBefore(samlLogoutProcessingFilter, CsrfFilter.class);
        // @formatter:on

        return http.build();
    }

    @Bean
    AuthenticationProvider samlAuthenticationProvider(@Qualifier("webSSOprofileConsumer") WebSSOProfileConsumer consumer,
            @Qualifier("hokWebSSOprofileConsumer") WebSSOProfileConsumer hokConsumer, SAMLLogger samlLogger) {
        SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
        provider.setConsumer(consumer);
        provider.setHokConsumer(hokConsumer);
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
    WebSSOProfileConsumer webSsoProfileConsumer(SAMLProcessor samlProcessor, MetadataManager assertingPartyMetadata) {
        return new WebSSOProfileConsumerImpl(samlProcessor, assertingPartyMetadata);
    }

    @Bean("hokWebSSOprofileConsumer")
    WebSSOProfileConsumer hokWebSsoProfileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    SAMLProcessor samlProcessor(ParserPool parserPool, VelocityEngine velocityEngine) {
        SAMLBinding post = new HTTPPostBinding(parserPool, velocityEngine);
        return new SAMLProcessorImpl(post);
    }

    @Bean
    VelocityEngine velocity() {
        return VelocityFactory.getEngine();
    }

    @Bean
    MetadataManager assertingPartyMetadata(KeyManager keyManager, ParserPool pool) throws MetadataProviderException {
        // The IDP metatdata URL is from the Okta Application Sign On setting
        HTTPMetadataProvider http = new HTTPMetadataProvider(new Timer(), new HttpClient(),
                "https://dev-73893672.okta.com/app/exkef5al7mopEta1B5d7/sso/saml/metadata");
        http.setParserPool(pool);
        List<MetadataProvider> providers = Arrays.asList(http);
        MetadataManager manager = new CachingMetadataManager(providers);
        manager.setKeyManager(keyManager);
        return manager;
    }

    @Bean
    AuthenticationEntryPoint samlEntryPoint() {
        SAMLEntryPoint entryPoint = new SAMLEntryPoint();
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        entryPoint.setDefaultProfileOptions(webSSOProfileOptions);
        return entryPoint;
    }

    @Bean("webSSOprofile")
    WebSSOProfile webSsoProfile(SAMLProcessor samlProcessor, MetadataManager assertingPartyMetadata) {
        return new WebSSOProfileImpl(samlProcessor, assertingPartyMetadata);
    }

    @Bean
    ParserPool parserPool() throws XMLParserException {
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        parserPool.initialize();
        return parserPool;
    }

    @Bean
    SAMLBootstrap bootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    KeyManager keyManager() {
        Map<String, String> passwords = new HashMap<>();
        passwords.put("samlKeystore", "123456");
        return new JKSKeyManager(new ClassPathResource("credentials/samlKeystore.p12"), "123456", passwords, "samlKeystore");
    }

    // Logout beans

    @Bean
    SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl("/logged-out");
        return logoutSuccessHandler;
    }

    @Bean
    LogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(false);
        return logoutHandler;
    }

    SAMLLogoutProcessingFilter samlLogoutProcessingFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler logoutHandler) {
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = new SAMLLogoutProcessingFilter(logoutSuccessHandler, logoutHandler);
        samlLogoutProcessingFilter.setFilterProcessesUrl("/logout/saml2/slo");
        return samlLogoutProcessingFilter;
    }

    SAMLLogoutFilter samlLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler logoutHandler) {
        SAMLLogoutFilter samlLogoutFilter = new SAMLLogoutFilter(logoutSuccessHandler, new LogoutHandler[]{logoutHandler},
                new LogoutHandler[]{logoutHandler});
        samlLogoutFilter.setFilterProcessesUrl("/logout");
        return samlLogoutFilter;
    }

}
