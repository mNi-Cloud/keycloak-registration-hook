package jp.mnicloud.reghook;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class EventListenerProviderFactory implements org.keycloak.events.EventListenerProviderFactory {
    private final Config config = new Config();
    private MniAuthGateway mniAuthGateway;
    private TokenManager tokenManager;

    @Override
    public void init(org.keycloak.Config.Scope scope) {
        config.REALM_ID = scope.get("realm-id");
        if (config.REALM_ID == null) {
            throw new RuntimeException("realm-id is required");
        }
        config.IDENTITY_PROVIDER = scope.get("identity-provider");
        if (config.IDENTITY_PROVIDER == null) {
            throw new RuntimeException("identity-provider is required");
        }
        config.MNI_AUTH_ENDPOINT = scope.get("mni-auth-endpoint");
        if (config.MNI_AUTH_ENDPOINT == null) {
            throw new RuntimeException("mni-auth-endpoint is required");
        }
        config.IDP_ENDPOINT = scope.get("idp-endpoint");
        if (config.IDP_ENDPOINT == null) {
            throw new RuntimeException("idp-endpoint is required");
        }
        config.USERNAME = scope.get("username");
        if (config.USERNAME == null) {
            throw new RuntimeException("username is required");
        }
        config.PASSWORD = scope.get("password");
        if (config.PASSWORD == null) {
            throw new RuntimeException("password is required");
        }

        mniAuthGateway = new MniAuthGateway(config);
        tokenManager = new TokenManager(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public org.keycloak.events.EventListenerProvider create(KeycloakSession keycloakSession) {
        return new EventListenerProvider(this.config, mniAuthGateway, tokenManager);
    }


    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "mni-registration-hook";
    }
}
