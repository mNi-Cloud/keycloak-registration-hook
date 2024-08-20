package jp.mnicloud.reghook;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;

import java.io.IOException;
import java.util.logging.Logger;

public class EventListenerProvider implements org.keycloak.events.EventListenerProvider {
    private final Config config;
    private final MniAuthGateway mniAuthGateway;
    private final TokenManager tokenManager;

    public EventListenerProvider(Config config, MniAuthGateway mniAuthGateway, TokenManager tokenManager) {
        super();
        this.config = config;
        this.mniAuthGateway = mniAuthGateway;
        this.tokenManager = tokenManager;
    }

    @Override
    public void onEvent(Event event) {
        if ( event.getType() != EventType.REGISTER || !config.REALM_ID.equals(event.getRealmId())) {
            return;
        }

        String identityProvider = event.getDetails().get("identity_provider");
        if (identityProvider == null || !identityProvider.equals(config.IDENTITY_PROVIDER)) {
            return;
        }

        String userid = event.getUserId();
        try {
            String token = tokenManager.getIdToken();
            mniAuthGateway.postRegistrationHook(token, userid);
        } catch (IOException e) {
            Logger.getLogger("EventListenerProvider").severe("Failed to post registration hook: " + e.getMessage());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {
    }

    @Override
    public void close() {
    }
}
