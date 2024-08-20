package jp.mnicloud.reghook;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import okhttp3.*;

import java.io.IOException;
import java.io.Serial;
import java.util.Date;

public class TokenManager {
    private final OkHttpClient client;
    private final Gson gson;
    private final Config config;

    private String tokenEndpoint;

    private String idToken;
    private String accessToken;
    private String refreshToken;
    private long expiresAccessTokenAt;
    private long expiresRefreshTokenAt;

    public TokenManager(Config config) {
        this.client = new OkHttpClient();
        this.gson = new Gson();
        this.config = config;
    }

    private void init() {
        try {
            loadEndpointsFromWellKnown();
            requestToken();
        } catch (IOException e) {
            throw new RuntimeException("Failed to load endpoints from well-known: " + e.getMessage());
        }
    }

    public String getToken() {
        // if not initialized
        if (accessToken == null) {
            init();
            return accessToken;
        }


        // if not token expired
        if (System.currentTimeMillis() < expiresAccessTokenAt-500) {
            return accessToken;
        }
        // if not refresh token expired
        if (System.currentTimeMillis() < expiresRefreshTokenAt-500) {
            try {
                requestToken(true);
                return accessToken;
            } catch (IOException e) {
                throw new RuntimeException("Failed to refresh token: " + e.getMessage());
            }
        }
        // if refresh token expired
        try {
            requestToken();
            return accessToken;
        } catch (IOException e) {
            throw new RuntimeException("Failed to request token: " + e.getMessage());
        }
    }

    public String getIdToken() {
        if (idToken == null) {
            init();
            return idToken;
        }

        DecodedJWT jwt = JWT.decode(idToken);
        if(jwt.getExpiresAt().after(new Date())) {
            return idToken;
        }

        // if not refresh token expired
        if (System.currentTimeMillis() < expiresRefreshTokenAt-500) {
            try {
                requestToken(true);
                return idToken;
            } catch (IOException e) {
                throw new RuntimeException("Failed to refresh token: " + e.getMessage());
            }
        }
        // if refresh token expired
        try {
            requestToken();
            return idToken;
        } catch (IOException e) {
            throw new RuntimeException("Failed to request token: " + e.getMessage());
        }
    }

    private void loadEndpointsFromWellKnown() throws IOException {
        String endpoint = config.IDP_ENDPOINT;
        if (!endpoint.endsWith(".well-known/openid-configuration")) {
            if (!endpoint.endsWith("/"))
                endpoint += "/";
            endpoint += ".well-known/openid-configuration";
        }

        Request request = new Request.Builder().get()
                .url(endpoint)
                .build();

        System.out.println(endpoint);

        Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new IOException("Failed to load well-known configuration: " + response.code());
        }

        WellKnownResponse wellKnownResponse = gson.fromJson(response.body().string(), WellKnownResponse.class);
        this.tokenEndpoint = wellKnownResponse.tokenEndpoint;
    }

    public static class WellKnownResponse {
        @SerializedName("token_endpoint")
        public String tokenEndpoint;
    }

    private void requestToken() throws IOException {
        requestToken(false);
    }

    private void requestToken(boolean refresh) throws IOException {
        RequestBody formBody = null;

        if (refresh && refreshToken != null) {
            formBody = new FormBody.Builder()
                    .add("grant_type", "refresh_token")
                    .add("client_id", "direct-login")
                    .add("refresh_token", refreshToken)
                    .build();
        } else {
            formBody = new FormBody.Builder()
                    .add("grant_type", "password")
                    .add("client_id", "direct-login")
                    .add("username", config.USERNAME)
                    .add("password", config.PASSWORD)
                    .add("scope", "openid roles")
                    .build();
        }

        Request request = new Request.Builder()
                .url(tokenEndpoint)
                .post(formBody)
                .build();

        Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new IOException("Failed to request token: " + response.code() + " " + response.body().string());
        }

        TokenResponse tokenResponse = gson.fromJson(response.body().string(), TokenResponse.class);

        this.accessToken = tokenResponse.accessToken;
        this.refreshToken = tokenResponse.refreshToken;
        this.idToken = tokenResponse.idToken;
        this.expiresAccessTokenAt = System.currentTimeMillis() + tokenResponse.expiresIn * 1000;
        this.expiresRefreshTokenAt = System.currentTimeMillis() + tokenResponse.refreshExpiresIn * 1000;
    }

    public static class TokenResponse {
        @SerializedName("access_token")
        public String accessToken;
        @SerializedName("refresh_token")
        public String refreshToken;
        @SerializedName("id_token")
        public String idToken;
        @SerializedName("expires_in")
        public long expiresIn;
        @SerializedName("refresh_expires_in")
        public long refreshExpiresIn;
    }

}
