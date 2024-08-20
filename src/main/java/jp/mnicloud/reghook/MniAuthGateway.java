package jp.mnicloud.reghook;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import okhttp3.*;

import java.io.IOException;

public class MniAuthGateway {
    private final OkHttpClient client;
    private final Gson gson;
    private final Config config;

    public MniAuthGateway(Config config) {
        this.client = new OkHttpClient();
        this.gson = new Gson();
        this.config = config;
    }

    public void postRegistrationHook(String token, String uid) throws IOException {
        String endpoint = config.MNI_AUTH_ENDPOINT;
        if (!endpoint.endsWith("/"))
            endpoint += "/";
        endpoint += "hooks/registration";

        Request request = new Request.Builder()
                .url(endpoint)
                .header("Authorization", "Bearer "+token)
                .post(RequestBody.create(
                        MediaType.parse("application/json"),
                        gson.toJson(new HooksRegistrationRequest(uid))
                        ))
                .build();

        Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new IOException("Failed to post registration hook: " + response.code()+" "+response.body().string());
        }
    }

    public static class HooksRegistrationRequest {
        @SerializedName("uid")
        public String uid;

        public HooksRegistrationRequest(String uid) {
            this.uid = uid;
        }
    }
}
