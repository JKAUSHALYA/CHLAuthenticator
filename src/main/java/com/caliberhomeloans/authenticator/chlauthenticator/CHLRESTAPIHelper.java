package com.caliberhomeloans.authenticator.chlauthenticator;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class is to give helper methods to call Caliber Home Loans REST APIs.
 */
class CHLRESTAPIHelper {

    private HttpClient client;
    private HttpPost post;

    CHLRESTAPIHelper(String url) {

        client = new DefaultHttpClient();
        post = new HttpPost(url);
    }

    /**
     * Authenticate the give user by calling the respective REST API.
     *
     * @param username Username of the user.
     * @param password Password of the user.
     * @return Id of the user if authentication success.
     */
    String authenticateUser(String username, String password) throws IOException {

        List<NameValuePair> nameValuePairs = new ArrayList<>();
        nameValuePairs.add(new BasicNameValuePair("username", username));
        nameValuePairs.add(new BasicNameValuePair("password", password));

        post.setEntity(new UrlEncodedFormEntity(nameValuePairs));

        HttpResponse response = client.execute(post);

        String jsonResponse = EntityUtils.toString(response.getEntity());

        JSONObject jsonObject = new JSONObject(jsonResponse);

        if (((Integer) jsonObject.get("statusCode")) != 200) {
            throw new RuntimeException("Error in JSON response. Status code: " + jsonObject.get("statusCode"));
        }

        return jsonObject.get("payLoad").toString();
    }

    JSONObject getUserIdAppNameClaims(String username, String serviceProviderName) throws IOException {

        List<NameValuePair> nameValuePairs = new ArrayList<>();
        nameValuePairs.add(new BasicNameValuePair("username", username));
        nameValuePairs.add(new BasicNameValuePair("spName", serviceProviderName));

        post.setEntity(new UrlEncodedFormEntity(nameValuePairs));

        HttpResponse response = client.execute(post);

        String jsonResponse = EntityUtils.toString(response.getEntity());

        JSONObject jsonObject = new JSONObject(jsonResponse);

        if (((Integer) jsonObject.get("statusCode")) != 200) {
            throw new RuntimeException("Error in JSON response. Status code: " + jsonObject.get("statusCode"));
        }

        return new JSONObject(jsonResponse);
    }
}
