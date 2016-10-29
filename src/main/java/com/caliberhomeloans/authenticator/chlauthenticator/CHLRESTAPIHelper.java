package com.caliberhomeloans.authenticator.chlauthenticator;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is to give helper methods to call Caliber Home Loans REST APIs.
 */
class CHLRESTAPIHelper extends BasicAuthenticator {

    private static final Log log = LogFactory.getLog(CHLRESTAPIHelper.class);

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

        Map<String, String> payLoad = new HashMap<>();
        payLoad.put(CHLAuthenticatorConstants.LOGIN_ID, username);
        payLoad.put(CHLAuthenticatorConstants.PASSWORD, password);

        JSONObject jsonPayLoad = new JSONObject(payLoad);
        StringEntity entity = new StringEntity(jsonPayLoad.toString());
        entity.setContentType(CHLAuthenticatorConstants.JSON_CONTENT_TYPE);
        post.setEntity(entity);

        HttpResponse response = client.execute(post);

        String jsonResponse = EntityUtils.toString(response.getEntity());

        if (log.isDebugEnabled()) {
            log.debug("JSON response: " + jsonResponse);
        }

        JSONObject jsonObject = new JSONObject(jsonResponse);

        if (((Integer) jsonObject.get(CHLAuthenticatorConstants.STATUS_CODE)) != 200) {
            throw new RuntimeException("Error in JSON response. Status code: " + jsonObject.get("statusCode"));
        }

        return jsonObject.get(CHLAuthenticatorConstants.PAY_LOAD).toString();
    }

    JSONObject getUserIdAppNameClaims(String username, String userId, String serviceProviderName) throws IOException {

        Map<String, String> payLoad = new HashMap<>();
        payLoad.put(CHLAuthenticatorConstants.LOGIN_ID, username);
        payLoad.put(CHLAuthenticatorConstants.USER_ID, userId);
        payLoad.put(CHLAuthenticatorConstants.APPLICATION_NAME, serviceProviderName);

        JSONObject jsonPayLoad = new JSONObject(payLoad);
        StringEntity entity = new StringEntity(jsonPayLoad.toString());
        entity.setContentType(CHLAuthenticatorConstants.JSON_CONTENT_TYPE);

        post.setEntity(entity);

        HttpResponse response = client.execute(post);
        String jsonResponse = EntityUtils.toString(response.getEntity());

        if (log.isDebugEnabled()) {
            log.debug("JSON response: " + jsonResponse);
        }

        JSONObject jsonObject = new JSONObject(jsonResponse);

        if (((Integer) jsonObject.get(CHLAuthenticatorConstants.STATUS_CODE)) != 200) {
            throw new RuntimeException("Error in JSON response. Status code: " + jsonObject.get("statusCode"));
        }

        return jsonObject;
    }
}
