package com.moxtra.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.xml.security.utils.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONObject;

public class MoxtraAPIUtil {
    public static String UNIQUEID_GRANT_TYPE = "http://www.moxtra.com/auth_uniqueid";
    public static String API_HOST_URL = "https://api.moxtra.com/";
    public static String WEB_HOST_URL = "https://www.moxtra.com/";
    public static String PARAM_ACCESS_TOKEN = "access_token";
    public static String PARAM_EXPIRES_IN = "expires_in";

    /**
     * To get the Access Token via /oauth/token unique_id. The return in the following JSON format
     *   
     *   {
     *   	"access_token": ACCESS_TOKEN,
     *   	"expires_in": EXPIRES_IN,
     *   	...
     *   }
     * 
     * @param client_id
     * @param client_secret
     * @param unique_id
     * @param firstname (optional)
     * @param lastname (optional) 
     * @return HashMap    
     * @throws MoxtraAPIUtilException
     */

    public static HashMap<String, Object> getAccessToken(String client_id, String client_secret, String unique_id,
            String firstname, String lastname, String pictureUrl) throws MoxtraAPIUtilException {

        if (client_id == null || client_secret == null || unique_id == null) {
            throw new MoxtraAPIUtilException("client_id, client_secret, and unique_id are required!");
        }

        String timestamp = Long.toString(System.currentTimeMillis());
        HashMap<String, Object> myMap = new HashMap<String, Object>();

        try {

            // generate code
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secret_key = new SecretKeySpec(client_secret.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);

            StringBuffer total = new StringBuffer();
            total.append(client_id);
            total.append(unique_id);
            total.append(timestamp);

            String signature = new String(encodeUrlSafe(sha256_HMAC.doFinal(total.toString().getBytes()))).trim();

            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httpPost = new HttpPost(API_HOST_URL + "oauth/token");
            // Request parameters and other properties.
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("client_id", client_id));
            params.add(new BasicNameValuePair("client_secret", client_secret));
            params.add(new BasicNameValuePair("grant_type", UNIQUEID_GRANT_TYPE));
            params.add(new BasicNameValuePair("uniqueid", unique_id));
            params.add(new BasicNameValuePair("timestamp", timestamp));
            params.add(new BasicNameValuePair("signature", signature));
            params.add(new BasicNameValuePair("orgid", "PblxugkJOeZ4lVaPgktFs64"));
            //params.add(new BasicNameValuePair("pictureurl", pictureUrl));
            //params.add(new BasicNameValuePair("timezone", "Asia/Dubai"));

            // optional
            if (firstname != null) {
                params.add(new BasicNameValuePair("firstname", firstname));
            }

            if (lastname != null) {
                params.add(new BasicNameValuePair("lastname", lastname));
            }
            httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

            HttpResponse response = httpClient.execute(httpPost);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("unable to get access_token");
            }
            if (responseEntity != null) {
                // EntityUtils to get the response content
                String content = EntityUtils.toString(responseEntity);

                JSONObject obj = new JSONObject(content);

                String aT = obj.getString("access_token");
                String tokenType = obj.getString("token_type");
                Long expiresIn = obj.getLong("expires_in");
                String scope = obj.getString("scope");

                // get access token
                ObjectMapper objectMapper = new ObjectMapper();
                myMap = objectMapper.readValue(content, HashMap.class);

            } else {
                throw new Exception("unable to make request");
            }

            return myMap;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);
        }
    }

    public static String getPartnerAccessToken(String clientId, String clientSecret, String userName, String password)
            throws Exception {

        HttpClient httpClient = HttpClientBuilder.create().build();

        HttpGet httpGet;
        try {
            httpGet = new HttpGet(API_HOST_URL + "/oauth/token?client_id=" + clientId + "&client_secret="
                    + clientSecret + "&username=" + userName + "&password=" + password + "&grant_type=password");

            HttpResponse response = httpClient.execute(httpGet);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Unable to get partner access_token");
            }
            if (responseEntity != null) {
                // EntityUtils to get the response content
                return EntityUtils.toString(responseEntity);
            }

        } catch (Exception e) {
            throw new Exception("unable to make request");
        }
        return null;
    }

    /**
     * upload Binder Cover page
     * 
     * @param binder_id
     * @param uploadImage
     * @param access_token
     * @return Binder info in JSON
     * @throws MoxtraAPIUtilException
     */

    public static String uploadBinderCover(String binder_id, File uploadImage, String access_token)
            throws MoxtraAPIUtilException {

        if (binder_id == null || uploadImage == null || access_token == null) {
            throw new MoxtraAPIUtilException("binder_id, uploadImage, and access_token are required!");
        }

        String requestURL = API_HOST_URL + binder_id + "/coverupload?access_token=" + access_token;

        try {
            MultipartUtility multipart = new MultipartUtility(requestURL, "UTF-8");

            multipart.addFilePart("file", uploadImage);

            List<String> response = multipart.finish();

            //System.out.println("SERVER REPLIED:");

            StringBuffer result = new StringBuffer();
            for (String line : response) {
                //System.out.println(line);
                result.append(line);
            }

            return result.toString();

        } catch (IOException ex) {
            throw new MoxtraAPIUtilException("unable to upload image", ex);
        }
    }

    /**
     * Upload page into Binder
     * 
     * @param binder_id
     * @param uploadFile
     * @param access_token
     * @return Binder page info in JSON
     * @throws MoxtraAPIUtilException
     */

    public static String uploadBinderPage(String binder_id, File uploadFile, String access_token)
            throws MoxtraAPIUtilException {

        if (binder_id == null || uploadFile == null || access_token == null) {
            throw new MoxtraAPIUtilException("binder_id, uploadFile, and access_token are required!");
        }

        String requestURL = API_HOST_URL + binder_id + "/pageupload?access_token=" + access_token;

        try {
            MultipartUtility multipart = new MultipartUtility(requestURL, "UTF-8");

            multipart.addFilePart("file", uploadFile);

            List<String> response = multipart.finish();

            //System.out.println("SERVER REPLIED:");

            StringBuffer result = new StringBuffer();
            for (String line : response) {
                //System.out.println(line);
                result.append(line);
            }

            return result.toString();

        } catch (IOException ex) {
            throw new MoxtraAPIUtilException("unable to upload page file", ex);
        }
    }

    /**
     * Upload current user's picture
     * 
     * @param uploadImage
     * @param access_token
     * @return update status in JSON
     * @throws MoxtraAPIUtilException
     */

    public static String uploadUserPicture(File uploadImage, String access_token) throws MoxtraAPIUtilException {

        if (uploadImage == null || access_token == null) {
            throw new MoxtraAPIUtilException("uploadImage and access_token are required!");
        }

        String requestURL = API_HOST_URL + "me/picture?access_token=" + access_token;

        try {
            MultipartUtility multipart = new MultipartUtility(requestURL, "UTF-8");

            multipart.addFilePart("file", uploadImage);

            List<String> response = multipart.finish();

            //System.out.println("SERVER REPLIED:");

            StringBuffer result = new StringBuffer();
            for (String line : response) {
                //System.out.println(line);
                result.append(line);
            }

            return result.toString();

        } catch (IOException ex) {
            throw new MoxtraAPIUtilException("unable to upload user picture", ex);
        }
    }

    /**
     * upload File into Meet based on session_id and session_key for host
     * 
     * @param session_id
     * @param session_key
     * @param uploadFile
     * @param access_token
     * @return response in JSON
     * @throws MoxtraAPIUtilException
     */

    public static String uploadFileToMeet(String session_id, String session_key, File uploadFile, String access_token)
            throws MoxtraAPIUtilException {

        if (session_id == null || session_key == null || uploadFile == null || access_token == null) {
            throw new MoxtraAPIUtilException("session_id, session_key, uploadFile, and access_token are required!");
        }

        String json_result = null;
        InputStream inputStream = null;

        try {

            String filename = URLEncoder.encode(uploadFile.getName(), "UTF-8");
            String requestURL = WEB_HOST_URL + "board/upload?type=original&session_id=" + session_id + "&key="
                    + session_key + "&name=" + filename + "&access_token=" + access_token;

            inputStream = new FileInputStream(uploadFile);

            long length = uploadFile.length();

            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httppost = new HttpPost(requestURL);
            InputStreamEntity entity = new InputStreamEntity(inputStream, length, ContentType.APPLICATION_OCTET_STREAM);
            httppost.setEntity(entity);

            HttpResponse response = httpClient.execute(httppost);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Upload file failed");
            }
            if (responseEntity != null) {
                json_result = EntityUtils.toString(responseEntity);
            }

            return json_result;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);

        } finally {

            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ex) {
                    throw new MoxtraAPIUtilException(ex.getMessage(), ex);
                }
            }

        }

    }

    /**
     * invoke API
     * 
     * @param url
     * @param json_input
     * @param access_token
     * @return response
     * @throws MoxtraAPIUtilException
     */

    public static String invokePostAPI(String url, String json_input, String access_token)
            throws MoxtraAPIUtilException {

        if (url == null || json_input == null || access_token == null) {
            throw new MoxtraAPIUtilException("url, json, and access_token are required!");
        }

        String json_result = null;

        try {
            String requestURL = null;
            if (url.indexOf("?") > 0) {
                requestURL = url + "&access_token=" + access_token;
            } else {
                requestURL = url + "?access_token=" + access_token;
            }

            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httppost = new HttpPost(requestURL);

            ContentType contentType = ContentType.create("application/json", Charset.forName("UTF-8"));
            StringEntity entity = new StringEntity(json_input, contentType);
            httppost.setEntity(entity);

            HttpResponse response = httpClient.execute(httppost);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Invoke Post API failed");
            }
            if (responseEntity != null) {
                json_result = EntityUtils.toString(responseEntity);
            }

            return json_result;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);
        }

    }

    /**
     * invoke Get API
     * 
     * @param url
     * @param access_token
     * @return response
     * @throws MoxtraAPIUtilException
     */

    public static String invokeGetAPI(String url, String access_token) throws MoxtraAPIUtilException {

        if (url == null || access_token == null) {
            throw new MoxtraAPIUtilException("url and access_token are required!");
        }

        String json_result = null;

        try {
            String requestURL = null;
            if (url.indexOf("?") > 0) {
                requestURL = url + "&access_token=" + access_token;
            } else {
                requestURL = url + "?access_token=" + access_token;
            }

            // verifica proxy
            CloseableHttpClient httpClient = null;
            HttpGet httpget = new HttpGet(requestURL);
            if (System.getProperty("http.proxyHost") == null && System.getProperty("http.proxyPort") == null) {
                System.out.println("sem proxy");
                httpClient = HttpClients.createDefault();
            } else {
                System.out.println("com proxy");
                String host = System.getProperty("http.proxyHost");
                String port = System.getProperty("http.proxyPort");
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(new AuthScope(host, Integer.parseInt(port), AuthScope.ANY_REALM,
                        AuthScope.ANY_SCHEME), new UsernamePasswordCredentials("luiz.taira", "taira@201506"));
                //                        //new NTCredentials("luiz.taira", "taira@201506", "", "sp01"));
                httpClient = HttpClients.custom().setDefaultCredentialsProvider(credsProvider).build();
                //httpClient = HttpClients.custom().build();
                HttpHost proxy = new HttpHost(host, Integer.parseInt(port));
                RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
                httpget.setConfig(config);
            }

            HttpResponse response = httpClient.execute(httpget);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Invoke Get API failed");
            }
            if (responseEntity != null) {
                json_result = EntityUtils.toString(responseEntity);
            }

            return json_result;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);
        }

    }

    /**
     * invoke Delete API
     * 
     * @param url
     * @param access_token
     * @return response
     * @throws MoxtraAPIUtilException
     */

    public static String invokeDeleteAPI(String url, String access_token) throws MoxtraAPIUtilException {

        if (url == null || access_token == null) {
            throw new MoxtraAPIUtilException("url and access_token are required!");
        }

        String json_result = null;

        try {
            String requestURL = null;
            if (url.indexOf("?") > 0) {
                requestURL = url + "&access_token=" + access_token;
            } else {
                requestURL = url + "?access_token=" + access_token;
            }

            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpDelete httpdelete = new HttpDelete(requestURL);

            HttpResponse response = httpClient.execute(httpdelete);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Invoke Delete API failed");
            }
            if (responseEntity != null) {
                json_result = EntityUtils.toString(responseEntity);
            }

            return json_result;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);
        }

    }

    /**
     * create a binder with json_input String
     * 
     * @param json_input
     * @param access_token
     * @return response in JSON
     * @throws MoxtraAPIUtilException
     */

    public static String createBinder(String json_input, String access_token) throws MoxtraAPIUtilException {

        if (json_input == null || access_token == null) {
            throw new MoxtraAPIUtilException("json and access_token are required!");
        }

        String json_result = null;

        try {
            String requestURL = API_HOST_URL + "me/binders?access_token=" + access_token;

            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httppost = new HttpPost(requestURL);

            ContentType contentType = ContentType.create("application/json", Charset.forName("UTF-8"));
            StringEntity entity = new StringEntity(json_input, contentType);
            httppost.setEntity(entity);

            HttpResponse response = httpClient.execute(httppost);
            HttpEntity responseEntity = response.getEntity();
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Create binder failed");
            }
            if (responseEntity != null) {
                json_result = EntityUtils.toString(responseEntity);
            }

            return json_result;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);
        }

    }

    /**
     * URLSafe Base64 encoding with space padding 
     * 
     * @param data
     * @return
     */
    public static byte[] encodeUrlSafe(byte[] data) {
        String strcode = Base64.encode(data);
        byte[] encode = strcode.getBytes();
        for (int i = 0; i < encode.length; i++) {
            if (encode[i] == '+') {
                encode[i] = '-';
            } else if (encode[i] == '/') {
                encode[i] = '_';
            } else if (encode[i] == '=') {
                encode[i] = ' ';
            }
        }
        return encode;
    }

    public static String createUser(String accessToken) {
        JSONObject params = new JSONObject();
        params.put("unique_id", "steve.jobs");
        params.put("first_name", "Steve");
        params.put("last_name", "Jobs");
        //params.put("timezone", "America/Sao_Paulo");

        String[] users = new String[1];
        users[0] = params.toString();
        JSONObject object = new JSONObject();
        object.accumulate("users", users);

        try {
            return invokePostAPI(API_HOST_URL + "QtdSyVAq3S9AgD1VK9X4Yi0/orgs/PBjgNRrhb5sBXvzTzQIfi55/users",
                    object.toString(), accessToken);
        } catch (MoxtraAPIUtilException e) {
            e.printStackTrace();
        }
        return "nada";
    }

    public static String downloadFile(String url, String access_token) throws MoxtraAPIUtilException {
        if (url == null || access_token == null) {
            throw new MoxtraAPIUtilException("url and access_token are required!");
        }

        String json_result = null;

        try {
            String requestURL = null;
            if (url.indexOf("?") > 0) {
                requestURL = url + "&access_token=" + access_token;
            } else {
                requestURL = url + "?access_token=" + access_token;
            }

            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpGet httpget = new HttpGet(requestURL);

            HttpResponse response = httpClient.execute(httpget);
            HttpEntity responseEntity = response.getEntity();
            Header[] e = response.getAllHeaders();
            for (Header header : e) {
                HeaderElement[] el = header.getElements();
                for (HeaderElement headerElement : el) {
                    System.out.println(headerElement.getName());
                    System.out.println(headerElement.getValue());
                }
                System.out.println(header.getName());
                System.out.println(header.getValue());
            }
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Invoke Get API failed");
            }
            if (responseEntity != null) {
                String filePath = "/home/taira/Desktop/teste";
                BufferedInputStream bis = new BufferedInputStream(responseEntity.getContent());
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(new File(filePath)));
                int inByte;
                while ((inByte = bis.read()) != -1) {
                    bos.write(inByte);
                }
                bis.close();
                bos.close();
            }

            return json_result;

        } catch (Exception e) {
            throw new MoxtraAPIUtilException(e.getMessage(), e);
        }
    }

    public static String extractHistoric(String result) {
        JSONObject object = new JSONObject(result);
        JSONArray feeds = object.getJSONObject("data").getJSONArray("feeds");
        System.out.println(feeds);
        int j = 1;
        for (int i = feeds.length() - 1; i >= 0; i--) {
            System.out.println("Mensagem: " + j);
            j++;
            JSONObject feed = feeds.getJSONObject(i);

            // verb
            Object v = feed.get("verb");
            String verb = null;
            if (!v.equals(null)) {
                verb = v.toString();
                System.out.println("verb: " + verb);
            } else {
                continue;
            }

            // msg
            Object o = feed.get("object");
            JSONObject obj = null;
            if (!o.equals(null)) {
                obj = new JSONObject(o.toString());
            } else {
                continue;
            }

            //type
            String objectType = obj.get("objectType").toString();
            System.out.println("objectType: " + objectType);

            //caso o objeto é uma criação de uma conversa
            if (objectType.equals("binder")) {
                String binderName = obj.get("displayName").toString();
                System.out.println(binderName);
                String id = obj.get("id").toString();
                System.out.println("id: " + id);

                //caso o objeto é em relação a um usuário    
            } else if (objectType.equals("person")) {
                String action = null;
                if (verb.equals("add")) {
                    action = "Adicionou o";
                } else if (verb.equals("remove")) {
                    action = "Removeu o";
                } else if (verb.equals("give")) {
                    action = "Atribuiu uma tarefa ao";
                }
                String userName = obj.get("displayName").toString();
                System.out.println(action + " usuário " + userName);
                String id = obj.get("id").toString();
                System.out.println("id: " + id);

                //caso o objeto é em relação a um comentario na conversa
            } else if (objectType.equals("comment")) {
                String contentText = obj.get("content_text").toString();
                System.out.println("texto: " + contentText);
                String id = obj.get("id").toString();
                System.out.println("id: " + id);

                //caso o objeto é em relação a um arquivo e/ou documento
            } else if (objectType.equals("file")) {
                String fileName = obj.get("displayName").toString();
                System.out.println("fileName: " + fileName);
                String mimeType = obj.get("mimeType").toString();
                System.out.println("mimeType: " + mimeType);
                String id = obj.get("id").toString();
                System.out.println("id: " + id);

                //caso o objeto é em relação a um quadro branco
            } else if (objectType.equals("page")) {
                String id = obj.get("id").toString();
                System.out.println("id: " + id);
                if (verb.equals("create")) {
                    String url = obj.get("url").toString();
                    System.out.println("url: " + url);
                } else if (verb.equals("add")) {
                    System.out.println("Esta retornando null em tudo");
                }
                String tp = obj.get("type").toString();
                System.out.println(tp);

                //caso o objeto é em relação a uma lista de usuários
            } else if (objectType.equals("collection")) {
                JSONArray array = obj.getJSONArray("items");
                System.out.println("items: " + array);

                //caso o objeto é em relação a uma anotação feita em um arquivo, nota, etc
            } else if (objectType.equals("annotation")) {
                if (verb.equals("tag")) {
                    System.out.println("Fez uma anotação ");
                }

                //caso o objeto é em relação a uma tarefa
            } else if (objectType.equals("todo")) {
                String id = obj.get("id").toString();
                System.out.println("id: " + id);
                String action = null;
                String tarefa = obj.get("displayName").toString();
                if (verb.equals("create")) {
                    action = "Criou a tarefa: ";
                    System.out.println(action + tarefa);
                } else if (verb.equals("complete")) {
                    action = "Completou a tarefa: ";
                    System.out.println(action + tarefa);
                } else if (verb.equals("update")) {
                    String summary = obj.getString("summary");
                    action = "Atualizou a tarefa ";
                    System.out.println(action + tarefa + ": " + summary);
                }

            } else if (objectType.equals("duedate")) {
                Calendar calendar = DatatypeConverter.parseDateTime(obj.getString("content"));
                Date until = calendar.getTime();
                System.out.println("Data de vencimento da tarefa: " + until);
            }

            // actor
            JSONObject actor = feed.getJSONObject("actor");
            System.out.println("Nome: " + actor.get("displayName"));
            System.out.println("unique_id: " + actor.get("unique_id"));

            // data
            Calendar calendar = DatatypeConverter.parseDateTime(feed.getString("published"));
            Date published = calendar.getTime();
            System.out.println("data:  " + published);

            System.out.println("=========================================================");
            System.out.println("");

        }
        return "";
    }

    public static void main(String[] args) throws Exception {

        //System.setProperty("http.proxyHost", "172.16.98.21");
        //System.setProperty("http.proxyPort", "8080");

        String client_id = "l4Wg3QmXme4";
        String client_secret = "qrp1zA_pF5w";
        String login1 = "luiz.taira";
        String login2 = "bart";
        String partnerLogin = "";
        String partnerPassword = "";

        HashMap<String, Object> map = getAccessToken(client_id, client_secret, login1, "", "", "");
        //String partnerAccessToken = getPartnerAccessToken(client_id, client_secret, partnerLogin, partnerPassword);
        //JSONObject obj = new JSONObject(partnerAccessToken);
        //HashMap<String, Object> map1 = getAccessToken(client_id, client_secret, login2, "", "", "");

        // informações do usuário
        //String result = invokeGetAPI(API_HOST_URL + "me", map.get("access_token").toString());

        // informações do orgId
        //String result = invokeGetAPI(API_HOST_URL + "QtdSyVAq3S9AgD1VK9X4Yi0/orgs/PBjgNRrhb5sBXvzTzQIfi55", obj.get("access_token").toString());

        // mensagens não lidas
        //        for (int i = 0; i < 20; i++) {
        //            long tempoInicial = System.currentTimeMillis();
        //            invokeGetAPI(API_HOST_URL + "/me/unreadfeeds", map.get("access_token").toString());
        //            System.out
        //                    .println(String.format(i + ": " + "%.3f s%n", (System.currentTimeMillis() - tempoInicial) / 1000d));
        //            long tempoInicial2 = System.currentTimeMillis();
        //            invokeGetAPI(API_HOST_URL + "/me/unreadfeeds", map1.get("access_token").toString());
        //            System.out.println(String.format(i + ": " + "%.3f s%n",
        //                    (System.currentTimeMillis() - tempoInicial2) / 1000d));
        //            Thread.sleep(5000);
        //        }

        // remove user
        //String result = invokeDeleteAPI(API_HOST_URL + "PKu5ciAsdUN66qgUlLOg8WG/users/" + login, obj.get("access_token").toString());

        // anexos
        //String result = invokeGetAPI(API_HOST_URL + "BFWKSltOZ21EbnJSgW4Vum4/pages", map.get("access_token").toString());

        // contatos do usuario
        //String result = invokeGetAPI(API_HOST_URL + "U9HqlFuaoBd3LAHVDC6kgqC/contacts", map.get("access_token").toString());        

        //String result = invokeGetAPI(API_HOST_URL + "PBjgNRrhb5sBXvzTzQIfi55/users/luiz.taira", map.get("access_token").toString());

        // binders do usuario
        //String result = invokePostAPI(API_HOST_URL + "me/binders","{\"name\": \"\",\"conversation\":true, \"restricted\":true, \"suppress_feed\":true}", map.get("access_token").toString());
        //JSONObject obj = new JSONObject(result);
        //String result1 = invokePostAPI(API_HOST_URL + obj.getJSONObject("data").getString("id") + "/inviteuser", "{\"users\": [{\"user\": {\"unique_id\": \"michael\"}}]}", map.get("access_token").toString());

        // upload user picture
        //File file = new File("/home/taira/Desktop/RFLUIG-743-Fluig_Messaging.pdf");
        //String result = uploadUserPicture(file, map.get("access_token").toString());

        // upload file para binder
        //String result = uploadBinderPage("BCy4c4uhWOhB2QBpxghFkl5", file, map.get("access_token").toString());

        // criar usuário
        //String result = createUser(map.get("access_token").toString());

        // getBinder informaçções do binder
        //String result = invokeGetAPI(API_HOST_URL + "BArf4zyN0Q4AaUh6hLF0sW2", map.get("access_token").toString());

        // download de arquivo        
        //String result = downloadFile(API_HOST_URL + "BFWKSltOZ21EbnJSgW4Vum4/pagedownload/44", map.get("access_token").toString());

        //meeting info
        //String result = invokeGetAPI(API_HOST_URL + "meets/438830124", map.get("access_token").toString());

        //rename binder
        //String result = invokePostAPI(API_HOST_URL + "BaVkFRG5xXCKNxBRsOAocWL", "{\"name\":\"Novo nome de binder\"}",map.get("access_token").toString());

        //remove binder        
        //String result = invokeDeleteAPI(API_HOST_URL + "Bj8JDfAZL2FAKCQiLKd4ut1", map.get("access_token").toString());
        //invokeDeleteAPI(API_HOST_URL + "BCNzT1QewpcHA7qRLmMoSlB", map.get("access_token").toString());

        // lista de binders
        //String result = invokeGetAPI(API_HOST_URL + "me/binders", map.get("access_token").toString());

        // mensagens não lidas
        //String result = invokeGetAPI(API_HOST_URL + "/me/unreadfeeds", map.get("access_token").toString());

        // conversas de um binder
        String result = extractHistoric(invokeGetAPI(API_HOST_URL + "/BoAo6aULPrzIWdZgkVdIbdJ/conversations?count=100",
                map.get("access_token").toString()));

        //System.out.println(map);
        System.out.println(result);
        //System.out.println(result1);
    }
}
