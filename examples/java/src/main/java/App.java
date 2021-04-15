import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import com.google.gson.Gson;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class App {
    // Replace this with the actual issuer ID you've got from Wallester
    private static final String issuer = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

    // Replace this with the actual audience ID you've got from Wallester
    private static final String audience = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

    // Replace this with actual Wallester API URL
    private static final String apiURL = "http://xxx.wallester.eu/v1/test/ping";
    
    public static void main(String[] args) {
        try {
            PrivateKey privateKey = readPrivateKey(System.getProperty("user.dir") + "/keys/example_private.pkcs8");
            PublicKey wallesterPublicKey = readPublicKey(System.getProperty("user.dir") + "/keys/example_wallester_public.pkcs8");

            // Replace with actual JSON payload
            PingRequest request = new PingRequest();
            request.message = "ping";
            Gson gson = new Gson();
            String json = gson.toJson(request);
            byte[] requestBody = json.getBytes(StandardCharsets.UTF_8.name());
            String responseBody = doRequest(requestBody, privateKey, wallesterPublicKey);
            PingResponse response = gson.fromJson(responseBody, PingResponse.class);
            if (!response.message.equals("pong")) {
                throw new RuntimeException("Invalid response message, expected 'pong', got '" + response.message + "'");
            }

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private static String calculateRequestBodyHash(byte[] body) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(body);
        String encoded = Base64.getEncoder().encodeToString(hash);
        return encoded;
    }

    private static String createToken(PrivateKey privateKey, String requestBodyHash) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("rbh", requestBodyHash);

        TimeZone utc = TimeZone.getTimeZone("UTC");

        Calendar expires = Calendar.getInstance(utc);
        expires.roll(Calendar.MINUTE, 1);

        String token = Jwts.builder()
            .setClaims(claims)
            .setIssuer(issuer)
            .setAudience(audience)
            .setExpiration(expires.getTime())
            .setSubject("api-request")
            .signWith(SignatureAlgorithm.RS256, privateKey)
            .compact();

        return token;
    }

    private static String doRequest(byte[] requestBody, PrivateKey privateKey, PublicKey wallesterPublicKey) throws Exception {
        String requestBodyHash = calculateRequestBodyHash(requestBody);
        String token = createToken(privateKey, requestBodyHash);

        System.out.println("Request JWT token: " + token);

        URL url = new URL(apiURL);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + token);

        DataOutputStream output = new DataOutputStream(connection.getOutputStream());
        output.write(requestBody);
        output.flush();
        output.close();

        InputStream input = connection.getInputStream();
        BufferedReader in = new BufferedReader(new InputStreamReader(input));
        StringBuffer sb = new StringBuffer();
        String line;
        while ((line = in.readLine()) != null) {
            sb.append(line);
        }
        in.close();
        String responseString = sb.toString();
        byte[] responseBody = responseString.getBytes(StandardCharsets.UTF_8.name());

        String bearer = connection.getHeaderField("Authorization");
        String responseToken = bearer.replace("Bearer ", "");
        System.out.println("Response JWT token: " + responseToken);

        connection.disconnect();

        String responseBodyHash = calculateRequestBodyHash(responseBody);

        try {
            verifyToken(responseToken, responseBodyHash, wallesterPublicKey);
            System.out.println("Response is trusted");
        } catch (Exception e) {
            System.out.println("Response is not trusted: " + e);
        }

        return responseString;
    }

    private static PrivateKey readPrivateKey(String filename) throws Exception {
        RandomAccessFile raf = new RandomAccessFile(filename, "r");
        byte[] buf = new byte[(int)raf.length()];
        raf.readFully(buf);
        raf.close();
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(kspec);
    }

    private static PublicKey readPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static void verifyToken(String token, String requestBodyHash, PublicKey publicKey) {
        Jwts.parser().setSigningKey(publicKey).require("rbh", requestBodyHash).parse(token);
    }    
}
