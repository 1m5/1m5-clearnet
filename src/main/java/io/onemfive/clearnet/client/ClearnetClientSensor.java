package io.onemfive.clearnet.client;

import io.onemfive.sensors.BaseSensor;
import io.onemfive.sensors.SensorManager;
import io.onemfive.data.Message;
import io.onemfive.data.util.DLC;
import io.onemfive.data.DocumentMessage;
import io.onemfive.data.Envelope;
import io.onemfive.data.util.Multipart;
import okhttp3.*;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

/**
 * TODO: Add Description
 *
 * @author objectorange
 */
public class ClearnetClientSensor extends BaseSensor {

    private static final Logger LOG = Logger.getLogger(ClearnetClientSensor.class.getName());

    public static final String PROP_HTTP_CLIENT = "1m5.clearnet.client"; // true | false
    public static final String PROP_HTTP_CLIENT_TLS = "1m5.clearnet.client.tls"; // true | false
    public static final String PROP_HTTP_CLIENT_TLS_STRONG = "1m5.clearnet.client.tls.strong"; // true | false

    protected static final Set<String> trustedHosts = new HashSet<>();

    protected static final HostnameVerifier trustAllHostnameVerifier = new HostnameVerifier() {

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    protected static final HostnameVerifier hostnameVerifier = new HostnameVerifier() {

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return trustedHosts.contains(hostname);
        }
    };

    protected X509TrustManager trustAllX509TrustManager = new X509TrustManager() {

        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[]{};
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }
    };

    // Create a trust manager that does not validate certificate chains
    protected TrustManager[] trustAllTrustManager = new TrustManager[]{trustAllX509TrustManager};

    protected ConnectionSpec httpSpec;
    protected OkHttpClient httpClient;

    protected ConnectionSpec httpsCompatibleSpec;
    protected OkHttpClient httpsCompatibleClient;

    protected ConnectionSpec httpsStrongSpec;
    protected OkHttpClient httpsStrongClient;

    protected Proxy proxy = null;

    public ClearnetClientSensor() {super();}

    public ClearnetClientSensor(SensorManager sensorManager, Envelope.Sensitivity sensitivity, Integer priority) {
        super(sensorManager, sensitivity, priority);
    }

    @Override
    public String[] getOperationEndsWith() {
        return new String[]{".html"};
    }

    @Override
    public String[] getURLBeginsWith() {
        return new String[]{"http","https"};
    }

    @Override
    public String[] getURLEndsWith() {
        return new String[]{".html",".htm"};
    }

    @Override
    public boolean send(Envelope e) {
        URL url = e.getURL();
        if(url != null) {
            LOG.info("URL="+url.toString());
        } else {
            LOG.info("URL must not be null.");
            return false;
        }
        Map<String,Object> h = e.getHeaders();
        Map<String,String> hStr = new HashMap<>();
        if(h.containsKey(Envelope.HEADER_CONTENT_DISPOSITION) && h.get(Envelope.HEADER_CONTENT_DISPOSITION)!=null) {
            hStr.put(Envelope.HEADER_CONTENT_DISPOSITION,(String)h.get(Envelope.HEADER_CONTENT_DISPOSITION));
        }
        if(h.containsKey(Envelope.HEADER_CONTENT_TYPE) && h.get(Envelope.HEADER_CONTENT_TYPE)!=null) {
            hStr.put(Envelope.HEADER_CONTENT_TYPE, (String)h.get(Envelope.HEADER_CONTENT_TYPE));
        }
        if(h.containsKey(Envelope.HEADER_CONTENT_TRANSFER_ENCODING) && h.get(Envelope.HEADER_CONTENT_TRANSFER_ENCODING)!=null) {
            hStr.put(Envelope.HEADER_CONTENT_TRANSFER_ENCODING, (String)h.get(Envelope.HEADER_CONTENT_TRANSFER_ENCODING));
        }
        if(h.containsKey(Envelope.HEADER_USER_AGENT) && h.get(Envelope.HEADER_USER_AGENT)!=null) {
            hStr.put(Envelope.HEADER_USER_AGENT, (String)h.get(Envelope.HEADER_USER_AGENT));
        }

        ByteBuffer bodyBytes = null;
        CacheControl cacheControl = null;
        if(e.getMultipart() != null) {
            // handle file upload
            Multipart m = e.getMultipart();
            hStr.put(Envelope.HEADER_CONTENT_TYPE, "multipart/form-data; boundary=" + m.getBoundary());
            try {
                bodyBytes = ByteBuffer.wrap(m.finish().getBytes());
            } catch (IOException e1) {
                e1.printStackTrace();
                // TODO: Provide error message
                LOG.warning("IOException caught while building HTTP body with multipart: "+e1.getLocalizedMessage());
                return false;
            }
            cacheControl = new CacheControl.Builder().noCache().build();
        }

        Headers headers = Headers.of(hStr);

        Message m = e.getMessage();
        if(m instanceof DocumentMessage) {
            Object contentObj = DLC.getContent(e);
            if(contentObj instanceof String) {
                if(bodyBytes == null) {
                    bodyBytes = ByteBuffer.wrap(((String)contentObj).getBytes());
                } else {
                    bodyBytes.put(((String)contentObj).getBytes());
                }
            } else if(contentObj instanceof byte[]) {
                if(bodyBytes == null) {
                    bodyBytes = ByteBuffer.wrap((byte[])contentObj);
                } else {
                    bodyBytes.put((byte[])contentObj);
                }
            }
        } else {
            LOG.warning("Only DocumentMessages supported at this time.");
            DLC.addErrorMessage("Only DocumentMessages supported at this time.",e);
            return false;
        }

        RequestBody requestBody = null;
        if(bodyBytes != null) {
            requestBody = RequestBody.create(MediaType.parse((String) h.get(Envelope.HEADER_CONTENT_TYPE)), bodyBytes.array());
        }

        Request.Builder b = new Request.Builder().url(url);
        if(cacheControl != null)
            b = b.cacheControl(cacheControl);
        b = b.headers(headers);
        switch(e.getAction()) {
            case ADD: {b = b.post(requestBody);break;}
            case UPDATE: {b = b.put(requestBody);break;}
            case REMOVE: {b = (requestBody == null ? b.delete() : b.delete(requestBody));break;}
            case VIEW: {b = b.get();break;}
            default: {
                LOG.warning("Envelope.action must be set to ADD, UPDATE, REMOVE, or VIEW");
                return false;
            }
        }
        Request req = b.build();
        if(req == null) {
            LOG.warning("okhttp3 builder didn't build request.");
            return false;
        }
        Response response = null;
        if(url.toString().startsWith("https:")) {
            LOG.info("Sending https request, host="+url.getHost());
//            if(trustedHosts.contains(url.getHost())) {
                try {
//                    LOG.info("Trusted host, using compatible connection...");
                    response = httpsStrongClient.newCall(req).execute();
                    if(!response.isSuccessful()) {
                        LOG.warning(response.toString()+" - code="+response.code());
                        m.addErrorMessage(response.code()+"");
                        handleFailure(m);
                        return false;
                    }
                } catch (IOException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                    m.addErrorMessage(e1.getLocalizedMessage());
                    return false;
                }
//            } else {
//                try {
//                    System.out.println(ClearnetClientSensor.class.getSimpleName() + ": using strong connection...");
//                    response = httpsStrongClient.newCall(req).execute();
//                    if (!response.isSuccessful()) {
//                        m.addErrorMessage(response.code()+"");
//                        return false;
//                    }
//                } catch (IOException ex) {
//                    ex.printStackTrace();
//                    m.addErrorMessage(ex.getLocalizedMessage());
//                    return false;
//                }
//            }
        } else {
            LOG.info("Sending http request, host="+url.getHost());
            if(httpClient == null) {
                LOG.severe("httpClient was not set up.");
                return false;
            }
            try {
                response = httpClient.newCall(req).execute();
                if(!response.isSuccessful()) {
                    LOG.warning("HTTP request not successful: "+response.code());
                    m.addErrorMessage(response.code()+"");
                    handleFailure(m);
                    return false;
                }
            } catch (IOException e2) {
                LOG.warning(e2.getLocalizedMessage());
                m.addErrorMessage(e2.getLocalizedMessage());
                return false;
            }
        }

        LOG.info("Received http response.");
        Headers responseHeaders = response.headers();
        for (int i = 0; i < responseHeaders.size(); i++) {
            LOG.info(responseHeaders.name(i) + ": " + responseHeaders.value(i));
        }
        ResponseBody responseBody = response.body();
        if(responseBody != null) {
            try {
                DLC.addContent(responseBody.bytes(),e);
            } catch (IOException e1) {
                LOG.warning(e1.getLocalizedMessage());
            } finally {
                responseBody.close();
            }
            LOG.info(new String((byte[])DLC.getContent(e)));
        } else {
            LOG.info("Body was null.");
            DLC.addContent(null,e);
        }

        return true;
    }

    protected void handleFailure(Message m) {
        if(m!=null && m.getErrorMessages()!=null && m.getErrorMessages().size()>0) {
            boolean blocked = false;
            for (String err : m.getErrorMessages()) {
                LOG.warning("HTTP Error Message (Tor): " + err);
                if(!blocked) {
                    switch (err) {
                        case "403": {
                            // Forbidden
                            LOG.info("Received HTTP 403 response: Forbidden. HTTP Request considered blocked.");
                            m.addErrorMessage("BLOCKED");
                            blocked = true;
                            break;
                        }
                        case "408": {
                            // Request Timeout
                            LOG.info("Received HTTP 408 response: Request Timeout. HTTP Request considered blocked.");
                            m.addErrorMessage("BLOCKED");
                            blocked = true;
                            break;
                        }
                        case "410": {
                            // Gone
                            LOG.info("Received HTTP 410 response: Gone. HTTP Request considered blocked.");
                            m.addErrorMessage("BLOCKED");
                            blocked = true;
                            break;
                        }
                        case "418": {
                            // I'm a teapot
                            LOG.warning("Received HTTP 418 response: I'm a teapot. HTTP Sensor ignoring.");
                            break;
                        }
                        case "451": {
                            // Unavailable for legal reasons; your IP address might be denied access to the resource
                            LOG.info("Received HTTP 451 response: unavailable for legal reasons. HTTP Request considered blocked.");
                            m.addErrorMessage("BLOCKED");
                            blocked = true;
                            break;
                        }
                        case "511": {
                            // Network Authentication Required
                            LOG.info("Received HTTP 511 response: network authentication required. HTTP Request considered blocked.");
                            m.addErrorMessage("BLOCKED");
                            blocked = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    void sendToBus(Envelope envelope) {
        sensorManager.sendToBus(envelope);
    }

    @Override
    public boolean reply(Envelope e) {
        sensorManager.sendToBus(e);
        return true;
    }

    @Override
    public boolean start(Properties properties) {
        LOG.info("Starting Clearnet Client Sensor...");

        String sensorsDirStr = properties.getProperty("1m5.dir.sensors");
        if(sensorsDirStr==null) {
            LOG.warning("1m5.dir.sensors property is null. Please set prior to instantiating Clearnet Client Sensor.");
            return false;
        }
        try {
            File sensorDir = new File(new File(sensorsDirStr),"clearnet");
            if(!sensorDir.exists() && !sensorDir.mkdir()) {
                LOG.warning("Unable to create Clearnet Sensor directory.");
                return false;
            } else {
                properties.put("1m5.dir.sensors.clearnet",sensorDir.getCanonicalPath());
            }
        } catch (IOException e) {
            LOG.warning("IOException caught while building Clearnet sensor directory: \n"+e.getLocalizedMessage());
            return false;
        }

        boolean trustAllCerts = "true".equals(properties.get("io.onemfive.clearnet.client.trustallcerts"));
        SSLContext trustAllSSLContext = null;
        try {
            if(trustAllCerts) {
                LOG.info("Initialize SSLContext with trustallcerts...");
                trustAllSSLContext = SSLContext.getInstance("TLS");
                trustAllSSLContext.init(null, trustAllTrustManager, new java.security.SecureRandom());
            }
        } catch (NoSuchAlgorithmException e) {
            LOG.warning(e.getLocalizedMessage());
            return false;
        } catch (KeyManagementException e) {
            LOG.warning(e.getLocalizedMessage());
            return false;
        }

        try {
            LOG.info("Setting up HTTP spec clients for http, https, and strong https....");
            httpSpec = new ConnectionSpec
                    .Builder(ConnectionSpec.CLEARTEXT)
                    .build();
            if(proxy == null) {
                LOG.info("Setting up http client...");
                httpClient = new OkHttpClient.Builder()
                        .connectionSpecs(Collections.singletonList(httpSpec))
                        .retryOnConnectionFailure(true)
                        .followRedirects(true)
                        .build();
            } else {
                LOG.info("Setting up http client with proxy...");
                httpClient = new OkHttpClient.Builder()
                        .connectionSpecs(Arrays.asList(httpSpec))
                        .retryOnConnectionFailure(true)
                        .followRedirects(true)
                        .proxy(proxy)
                        .build();
            }

            LOG.info("Setting https.protocols to system property...");
            System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2,TLSv1.3");

            httpsCompatibleSpec = new ConnectionSpec
                    .Builder(ConnectionSpec.COMPATIBLE_TLS)
//                    .supportsTlsExtensions(true)
//                    .allEnabledTlsVersions()
//                    .allEnabledCipherSuites()
                    .build();

            if(proxy == null) {
                LOG.info("Setting up https client...");
                if(trustAllCerts) {
                    LOG.info("Trust All Certs HTTPS Compatible Client building...");
                    httpsCompatibleClient = new OkHttpClient.Builder()
                            .sslSocketFactory(trustAllSSLContext.getSocketFactory(), trustAllX509TrustManager)
                            .hostnameVerifier(trustAllHostnameVerifier)
                            .build();
                } else {
                    LOG.info("Standard HTTPS Compatible Client building...");
                    httpsCompatibleClient = new OkHttpClient.Builder()
                            .connectionSpecs(Arrays.asList(httpsCompatibleSpec))
                            .build();
                }
            } else {
                LOG.info("Setting up https client with proxy...");
                if(trustAllCerts) {
                    LOG.info("Trust All Certs HTTPS Compatible Client with Proxy building...");
                    httpsCompatibleClient = new OkHttpClient.Builder()
                            .sslSocketFactory(trustAllSSLContext.getSocketFactory(), trustAllX509TrustManager)
                            .hostnameVerifier(trustAllHostnameVerifier)
                            .proxy(proxy)
                            .build();
                } else {
                    LOG.info("Standard HTTPS Compatible Client with Proxy building...");
                    httpsCompatibleClient = new OkHttpClient.Builder()
                            .connectionSpecs(Arrays.asList(httpsCompatibleSpec))
                            .proxy(proxy)
                            .build();
                }
            }

            httpsStrongSpec = new ConnectionSpec
                    .Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
                    .cipherSuites(
                            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
                    .build();

            if(proxy == null) {
                LOG.info("Setting up strong https client...");
                if(trustAllCerts) {
                    LOG.info("Trust All Certs Strong HTTPS Compatible Client building...");
                    httpsStrongClient = new OkHttpClient.Builder()
                            .connectionSpecs(Collections.singletonList(httpsStrongSpec))
                            .retryOnConnectionFailure(true)
                            .followSslRedirects(true)
                            .sslSocketFactory(trustAllSSLContext.getSocketFactory(), trustAllX509TrustManager)
                            .hostnameVerifier(trustAllHostnameVerifier)
                            .build();
                } else {
                    LOG.info("Standard Strong HTTPS Compatible Client building...");
                    httpsStrongClient = new OkHttpClient.Builder()
                            .connectionSpecs(Collections.singletonList(httpsStrongSpec))
                            .retryOnConnectionFailure(true)
                            .followSslRedirects(true)
                            .build();
                }
            } else {
                LOG.info("Setting up strong https client with proxy...");
                if(trustAllCerts) {
                    LOG.info("Trust All Certs Strong HTTPS Compatible Client with Proxy building...");
                    httpsStrongClient = new OkHttpClient.Builder()
                            .connectionSpecs(Collections.singletonList(httpsStrongSpec))
                            .retryOnConnectionFailure(true)
                            .followSslRedirects(true)
                            .sslSocketFactory(trustAllSSLContext.getSocketFactory(), trustAllX509TrustManager)
                            .hostnameVerifier(trustAllHostnameVerifier)
                            .proxy(proxy)
                            .build();
                } else {
                    LOG.info("Standard Strong HTTPS Compatible Client with Proxy building...");
                    httpsStrongClient = new OkHttpClient.Builder()
                            .connectionSpecs(Collections.singletonList(httpsStrongSpec))
                            .retryOnConnectionFailure(true)
                            .followSslRedirects(true)
                            .proxy(proxy)
                            .build();
                }
            }

        } catch (Exception e) {
            LOG.warning("Exception caught launching Clearnet Client Sensor: "+e.getLocalizedMessage());
            return false;
        }

        LOG.info("Started.");
        return true;
    }

    @Override
    public boolean pause() {
        return false;
    }

    @Override
    public boolean unpause() {
        return false;
    }

    @Override
    public boolean restart() {
        return false;
    }

    @Override
    public boolean shutdown() {
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        return shutdown();
    }

}
