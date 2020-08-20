package com.twilio.requestverification;

import com.twilio.security.RequestValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

@Component
public class TwilioValidationHandlerInterceptor implements HandlerInterceptor {

    private final Logger logger = LoggerFactory.getLogger(TwilioValidationHandlerInterceptor.class);

    private final String webhookUrlOverride;
    private final RequestValidator twilioValidator;

    @Autowired
    public TwilioValidationHandlerInterceptor(
        @Value("${twilio.auth.token}") String authToken,
        @Value("${twilio.webhook.url.override}") String webhookUrlOverride) {

        this.webhookUrlOverride = webhookUrlOverride;
        twilioValidator = new RequestValidator(authToken);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object requestHandler) throws Exception {

        if (((HandlerMethod) requestHandler).getMethodAnnotation(ValidateTwilioSignature.class) == null) {
            return true;
        }

        var signatureHeader = request.getHeader("X-Twilio-Signature");
        var validationUrl = normalizedRequestUrl(request);

        switch (request.getMethod().toUpperCase()) {
            case "GET":
            case "POST":

                var validationParameters = extractOnlyBodyParams(request, validationUrl);

                if (twilioValidator.validate(validationUrl, validationParameters, signatureHeader)) {
                    return true;
                } else {
                    logger.warn("Validation failed for {} request to {}", request.getMethod(), validationUrl);
                    return validationFailedResponse(response);
                }

            default:
                // only GET and POST are valid
                return validationFailedResponse(response);
        }
    }

    // This method exists to do a couple of things:
    //  1. Take the first value for each param. x-www-form-urlencoded requests can theoretically specify
    //     multiple values for the same parameter. Twilio doesn't do this, and the RequestValidator expects
    //     a `Map<String,String>` so we just take the first value of any parameter found.
    //  2. Work around a quirk in HttpServletRequest. For validation we only need to pass the parameters
    //     from the request *body*, but HSR.getParameterMap() *also* includes any parameters found in the
    //     query String, which will cause validation to fail if present. For POST requests, Twilio will not
    //     add any queryString params, but it's perfectly possible for a user to do that by including them
    //     in the webhook URL.
    private HashMap<String, String> extractOnlyBodyParams(HttpServletRequest request, String validationUrl) throws IOException {

        var allRequestParameters = request.getParameterMap();
        var queryStringParams = UriComponentsBuilder.fromUriString(validationUrl).build().getQueryParams();

        var validationParams = new HashMap<String, String>();

        // loop through _all_ parameters, only keeping ones which _don't_ appear in the query string.
        // request.getParameterMap() decodes query param values, but UriComponents _doesn't_ so we need to
        // cater for that in our comparison
        allRequestParameters.forEach((name, values) -> {
            for (String value : values) {
                if (!(queryStringParams.containsKey(name) &&
                      queryStringParams.get(name).contains(URLEncoder.encode(value, StandardCharsets.US_ASCII)))) {
                    validationParams.put(name, value);
                }
            }
        });

        return validationParams;
    }

    private String normalizedRequestUrl(HttpServletRequest request) {

        String queryStringPart = "";
        if (request.getQueryString() != null){
            queryStringPart = "?" + request.getQueryString();
        }

        if (webhookUrlOverride == null || webhookUrlOverride.isBlank()) {
            return request.getRequestURL().toString() + queryStringPart;
        }

        return webhookUrlOverride + queryStringPart;
    }

    private boolean validationFailedResponse(HttpServletResponse response) throws IOException {
        response.setStatus(401);
        response.getWriter().print("unauthorized");
        return false;
    }

}
