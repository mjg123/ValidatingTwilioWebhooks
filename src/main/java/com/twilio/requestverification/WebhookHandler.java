package com.twilio.requestverification;

import com.twilio.twiml.MessagingResponse;
import com.twilio.twiml.messaging.Message;
import org.springframework.web.bind.annotation.*;

@RestController
public class WebhookHandler {

    @GetMapping(value = "/webhook", produces = "application/xml")
    @ValidateTwilioSignature
    @ResponseBody
    public String getWebhook(@RequestParam("Body") String messageBody) {

        System.out.println("Valid webhook call, the message Body is: " + messageBody);

        return new MessagingResponse.Builder().message(
            new Message.Builder(
                "Congrats, you're verified by GET \uD83E\uDD95"
            ).build()
        ).build().toXml();
    }

    @PostMapping(value = "/webhook", produces = "application/xml")
    @ValidateTwilioSignature
    @ResponseBody
    public String postWebhook(@RequestParam("Body") String messageBody) {

        System.out.println("Valid webhook call, the message Body is: " + messageBody);

        return new MessagingResponse.Builder().message(
            new Message.Builder(
                "Congrats, you're verified by POST \uD83E\uDD96"
            ).build()
        ).build().toXml();
    }

}
