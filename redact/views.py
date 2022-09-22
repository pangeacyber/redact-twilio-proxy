import os

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

# Load the .env file into environment variables
from dotenv import load_dotenv
load_dotenv()

# Read the Twilio SID and Auth Token from the environment variables
accountSid = os.getenv("ACCOUNT_SID")
authToken = os.getenv("AUTH_TOKEN")

# Import the Twilio SDK
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse

# Instantiate a Twilio Client using the accountSid and authToken
twilioClient = Client(accountSid, authToken)

# Import the Pangea SDK
from pangea.config import PangeaConfig
from pangea.services import Redact

# Read the Pangea Config Id and Auth Token from the environment variables
pangeaDomain = os.getenv("PANGEA_DOMAIN")
redactToken = os.getenv("PANGEA_AUTH_TOKEN")
redactConfigId = os.getenv("PANGEA_CONFIG_ID")

# Instantiate a Pangea Configuration object with the end point domain and configId
redactConfig = PangeaConfig(domain=pangeaDomain, config_id=redactConfigId)
redactService = Redact(redactToken, config=redactConfig)

# Read the target recipients numbers from environment variables
ownerNumber = os.getenv("OWNER_NUMBER")
targetNumber = os.getenv("TARGET_NUMBER")

print("********************************************")

# A Proxy that forwards messages between the proxy owner and the target number.
# Each message is checked for PIII and redacted according to the redact rules
# set on the Pangea Console (https://console.pangea.cloud)
@require_POST
@csrf_exempt
def index(request):

    print(f"Event: {request.POST}")

    # Define a response object, in case a response to the sender is required
    resp = MessagingResponse()

    # Determine the destination number
    if request.POST['From'].endswith(ownerNumber):
      # If the message is from the owner, send it to target
      destinationNumber = targetNumber
    elif request.POST['From'].endswith(targetNumber):
      # If the message is form the target, send it to owner
      destinationNumber = ownerNumber
    else:
      # If the message is from any other number, reply to the sender
      destinationNumber = request.POST['From']

    originalMessage = request.POST['Body']
    print(f"Redacting PII from: {originalMessage}")
    redactResponse = redactService.redact(originalMessage)

    if redactResponse.success:
        print(f"Response: {redactResponse.result}")
        redactedMessage = redactResponse.result.redacted_text

        # Send the redacted message to the destinationNumber
        twilioClient.messages.create(
                     body=redactedMessage,
                     from_=request.POST['To'],
                     to=destinationNumber
                 )
        # If a redacted message was sent, notify the sender via an automated response
        if redactedMessage != originalMessage:
            resp.message("AUTOMATED RESPONSE: You sent a message with sensitive, personal information. Our system redacted that information so that you can remain protected. The recipient of that message cannot access your sensitive information through this conversation.")
    else:
        print(f"Redact Request Error: {redactResponse.response.text}")
        if redactResponse.result and redactResponse.result.errors:
            for err in redactResponse.result.errors:
                print(f"\t{err.detail}")
                resp.message(err.detail)

    # Return the TwiML
    return HttpResponse(resp)
