from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def upload_pcap(request):
    # In a real app, we would process request.FILES['file'] here
    return Response({"status": "ok", "message": "PCAP received successfully"})
