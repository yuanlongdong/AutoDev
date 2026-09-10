"""v0.4.0 round-5 – @csrf_exempt decoration on state-changing views."""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect


@csrf_exempt
def create_user(request):
    # VULNERABLE: CSRF protection disabled on a POST endpoint.
    data = request.POST.dict()
    return JsonResponse({"created": data})


@csrf_exempt
def update_profile(request):
    # VULNERABLE: another csrf_exempt view.
    return JsonResponse({"updated": True})


@csrf_protect
def safe_profile(request):
    # SAFE: csrf_protect (the detector must only flag csrf_exempt).
    return JsonResponse({"ok": True})


def normal_view(request):
    # SAFE: no CSRF decoration at all.
    return JsonResponse({"ok": True})
