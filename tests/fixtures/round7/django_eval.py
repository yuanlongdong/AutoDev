"""Round-7 Django-style code injection fixture (request.POST / request.GET)."""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def calculate(request):
    """BAD: eval() on request.POST."""
    expression = request.POST.get('expr')
    result = eval(expression)
    return JsonResponse({'result': result})


@csrf_exempt
def dynamic_query(request):
    """BAD: exec() on request.POST."""
    code = request.POST.get('code')
    result = {}
    exec(code, {'result': result})
    return JsonResponse(result)


@csrf_exempt
def evaluate_query_param(request):
    """BAD: eval() on request.GET."""
    expr = request.GET.get('expr')
    return JsonResponse({'result': eval(expr)})
