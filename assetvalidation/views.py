from django.views.decorators.cache import never_cache
from django.shortcuts import render
from django.http import HttpResponse
from .apienginetw import ApiEngineTw
from .apienginecbp import ApiEngineCbp
from .apienginecbc import ApiEngineCbc
from datetime import datetime
from datetime import timedelta
import time
import pandas
import csv

# Create your views here.
@never_cache
def home(request):
    context = {}
    if request.method == 'POST':
        tm = time.time()
        assetvalidation = []
        hostnames = request.POST['hostnames']
        ipaddresses = request.POST['ipaddresses']
        sectool = "blank" if (("sectool" not in request.POST) or (request.POST["sectool"] is None)) else request.POST["sectool"]
        dt = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        request.session['sectool'] = sectool
        request.session['dt'] = dt
        if (sectool == 'tw'):
            apitw = ApiEngineTw()
            assetvalidation.append(apitw.GetHeader())
            if (not ((hostnames is None) or (hostnames == ""))): assetvalidation += apitw.validatetw(hostnames=request.POST['hostnames'])["assetvalidation"]          #concatenate array not append 
            if (not ((ipaddresses is None) or (ipaddresses == ""))): assetvalidation += apitw.validatetw(ipaddresses=request.POST['ipaddresses'])["assetvalidation"]  #concatenate array not append
            context = { "assetvalidation": pandas.DataFrame(assetvalidation).to_html(header=False), "sectool": sectool, "dt": dt, "tm": timedelta(seconds=time.time()-tm) }
            request.session['csvdata'] = assetvalidation
        elif (sectool == 'cbp'):
            apicbp = ApiEngineCbp()
            assetvalidation.append(apicbp.GetHeader())
            if (not ((hostnames is None) or (hostnames == ""))): assetvalidation += apicbp.validatecbp(hostnames=request.POST['hostnames'])["assetvalidation"]          #concatenate array not append 
            if (not ((ipaddresses is None) or (ipaddresses == ""))): assetvalidation += apicbp.validatecbp(ipaddresses=request.POST['ipaddresses'])["assetvalidation"]  #concatenate array not append
            context = { "assetvalidation": pandas.DataFrame(assetvalidation).to_html(header=False), "sectool": sectool, "dt": dt, "tm": timedelta(seconds=time.time()-tm) }
            request.session['csvdata'] = assetvalidation
        elif (sectool == 'cbc'):
            apicbc = ApiEngineCbc()
            assetvalidation.append(apicbc.GetHeader())
            if (not ((hostnames is None) or (hostnames == ""))): assetvalidation += apicbc.validatecbc(hostnames=request.POST['hostnames'])["assetvalidation"]          #concatenate array not append 
            if (not ((ipaddresses is None) or (ipaddresses == ""))): assetvalidation += apicbc.validatecbc(ipaddresses=request.POST['ipaddresses'])["assetvalidation"]  #concatenate array not append
            context = { "assetvalidation": pandas.DataFrame(assetvalidation).to_html(header=False), "sectool": sectool, "dt": dt, "tm": timedelta(seconds=time.time()-tm) }
            request.session['csvdata'] = assetvalidation
        elif (sectool == 'zs'):
            assetvalidation.append(["Zscaler"])
            context = { "assetvalidation": pandas.DataFrame(assetvalidation).to_html(header=False), "sectool": sectool, "dt": dt, "tm": timedelta(seconds=time.time()-tm) }
            request.session['csvdata'] = assetvalidation
        elif (sectool == 'bfx'):
            assetvalidation.append(["BigFix"])
            context = { "assetvalidation": pandas.DataFrame(assetvalidation).to_html(header=False), "sectool": sectool, "dt": dt, "tm": timedelta(seconds=time.time()-tm) }
            request.session['csvdata'] = assetvalidation
            
            
        return render(request, 'assetvalidation/home.html', context)
    else: #GET
        return render(request, 'assetvalidation/home.html', context)

@never_cache
def csvexport(request):
    sectool = request.session.get('sectool')
    dt = request.session.get('dt')
    csvdata = request.session.get('csvdata')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="asset-validation ('+sectool+') '+dt+'.csv"'
    writer = csv.writer(response)
    writer.writerows(csvdata)

    return response