#!/usr/bin/python
# -*- coding:utf-8 -*-
from django.core.exceptions import ObjectDoesNotExist, ImproperlyConfigured
from django.http import Http404, HttpResponse, HttpResponseRedirect, HttpRequest
from django.core.paginator import InvalidPage
from django.views.generic.list_detail import object_list
from django.contrib.auth import authenticate, login, logout
from django.template import loader, RequestContext
from django.utils.translation import gettext as _
from django.core.xheaders import populate_xheaders
from django.shortcuts import render_to_response
from django.core.context_processors import csrf
from django.utils.translation import gettext
from pacmanager.proxypac.models import *
from django import forms
from django.utils.html import escape
from django.db import connection
from django.conf import settings
from forms import *
from django.utils.encoding import *
from copy import copy
from netaddr.ip import smallest_matching_cidr, IPNetwork
import pacparser
import re
from django.core.mail import send_mail
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
import logging
import rrdtool

def logon(request):
	if request.user.is_authenticated():
		return HttpResponseRedirect("/network/")
	if request.POST:
		c = {}
		c.update(csrf(request))
		username = request.POST['username']
		password = request.POST['password']
		user = authenticate(username=username, password=password)
		if user is not None:
			if user.is_active:
				try:
					ipsource = request.META['HTTP_X_FORWARDED_FOR']
					ipsource = ipsource.split(",")[0]
				except:
					ipsource = request.META['REMOTE_ADDR']
				login(request, user)
				send_mail('User connexion', username+" "+ipsource, 'admin@admin.net',['admin@admin.net'], fail_silently=False)
				return HttpResponseRedirect("/network/")
			else:
				return render_to_response('logon.html',context_instance=RequestContext(request))
		return render_to_response('logon.html',context_instance=RequestContext(request))
	else:
		return render_to_response('logon.html',context_instance=RequestContext(request))

def disconnect(request):
	c = {}
	c.update(csrf(request)) 
	logout(request)
	return HttpResponseRedirect("/logon/")

def network(request):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	network = source.objects.all()
	return render_to_response("network.html",{'nodes':source.tree.all(),'network':network,},context_instance=RequestContext(request))

def network_reset_counters(request):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	networks = source.objects.all()
	stats.objects.all().delete()
	for network in networks:
		network.hits = 0
		network.save()
	vacuum_db()
	return HttpResponseRedirect("/network/")

def vacuum_db():
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("VACUUM")
    connection.close()
	
def network_new(request):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	if request.POST:
		c = {}
		c.update(csrf(request))
		form = Form_network(request.POST)
		if form.is_valid():
			try:
				IPNetwork(str(form.cleaned_data['address_ip'])+"/"+str(form.cleaned_data['mask']))
			except UnboundLocalError:
				error = "Invalid address"
				return render_to_response('network_new.html', {'form': form,'error':error},context_instance=RequestContext(request))
			try:
				source.objects.get(address_ip = form.cleaned_data['address_ip'],mask = form.cleaned_data['mask'],)
				error = "Object already exist"
				return render_to_response('network_new.html', locals(),context_instance=RequestContext(request))
			except ObjectDoesNotExist:
				sourceip = source(description = form.cleaned_data['description'], address_ip = form.cleaned_data['address_ip'], mask = form.cleaned_data['mask'], parent = form.cleaned_data['parent'])
				sourceip.save()
		else:
			return render_to_response('network_new.html', {'form': form,},context_instance=RequestContext(request))
		return HttpResponseRedirect("/network/rule/"+str(sourceip.id)+"/")
	else:
		action = "Add"
		form = Form_network(request.POST)
		network = source.objects.all()
		return render_to_response('network_new.html', locals(),context_instance=RequestContext(request))

def network_del(request,nid):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	network = source.objects.get(id=nid)
	try:
		rulepac = rules.objects.get(ref_address_ip = network)
		rulepac.delete()
	except ObjectDoesNotExist:
		pass
	network.delete()
	return HttpResponseRedirect("/network/")

def network_edit(request,nid):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	action = "Edit"
	if request.POST:
		c = {}
		c.update(csrf(request))
		form = Form_network(request.POST)
		if form.is_valid():
			try:
				IPNetwork(str(form.cleaned_data['address_ip'])+"/"+str(form.cleaned_data['mask']))
			except UnboundLocalError:
				error = "Invalid address"
				return render_to_response('network_new.html', {'form': form,'error':error},context_instance=RequestContext(request))
			sourceip = source.objects.get(id = nid)
			sourceip.description = form.cleaned_data['description']
			sourceip.address_ip = form.cleaned_data['address_ip']
			sourceip.mask = form.cleaned_data['mask']
			sourceip.parent = form.cleaned_data['parent']
			try:
				sourceip.save()
			except:
				error = "Problem with child and parent"
				return render_to_response('network_new.html', {'form': form,'error':error},context_instance=RequestContext(request))
		else:
			return render_to_response('network_new.html', {'form': form,},context_instance=RequestContext(request))
		return HttpResponseRedirect("/network/")
	else:	
		network = source.objects.get(id=nid)
		form = Form_network(initial={'description': network.description,'address_ip': network.address_ip,'mask' : network.mask, 'parent' : network.parent,})
		return render_to_response('network_new.html', locals(),context_instance=RequestContext(request))

def network_rule(request,nid):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	if request.POST:
		c = {}
		c.update(csrf(request))
		form = Form_pac(request.POST)
		requette_test = "function FindProxyForURL(url, host){if(1){}"
		if form.is_valid():
			network = source.objects.get(id=nid)
			p = re.compile('[\r\n\t]+')
			requette = p.sub( "", form.cleaned_data['script'])
			p = re.compile('[\s]')
			requette = p.sub( " ", requette)
			requette_test += requette +"}"
			pacparser.init()
			try:
				pacparser.parse_pac_string(str(requette_test))
			except:
				parse = "Pac syntax error"
				return render_to_response('pac_new.html', locals(),context_instance=RequestContext(request))
			pacparser.cleanup()
			try:
				rulepac = rules.objects.get(ref_address_ip = network)
				rulepac.pac = form.cleaned_data['script']
			except ObjectDoesNotExist:
				rulepac = rules(ref_address_ip = network, pac = form.cleaned_data['script'])
			rulepac.save()
		else:
			return render_to_response('pac_new.html', locals(),context_instance=RequestContext(request))
		return HttpResponseRedirect("/network/")
	else:
		pac = "function FindProxyForURL(url, host){\n"
		try:
			network = source.objects.get(id=nid)
			rulepac = rules.objects.get(ref_address_ip = network)
			form = Form_pac(initial={'script': rulepac.pac})
			action = "Edit"
			try:
				tree = network.get_ancestors(include_self=True,ascending=True)
				for networks in tree:
					rulepac = rules.objects.get(ref_address_ip = networks)
					pac += rulepac.pac +"\n"
				pac += "}"
			except:
				pass
			pacparser.init()
			try:
				pacparser.parse_pac_string(str(pac))
				parse_global = "Pac syntax seems to be ok"
			except:
				parse_global = "Pac syntax error"
			pacparser.cleanup()
			pac2 = "<code>"
			pac2 += pac
			form2 = Form_result(initial={'script': pac})
		except ObjectDoesNotExist:
			form = Form_pac()
			action = "Add"
		return render_to_response('pac_new.html', locals(),context_instance=RequestContext(request))


def pac(request,ficpac):
	networks = source.objects.all()
	network =[]
	try:
		ipsource = request.META['HTTP_X_FORWARDED_FOR']
		ipsource = ipsource.split(",")[0]
	except:
		ipsource = request.META['REMOTE_ADDR']
	network_save = 0
	count = 0
	pac = "function FindProxyForURL(url, host){\n"
	for network in networks:
		cidr = [str(network.address_ip) +"/"+ str(network.mask)]
		match = smallest_matching_cidr(ipsource,cidr)
		if match:
			try:
				if (int(str(network.mask)) > int(str(network_save.mask))):
					network_save = network
					del match
			except AttributeError:
				network_save = network
				del match
	try:
		tree = network_save.get_ancestors(include_self=True,ascending=True)
		for network_node in tree:
			rulepac = rules.objects.get(ref_address_ip = network_node)
			pac += rulepac.pac +"\n"
		pac += "}"
	except AttributeError:
		if (IPNetwork(str(ipsource)).version == 6):
			network_save = source.objects.get(address_ip='fe80::')
		else:
			network_save = source.objects.get(address_ip='0.0.0.0')
		rulepac = rules.objects.get(ref_address_ip = network_save)
		pac += rulepac.pac +"\n"
		pac += "}"
	count = network_save.hits
	count = int(count) + 1
	network_save.hits = count
	network_save.save()
	try :
		ref_HTTP_ACCEPT = request.META['HTTP_ACCEPT']
	except:
		ref_HTTP_ACCEPT = "None"
	try:
		ref_HTTP_ACCEPT_CHARSET = request.META['HTTP_ACCEPT_CHARSET']
	except:
		ref_HTTP_ACCEPT_CHARSET = "None"
	try:
		ref_HTTP_ACCEPT_ENCODING = request.META['HTTP_ACCEPT_ENCODING']
	except:
		ref_HTTP_ACCEPT_ENCODING = "None"
	try:
		ref_REQUEST_METHOD = request.META['REQUEST_METHOD']
	except:
		ref_REQUEST_METHOD = "None"
	try:
		ref_REMOTE_USER = request.META['REMOTE_USER']
	except:
		ref_REMOTE_USER = "None"
	try:
		ref_REMOTE_IDENT = request.META['REMOTE_IDENT']
	except:
		ref_REMOTE_IDENT = "None"
	try:
		ref_REMOTE_HOST = request.META['REMOTE_HOST']
	except:
		ref_REMOTE_HOST = "None"
	try:
		ref_REMOTE_ADDR = request.META['REMOTE_ADDR']
	except:
		ref_REMOTE_ADDR = "None"
	try:
		ref_QUERY_STRING = request.META['QUERY_STRING']
	except:
		ref_QUERY_STRING = "None"
	try:
		ref_PATH_TRANSLATED = request.META['PATH_TRANSLATED']
	except:
		ref_PATH_TRANSLATED = "None"
	try:
		ref_PATH_INFO = request.META['PATH_INFO']
	except:
		ref_PATH_INFO = "None"
	try:
		ref_HTTP_X_FORWARDED_FOR = request.META['HTTP_X_FORWARDED_FOR']
	except:
		ref_HTTP_X_FORWARDED_FOR = "None"
	try:
		ref_HTTP_VIA = request.META['HTTP_VIA']
	except:
		ref_HTTP_VIA = "None"
	try:
		ref_HTTP_USER_AGENT = request.META['HTTP_USER_AGENT']
	except:
		ref_HTTP_USER_AGENT = "None"
	try:
		ref_HTTP_HOST = request.META['HTTP_HOST']
	except:
		ref_HTTP_HOST = "None"
	try:
		ref_HTTP_COOKIE = request.META['HTTP_COOKIE']
	except:
		ref_HTTP_COOKIE = "None"
	try:
		ref_HTTP_CONNECTION = request.META['HTTP_CONNECTION']
	except:
		ref_HTTP_CONNECTION = "None"
	try:
		ref_HTTP_CACHE_CONTROL = request.META['HTTP_CACHE_CONTROL']
	except:
		ref_HTTP_CACHE_CONTROL = "None"
	try:
		ref_HTTP_ACCEPT_LANGUAGE = request.META['HTTP_ACCEPT_LANGUAGE']
	except:
		ref_HTTP_ACCEPT_LANGUAGE = "None"
#	statistiques = stats(ref_address_ip = network_save , HTTP_ACCEPT = ref_HTTP_ACCEPT , HTTP_ACCEPT_CHARSET = ref_HTTP_ACCEPT_CHARSET , HTTP_ACCEPT_ENCODING = ref_HTTP_ACCEPT_ENCODING , HTTP_ACCEPT_LANGUAGE = ref_HTTP_ACCEPT_LANGUAGE , HTTP_CACHE_CONTROL = ref_HTTP_CACHE_CONTROL , HTTP_CONNECTION = ref_HTTP_CONNECTION , HTTP_COOKIE = ref_HTTP_COOKIE , HTTP_HOST = ref_HTTP_HOST , HTTP_USER_AGENT = ref_HTTP_USER_AGENT , HTTP_VIA = ref_HTTP_VIA , HTTP_X_FORWARDED_FOR = ref_HTTP_X_FORWARDED_FOR , PATH_INFO = ref_PATH_INFO , PATH_TRANSLATED = ref_PATH_TRANSLATED , QUERY_STRING = ref_QUERY_STRING , REMOTE_ADDR = ref_REMOTE_ADDR , REMOTE_HOST = ref_REMOTE_HOST , REMOTE_IDENT = ref_REMOTE_IDENT , REMOTE_USER = ref_REMOTE_USER , REQUEST_METHOD = ref_REQUEST_METHOD)
#	statistiques.save()
	fichier = settings.RRD_ROOT+network_save.address_ip+".rrd"
	try:
		openfile = open(str(fichier), 'r')
		openfile.close()
	except:
		ret = rrdtool.create(str(fichier), "--step", "60", "--start", '0', "DS:input:COUNTER:120:U:U", "RRA:AVERAGE:0.5:1:120", "RRA:AVERAGE:0.5:5:288", "RRA:AVERAGE:0.5:30:336", "RRA:AVERAGE:0.5:30:1488", "RRA:MAX:0.5:1:120", "RRA:MAX:0.5:5:288", "RRA:MAX:0.5:30:336", "RRA:MAX:0.5:30:1488")
	try:
		ret = rrdtool.update(str(fichier),'N:' + `int(network_save.hits)`);
	except:
		pass
	return HttpResponse(pac, mimetype="application/x-ns-proxy-autoconfig")


def test(request):
	if not request.user.is_authenticated():
		return HttpResponseRedirect("/logon/")
	if request.POST:
		c = {}
		c.update(csrf(request))
		pac = "function FindProxyForURL(url, host){\n"
		form = Form_test(request.POST)
		if form.is_valid():
			networks = source.objects.all()
			network =[]
			ipsource = form.cleaned_data['address_ip']
			destination = form.cleaned_data['destination']
			network_save = 0
			match2 =[]
			cidr2 =[]
			for network in networks:
				cidr = [str(network.address_ip) +"/"+ str(network.mask)]
				match = smallest_matching_cidr(ipsource,cidr)
				match2.append(match)
				cidr2.append(cidr)
				if match:
					try:
						if ((int(str(network.mask))) > (int(str(network_save.mask)))):
							network_save = network
							del match
					except AttributeError:
						network_save = network
						del match
			try:
				tree = network_save.get_ancestors(include_self=True,ascending=True)
				for network_node in tree:
					rulepac = rules.objects.get(ref_address_ip = network_node)
					pac += rulepac.pac +"\n"
				pac += "}"
				p = re.compile('[\r\n\t]+')
				requette = p.sub( "", pac)
				p = re.compile('[\s]')
				requette = p.sub( " ", requette)
			except AttributeError:
				if (IPNetwork(str(ipsource)).version == 6):
					network_save = source.objects.get(address_ip='fe80::')
				else:
					network_save = source.objects.get(address_ip='0.0.0.0')
				rulepac = rules.objects.get(ref_address_ip = network_save)
				pac += rulepac.pac +"\n"
				pac += "}"
				p = re.compile('[\r\n\t]+')
				requette = p.sub( "", pac)
				p = re.compile('[\s]')
				requette = p.sub( " ", requette)
			pacparser.init()
			parse = pacparser.parse_pac_string(str(requette))
			proxy = pacparser.find_proxy(str(destination))
			pacparser.cleanup()
			return render_to_response('test.html', locals(),context_instance=RequestContext(request))
		else:
			return render_to_response('test.html', {'form': form,},context_instance=RequestContext(request))
	else:
		form = Form_test()
		return render_to_response('test.html', {'form': form,},context_instance=RequestContext(request))

def user_list(request):
	if not request.user.is_authenticated():
		return HttpResponseRedirect('/logon/')
	user_list = User.objects.all()
	return render_to_response('user_list.html', {'user_list': user_list,},context_instance=RequestContext(request))

def edit_user(request,user_id):
	if not request.user.is_authenticated():
		return HttpResponseRedirect('/logon/')
	if request.method == 'POST':
		form = USERform(request.POST)
		if form.is_valid():
			if user_id == 'new':
				user = User.objects.create_user(str(form.cleaned_data['login']), str(form.cleaned_data['email']), str(form.cleaned_data['password']))
				user.is_staff = True
			else:
				user = User.objects.get(username=user_id)
				user.username=str(form.cleaned_data['login'])
				user.email=str(form.cleaned_data['email'])
				user.is_staff = True
				if str(form.cleaned_data['password']):
					user.set_password(str(form.cleaned_data['password']))
			user.save()
			return HttpResponseRedirect('/user/')
		return render_to_response('user_edit.html', {'form': form,},context_instance=RequestContext(request))
	else:
		if user_id == 'new':
			form = USERform()
			return render_to_response('user_edit.html', {'form': form,},context_instance=RequestContext(request))
		user = User.objects.get(username=user_id)
		form = USERform(initial={'login': user.username, 'email': user.email, })
		return render_to_response('user_edit.html', {'form': form,},context_instance=RequestContext(request))
		
def del_user(request,user_id):
	user = User.objects.get(username=user_id)
	if user.is_superuser:
		return HttpResponseRedirect('/user/')
	else:
		user.delete()
		return HttpResponseRedirect('/user/')

def pac_result(request,nid):
	pac = "<code>function FindProxyForURL(url, host){\n"
	network = source.objects.get(id=nid)
	rulepac = rules.objects.get(ref_address_ip = network)
	statistiques = stats.objects.filter(ref_address_ip = network).order_by('id').reverse()[:20]
	form = []
	form3 = Form_stats()
	for statis in statistiques:
		form.append(Form_stats(initial={'HTTP_ACCEPT' : statis.HTTP_ACCEPT , 'HTTP_ACCEPT_CHARSET' : statis.HTTP_ACCEPT_CHARSET , 'HTTP_ACCEPT_ENCODING' : statis.HTTP_ACCEPT_ENCODING , 'HTTP_ACCEPT_LANGUAGE' : statis.HTTP_ACCEPT_LANGUAGE , 'HTTP_CACHE_CONTROL' : statis.HTTP_CACHE_CONTROL , 'HTTP_CONNECTION' : statis.HTTP_CONNECTION , 'HTTP_COOKIE' : statis.HTTP_COOKIE , 'HTTP_HOST' : statis.HTTP_HOST , 'HTTP_USER_AGENT' : statis.HTTP_USER_AGENT , 'HTTP_VIA' : statis.HTTP_VIA , 'HTTP_X_FORWARDED_FOR' : statis.HTTP_X_FORWARDED_FOR , 'PATH_INFO' : statis.PATH_INFO , 'PATH_TRANSLATED' : statis.PATH_TRANSLATED , 'QUERY_STRING' : statis.QUERY_STRING , 'REMOTE_ADDR' : statis.REMOTE_ADDR , 'REMOTE_HOST' : statis.REMOTE_HOST , 'REMOTE_IDENT' : statis.REMOTE_IDENT , 'REMOTE_USER' : statis.REMOTE_USER , 'REQUEST_METHOD' : statis.REQUEST_METHOD}))
	try:
		tree = network.get_ancestors(include_self=True,ascending=True)
		for networks in tree:
			rulepac = rules.objects.get(ref_address_ip = networks)
			pac += rulepac.pac +"\n"
		pac += "}"
	except:
		pass
	pacparser.init()
	try:
		pacparser.parse_pac_string(str(pac))
		parse_global = "Pac syntax seems to be ok"
	except:
		parse_global = "Pac syntax error"
	pacparser.cleanup()
	fichier = settings.RRD_ROOT+network.address_ip+".rrd"
	png = settings.MEDIA_ROOT+"img/rrd/"+network.address_ip+".png"
	try:
		openfile = open(str(fichier), 'r')
		openfile.close()
	except:
		ret = rrdtool.create(str(fichier), "--step", "60", "--start", '0', "DS:input:COUNTER:120:U:U", "RRA:AVERAGE:0.5:1:120", "RRA:AVERAGE:0.5:5:288", "RRA:AVERAGE:0.5:30:336", "RRA:AVERAGE:0.5:30:1488", "RRA:MAX:0.5:1:120", "RRA:MAX:0.5:5:288", "RRA:MAX:0.5:30:336", "RRA:MAX:0.5:30:1488")
	ret = rrdtool.graph( str(png), "--start", "-2hour", "--vertical-label=Access/s", "DEF:inoctets="+str(fichier)+":input:AVERAGE", "AREA:inoctets#FF0000:In access", "COMMENT:\\n", "GPRINT:inoctets:AVERAGE:Avg In access\: %6.2lf %S access", "COMMENT:  ", "GPRINT:inoctets:MAX:Max In access\: %6.2lf %S access\\r")
	return render_to_response('pac_result.html', locals(),context_instance=RequestContext(request))
