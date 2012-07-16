from pacmanager.proxypac.models import *
from django import forms
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.db import connection

class Form_network(forms.Form):
	Type_Choices = (
		('8','/8'),
		('9','/9'),
		('10','/10'),
		('11','/11'),
		('12','/12'),
		('13','/13'),
		('14','/14'),
		('15','/15'),
		('16','/16'),
		('17','/17'),
		('18','/18'),
		('19','/19'),
		('20','/20'),
		('21','/21'),
		('22','/22'),
		('23','/23'),
		('24','/24'),
		('25','/25'),
		('26','/26'),
		('27','/27'),
		('28','/28'),
		('29','/29'),
		('30','/30'),
		('32','/32'),
		('64','/64'),
		)
	description = forms.CharField()
	address_ip = forms.CharField()
	mask =  forms.ChoiceField(choices=Type_Choices)
	parent = forms.ModelChoiceField(queryset = source.tree.all(),label=_('Referent'),required=False)

class Form_pac(forms.Form):
	script = forms.CharField(label=_('Pac script'),widget=forms.Textarea)
	
class Form_test(forms.Form):
	address_ip = forms.CharField(label=_('Address IP'))
	destination =  forms.CharField(label=_('Destination'))

class USERform(forms.Form):
	login = forms.CharField(label=_('Identifiant utilisateur'))
	password = forms.CharField(label=_('Mot de passe'),widget=forms.PasswordInput,required=False)
	email = forms.EmailField(label=_('Adresse email'))
	
class Form_result(forms.Form):
	script = forms.CharField(label=_('Result script'),widget=forms.Textarea)

class Form_stats(forms.Form):
	HTTP_ACCEPT = forms.CharField(label=_('HTTP_ACCEPT'))
	HTTP_ACCEPT_CHARSET = forms.CharField(label=_('HTTP_ACCEPT_CHARSET'))
	HTTP_ACCEPT_ENCODING = forms.CharField(label=_('HTTP_ACCEPT_ENCODING'))
	HTTP_ACCEPT_LANGUAGE = forms.CharField(label=_('HTTP_ACCEPT_LANGUAGE'))
	HTTP_CACHE_CONTROL = forms.CharField(label=_('HTTP_CACHE_CONTROL'))
	HTTP_CONNECTION = forms.CharField(label=_('HTTP_CONNECTION'))
	HTTP_COOKIE = forms.CharField(label=_('HTTP_COOKIE'))
	HTTP_HOST = forms.CharField(label=_('HTTP_HOST'))
	HTTP_USER_AGENT = forms.CharField(label=_('HTTP_USER_AGENT'))
	HTTP_VIA = forms.CharField(label=_('HTTP_VIA'))
	HTTP_X_FORWARDED_FOR = forms.CharField(label=_('HTTP_X_FORWARDED_FOR'))
	PATH_INFO = forms.CharField(label=_('PATH_INFO'))
	PATH_TRANSLATED = forms.CharField(label=_('PATH_TRANSLATED'))
	QUERY_STRING = forms.CharField(label=_('QUERY_STRING'))
	REMOTE_ADDR = forms.CharField(label=_('REMOTE_ADDR'))
	REMOTE_HOST = forms.CharField(label=_('REMOTE_HOST'))
	REMOTE_IDENT = forms.CharField(label=_('REMOTE_IDENT'))
	REMOTE_USER = forms.CharField(label=_('REMOTE_USER'))
	REQUEST_METHOD = forms.CharField(label=_('REQUEST_METHOD'))