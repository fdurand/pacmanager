from django.db import models
from django.contrib.auth.models import User
from mptt.models import MPTTModel, TreeForeignKey

class source(MPTTModel):
	address_ip = models.CharField(max_length=39)
	mask = models.CharField(max_length=3)
	description = models.CharField(max_length=40)
	parent = TreeForeignKey('self', null=True, blank=True, related_name='children')
	hits = models.CharField(max_length=9,default=0)
	class MPTTMeta:
		level_attr = 'mptt_level'
		order_insertion_by=['description']
	def __unicode__(self):
		return self.description


class rules(models.Model):
	ref_address_ip = models.ForeignKey(source)
	pac = models.CharField(max_length=3000)

class stats(models.Model):
	ref_address_ip = models.ForeignKey(source)
	HTTP_ACCEPT = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_ACCEPT_CHARSET = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_ACCEPT_ENCODING = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_ACCEPT_LANGUAGE = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_CACHE_CONTROL = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_CONNECTION = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_COOKIE = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_HOST = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_USER_AGENT = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_VIA = models.CharField(max_length = 100, null=True, blank=True)
	HTTP_X_FORWARDED_FOR = models.CharField(max_length = 100, null=True, blank=True)
	PATH_INFO = models.CharField(max_length = 100, null=True, blank=True)
	PATH_TRANSLATED = models.CharField(max_length = 100, null=True, blank=True)
	QUERY_STRING = models.CharField(max_length = 100, null=True, blank=True)
	REMOTE_ADDR = models.CharField(max_length = 100, null=True, blank=True)
	REMOTE_HOST = models.CharField(max_length = 100, null=True, blank=True)
	REMOTE_IDENT = models.CharField(max_length = 100, null=True, blank=True)
	REMOTE_USER = models.CharField(max_length = 100, null=True, blank=True)
	REQUEST_METHOD = models.CharField(max_length = 100, null=True, blank=True)
	timestamp = models.DateTimeField(auto_now_add=True)