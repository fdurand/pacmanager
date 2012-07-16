from django.conf.urls.defaults import patterns, include, url
from django.conf import settings
# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

#urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'pacmanager.views.home', name='home'),
    # url(r'^pacmanager/', include('pacmanager.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
#)

urlpatterns = patterns('',
	(r'^/?$',                               'proxypac.views.logon'),
	(r'^logon/$',                             'proxypac.views.logon'),
	(r'^logout/$',                             'proxypac.views.disconnect'),
	(r'^network/$',                             'proxypac.views.network'),
	(r'^network/new/$',                             'proxypac.views.network_new'),
	(r'^network/del/(?P<nid>\d+)/$',                             'proxypac.views.network_del'),
	(r'^network/edit/(?P<nid>\d+)/$',                             'proxypac.views.network_edit'),
	(r'^network/rule/(?P<nid>\d+)/$',                             'proxypac.views.network_rule'),
	(r'^network/reset/$',                             'proxypac.views.network_reset_counters'),	
	(r'^(?P<ficpac>\w+).pac$',                             'proxypac.views.pac'),
	(r'^(?P<ficpac>\w+).PAC$',                             'proxypac.views.pac'),
	(r'^wpad.dat$',                             'proxypac.views.pac', {'ficpac': 'wpad.dat'}),
	(r'^test/$',                             'proxypac.views.test'),
	(r'^user/$',                             'proxypac.views.user_list'),
	(r'^user/new/$',                             'proxypac.views.edit_user', {'user_id': 'new'}),
	(r'^user/del/(?P<user_id>\w+[\.-]*\w+[\.-]*\w+)/$',                             'proxypac.views.del_user'),
	(r'^user/edit/(?P<user_id>\w+[\.-]*\w+[\.-]*\w+)/$',                             'proxypac.views.edit_user'),
	(r'^i18n/', include('django.conf.urls.i18n')),
	(r'^img/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.MEDIA_ROOT+"/img/",}),
	(r'^css/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.MEDIA_ROOT+"/css/",}),
	(r'^network/result/(?P<nid>\d+)/$',                             'proxypac.views.pac_result'),	
)
