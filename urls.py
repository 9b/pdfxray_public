from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from django.conf import settings

import os
admin.autodiscover()

handler404 = 'pdfxray.apps.core.views.handle_error'
handler500 = 'pdfxray.apps.core.views.handle_error'

urlpatterns = patterns('',
                       
    # accounts
    url(r'^login/$', 'pdfxray.apps.accounts.views.show_login'),
    url(r'^register/$', 'pdfxray.apps.accounts.views.show_register'),
    url(r'^process_login/$', 'pdfxray.apps.accounts.views.handle_login'),
    url(r'^process_register/$', 'pdfxray.apps.accounts.views.handle_register'),
    url(r'^my_account/$', 'pdfxray.apps.accounts.views.my_account_details'),
    url(r'^logout/$', 'pdfxray.apps.accounts.views.handle_logout'),    

    # admin
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', include(admin.site.urls)),
    
    # main nav pages
    url(r'^$', 'pdfxray.apps.core.views.main'),
    url(r'^submit/$', 'pdfxray.apps.core.views.upload_file_form'),
    url(r'^process/$', 'pdfxray.apps.core.views.process_file'),
    url(r'^about/$', 'pdfxray.apps.core.views.about'),
    url(r'^accounts/$', 'pdfxray.apps.core.views.accounts'),
    
    # reports
    url(r'^reports/$', 'pdfxray.apps.reports.views.last_fifty'),
    url(r'^malicious_reports/$', 'pdfxray.apps.reports.views.all_malicious'),
    url(r'^flag/$', 'pdfxray.apps.utilities.views.flag_data'),
    url(r'^compare_detail/$', 'pdfxray.apps.utilities.views.compare_detail'),

    # search    
    url(r'^search/$', 'pdfxray.apps.search.views.standard'),
    url(r'^process_search/$', 'pdfxray.apps.search.views.process_search'),
    
    #url(r'^statistics/$', 'pdfxray.apps.core.views.statistics'),

    # reporting
    url(r'^interact/(?P<rhash>\w+)/$', 'pdfxray.apps.core.views.interact', {'template_name': 'interact.html'}, name='interact'),   
    url(r'^report/(?P<rhash>\w+)/$', 'pdfxray.apps.core.views.interact', {'template_name': 'report.html'}, name='report'),
    
    # api
    url(r'^api/$', 'pdfxray.apps.api.views.main'),
    url(r'^api/submit/', 'pdfxray.apps.api.views.submit_file'),    
    url(r'^api/hash/(?P<rhash>\w+)/$', 'pdfxray.apps.api.views.get_full'),
    url(r'^api/hash/(?P<rhash>\w+)/object/(?P<robj>\w+)/$', 'pdfxray.apps.api.views.get_object'),
    url(r'^api/hash/(?P<rhash>\w+)/hash_data/$', 'pdfxray.apps.api.views.get_hash_data'),
    url(r'^api/hash/(?P<rhash>\w+)/structure/$', 'pdfxray.apps.api.views.get_structure'),
    url(r'^api/hash/(?P<rhash>\w+)/scans/$', 'pdfxray.apps.api.views.get_scans'),
    url(r'^api/hash/(?P<rhash>\w+)/contents/$', 'pdfxray.apps.api.views.get_contents'),
    url(r'^api/hash/(?P<rhash>\w+)/report/$', 'pdfxray.apps.api.views.get_report'),

	# admin tools
	url(r'^file_status/$', 'pdfxray.apps.flagger.views.get_status'),
	url(r'^flag_file/$', 'pdfxray.apps.flagger.views.flag_file'),
	url(r'^add_object_comment/$', 'pdfxray.apps.flagger.views.add_object_comment'),
	url(r'^get_object_comment/$', 'pdfxray.apps.flagger.views.get_object_comment'),
	url(r'^all_object_comments/$', 'pdfxray.apps.flagger.views.all_object_comments'),

    # flagger
    #url(r'^flagger/$', 'pdfxray.apps.flagger.views.snatch_data'),
    #url(r'^flag/$', 'pdfxray.apps.flagger.views.flag_data'),
    #url(r'^skip/$', 'pdfxray.apps.flagger.views.skip_data'),

    # peep test
    #url(r'^process/$', 'pdfxray.apps.peep.views.process_file'),    
    #url(r'^report/(?P<rhash>\w+)/$', 'pdfxray.apps.peep.views.interact', {'template_name': 'peep.html'}, name='peep'),
    
    # serve static files
    (r'^media/(?P<path>.*)$', 'django.views.static.serve',
        {'document_root': os.path.join(settings.BASE_DIR, 'media'),
         'show_indexes': False}),

)
