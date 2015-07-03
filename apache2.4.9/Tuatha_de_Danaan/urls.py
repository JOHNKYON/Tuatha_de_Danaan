import os.path
from django.conf.urls import patterns, url, include
from choroi.views import *
from Tuatha_de_Danaan import settings
from django.views.generic import TemplateView

urlpatterns = patterns(
    '',
    # Examples:
    # url(r'^$', 'Tuatha_de_Danaan.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    (r'^square_page/(\d+)/$', square),
    (r'^login/$', login),
    (r'^user/(\w+)/$', user_page),
    (r'^login/$', 'django.contrib.auth.views.login'),
    (r'^logout/$', logout_page),
    (r'^register/$', register_page),
    (r'^upload/(\w+)/$', upload),
    (r'^(\w+)/image_delete/(\d+)/$', image_delete),
    (r'^media/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.MEDIA_ROOT, }),
    (r'^password_change/(\w+)/$', password_change),
    (r'^download_origin/(\d+)/$', download_origin),
    (r'^(\w+)/blacklist/insert/$', blacklist_insert),
    (r'^(\w+)/blacklist/delete/$', blacklist_delete),
    (r'^(\w+)/blacklist/show/$', show_blacklist),
    (r'^(\w+)/concern/insert/$', concern_insert),
    (r'^(\w+)/concern/delete/$', concern_delete),
    (r'^(\w+)/concern/show/$', show_concern),
    (r'^(\w+)/relation_page/$', relation_page),
    (r'^(\w+)/image_detail/$', image_detail),
    (r'^(\w+)/like_change/(\d+)/$', like_change),
    (r'^(\w+)/comment_insert/(\d+)/$', comment_insert),
    (r'^(\w+)/comment_delete/(\d+)/$', comment_delete),
    (r'^comment_show/(\d+)/page/(\d+)/$', comment_show),
    (r'^(\w+)/tag_insert/$', tag_insert),
    (r'^(\w+)/tag_delete/$', tag_delete),
    (r'^big_get/(\d+)/$', big_get),
    (r'^origin_get/(\d+)/$', origin_get),
    (r'^search/user/page/(\d+)/$', search_user),
    (r'^search/tag/page/(\d+)/$', search_by_tag),
    (r'^(\w+)/image_of/(\w+)/page/(\d+)/$', image_of),
    (r'^(\w+)/my_image/page/(\d+)/$', my_image),
    (r'^tag_show/(\d+)/$', tag_show),
    (r'^(\w+)/concerned_image/page/(\d+)/$', concerned_image),
    (r'^calculate/$', calculate),
)
