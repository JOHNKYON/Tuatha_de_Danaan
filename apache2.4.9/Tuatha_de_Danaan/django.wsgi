import os
import sys
import django.core.handlers.wsgi
sys.path.append(r'G:/software_engineering')
os.environ['DJANGO_SETTINGS_MODULE'] = 'Tuatha_de_Danaan.settings'
application = django.core.handlers.wsgi.WSGIHandler()
