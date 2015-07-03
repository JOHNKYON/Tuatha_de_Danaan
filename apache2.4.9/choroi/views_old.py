from django.http import HttpResponse, Http404
from django.core.context_processors import csrf
from django.shortcuts import render_to_response
from django.template import Context
from django.template.loader import get_template
from django.contrib.auth.models import User


def main_page(request):
	c = {}
	c.update(csrf(request))
	return render_to_response(
		'main_page.html',
		{'user'}
	)
	template = get_template('main_page.html')
	variables = Context({
		'user':request.user,
		'head_title': 'Django Bookmarks',
		'page_title': 'Welcome to Django Bookmarks',
		'page_body': 'Where you can store and share bookmarks!'
	})
	output = template.render(variables)
	return HttpResponse(output)
	return render_to_response('main_page.html', c)

def user_page(request, username):
	try:
		user = User.objects.get(username=username)
	except:
		raise Http404('Requested user not found.')
	bookmarks = user.bookmark_set.all()
	template = get_template('user_page.html')
	variables = Context({
		'username': username,
		'bookmarks': bookmarks
	})
	output = template.render(variables)
	return HttpResponse(output)
