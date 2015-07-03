from django.http import HttpResponse
def main_page(request):
	output = '''
	<html>
		<head><title>%s</title>
		</head>
		<body>
			<h1>%s</h1><p>%s</p>
		</body>
	</html>
	''' % (
	'Tuatha_de_Danaan',
	'Welcome to Tuatha_de_Danaan',
	'Where you can store and share photos!'
	)
	return HttpResponseRedirect('/register/success/')
