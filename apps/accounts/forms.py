from django import forms

class login_form(forms.Form):
	username = forms.CharField(max_length=100)
	password = forms.CharField(widget=forms.PasswordInput)

class register_form(forms.Form):
	username = forms.CharField(max_length=100)
	email = forms.EmailField()
	first = forms.CharField(max_length=50)
	last = forms.CharField(max_length=50)
	company = forms.CharField(max_length=100)
	password = forms.CharField(widget=forms.PasswordInput)
	confirm_password = forms.CharField(widget=forms.PasswordInput)
