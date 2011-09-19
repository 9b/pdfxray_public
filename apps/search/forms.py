from django import forms

class SearchForm(forms.Form):
    hash = forms.CharField(max_length=200)
    
class vModelChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return "%s" % obj.name

class SearchOptions(forms.Form):
    data = ['one','two','three']
