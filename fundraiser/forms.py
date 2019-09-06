from django import forms

from django.utils.translation import gettext_lazy as _

from django.contrib.auth.forms  import UserCreationForm

from fundraiser.models import *



class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss577 jss562", "id":"log_email"}))
    password = forms.CharField(strip=False,widget=forms.PasswordInput(attrs={"aria-invalid":"false", "autocomplete":"current-password", "class":"jss577 jss562 jss580 jss565", "id":"log_pass" }))
    

class UserSignupForm(UserCreationForm):
    class Meta:
        model = User
        fields = {
            'email',
            'password1',
            'name',
            'is_indian',
            'mobile_no',
            'i_agree',
            }


        widgets = {
            'email' :forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss860 jss845", "id":"reg_email"}),
            'name' :forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"reg_name"}),
            'mobile_no':forms.TextInput(attrs={"type":"tel", "id":"mobile-number", "placeholder":"e.g. +1 702 123 4567"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        del self.fields['password2']


class AdminUserSignupForm(UserCreationForm):
    class Meta:
        model = User
        fields = {
            'email',
            'password1',
            'name',
            'is_indian',
            'mobile_no',
            'i_agree',
            'user_type',
            'address',
            'pincode',
            'facebook',
            'twitter',
            'profile',
            }


        widgets = {
            'email' :forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss860 jss845", "id":"reg_email"}),
            'name' :forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"reg_name"}),
            'mobile_no':forms.TextInput(attrs={"type":"tel", "id":"mobile-number", "placeholder":"e.g. +1 702 123 4567"}),
            'user_type':forms.Select(attrs={"class":"select2_modal"}),
            'i_agree' : forms.CheckboxInput(attrs={"class":"jss885",  "id":"termsCheck_box", "required":"required"}),
            'is_indian': forms.CheckboxInput(attrs={"class":"jss885", "id":"user_citizen_id"}),
            'address':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_address_user"}),
            'pincode':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845 integer_value", "id":"id_pincode_user"}),
            'facebook':forms.URLInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_facebook"}),
            'twitter':forms.URLInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_twitter"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        del self.fields['password2']
        


class AdminUserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = {
            'name',
            'email',
            'user_type',
            'mobile_no',
            'is_indian',
            'address',
            'pincode',
            'facebook',
            'twitter',
            'profile',
        }

        widgets = {
            'email' :forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss860 jss845", "id":"reg_email"}),
            'name' :forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"reg_name"}),
            'mobile_no':forms.TextInput(attrs={"type":"tel", "id":"mobile-number", "placeholder":"e.g. +1 702 123 4567"}),
            'user_type':forms.Select(attrs={"class":"select2"}),
            'is_indian': forms.CheckboxInput(attrs={"class":"jss885", "id":"user_citizen_id"}),
            'address':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_address_user"}),
            'pincode':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845 integer_value", "id":"id_pincode_user"}),
            'facebook':forms.URLInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_facebook"}),
            'twitter':forms.URLInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_twitter"}),
        }


class MyUserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = {
            'name',
            'email',
            'mobile_no',
            'is_indian',
            'address',
            'pincode',
            'facebook',
            'twitter',
            'profile',
        }

        widgets = {
            'email' :forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss860 jss845", "id":"reg_email_user"}),
            'name' :forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"reg_name_user"}),
            'mobile_no':forms.TextInput(attrs={"type":"tel", "class":"mobile-number-2 , integer_value", "id":"mobile-number-2", "placeholder":"e.g. +1 702 123 4567"}),
            'is_indian':forms.CheckboxInput(attrs={"class":"jss885", "id":"user_citizen_id"}),
            'address':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_address_user"}),
            'pincode':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845 integer_value", "id":"id_pincode_user"}),
            'facebook':forms.URLInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_facebook"}),
            'twitter':forms.URLInput(attrs={"aria-invalid":"false", "class":"jss860 jss845", "id":"id_twitter"}),
        }




class BeneficiaryForm(forms.ModelForm):
    class Meta:
        model = Beneficiary
        fields = {
            'name',
            'email',
            'mobile_no',
            'bank_account',
            'account_holder',
            'ifsc',
            'primary_address',
            'secondry_address',
            'pincode',
            'state',
            'city',
            'pan_card_no'
        }

        widgets = {
            'name' :forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'email' :forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss860 jss845", "id":"reg_email"}),
            'mobile_no':forms.TextInput(attrs={"type":"tel", "id":"mobile-number", "placeholder":"e.g. +1 702 123 4567"}),
            'bank_account':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'account_holder':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'ifsc':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'primary_address':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'secondry_address':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'pincode':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845 integer_value"}),
            'state':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'city':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'pan_card_no':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
        }

class GenericEmailsForm(forms.ModelForm):
    class Meta:
        model = GenericEmails
        fields = {
            'name',
            'departments',
            'email',
            'role',
        }
        widgets = {
            'name':forms.TextInput(attrs={"aria-invalid":"false", "class":"jss860 jss845"}),
            'departments':forms.Select(attrs={"class":"select2 select2_modal"}),
            'email' :forms.EmailInput(attrs={"aria-invalid":"false", "autocomplete":"email", "class":"jss860 jss845", "id":"reg_email"}),
            'role':forms.Select(attrs={"class":"select2 select2_modal"}),
        }


class ServicesEnquiryForm(forms.ModelForm):
    class Meta:
        model = ServicesEnquiry
        fields = (
            'name',
            'email',
            'mobile_no',
            'message'
        )

        widgets = {
            'name':forms.TextInput(attrs={"class":"jss860 jss845", "aria-invalid":"false"}),
            'email':forms.EmailInput(attrs={"class":"jss860 jss845", "aria-invalid":"false"}),
            'mobile_no':forms.TextInput(attrs={"type":"tel", "class":"mobile-number-2", "id":"mobile-number-2", "placeholder":"e.g. +1 702 123 4567"}),
            'message':forms.TextInput(attrs={"class":"jss860 jss845", "aria-invalid":"false"}),
        }



class CampaignFundRaiserForm(forms.ModelForm):
    
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "title",
            "category",
            "goal",
            "day",
            "short_description",
            "about",
            "picture",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'category' :forms.Select(attrs={"class":"select2"}),
            'goal' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
            'day' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
            'short_description':forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
        }

    def __init__(self, *args, **kwargs):
        super(CampaignFundRaiserForm, self).__init__(*args, **kwargs)
        self.fields['category']=forms.ModelChoiceField(queryset=CampaignCategory.objects.filter(is_active=True), widget=forms.Select(attrs={"class":"select2"}))


class CampaignFundRaiser_Goal_Form(forms.ModelForm):
    
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "goal",
        )

        widgets = {
            'goal' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
        }

class CampaignFundRaiser_Title_Form(forms.ModelForm):
    
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "title",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }

class CampaignFundRaiser_Picture_Form(forms.ModelForm):
    
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "picture",
        )

        widgets = {
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1", "id":"id_picture", "data-multiple-caption":"{count} files selected"}),
        }

class CampaignFundRaiser_About_Form(forms.ModelForm):
    
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "about",
        )

        widgets = {
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }

class CampaignFundRaiser_Day(forms.ModelForm):

    class Meta:
        model = CampaignFundRaiser
        fields = (
            "day",
        )

        widgets = {
            'day' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
        }

class CampaignFundRaiser_Short_Description(forms.ModelForm):
    
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "short_description",
        )

        widgets = {
            'short_description' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }




class AdminCampaignFundRaiserForm(forms.ModelForm):
    is_active = forms.TypedChoiceField(coerce=lambda x: x == 'True',choices=((False, 'No'), (True, 'Yes')),widget=forms.RadioSelect)

    class Meta:
        model = CampaignFundRaiser
        fields = (
            "title",
            "category",
            "goal",
            "day",
            "short_description",
            "about",
            "picture",
            "cause",
            "sensitivity",
            "is_active",
            "commission",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'goal' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
            'day' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
            'short_description':forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            'cause':forms.Select(attrs={"class":"select2", "id":"select_cause"}),
            'sensitivity':forms.Select(attrs={"class":"select2", "id":"select_sensitivity"}),
            'commission' :forms.NumberInput(attrs={"class":"jss577 jss562", "step":"any"}),
        }

    def __init__(self, *args, **kwargs):
        super(AdminCampaignFundRaiserForm, self).__init__(*args, **kwargs)
        self.fields['category']=forms.ModelChoiceField(queryset=CampaignCategory.objects.filter(is_active=True), widget=forms.Select(attrs={"class":"select2", "id":"select_category"}))



class SupportGroupForm(forms.ModelForm):
    
    class Meta:
        model = SupportGroup
        fields = (
            "title",
            "goal",
            "short_description",
            "about",
            "picture",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'goal' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
            'short_description':forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
        }


class SupportGroupGoalForm(forms.ModelForm):
    
    class Meta:
        model = SupportGroup
        fields = (
            "goal",
        )

        widgets = {
            'goal' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
        }

class SupportGroupShortDescriptionForm(forms.ModelForm):

    class Meta:
        model = SupportGroup
        fields = (
            "short_description",
        )

        widgets = {
            'short_description' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }

class SupportGroupTitleForm(forms.ModelForm):
    
    class Meta:
        model = SupportGroup
        fields = (
            "title",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }

class SupportGroupPictureForm(forms.ModelForm):
    
    class Meta:
        model = SupportGroup
        fields = (
            "picture",
        )

        widgets = {
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1", "id":"id_picture", "data-multiple-caption":"{count} files selected"}),
        }

class SupportGroupAboutForm(forms.ModelForm):
    
    class Meta:
        model = SupportGroup
        fields = (
            "about",
        )

        widgets = {
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }


class AdminSupportGroupForm(forms.ModelForm):
    is_active = forms.TypedChoiceField(coerce=lambda x: x == 'True',choices=((False, 'No'), (True, 'Yes')),widget=forms.RadioSelect)
    class Meta:
        model = SupportGroup
        fields = (
            "title",
            "goal",
            "short_description",
            "about",
            "picture",
            "cause",
            "sensitivity",
            "is_active"
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'goal' :forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}),
            'short_description':forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            'cause':forms.Select(attrs={"class":"select2", "id":"select_cause"}),
            'sensitivity':forms.Select(attrs={"class":"select2", "id":"select_sensitivity"}),
        }


class EventForm(forms.ModelForm):
    class Meta:
        model = Event
        fields = (
            "name",
            "about",
            "place",
            "date",
            "ticket",
            "image",
        )

        widgets = {
            "name" :forms.TextInput(attrs={"class":"jss577 jss562"}),
            "about" :forms.Textarea(attrs={"class":"jss577 jss562"}),
            "place" :forms.TextInput(attrs={"class":"jss577 jss562"}),
            "date" :forms.TextInput(attrs={"class":"jss577 jss562", "autocomplete":"off", "id":'datetimepicker1'}),
            "ticket" :forms.TextInput(attrs={"class":"jss577 jss562"}),
            "image" :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
        }


class AdminEventForm(forms.ModelForm):
    is_active = forms.TypedChoiceField(coerce=lambda x: x == 'True',choices=((False, 'No'), (True, 'Yes')),widget=forms.RadioSelect)
    class Meta:
        model = Event
        fields = (
            "name",
            "about",
            "place",
            "date",
            "ticket",
            "image",
            "cause",
            "sensitivity",
            "is_active",
        )

        widgets = {
            "name" :forms.TextInput(attrs={"class":"jss577 jss562"}),
            "about" :forms.Textarea(attrs={"class":"jss577 jss562"}),
            "place" :forms.TextInput(attrs={"class":"jss577 jss562"}),
            "date" :forms.TextInput(attrs={"class":"jss577 jss562", "autocomplete":"off", "id":'datetimepicker1'}),
            "ticket" :forms.TextInput(attrs={"class":"jss577 jss562"}),
            "image" :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            "cause" :forms.Select(attrs={"class":"select2", "id":"select_cause"}),
            "sensitivity" :forms.Select(attrs={"class":"select2", "id":"select_sensitivity"}),
        }



class CrowdNewsingForm(forms.ModelForm):
    class Meta:
        model = CrowdNewsing
        fields = (
            "profile",
            "name",
            "designation",
            "about_crowd_newsing",
        )

        widgets = {
            'name' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'designation' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about_crowd_newsing' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }



class CampaignCategoryForm(forms.ModelForm):
    class Meta:
        model = CampaignCategory
        fields = (
            "category",
            # "image",
            # "description",
        )

        widgets = {
            'category' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            # "description" :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }


class CauseCategoryForm(forms.ModelForm):
    class Meta:
        model = CauseCategory
        fields = (
            "cause",
            "description",
        )

        widgets = {
            'cause' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'description' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }



class MediaArticalForm(forms.ModelForm):
    
    class Meta:
        model = MediaArtical
        fields = (
            "title",
            "picture",
            "publisher",
            "link",
            "short_text"
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'picture' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            'publisher':forms.TextInput(attrs={"class":"jss577 jss562"}),
            'link' :forms.URLInput(attrs={"class":"jss577 jss562" , "id":"id_article_link"}),
            'short_text' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }


class CampaignUpdatesForm(forms.ModelForm):
    class Meta:
        model = CampaignUpdates
        fields = (
            "title",
            "about",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }


class SupportUpdatesForm(forms.ModelForm):
    class Meta:
        model = SupportUpdates
        fields = (
            "title",
            "about",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }


class CampaignBuzzForm(forms.ModelForm):
    class Meta:
        model = CampaignBuzz
        fields = (
            "title",
            "buzz",
            "article_link",
            "picture",
            "publisher",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'buzz' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'article_link' : forms.URLInput(attrs={"class":"jss577 jss562"}),
            "picture":forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            "publisher":forms.TextInput(attrs={"class":"jss577 jss562"}),
        }


class SupportBuzzForm(forms.ModelForm):
    class Meta:
        model = SupportBuzz
        fields = (
            "title",
            "buzz",
            "article_link",
            "picture",
            "publisher",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'buzz' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'article_link' : forms.URLInput(attrs={"class":"jss577 jss562"}),
            "picture":forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            "publisher":forms.TextInput(attrs={"class":"jss577 jss562"}),
        }

class CampaignCommentsForm(forms.ModelForm):
    class Meta:
        model = CampaignComments
        fields = (
            "comment",
        )

        widgets = {
            'comment' :forms.Textarea(attrs={"class":"CDCommentNewText", "rows":"0"}),
        }


class SupportCommentsForm(forms.ModelForm):
    class Meta:
        model = SupportComments
        fields = (
            "comment",
        )

        widgets = {
            'comment' :forms.Textarea(attrs={"class":"CDCommentNewText", "rows":"0"}),
        }


class EventCommentsForm(forms.ModelForm):
    class Meta:
        model = EventComments
        fields = (
            "comment",
        )

        widgets = {
            'comment' :forms.Textarea(attrs={"class":"CDCommentNewText", "rows":"0"}),
        }


class CampaignDonersForms(forms.ModelForm):
    class Meta:
        model = CampaignDoners
        fields = (
            "amount",
            "name",
            "email",
            "phone",
            'address',
            "pincode",
            "city",
            "state",
            "facbook",
            "twitter",
            "indian_citizen",
            "is_hide_me",
        )

        widgets = {
            "amount":forms.NumberInput(attrs={"class":"jss860 jss845 integer_value"}),
            "name":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "email":forms.EmailInput(attrs={"class":"jss860 jss845"}),
            "phone":forms.TextInput(attrs={"id":'mobile-number'}),
            'address':forms.TextInput(attrs={"class":"jss860 jss845"}),
            "pincode":forms.TextInput(attrs={"class":"jss860 jss845 integer_value"}),
            "city":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "state":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "facbook":forms.URLInput(attrs={"class":"jss860 jss845"}),
            "twitter":forms.URLInput(attrs={"class":"jss860 jss845"}),
            "is_hide_me":forms.CheckboxInput(attrs={"class":"jss885", "id":"donation_anonymous_checkbox"}),
            "indian_citizen":forms.CheckboxInput(attrs={"class":"jss885", "id":"citizen_voluntary"}),
        }


class SupportGroupMembersForms(forms.ModelForm):
    class Meta:
        model = SupportGroupMembers
        fields = (
            "name",
            "email",
            "phone",
            'address',
            "pincode",
            "city",
            "state",
            "facbook",
            "twitter",
            "is_share",
            "is_hide_me",
        )

        widgets = {
            "name":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "email":forms.EmailInput(attrs={"class":"jss860 jss845"}),
            "phone":forms.TextInput(attrs={"id":'mobile-number'}),
            'address':forms.TextInput(attrs={"class":"jss860 jss845"}),
            "pincode":forms.TextInput(attrs={"class":"jss860 jss845 integer_value"}),
            "city":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "state":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "facbook":forms.URLInput(attrs={"class":"jss860 jss845"}),
            "twitter":forms.URLInput(attrs={"class":"jss860 jss845"}),
            "is_share":forms.CheckboxInput(attrs={"class":"jss885", "id":"contact_details_private"}),
            "is_hide_me":forms.CheckboxInput(attrs={"class":"jss885", "id":"hide_my_name"}),
        }



class EventGroupMembersForms(forms.ModelForm):
    class Meta:
        model = EventGroupMembers
        fields = (
            "name",
            "email",
            "phone",
            'address',
            "pincode",
            "city",
            "state",
            "facbook",
            "twitter",
            "is_share",
            "is_hide_me",
        )

        widgets = {
            "name":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "email":forms.EmailInput(attrs={"class":"jss860 jss845"}),
            "phone":forms.TextInput(attrs={"id":'mobile-number'}),
            'address':forms.TextInput(attrs={"class":"jss860 jss845"}),
            "pincode":forms.TextInput(attrs={"class":"jss860 jss845 integer_value"}),
            "city":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "state":forms.TextInput(attrs={"class":"jss860 jss845"}),
            "facbook":forms.URLInput(attrs={"class":"jss860 jss845"}),
            "twitter":forms.URLInput(attrs={"class":"jss860 jss845"}),
            "is_share":forms.CheckboxInput(attrs={"class":"jss885", "id":"contact_details_private"}),
            "is_hide_me":forms.CheckboxInput(attrs={"class":"jss885", "id":"hide_my_name"}),
        }


class EventTitleForm(forms.ModelForm):
    
    class Meta:
        model = Event
        fields = (
            "name",
        )

        widgets = {
            'name' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }

class EventPictureForm(forms.ModelForm):
    
    class Meta:
        model = Event
        fields = (
            "image",
        )

        widgets = {
            'image' :forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1", "id":"id_picture", "data-multiple-caption":"{count} files selected"}),
        }

class EventAboutForm(forms.ModelForm):
    
    class Meta:
        model = Event
        fields = (
            "about",
        )

        widgets = {
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }

class EventPlaceForm(forms.ModelForm):

    class Meta:
        model = Event
        fields = (
            "place",
        )

        widgets = {
            'place' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }


class EventDateForm(forms.ModelForm):
    
    class Meta:
        model = Event
        fields = (
            "date",
        )

        widgets = {
            'date' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }


class EventBuzzForm(forms.ModelForm):
    class Meta:
        model = EventBuzz
        fields = (
            "title",
            "buzz",
            "article_link",
            "picture",
            "publisher",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'buzz' :forms.Textarea(attrs={"class":"jss577 jss562"}),
            'article_link' : forms.URLInput(attrs={"class":"jss577 jss562"}),
            "picture":forms.FileInput(attrs={"onchange":"Validateimgupload(this);", "class":"inputfile inputfile-1"}),
            "publisher":forms.TextInput(attrs={"class":"jss577 jss562"}),
        }


class EventUpdatesForm(forms.ModelForm):
    class Meta:
        model = EventUpdates
        fields = (
            "title",
            "about",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'about' :forms.Textarea(attrs={"class":"jss577 jss562"}),
        }


class WithdrawalRequestForm(forms.ModelForm):
    class Meta:
        model = WithdrawalRequest
        fields = (
            'campaign',
            'amount',
            'document',
            'summary',
        )
        widgets = {
            'campaign' :forms.TextInput(attrs={"class":"jss577 jss562", "type":"hidden"}),
            'amount' :forms.NumberInput(attrs={"class":"jss577 jss562", 'step':"any"}),
            'document' :forms.FileInput(attrs={"onchange":"Validatedocupload(this);", "id":"id_doc", "class":"inputfile inputfile-1"}),
            'summary' :forms.TextInput(attrs={"class":"jss577 jss562"}),
        }

    
    def clean(self):
        cleaned_data = super().clean()
        p_amount = cleaned_data.get("amount")
        p_campaign = cleaned_data.get("campaign")

        instance_campaign = CampaignFundRaiser.objects.get(id=p_campaign.id)

        if instance_campaign.available_withdrawl_fund() < p_amount:
            self.add_error('amount', 'you do not have enough balance to withdraw.')


class AdminWithdrawalRequestForm(forms.ModelForm):
    class Meta:
        model = WithdrawalRequest
        fields = (
            'status',
            'payment_date',
        )
        widgets = {
            'status':forms.Select(attrs={"class":"select2" , "onchange":'onChangeStatus()'}),
            'payment_date':forms.TextInput(attrs={"class":"jss577 jss562", 'required':'required', "id":'datetimepicker3'}),
        }


class AdminCampaignFundRaiserCommissionForm(forms.ModelForm):
    class Meta:
        model = CampaignFundRaiser
        fields = (
            "commission",
        )

        widgets = {
            'commission' :forms.NumberInput(attrs={"class":"jss577 jss562", "step":"any"}),
        }


class ContactUSForm(forms.ModelForm):
    class Meta:
        model = ContactUS
        fields = (
            'name',
            'email',
            'subject',
            'message',
        )

        widgets = {
            'name':forms.TextInput(attrs={'id':"contact_name"}),
            'email':forms.EmailInput(attrs={"id":"contact_email"}),
            'subject':forms.TextInput(attrs={"id":"contact_subject"}),
            'message':forms.Textarea(attrs={"rows":"4", "id":"contact_textarea"}),
        }


class PublicEmailForm(forms.Form):
    subject = forms.CharField(widget=forms.TextInput(attrs={"class":"jss577 jss562 integer_value"}))
    message = forms.CharField(widget=forms.Textarea(attrs={"class":"w-100", "style":"resize: both;height: 150px;overflow-y: scroll;"}))


class BannerImagesForm(forms.ModelForm):
    class Meta:
        model = BannerImages
        fields = (
            "title",
            "short_description",
            "picture",
            # "button_text",
            # "button_url",
        )

        widgets = {
            'title' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'short_description':forms.TextInput(attrs={"class":"jss577 jss562"}),
            # 'button_text':forms.TextInput(attrs={"class":"jss577 jss562"}),
            # 'button_url':forms.URLInput(attrs={"class":"jss577 jss562"}),
        }


class CategorySelectionForm(forms.Form):
    category = forms.ModelChoiceField(queryset=CampaignCategory.objects.filter(is_active=True))




class CashfreePaymentDetailsForm(forms.ModelForm):
    class Meta:
        model = CashfreePaymentDetails
        fields = (
            "app_id",
            "secrate_key",
            "payment_mode",
        )

        widgets = {
            'app_id' :forms.TextInput(attrs={"class":"jss577 jss562"}),
            'secrate_key':forms.TextInput(attrs={"class":"jss577 jss562"}),
            "payment_mode":forms.Select(attrs={"class":"select2"}),
        }