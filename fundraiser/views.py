from django.shortcuts import render,redirect,HttpResponse
from django.template.loader import render_to_string
from django.http import JsonResponse


#---------------- import form -----------------#
from fundraiser.forms import *
from django.contrib.auth.forms import PasswordChangeForm


#---------------- import models ------------------#
from fundraiser.models import *
from django.db.models import Sum
from django.db.models import Q
from django.db.models import Count
from django.db.models.functions import Coalesce


#---------------- import django message framework --------------------#
from django.contrib import messages 


#----------------- login or authentication -----------------------#
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login

from django.contrib.auth import get_user_model
User = get_user_model()

from django.contrib.auth.decorators import login_required


#--------------------- decoraters ------------------------#
from fundraiser.decorators import *


#-------------------- get domain -------------------------#
from django.contrib.sites.shortcuts import get_current_site

#------------------------ To Send Emails ------------------------#
from django.core.mail import send_mail

from django.core.mail import EmailMultiAlternatives

from django.core.mail import EmailMessage

#---------------------------- paginator -----------------------------------#
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger


#--------------------------- datetime ---------------------------------------#
from datetime import datetime, timedelta


#--------------------------- activation token -------------------------------#
from fundraiser.tokens import account_activation_token


#------------------------ url base 64 ---------------------------------------#
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_text

#----------------------- import choices ----------------------------------------#
from fundraiser.choices import *

#-------------------------- import razorpay -------------------------------#
import razorpay
client = razorpay.Client(auth=("rzp_test_V5XeIgR2BcnPrv", "cKgTUhxtsWCA1RabkFesBY5M"))
rzpay_api_key = 'rzp_test_V5XeIgR2BcnPrv'


# cashfree_appid = '16299ea30060882e532440419261'
# cashfree_secretKey = "f5a70e01a7861d1c36238e0df6d85a9f800deba5"
# cashfree_payment_mode = "TEST" # option TEST or PROD

import hashlib
import hmac
import base64

import requests
import json

#------------------------ csrf excempt--------------------------#
from django.views.decorators.csrf import csrf_exempt


#--------------------------- import geoip2 for location --------------------------------------#
import geoip2.database


#--------------------- save visit history ---------------------------------------------------------#
def save_support_group_visiter(request, supportgroup):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    elif request.META.get('HTTP_X_REAL_IP'):
        ip = request.META.get('HTTP_X_REAL_IP')
    else:
        ip = request.META.get('REMOTE_ADDR')

    
    source = request.GET.get('source')

    try:

        reader = geoip2.database.Reader('GeoLite2-City_20190730/GeoLite2-City.mmdb')

        response = reader.city(ip)
        location = {
            'country_iso_code':response.country.iso_code, 'country_name':response.country.name, 
            'subdivisions_name':response.subdivisions.most_specific.name, 'subdivisions_iso_code':response.subdivisions.most_specific.iso_code,
            'city':response.city.name, 'postal':response.postal.code, 'location_latitude':response.location.latitude, 'location_longitude':response.location.longitude
            }

        reader.close()
        if request.user.is_authenticated:
            SupportVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, location=location, support_group=supportgroup, user=request.user, source=source)
        else:
            SupportVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, location=location, support_group=supportgroup, source=source)
    except:
        if request.user.is_authenticated:
            SupportVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, support_group=supportgroup, user=request.user, source=source)
        else:
            SupportVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, support_group=supportgroup, source=source)

    return True


def save_event_visiter(request, event):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    elif request.META.get('HTTP_X_REAL_IP'):
        ip = request.META.get('HTTP_X_REAL_IP')
    else:
        ip = request.META.get('REMOTE_ADDR')


    source = request.GET.get('source')

    try:
        reader = geoip2.database.Reader('GeoLite2-City_20190730/GeoLite2-City.mmdb')

        response = reader.city(ip)
        location = {
            'country_iso_code':response.country.iso_code, 'country_name':response.country.name, 
            'subdivisions_name':response.subdivisions.most_specific.name, 'subdivisions_iso_code':response.subdivisions.most_specific.iso_code,
            'city':response.city.name, 'postal':response.postal.code, 'location_latitude':response.location.latitude, 'location_longitude':response.location.longitude
            }

        reader.close()
        if request.user.is_authenticated:
            EventVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, location=location, event=event, user=request.user, source=source)
        else:
            EventVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, location=location, event=event, source=source)
    except:
        if request.user.is_authenticated:
            EventVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, event=event, user=request.user, source=source)
        else:
            EventVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, event=event, source=source)

    return True



def save_fundraiser_visiter(request, fundraiser):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    elif request.META.get('HTTP_X_REAL_IP'):
        ip = request.META.get('HTTP_X_REAL_IP')
    else:
        ip = request.META.get('REMOTE_ADDR')

    source = request.GET.get('source')

    try:
        reader = geoip2.database.Reader('GeoLite2-City_20190730/GeoLite2-City.mmdb')

        response = reader.city(ip)
        location = {
            'country_iso_code':response.country.iso_code, 'country_name':response.country.name, 
            'subdivisions_name':response.subdivisions.most_specific.name, 'subdivisions_iso_code':response.subdivisions.most_specific.iso_code,
            'city':response.city.name, 'postal':response.postal.code, 'location_latitude':response.location.latitude, 'location_longitude':response.location.longitude
            }

        reader.close()
        if request.user.is_authenticated:
            CampaignFundRaiserVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, location=location, campaign_fundraiser=fundraiser, user=request.user, source=source)
        else:
            CampaignFundRaiserVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, location=location, campaign_fundraiser=fundraiser, source=source)
    except:
        if request.user.is_authenticated:
            CampaignFundRaiserVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, campaign_fundraiser=fundraiser, user=request.user, source=source)
        else:
            CampaignFundRaiserVisitHistory.objects.create(path=request.path, ip=ip, request_type=request.method, campaign_fundraiser=fundraiser, source=source)
    return True


#------------------------------------------ start befor login ---------------------------------------------#
def landingpage(request):
    """
    This view to get method and response is index page
    """
    instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(is_active=True)
    instance_SupportGroup = SupportGroup.objects.filter(is_active=True)
    instance_Event = Event.objects.filter(is_active=True)
    instance_CrowdNewsing = CrowdNewsing.objects.all().order_by("-id")
    # instance_first_banner = BannerImages.objects.filter(is_active=True)
    try:
        instance_first_banner = BannerImages.objects.get(id=1)
    except:
        instance_first_banner = False

    try:
        instance_second_banner = BannerImages.objects.get(id=2)
    except:
        instance_second_banner = False

    try:
        instance_third_banner = BannerImages.objects.get(id=3)
    except:
        instance_third_banner = False

    context = {
        'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
        'instance_SupportGroup':instance_SupportGroup,
        'instance_CrowdNewsing':instance_CrowdNewsing,
        'instance_Event':instance_Event,
        'today':datetime.now().date(),
        'instance_first_banner':instance_first_banner,
        'instance_second_banner':instance_second_banner,
        'instance_third_banner':instance_third_banner,
        # 'instance_Banner':instance_Banner,
    }
    return render(request, 'before_login/index.html', context)

def password_reset_done(request):
    if request.user.is_authenticated:
        messages.add_message(request,messages.SUCCESS," We've emailed you instructions for setting your password, You should receive them shortly.")
        return redirect('logout')
    else:
        messages.add_message(request,messages.SUCCESS," We've emailed you instructions for setting your password, if an account exists with the email you entered. You should receive them shortly.")
        return redirect('login')

def password_reset_complete(request):
    messages.add_message(request,messages.SUCCESS,"Your password has been set. You may go ahead and Sign in.")
    return redirect('login')



@anonymous_user_required
def login(request):
    """
    This view to validate the login credentials of the user

    """
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password =  form.cleaned_data['password']
            user = authenticate(username=email, password=password)
            if user is not None:
                if user.is_active:
                    if user.user_type == 'End User':
                        if user.email_confirm:
                            auth_login(request, user)
                            if 'next' in request.GET and request.GET['next']:
                                return redirect(request.GET['next'])
                            else:
                                return redirect('landingpage')
                        else:
                            messages.add_message(request,messages.ERROR, 'Email not verified. Please click on the link sent to your email id.')
                            return redirect("login")
                    else :
                        auth_login(request, user)
                        if 'next' in request.GET and request.GET['next']:
                            return redirect(request.GET['next'])
                        return redirect('admin_dashboard')
                           
                else:
                    messages.add_message(request,messages.ERROR,'Your Account is not Activated admin will active your account with in 24 hours.')
            else:
                messages.add_message(request,messages.ERROR,'Your Email or Password is Incorrect.')
        else:
            pass
    else :
        form = LoginForm()
    context = {"login_form":form}
    return render(request, 'registration/login.html', context)
    

@anonymous_user_required
def registration(request):
    """
    This view to register new user
    GET : send a new form
    POST : read a post form and save in database

    """
    if request.method == 'POST':
        password = request.POST.get('password1', '')
        userform = UserSignupForm(request.POST)
        if userform.is_valid():
            userform = userform.save(commit=False)
            userform.user_type = 'End User'
            userform.save()



            current_site = get_current_site(request)
            mail_subject = 'Activate your Crowd Funding account'
            message = render_to_string('email_template/activate_email.html', {
                'user': userform,
                'domain': current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(userform.pk)).decode(),
                'token':account_activation_token.make_token(userform),
            })
            email = EmailMultiAlternatives(
                             mail_subject, message, to=[userform.email]
             )
            email.attach_alternative(message, "text/html")
            email.send()


            messages.add_message(request,messages.SUCCESS, "Please confirm your email address using the verification link just sent to you. In case it's missing from your inbox, check your spam folder or click below to resend the activation email.")

            return redirect("login")

        else:
            pass

    else:
        userform = UserSignupForm()
    context = {
        'userform':userform,
    }
    return render(request, 'registration/registration.html', context)


@anonymous_user_required
def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.email_confirm = True
        user.save()
       
        messages.add_message(request,messages.SUCCESS,'Your account has been activated successfully. You may go ahead and Sign in.')
        
    else:
        messages.add_message(request,messages.ERROR,'activation link has expired to get new link form login page.')


    return redirect("login")


def new_activate_link(request):
    if request.method == 'POST':
        email = request.POST.get('email', None)
        try:
            try:
                user = User.objects.get(email__iexact=email)
            except:
                messages.add_message(request,messages.SUCCESS,'Email id is not registered.')
                return redirect("login")


            if user.email_confirm:
                messages.add_message(request,messages.SUCCESS,'Your account is already activated. You may go ahead and Sign in.')
                return redirect("login")
            else:
                current_site = get_current_site(request)
                message = render_to_string('email_template/new_activate_email.html',{
                    'user': user,
                    'domain': current_site.domain,
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                    'token':account_activation_token.make_token(user),
                })
                mail_subject = 'Forgot Activation link.'
                email = EmailMultiAlternatives(
                    mail_subject, message, to=[user.email]
                )
                email.attach_alternative(message, "text/html")
                email.send()

                messages.add_message(request,messages.SUCCESS, 'You will receive instructions for activating your account at ' + str(user.email) + ' .')
        except:
            pass
        return redirect("login")
    else:
        return redirect("login")
        

#------------------------------------------ end befor login ---------------------------------------------#


#------------------------------------------ start all user ----------------------------------------------#

def discover(request):
    if request.is_ajax():
        category = request.GET.get('category', None)
        sub_category = request.GET.get('sub_category', None)
        nested_sub_category = request.GET.get('nested_sub_category', None)
        page = request.GET.get('page', None)
        if sub_category == 'Show All':
            sub_category = None
        if nested_sub_category == 'Show All':
            nested_sub_category = None

        if category == 'Fundraisers':
            instance_CampaignCategory = CampaignCategory.objects.filter(is_active=True)
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(is_active=True, category__is_active=True)

            if sub_category:
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(category__category__iexact=sub_category)
                instance_CampaignSubCategory = CampaignSubCategory.objects.filter(category__category__iexact=sub_category)
            else:
                instance_CampaignSubCategory = []

            if nested_sub_category:
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(sub_category__sub_category__iexact=nested_sub_category)
                

            paginator  = Paginator(instance_CampaignFundRaiser, 6)
            page = request.GET.get('page')
            try: 
                instance_CampaignFundRaiser = paginator.page(page)
            except PageNotAnInteger:
                instance_CampaignFundRaiser = paginator.page(1)
            except EmptyPage:
                instance_CampaignFundRaiser = paginator.page(Paginator.num_pages)

            context = {
                'sub_category':sub_category,
                'nested_sub_category':nested_sub_category,
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
                'instance_CampaignCategory':instance_CampaignCategory,
                'instance_CampaignSubCategory':instance_CampaignSubCategory,
            }
            return render(request, 'before_login/discover_fundraiser.html', context)
        if category == 'Event':
            Today = datetime.now().date()
            instance_Event = Event.objects.filter(is_active=True, date__gte=Today)

            paginator  = Paginator(instance_Event, 6)
            page = request.GET.get('page')
            try: 
                instance_Event = paginator.page(page)
            except PageNotAnInteger:
                instance_Event = paginator.page(1)
            except EmptyPage:
                instance_Event = paginator.page(Paginator.num_pages)

            context = {
                'instance_Event':instance_Event
            }
            return render(request, 'before_login/discover_event.html', context)

        else:
            instance_SupportGroup = SupportGroup.objects.filter(is_active=True)

            paginator  = Paginator(instance_SupportGroup, 6)
            page = request.GET.get('page')
            try: 
                joinstance_SupportGroupb = paginator.page(page)
            except PageNotAnInteger:
                instance_SupportGroup = paginator.page(1)
            except EmptyPage:
                instance_SupportGroup = paginator.page(Paginator.num_pages)

            context = {
                'instance_SupportGroup':instance_SupportGroup
            }
            return render(request, 'before_login/discover_supportgroup.html', context)

    elif request.method == 'POST':
        title = request.POST.get('title', None)
        instance_CampaignCategory = CampaignCategory.objects.filter(is_active=True)

        if title:
            Today = datetime.now().date()
            instance_Event = Event.objects.filter(is_active=True, date__gte=Today).filter(Q(name__icontains=title)|Q(about__icontains=title)|Q(place__icontains=title)|Q(user__email__icontains=title)|Q(user__name__icontains=title))
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(is_active=True, category__is_active=True).filter(Q(title__icontains=title)|Q(short_description__icontains=title)|Q(about__icontains=title)|Q(user__email__icontains=title)|Q(user__name__icontains=title))
            instance_SupportGroup = SupportGroup.objects.filter(is_active=True).filter(Q(title__icontains=title)|Q(short_description__icontains=title)|Q(about__icontains=title)|Q(group_leader__email__icontains=title)|Q(group_leader__name__icontains=title))
        else:
            return redirect('discover')

        

        context = {
            'title':title,
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignCategory':instance_CampaignCategory,
            'instance_Event':instance_Event,

            'instance_SupportGroup':instance_SupportGroup
        }
        return render(request, 'before_login/discover.html', context)

    else:
        context = {

        }
        return render(request, 'before_login/discover.html', context)

def campaign_selected(request, url_text):
    form_error = False
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text)

        source = request.GET.get('source')

        try:
            save_fundraiser_visiter(request, instance_CampaignFundRaiser)
        except Exception as e:
            pass



        is_authorised_for_edit = False
        if request.user.is_authenticated:
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                is_authorised_for_edit = True
            elif instance_CampaignFundRaiser.user.id == request.user.id:
                is_authorised_for_edit = False
            else:
                is_authorised_for_edit = False
        else:
            pass



        if is_authorised_for_edit:
            if request.method == "POST":
                form_type = request.POST.get('form_type', None)

                if form_type == 'Goal':
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(request.POST, instance=instance_CampaignFundRaiser)
                    if CampaignFundRaiserGoalForm.is_valid():
                        CampaignFundRaiserGoalForm = CampaignFundRaiserGoalForm.save()

                        messages.add_message(request,messages.SUCCESS,'Goal updated successfully.')

                        return redirect('campaign_selected', url_text=url_text)
                    else:
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()

                elif form_type == 'Title':
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(request.POST, instance=instance_CampaignFundRaiser)
                    if CampaignFundRaiserTitleForm.is_valid():
                        CampaignFundRaiserTitleForm = CampaignFundRaiserTitleForm.save()

                        messages.add_message(request,messages.SUCCESS,'Title updated successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()



                elif form_type == 'Picture':
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
                    if CampaignFundRaiserPictureForm.is_valid():
                        CampaignFundRaiserPictureForm = CampaignFundRaiserPictureForm.save()

                        messages.add_message(request,messages.SUCCESS,'Picture updated successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()




                elif form_type == 'About':
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(request.POST, instance=instance_CampaignFundRaiser)
                    if CampaignFundRaiserAboutForm.is_valid():
                        CampaignFundRaiserAboutForm = CampaignFundRaiserAboutForm.save()

                        messages.add_message(request,messages.SUCCESS,'About updated successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()


                elif form_type == 'Updates':
                    CampaignUpdates_Form = CampaignUpdatesForm(request.POST)
                    if CampaignUpdates_Form.is_valid():
                        CampaignUpdates_Form = CampaignUpdates_Form.save(commit=False)
                        CampaignUpdates_Form.campaign_fund_raiser = instance_CampaignFundRaiser
                        CampaignUpdates_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Update added successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()


                elif form_type == 'Buzz':
                    CampaignBuzz_Form = CampaignBuzzForm(request.POST, request.FILES)
                    if CampaignBuzz_Form.is_valid():
                        CampaignBuzz_Form = CampaignBuzz_Form.save(commit=False)
                        CampaignBuzz_Form.campaign_fund_raiser = instance_CampaignFundRaiser
                        CampaignBuzz_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Buzz added successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        Campaign_Comments_Form = CampaignCommentsForm()


                elif form_type == 'comment':
                    Campaign_Comments_Form = CampaignCommentsForm(request.POST)
                    if Campaign_Comments_Form.is_valid():
                        Campaign_Comments_Form = Campaign_Comments_Form.save(commit=False)
                        Campaign_Comments_Form.campaign_fund_raiser = instance_CampaignFundRaiser
                        Campaign_Comments_Form.comment_user = request.user
                        Campaign_Comments_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Comment added successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()

                elif form_type == 'Day':
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(request.POST, instance=instance_CampaignFundRaiser)
                    if CampaignFundRaiserDay.is_valid():
                        CampaignFundRaiserDay = CampaignFundRaiserDay.save(commit=False)
                        CampaignFundRaiserDay.CampaignFundRaiserDay = instance_CampaignFundRaiser
                        CampaignFundRaiserDay.comment_user = request.user
                        CampaignFundRaiserDay.save()

                        messages.add_message(request,messages.SUCCESS,'Days updated successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()

                elif form_type == 'short_description':
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(request.POST, instance=instance_CampaignFundRaiser)
                    if CampaignFundRaiserShortDescription.is_valid():
                        CampaignFundRaiserShortDescription = CampaignFundRaiserShortDescription.save(commit=False)
                        CampaignFundRaiserShortDescription.campaign_fund_raiser = instance_CampaignFundRaiser
                        CampaignFundRaiserShortDescription.comment_user = request.user
                        CampaignFundRaiserShortDescription.save()

                        messages.add_message(request,messages.SUCCESS,'Short Description updated successfully.')

                        return redirect('campaign_selected', url_text=url_text)

                    else:
                        CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                        CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                        CampaignUpdates_Form = CampaignUpdatesForm()
                        CampaignBuzz_Form = CampaignBuzzForm()
                        Campaign_Comments_Form = CampaignCommentsForm()


                else:
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignUpdates_Form = CampaignUpdatesForm()
                    CampaignBuzz_Form = CampaignBuzzForm()
                    Campaign_Comments_Form = CampaignCommentsForm()

            else:
                CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                CampaignUpdates_Form = CampaignUpdatesForm()
                CampaignBuzz_Form = CampaignBuzzForm()
                Campaign_Comments_Form = CampaignCommentsForm()




            instance_top_five_campaigndoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').values('email', 'name', 'is_hide_me').order_by('email').annotate(total=Sum('amount')).order_by('-total')[:5]
            instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').order_by("-id")
            instance_CampaignComments = CampaignComments.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).order_by("-id")
            instance_CampaignUpdates = CampaignUpdates.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).order_by("id")
            instance_CampaignBuzz = CampaignBuzz.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).order_by("id")

            current_site = get_current_site(request)
            domain = current_site.domain

            context = {
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
                'instance_top_five_campaigndoners':instance_top_five_campaigndoners,
                'instance_CampaignDoners':instance_CampaignDoners,
                'instance_CampaignComments':instance_CampaignComments,
                'instance_CampaignUpdates':instance_CampaignUpdates,
                'instance_CampaignBuzz':instance_CampaignBuzz,

                "CampaignFundRaiserGoalForm":CampaignFundRaiserGoalForm,
                "CampaignFundRaiserTitleForm":CampaignFundRaiserTitleForm,
                "CampaignFundRaiserPictureForm" : CampaignFundRaiserPictureForm,
                "CampaignFundRaiserAboutForm" : CampaignFundRaiserAboutForm,
                'CampaignFundRaiserDay':CampaignFundRaiserDay,
                'CampaignFundRaiserShortDescription':CampaignFundRaiserShortDescription,
                'CampaignUpdates_Form':CampaignUpdates_Form,
                'CampaignBuzz_Form':CampaignBuzz_Form,
                'Campaign_Comments_Form':Campaign_Comments_Form,


                'group_member':True,
                'Today':datetime.now().date(),
                'domain':domain,
                'is_authorised_for_edit':is_authorised_for_edit,
            }

            return render(request, 'before_login/campaign_selected.html', context)
            
        else:
            if request.user.is_authenticated:
                group_member_count = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').filter(Q(doner_user=request.user)|Q(email__iexact=request.user.email)).count()
                if group_member_count != 0:
                    group_member = True
                else:
                    group_member = False
            else:
                group_member = False


            if request.method == 'POST':
                form_type = request.POST.get('form_type', None)
                if form_type == 'comment':
                    if request.user.is_authenticated:
                        Campaign_Comments_Form = CampaignCommentsForm(request.POST)
                        if Campaign_Comments_Form.is_valid():
                            Campaign_Comments_Form = Campaign_Comments_Form.save(commit=False)
                            Campaign_Comments_Form.comment_user = request.user
                            Campaign_Comments_Form.campaign_fund_raiser = instance_CampaignFundRaiser
                            Campaign_Comments_Form.save()

                            messages.add_message(request,messages.SUCCESS,'Comment added successfully.')

                            return redirect('campaign_selected', url_text=url_text)
                        else:
                            Campaign_Doners_Forms = CampaignDonersForms()
                            CheckPotentialCampaignDoners_Forms = CheckPotentialCampaignDoners()
                    else:
                        messages.add_message(request,messages.ERROR,'for comment authenticate must be need.')
                        return redirect('login')

                elif form_type == 'Doners':
                    # CheckPotentialCampaignDoners_Forms = CheckPotentialCampaignDoners(request.POST)
                    # if CheckPotentialCampaignDoners_Forms.is_valid():
                    #     is_donating = CheckPotentialCampaignDoners_Forms.cleaned_data['is_donating']
                    #     if is_donating:
                    #         Campaign_Doners_Forms = CampaignDonersForms(request.POST)
                    #         if Campaign_Doners_Forms.is_valid():
                    #             Campaign_Doners_Forms = Campaign_Doners_Forms.save(commit=False)
                    #             Campaign_Doners_Forms.campaign_fund_raiser = instance_CampaignFundRaiser
                    #             if request.user.is_authenticated:
                    #                 Campaign_Doners_Forms.doner_user = request.user
                    #             Campaign_Doners_Forms.source = source

                    #             Campaign_Doners_Forms.save()

                    #             return redirect('campaign_payment', ID=instance_CampaignFundRaiser.id, OID=Campaign_Doners_Forms.id)

                    #         else:
                    #             form_error = 'Doners'
                    #             Campaign_Comments_Form = CampaignCommentsForm()

                    #     else:
                    #         Campaign_Doners_Forms = PotentialCampaignDonersForms(request.POST)
                    #         if Campaign_Doners_Forms.is_valid():
                    #             Campaign_Doners_Forms = Campaign_Doners_Forms.save(commit=False)
                    #             Campaign_Doners_Forms.campaign_fund_raiser = instance_CampaignFundRaiser
                    #             if request.user.is_authenticated:
                    #                 Campaign_Doners_Forms.doner_user = request.user
                    #             Campaign_Doners_Forms.source = source

                    #             Campaign_Doners_Forms.save()

                    #             messages.add_message(request,messages.SUCCESS,'Thanks for supporting.')

                    #             return redirect('campaign_selected', url_text=url_text)

                    #         else:
                    #             form_error = 'Doners'
                    #             Campaign_Comments_Form = CampaignCommentsForm()

                    # else:
                    #     form_error = 'Doners'
                    #     Campaign_Doners_Forms = CampaignDonersForms(request.POST)
                    #     Campaign_Comments_Form = CampaignCommentsForm()
                    Campaign_Doners_Forms = CampaignDonersForms(request.POST)
                    if Campaign_Doners_Forms.is_valid():
                        Campaign_Doners_Forms = Campaign_Doners_Forms.save(commit=False)
                        Campaign_Doners_Forms.campaign_fund_raiser = instance_CampaignFundRaiser
                        if request.user.is_authenticated:
                            Campaign_Doners_Forms.doner_user = request.user
                            Campaign_Doners_Forms.source = source

                        Campaign_Doners_Forms.save()

                        return redirect('campaign_payment', ID=instance_CampaignFundRaiser.id, OID=Campaign_Doners_Forms.id)

                    else:
                        print(Campaign_Doners_Forms.errors)
                        Campaign_Comments_Form = CampaignCommentsForm()
                        
                else:
                    Campaign_Comments_Form = CampaignCommentsForm()
                    Campaign_Doners_Forms = CampaignDonersForms()
                    CheckPotentialCampaignDoners_Forms = CheckPotentialCampaignDoners()

                    


            else:
                Campaign_Comments_Form = CampaignCommentsForm()
                CheckPotentialCampaignDoners_Forms = CheckPotentialCampaignDoners()
                if request.user.is_authenticated:
                    Campaign_Doners_Forms = CampaignDonersForms(initial={'name':request.user.name, 'email':request.user.email, 'phone':request.user.mobile_no, 'address':request.user.address, 'pincode':request.user.pincode})
                else:
                    Campaign_Doners_Forms = CampaignDonersForms()


            instance_top_five_campaigndoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').values('email', 'name', 'is_hide_me',).order_by('email').annotate(total=Sum('amount')).order_by('-total')[:5]
            instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').order_by("-id")
            instance_CampaignComments = CampaignComments.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).order_by("-id")
            instance_CampaignUpdates = CampaignUpdates.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).order_by("id")
            instance_CampaignBuzz = CampaignBuzz.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).order_by("id")


            current_site = get_current_site(request)
            domain = current_site.domain

            context = {
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
                'instance_top_five_campaigndoners':instance_top_five_campaigndoners,
                'instance_CampaignDoners':instance_CampaignDoners,
                'instance_CampaignComments':instance_CampaignComments,
                'instance_CampaignUpdates':instance_CampaignUpdates,
                'instance_CampaignBuzz':instance_CampaignBuzz,
                'Campaign_Comments_Form':Campaign_Comments_Form,
                'Campaign_Doners_Forms':Campaign_Doners_Forms,
                'group_member':group_member,
                'Today':datetime.now().date(),
                'domain':domain,
                'is_authorised_for_edit':is_authorised_for_edit,
                'form_error':form_error,
                'CheckPotentialCampaignDoners_Forms':CheckPotentialCampaignDoners_Forms,
            }

            return render(request, 'before_login/campaign_selected.html', context)
    except:
        return redirect('discover')


def campaign_payment(request, ID, OID):
    try:
        instance_CashfreePaymentDetails = CashfreePaymentDetails.objects.all()[0]
    except:
        instance_CashfreePaymentDetails = CashfreePaymentDetails()
        instance_CashfreePaymentDetails.payment_mode='TEST'
        instance_CashfreePaymentDetails.save()

    

    try:
        cashfree_appid = instance_CashfreePaymentDetails.app_id
        cashfree_secretKey = instance_CashfreePaymentDetails.secrate_key
        cashfree_payment_mode = instance_CashfreePaymentDetails.payment_mode


        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)

        instance_CampaignDoners = CampaignDoners.objects.get(id=OID)

        if instance_CampaignDoners.payment_status == 'captured':
            messages.add_message(request,messages.SUCCESS,'You already completed payment if any query please contact to admin.')
            return redirect('discover')
        elif instance_CampaignDoners.payment_status == 'failed':
            messages.add_message(request,messages.SUCCESS,'Payment failed please do again.')
            return redirect('discover')

        postData = {
            "appId" : cashfree_appid, 
            "orderId" : str(instance_CampaignDoners.order_id), 
            "orderAmount" :str(instance_CampaignDoners.amount), 
            "orderCurrency" : 'INR', 
            "orderNote": "",
            "customerName" : instance_CampaignDoners.name, 
            "customerPhone" : str(instance_CampaignDoners.phone), 
            "customerEmail" : instance_CampaignDoners.email, 
            "returnUrl": "http://new.ourdemocracy.in/payment/check/",
            "notifyUrl": ''
        }
        
        sortedKeys = sorted(postData)
        signatureData = ""
        for key in sortedKeys:
            signatureData += key+postData[key]
        message = signatureData.encode('utf-8')
        #get secret key from your config
        secret = cashfree_secretKey.encode('utf-8')
        signature = base64.b64encode(hmac.new(secret,message,digestmod=hashlib.sha256).digest()).decode("utf-8")
        if cashfree_payment_mode == 'PROD': 
            url = "https://www.cashfree.com/checkout/post/submit"
        else: 
            url = "https://test.cashfree.com/billpay/checkout/post/submit"

        context = {
            'postData':postData,
            'signature':signature,
            'url':url,
        }

        return render(request, 'before_login/campaign_payment.html', context)
    except:
        return redirect('discover')

@csrf_exempt
def payment_check(request):
    if request.method == 'POST':
        try:
            instance_CashfreePaymentDetails = CashfreePaymentDetails.objects.all()[0]
        except:
            instance_CashfreePaymentDetails = CashfreePaymentDetails()
            instance_CashfreePaymentDetails.payment_mode='TEST'
            instance_CashfreePaymentDetails.save()

        


        instance_CampaignDoners = False
        try:
            cashfree_appid = instance_CashfreePaymentDetails.app_id
            cashfree_secretKey = instance_CashfreePaymentDetails.secrate_key
            cashfree_payment_mode = instance_CashfreePaymentDetails.payment_mode


            postData = {
                "orderId" : request.POST.get('orderId', None), 
                "orderAmount" : request.POST.get('orderAmount', None),  
                "referenceId" : request.POST.get('referenceId', None), 
                "txStatus" : request.POST.get('txStatus', None), 
                "paymentMode" : request.POST.get('paymentMode', None), 
                "txMsg" : request.POST.get('txMsg', None), 
                "signature" : request.POST.get('signature', None), 
                "txTime" : request.POST.get('txTime', None), 
            }

            signatureData = ""
            signatureData = postData['orderId'] + postData['orderAmount'] + postData['referenceId'] + postData['txStatus'] + postData['paymentMode'] + postData['txMsg'] + postData['txTime']

            message = signatureData.encode('utf-8')
            secret = cashfree_secretKey.encode('utf-8')
            computedsignature = base64.b64encode(hmac.new(secret,message,digestmod=hashlib.sha256).digest()).decode('utf-8')
            instance_CampaignDoners = CampaignDoners.objects.get(order_id__iexact=postData['orderId'])

            # get payment stattus
            api_url = 'https://test.cashfree.com/api/v1/order/info/'
            payload = {'appId':cashfree_appid, 'secretKey':cashfree_secretKey, 'orderId':instance_CampaignDoners.order_id}
            headers = {'cache-control': 'no-cache', 'content-type':'application/x-www-form-urlencoded'}
            response = requests.post(api_url, data=payload, headers=headers)
            response = response.json()

            # get payment mode
            try:
                payment_mode_api_url = 'https://test.cashfree.com/api/v1/order/info/status/'
                payment_mode_response = requests.post(payment_mode_api_url, data=payload, headers=headers)
                payment_mode_response = payment_mode_response.json()
                payment_mode = payment_mode_response['paymentDetails']['paymentMode']
            except:
                payment_mode = None




            if postData['signature'] == computedsignature and postData['txStatus'] == 'SUCCESS' and float(postData['orderAmount']) == float(instance_CampaignDoners.amount) and response['status'] == 'OK':
                instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=instance_CampaignDoners.campaign_fund_raiser.id)
                instance_CampaignDoners.payment_status = 'captured'
                instance_CampaignDoners.payment_id = postData['referenceId']
                instance_CampaignDoners.payment_mode = payment_mode
                instance_CampaignDoners.save()

                instance_CampaignDoners_count = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured', email=instance_CampaignDoners.email).count()
                instance_CampaignTotalAmount = CampaignTotalAmount.objects.get(campaign_fund_raiser=instance_CampaignFundRaiser)
                if instance_CampaignDoners_count != 0:
                    instance_CampaignTotalAmount.total_amount = (instance_CampaignTotalAmount.total_amount + instance_CampaignDoners.amount)
                    instance_CampaignTotalAmount.total_supporters = (instance_CampaignTotalAmount.total_supporters + 1)
                else:
                    instance_CampaignTotalAmount.total_amount = (instance_CampaignTotalAmount.total_amount + instance_CampaignDoners.amount)
                instance_CampaignTotalAmount.save()


                try:
                    current_site = get_current_site(request)
                    mail_subject = 'Thank you for supporting us.'
                    message = render_to_string('email_template/my_fundraiser_campaign_supporter_reminder_email.html', {
                        'domain': current_site.domain,
                        'instance_CampaignDoners':instance_CampaignDoners,
                    })
                    email = EmailMultiAlternatives(
                                        mail_subject, message, to=[instance_CampaignDoners.email]
                        )
                    email.attach_alternative(message, "text/html")
                    email.send()

                    mail_subject_campaign_creator = 'A new doner funded your campaign.'
                    message_campaign_creator = render_to_string('email_template/fundraiser_campaign_creator_inform.html', {
                        'domain': current_site.domain,
                        'instance_CampaignDoners':instance_CampaignDoners,
                        'instance_CampaignFundRaiser':instance_CampaignFundRaiser
                    })
                    email_campaigner = EmailMultiAlternatives(
                                        mail_subject_campaign_creator, message_campaign_creator, to=[instance_CampaignFundRaiser.user.email]
                        )
                    email_campaigner.attach_alternative(message, "text/html")
                    email_campaigner.send()
                except:
                    pass

                messages.add_message(request,messages.SUCCESS,'Thanks for supporting.')
                return redirect('campaign_selected', url_text=instance_CampaignDoners.campaign_fund_raiser.url_text)
            else:
                if instance_CampaignDoners:
                    instance_CampaignDoners.payment_status = 'failed'
                    instance_CampaignDoners.save()
        except:
            if instance_CampaignDoners:
                instance_CampaignDoners.payment_status = 'failed'
                instance_CampaignDoners.save()

    messages.add_message(request,messages.ERROR,'There seems to be some error in payment. In case your payment was successful please contact out support.')
    return redirect('discover')


    
# def campaign_payment(request, ID, OID):
#     try:
#         instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)

#         instance_CampaignDoners = CampaignDoners.objects.get(id=OID)

#         if instance_CampaignDoners.payment_status == 'captured':
#             messages.add_message(request,messages.SUCCESS,'You already completed payment if any query please contact to admin.')
#             return redirect('discover')
#         elif instance_CampaignDoners.payment_status == 'failed':
#             messages.add_message(request,messages.SUCCESS,'Payment failed please do again.')
#             return redirect('discover')

#         context = {
#             'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
#             'instance_CampaignDoners':instance_CampaignDoners,

#             'rzpay_api_key':rzpay_api_key,
#         }

#         return render(request, 'before_login/campaign_payment.html', context)
#     except:
#         return redirect('discover')

# def payment_check(request):
#     if request.method == 'POST':
#         instance_CampaignDoners = False
#         try:
#             paymentid = request.POST.get("razorpay_payment_id", None)
#             if paymentid :
#                 payment = client.payment.fetch(paymentid)
#                 razor_order_id = payment['notes']['order_id']
#                 instance_CampaignDoners = CampaignDoners.objects.get(id=razor_order_id)
#                 payment_amount = int(payment["amount"])
#                 if instance_CampaignDoners.amount_in_paisa()  == payment_amount:

#                     instance_CampaignDoners.payment_status = 'captured'
#                     instance_CampaignDoners.payment_id = paymentid
#                     instance_CampaignDoners.save()
#                     client.payment.capture(paymentid, payment_amount)

#                     instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=instance_CampaignDoners.campaign_fund_raiser.id)

#                     instance_CampaignDoners_count = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured', email=instance_CampaignDoners.email).count()
#                     instance_CampaignTotalAmount = CampaignTotalAmount.objects.get(campaign_fund_raiser=instance_CampaignFundRaiser)
#                     if instance_CampaignDoners_count != 0:
#                         instance_CampaignTotalAmount.total_amount = (instance_CampaignTotalAmount.total_amount + instance_CampaignDoners.amount)
#                         instance_CampaignTotalAmount.total_supporters = (instance_CampaignTotalAmount.total_supporters + 1)
#                     else:
#                         instance_CampaignTotalAmount.total_amount = (instance_CampaignTotalAmount.total_amount + instance_CampaignDoners.amount)
#                     instance_CampaignTotalAmount.save()

#                     messages.add_message(request,messages.SUCCESS,'Thanks for supporting.')
#                     return redirect('campaign_selected', ID=instance_CampaignDoners.campaign_fund_raiser.id, name=instance_CampaignDoners.campaign_fund_raiser.title)

#         except:
#             if instance_CampaignDoners:
#                 instance_CampaignDoners.payment_status = 'failed'
#                 instance_CampaignDoners.save()

#     messages.add_message(request,messages.ERROR,'There seems to be some error in payment. In case your payment was successful please contact out support.')
#     return redirect('discover')

@login_required
@end_user_required
def report_campaign_selected(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)

        instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))

        current_site = get_current_site(request)

        mail_subject = "Report Campaign"
        message = render_to_string('email_template/report_campaign.html',{
            'domain': current_site.domain,
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_user':request.user,
        })
        
        email = EmailMultiAlternatives(
            mail_subject, message, to=instance_admin_email
        )
        email.attach_alternative(message, "text/html")
        email.send()


        messages.add_message(request,messages.SUCCESS,'report send to admin successfully.')
        return redirect('campaign_selected', url_text=instance_CampaignFundRaiser.url_text)
        
    except:
        return redirect('discover')

@login_required
@end_user_required
def ask_update_campaign_selected(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)

        instance_user = request.user

        current_site = get_current_site(request)

        mail_subject = "Update query"
        message = render_to_string('email_template/ask_campaign_update.html',{
            'domain': current_site.domain,
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_user':instance_user,
        })
        
        email = EmailMultiAlternatives(
            mail_subject, message, to=[instance_CampaignFundRaiser.user.email]
        )
        email.attach_alternative(message, "text/html")
        email.send()


        messages.add_message(request,messages.SUCCESS,'Email send successfully.')
        return redirect('campaign_selected', url_text=instance_CampaignFundRaiser.url_text)

    except:
        return redirect('discover')


def support_group_selected(request, url_text):
    try:

        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text)

        source = request.GET.get('source')

        try:
            save_support_group_visiter(request, instance_SupportGroup)
        except:
            pass

        is_authorised_for_edit = False
        if request.user.is_authenticated:
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                is_authorised_for_edit = True
            elif instance_SupportGroup.group_leader.id == request.user.id:
                is_authorised_for_edit = False
            else:
                is_authorised_for_edit = False
        else:
            pass


        if is_authorised_for_edit:
            group_member = True
            is_not_joined = False


            if request.method == "POST":
                form_type = request.POST.get('form_type', None)

                if form_type == 'Goal':
                    SupportGroup_Goal_Form = SupportGroupGoalForm(request.POST, instance=instance_SupportGroup)
                    if SupportGroup_Goal_Form.is_valid():
                        SupportGroup_Goal_Form = SupportGroup_Goal_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Goal updated successfully.')

                        return redirect('support_group_selected', url_text=url_text)
                    else:
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Buzz_Form = SupportBuzzForm()
                        Support_Comments_Form = SupportCommentsForm()

                elif form_type == 'Title':
                    SupportGroup_Title_Form = SupportGroupTitleForm(request.POST, instance=instance_SupportGroup)
                    if SupportGroup_Title_Form.is_valid():
                        SupportGroup_Title_Form = SupportGroup_Title_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Title updated successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Buzz_Form = SupportBuzzForm()
                        Support_Comments_Form = SupportCommentsForm()



                elif form_type == 'Picture':
                    SupportGroup_Picture_Form = SupportGroupPictureForm(request.POST, request.FILES, instance=instance_SupportGroup)
                    if SupportGroup_Picture_Form.is_valid():
                        SupportGroup_Picture_Form = SupportGroup_Picture_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Picture updated successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Buzz_Form = SupportBuzzForm()
                        Support_Comments_Form = SupportCommentsForm()




                elif form_type == 'About':
                    SupportGroup_About_Form = SupportGroupAboutForm(request.POST, instance=instance_SupportGroup)
                    if SupportGroup_About_Form.is_valid():
                        SupportGroup_About_Form = SupportGroup_About_Form.save()

                        messages.add_message(request,messages.SUCCESS,'About updated successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Buzz_Form = SupportBuzzForm()
                        Support_Comments_Form = SupportCommentsForm()


                elif form_type == 'ShortDescription':
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(request.POST, instance=instance_SupportGroup)
                    if SupportGroup_ShortDescription_Form.is_valid():
                        SupportGroup_ShortDescription_Form = SupportGroup_ShortDescription_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Short Description updated successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Buzz_Form = SupportBuzzForm()
                        Support_Comments_Form = SupportCommentsForm()


                elif form_type == 'Updates':
                    Support_Updates_Form = SupportUpdatesForm(request.POST)
                    if Support_Updates_Form.is_valid():
                        Support_Updates_Form = Support_Updates_Form.save(commit=False)
                        Support_Updates_Form.support_group = instance_SupportGroup
                        Support_Updates_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Update added successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Buzz_Form = SupportBuzzForm()
                        Support_Comments_Form = SupportCommentsForm()


                elif form_type == 'Buzz':
                    Support_Buzz_Form = SupportBuzzForm(request.POST, request.FILES)
                    if Support_Buzz_Form.is_valid():
                        Support_Buzz_Form = Support_Buzz_Form.save(commit=False)
                        Support_Buzz_Form.support_group = instance_SupportGroup
                        Support_Buzz_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Buzz added successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Comments_Form = SupportCommentsForm()

                
                elif form_type == 'comment':
                    Support_Comments_Form = SupportCommentsForm(request.POST)
                    if Support_Comments_Form.is_valid():
                        Support_Comments_Form = Support_Comments_Form.save(commit=False)
                        Support_Comments_Form.support_group = instance_SupportGroup
                        Support_Comments_Form.comment_user = request.user
                        Support_Comments_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Comment added successfully.')

                        return redirect('support_group_selected', url_text=url_text)

                    else:
                        SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                        SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                        SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                        SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                        SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                        Support_Updates_Form = SupportUpdatesForm()
                        Support_Buzz_Form = SupportBuzzForm()



                else:
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    Support_Updates_Form = SupportUpdatesForm()
                    Support_Buzz_Form = SupportBuzzForm()
                    Support_Comments_Form = SupportCommentsForm()

            else:
                SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                Support_Updates_Form = SupportUpdatesForm()
                Support_Buzz_Form = SupportBuzzForm()
                Support_Comments_Form = SupportCommentsForm()

            
            instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).order_by("-id")
            instance_SupportComments = SupportComments.objects.filter(support_group=instance_SupportGroup).order_by("-id")
            instance_SupportUpdates = SupportUpdates.objects.filter(support_group=instance_SupportGroup).order_by("id")
            instance_SupportBuzz = SupportBuzz.objects.filter(support_group=instance_SupportGroup).order_by("id")

            current_site = get_current_site(request)
            domain = current_site.domain

            context = {
                'instance_SupportGroup':instance_SupportGroup,
                'instance_SupportGroupMembers':instance_SupportGroupMembers,
                'instance_SupportComments':instance_SupportComments,
                'instance_SupportUpdates':instance_SupportUpdates,
                'instance_SupportBuzz':instance_SupportBuzz,

                'SupportGroup_Goal_Form':SupportGroup_Goal_Form,
                'SupportGroup_Title_Form':SupportGroup_Title_Form,
                'SupportGroup_Picture_Form':SupportGroup_Picture_Form,
                'SupportGroup_About_Form':SupportGroup_About_Form,
                'SupportGroup_ShortDescription_Form':SupportGroup_ShortDescription_Form,
                'Support_Updates_Form':Support_Updates_Form,
                'Support_Buzz_Form':Support_Buzz_Form,
                'Support_Comments_Form':Support_Comments_Form,

                'group_member':group_member,
                'is_not_joined':is_not_joined,
                'is_authorised_for_edit':is_authorised_for_edit,

                'Today':datetime.now().date(),
                'domain':domain,
            }

            return render(request, 'before_login/support_group_selected.html', context)
        else:
            if request.user.is_authenticated:
                group_member_count = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).count()
                if group_member_count != 0:
                    group_member = True
                else:
                    group_member = False
            else:
                group_member = False


            if request.user.is_authenticated:
                dublicate_count =  SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).count()
                try:
                    if instance_SupportGroup.group_leader.id == request.user.id:
                        is_not_joined = False
                    elif dublicate_count != 0:
                        is_not_joined = False
                    else:
                        is_not_joined = True
                except:
                    is_not_joined = True
            else:
                is_not_joined = True


            if request.method == 'POST':
                form_type = request.POST.get('form_type', None)
                if form_type == 'comment':
                    if request.user.is_authenticated:
                        Support_Comments_Form = SupportCommentsForm(request.POST)
                        if Support_Comments_Form.is_valid():
                            Support_Comments_Form = Support_Comments_Form.save(commit=False)
                            Support_Comments_Form.comment_user = request.user
                            Support_Comments_Form.support_group = instance_SupportGroup
                            Support_Comments_Form.save()

                            messages.add_message(request,messages.SUCCESS,'Comment added successfully.')

                            return redirect('support_group_selected', url_text=url_text)
                        else:
                            Support_Group_Members_Forms = SupportGroupMembersForms()
                    else:
                        messages.add_message(request,messages.ERROR,'for comment authenticate must be need.')
                        return redirect('login')

                elif form_type == 'GroupMembers':
                    Support_Group_Members_Forms = SupportGroupMembersForms(request.POST)
                    if Support_Group_Members_Forms.is_valid():
                        post_email = Support_Group_Members_Forms.cleaned_data['email']


                        if request.user.is_authenticated:
                            dublicate_count =  SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).count()
                            try:
                                if instance_SupportGroup.group_leader.id == request.user.id:
                                    messages.add_message(request,messages.SUCCESS,"You can't join your own mobilisation campaign.")
                                    return redirect('support_group_selected', url_text=url_text)
                                elif dublicate_count != 0:
                                    messages.add_message(request,messages.SUCCESS,"You have already joined this mobilisation campaign.")
                                    return redirect('support_group_selected', url_text=url_text)
                                else:
                                    pass
                            except:
                                pass
                        else:
                            dublicate_count =  SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, email__iexact=post_email).count()
                            check_owner =  SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, support_group__group_leader__email__iexact=post_email).count()
                            if dublicate_count != 0:
                                messages.add_message(request,messages.SUCCESS,"You have already joined this mobilisation campaign.")
                                return redirect('support_group_selected', url_text=url_text)

                            elif check_owner != 0:
                                messages.add_message(request,messages.SUCCESS,"You can't join your own mobilisation campaign.")
                                return redirect('support_group_selected', url_text=url_text)



                        Support_Group_Members_Forms = Support_Group_Members_Forms.save(commit=False)
                        Support_Group_Members_Forms.support_group = instance_SupportGroup
                        if request.user.is_authenticated:
                            Support_Group_Members_Forms.group_member = request.user

                        Support_Group_Members_Forms.source = source

                        Support_Group_Members_Forms.save()

                        try:
                            current_site = get_current_site(request)
                            mail_subject = 'Thank you for supporting us.'
                            message = render_to_string('email_template/my_mobilisation_campaign_supporter_reminder_email.html', {
                                'domain': current_site.domain,
                                'instance_SupportGroupMembers':Support_Group_Members_Forms,
                            })
                            email = EmailMultiAlternatives(
                                                mail_subject, message, to=[Support_Group_Members_Forms.email]
                                )
                            email.attach_alternative(message, "text/html")
                            email.send()
                        except:
                            pass

                        messages.add_message(request,messages.SUCCESS,'Thank you.')

                        return redirect('support_group_selected', url_text=url_text)
                    
                    else:
                        Support_Comments_Form = SupportCommentsForm()

                else:
                    Support_Comments_Form = SupportCommentsForm()
                    Support_Group_Members_Forms = SupportGroupMembersForms()
                        


            else:
                Support_Comments_Form = SupportCommentsForm()
                Support_Group_Members_Forms = SupportGroupMembersForms()

            
            instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).order_by("-id")
            instance_SupportComments = SupportComments.objects.filter(support_group=instance_SupportGroup).order_by("-id")
            instance_SupportUpdates = SupportUpdates.objects.filter(support_group=instance_SupportGroup).order_by("id")
            instance_SupportBuzz = SupportBuzz.objects.filter(support_group=instance_SupportGroup).order_by("id")

            current_site = get_current_site(request)
            domain = current_site.domain

            context = {
                'instance_SupportGroup':instance_SupportGroup,
                'instance_SupportGroupMembers':instance_SupportGroupMembers,
                'instance_SupportComments':instance_SupportComments,
                'instance_SupportUpdates':instance_SupportUpdates,
                'instance_SupportBuzz':instance_SupportBuzz,

                'Support_Comments_Form':Support_Comments_Form,
                'Support_Group_Members_Forms':Support_Group_Members_Forms,

                'group_member':group_member,
                'is_not_joined':is_not_joined,
                'is_authorised_for_edit':is_authorised_for_edit,

                'Today':datetime.now().date(),
                'domain':domain,
            }

            return render(request, 'before_login/support_group_selected.html', context)
    except:
        return redirect('discover')


@login_required
@end_user_required
def report_support_group_selected(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID)

        instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))

        current_site = get_current_site(request)

        mail_subject = "Report Mobilisation Campaign"
        message = render_to_string('email_template/report_start_group.html',{
            'domain': current_site.domain,
            'instance_SupportGroup':instance_SupportGroup,
            'instance_user':request.user,
        })
        
        email = EmailMultiAlternatives(
            mail_subject, message, to=instance_admin_email
        )
        email.attach_alternative(message, "text/html")
        email.send()


        messages.add_message(request,messages.SUCCESS,'report send to admin successfully.')
        return redirect('support_group_selected', url_text=instance_SupportGroup.url_text)
        
    except:
        return redirect('discover')


@login_required
@end_user_required
def ask_update_support_group_selected(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID)

        instance_user = request.user

        current_site = get_current_site(request)

        mail_subject = "Update query"
        message = render_to_string('email_template/ask_support_group_update.html',{
            'domain': current_site.domain,
            'instance_SupportGroup':instance_SupportGroup,
            'instance_user':instance_user,
        })
        
        email = EmailMultiAlternatives(
            mail_subject, message, to=[instance_SupportGroup.group_leader.email]
        )
        email.attach_alternative(message, "text/html")
        email.send()


        messages.add_message(request,messages.SUCCESS,'Email send successfully.')
        return redirect('support_group_selected', name=instance_SupportGroup.url_text)
    except:
        return redirect('discover')





def event_selected(request, url_text):
    try:

        instance_Event = Event.objects.get(url_text=url_text)

        source = request.GET.get('source')

        try:
            save_event_visiter(request, instance_Event)
        except:
            pass

        is_authorised_for_edit = False
        if request.user.is_authenticated:
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                is_authorised_for_edit = True
            elif instance_Event.user.id == request.user.id:
                is_authorised_for_edit = False
            else:
                is_authorised_for_edit = False
        else:
            pass


        if is_authorised_for_edit:
            event_member = True
            is_not_joined = False


            if request.method == "POST":
                form_type = request.POST.get('form_type', None)

                if form_type == 'Title':
                    Event_Title_Form = EventTitleForm(request.POST, instance=instance_Event)
                    if Event_Title_Form.is_valid():
                        Event_Title_Form = Event_Title_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Title updated successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Buzz_Form = EventBuzzForm()
                        Event_Comments_Form = EventCommentsForm()



                elif form_type == 'Picture':
                    Event_Picture_Form = EventPictureForm(request.POST, request.FILES, instance=instance_Event)
                    if Event_Picture_Form.is_valid():
                        Event_Picture_Form = Event_Picture_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Picture updated successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Buzz_Form = EventBuzzForm()
                        Event_Comments_Form = EventCommentsForm()




                elif form_type == 'About':
                    Event_About_Form = EventAboutForm(request.POST, instance=instance_Event)
                    if Event_About_Form.is_valid():
                        Event_About_Form = Event_About_Form.save()

                        messages.add_message(request,messages.SUCCESS,'About updated successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Buzz_Form = EventBuzzForm()
                        Event_Comments_Form = EventCommentsForm()


                if form_type == 'Location':
                    Event_Place_Form = EventPlaceForm(request.POST, instance=instance_Event)
                    if Event_Place_Form.is_valid():
                        Event_Place_Form = Event_Place_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Location updated successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Buzz_Form = EventBuzzForm()
                        Event_Comments_Form = EventCommentsForm()


                if form_type == 'Date':
                    Event_Date_Form = EventDateForm(request.POST, instance=instance_Event)
                    if Event_Date_Form.is_valid():
                        Event_Date_Form = Event_Date_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Date updated successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Buzz_Form = EventBuzzForm()
                        Event_Comments_Form = EventCommentsForm()


                elif form_type == 'Updates':
                    Event_Updates_Form = EventUpdatesForm(request.POST)
                    if Event_Updates_Form.is_valid():
                        Event_Updates_Form = Event_Updates_Form.save(commit=False)
                        Event_Updates_Form.event = instance_Event
                        Event_Updates_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Update added successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Buzz_Form = EventBuzzForm()
                        Event_Comments_Form = EventCommentsForm()


                elif form_type == 'Buzz':
                    Event_Buzz_Form = EventBuzzForm(request.POST, request.FILES)
                    if Event_Buzz_Form.is_valid():
                        Event_Buzz_Form = Event_Buzz_Form.save(commit=False)
                        Event_Buzz_Form.event = instance_Event
                        Event_Buzz_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Buzz added successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Comments_Form = EventCommentsForm()

                elif form_type == 'comment':
                    Event_Comments_Form = EventCommentsForm(request.POST)
                    if Event_Comments_Form.is_valid():
                        Event_Comments_Form = Event_Comments_Form.save(commit=False)
                        Event_Comments_Form.event = instance_Event
                        Event_Comments_Form.comment_user = request.user
                        Event_Comments_Form.save()

                        messages.add_message(request,messages.SUCCESS,'Comment added successfully.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Title_Form = EventTitleForm(instance=instance_Event)
                        Event_Picture_Form = EventPictureForm(instance=instance_Event)
                        Event_About_Form = EventAboutForm(instance=instance_Event)
                        Event_Place_Form = EventPlaceForm(instance=instance_Event)
                        Event_Date_Form = EventDateForm(instance=instance_Event)
                        Event_Updates_Form = EventUpdatesForm()
                        Event_Buzz_Form = EventBuzzForm()



                else:
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    Event_Updates_Form = EventUpdatesForm()
                    Event_Buzz_Form = EventBuzzForm()
                    Event_Comments_Form = EventCommentsForm()

            else:
                Event_Title_Form = EventTitleForm(instance=instance_Event)
                Event_Picture_Form = EventPictureForm(instance=instance_Event)
                Event_About_Form = EventAboutForm(instance=instance_Event)
                Event_Place_Form = EventPlaceForm(instance=instance_Event)
                Event_Date_Form = EventDateForm(instance=instance_Event)
                Event_Updates_Form = EventUpdatesForm()
                Event_Buzz_Form = EventBuzzForm()
                Event_Comments_Form = EventCommentsForm()

            
            instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event).order_by("-id")
            instance_EventComments = EventComments.objects.filter(event=instance_Event).order_by("-id")
            instance_EventUpdates = EventUpdates.objects.filter(event=instance_Event).order_by("id")
            instance_EventBuzz = EventBuzz.objects.filter(event=instance_Event).order_by("id")

            current_site = get_current_site(request)
            domain = current_site.domain

            context = {
                'instance_Event':instance_Event,
                'instance_EventGroupMembers':instance_EventGroupMembers,
                'instance_EventComments':instance_EventComments,
                'instance_EventUpdates':instance_EventUpdates,
                'instance_EventBuzz':instance_EventBuzz,


                'Event_Title_Form':Event_Title_Form,
                'Event_Picture_Form':Event_Picture_Form,
                'Event_About_Form':Event_About_Form,
                'Event_Place_Form':Event_Place_Form,
                'Event_Date_Form':Event_Date_Form,
                'Event_Updates_Form':Event_Updates_Form,
                'Event_Buzz_Form':Event_Buzz_Form,
                'Event_Comments_Form':Event_Comments_Form,

                'is_not_joined':is_not_joined,
                'event_member':event_member,
                'is_authorised_for_edit':is_authorised_for_edit,

                'Today':datetime.now().date(),
                'domain':domain,
            }

            return render(request, 'before_login/event_selected.html', context)
        else:
            if request.user.is_authenticated:
                event_member_count = EventGroupMembers.objects.filter(event=instance_Event).filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).count()
                if event_member_count != 0:
                    event_member = True
                else:
                    event_member = False
            else:
                event_member = False


            if request.user.is_authenticated:
                dublicate_count =  EventGroupMembers.objects.filter(event=instance_Event).filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).count()
                try:
                    if instance_Event.user.id == request.user.id:
                        is_not_joined = False
                    elif dublicate_count != 0:
                        is_not_joined = False
                    else:
                        is_not_joined = True
                except:
                    is_not_joined = True
            else:
                is_not_joined = True


            if request.method == 'POST':
                form_type = request.POST.get('form_type', None)
                if form_type == 'comment':
                    if request.user.is_authenticated:
                        Event_Comments_Form = EventCommentsForm(request.POST)
                        if Event_Comments_Form.is_valid():
                            Event_Comments_Form = Event_Comments_Form.save(commit=False)
                            Event_Comments_Form.comment_user = request.user
                            Event_Comments_Form.event = instance_Event
                            Event_Comments_Form.save()

                            messages.add_message(request,messages.SUCCESS,'Comment added successfully.')

                            return redirect('event_selected', url_text=url_text)
                        else:
                            Event_GroupMembers_Forms = EventGroupMembersForms()
                    else:
                        messages.add_message(request,messages.ERROR,'for comment authenticate must be need.')
                        return redirect('login')

                elif form_type == 'GroupMembers':
                    Event_GroupMembers_Forms = EventGroupMembersForms(request.POST)
                    if Event_GroupMembers_Forms.is_valid():
                        post_email = Event_GroupMembers_Forms.cleaned_data['email']


                        if request.user.is_authenticated:
                            dublicate_count =  EventGroupMembers.objects.filter(event=instance_Event).filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).count()
                            try:
                                if instance_Event.user.id == request.user.id:
                                    messages.add_message(request,messages.SUCCESS,"You can't join your own mobilisation campaign.")
                                    return redirect('event_selected', url_text=url_text)
                                elif dublicate_count != 0:
                                    messages.add_message(request,messages.SUCCESS,"You have already joined this mobilisation campaign.")
                                    return redirect('event_selected', url_text=url_text)
                                else:
                                    pass
                            except:
                                pass
                        else:
                            dublicate_count =  EventGroupMembers.objects.filter(event=instance_Event, email__iexact=post_email).count()
                            check_owner =  EventGroupMembers.objects.filter(event=instance_Event, event__user__email__iexact=post_email).count()
                            if dublicate_count != 0:
                                messages.add_message(request,messages.SUCCESS,"You have already joined this mobilisation campaign.")
                                return redirect('event_selected', url_text=url_text)

                            elif check_owner != 0:
                                messages.add_message(request,messages.SUCCESS,"You can't join your own mobilisation campaign.")
                                return redirect('event_selected', url_text=url_text)



                        Event_GroupMembers_Forms = Event_GroupMembers_Forms.save(commit=False)
                        Event_GroupMembers_Forms.event = instance_Event
                        if request.user.is_authenticated:
                            Event_GroupMembers_Forms.group_member = request.user

                        Event_GroupMembers_Forms.source = source

                        Event_GroupMembers_Forms.save()


                        try:
                            current_site = get_current_site(request)
                            mail_subject = 'Thank you for supporting us.'
                            message = render_to_string('email_template/my_event_campaign_supporter_reminder_email.html', {
                                'domain': current_site.domain,
                                'instance_EventGroupMembers':Event_GroupMembers_Forms,
                            })
                            email = EmailMultiAlternatives(
                                                mail_subject, message, to=[Event_GroupMembers_Forms.email]
                                )
                            email.attach_alternative(message, "text/html")
                            email.send()
                        except:
                            pass

                        messages.add_message(request,messages.SUCCESS,'Thank you.')

                        return redirect('event_selected', url_text=url_text)

                    else:
                        Event_Comments_Form = EventCommentsForm()

                else:
                    Event_Comments_Form = EventCommentsForm()
                    Event_GroupMembers_Forms = EventGroupMembersForms()
                        


            else:
                Event_Comments_Form = EventCommentsForm()
                Event_GroupMembers_Forms = EventGroupMembersForms()

            
            instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event).order_by("-id")
            instance_EventComments = EventComments.objects.filter(event=instance_Event).order_by("-id")
            instance_EventUpdates = EventUpdates.objects.filter(event=instance_Event).order_by("id")
            instance_EventBuzz = EventBuzz.objects.filter(event=instance_Event).order_by("id")

            current_site = get_current_site(request)
            domain = current_site.domain

            context = {

                'instance_Event':instance_Event,
                'instance_EventGroupMembers':instance_EventGroupMembers,
                'instance_EventComments':instance_EventComments,
                'instance_EventUpdates':instance_EventUpdates,
                'instance_EventBuzz':instance_EventBuzz,


                'Event_Comments_Form':Event_Comments_Form,
                'Event_GroupMembers_Forms':Event_GroupMembers_Forms,

                'is_not_joined':is_not_joined,
                'event_member':event_member,
                'is_authorised_for_edit':is_authorised_for_edit,

                'Today':datetime.now().date(),
                'domain':domain,
            }

            return render(request, 'before_login/event_selected.html', context)
    except:
        return redirect('discover')



@login_required
@end_user_required
def report_event_selected(request, ID):
    try:
        instance_Event = Event.objects.get(id=ID)

        instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))

        current_site = get_current_site(request)

        mail_subject = "Report Event"
        message = render_to_string('email_template/report_event.html',{
            'domain': current_site.domain,
            'instance_Event':instance_Event,
            'instance_user':request.user,
        })
        
        email = EmailMultiAlternatives(
            mail_subject, message, to=instance_admin_email
        )
        email.attach_alternative(message, "text/html")
        email.send()


        messages.add_message(request,messages.SUCCESS,'report send to admin successfully.')
        return redirect('event_selected', url_text=instance_Event.url_text)
        
    except:
        return redirect('discover')


@login_required
@end_user_required
def ask_update_event_selected(request, ID):
    try:
        instance_Event = Event.objects.get(id=ID)

        instance_user = request.user

        current_site = get_current_site(request)

        mail_subject = "Update query"
        message = render_to_string('email_template/ask_update_event.html',{
            'domain': current_site.domain,
            'instance_Event':instance_Event,
            'instance_user':instance_user,
        })
        
        email = EmailMultiAlternatives(
            mail_subject, message, to=[instance_Event.user.email]
        )
        email.attach_alternative(message, "text/html")
        email.send()


        messages.add_message(request,messages.SUCCESS,'Email send successfully.')
        return redirect('event_selected', url_text=instance_Event.url_text)
    except:
        return redirect('discover')





#------------------------------------------ end all user ------------------------------------------------#


#------------------------------------------ start admin view ----------------------------------------------#
def admin_analytics(request):
    Today = datetime.now().date() 

    today_supporters = SupportGroupMembers.objects.filter(created_at__gte=Today).count()
    total_supporters = SupportGroupMembers.objects.all().count()

    total_supporters_graph = SupportGroupMembers.objects.all().extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at')

    today_visit = SupportVisitHistory.objects.filter(created_at__gte=Today).count()
    total_visit = SupportVisitHistory.objects.all().count()
    previous_total_visit = SupportVisitHistory.objects.all().exclude(created_at__gte=Today).count()

    total_visit_graph = SupportVisitHistory.objects.all().extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at')

    try:
        today_increases = round(((today_visit - previous_total_visit) / today_visit) * 100, 2)
    except:
        today_increases = 0

    context = {
       'today_supporters':today_supporters,
       'total_supporters':total_supporters,
       'total_supporters_graph':total_supporters_graph,

       'today_visit':today_visit,
       'total_visit':total_visit,
       'total_visit_graph':total_visit_graph,

       'today_increases':today_increases,

    }
    return render(request, 'admin_template/admin_analytics.html', context)


@login_required
@admin_or_backend_user_required
def admin_dashboard(request):
    if request.is_ajax():
        category = request.GET.get('category', None)
        status = request.GET.get('status', None)
        cause = request.GET.get('cause', None)
        sensitivity = request.GET.get('sensitivity', None)
        object_id = request.GET.get('object_id', None)

        if category:
            category = category.lower()
            category = category.strip()
        if status:
            status = status.lower()
            status = status.strip()
        if object_id == 'all':
            object_id = None
        if sensitivity == 'all':
            sensitivity = None
        if cause == 'all':
            cause = None

        Today = datetime.now().date()

        if category == 'event':
            instance_Event = Event.objects.all().order_by('-id')
            if status == 'approval request':
                instance_Event = instance_Event.filter(is_active=False, date__gte=Today)
            elif status == 'completed':
                instance_Event = instance_Event.filter(date__lt=Today)
            else :
                instance_Event = instance_Event.filter(is_active=True, date__gte=Today)
            
            if object_id:
                instance_Event = instance_Event.filter(id=object_id)
            if sensitivity:
                instance_Event = instance_Event.filter(sensitivity__iexact=sensitivity)
            if cause:
                instance_Event = instance_Event.filter(cause__id=cause)



            paginator  = Paginator(instance_Event, 6)
            page = request.GET.get('page')
            try: 
                instance_Event = paginator.page(page)
            except PageNotAnInteger:
                instance_Event = paginator.page(1)
            except EmptyPage:
                instance_Event = paginator.page(Paginator.num_pages)

            instance_CauseCategory = CauseCategory.objects.filter(is_active=True)

            context = {
                'instance_Event':instance_Event,
                'instance_CauseCategory':instance_CauseCategory,
                'sensitivity_choices':sensitivity_choices,
                'block':'event',
            }
            return render(request, 'admin_template/dashboard_ajax.html', context)

        elif category == 'mobilisation campaign':
            instance_SupportGroup = SupportGroup.objects.all().order_by('-id')
            if status == 'approval request':
                instance_SupportGroup = instance_SupportGroup.filter(is_active=False)
            elif status == 'completed':
                completed_support_group = []
                for i in instance_SupportGroup:
                    if i.group_member_count() >= i.goal:
                        completed_support_group.append(i.id)

                instance_SupportGroup = SupportGroup.objects.filter(id__in=completed_support_group)
            else :
                instance_SupportGroup = instance_SupportGroup.filter(is_active=True)

            if object_id :
                instance_SupportGroup = instance_SupportGroup.filter(id=object_id)
            if sensitivity:
                instance_SupportGroup = instance_SupportGroup.filter(sensitivity__iexact=sensitivity)
            if cause:
                instance_SupportGroup = instance_SupportGroup.filter(cause__id=cause)


            paginator  = Paginator(instance_SupportGroup, 6)
            page = request.GET.get('page')
            try: 
                instance_SupportGroup = paginator.page(page)
            except PageNotAnInteger:
                instance_SupportGroup = paginator.page(1)
            except EmptyPage:
                instance_SupportGroup = paginator.page(Paginator.num_pages)

            instance_CauseCategory = CauseCategory.objects.filter(is_active=True)

            context = {
                'instance_SupportGroup':instance_SupportGroup,
                'instance_CauseCategory':instance_CauseCategory,
                'sensitivity_choices':sensitivity_choices,
                'block':'supportgroup',
            }

            print('instance_SupportGroup : ', instance_SupportGroup)
            return render(request, 'admin_template/dashboard_ajax.html', context)

        elif category == 'fundraiser':
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by('-id')
            if status == 'approval request':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=False, end_date__gte=Today)
            elif status == 'completed':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(end_date__lt=Today)
            else :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=True, end_date__gte=Today)

            if object_id :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(id=object_id)
            if sensitivity :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(sensitivity__iexact=sensitivity)
            if cause :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(cause__id=cause)

            paginator  = Paginator(instance_CampaignFundRaiser, 6)
            page = request.GET.get('page')
            try: 
                instance_CampaignFundRaiser = paginator.page(page)
            except PageNotAnInteger:
                instance_CampaignFundRaiser = paginator.page(1)
            except EmptyPage:
                instance_CampaignFundRaiser = paginator.page(Paginator.num_pages)

            instance_CauseCategory = CauseCategory.objects.filter(is_active=True)

            context = {
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
                'instance_CauseCategory':instance_CauseCategory,
                'sensitivity_choices':sensitivity_choices,
                'block':'fundraiser',
            }
            return render(request, 'admin_template/dashboard_ajax.html', context)

        else:
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by('-id')
            if status == 'approval request':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=False, end_date__gte=Today)
            elif status == 'completed':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(end_date__lt=Today)
            else :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=True, end_date__gte=Today)

            if object_id :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(id=object_id)
            if sensitivity :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(sensitivity__iexact=sensitivity)
            if cause :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(cause__id=cause)

            
            paginator  = Paginator(instance_CampaignFundRaiser, 6)
            page = request.GET.get('page')
            try: 
                instance_CampaignFundRaiser = paginator.page(page)
            except PageNotAnInteger:
                instance_CampaignFundRaiser = paginator.page(1)
            except EmptyPage:
                instance_CampaignFundRaiser = paginator.page(Paginator.num_pages)

            instance_CauseCategory = CauseCategory.objects.filter(is_active=True)

            context = {
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
                'instance_CauseCategory':instance_CauseCategory,
                'sensitivity_choices':sensitivity_choices,
                'block':'fundraiser',
            }
            return render(request, 'admin_template/dashboard_ajax.html', context)

    else:
        pass

    return render(request, 'admin_template/admin_dashboard.html')

@login_required
@admin_or_backend_user_required
def admin_campaign_user(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)
        instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured')
        context = {
            'instance_CampaignDoners':instance_CampaignDoners,
        }
        return render(request, 'admin_template/campaign_user.html', context)
    except:
        pass

    return redirect('admin_dashboard')

@login_required
@admin_or_backend_user_required
def admin_event_user(request, ID):
    try:
        instance_Event = Event.objects.get(id=ID)
        instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event, is_share=True)
        context = {
            'instance_EventGroupMembers':instance_EventGroupMembers,
        }
        return render(request, 'user_template/my_event_user.html', context)
    except:
        pass

    return redirect('dashboard')

@login_required
@admin_or_backend_user_required
def admin_campaign_funds_summary(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)
        instance_WithdrawalRequest = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser).order_by("-id")

        try:
            instance_WithdrawalRequest_latest = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser, status='Approved').order_by("-id")[0]
        except:
            instance_WithdrawalRequest_latest = False
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_WithdrawalRequest':instance_WithdrawalRequest,
            'instance_WithdrawalRequest_latest':instance_WithdrawalRequest_latest,


        }
        return render(request, 'admin_template/campaign_funds_summary.html', context)
    except:
        pass

    return redirect('admin_dashboard')

@login_required
@admin_or_backend_user_required
def admin_support_group_user(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID)
        instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, is_share=True)
        context = {
            'instance_SupportGroupMembers':instance_SupportGroupMembers,
        }
        return render(request, 'admin_template/my_support_group_user.html', context)
    except:
        pass

    return redirect('admin_dashboard')

@login_required
@admin_or_backend_user_required
def admin_crm(request):
    if request.is_ajax():
        campaign = request.GET.get('campaign', None)
        instance_query = request.GET.get('instance_query', None) 
        amount = request.GET.get('amount', None)
        city = request.GET.get('city', None)
        state = request.GET.get('state', None)

        if campaign == 'Event':
            instance_Event = Event.objects.all()
            instance_EventGroupMembers = EventGroupMembers.objects.all()

            if instance_query:
                if instance_query != 'all':
                    instance_Event = instance_Event.filter(id=instance_query)
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(event__id__in=instance_Event.values_list('id', flat=True).distinct())
                else:
                    pass

            if city:
                if city != 'all':
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(state__iexact=state)
                else:
                    pass

            table = render_to_string('admin_template/admin_crm_event_ajax.html',{
                'instance_EventGroupMembers':instance_EventGroupMembers,
            })

            if state:
                # writing respons
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            elif city:
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                }
                return JsonResponse(context)

            elif instance_query:
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_Event.values_list('id','name').distinct().order_by('name')
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing response
                context = {
                    'table':table,
                    'instance_query_list' : list(instance_query_list),
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

        elif campaign == 'Mobilisation Campaign':

            instance_SupportGroup = SupportGroup.objects.all()
            instance_SupportGroupMembers = SupportGroupMembers.objects.all()

            if instance_query:
                if instance_query != 'all':
                    instance_SupportGroup = instance_SupportGroup.filter(id=instance_query)
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(support_group__id__in=instance_SupportGroup.values_list('id', flat=True).distinct())
                else:
                    pass

            if city:
                if city != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(state__iexact=state)
                else:
                    pass


            table = render_to_string('admin_template/admin_crm_support_group_ajax.html',{
                'instance_SupportGroupMembers':instance_SupportGroupMembers,
            })

            if state:
                # writing respons
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            elif city:
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                }
                return JsonResponse(context)

            elif instance_query:
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_SupportGroup.values_list('id','title').distinct().order_by('title')
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'instance_query_list' : list(instance_query_list),
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

        else:
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.all()
            instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured')

            campaign_amount_list = CampaignDoners.objects.filter(payment_status='captured').values_list('amount', flat=True).distinct().order_by('amount')

            if instance_query:
                if instance_query != 'all':
                    instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(id=instance_query)
                    instance_CampaignDoners = instance_CampaignDoners.filter(campaign_fund_raiser__id__in=instance_CampaignFundRaiser.values_list('id', flat=True).distinct())
                else:
                    pass

            if amount:
                if amount != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(amount=amount)
                else:
                    pass

            if city:
                if city != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(state__iexact=state)
                else:
                    pass

            table = render_to_string('admin_template/admin_crm_fundraiser_ajax.html',{
                'instance_CampaignDoners':instance_CampaignDoners,
            })

            # writing response
            if state:
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            if city:
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                context = {
                    'table':table,
                    'state_list' : list(campaign_state_list),
                }
                return JsonResponse(context)

            if amount:
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                context = {
                    'table':table,
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                }
                return JsonResponse(context)

            if instance_query:
                campaign_amount_list = instance_CampaignDoners.values_list('amount', flat=True).distinct().order_by('amount')
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                context = {
                    'campaign_amount_list' : list(campaign_amount_list),
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'table':table,
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_CampaignFundRaiser.values_list('id','title').distinct().order_by('title')
                campaign_amount_list = instance_CampaignDoners.values_list('amount', flat=True).distinct().order_by('amount')
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')

                context = {
                    'instance_query_list' : list(instance_query_list),
                    'campaign_amount_list' : list(campaign_amount_list),
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'table':table,
                }
                return JsonResponse(context)

    else:
        instance_query_list = CampaignFundRaiser.objects.values_list('id','title').distinct().order_by('title')
        campaign_amount_list = CampaignDoners.objects.filter(payment_status='captured').values_list('amount', flat=True).distinct().order_by('amount')
        campaign_city_list = CampaignDoners.objects.filter(payment_status='captured').values_list('city', flat=True).distinct().order_by('city')
        campaign_state_list = CampaignDoners.objects.filter(payment_status='captured').values_list('state', flat=True).distinct().order_by('state')
        instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured')
        context ={
            'instance_query_list':instance_query_list,
            'campaign_amount_list':campaign_amount_list,
            'campaign_city_list':campaign_city_list,
            'campaign_state_list':campaign_state_list,
            'instance_CampaignDoners':instance_CampaignDoners,
        }
        return render(request, 'admin_template/admin_crm.html', context)


@login_required
@admin_or_backend_user_required
def admin_crm_email(request):
    email = request.GET.getlist('id[]', None)
    email_message = request.GET.get('message', None)
    mail_subject = request.GET.get('subject', None)
    current_site = get_current_site(request)
    message = render_to_string('email_template/crm_email.html',{
        'email_message':email_message,
        'domain': current_site.domain,
    })
    email = EmailMultiAlternatives(
        mail_subject, message, to=email
    )
    email.attach_alternative(message, "text/html")
    email.send()

    context = {
        'message':'email send successfully'
    }
    return JsonResponse(context)


@login_required
@admin_or_backend_user_required
def admin_manage_category(request):
    form_error = False
    if request.method == 'POST':
        Campaign_Category_Form = CampaignCategoryForm(request.POST, request.FILES)
        if Campaign_Category_Form.is_valid():
            Campaign_Category_Form = Campaign_Category_Form.save()

            messages.add_message(request,messages.SUCCESS,'Category "%s" added successfully' %(Campaign_Category_Form.category))

            return redirect('admin_manage_category')

        else:
            form_error = True

    else:
        Campaign_Category_Form = CampaignCategoryForm()


    instance_CampaignCategory = CampaignCategory.objects.all().order_by("-id")
    context ={
        'instance_CampaignCategory':instance_CampaignCategory,
        'Campaign_Category_Form':Campaign_Category_Form,
        'form_error':form_error,
    }
    return render(request, 'admin_template/admin_manage_category.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_category_status(request, ID, status):
    try:
        instance_CampaignCategory = CampaignCategory.objects.get(id=ID)
        if status == "True":
            instance_CampaignCategory.is_active = True
            instance_CampaignCategory.save()

            messages.add_message(request,messages.SUCCESS,'Category "%s" activated successfully' %(instance_CampaignCategory.category))

        elif status == "False":
            instance_CampaignCategory.is_active = False
            instance_CampaignCategory.save()

            messages.add_message(request,messages.SUCCESS,'Category "%s" inactivate successfully' %(instance_CampaignCategory.category))
    except:
        pass
    return redirect('admin_manage_category')

@login_required
@admin_or_backend_user_required
def admin_manage_category_edit(request, ID):
    try:
        instance_CampaignCategory = CampaignCategory.objects.get(id=ID)
        if request.method == 'POST':
            Campaign_Category_Form = CampaignCategoryForm(request.POST, request.FILES, instance=instance_CampaignCategory)
            if Campaign_Category_Form.is_valid():
                Campaign_Category_Form = Campaign_Category_Form.save()

                messages.add_message(request,messages.SUCCESS,'Category "%s" updated successfully' %(Campaign_Category_Form.category))

                return redirect('admin_manage_category')
        else:
            Campaign_Category_Form = CampaignCategoryForm(instance=instance_CampaignCategory)
        
        context = {
            'Campaign_Category_Form':Campaign_Category_Form,
        }
        return render(request, 'admin_template/admin_manage_category_edit.html', context)
    except:
        return redirect('admin_manage_category')



@login_required
@admin_or_backend_user_required
def admin_manage_sub_category(request):
    form_error = False
    if request.method == 'POST':
        Campaign_SubCategory_Form = CampaignSubCategoryForm(request.POST, request.FILES)
        if Campaign_SubCategory_Form.is_valid():
            Campaign_SubCategory_Form = Campaign_SubCategory_Form.save()

            messages.add_message(request,messages.SUCCESS,'Sub-Category "%s" added successfully' %(Campaign_SubCategory_Form.sub_category))

            return redirect('admin_manage_sub_category')

        else:
            form_error = True

    else:
        Campaign_SubCategory_Form = CampaignSubCategoryForm()


    instance_CampaignSubCategory = CampaignSubCategory.objects.all().order_by("-id")
    context ={
        'instance_CampaignSubCategory':instance_CampaignSubCategory,
        'Campaign_SubCategory_Form':Campaign_SubCategory_Form,
        'form_error':form_error,
    }
    return render(request, 'admin_template/admin_manage_sub_category.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_sub_category_status(request, ID, status):
    try:
        instance_CampaignSubCategory = CampaignSubCategory.objects.get(id=ID)
        if status == "True":
            instance_CampaignSubCategory.is_active = True
            instance_CampaignSubCategory.save()

            messages.add_message(request,messages.SUCCESS,'Sub-Category "%s" activated successfully' %(instance_CampaignSubCategory.sub_category))

        elif status == "False":
            instance_CampaignSubCategory.is_active = False
            instance_CampaignSubCategory.save()

            messages.add_message(request,messages.SUCCESS,'Sub-Category "%s" inactivate successfully' %(instance_CampaignSubCategory.sub_category))
    except:
        pass
    return redirect('admin_manage_sub_category')

@login_required
@admin_or_backend_user_required
def admin_manage_sub_category_edit(request, ID):
    try:
        instance_CampaignSubCategory = CampaignSubCategory.objects.get(id=ID)
        if request.method == 'POST':
            Campaign_SubCategory_Form = CampaignSubCategoryEditForm(request.POST, request.FILES, instance=instance_CampaignSubCategory)
            if Campaign_SubCategory_Form.is_valid():
                Campaign_SubCategory_Form = Campaign_SubCategory_Form.save()

                messages.add_message(request,messages.SUCCESS,'Sub-Category "%s" updated successfully' %(Campaign_SubCategory_Form.sub_category))

                return redirect('admin_manage_sub_category')
        else:
            Campaign_SubCategory_Form = CampaignSubCategoryEditForm(instance=instance_CampaignSubCategory)
        
        context = {
            'Campaign_SubCategory_Form':Campaign_SubCategory_Form,
        }
        return render(request, 'admin_template/admin_manage_sub_category_edit.html', context)
    except:
        return redirect('admin_manage_sub_category')




@login_required
@admin_or_backend_user_required
def admin_manage_cause(request):
    form_error = False
    if request.method == 'POST':
        Cause_Category_Form = CauseCategoryForm(request.POST)
        if Cause_Category_Form.is_valid():
            Cause_Category_Form = Cause_Category_Form.save()

            messages.add_message(request,messages.SUCCESS,'Cause "%s" added successfully' %(Cause_Category_Form.cause))

            return redirect('admin_manage_cause')

        else:
            form_error = True

    else:
        Cause_Category_Form = CauseCategoryForm()


    instance_CauseCategory = CauseCategory.objects.all().order_by("-id")
    context ={
        'instance_CauseCategory':instance_CauseCategory,
        'Cause_Category_Form':Cause_Category_Form,
        'form_error':form_error,
    }
    return render(request, 'admin_template/admin_manage_cause.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_cause_status(request, ID, status):
    try:
        instance_CauseCategory = CauseCategory.objects.get(id=ID)
        if status == "True":
            instance_CauseCategory.is_active = True
            instance_CauseCategory.save()

            messages.add_message(request,messages.SUCCESS,'Cause "%s" activated successfully' %(instance_CauseCategory.cause))

        elif status == "False":
            instance_CauseCategory.is_active = False
            instance_CauseCategory.save()

            messages.add_message(request,messages.SUCCESS,'Cause "%s" inactivate successfully' %(instance_CauseCategory.cause))
    except:
        pass
    return redirect('admin_manage_cause')

@login_required
@admin_or_backend_user_required
def admin_manage_cause_edit(request, ID):
    try:
        instance_CauseCategory = CauseCategory.objects.get(id=ID)
        if request.method == 'POST':
            Cause_Category_Form = CauseCategoryForm(request.POST, instance=instance_CauseCategory)
            if Cause_Category_Form.is_valid():
                Cause_Category_Form = Cause_Category_Form.save()

                messages.add_message(request,messages.SUCCESS,'Cause "%s" updated successfully' %(Cause_Category_Form.cause))

                return redirect('admin_manage_cause')
        else:
            Cause_Category_Form = CauseCategoryForm(instance=instance_CauseCategory)
        
        context = {
            'Cause_Category_Form':Cause_Category_Form,
        }
        return render(request, 'admin_template/admin_manage_cause_edit.html', context)
    except:
        return redirect('admin_manage_cause')





@login_required
@admin_or_backend_user_required
def admin_manage_campaign(request):
    instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by("-id")
    context ={
        'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
    }
    return render(request, 'admin_template/admin_manage_campaign.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_campaign_status(request, ID, status):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)
        if status == "True":
            instance_CampaignFundRaiser.is_active = True
            instance_CampaignFundRaiser.save()

            messages.add_message(request,messages.SUCCESS,'Campaign "%s" activated successfully' %(instance_CampaignFundRaiser.title))

        elif status == "False":
            instance_CampaignFundRaiser.is_active = False
            instance_CampaignFundRaiser.save()

            messages.add_message(request,messages.SUCCESS,'Campaign "%s" inactivate successfully' %(instance_CampaignFundRaiser.title))
    except:
        pass
    return redirect('admin_manage_campaign')

@login_required
@admin_or_backend_user_required
def admin_manage_campaign_edit(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID)
        if request.method == 'POST':
            Admin_Campaign_FundRaiser_Form = AdminCampaignFundRaiserForm(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
            if Admin_Campaign_FundRaiser_Form.is_valid():
                Admin_Campaign_FundRaiser_Form = Admin_Campaign_FundRaiser_Form.save()

                return redirect("admin_manage_campaign")
        else:
            Admin_Campaign_FundRaiser_Form = AdminCampaignFundRaiserForm(instance=instance_CampaignFundRaiser)

        context = {
            'Admin_Campaign_FundRaiser_Form':Admin_Campaign_FundRaiser_Form,
        }
        return render(request, 'admin_template/admin_manage_campaign_edit.html', context)
    except:
        pass
    return redirect('admin_manage_campaign')


@login_required
@admin_or_backend_user_required
def admin_manage_campaign_action(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Fund_Raiser = request.GET.getlist('FundRaiser[]')
        Support_Group = request.GET.getlist('SupportGroup[]')
        Event_Event = request.GET.getlist('Event[]')

        instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(id__in=Fund_Raiser).order_by("-id")
        instance_SupportGroup = SupportGroup.objects.filter(id__in=Support_Group).order_by("-id")
        instance_Event = Event.objects.filter(id__in=Event_Event).order_by("-id")

        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_SupportGroup':instance_SupportGroup,
            'instance_Event':instance_Event,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_manage_campaign_action_ajax.html', context)
    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by("-id")
        instance_SupportGroup = SupportGroup.objects.all().order_by("-id")
        instance_Event = Event.objects.all().order_by("-id")

        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_SupportGroup':instance_SupportGroup,
            'instance_Event':instance_Event,
        }
        return render(request, 'admin_template/admin_manage_campaign_action.html', context) 

@login_required
@admin_or_backend_user_required
def admin_manage_support_group_member(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Support_Group = request.GET.getlist('SupportGroup[]')

        instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group__id__in=Support_Group)

        context = {
            'instance_SupportGroupMembers':instance_SupportGroupMembers,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_manage_support_group_member_ajax.html', context)
    else:
        instance_SupportGroup = SupportGroup.objects.all().order_by("-id")
        instance_SupportGroupMembers_count = SupportGroupMembers.objects.all().count()
        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'instance_SupportGroupMembers_count':instance_SupportGroupMembers_count,
        }
        return render(request, 'admin_template/admin_manage_support_group_member.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_mobilisation_member(request):
    if request.is_ajax():
        campaign = request.GET.get('campaign', None)
        instance_query = request.GET.get('instance_query', None) 
        amount = request.GET.get('amount', None)
        city = request.GET.get('city', None)
        state = request.GET.get('state', None)
        country = request.GET.get('country', None)

        if campaign == 'Event':
            instance_Event = Event.objects.all()
            instance_EventGroupMembers = EventGroupMembers.objects.all()

            if instance_query:
                if instance_query != 'all':
                    instance_Event = instance_Event.filter(id=instance_query)
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(event__id__in=instance_Event.values_list('id', flat=True).distinct())
                else:
                    pass

            if city:
                if city != 'all':
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(state__iexact=state)
                else:
                    pass

            table = render_to_string('admin_template/admin_manage_mobilisation_member_ajax.html',{
                'instance_EventGroupMembers':instance_EventGroupMembers,
            })

            if state:
                # writing respons
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            elif city:
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                }
                return JsonResponse(context)

            elif instance_query:
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_Event.values_list('id','name').distinct().order_by('name')
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing response
                context = {
                    'table':table,
                    'instance_query_list' : list(instance_query_list),
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

        elif campaign == 'Mobilisation Campaign':

            instance_SupportGroup = SupportGroup.objects.all()
            instance_SupportGroupMembers = SupportGroupMembers.objects.all()

            if instance_query:
                if instance_query != 'all':
                    instance_SupportGroup = instance_SupportGroup.filter(id=instance_query)
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(support_group__id__in=instance_SupportGroup.values_list('id', flat=True).distinct())
                else:
                    pass

            if city:
                if city != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(state__iexact=state)
                else:
                    pass

            if country:
                if state != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(country__iexact=country)
                else:
                    pass


            table = render_to_string('admin_template/admin_manage_mobilisation_member_ajax.html',{
                'instance_SupportGroupMembers':instance_SupportGroupMembers,
            })

            if country:
                # writing respons
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            if state:
                country_list = instance_SupportGroupMembers.values_list('country', flat=True).distinct().order_by('country')
                # writing respons
                context = {
                    'table':table,
                    'country_list':list(country_list),
                }
                return JsonResponse(context)

            elif city:
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                country_list = instance_SupportGroupMembers.values_list('country', flat=True).distinct().order_by('country')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'country_list':list(country_list),
                }
                return JsonResponse(context)

            elif instance_query:
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                country_list = instance_SupportGroupMembers.values_list('country', flat=True).distinct().order_by('country')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                    'country_list':list(country_list),
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_SupportGroup.values_list('id','title').distinct().order_by('title')
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                country_list = instance_SupportGroupMembers.values_list('country', flat=True).distinct().order_by('country')
                # writing respons
                context = {
                    'table':table,
                    'instance_query_list' : list(instance_query_list),
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                    'country_list':list(country_list),
                }
                return JsonResponse(context)

        else:
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.all()
            instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured')

            campaign_amount_list = CampaignDoners.objects.filter(payment_status='captured').values_list('amount', flat=True).distinct().order_by('amount')

            if instance_query:
                if instance_query != 'all':
                    instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(id=instance_query)
                    instance_CampaignDoners = instance_CampaignDoners.filter(campaign_fund_raiser__id__in=instance_CampaignFundRaiser.values_list('id', flat=True).distinct())
                else:
                    pass

            if amount:
                if amount != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(amount=amount)
                else:
                    pass

            if city:
                if city != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(state__iexact=state)
                else:
                    pass

            if country:
                if country != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(country__iexact=country)
                else:
                    pass

            table = render_to_string('admin_template/admin_manage_mobilisation_member_ajax.html',{
                'instance_CampaignDoners':instance_CampaignDoners,
            })

            # writing response

            if country:
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            if state:
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'table':table,
                    'country_list' : list(campaign_country_list),
                }
                return JsonResponse(context)

            if city:
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'table':table,
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                }
                return JsonResponse(context)

            if amount:
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'table':table,
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                }
                return JsonResponse(context)

            if instance_query:
                campaign_amount_list = instance_CampaignDoners.values_list('amount', flat=True).distinct().order_by('amount')
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'campaign_amount_list' : list(campaign_amount_list),
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                    'table':table,
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_CampaignFundRaiser.values_list('id','title').distinct().order_by('title')
                campaign_amount_list = instance_CampaignDoners.values_list('amount', flat=True).distinct().order_by('amount')
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')

                context = {
                    'instance_query_list' : list(instance_query_list),
                    'campaign_amount_list' : list(campaign_amount_list),
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                    'table':table,
                }
                return JsonResponse(context)

    else:
        instance_SupportGroup = SupportGroup.objects.all()
        instance_SupportGroupMembers = SupportGroupMembers.objects.all()
        instance_query_list = instance_SupportGroup.values_list('id','title').distinct().order_by('title')
        campaign_state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
        campaign_city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
        campaign_country_list = instance_SupportGroupMembers.values_list('country', flat=True).distinct().order_by('country')
        # writing respons
        context = {
            'instance_query_list' : instance_query_list,
            'campaign_state_list' : campaign_state_list,
            'campaign_city_list':campaign_city_list,
            'campaign_country_list':campaign_country_list,
            'instance_SupportGroupMembers':instance_SupportGroupMembers
        }
        # instance_query_list = CampaignFundRaiser.objects.values_list('id','title').distinct().order_by('title')
        # campaign_amount_list = CampaignDoners.objects.filter(payment_status='captured').values_list('amount', flat=True).distinct().order_by('amount')
        # campaign_city_list = CampaignDoners.objects.filter(payment_status='captured').values_list('city', flat=True).distinct().order_by('city')
        # campaign_state_list = CampaignDoners.objects.filter(payment_status='captured').values_list('state', flat=True).distinct().order_by('state')
        # campaign_country_list = CampaignDoners.objects.filter(payment_status='captured').values_list('country', flat=True).distinct().order_by('country')
        # instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured')
        # context ={
        #     'instance_query_list':instance_query_list,
        #     'campaign_amount_list':campaign_amount_list,
        #     'campaign_city_list':campaign_city_list,
        #     'campaign_state_list':campaign_state_list,
        #     'campaign_country_list':campaign_country_list,
        #     'instance_CampaignDoners':instance_CampaignDoners,
        # }
        return render(request, 'admin_template/admin_manage_mobilisation_member.html', context)

@login_required
@admin_or_backend_user_required
def admin_fundraiser_campaign_member(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Campaign_Doners = request.GET.getlist('CampaignDoners[]')

        instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser__id__in=Campaign_Doners, payment_status='captured')

        context = {
            'instance_CampaignDoners':instance_CampaignDoners,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_fundraiser_campaign_member_ajax.html', context)
    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by('-id')
        instance_CampaignDoners_count = CampaignDoners.objects.all().count()
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignDoners_count':instance_CampaignDoners_count,
        }
        return render(request, 'admin_template/admin_fundraiser_campaign_member.html', context)


@login_required
@admin_or_backend_user_required
def admin_manage_fundraiser_member(request):
    if request.is_ajax():
        campaign = request.GET.get('campaign', None)
        instance_query = request.GET.get('instance_query', None) 
        amount = request.GET.get('amount', None)
        city = request.GET.get('city', None)
        state = request.GET.get('state', None)
        country = request.GET.get('country', None)

        if campaign == 'Event':
            instance_Event = Event.objects.all()
            instance_EventGroupMembers = EventGroupMembers.objects.all()

            if instance_query:
                if instance_query != 'all':
                    instance_Event = instance_Event.filter(id=instance_query)
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(event__id__in=instance_Event.values_list('id', flat=True).distinct())
                else:
                    pass

            if city:
                if city != 'all':
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_EventGroupMembers = instance_EventGroupMembers.filter(state__iexact=state)
                else:
                    pass

            table = render_to_string('admin_template/admin_manage_fundraiser_member_ajax.html',{
                'instance_EventGroupMembers':instance_EventGroupMembers,
            })

            if state:
                # writing respons
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            elif city:
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                }
                return JsonResponse(context)

            elif instance_query:
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_Event.values_list('id','name').distinct().order_by('name')
                state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing response
                context = {
                    'table':table,
                    'instance_query_list' : list(instance_query_list),
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

        elif campaign == 'Mobilisation Campaign':

            instance_SupportGroup = SupportGroup.objects.all()
            instance_SupportGroupMembers = SupportGroupMembers.objects.all()

            if instance_query:
                if instance_query != 'all':
                    instance_SupportGroup = instance_SupportGroup.filter(id=instance_query)
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(support_group__id__in=instance_SupportGroup.values_list('id', flat=True).distinct())
                else:
                    pass

            if city:
                if city != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_SupportGroupMembers = instance_SupportGroupMembers.filter(state__iexact=state)
                else:
                    pass


            table = render_to_string('admin_template/admin_manage_fundraiser_member_ajax.html',{
                'instance_SupportGroupMembers':instance_SupportGroupMembers,
            })

            if state:
                # writing respons
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            elif city:
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                }
                return JsonResponse(context)

            elif instance_query:
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_SupportGroup.values_list('id','title').distinct().order_by('title')
                state_list = instance_SupportGroupMembers.values_list('state', flat=True).distinct().order_by('state')
                city_list = instance_SupportGroupMembers.values_list('city', flat=True).distinct().order_by('city')
                # writing respons
                context = {
                    'table':table,
                    'instance_query_list' : list(instance_query_list),
                    'state_list' : list(state_list),
                    'city_list':list(city_list),
                }
                return JsonResponse(context)

        else:
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.all()
            instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured')

            campaign_amount_list = CampaignDoners.objects.filter(payment_status='captured').values_list('amount', flat=True).distinct().order_by('amount')

            if instance_query:
                if instance_query != 'all':
                    instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(id=instance_query)
                    instance_CampaignDoners = instance_CampaignDoners.filter(campaign_fund_raiser__id__in=instance_CampaignFundRaiser.values_list('id', flat=True).distinct())
                else:
                    pass

            if amount:
                if amount != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(amount=amount)
                else:
                    pass

            if city:
                if city != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(city__iexact=city)
                else:
                    pass

            if state:
                if state != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(state__iexact=state)
                else:
                    pass

            if country:
                if country != 'all':
                    instance_CampaignDoners = instance_CampaignDoners.filter(country__iexact=country)
                else:
                    pass

            table = render_to_string('admin_template/admin_manage_fundraiser_member_ajax.html',{
                'instance_CampaignDoners':instance_CampaignDoners,
            })

            # writing response

            if country:
                context = {
                    'table':table,
                }
                return JsonResponse(context)

            if state:
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'table':table,
                    'country_list' : list(campaign_country_list),
                }
                return JsonResponse(context)

            if city:
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'table':table,
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                }
                return JsonResponse(context)

            if amount:
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'table':table,
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                }
                return JsonResponse(context)

            if instance_query:
                campaign_amount_list = instance_CampaignDoners.values_list('amount', flat=True).distinct().order_by('amount')
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')
                context = {
                    'campaign_amount_list' : list(campaign_amount_list),
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                    'table':table,
                }
                return JsonResponse(context)

            else:
                instance_query_list = instance_CampaignFundRaiser.values_list('id','title').distinct().order_by('title')
                campaign_amount_list = instance_CampaignDoners.values_list('amount', flat=True).distinct().order_by('amount')
                campaign_city_list = instance_CampaignDoners.values_list('city', flat=True).distinct().order_by('city')
                campaign_state_list = instance_CampaignDoners.values_list('state', flat=True).distinct().order_by('state')
                campaign_country_list = instance_CampaignDoners.values_list('country', flat=True).distinct().order_by('country')

                context = {
                    'instance_query_list' : list(instance_query_list),
                    'campaign_amount_list' : list(campaign_amount_list),
                    'city_list' : list(campaign_city_list),
                    'state_list' : list(campaign_state_list),
                    'country_list' : list(campaign_country_list),
                    'table':table,
                }
                return JsonResponse(context)

    else:
        instance_query_list = CampaignFundRaiser.objects.values_list('id','title').distinct().order_by('title')
        campaign_amount_list = CampaignDoners.objects.filter(payment_status='captured').values_list('amount', flat=True).distinct().order_by('amount')
        campaign_city_list = CampaignDoners.objects.filter(payment_status='captured').values_list('city', flat=True).distinct().order_by('city')
        campaign_state_list = CampaignDoners.objects.filter(payment_status='captured').values_list('state', flat=True).distinct().order_by('state')
        campaign_country_list = CampaignDoners.objects.filter(payment_status='captured').values_list('country', flat=True).distinct().order_by('country')
        instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured')
        context ={
            'instance_query_list':instance_query_list,
            'campaign_amount_list':campaign_amount_list,
            'campaign_city_list':campaign_city_list,
            'campaign_state_list':campaign_state_list,
            'campaign_country_list':campaign_country_list,
            'instance_CampaignDoners':instance_CampaignDoners,
        }
        return render(request, 'admin_template/admin_manage_fundraiser_member.html', context)


@login_required
@admin_or_backend_user_required
def admin_event_member(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        GET_Event = request.GET.getlist('Event[]')

        instance_EventGroupMembers = EventGroupMembers.objects.filter(event__id__in=GET_Event)

        context = {
            'instance_EventGroupMembers':instance_EventGroupMembers,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_event_member_ajax.html', context)
    else:
        instance_Event = Event.objects.all().order_by("-id")
        instance_EventGroupMembers_count = EventGroupMembers.objects.all().count()
        context = {
            'instance_Event':instance_Event,
            'instance_EventGroupMembers_count':instance_EventGroupMembers_count,
        }
        return render(request, 'admin_template/admin_event_member.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_event_member(request):
    if request.is_ajax():
        campaign = request.GET.get('campaign', None)
        instance_query = request.GET.get('instance_query', None) 
        city = request.GET.get('city', None)
        state = request.GET.get('state', None)
        country = request.GET.get('country', None)
        
        instance_Event = Event.objects.all()
        instance_EventGroupMembers = EventGroupMembers.objects.all()

        if instance_query:
            if instance_query != 'all':
                instance_Event = instance_Event.filter(id=instance_query)
                instance_EventGroupMembers = instance_EventGroupMembers.filter(event__id__in=instance_Event.values_list('id', flat=True).distinct())
            else:
                pass

        if city:
            if city != 'all':
                instance_EventGroupMembers = instance_EventGroupMembers.filter(city__iexact=city)
            else:
                pass

        if state:
            if state != 'all':
                instance_EventGroupMembers = instance_EventGroupMembers.filter(state__iexact=state)
            else:
                pass

        if country:
            if country != 'all':
                instance_EventGroupMembers = instance_EventGroupMembers.filter(country__iexact=country)
            else:
                pass

        table = render_to_string('admin_template/admin_manage_event_member_ajax.html',{
            'instance_EventGroupMembers':instance_EventGroupMembers,
        })

        if country:
            # writing respons
            context = {
                'table':table,
            }
            return JsonResponse(context)

        if state:
            country_list = instance_EventGroupMembers.values_list('country', flat=True).distinct().order_by('country')
            # writing respons
            context = {
                'table':table,
                'country_list' : list(country_list),
            }
            return JsonResponse(context)

        elif city:
            state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
            country_list = instance_EventGroupMembers.values_list('country', flat=True).distinct().order_by('country')
            # writing respons
            context = {
                'table':table,
                'state_list' : list(state_list),
                'country_list' : list(country_list),
            }
            return JsonResponse(context)

        elif instance_query:
            state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
            city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
            country_list = instance_EventGroupMembers.values_list('country', flat=True).distinct().order_by('country')
            # writing respons
            context = {
                'table':table,
                'state_list' : list(state_list),
                'city_list':list(city_list),
                'country_list':list(country_list),
            }
            return JsonResponse(context)

        else:
            instance_query_list = instance_Event.values_list('id','name').distinct().order_by('name')
            state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
            city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
            country_list = instance_EventGroupMembers.values_list('country', flat=True).distinct().order_by('country')
            # writing response
            context = {
                'table':table,
                'instance_query_list' : list(instance_query_list),
                'state_list' : list(state_list),
                'city_list':list(city_list),
                'country_list':list(country_list),
            }
            return JsonResponse(context)

    else:
        # instance_Event = Event.objects.all()
        instance_EventGroupMembers = EventGroupMembers.objects.all()
        instance_query_list = Event.objects.values_list('id','name').distinct().order_by('name')
        campaign_state_list = instance_EventGroupMembers.values_list('state', flat=True).distinct().order_by('state')
        campaign_city_list = instance_EventGroupMembers.values_list('city', flat=True).distinct().order_by('city')
        campaign_country_list = instance_EventGroupMembers.values_list('country', flat=True).distinct().order_by('country')
        # writing response
        context = {
            'instance_query_list' : instance_query_list,
            'campaign_state_list' : campaign_state_list,
            'campaign_city_list':campaign_city_list,
            'campaign_country_list':campaign_country_list,
            'instance_EventGroupMembers':instance_EventGroupMembers
        }
        
        return render(request, 'admin_template/admin_manage_event_member.html', context)



@login_required
@admin_or_backend_user_required
def admin_manage_contributors(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Fund_Raiser = request.GET.getlist('FundRaiser[]')

        instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured', campaign_fund_raiser__id__in=Fund_Raiser)

        context = {
            'instance_CampaignDoners':instance_CampaignDoners,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_manage_contributors_ajax.html', context)
    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by("-id")
        instance_CampaignDoners_count = CampaignDoners.objects.filter(payment_status='captured').count()
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignDoners_count':instance_CampaignDoners_count,
        }
        return render(request, 'admin_template/admin_manage_contributors.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_donors(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Fund_Raiser = request.GET.getlist('FundRaiser[]')

        instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured', campaign_fund_raiser__id__in=Fund_Raiser).values('email', 'name', 'campaign_fund_raiser__title', 'phone', 'address', 'pincode').order_by('email').annotate(num_donation=Count('amount'), total=Sum('amount'))

        context = {
            'instance_CampaignDoners':instance_CampaignDoners,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_manage_donors_ajax.html', context)
    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by("-id")

        instance_CampaignDoners_count = CampaignDoners.objects.filter(payment_status='captured').values('email', 'name', 'is_hide_me').order_by('email').annotate(total=Sum('amount')).count()
        
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignDoners_count':instance_CampaignDoners_count,
        }
        return render(request, 'admin_template/admin_manage_donors.html', context)


def admin_manage_refund(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Fund_Raiser = request.GET.getlist('FundRaiser[]')

        instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured', campaign_fund_raiser__id__in=Fund_Raiser, is_request_refund=True)

        context = {
            'Column':Column,
            'instance_CampaignDoners':instance_CampaignDoners,
        }
        return render(request, 'admin_template/admin_manage_refund_ajax.html', context)
    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by("-id")
        
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
        }
        return render(request, 'admin_template/admin_manage_refund.html', context)


def admin_manage_refund_status(request, ID, status):
    try:
        instance_CampaignDoners = CampaignDoners.objects.get(id=ID, payment_status='captured', is_request_refund=True, refund_status='request refund')
    except:
        messages.add_message(request,messages.SUCCESS, 'Object error')
        return redirect('admin_manage_refund')

    try:
        instance_CashfreePaymentDetails = CashfreePaymentDetails.objects.all()[0]
    except:
        instance_CashfreePaymentDetails = CashfreePaymentDetails()
        instance_CashfreePaymentDetails.payment_mode='TEST'
        instance_CashfreePaymentDetails.save()

    try:
        cashfree_appid = instance_CashfreePaymentDetails.app_id
        cashfree_secretKey = instance_CashfreePaymentDetails.secrate_key
        cashfree_payment_mode = instance_CashfreePaymentDetails.payment_mode
    except:
        messages.add_message(request,messages.SUCCESS, 'Cashfree payment gateway error.')
        return redirect('admin_manage_refund')


    if status == 'refund approved':
        instance_CampaignDoners.refund_status = 'refund approved'
        instance_CampaignDoners.payment_status = 'refund'
        instance_CampaignDoners.save()

        instance_CampaignTotalAmount = CampaignTotalAmount.objects.get(campaign_fund_raiser=instance_CampaignDoners.campaign_fund_raiser)
        instance_CampaignTotalAmount.total_amount = instance_CampaignTotalAmount.total_amount - instance_CampaignDoners.amount
        # check how many time donation
        no_of_donation = CampaignDoners.objects.filter(id=ID, payment_status='captured', email=instance_CampaignDoners.email).count()
        if no_of_donation <= 1:
            instance_CampaignTotalAmount.total_supporters = instance_CampaignTotalAmount.total_supporters - 1

        instance_CampaignTotalAmount.save()


        # payment = client.payment.refund(instance_CampaignDoners.payment_id, instance_CampaignDoners.amount_in_paisa())
        api_url = 'https://test.cashfree.com/api/v1/order/refund'
        payload = {
            'appId':cashfree_appid, 
            'secretKey':cashfree_secretKey,
            'orderId':instance_CampaignDoners.order_id,
            'referenceId':instance_CampaignDoners.payment_id,
            'refundAmount':instance_CampaignDoners.amount,
            'refundNote':'user request refund',
            }
        headers = {'cache-control': 'no-cache', 'content-type':'application/x-www-form-urlencoded'}
        response = requests.post(api_url, data=payload, headers=headers)
        response = response.json()




        messages.add_message(request,messages.SUCCESS, 'Refund approved successfully')



    elif status == 'refund decline':
        instance_CampaignDoners.refund_status = 'refund decline'
        instance_CampaignDoners.save()

        messages.add_message(request,messages.SUCCESS, 'Refund decline successfully')



    return redirect('admin_manage_refund')


@login_required
@admin_or_backend_user_required
def admin_manage_support_group(request):
    instance_SupportGroup = SupportGroup.objects.all().order_by("-id")
    context = {
        'instance_SupportGroup':instance_SupportGroup,
    }
    return render(request, 'admin_template/admin_manage_support_group.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_support_group_status(request, ID, status):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID)
        if status == "True":
            instance_SupportGroup.is_active = True
            instance_SupportGroup.save()

            messages.add_message(request,messages.SUCCESS,'Mobilisation Campaign "%s" activated successfully' %(instance_SupportGroup.title))

        elif status == "False":
            instance_SupportGroup.is_active = False
            instance_SupportGroup.save()

            messages.add_message(request,messages.SUCCESS,'Mobilisation Campaign"%s" inactivate successfully' %(instance_SupportGroup.title))
    except:
        pass
    return redirect('admin_manage_support_group')

@login_required
@admin_or_backend_user_required
def admin_manage_support_group_edit(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID)
        if request.method == 'POST':
            Admin_SupportGroup_Form = AdminSupportGroupForm(request.POST, request.FILES, instance=instance_SupportGroup)
            if Admin_SupportGroup_Form.is_valid():
                Admin_SupportGroup_Form = Admin_SupportGroup_Form.save()

                return redirect("admin_manage_support_group")
        else:
            Admin_SupportGroup_Form = AdminSupportGroupForm(instance=instance_SupportGroup)

        context = {
            'Admin_SupportGroup_Form':Admin_SupportGroup_Form,
        }
        return render(request, 'admin_template/admin_manage_support_group_edit.html', context)
    except:
        pass
    return redirect('admin_manage_support_group')


@login_required
@admin_or_backend_user_required
def admin_manage_event(request):
    instance_Event = Event.objects.all().order_by("-id")
    context = {
        'instance_Event':instance_Event,
    }
    return render(request, 'admin_template/admin_manage_event.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_event_status(request, ID, status):
    try:
        instance_Event = Event.objects.get(id=ID)
        if status == "True":
            instance_Event.is_active = True
            instance_Event.save()

            messages.add_message(request,messages.SUCCESS,'Event "%s" activated successfully' %(instance_Event.name))

        elif status == "False":
            instance_Event.is_active = False
            instance_Event.save()

            messages.add_message(request,messages.SUCCESS,'Event "%s" inactivate successfully' %(instance_Event.name))
    except:
        pass
    return redirect('admin_manage_event')

@login_required
@admin_or_backend_user_required
def admin_manage_event_edit(request, ID):
    try:
        instance_Event = Event.objects.get(id=ID)
        if request.method == 'POST':
            Admin_Event_Form = AdminEventForm(request.POST, request.FILES, instance=instance_Event)
            if Admin_Event_Form.is_valid():
                Admin_Event_Form = Admin_Event_Form.save()

                return redirect("admin_manage_event")
        else:
            Admin_Event_Form = AdminEventForm(instance=instance_Event)

        context = {
            'Admin_Event_Form':Admin_Event_Form,
        }
        return render(request, 'admin_template/admin_manage_event_edit.html', context)
    except:
        pass
    return redirect('admin_manage_event')






@login_required
@admin_or_backend_user_required
def admin_manage_media(request):
    form_error = False
    if request.method == 'POST':
        Media_Artical_Form = MediaArticalForm(request.POST, request.FILES)
        if Media_Artical_Form.is_valid():
            Media_Artical_Form = Media_Artical_Form.save()

            messages.add_message(request,messages.SUCCESS,'Media Artical "%s" added successfully' %(Media_Artical_Form.title))

            return redirect('admin_manage_media')
        else:
            form_error = True
    else:
        Media_Artical_Form = MediaArticalForm()

    instance_MediaArtical = MediaArtical.objects.all().order_by("-id")

    context = {
        'instance_MediaArtical':instance_MediaArtical,
        'Media_Artical_Form':Media_Artical_Form,
        'form_error':form_error
    }
    return render(request, 'admin_template/admin_manage_media.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_media_delete(request, ID):
    try:
        instance_MediaArtical = MediaArtical.objects.get(id=ID)
        
        messages.add_message(request,messages.SUCCESS,'Media Artical "%s" deleted successfully' %(instance_MediaArtical.title))

        instance_MediaArtical.delete()
    except:
        pass
    return redirect('admin_manage_media')

@login_required
@admin_or_backend_user_required
def admin_manage_media_edit(request, ID):
    try:
        instance_MediaArtical = MediaArtical.objects.get(id=ID)
        
        if request.method == 'POST':
            Media_Artical_Form = MediaArticalForm(request.POST, request.FILES, instance=instance_MediaArtical)
            if Media_Artical_Form.is_valid():
                Media_Artical_Form = Media_Artical_Form.save()

                messages.add_message(request,messages.SUCCESS,'Media Artical "%s" updated successfully' %(Media_Artical_Form.title))

                return redirect('admin_manage_media')
        else:
            Media_Artical_Form = MediaArticalForm(instance=instance_MediaArtical)

        context = {
            'Media_Artical_Form':Media_Artical_Form,
        }
        return render(request, 'admin_template/admin_manage_media_edit.html', context)
    except:
        pass
    return redirect('admin_manage_media')


####################################################################

@login_required
@admin_or_backend_user_required
def admin_manage_crowd_newsing(request):
    form_error = False
    if request.method == 'POST':
        CrowdNewsing_Form = CrowdNewsingForm(request.POST, request.FILES)
        if CrowdNewsing_Form.is_valid():
            CrowdNewsing_Form = CrowdNewsing_Form.save()

            messages.add_message(request,messages.SUCCESS,'"%s" CrowdNewsing added successfully' %(CrowdNewsing_Form.name))

            return redirect('admin_manage_crowd_newsing')
        else:
            form_error = True
    else:
        CrowdNewsing_Form = CrowdNewsingForm()

    instance_CrowdNewsing = CrowdNewsing.objects.all().order_by("-id")

    context = {
        'instance_CrowdNewsing':instance_CrowdNewsing,
        'CrowdNewsing_Form':CrowdNewsing_Form,
        'form_error':form_error
    }
    return render(request, 'admin_template/admin_manage_crowd_newsing.html', context)

@login_required
@admin_or_backend_user_required
def admin_manage_crowd_newsing_delete(request, ID):
    try:
        instance_CrowdNewsing = CrowdNewsing.objects.get(id=ID)
        
        messages.add_message(request,messages.SUCCESS,'"%s" CrowdNewsing deleted successfully' %(instance_CrowdNewsing.name))

        instance_CrowdNewsing.delete()
    except:
        pass
    return redirect('admin_manage_crowd_newsing')

@login_required
@admin_or_backend_user_required
def admin_manage_crowd_newsing_edit(request, ID):
    try:
        instance_CrowdNewsing = CrowdNewsing.objects.get(id=ID)


        if request.method == 'POST':
            CrowdNewsing_Form = CrowdNewsingForm(request.POST, request.FILES, instance=instance_CrowdNewsing)
            if CrowdNewsing_Form.is_valid():
                CrowdNewsing_Form = CrowdNewsing_Form.save()

                messages.add_message(request,messages.SUCCESS,'"%s" CrowdNewsing updated successfully' %(CrowdNewsing_Form.name))

                return redirect('admin_manage_crowd_newsing')
            else:
                form_error = True
        else:
            CrowdNewsing_Form = CrowdNewsingForm(instance=instance_CrowdNewsing)

        context = {
            'CrowdNewsing_Form':CrowdNewsing_Form,
        }
        return render(request, 'admin_template/admin_manage_crowd_newsing_edit.html', context)
    except:
        pass
    return redirect('admin_manage_crowd_newsing')
####################################################################


@login_required
@admin_user_required
def admin_manage_user(request):
    form_error = False
    if request.method == 'POST':
        Admin_User_Signup_Form = AdminUserSignupForm(request.POST)
        if Admin_User_Signup_Form.is_valid():
            Admin_User_Signup_Form = Admin_User_Signup_Form.save()

            current_site = get_current_site(request)
            mail_subject = 'Activate your Crowd Funding account'
            message = render_to_string('email_template/activate_email.html', {
                'user': Admin_User_Signup_Form,
                'domain': current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(Admin_User_Signup_Form.pk)).decode(),
                'token':account_activation_token.make_token(Admin_User_Signup_Form),
            })
            email = EmailMultiAlternatives(
                             mail_subject, message, to=[Admin_User_Signup_Form.email]
             )
            email.attach_alternative(message, "text/html")
            email.send()

            messages.add_message(request,messages.SUCCESS,'User "%s" created successfully' %(Admin_User_Signup_Form.name))

            return redirect('admin_manage_user')

        else:
            form_error = True

    else:
        Admin_User_Signup_Form = AdminUserSignupForm()

    instance_user = User.objects.all().order_by('-id')
    context = {
        'instance_user':instance_user,
        'Admin_User_Signup_Form':Admin_User_Signup_Form,
        'form_error':form_error,
    }
    return render(request, 'admin_template/admin_manage_user.html', context)

@login_required
@admin_user_required
def admin_manage_usera_edit(request, ID):
    try:
        instance_user = User.objects.get(id=ID)
        
        if request.method == 'POST':
            Admin_User_Edit_Form = AdminUserEditForm(request.POST, instance=instance_user)
            if Admin_User_Edit_Form.is_valid():
                Admin_User_Edit_Form = Admin_User_Edit_Form.save()

                messages.add_message(request,messages.SUCCESS,'User "%s" updated successfully' %(Admin_User_Edit_Form.name))

                return redirect('admin_manage_user')
        else:
            Admin_User_Edit_Form = AdminUserEditForm(instance=instance_user)

        context = {
            'Admin_User_Edit_Form':Admin_User_Edit_Form,
        }
        return render(request, 'admin_template/admin_manage_usera_edit.html', context)
    except:
        pass
    return redirect('admin_manage_user')

@login_required
@admin_or_backend_user_required
def admin_manage_user_delete(request, ID):
    try:
        instance_user = User.objects.get(id=ID)
        
        messages.add_message(request,messages.SUCCESS,'User "%s" deleted successfully' %(instance_user.name))

        instance_user.delete()
    except:
        pass
    return redirect('admin_manage_user')

@login_required
@admin_or_backend_user_required
def admin_manage_user_status(request, ID, status):
    try:
        instance_user = User.objects.get(id=ID)
        if status == "True":
            instance_user.is_active = True
            instance_user.save()

            messages.add_message(request,messages.SUCCESS,'User "%s" activated successfully' %(instance_user.name))

        elif status == "False":
            instance_user.is_active = False
            instance_user.save()

            messages.add_message(request,messages.SUCCESS,'User "%s" inactivate successfully' %(instance_user.name))
    except:
        pass
    return redirect('admin_manage_user')



@login_required
@admin_or_backend_user_required
def admin_manage_banner_images(request):
    form_error = False
    if request.method == 'POST':
        Banner_Images_Form = BannerImagesForm(request.POST, request.FILES)
        if Banner_Images_Form.is_valid():
            Banner_Images_Form = Banner_Images_Form.save()

            messages.add_message(request,messages.SUCCESS,'"%s" Banner added successfully' %(Banner_Images_Form.title))

            return redirect('admin_manage_banner_images')
        else:
            form_error = True
    else:
        Banner_Images_Form = BannerImagesForm()

    instance_BannerImages = BannerImages.objects.all().order_by("-id")

    context = {
        'instance_BannerImages':instance_BannerImages,
        'Banner_Images_Form':Banner_Images_Form,
        'form_error':form_error
    }
    return render(request, 'admin_template/admin_manage_banner_images.html', context)


@login_required
@admin_or_backend_user_required
def admin_manage_banner_images_edit(request, ID):
    try:
        instance_BannerImages = BannerImages.objects.get(id=ID)


        if request.method == 'POST':
            Banner_Images_Form = BannerImagesForm(request.POST, request.FILES, instance=instance_BannerImages)
            if Banner_Images_Form.is_valid():
                Banner_Images_Form = Banner_Images_Form.save()

                messages.add_message(request,messages.SUCCESS,'"%s" Banner updated successfully' %(Banner_Images_Form.title))

                return redirect('admin_manage_banner_images')
            else:
                form_error = True
        else:
            Banner_Images_Form = BannerImagesForm(instance=instance_BannerImages)

        context = {
            'Banner_Images_Form':Banner_Images_Form,
        }
        return render(request, 'admin_template/admin_manage_banner_images_edit.html', context)
    except:
        pass
    return redirect('admin_manage_banner_images')



@login_required
@admin_or_backend_user_required
def admin_manage_banner_images_status(request, ID, status):
    try:
        instance_BannerImages = BannerImages.objects.get(id=ID)
        if status == "True":
            instance_BannerImages.is_active = True
            instance_BannerImages.save()

            messages.add_message(request,messages.SUCCESS,'Banner Image "%s" activated successfully' %(instance_user.name))

        elif status == "False":
            instance_BannerImages.is_active = False
            instance_BannerImages.save()

            messages.add_message(request,messages.SUCCESS,'Banner Image "%s" inactivate successfully' %(instance_user.name))
    except:
        pass
    return redirect('admin_manage_banner_images')

@login_required
@admin_or_backend_user_required
def generic_user_view(request):
    if request.method == 'POST':
        Generic_Emails_Form = GenericEmailsForm(request.POST)
        if Generic_Emails_Form.is_valid():
            Generic_Emails_Form = Generic_Emails_Form.save()

            messages.add_message(request,messages.SUCCESS,'Generic user "%s" added successfully' %(Generic_Emails_Form.name))

            return redirect('generic_user_view')

    else:
        Generic_Emails_Form = GenericEmailsForm()
    instance_GenericEmails = GenericEmails.objects.all().order_by("-id")
    context = {
        'Generic_Emails_Form':Generic_Emails_Form,
        'instance_GenericEmails':instance_GenericEmails,
    }
    return render(request, 'admin_template/generic_user_view.html', context)


@login_required
@admin_or_backend_user_required
def platform_generic_user(request):
    if request.is_ajax():
        Column = request.GET.getlist('Column[]')
        Fund_Raiser = request.GET.getlist('FundRaiser[]')
        Support_Group = request.GET.getlist('SupportGroup[]')
        Event_Event = request.GET.getlist('Event[]')

        instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(id__in=Fund_Raiser).distinct().order_by("-id")
        instance_SupportGroup = SupportGroup.objects.filter(id__in=Support_Group).distinct().order_by("-id")
        instance_Event = Event.objects.filter(id__in=Event_Event).distinct().order_by("-id")
# campaign_country_list = instance_SupportGroupMembers.values_list('country', flat=True).distinct().order_by('country')
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_SupportGroup':instance_SupportGroup,
            'instance_Event':instance_Event,
            'Column':Column,
        }
        return render(request, 'admin_template/admin_manage_platform_generic_user_ajax.html', context)
    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.all().order_by("-id")
        instance_SupportGroup = SupportGroup.objects.all().order_by("-id")
        instance_Event = Event.objects.all().order_by("-id")

        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_SupportGroup':instance_SupportGroup,
            'instance_Event':instance_Event,
        }
        return render(request, 'admin_template/admin_manage_platform_generic_user.html', context)


@login_required
@admin_user_required
def admin_manage_generic_user_edit(request, ID):
    try:
        instance_GenericEmails = GenericEmails.objects.get(id=ID)
        
        if request.method == 'POST':
            Generic_Emails_Form = GenericEmailsForm(request.POST, instance=instance_GenericEmails)
            if Generic_Emails_Form.is_valid():
                Generic_Emails_Form = Generic_Emails_Form.save()

                messages.add_message(request,messages.SUCCESS,'Generic user "%s" updated successfully' %(Generic_Emails_Form.name))

                return redirect('generic_user_view')
        else:
            Generic_Emails_Form = GenericEmailsForm(instance=instance_GenericEmails)

        context = {
            'Generic_Emails_Form':Generic_Emails_Form,
        }
        return render(request, 'admin_template/admin_manage_generic_user_edit.html', context)
    except:
        pass
    return redirect('generic_user_view')

@login_required
@admin_or_backend_user_required
def admin_manage_generic_user_delete(request, ID):
    try:
        instance_GenericEmails = GenericEmails.objects.get(id=ID)
        
        messages.add_message(request,messages.SUCCESS,'Generic user "%s" deleted successfully' %(instance_GenericEmails.name))

        instance_GenericEmails.delete()
    except:
        pass
    return redirect('generic_user_view')

@login_required
@admin_or_backend_user_required
def admin_manage_generic_user_status(request, ID, status):
    try:
        instance_GenericEmails = GenericEmails.objects.get(id=ID)
        if status == "True":
            instance_GenericEmails.is_active = True
            instance_GenericEmails.save()

            messages.add_message(request,messages.SUCCESS,'Generic user "%s" activated successfully' %(instance_GenericEmails.name))

        elif status == "False":
            instance_GenericEmails.is_active = False
            instance_GenericEmails.save()

            messages.add_message(request,messages.SUCCESS,'Generic user "%s" inactivate successfully' %(instance_GenericEmails.name))
    except:
        pass
    return redirect('generic_user_view')

@login_required
def public_personas(request):
    if request.method == 'POST':
        departments = request.POST.get('departments', None)
        email = request.POST.getlist('email', None)
        email_message = request.POST.get('message', None)
        mail_subject = request.POST.get('subject', None)

        public_email_form = PublicEmailForm()

        if departments and email and email_message and mail_subject:
            current_site = get_current_site(request)
            message = render_to_string('email_template/public_personas_email.html',{
                'email_message':email_message,
                'domain': current_site.domain,
            })
            email = EmailMultiAlternatives(
                mail_subject, message, to=email
            )
            email.attach_alternative(message, "text/html")
            email.send()

            messages.add_message(request,messages.SUCCESS,'Email send successfully.')
            return redirect('discover')
        else:
            pass
    else:
        Category = request.GET.get('Category', None)
        instance_object = request.GET.get('ID', None)
        public_email_form = PublicEmailForm()
        
        if not Category and not instance_object:
            return redirect('discover')
        if Category == 'FundRaiser':
            try:
                instance_fundraiser = CampaignFundRaiser.objects.get(id=instance_object)
                public_email_form = PublicEmailForm(initial={'subject':instance_fundraiser.title, 'message':instance_fundraiser.about})
            except:
                return redirect('discover')
            
        elif Category == 'SupportGroup':
            try:
                instance_supportgroup = SupportGroup.objects.get(id=instance_object)
                public_email_form = PublicEmailForm(initial={'subject':instance_supportgroup.title, 'message':instance_supportgroup.about})
            except:
                return redirect('discover')
            
        elif Category == 'Event':
            try:
                instance_event = Event.objects.get(id=instance_object)
                public_email_form = PublicEmailForm(initial={'subject':instance_event.name, 'message':instance_event.about})
            except:
                return redirect('discover')

        else:
            return redirect('discover')


    context = {
        'generic_emails_departments':generic_emails_departments,
        'public_email_form':public_email_form,
    }
    return render(request, 'admin_template/public_personas.html', context)



@login_required
@admin_or_backend_user_required
def public_personas_get_department_user(request):
    department = request.GET.get('department', None)
    instance_GenericEmails = GenericEmails.objects.filter(departments__iexact=department, is_active=True)
    email_field = ''
    for i in instance_GenericEmails:
        email_field += '<div><input type="checkbox" name="email" value="%s" class="mr-2" />%s</div>' %(str(i.email), str(i.email))

    return HttpResponse(email_field)



@login_required
@admin_or_backend_user_required
def admin_withdrawl_request(request):
    instance_WithdrawalRequest = WithdrawalRequest.objects.all().order_by('-id')
    context = {
        'instance_WithdrawalRequest':instance_WithdrawalRequest,
    }
    return render(request, 'admin_template/admin_withdrawl_request.html', context)


@login_required
@admin_or_backend_user_required
def admin_manage_cashfree_credential(request):
    try:
        instance_CashfreePaymentDetails = CashfreePaymentDetails.objects.all()[0]
    except:
        instance_CashfreePaymentDetails = CashfreePaymentDetails()
        instance_CashfreePaymentDetails.payment_mode='TEST'
        instance_CashfreePaymentDetails.save()
    if request.method == 'POST':
        CashfreePayment_DetailsForm = CashfreePaymentDetailsForm(request.POST, instance=instance_CashfreePaymentDetails)
        if CashfreePayment_DetailsForm.is_valid():
            CashfreePayment_DetailsForm.save()

            messages.add_message(request,messages.SUCCESS,'Cashfree payment gateway credential updated successfully.')

            return redirect('admin_manage_cashfree_credential')
    else:
        CashfreePayment_DetailsForm = CashfreePaymentDetailsForm(instance=instance_CashfreePaymentDetails)

    context = {
        'CashfreePayment_DetailsForm':CashfreePayment_DetailsForm,
    }

    return render(request, 'admin_template/admin_manage_cashfree_credential.html', context)


@login_required
@admin_or_backend_user_required
def admin_manage_commission(request):
    try:
        instance_Commission = Commission.objects.all()[0]
    except:
        instance_Commission = Commission()
        instance_Commission.save()
    if request.method == 'POST':
        Commission_Form = CommissionForm(request.POST, instance=instance_Commission)
        if Commission_Form.is_valid():
            Commission_Form.save()

            messages.add_message(request,messages.SUCCESS,'Comission updated successfully.')

            return redirect('admin_manage_commission')
    else:
        Commission_Form = CommissionForm(instance=instance_Commission)

    context = {
        'Commission_Form':Commission_Form,
    }

    return render(request, 'admin_template/admin_manage_commission.html', context)


@login_required
@admin_or_backend_user_required
def admin_withdrawl_request_edit(request, ID):
    instance_WithdrawalRequest = WithdrawalRequest.objects.get(id=ID)
    if request.method == 'POST':
        Admin_Withdrawal_Request_Form = AdminWithdrawalRequestForm(request.POST, instance = instance_WithdrawalRequest)



        instance_campaign = CampaignFundRaiser.objects.get(id=instance_WithdrawalRequest.campaign.id)
        
        

        if Admin_Withdrawal_Request_Form.is_valid() :
            status = Admin_Withdrawal_Request_Form.cleaned_data['status']
            if instance_campaign.available_withdrawl_fund() < instance_WithdrawalRequest.amount and status == 'Approved':
                Admin_Withdrawal_Request_Form.add_error('status', 'User do not have enough balance to withdraw.')
            else:
                Admin_Withdrawal_Request_Form = Admin_Withdrawal_Request_Form.save()

                messages.add_message(request,messages.SUCCESS,'%s withdrawl request updated successfully.' %(Admin_Withdrawal_Request_Form.campaign.user.name))

                return redirect('admin_withdrawl_request')
            
    else:
        Admin_Withdrawal_Request_Form = AdminWithdrawalRequestForm(instance=instance_WithdrawalRequest)
    context = {
        'Admin_Withdrawal_Request_Form':Admin_Withdrawal_Request_Form,
    }
    return render(request, 'admin_template/admin_withdrawl_request_edit.html', context)
    
    
#------------------------------------------ end admin view ----------------------------------------------#



#------------------------------------------ start user view ---------------------------------------------#


@login_required
@end_user_required
def dashboard(request):
    if request.is_ajax():
        category = request.GET.get('category', None)
        status = request.GET.get('status', None)

        if category:
            category = category.lower()
            category = category.strip()
        if status:
            status = status.lower()
            status = status.strip()

        Today = datetime.now().date()

        if category == 'event':
            instance_Event = Event.objects.filter(user=request.user)
            if status == 'approval request':
                instance_Event = instance_Event.filter(is_active=False, date__gte=Today)
            elif status == 'completed':
                instance_Event = instance_Event.filter(date__lt=Today)
            else :
                instance_Event = instance_Event.filter(is_active=True, date__gte=Today)

            paginator  = Paginator(instance_Event, 6)
            page = request.GET.get('page')
            try: 
                instance_Event = paginator.page(page)
            except PageNotAnInteger:
                instance_Event = paginator.page(1)
            except EmptyPage:
                instance_Event = paginator.page(Paginator.num_pages)

            context = {
                'instance_Event':instance_Event,
            }
            return render(request, 'user_template/dashboard_ajax.html', context)

        elif category == 'mobilisation campaign':
            instance_SupportGroup = SupportGroup.objects.filter(group_leader=request.user)
            if status == 'approval request':
                instance_SupportGroup = instance_SupportGroup.filter(is_active=False)
            elif status == 'completed':
                completed_support_group = []
                for i in instance_SupportGroup:
                    if i.group_member_count() >= i.goal:
                        completed_support_group.append(i.id)

                instance_SupportGroup = SupportGroup.objects.filter(group_leader=request.user, id__in=completed_support_group)
            else :
                instance_SupportGroup = instance_SupportGroup.filter(is_active=True)


            paginator  = Paginator(instance_SupportGroup, 6)
            page = request.GET.get('page')
            try: 
                instance_SupportGroup = paginator.page(page)
            except PageNotAnInteger:
                instance_SupportGroup = paginator.page(1)
            except EmptyPage:
                instance_SupportGroup = paginator.page(Paginator.num_pages)

            context = {
                'instance_SupportGroup':instance_SupportGroup,
            }

            print('instance_SupportGroup : ', instance_SupportGroup)
            return render(request, 'user_template/dashboard_ajax.html', context)

        elif category == 'fundraiser':
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(user=request.user)
            if status == 'approval request':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=False, end_date__gte=Today)
            elif status == 'completed':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(end_date__lt=Today)
            else :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=True, end_date__gte=Today)

            paginator  = Paginator(instance_CampaignFundRaiser, 6)
            page = request.GET.get('page')
            try: 
                instance_CampaignFundRaiser = paginator.page(page)
            except PageNotAnInteger:
                instance_CampaignFundRaiser = paginator.page(1)
            except EmptyPage:
                instance_CampaignFundRaiser = paginator.page(Paginator.num_pages)

            context = {
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            }
            return render(request, 'user_template/dashboard_ajax.html', context)

        else:
            instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(user=request.user)
            if status == 'approval request':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=False, end_date__gte=Today)
            elif status == 'completed':
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(end_date__lt=Today)
            else :
                instance_CampaignFundRaiser = instance_CampaignFundRaiser.filter(is_active=True, end_date__gte=Today)

            
            paginator  = Paginator(instance_CampaignFundRaiser, 6)
            page = request.GET.get('page')
            try: 
                instance_CampaignFundRaiser = paginator.page(page)
            except PageNotAnInteger:
                instance_CampaignFundRaiser = paginator.page(1)
            except EmptyPage:
                instance_CampaignFundRaiser = paginator.page(Paginator.num_pages)

            context = {
                'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            }
            return render(request, 'user_template/dashboard_ajax.html', context)

    else:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(user=request.user)
        instance_SupportGroup = SupportGroup.objects.filter(group_leader=request.user)
        instance_Event = Event.objects.filter(user=request.user)

        if instance_CampaignFundRaiser.count() > 0:
            return redirect('my_fundraiser_campaign_dashboard', url_text=instance_CampaignFundRaiser[0].url_text)
        elif instance_SupportGroup.count() > 0:
            return redirect('my_mobilisation_campaign_dashboard', url_text=instance_SupportGroup[0].url_text)
        elif instance_Event.count() > 0:
            return redirect('my_event_dashboard', url_text=instance_Event[0].url_text)
        else:
            return redirect('chose_campaign')

    context = {
    }
    return render(request, 'user_template/dashboard.html', context)

@login_required
@end_user_required
@one_supportgroup_required
def my_analytics(request):
    Today = datetime.now().date() 

    today_supporters = SupportGroupMembers.objects.filter(support_group__group_leader=request.user, created_at__gte=Today).count()
    total_supporters = SupportGroupMembers.objects.filter(support_group__group_leader=request.user).count()

    today_visit = SupportVisitHistory.objects.filter(support_group__group_leader=request.user, created_at__gte=Today).count()
    total_visit = SupportVisitHistory.objects.filter(support_group__group_leader=request.user).count()
    previous_total_visit = SupportVisitHistory.objects.filter(support_group__group_leader=request.user).exclude(created_at__gte=Today).count()

    try:
        today_increases = round(((today_visit - previous_total_visit) / today_visit) * 100, 2)
    except:
        today_increases = 0
        
    context = {
       'today_supporters':today_supporters,
       'total_supporters':total_supporters,

       'today_visit':today_visit,
       'total_visit':total_visit,

       'today_increases':today_increases,

       'Today':Today,

    }
    return render(request, 'user_template/my_analytics.html', context)

@login_required
def chose_campaign(request):
    return render(request, 'user_template/chose_campaign.html')


@login_required
def start_campaign(request):
    if request.method == 'POST':
        Campaign_FundRaiser_Form = CampaignFundRaiserForm(request.POST, request.FILES)
        if Campaign_FundRaiser_Form.is_valid():
            Campaign_FundRaiser_Form = Campaign_FundRaiser_Form.save(commit=False)
            Campaign_FundRaiser_Form.user = request.user
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                Campaign_FundRaiser_Form.is_active = True
            Campaign_FundRaiser_Form.save()


            messages.add_message(request,messages.SUCCESS,'Campaign %s created successfully, wait for admin confirmation.' %(Campaign_FundRaiser_Form.title))

            return redirect('dashboard')

        else:
            print(Campaign_FundRaiser_Form.errors)

    else:
        Campaign_FundRaiser_Form = CampaignFundRaiserForm()


    context = {
        'Campaign_FundRaiser_Form':Campaign_FundRaiser_Form,
    }
    return render(request, 'user_template/start_campaign.html', context)



# @beneficiary_completed_required

# @login_required
# def start_campaign(request):
#     if request.method == 'POST':
#         form_type = request.POST.get('', None)
#         if form_type == 'category_selection':
#             category_id = request.POST.get('category_id', None)
#             if category_id:
#                 try:
#                     instance_CampaignCategory = CampaignCategory.objects.get(id=category_id)

#                     Campaign_FundRaiser_Form = CampaignFundRaiserForm()

#                     context = {
#                         'Campaign_FundRaiser_Form':Campaign_FundRaiser_Form,
#                     }
#                     return render(request, 'user_template/start_campaign.html', context)
#                 except:
#                     pass
#             else:
#                 Category_Selection_Form = CategorySelectionForm()
#                 context = {
#                     'Category_Selection_Form':Category_Selection_Form,
#                 }
#                 return render(request, 'user_template/category_selection.html', context)
#         elif form_type == 'start_campaign':
#             Campaign_FundRaiser_Form = CampaignFundRaiserForm(request.POST, request.FILES)
#             if Campaign_FundRaiser_Form.is_valid():
#                 Campaign_FundRaiser_Form = Campaign_FundRaiser_Form.save(commit=False)
#                 Campaign_FundRaiser_Form.user = request.user
#                 Campaign_FundRaiser_Form.save()

#                 messages.add_message(request,messages.SUCCESS,'Campaign %s created successfully, wait for admin confirmation.' %(Campaign_FundRaiser_Form.title))

#                 return redirect('dashboard')

#             else:
#                 context = {
#                     'Campaign_FundRaiser_Form':Campaign_FundRaiser_Form,
#                 }
#                 return render(request, 'user_template/start_campaign.html', context)

#         else:
#             Category_Selection_Form = CategorySelectionForm()
#             context = {
#                 'Category_Selection_Form':Category_Selection_Form,
#             }
#             return render(request, 'user_template/category_selection.html', context)

#     else:
#         Category_Selection_Form = CategorySelectionForm()
#         context = {
#             'Category_Selection_Form':Category_Selection_Form,
#         }
#         return render(request, 'user_template/category_selection.html', context)
        

@login_required
@end_user_required
def my_campaign(request):
    instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(user=request.user)

    context = {
        'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
    }
    return render(request, 'user_template/my_campaign.html', context)



@login_required
@end_user_required
def campaign_edit(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID, user=request.user)
        if request.method == 'POST':
            Campaign_FundRaiser_Form = CampaignFundRaiserForm(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
            if Campaign_FundRaiser_Form.is_valid():
                Campaign_FundRaiser_Form = Campaign_FundRaiser_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign %s created successfully, wait for admin confirmation.' %(Campaign_FundRaiser_Form.title))

                return redirect('my_campaign')

        else:
            Campaign_FundRaiser_Form = CampaignFundRaiserForm(instance=instance_CampaignFundRaiser)
        context = {
            'Campaign_FundRaiser_Form':Campaign_FundRaiser_Form,
        }
        return render(request, 'user_template/start_campaign.html', context)
    except:
        pass

    return redirect('my_campaign')


@login_required
@end_user_required
def campaign_withdrawal(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID, user=request.user)
        if request.method == 'POST':
            Withdrawal_Request_Form = WithdrawalRequestForm(request.POST, request.FILES)
            if Withdrawal_Request_Form.is_valid():
                Withdrawal_Request_Form = Withdrawal_Request_Form.save()

                messages.add_message(request,messages.SUCCESS, 'Withdrawal request sended successfully')

                Withdrawal_Request_Form = WithdrawalRequestForm(initial={'campaign':instance_CampaignFundRaiser.id})

        else:
            Withdrawal_Request_Form = WithdrawalRequestForm(initial={'campaign':instance_CampaignFundRaiser.id})
        context = {
            'Withdrawal_Request_Form':Withdrawal_Request_Form,
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
        }
        return render(request, 'user_template/campaign_withdrawal.html', context)
    except:
        pass

    return redirect('my_campaign')


def campaign_funds_summary(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID, user=request.user)

        
        instance_WithdrawalRequest = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser).order_by("-id")

        try:
            instance_WithdrawalRequest_latest = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser, status='Approved').order_by("-id")[0]
        except:
            instance_WithdrawalRequest_latest = False
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_WithdrawalRequest':instance_WithdrawalRequest,
            'instance_WithdrawalRequest_latest':instance_WithdrawalRequest_latest,


        }
        return render(request, 'user_template/campaign_funds_summary.html', context)
    except:
        pass

    return redirect('my_campaign')

@login_required
@end_user_required
def campaign_updates(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID, user=request.user)
        
        if request.method == 'POST':
            Campaign_Updates_Form = CampaignUpdatesForm(request.POST)
            if Campaign_Updates_Form.is_valid():
                Campaign_Updates_Form = Campaign_Updates_Form.save(commit=False)
                Campaign_Updates_Form.campaign_fund_raiser = instance_CampaignFundRaiser
                Campaign_Updates_Form.save()

                messages.add_message(request,messages.SUCCESS,'Update " %s " added successfully. ' %(Campaign_Updates_Form.title))

                return redirect('my_campaign')

        else:
            Campaign_Updates_Form = CampaignUpdatesForm()


        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'Campaign_Updates_Form':Campaign_Updates_Form,
        }
        return render(request, 'user_template/campaign_updates.html', context)
    except:
        pass

    return redirect('my_campaign')


@login_required
@end_user_required
def campaign_buzz(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID, user=request.user)

        if request.method == 'POST':
            Campaign_Buzz_Form = CampaignBuzzForm(request.POST, request.FILES)
            if Campaign_Buzz_Form.is_valid():
                Campaign_Buzz_Form = Campaign_Buzz_Form.save(commit=False)
                Campaign_Buzz_Form.campaign_fund_raiser = instance_CampaignFundRaiser
                Campaign_Buzz_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Buzz " %s " added successfully. ' %(Campaign_Buzz_Form.title))

                return redirect('my_campaign')

        else:
            Campaign_Buzz_Form = CampaignBuzzForm()


        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'Campaign_Buzz_Form':Campaign_Buzz_Form,
        }
        return render(request, 'user_template/campaign_buzz.html', context)
    except:
        pass

    return redirect('my_campaign')

@login_required
def start_support_group(request):
    if request.method == 'POST':
        Support_Group_Form = SupportGroupForm(request.POST, request.FILES)
        if Support_Group_Form.is_valid():
            Support_Group_Form = Support_Group_Form.save(commit=False)
            Support_Group_Form.group_leader = request.user
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                Support_Group_Form.is_active = True
            Support_Group_Form.save()

            messages.add_message(request,messages.SUCCESS,'Mobilisation Campaign %s created successfully, wait for admin confirmation.' %(Support_Group_Form.title))

            return redirect('dashboard')

        else:
            print(Support_Group_Form.errors)

    else:
        Support_Group_Form = SupportGroupForm()


    context = {
        'Support_Group_Form':Support_Group_Form,
    }
    return render(request, 'user_template/start_support_group.html', context)


@login_required
@end_user_required
def my_support_group(request):
    instance_SupportGroup = SupportGroup.objects.filter(group_leader=request.user)

    context = {
        'instance_SupportGroup':instance_SupportGroup,
    }
    return render(request, 'user_template/my_support_group.html', context)


@login_required
@end_user_required
def my_support_group_edit(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID, group_leader=request.user)
        if request.method == 'POST':
            Support_Group_Form = SupportGroupForm(request.POST, request.FILES, instance=instance_SupportGroup)
            if Support_Group_Form.is_valid():
                Support_Group_Form = Support_Group_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign %s updated successfully.' %(Support_Group_Form.title))

                return redirect('my_support_group')

        else:
            Support_Group_Form = SupportGroupForm(instance=instance_SupportGroup)
        context = {
            'Support_Group_Form':Support_Group_Form,
        }
        return render(request, 'user_template/start_support_group.html', context)
    except:
        pass

    return redirect('my_support_group')

@login_required
@end_user_required
def my_support_group_user(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID, group_leader=request.user)
        instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, is_share=True)
        context = {
            'instance_SupportGroupMembers':instance_SupportGroupMembers,
        }
        return render(request, 'user_template/my_support_group_user.html', context)
    except:
        pass

    return redirect('dashboard')

@login_required
@end_user_required
def my_event_user(request, ID):
    try:
        instance_Event = Event.objects.get(id=ID, user=request.user)
        instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event, is_share=True)
        context = {
            'instance_EventGroupMembers':instance_EventGroupMembers,
        }
        return render(request, 'user_template/my_event_user.html', context)
    except:
        pass

    return redirect('dashboard')

@login_required
@end_user_required
def campaign_user(request, ID):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(id=ID, user=request.user)
        instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured')
        context = {
            'instance_CampaignDoners':instance_CampaignDoners,
        }
        return render(request, 'user_template/campaign_user.html', context)
    except:
        pass

    return redirect('dashboard')
    


@login_required
@end_user_required
def my_support_group_updates(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID, group_leader=request.user)
        
        if request.method == 'POST':
            Support_Updates_Form = SupportUpdatesForm(request.POST)
            if Support_Updates_Form.is_valid():
                Support_Updates_Form = Support_Updates_Form.save(commit=False)
                Support_Updates_Form.support_group = instance_SupportGroup
                Support_Updates_Form.save()

                messages.add_message(request,messages.SUCCESS,'Update " %s " added successfully. ' %(Support_Updates_Form.title))

                return redirect('my_support_group')

        else:
            Support_Updates_Form = SupportUpdatesForm()


        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'Support_Updates_Form':Support_Updates_Form,
        }
        return render(request, 'user_template/my_support_group_updates.html', context)
    except:
        pass

    return redirect('my_support_group')


@login_required
@end_user_required
def my_support_group_buzz(request, ID):
    try:
        instance_SupportGroup = SupportGroup.objects.get(id=ID, group_leader=request.user)

        if request.method == 'POST':
            Support_Buzz_Form = SupportBuzzForm(request.POST, request.FILES)
            if Support_Buzz_Form.is_valid():
                Support_Buzz_Form = Support_Buzz_Form.save(commit=False)
                Support_Buzz_Form.support_group = instance_SupportGroup
                Support_Buzz_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Buzz " %s " added successfully. ' %(Support_Buzz_Form.title))

                return redirect('my_support_group')

        else:
            Support_Buzz_Form = SupportBuzzForm()


        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'Support_Buzz_Form':Support_Buzz_Form,
        }
        return render(request, 'user_template/my_support_group_buzz.html', context)
    except:
        pass

    return redirect('my_support_group')



@login_required
def start_event(request):
    if request.method == 'POST':
        Event_Form = EventForm(request.POST, request.FILES)
        if Event_Form.is_valid():
            Event_Form = Event_Form.save(commit=False)
            Event_Form.user = request.user
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                Event_Form.is_active = True
            Event_Form.save()

            messages.add_message(request,messages.SUCCESS,'Event %s created successfully, wait for admin confirmation.' %(Event_Form.name))

            return redirect('start_event')


    else:
        Event_Form = EventForm()


    context = {
        'Event_Form':Event_Form,
    }
    return render(request, 'user_template/start_event.html', context)


@login_required
def my_profile(request):
    form_error = False
    if request.method == 'POST':
        form_type = request.POST.get('form_type', None)
        if form_type == 'profile':
            My_User_Edit_Form = MyUserEditForm(request.POST, request.FILES, instance=request.user)
            if My_User_Edit_Form.is_valid():
                My_User_Edit_Form = My_User_Edit_Form.save()

                messages.add_message(request,messages.SUCCESS,'Profile updated successfully.')
                return redirect('my_profile')


            else:
                form_error = 'profile'
                Beneficiary_Form = BeneficiaryForm(instance=request.user.beneficiary)


        elif form_type == 'beneficiary':
            Beneficiary_Form = BeneficiaryForm(request.POST, instance=request.user.beneficiary)
            if Beneficiary_Form.is_valid():
                Beneficiary_Form = Beneficiary_Form.save()
                    

                try:
                    current_site = get_current_site(request)
                    mail_subject = "You have successfully added as a Benificiary on Ourdemocracy.in"
                    message = render_to_string('email_template/benificiary_added.html',{
                        'Beneficiary_Form':Beneficiary_Form,
                        'domain': current_site.domain,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=[Beneficiary_Form.email]
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass

                messages.add_message(request,messages.SUCCESS,'Beneficiary Account detail updated successfully.')
                return redirect('my_profile')

            else:
                form_error = 'beneficiary'
                My_User_Edit_Form = MyUserEditForm(instance=request.user)

        else:
            My_User_Edit_Form = MyUserEditForm(instance=request.user)
            Beneficiary_Form = BeneficiaryForm(instance=request.user.beneficiary)


    else:
        My_User_Edit_Form = MyUserEditForm(instance=request.user)
        Beneficiary_Form = BeneficiaryForm(instance=request.user.beneficiary)


    instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(user=request.user)
    instance_SupportGroup = SupportGroup.objects.filter(group_leader=request.user)
    instance_Event = Event.objects.filter(user=request.user)


    instance_supported_CampaignFundRaiser_list = CampaignDoners.objects.filter(payment_status='captured').filter(Q(doner_user=request.user)|Q(email__iexact=request.user.email)).values_list('campaign_fund_raiser__id').distinct()
    instance_joined_SupportGroup_list = SupportGroupMembers.objects.filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).values_list('support_group__id').distinct()
    instance_joined_EventGroup_list = EventGroupMembers.objects.filter(Q(group_member=request.user)|Q(email__iexact=request.user.email)).values_list('event__id').distinct()

    instance_supported_CampaignFundRaiser = CampaignFundRaiser.objects.filter(id__in=instance_supported_CampaignFundRaiser_list)
    instance_joined_SupportGroup = SupportGroup.objects.filter(id__in=instance_joined_SupportGroup_list)
    instance_joined_EventGroup = Event.objects.filter(id__in=instance_joined_EventGroup_list)

    current_site = get_current_site(request)
    domain = current_site.domain

    context = {
        'My_User_Edit_Form':My_User_Edit_Form,
        'Beneficiary_Form':Beneficiary_Form,

        'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
        'instance_supported_CampaignFundRaiser':instance_supported_CampaignFundRaiser,

        'instance_SupportGroup':instance_SupportGroup,
        'instance_joined_SupportGroup':instance_joined_SupportGroup,

        'instance_Event':instance_Event,
        'instance_joined_EventGroup':instance_joined_EventGroup,

        'domain':domain,

        'form_error':form_error,
    }
    return render(request, 'user_template/my_profile.html', context)


@login_required
@end_user_required
def my_supported_fundraise_history(request, ID):
    instance_CampaignDoners = CampaignDoners.objects.filter(payment_status='captured', campaign_fund_raiser__id=ID).filter(Q(doner_user=request.user)|Q(email__iexact=request.user.email))
    context = {
        'instance_CampaignDoners':instance_CampaignDoners,
    }
    return render(request, 'user_template/my_supported_fundraise_history.html', context)


@login_required
@end_user_required
def my_supported_fundraise_request_refund(request, ID):
    try:
        instance_CampaignDoners = CampaignDoners.objects.filter(Q(doner_user=request.user)| Q(email__iexact=request.user.email)).get(payment_status='captured', id=ID)
        instance_CampaignDoners.refund_status = 'request refund'
        instance_CampaignDoners.is_request_refund = True
        instance_CampaignDoners.save()

        messages.add_message(request,messages.SUCCESS,'Refund request submited successfully.')
        
    except:
        pass

    

    return redirect('my_profile')






def view_user_profile(request, ID):
    try:
        instance_UserUniqueToken = UserUniqueToken.objects.get(unique_token__iexact=ID)
    except:
        messages.add_message(request,messages.SUCCESS,"Your password has been set. You may go ahead and Sign in.")
        return redirect('landingpage')


    instance_user = instance_UserUniqueToken.user
    
    instance_CampaignFundRaiser = CampaignFundRaiser.objects.filter(user=instance_user)
    instance_SupportGroup = SupportGroup.objects.filter(group_leader=instance_user)
    instance_Event = Event.objects.filter(user=instance_user)


    instance_supported_CampaignFundRaiser_list = CampaignDoners.objects.filter(payment_status='captured').filter(Q(doner_user=instance_user)|Q(email__iexact=instance_user.email)).values_list('campaign_fund_raiser__id').distinct()
    instance_joined_SupportGroup_list = SupportGroupMembers.objects.filter(Q(group_member=instance_user)|Q(email__iexact=instance_user.email)).values_list('support_group__id').distinct()
    instance_joined_EventGroup_list = EventGroupMembers.objects.filter(Q(group_member=instance_user)|Q(email__iexact=instance_user.email)).values_list('event__id').distinct()

    instance_supported_CampaignFundRaiser = CampaignFundRaiser.objects.filter(id__in=instance_supported_CampaignFundRaiser_list)
    instance_joined_SupportGroup = SupportGroup.objects.filter(id__in=instance_joined_SupportGroup_list)
    instance_joined_EventGroup = Event.objects.filter(id__in=instance_joined_EventGroup_list)

    current_site = get_current_site(request)
    domain = current_site.domain

    context = {
        'instance_user':instance_user,

        'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
        'instance_supported_CampaignFundRaiser':instance_supported_CampaignFundRaiser,
        'instance_Event':instance_Event,

        'instance_SupportGroup':instance_SupportGroup,
        'instance_joined_SupportGroup':instance_joined_SupportGroup,
        'instance_joined_EventGroup':instance_joined_EventGroup,

        'domain':domain,
    }
    return render(request, 'before_login/view_user_profile.html', context)


def how_it_works(request):
    instance_CrowdNewsing = CrowdNewsing.objects.all().order_by("-id")
    context = {
        'instance_CrowdNewsing':instance_CrowdNewsing,
    }
    return render(request, 'before_login/How_it_works.html', context)

def services(request):
    form_error = False
    if request.method == 'POST':
        Services_Enquiry_Form = ServicesEnquiryForm(request.POST)
        if Services_Enquiry_Form.is_valid():
            Services_Enquiry_Form = Services_Enquiry_Form.save()


            try:
                instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))
                current_site = get_current_site(request)

                mail_subject = "Services Enquiry"
                message = render_to_string('email_template/services_enquiry_to_admin.html',{
                    'domain': current_site.domain,
                    'Services_Enquiry_Form':Services_Enquiry_Form,
                })
                email = EmailMultiAlternatives(
                    mail_subject, message, to=instance_admin_email
                )
                email.attach_alternative(message, "text/html")
                email.send()
            except:
                pass


            try:
                current_site = get_current_site(request)

                mail_subject = "Services Enquiry Confirmation"
                message = render_to_string('email_template/services_enquiry_to_user.html',{
                    'domain': current_site.domain,
                    'Services_Enquiry_Form':Services_Enquiry_Form,
                })
                email = EmailMultiAlternatives(
                    mail_subject, message, to=[Services_Enquiry_Form.email]
                )
                email.attach_alternative(message, "text/html")
                email.send()
            except:
                pass



            messages.add_message(request,messages.SUCCESS,'Services enquiry send successfully.')

            return redirect('services')

        else:
            form_error = True
    else:
        Services_Enquiry_Form = ServicesEnquiryForm()

    context = {
        'Services_Enquiry_Form':Services_Enquiry_Form,
        'form_error':form_error,
    }
    return render(request, 'before_login/services.html', context)

def tips(request):
    return render(request, 'before_login/Campaign-Tips.html')

def media(request):
    instance_MediaArtical = MediaArtical.objects.all().order_by('-id')
    context = {
        'instance_MediaArtical':instance_MediaArtical,
    }
    return render(request, 'before_login/media.html', context)


def campaign_criteria(request):
    return render(request, 'before_login/Campaign_Criteria.html')

def terms_conditions(request):
    return render(request, 'before_login/Terms_And_Conditions.html')

def privacy_policy(request):
    return render(request, 'before_login/Privacy_Policy.html')

def pricing(request):
    return render(request, 'before_login/pricing.html')

def about_us(request):
    return render(request, 'before_login/about_us.html')

def contact_us(request):
    if request.method == "POST":
        Contact_US_Form = ContactUSForm(request.POST)
        if Contact_US_Form.is_valid():
            Contact_US_Form = Contact_US_Form.save()
            Contact_US_Form.save()


            instance_admin_email = list(User.objects.filter(Q(user_type='Admin')|Q(user_type='Backend User')).values_list('email', flat=True))
            current_site = get_current_site(request)
            mail_subject = "Contact Request"
            message = render_to_string('email_template/contact_request.html',{
                'domain': current_site.domain,
                'Contact_US_Form':Contact_US_Form,
            })
            
            email = EmailMultiAlternatives(
                mail_subject, message, to=instance_admin_email
            )
            email.attach_alternative(message, "text/html")
            email.send()

            messages.add_message(request,messages.SUCCESS,'Contact request submited successfully.')

            return redirect("contact_us")
    else:
        Contact_US_Form = ContactUSForm()
    context = {
        'Contact_US_Form':Contact_US_Form
    }
    return render(request, 'before_login/contact_us.html', context)
#------------------------------------------ end user view ---------------------------------------------#










#-----------------------------------> Ajax Validation <---------------------------------#

def get_sub_category(request):
    category = request.GET.get('category', None)
    if category:
        instance_sub_category = CampaignSubCategory.objects.filter(category__id=category, is_active=True, category__is_active=True)
        context = {
            'sub_category':list(instance_sub_category.values('id', 'sub_category')),
        }
    else:
        context = {
            'sub_category':[],
        }
    return JsonResponse(context)



@login_required
@end_user_required
def my_fundraiser_campaign_dashboard(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)


        Today = datetime.now().date() 

        completed_days = ( datetime.now().date()  - instance_CampaignFundRaiser.created_at.date() ).days

        today_supporters = CampaignDoners.objects.filter(created_at__gte=Today, payment_status='captured', campaign_fund_raiser=instance_CampaignFundRaiser).count()
        total_supporters = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').count()

        total_supporters_graph = list(CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at'))
        total_supporters_dates = [x.get('created_at') for x in total_supporters_graph]

        for d in (datetime.today() - timedelta(days=x) for x in range(0,10)):
            if d.date() not in total_supporters_dates:
                total_supporters_graph.append({'created_at': d.date(), 'created_at__count': 0})


        # total_supporters_graph.sort(key = lambda x:x['created_at'])
        
        total_raised = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').aggregate(total_amount=Sum('amount'))
        today_raised = CampaignDoners.objects.filter(created_at__gte=Today, campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').aggregate(total_amount=Sum('amount'))
        
        
        today_visit = CampaignFundRaiserVisitHistory.objects.filter(created_at__gte=Today, campaign_fundraiser=instance_CampaignFundRaiser).distinct('ip','user').count()
        total_visit = CampaignFundRaiserVisitHistory.objects.filter(campaign_fundraiser=instance_CampaignFundRaiser).distinct('ip','user').count()
        previous_total_visit = CampaignFundRaiserVisitHistory.objects.filter(campaign_fundraiser=instance_CampaignFundRaiser).exclude(created_at__gte=Today).count()

        distinct_total_visit_graph = CampaignFundRaiserVisitHistory.objects.filter(created_at__lte=datetime.today(), created_at__gt=datetime.today()-timedelta(days=10)).distinct('ip','user')
        total_visit_graph = list(CampaignFundRaiserVisitHistory.objects.filter(campaign_fundraiser=instance_CampaignFundRaiser).extra({'created_at': "date(created_at)"}).values('created_at').annotate(Count('created_at')).order_by('created_at').filter(id__in=distinct_total_visit_graph))
        
        
        dates = [x.get('created_at') for x in total_visit_graph]

        for d in (datetime.today() - timedelta(days=x) for x in range(0,10)):
            if d.date() not in dates:
                total_visit_graph.append({'created_at': d.date(), 'created_at__count': 0})


        # total_visit_graph = total_visit_graph.order_by('created_at')


        # distinct_total_visit_graph.sort(key = lambda x:x['created_at'])

        facebook_total_supporters = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured', source__icontains='facebook').count()
        twitter_total_supporters = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured', source__icontains='twitter').count()
        whatsapp_total_supporters = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured', source__icontains='whatsapp').count()

        facebook_total_visit = CampaignFundRaiserVisitHistory.objects.filter(campaign_fundraiser=instance_CampaignFundRaiser, source__icontains='facebook').distinct('ip','user').count()
        twitter_total_visit = CampaignFundRaiserVisitHistory.objects.filter(campaign_fundraiser=instance_CampaignFundRaiser, source__icontains='twitter').distinct('ip','user').count()
        whatsapp_total_visit = CampaignFundRaiserVisitHistory.objects.filter(campaign_fundraiser=instance_CampaignFundRaiser, source__icontains='whatsapp').distinct('ip','user').count()
        try:
            today_increases = round((today_visit / ( previous_total_visit - today_visit )) * 100, 2)
        except ZeroDivisionError:
            today_increases = today_visit

        

        context = {
        'today_supporters':today_supporters,
        'total_supporters':total_supporters,
        'total_supporters_graph':total_supporters_graph,

        'today_visit':today_visit,
        'total_visit':total_visit,
        'total_visit_graph':total_visit_graph,

        'total_raised':total_raised,
        'today_raised':today_raised,

        'today_increases':today_increases,

        'instance_CampaignFundRaiser':instance_CampaignFundRaiser,

        'facebook_total_supporters':facebook_total_supporters,
        'twitter_total_supporters':twitter_total_supporters,
        'whatsapp_total_supporters':whatsapp_total_supporters,

        'facebook_total_visit':facebook_total_visit,
        'twitter_total_visit':twitter_total_visit,
        'whatsapp_total_visit':whatsapp_total_visit,

        'completed_days':completed_days,
        }

        return render(request, 'user_template/my_fundraiser_campaign_dashboard.html', context)
    except:
        return redirect('my_profile')

@login_required
@end_user_required
def my_fundraiser_campaign_modify(request, url_text):
    try:
    
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        form_error = False



        if request.method == "POST":
            form_type = request.POST.get('form_type', None)

            if form_type == 'Goal':
                CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserGoalForm.is_valid():
                    CampaignFundRaiserGoalForm = CampaignFundRaiserGoalForm.save()

                    messages.add_message(request,messages.SUCCESS,'Goal updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)
                else:
                    form_error = 'Goal'
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                    

            elif form_type == 'Title':
                CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserTitleForm.is_valid():
                    CampaignFundRaiserTitleForm = CampaignFundRaiserTitleForm.save()

                    messages.add_message(request,messages.SUCCESS,'Title updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Title'
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                    



            elif form_type == 'Picture':
                CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserPictureForm.is_valid():
                    CampaignFundRaiserPictureForm = CampaignFundRaiserPictureForm.save()

                    messages.add_message(request,messages.SUCCESS,'Picture updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Picture'
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                    




            elif form_type == 'About':
                CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserAboutForm.is_valid():
                    CampaignFundRaiserAboutForm = CampaignFundRaiserAboutForm.save()

                    messages.add_message(request,messages.SUCCESS,'About updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'About'
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                    


            elif form_type == 'Day':
                CampaignFundRaiserDay = CampaignFundRaiser_Day(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserDay.is_valid():
                    CampaignFundRaiserDay.save()

                    messages.add_message(request,messages.SUCCESS,'Days updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Day'
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                    

            elif form_type == 'short_description':
                CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserShortDescription.is_valid():
                    CampaignFundRaiserShortDescription.save()

                    messages.add_message(request,messages.SUCCESS,'Short Description updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'short_description'
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)


            elif form_type == 'EndGoal':
                CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserIsEndGoal_Form.is_valid():
                    CampaignFundRaiserIsEndGoal_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Campaign status updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'EndGoal'
                    
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)


            elif form_type == 'url':
                url_text = instance_CampaignFundRaiser.url_text
                CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserUrlText_Form.is_valid():
                    CampaignFundRaiserUrlText_Form.save()

                    return redirect(instance_CampaignFundRaiser.url_text)

                    messages.add_message(request,messages.SUCCESS,'Url text updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=instance_CampaignFundRaiser.url_text)

                else:
                    form_error = 'url'
                    instance_CampaignFundRaiser.url_text = url_text
                    instance_CampaignFundRaiser.save()
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)


            elif form_type == 'category':
                CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(request.POST, instance=instance_CampaignFundRaiser)
                if CampaignFundRaiserCategory_Form.is_valid():
                    CampaignFundRaiserCategory_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Category updated successfully.')

                    return redirect('my_fundraiser_campaign_modify', url_text=url_text)

                else:
                    form_error = 'category'
                    CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                    CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                    


            else:
                CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
                CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
                

        else:
            CampaignFundRaiserGoalForm = CampaignFundRaiser_Goal_Form(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserTitleForm = CampaignFundRaiser_Title_Form(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserPictureForm = CampaignFundRaiser_Picture_Form(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserAboutForm = CampaignFundRaiser_About_Form(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserDay = CampaignFundRaiser_Day(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserShortDescription = CampaignFundRaiser_Short_Description(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserUrlText_Form = CampaignFundRaiserUrlTextForm(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserIsEndGoal_Form = CampaignFundRaiserIsEndGoalForm(instance=instance_CampaignFundRaiser)
            CampaignFundRaiserCategory_Form = CampaignFundRaiserCategoryForm(instance=instance_CampaignFundRaiser)
            




       
        instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured').order_by("-id")


        current_site = get_current_site(request)
        domain = current_site.domain

        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignDoners':instance_CampaignDoners,
            

            "CampaignFundRaiserGoalForm":CampaignFundRaiserGoalForm,
            "CampaignFundRaiserTitleForm":CampaignFundRaiserTitleForm,
            "CampaignFundRaiserPictureForm" : CampaignFundRaiserPictureForm,
            "CampaignFundRaiserAboutForm" : CampaignFundRaiserAboutForm,
            'CampaignFundRaiserDay':CampaignFundRaiserDay,
            'CampaignFundRaiserShortDescription':CampaignFundRaiserShortDescription,
            'CampaignFundRaiserUrlText_Form':CampaignFundRaiserUrlText_Form,
            'CampaignFundRaiserIsEndGoal_Form':CampaignFundRaiserIsEndGoal_Form,
            'CampaignFundRaiserCategory_Form':CampaignFundRaiserCategory_Form,


            'Today':datetime.now().date(),
            'domain':domain,

            'form_error':form_error,
        }

        return render(request, 'user_template/my_fundraiser_campaign_modify.html', context)
    except:
        return redirect('dashboard')



@login_required
@end_user_required
def my_fundraiser_campaign_supporter(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)

        instance_CampaignDoners = PotentialCampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser)
        instance_CampaignDoners_created_at = PotentialCampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).values('created_at').distinct()
        instance_CampaignDoners_name = PotentialCampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).values('name').distinct()
        instance_CampaignDoners_email = PotentialCampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).values('email').distinct()
        instance_CampaignDoners_phone = PotentialCampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).values('phone').distinct()
        instance_CampaignDoners_sent = PotentialCampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser).values('sent').distinct()

        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignDoners':instance_CampaignDoners,
            'instance_CampaignDoners_created_at':instance_CampaignDoners_created_at,
            'instance_CampaignDoners_name':instance_CampaignDoners_name,
            'instance_CampaignDoners_email':instance_CampaignDoners_email,
            'instance_CampaignDoners_phone':instance_CampaignDoners_phone,
            'instance_CampaignDoners_sent':instance_CampaignDoners_sent,
        }


        return render(request, 'user_template/my_fundraiser_campaign_supporter.html', context)
    except:
        return redirect('dashboard')



@login_required
@end_user_required
def my_fundraiser_campaign_premium_services(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)


        form_error = False
        if request.method == 'POST':
            Services_Enquiry_Form = ServicesEnquiryForm(request.POST)
            if Services_Enquiry_Form.is_valid():
                Services_Enquiry_Form = Services_Enquiry_Form.save()


                try:
                    instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))
                    current_site = get_current_site(request)

                    mail_subject = "Services Enquiry"
                    message = render_to_string('email_template/services_enquiry_to_admin.html',{
                        'domain': current_site.domain,
                        'Services_Enquiry_Form':Services_Enquiry_Form,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=instance_admin_email
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass


                try:
                    current_site = get_current_site(request)

                    mail_subject = "Services Enquiry Confirmation"
                    message = render_to_string('email_template/services_enquiry_to_user.html',{
                        'domain': current_site.domain,
                        'Services_Enquiry_Form':Services_Enquiry_Form,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=[Services_Enquiry_Form.email]
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass



                messages.add_message(request,messages.SUCCESS,'Services enquiry send successfully.')

                return redirect('my_fundraiser_campaign_premium_services', url_text=url_text)

            else:
                form_error = True
        else:
            Services_Enquiry_Form = ServicesEnquiryForm(initial={'name':request.user.name, 'email':request.user.email, 'mobile_no':request.user.mobile_no})

        context = {
           'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'Services_Enquiry_Form':Services_Enquiry_Form,
            'form_error':form_error,
        }
        return render(request, 'user_template/my_fundraiser_campaign_premium_services.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_fundraiser_campaign_document(request, url_text):
    # try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)

        if request.method == 'POST':
            form_type = request.POST.get('form_type')
            if form_type == 'cheque':
                cancelled_cheque_form = CampaignFundRaiserCancelledChequeForm(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
                if cancelled_cheque_form.is_valid():
                    cancelled_cheque_form.save()
                    messages.add_message(request,messages.SUCCESS,'Cancelled cheque uploaded successfully.')

                    return redirect('my_fundraiser_campaign_document', url_text=url_text)
                else:
                    address_proof_form = CampaignFundRaiserAddressProofForm(instance=instance_CampaignFundRaiser)
                    pancard_proof_form = CampaignFundRaiserPancardProofForm(instance=instance_CampaignFundRaiser)

            elif form_type == 'address':
                address_proof_form = CampaignFundRaiserAddressProofForm(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
                if address_proof_form.is_valid():
                    address_proof_form.save()
                    messages.add_message(request,messages.SUCCESS,'Address proof uploaded successfully.')

                    return redirect('my_fundraiser_campaign_document', url_text=url_text)
                else:
                    cancelled_cheque_form = CampaignFundRaiserCancelledChequeForm(instance=instance_CampaignFundRaiser)
                    pancard_proof_form = CampaignFundRaiserPancardProofForm(instance=instance_CampaignFundRaiser)

            elif form_type == 'pancard':
                pancard_proof_form = CampaignFundRaiserPancardProofForm(request.POST, request.FILES, instance=instance_CampaignFundRaiser)
                if pancard_proof_form.is_valid():
                    pancard_proof_form.save()
                    messages.add_message(request,messages.SUCCESS,'Pancard uploaded successfully.')

                    return redirect('my_fundraiser_campaign_document', url_text=url_text)
                else:
                    cancelled_cheque_form = CampaignFundRaiserCancelledChequeForm(instance=instance_CampaignFundRaiser)
                    address_proof_form = CampaignFundRaiserAddressProofForm(instance=instance_CampaignFundRaiser)

            else:
                cancelled_cheque_form = CampaignFundRaiserCancelledChequeForm(instance=instance_CampaignFundRaiser)
                address_proof_form = CampaignFundRaiserAddressProofForm(instance=instance_CampaignFundRaiser)
                pancard_proof_form = CampaignFundRaiserPancardProofForm(instance=instance_CampaignFundRaiser)

        else:
            cancelled_cheque_form = CampaignFundRaiserCancelledChequeForm(instance=instance_CampaignFundRaiser)
            address_proof_form = CampaignFundRaiserAddressProofForm(instance=instance_CampaignFundRaiser)
            pancard_proof_form = CampaignFundRaiserPancardProofForm(instance=instance_CampaignFundRaiser)


        context = {
            'cancelled_cheque_form':cancelled_cheque_form,
            'address_proof_form':address_proof_form,
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'pancard_proof_form':pancard_proof_form,
        }


        return render(request, 'user_template/my_fundraiser_campaign_document.html', context)
    # except:
    #     return redirect('dashboard')


@login_required
@end_user_required
def my_fundraiser_campaign_updates(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        instance_CampaignUpdates = CampaignUpdates.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser)

        if request.method == 'POST':
            campaign_updates_form = CampaignUpdatesForm(request.POST)
            if campaign_updates_form.is_valid():
                campaign_updates_form = campaign_updates_form.save(commit=False)
                campaign_updates_form.campaign_fund_raiser = instance_CampaignFundRaiser
                campaign_updates_form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Update " %s " added successfully. ' %(campaign_updates_form.title))

                return redirect('my_fundraiser_campaign_updates', url_text=url_text)

        else:
            campaign_updates_form = CampaignUpdatesForm()


        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignUpdates':instance_CampaignUpdates,
            'CampaignUpdates_Form':campaign_updates_form,
        }
        return render(request, 'user_template/my_fundraiser_campaign_updates.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_fundraiser_campaign_buzz(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        instance_CampaignBuzz = CampaignBuzz.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser)

        if request.method == 'POST':
            campaign_buzz_form = CampaignBuzzForm(request.POST, request.FILES)
            if campaign_buzz_form.is_valid():
                campaign_buzz_form = campaign_buzz_form.save(commit=False)
                campaign_buzz_form.campaign_fund_raiser = instance_CampaignFundRaiser
                campaign_buzz_form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Buzz " %s " added successfully. ' %(campaign_buzz_form.title))

                return redirect('my_fundraiser_campaign_buzz', url_text=url_text)

        else:
            campaign_buzz_form = CampaignBuzzForm()


        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignBuzz':instance_CampaignBuzz,
            'CampaignBuzz_Form':campaign_buzz_form,
        }
        return render(request, 'user_template/my_fundraiser_campaign_buzz.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_fundraiser_campaign_updates_delete(request, url_text, id):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        instance_CampaignUpdates = CampaignUpdates.objects.get(id=id, campaign_fund_raiser=instance_CampaignFundRaiser)

        instance_CampaignUpdates.delete()

        messages.add_message(request,messages.SUCCESS,'Campaign Update deleted successfully. ')

        return redirect('my_fundraiser_campaign_updates', url_text=url_text)

    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_fundraiser_campaign_buzz_delete(request, url_text, id):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        instance_CampaignBuzz = CampaignBuzz.objects.get(id=id, campaign_fund_raiser=instance_CampaignFundRaiser)

        instance_CampaignBuzz.delete()
        messages.add_message(request,messages.SUCCESS,'Campaign Buzz deleted successfully.')

        return redirect('my_fundraiser_campaign_buzz', url_text=url_text)

       
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_fundraiser_campaign_comment(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        instance_comment = CampaignComments.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser)

        if request.method == 'POST':
            enable_comment_form = CampaignFundRaiserEnableCommentForm(request.POST, instance=instance_CampaignFundRaiser)
            if enable_comment_form.is_valid():
                enable_comment_form.save()
        else:
            enable_comment_form = CampaignFundRaiserEnableCommentForm(instance=instance_CampaignFundRaiser)

        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_comment':instance_comment,
            'Today':datetime.now(),
            'enable_comment_form':enable_comment_form,
        }
        return render(request, 'user_template/my_fundraiser_campaign_comment.html', context)
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_fundraiser_campaign_supporter_donor_info(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)
        instance_CampaignDoners = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, payment_status='captured')
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_CampaignDoners':instance_CampaignDoners,
            
        }
        return render(request, 'user_template/my_fundraiser_campaign_supporter_donor_info.html', context)
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_fundraiser_campaign_withdraw_funds(request, url_text):
    try:
        form_error = False
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)


        instance_WithdrawalRequest_amount = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser, status="New").aggregate(Sum('amount'))

        instance_WithdrawalRequest = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser)

        instance_refund = CampaignDoners.objects.filter(campaign_fund_raiser=instance_CampaignFundRaiser, refund_status='refund approved').aggregate(Sum('amount'))

        try:
            instance_WithdrawalRequest_latest = WithdrawalRequest.objects.filter(campaign=instance_CampaignFundRaiser, status='Approved').order_by("-id")[0]
        except:
            instance_WithdrawalRequest_latest = False



        if request.method == 'POST':
            Withdrawal_Request_Form = WithdrawalRequestForm(request.POST, request.FILES)
            if Withdrawal_Request_Form.is_valid():
                Withdrawal_Request_Form = Withdrawal_Request_Form.save()

                messages.add_message(request,messages.SUCCESS, 'Withdrawal request sended successfully')

                return redirect('my_fundraiser_campaign_withdraw_funds', url_text=url_text)
            else:
                form_error = True

        else:
            Withdrawal_Request_Form = WithdrawalRequestForm(initial={'campaign':instance_CampaignFundRaiser.id})


        instance_our_democracy_commission_in_rs = CampaignDoners.objects.filter(campaign_fund_raiser__id=instance_CampaignFundRaiser.id, payment_status='captured').aggregate(Sum('our_democracy_commission_in_rs'))['our_democracy_commission_in_rs__sum']
        instance_our_democracy_gst_in_rs = CampaignDoners.objects.filter(campaign_fund_raiser__id=instance_CampaignFundRaiser.id, payment_status='captured').aggregate(Sum('our_democracy_gst_in_rs'))['our_democracy_gst_in_rs__sum']
        instance_payment_gateway_charges_in_rs = CampaignDoners.objects.filter(campaign_fund_raiser__id=instance_CampaignFundRaiser.id, payment_status='captured').aggregate(Sum('payment_gateway_charges_in_rs'))['payment_gateway_charges_in_rs__sum']
        instance_payment_gateway_gst_in_rs = CampaignDoners.objects.filter(campaign_fund_raiser__id=instance_CampaignFundRaiser.id, payment_status='captured').aggregate(Sum('payment_gateway_gst_in_rs'))['payment_gateway_gst_in_rs__sum']

        try:
            instance_our_democracy_commission_in_rs = float(instance_our_democracy_commission_in_rs)
        except:
            instance_our_democracy_commission_in_rs = 0

        try:
            instance_our_democracy_gst_in_rs = float(instance_our_democracy_gst_in_rs)
        except:
            instance_our_democracy_gst_in_rs = 0

        try:
            instance_payment_gateway_charges_in_rs = float(instance_payment_gateway_charges_in_rs)
        except:
            instance_payment_gateway_charges_in_rs = 0

        try:
            instance_payment_gateway_gst_in_rs = float(instance_payment_gateway_gst_in_rs)
        except:
            instance_payment_gateway_gst_in_rs = 0

        try:
            last_withdrawl = WithdrawalRequest.objects.filter(campaign__id=instance_CampaignFundRaiser.id, status='Approved').order_by('-id')[0].amount
        except:
            last_withdrawl = 0



        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'instance_refund':instance_refund,
            'instance_WithdrawalRequest_amount':instance_WithdrawalRequest_amount,
            'instance_WithdrawalRequest':instance_WithdrawalRequest,
            'instance_WithdrawalRequest_latest':instance_WithdrawalRequest_latest,
            'Withdrawal_Request_Form':Withdrawal_Request_Form,
            'form_error':form_error,

            'instance_our_democracy_commission_in_rs':instance_our_democracy_commission_in_rs,
            'instance_payment_gateway_charges_in_rs':instance_payment_gateway_charges_in_rs,
            'gst_in_rs':instance_payment_gateway_gst_in_rs + instance_our_democracy_gst_in_rs,

            'last_withdrawl':last_withdrawl,

        }


        return render(request, 'user_template/my_fundraiser_campaign_withdraw_funds.html', context)
    except:
        return redirect('dashboard')


#------------------------ mobilization-------------------------

@login_required
@end_user_required
def my_mobilisation_campaign_dashboard(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)

        Today = datetime.now().date() 
        completed_days = ( datetime.now().date()  - instance_SupportGroup.created_at.date() ).days

        today_supporters = SupportGroupMembers.objects.filter(created_at__gte=Today, support_group=instance_SupportGroup).count()
        total_supporters = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).count()

        total_supporters_graph = list(SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at'))
        total_supporters_dates = [x.get('created_at') for x in total_supporters_graph]

        for d in (datetime.today() - timedelta(days=x) for x in range(0,10)):
            if d.date() not in total_supporters_dates:
                total_supporters_graph.append({'created_at': d, 'created_at__count': 0})
        
        today_visit = SupportVisitHistory.objects.filter(created_at__gte=Today, support_group=instance_SupportGroup).distinct('ip','user').count()
        total_visit = SupportVisitHistory.objects.filter(support_group=instance_SupportGroup).distinct('ip','user').count()
        previous_total_visit = SupportVisitHistory.objects.filter(support_group=instance_SupportGroup).exclude(created_at__gte=Today).count()

        distinct_total_visit_graph = SupportVisitHistory.objects.distinct('ip','user')
        total_visit_graph = list(SupportVisitHistory.objects.filter(support_group=instance_SupportGroup, created_at__lte=datetime.today(), created_at__gt=datetime.today()-timedelta(days=10)).extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at').filter(id__in=distinct_total_visit_graph))
        dates = [x.get('created_at') for x in total_visit_graph]

        for d in (datetime.today() - timedelta(days=x) for x in range(0,10)):
            if d.date() not in dates:
                total_visit_graph.append({'created_at': d, 'created_at__count': 0})

        facebook_total_supporters = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, source__icontains='facebook').count()
        twitter_total_supporters = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, source__icontains='twitter').count()
        whatsapp_total_supporters = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, source__icontains='whatsapp').count()

        facebook_total_visit = SupportVisitHistory.objects.filter(support_group=instance_SupportGroup, source__icontains='facebook').distinct('ip','user').count()
        twitter_total_visit = SupportVisitHistory.objects.filter(support_group=instance_SupportGroup, source__icontains='twitter').distinct('ip','user').count()
        whatsapp_total_visit = SupportVisitHistory.objects.filter(support_group=instance_SupportGroup, source__icontains='whatsapp').distinct('ip','user').count()


        try:
            today_increases = round((today_visit / ( previous_total_visit - today_visit )) * 100, 2)
        except ZeroDivisionError:
            today_increases = today_visit

        context = {
        'today_supporters':today_supporters,
        'total_supporters':total_supporters,
        'total_supporters_graph':total_supporters_graph,

        'today_visit':today_visit,
        'total_visit':total_visit,
        'total_visit_graph':total_visit_graph,

        'today_increases':today_increases,

        'instance_SupportGroup':instance_SupportGroup,

        'facebook_total_supporters':facebook_total_supporters,
        'twitter_total_supporters':twitter_total_supporters,
        'whatsapp_total_supporters':whatsapp_total_supporters,

        'facebook_total_visit':facebook_total_visit,
        'twitter_total_visit':twitter_total_visit,
        'whatsapp_total_visit':whatsapp_total_visit,

        'completed_days':completed_days,
        }

        return render(request, 'user_template/my_mobilisation_campaign_dashboard.html', context)
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_mobilisation_campaign_modify(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        form_error = False
        if request.method == "POST":
            form_type = request.POST.get('form_type', None)

            if form_type == 'Goal':
                SupportGroup_Goal_Form = SupportGroupGoalForm(request.POST, instance=instance_SupportGroup)
                if SupportGroup_Goal_Form.is_valid():
                    SupportGroup_Goal_Form = SupportGroup_Goal_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Goal updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=url_text)
                else:
                    form_error = 'Goal'
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)

            elif form_type == 'Title':
                SupportGroup_Title_Form = SupportGroupTitleForm(request.POST, instance=instance_SupportGroup)
                if SupportGroup_Title_Form.is_valid():
                    SupportGroup_Title_Form = SupportGroup_Title_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Title updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Title'
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)

            elif form_type == 'Picture':
                SupportGroup_Picture_Form = SupportGroupPictureForm(request.POST, request.FILES, instance=instance_SupportGroup)
                if SupportGroup_Picture_Form.is_valid():
                    SupportGroup_Picture_Form = SupportGroup_Picture_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Picture updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Picture'
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)


            elif form_type == 'About':
                SupportGroup_About_Form = SupportGroupAboutForm(request.POST, instance=instance_SupportGroup)
                if SupportGroup_About_Form.is_valid():
                    SupportGroup_About_Form = SupportGroup_About_Form.save()

                    messages.add_message(request,messages.SUCCESS,'About updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=url_text)

                else:
                    form_error = 'About'
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)


            elif form_type == 'ShortDescription':
                SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(request.POST, instance=instance_SupportGroup)
                if SupportGroup_ShortDescription_Form.is_valid():
                    SupportGroup_ShortDescription_Form = SupportGroup_ShortDescription_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Short Description updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=url_text)

                else:
                    form_error = 'short_description'
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)


            elif form_type == 'url':
                url_text = instance_SupportGroup.url_text
                SupportGroupUrlText_Form = SupportGroupUrlTextForm(request.POST, instance=instance_SupportGroup)
                if SupportGroupUrlText_Form.is_valid():
                    SupportGroupUrlText_Form = SupportGroupUrlText_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Url text updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=instance_SupportGroup.url_text)

                else:
                    instance_SupportGroup.url_text = url_text
                    instance_SupportGroup.save()
                    form_error = 'url'
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)


            elif form_type == 'EndGoal':
                SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(request.POST, instance=instance_SupportGroup)
                if SupportGroupIsEndGoal_Form.is_valid():
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoal_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Campaign status updated successfully.')

                    return redirect('my_mobilisation_campaign_modify', url_text=url_text)

                else:
                    form_error = 'EndGoal'
                    SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                    SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                    SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                    SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                    SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                    SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                    SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)



            else:
                SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
                SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
                SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
                SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
                SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
                SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
                SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)

        else:
            SupportGroup_Goal_Form = SupportGroupGoalForm(instance=instance_SupportGroup)
            SupportGroup_Title_Form = SupportGroupTitleForm(instance=instance_SupportGroup)
            SupportGroup_Picture_Form = SupportGroupPictureForm(instance=instance_SupportGroup)
            SupportGroup_About_Form = SupportGroupAboutForm(instance=instance_SupportGroup)
            SupportGroup_ShortDescription_Form = SupportGroupShortDescriptionForm(instance=instance_SupportGroup)
            SupportGroupUrlText_Form = SupportGroupUrlTextForm(instance=instance_SupportGroup)
            SupportGroupIsEndGoal_Form = SupportGroupIsEndGoalForm(instance=instance_SupportGroup)

        
        instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup).order_by("-id")


        current_site = get_current_site(request)
        domain = current_site.domain

        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'instance_SupportGroupMembers':instance_SupportGroupMembers,


            'SupportGroup_Goal_Form':SupportGroup_Goal_Form,
            'SupportGroup_Title_Form':SupportGroup_Title_Form,
            'SupportGroup_Picture_Form':SupportGroup_Picture_Form,
            'SupportGroup_About_Form':SupportGroup_About_Form,
            'SupportGroup_ShortDescription_Form':SupportGroup_ShortDescription_Form,
            'SupportGroupUrlText_Form':SupportGroupUrlText_Form,
            'SupportGroupIsEndGoal_Form':SupportGroupIsEndGoal_Form,


            'Today':datetime.now().date(),
            'domain':domain,
            'form_error':form_error,
        }

        return render(request, 'user_template/my_mobilisation_campaign_modify.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_supporter(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)

        instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup, is_share=True)


        context = {
            'instance_SupportGroupMembers':instance_SupportGroupMembers,
            'instance_SupportGroup':instance_SupportGroup,
        }

        return render(request, 'user_template/my_mobilisation_campaign_supporter.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_premium_services(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)



        form_error = False
        if request.method == 'POST':
            Services_Enquiry_Form = ServicesEnquiryForm(request.POST)
            if Services_Enquiry_Form.is_valid():
                Services_Enquiry_Form = Services_Enquiry_Form.save()


                try:
                    instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))
                    current_site = get_current_site(request)

                    mail_subject = "Services Enquiry"
                    message = render_to_string('email_template/services_enquiry_to_admin.html',{
                        'domain': current_site.domain,
                        'Services_Enquiry_Form':Services_Enquiry_Form,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=instance_admin_email
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass


                try:
                    current_site = get_current_site(request)

                    mail_subject = "Services Enquiry Confirmation"
                    message = render_to_string('email_template/services_enquiry_to_user.html',{
                        'domain': current_site.domain,
                        'Services_Enquiry_Form':Services_Enquiry_Form,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=[Services_Enquiry_Form.email]
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass



                messages.add_message(request,messages.SUCCESS,'Services enquiry send successfully.')

                return redirect('my_mobilisation_campaign_premium_services', url_text=url_text)

            else:
                form_error = True
        else:
            Services_Enquiry_Form = ServicesEnquiryForm(initial={'name':request.user.name, 'email':request.user.email, 'mobile_no':request.user.mobile_no})

        context = {
           'instance_SupportGroup':instance_SupportGroup,
            'Services_Enquiry_Form':Services_Enquiry_Form,
            'form_error':form_error,
        }
        return render(request, 'user_template/my_mobilisation_campaign_premium_services.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_updates(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        instance_SupportUpdates = SupportUpdates.objects.filter(support_group=instance_SupportGroup)

        if request.method == 'POST':
            SupportUpdates_Form = SupportUpdatesForm(request.POST)
            if SupportUpdates_Form.is_valid():
                SupportUpdates_Form = SupportUpdates_Form.save(commit=False)
                SupportUpdates_Form.support_group = instance_SupportGroup
                SupportUpdates_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Update " %s " added successfully. ' %(SupportUpdates_Form.title))

                return redirect('my_mobilisation_campaign_updates', url_text=url_text)

        else:
            SupportUpdates_Form = SupportUpdatesForm()


        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'instance_SupportUpdates':instance_SupportUpdates,
            'SupportUpdates_Form':SupportUpdates_Form,
        }
        return render(request, 'user_template/my_mobilisation_campaign_updates.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_buzz(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        instance_SupportBuzz = SupportBuzz.objects.filter(support_group=instance_SupportGroup)

        if request.method == 'POST':
            SupportBuzz_Form = SupportBuzzForm(request.POST, request.FILES)
            if SupportBuzz_Form.is_valid():
                SupportBuzz_Form = SupportBuzz_Form.save(commit=False)
                SupportBuzz_Form.support_group = instance_SupportGroup
                SupportBuzz_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Buzz " %s " added successfully. ' %(SupportBuzz_Form.title))

                return redirect('my_mobilisation_campaign_buzz', url_text=url_text)

        else:
            SupportBuzz_Form = SupportBuzzForm()


        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'instance_SupportBuzz':instance_SupportBuzz,
            'SupportBuzz_Form':SupportBuzz_Form,
        }
        return render(request, 'user_template/my_mobilisation_campaign_buzz.html', context)
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_mobilisation_campaign_comment(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        instance_SupportComments = SupportComments.objects.filter(support_group=instance_SupportGroup)

        if request.method == 'POST':
            enable_comment_form = SupportGroupEnableCommentForm(request.POST, instance=instance_SupportGroup)
            if enable_comment_form.is_valid():
                enable_comment_form.save()
        else:
            enable_comment_form = SupportGroupEnableCommentForm(instance=instance_SupportGroup)

        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'instance_SupportComments':instance_SupportComments,
            'enable_comment_form':enable_comment_form,
        }
        return render(request, 'user_template/my_mobilisation_campaign_comment.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_supporter_donor_info(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        instance_SupportGroupMembers = SupportGroupMembers.objects.filter(support_group=instance_SupportGroup)

        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'instance_SupportGroupMembers':instance_SupportGroupMembers,
        }
        return render(request, 'user_template/my_mobilisation_campaign_supporter_donor_info.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_updates_delete(request, url_text, id):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        instance_SupportUpdates = SupportUpdates.objects.get(id=id, support_group=instance_SupportGroup)

        instance_SupportUpdates.delete()

        messages.add_message(request,messages.SUCCESS,'Campaign Update deleted successfully. ')

        return redirect('my_mobilisation_campaign_updates', url_text=url_text)

    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_mobilisation_campaign_buzz_delete(request, url_text, id):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)
        instance_SupportBuzz = SupportBuzz.objects.get(id=id, support_group=instance_SupportGroup)

        instance_SupportBuzz.delete()
        messages.add_message(request,messages.SUCCESS,'Campaign Buzz deleted successfully.')

        return redirect('my_mobilisation_campaign_buzz', url_text=url_text)

       
    except:
        return redirect('dashboard')


#-------------------------- event -----------------------------


@login_required
@end_user_required
def my_event_dashboard(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)


        Today = datetime.now().date() 
        completed_days = ( datetime.now().date()  - instance_Event.created_at.date() ).days

        today_supporters = EventGroupMembers.objects.filter(created_at__gte=Today, event=instance_Event).count()
        total_supporters = EventGroupMembers.objects.filter(event=instance_Event).count()

        total_supporters_graph = list(EventGroupMembers.objects.filter(event=instance_Event).extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at'))
        total_supporters_dates = [x.get('created_at') for x in total_supporters_graph]

        for d in (datetime.today() - timedelta(days=x) for x in range(0,10)):
            if d.date() not in total_supporters_dates:
                total_supporters_graph.append({'created_at': d, 'created_at__count': 0})

        today_visit = EventVisitHistory.objects.filter(created_at__gte=Today, event=instance_Event).distinct('ip','user').count()
        total_visit = EventVisitHistory.objects.filter(event=instance_Event).distinct('ip','user').count()
        previous_total_visit = EventVisitHistory.objects.filter(event=instance_Event).exclude(created_at__gte=Today).count()
        distinct_total_visit_graph = EventVisitHistory.objects.distinct('ip','user')
        total_visit_graph = list(EventVisitHistory.objects.filter(event=instance_Event, created_at__lte=datetime.today(), created_at__gt=datetime.today()-timedelta(days=10)).extra({'created_at': "date(created_at)"}).values('created_at').distinct().annotate(Count('created_at')).order_by('created_at').filter(id__in=distinct_total_visit_graph))
        dates = [x.get('created_at') for x in total_visit_graph]

        for d in (datetime.today() - timedelta(days=x) for x in range(0,10)):
            if d.date() not in dates:
                total_visit_graph.append({'created_at': d, 'created_at__count': 0})


        facebook_total_supporters = EventGroupMembers.objects.filter(event=instance_Event, source__icontains='facebook').count()
        twitter_total_supporters = EventGroupMembers.objects.filter(event=instance_Event, source__icontains='twitter').count()
        whatsapp_total_supporters = EventGroupMembers.objects.filter(event=instance_Event, source__icontains='whatsapp').count()

        facebook_total_visit = EventVisitHistory.objects.filter(event=instance_Event, source__icontains='facebook').distinct('ip','user').count()
        twitter_total_visit = EventVisitHistory.objects.filter(event=instance_Event, source__icontains='twitter').distinct('ip','user').count()
        whatsapp_total_visit = EventVisitHistory.objects.filter(event=instance_Event, source__icontains='whatsapp').distinct('ip','user').count()


        try:
            today_increases = round((today_visit / ( previous_total_visit - today_visit )) * 100, 2)
        except ZeroDivisionError:
            today_increases = today_visit

        context = {
        'today_supporters':today_supporters,
        'total_supporters':total_supporters,
        'total_supporters_graph':total_supporters_graph,

        'today_visit':today_visit,
        'total_visit':total_visit,
        'total_visit_graph':total_visit_graph,

        'today_increases':today_increases,

        'instance_Event':instance_Event,

        'facebook_total_supporters':facebook_total_supporters,
        'twitter_total_supporters':twitter_total_supporters,
        'whatsapp_total_supporters':whatsapp_total_supporters,

        'facebook_total_visit':facebook_total_visit,
        'twitter_total_visit':twitter_total_visit,
        'whatsapp_total_visit':whatsapp_total_visit,

        'completed_days':completed_days,

        }

        return render(request, 'user_template/my_event_dashboard.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_modify(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        form_error = False

        if request.method == "POST":
            form_type = request.POST.get('form_type', None)

            if form_type == 'Title':
                Event_Title_Form = EventTitleForm(request.POST, instance=instance_Event)
                if Event_Title_Form.is_valid():
                    Event_Title_Form = Event_Title_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Title updated successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Title'
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
                    EventUrlText_Form = EventUrlTextForm(instance=instance_Event)



            elif form_type == 'Picture':
                Event_Picture_Form = EventPictureForm(request.POST, request.FILES, instance=instance_Event)
                if Event_Picture_Form.is_valid():
                    Event_Picture_Form = Event_Picture_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Picture updated successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Picture'
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
                    EventUrlText_Form = EventUrlTextForm(instance=instance_Event)




            elif form_type == 'About':
                Event_About_Form = EventAboutForm(request.POST, instance=instance_Event)
                if Event_About_Form.is_valid():
                    Event_About_Form = Event_About_Form.save()

                    messages.add_message(request,messages.SUCCESS,'About updated successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'About'
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
                    EventUrlText_Form = EventUrlTextForm(instance=instance_Event)


            if form_type == 'Location':
                Event_Place_Form = EventPlaceForm(request.POST, instance=instance_Event)
                if Event_Place_Form.is_valid():
                    Event_Place_Form = Event_Place_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Location updated successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Location'
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
                    EventUrlText_Form = EventUrlTextForm(instance=instance_Event)


            if form_type == 'Date':
                Event_Date_Form = EventDateForm(request.POST, instance=instance_Event)
                if Event_Date_Form.is_valid():
                    Event_Date_Form = Event_Date_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Date updated successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'Date'
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
                    EventUrlText_Form = EventUrlTextForm(instance=instance_Event)


            if form_type == 'EndGoal':
                EventIsEndGoal_Form = EventIsEndGoalForm(request.POST, instance=instance_Event)
                if EventIsEndGoal_Form.is_valid():
                    EventIsEndGoal_Form = EventIsEndGoal_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Event status updated successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'EndGoal'
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    EventUrlText_Form = EventUrlTextForm(instance=instance_Event)

            if form_type == 'url':
                url_text = instance_Event.url_text
                EventUrlText_Form = EventUrlTextForm(request.POST, instance=instance_Event)
                if EventUrlText_Form.is_valid():
                    EventUrlText_Form = EventUrlText_Form.save()

                    messages.add_message(request,messages.SUCCESS,'Url text successfully.')

                    return redirect('my_event_campaign_modify', url_text=url_text)

                else:
                    form_error = 'url'
                    instance_Event.url_text = url_text
                    instance_Event.save()
                    Event_Title_Form = EventTitleForm(instance=instance_Event)
                    Event_Picture_Form = EventPictureForm(instance=instance_Event)
                    Event_About_Form = EventAboutForm(instance=instance_Event)
                    Event_Place_Form = EventPlaceForm(instance=instance_Event)
                    Event_Date_Form = EventDateForm(instance=instance_Event)
                    EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)

            else:
                Event_Title_Form = EventTitleForm(instance=instance_Event)
                Event_Picture_Form = EventPictureForm(instance=instance_Event)
                Event_About_Form = EventAboutForm(instance=instance_Event)
                Event_Place_Form = EventPlaceForm(instance=instance_Event)
                Event_Date_Form = EventDateForm(instance=instance_Event)
                EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
                EventUrlText_Form = EventUrlTextForm(instance=instance_Event)


        else:
            Event_Title_Form = EventTitleForm(instance=instance_Event)
            Event_Picture_Form = EventPictureForm(instance=instance_Event)
            Event_About_Form = EventAboutForm(instance=instance_Event)
            Event_Place_Form = EventPlaceForm(instance=instance_Event)
            Event_Date_Form = EventDateForm(instance=instance_Event)
            EventIsEndGoal_Form = EventIsEndGoalForm(instance=instance_Event)
            EventUrlText_Form = EventUrlTextForm(instance=instance_Event)


        
        instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event).order_by("-id")


        current_site = get_current_site(request)
        domain = current_site.domain

        context = {
            'instance_Event':instance_Event,
            'instance_EventGroupMembers':instance_EventGroupMembers,

            'Event_Title_Form':Event_Title_Form,
            'Event_Picture_Form':Event_Picture_Form,
            'Event_About_Form':Event_About_Form,
            'Event_Place_Form':Event_Place_Form,
            'Event_Date_Form':Event_Date_Form,
            'EventIsEndGoal_Form':EventIsEndGoal_Form,
            'EventUrlText_Form':EventUrlText_Form,

            'Today':datetime.now().date(),
            'domain':domain,

            'form_error':form_error,
        }
        
        return render(request, 'user_template/my_event_campaign_modify.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_supporter(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)

        instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event, is_share=True)
        context = {
            'instance_EventGroupMembers':instance_EventGroupMembers,
            'instance_Event':instance_Event,
        }

        return render(request, 'user_template/my_event_campaign_supporter.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_premium_services(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)


        form_error = False
        if request.method == 'POST':
            Services_Enquiry_Form = ServicesEnquiryForm(request.POST)
            if Services_Enquiry_Form.is_valid():
                Services_Enquiry_Form = Services_Enquiry_Form.save()


                try:
                    instance_admin_email = list(User.objects.filter(user_type='Admin').values_list('email', flat=True))
                    current_site = get_current_site(request)

                    mail_subject = "Services Enquiry"
                    message = render_to_string('email_template/services_enquiry_to_admin.html',{
                        'domain': current_site.domain,
                        'Services_Enquiry_Form':Services_Enquiry_Form,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=instance_admin_email
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass


                try:
                    current_site = get_current_site(request)

                    mail_subject = "Services Enquiry Confirmation"
                    message = render_to_string('email_template/services_enquiry_to_user.html',{
                        'domain': current_site.domain,
                        'Services_Enquiry_Form':Services_Enquiry_Form,
                    })
                    email = EmailMultiAlternatives(
                        mail_subject, message, to=[Services_Enquiry_Form.email]
                    )
                    email.attach_alternative(message, "text/html")
                    email.send()
                except:
                    pass



                messages.add_message(request,messages.SUCCESS,'Services enquiry send successfully.')

                return redirect('my_event_campaign_premium_services', url_text=url_text)

            else:
                form_error = True
        else:
            Services_Enquiry_Form = ServicesEnquiryForm(initial={'name':request.user.name, 'email':request.user.email, 'mobile_no':request.user.mobile_no})

        context = {
            'instance_Event':instance_Event,
            'Services_Enquiry_Form':Services_Enquiry_Form,
            'form_error':form_error,
        }
        return render(request, 'user_template/my_event_campaign_premium_services.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_updates(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        instance_EventUpdates = EventUpdates.objects.filter(event=instance_Event)

        if request.method == 'POST':
            EventUpdates_Form = EventUpdatesForm(request.POST)
            if EventUpdates_Form.is_valid():
                EventUpdates_Form = EventUpdates_Form.save(commit=False)
                EventUpdates_Form.event = instance_Event
                EventUpdates_Form.save()

                messages.add_message(request,messages.SUCCESS,'Event Update " %s " added successfully. ' %(EventUpdates_Form.title))

                return redirect('my_event_campaign_updates', url_text=url_text)

        else:
            EventUpdates_Form = EventUpdatesForm()


        context = {
            'instance_Event':instance_Event,
            'instance_EventUpdates':instance_EventUpdates,
            'EventUpdates_Form':EventUpdates_Form,
        }
        return render(request, 'user_template/my_event_campaign_updates.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_buzz(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        instance_EventBuzz = EventBuzz.objects.filter(event=instance_Event)

        if request.method == 'POST':
            EventBuzz_Form = EventBuzzForm(request.POST, request.FILES)
            if EventBuzz_Form.is_valid():
                EventBuzz_Form = EventBuzz_Form.save(commit=False)
                EventBuzz_Form.event = instance_Event
                EventBuzz_Form.save()

                messages.add_message(request,messages.SUCCESS,'Campaign Buzz " %s " added successfully. ' %(EventBuzz_Form.title))

                return redirect('my_event_campaign_buzz', url_text=url_text)

        else:
            EventBuzz_Form = EventBuzzForm()


        context = {
            'instance_Event':instance_Event,
            'instance_EventBuzz':instance_EventBuzz,
            'EventBuzz_Form':EventBuzz_Form,
        }
        return render(request, 'user_template/my_event_campaign_buzz.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_comment(request, url_text):
    # try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        instance_EventComments = EventComments.objects.filter(event=instance_Event)

        if request.method == 'POST':
            enable_comment_form = EventEnableCommentForm(request.POST, instance=instance_Event)
            if enable_comment_form.is_valid():
                enable_comment_form.save()
        else:
            enable_comment_form = EventEnableCommentForm(instance=instance_Event)

        context = {
            'instance_Event':instance_Event,
            'instance_EventComments':instance_EventComments,
            'enable_comment_form':enable_comment_form,
        }
        return render(request, 'user_template/my_event_campaign_comment.html', context)
    # except:
    #     return redirect('dashboard')

@login_required
@end_user_required
def my_event_campaign_supporter_donor_info(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        instance_EventGroupMembers = EventGroupMembers.objects.filter(event=instance_Event)

        context = {
            'instance_Event':instance_Event,
            'instance_EventGroupMembers':instance_EventGroupMembers,
        }
        return render(request, 'user_template/my_event_campaign_supporter_donor_info.html', context)
    except:
        return redirect('dashboard')



@login_required
@end_user_required
def my_event_campaign_updates_delete(request, url_text, id):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        instance_EventUpdates = EventUpdates.objects.get(id=id, event=instance_Event)

        instance_EventUpdates.delete()

        messages.add_message(request,messages.SUCCESS,'Event Update deleted successfully. ')

        return redirect('my_event_campaign_updates', url_text=url_text)

    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_buzz_delete(request, url_text, id):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)
        instance_EventBuzz = EventBuzz.objects.get(id=id, event=instance_Event)

        instance_EventBuzz.delete()
        messages.add_message(request,messages.SUCCESS,'Event Buzz deleted successfully.')

        return redirect('my_event_campaign_buzz', url_text=url_text)

       
    except:
        return redirect('dashboard')


#-------------------------- mix code -------------------------------#

@login_required
@end_user_required
def my_fundraiser_campaign_custome_note(request, url_text):
    try:
        instance_CampaignFundRaiser = CampaignFundRaiser.objects.get(url_text=url_text, user=request.user)

        if request.method == 'POST':
            CustomeNoteForm = CampaignFundRaiserCustomeNoteForm(request.POST, instance=instance_CampaignFundRaiser)
            if CustomeNoteForm.is_valid():
                CustomeNoteForm.save()

                messages.add_message(request,messages.SUCCESS,'Custom Note updated successfully.')

                return redirect('my_fundraiser_campaign_custome_note', url_text=url_text)

        else:
            CustomeNoteForm = CampaignFundRaiserCustomeNoteForm(instance=instance_CampaignFundRaiser)

        current_site = get_current_site(request)
        context = {
            'instance_CampaignFundRaiser':instance_CampaignFundRaiser,
            'CustomeNoteForm':CustomeNoteForm,
            'domain': current_site.domain,
        }
        return render(request, 'user_template/my_fundraiser_campaign_custome_note.html', context)
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_mobilisation_campaign_custome_note(request, url_text):
    try:
        instance_SupportGroup = SupportGroup.objects.get(url_text=url_text, group_leader=request.user)

        if request.method == 'POST':
            CustomeNoteForm = SupportGroupCustomeNoteForm(request.POST, instance=instance_SupportGroup)
            if CustomeNoteForm.is_valid():
                CustomeNoteForm.save()

            messages.add_message(request,messages.SUCCESS,'Custom Note updated successfully.')

            return redirect('my_mobilisation_campaign_custome_note', url_text=url_text)

        else:
            CustomeNoteForm = SupportGroupCustomeNoteForm(instance=instance_SupportGroup)

        current_site = get_current_site(request)
        context = {
            'instance_SupportGroup':instance_SupportGroup,
            'CustomeNoteForm':CustomeNoteForm,
            'domain': current_site.domain,
        }
        return render(request, 'user_template/my_mobilisation_campaign_custome_note.html', context)
    except:
        return redirect('dashboard')

@login_required
@end_user_required
def my_event_campaign_custome_note(request, url_text):
    try:
        instance_Event = Event.objects.get(url_text=url_text, user=request.user)

        if request.method == 'POST':
            CustomeNoteForm = EventCustomeNoteForm(request.POST, instance=instance_Event)
            if CustomeNoteForm.is_valid():
                CustomeNoteForm.save()

                messages.add_message(request,messages.SUCCESS,'Custom Note updated successfully.')

                return redirect('my_event_campaign_custome_note', url_text=url_text)

        else:
            CustomeNoteForm = EventCustomeNoteForm(instance=instance_Event)

        current_site = get_current_site(request)
        context = {
            'instance_Event':instance_Event,
            'CustomeNoteForm':CustomeNoteForm,
            'domain': current_site.domain,
        }
        return render(request, 'user_template/my_event_campaign_custome_note.html', context)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_fundraiser_campaign_supporter_reminder(request, id):
    try:
        instance_CampaignDoners = PotentialCampaignDoners.objects.get(id=id)

        message = None
        if request.method == 'POST':
            message = request.POST.get('message', None)

        current_site = get_current_site(request)
        mail_subject = 'Thank you for supporting us.'
        message = render_to_string('email_template/potential_donor_email.html', {
            'domain': current_site.domain,
            'instance_CampaignDoners':instance_CampaignDoners,
            'message':message,
        })
        email = EmailMultiAlternatives(
                            mail_subject, message, to=[instance_CampaignDoners.email]
            )
        email.attach_alternative(message, "text/html")
        email.send()

        instance_CampaignDoners.sent = instance_CampaignDoners.sent + 1
        instance_CampaignDoners.save()

        return redirect('my_fundraiser_campaign_supporter', url_text=instance_CampaignDoners.campaign_fund_raiser.url_text)
    except:
        return redirect('dashboard')





@login_required
@end_user_required
def my_mobilisation_campaign_supporter_reminder(request, id):
    try:
        instance_SupportGroupMembers = SupportGroupMembers.objects.get(id=id)

        current_site = get_current_site(request)
        mail_subject = 'Thank you for supporting us.'
        message = render_to_string('email_template/my_mobilisation_campaign_supporter_reminder_email.html', {
            'domain': current_site.domain,
            'instance_SupportGroupMembers':instance_SupportGroupMembers,
        })
        email = EmailMultiAlternatives(
                            mail_subject, message, to=[instance_SupportGroupMembers.email]
            )
        email.attach_alternative(message, "text/html")
        email.send()

        return redirect('my_mobilisation_campaign_supporter', url_text=instance_SupportGroupMembers.support_group.url_text)
    except:
        return redirect('dashboard')


@login_required
@end_user_required
def my_event_campaign_supporter_reminder(request, id):
    try:
        instance_EventGroupMembers = EventGroupMembers.objects.get(id=id)

        current_site = get_current_site(request)
        mail_subject = 'Thank you for supporting us.'
        message = render_to_string('email_template/my_event_campaign_supporter_reminder_email.html', {
            'domain': current_site.domain,
            'instance_EventGroupMembers':instance_EventGroupMembers,
        })
        email = EmailMultiAlternatives(
                            mail_subject, message, to=[instance_EventGroupMembers.email]
            )
        email.attach_alternative(message, "text/html")
        email.send()

        return redirect('my_event_campaign_supporter', url_text=instance_EventGroupMembers.event.url_text)
    except:
        return redirect('dashboard')