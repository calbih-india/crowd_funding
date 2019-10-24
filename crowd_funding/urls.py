"""crowd_funding URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,re_path,include
from django.conf.urls import url
from django.contrib.auth.decorators import login_required

#----------- import viewe ------------#
from fundraiser import views

#------------ import default viewe ---------------#
from django.contrib.auth import views as auth_views

#------------ import setting --------------------#
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('administration/', admin.site.urls),
    #-------------- authentication start ----------------#
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='admin_password_reset'),
    path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
    re_path('reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', views.password_reset_complete, name='password_reset_complete'),
    
    path('login/',views.login,name='login'),
    path('account/', include('social_django.urls', namespace='social')),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    path('registration/', views.registration, name='registration'),


    re_path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',views.activate, name='activate'),
    path('reset-activate/',views.new_activate_link, name='new_activate_link'),
    #-------------- authentication start ----------------#

    #------------------- admin ----------------------------#
    re_path('admin/dashboard/event/(?P<ID>[0-9]+)/user/', views.admin_event_user, name='admin_event_user'),
    re_path('admin/dashboard/campaign/(?P<ID>[0-9]+)/user/', views.admin_campaign_user, name='admin_campaign_user'),
    re_path('admin/dashboard/campaign/(?P<ID>[0-9]+)/funds-summary/', views.admin_campaign_funds_summary, name='admin_campaign_funds_summary'),
    re_path('admin/dashboard/MobilisationCampaign/(?P<ID>[0-9]+)/user/', views.admin_support_group_user, name='admin_support_group_user'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),


    path('admin/analytics/', views.admin_analytics, name='admin_analytics'),

    path('admin-crm/email/', views.admin_crm_email, name='admin_crm_email'),
    path('admin-crm/', views.admin_crm, name='admin_crm'),
    
    re_path('admin/manage/(?P<ID>[0-9]+)/category/(?P<status>[a-z,A-Z]+)/', views.admin_manage_category_status, name='admin_manage_category_status'),
    re_path('admin/manage/category/(?P<ID>[0-9]+)/edit/', views.admin_manage_category_edit, name='admin_manage_category_edit'),
    path('admin/manage/category/', views.admin_manage_category, name='admin_manage_category'),

    re_path('admin/manage/(?P<ID>[0-9]+)/sub_category/(?P<status>[a-z,A-Z]+)/', views.admin_manage_sub_category_status, name='admin_manage_sub_category_status'),
    re_path('admin/manage/sub_category/(?P<ID>[0-9]+)/edit/', views.admin_manage_sub_category_edit, name='admin_manage_sub_category_edit'),
    path('admin/manage/sub_category/', views.admin_manage_sub_category, name='admin_manage_sub_category'),

    re_path('admin/manage/(?P<ID>[0-9]+)/cause/(?P<status>[a-z,A-Z]+)/', views.admin_manage_cause_status, name='admin_manage_cause_status'),
    re_path('admin/manage/cause/(?P<ID>[0-9]+)/edit/', views.admin_manage_cause_edit, name='admin_manage_cause_edit'),
    path('admin/manage/cause/', views.admin_manage_cause, name='admin_manage_cause'),

    re_path('admin/manage/campaign/(?P<ID>[0-9]+)/edit/', views.admin_manage_campaign_edit, name='admin_manage_campaign_edit'),
    re_path('admin/manage/(?P<ID>[0-9]+)/campaign/(?P<status>[a-z,A-Z]+)/', views.admin_manage_campaign_status, name='admin_manage_campaign_status'),
    path('admin/manage/campaign/', views.admin_manage_campaign, name='admin_manage_campaign'),

    path('admin/manage/campaign-action/', views.admin_manage_campaign_action, name='admin_manage_campaign_action'),
    path('admin/manage/mobilisation-campaign-member/', views.admin_manage_support_group_member, name='admin_manage_support_group_member'),
    path('admin/manage/fundraiser-campaign-member/', views.admin_fundraiser_campaign_member, name='admin_fundraiser_campaign_member'),
    path('admin/manage/event-members/', views.admin_event_member, name='admin_event_member'),
    path('admin/manage/contributors/', views.admin_manage_contributors, name='admin_manage_contributors'),
    path('admin/manage/donors/', views.admin_manage_donors, name='admin_manage_donors'),
    path('admin/manage/(?P<ID>[0-9]+)/refund/(?P<status>[a-z,A-Z]+)/', views.admin_manage_refund_status, name='admin_manage_refund_status'),
    path('admin/manage/refund/', views.admin_manage_refund, name='admin_manage_refund'),

    re_path('admin/manage/MobilisationCampaign/(?P<ID>[0-9]+)/edit/', views.admin_manage_support_group_edit, name='admin_manage_support_group_edit'),
    re_path('admin/manage/(?P<ID>[0-9]+)/MobilisationCampaign/(?P<status>[a-z,A-Z]+)/', views.admin_manage_support_group_status, name='admin_manage_support_group_status'),
    path('admin/manage/MobilisationCampaign/', views.admin_manage_support_group, name='admin_manage_support_group'),

    re_path('admin/manage/event/(?P<ID>[0-9]+)/edit/', views.admin_manage_event_edit, name='admin_manage_event_edit'),
    re_path('admin/manage/(?P<ID>[0-9]+)/event/(?P<status>[a-z,A-Z]+)/', views.admin_manage_event_status, name='admin_manage_event_status'),
    path('admin/manage/event/', views.admin_manage_event, name='admin_manage_event'),

    re_path('admin/manage/media/(?P<ID>[0-9]+)/delete/', views.admin_manage_media_delete, name='admin_manage_media_delete'),
    re_path('admin/manage/media/(?P<ID>[0-9]+)/edit/', views.admin_manage_media_edit, name='admin_manage_media_edit'),
    path('admin/manage/media/', views.admin_manage_media, name='admin_manage_media'),


    re_path('admin/manage/crowd-newsing/(?P<ID>[0-9]+)/delete/', views.admin_manage_crowd_newsing_delete, name='admin_manage_crowd_newsing_delete'),
    re_path('admin/manage/crowd-newsing/(?P<ID>[0-9]+)/edit/', views.admin_manage_crowd_newsing_edit, name='admin_manage_crowd_newsing_edit'),
    path('admin/manage/crowd-newsing/', views.admin_manage_crowd_newsing, name='admin_manage_crowd_newsing'),


    re_path('admin/manage/(?P<ID>[0-9]+)/user/(?P<status>[a-z,A-Z]+)/', views.admin_manage_user_status, name='admin_manage_user_status'),
    re_path('admin/manage/user/(?P<ID>[0-9]+)/delete/', views.admin_manage_user_delete, name='admin_manage_user_delete'),
    re_path('admin/manage/user/(?P<ID>[0-9]+)/edit/', views.admin_manage_usera_edit, name='admin_manage_usera_edit'),
    path('admin/manage/user/', views.admin_manage_user, name='admin_manage_user'),

    re_path('admin/manage/(?P<ID>[0-9]+)/generic-user/(?P<status>[a-z,A-Z]+)/', views.admin_manage_generic_user_status, name='admin_manage_generic_user_status'),
    re_path('admin/manage/generic-user/(?P<ID>[0-9]+)/delete/', views.admin_manage_generic_user_delete, name='admin_manage_generic_user_delete'),
    re_path('admin/manage/generic-user/(?P<ID>[0-9]+)/edit/', views.admin_manage_generic_user_edit, name='admin_manage_generic_user_edit'),
    path('generic-user/', views.generic_user_view, name='generic_user_view'),
    path('platform-generic-user/', views.platform_generic_user, name='platform_generic_user'),

    path('public-personas/get-department-user', views.public_personas_get_department_user, name='public_personas_get_department_user'),
    path('public-personas/', views.public_personas, name='public_personas'),

    re_path('admin/manage/(?P<ID>[0-9]+)/banner-images/(?P<status>[a-z,A-Z]+)/', views.admin_manage_banner_images_status, name='admin_manage_banner_images_status'),
    re_path('admin/manage/banner-images/(?P<ID>[0-9]+)/edit/', views.admin_manage_banner_images_edit, name='admin_manage_banner_images_edit'),
    path('admin/manage/banner-images/', views.admin_manage_banner_images, name='admin_manage_banner_images'),

    re_path('admin/withdrawl-request/(?P<ID>[0-9]+)/edit/', views.admin_withdrawl_request_edit, name='admin_withdrawl_request_edit'),
    path('admin/withdrawl-request/', views.admin_withdrawl_request, name='admin_withdrawl_request'),

    path('admin/manage/cashfree/credential/', views.admin_manage_cashfree_credential, name='admin_manage_cashfree_credential'),
    path('admin/manage/commission/', views.admin_manage_commission, name='admin_manage_commission'),

    path('admin/manage/fundraiser-member/', views.admin_manage_fundraiser_member, name='admin_manage_fundraiser_member'),
    path('admin/manage/mobilisation-member/', views.admin_manage_mobilisation_member, name='admin_manage_mobilisation_member'),
    path('admin/manage/event-member/', views.admin_manage_event_member, name='admin_manage_event_member'),
    #------------------- admin ----------------------------#

    #--------------- login user ----------------------------#
    path('dashboard/', views.dashboard, name='dashboard'),
    path('my-analytics/', views.my_analytics, name='my_analytics'),

    path('start-Campaign/', views.chose_campaign, name='chose_campaign'),
    path('start-FundraiserCampaign/', views.start_campaign, name='start_campaign'),
    path('start-MobilisationCampaign/', views.start_support_group, name='start_support_group'),
    path('start-event/', views.start_event, name='start_event'),

    re_path('my-event/(?P<ID>[0-9]+)/user/', views.my_event_user, name='my_event_user'),


    re_path('my-FundraiserCampaign/(?P<ID>[0-9]+)/buzz/', views.campaign_buzz, name='campaign_buzz'),
    re_path('my-FundraiserCampaign/(?P<ID>[0-9]+)/updates/', views.campaign_updates, name='campaign_updates'),
    re_path('my-FundraiserCampaign/(?P<ID>[0-9]+)/edit/', views.campaign_edit, name='campaign_edit'),
    re_path('my-FundraiserCampaign/(?P<ID>[0-9]+)/withdrawal/', views.campaign_withdrawal, name='campaign_withdrawal'),
    re_path('my-FundraiserCampaign/(?P<ID>[0-9]+)/user/', views.campaign_user, name='campaign_user'),
    re_path('my-FundraiserCampaign/(?P<ID>[0-9]+)/funds-summary/', views.campaign_funds_summary, name='campaign_funds_summary'),
    path('my-FundraiserCampaign/', views.my_campaign, name='my_campaign'),

    re_path('my-MobilisationCampaign/(?P<ID>[0-9]+)/buzz/', views.my_support_group_buzz, name='my_support_group_buzz'),
    re_path('my-MobilisationCampaign/(?P<ID>[0-9]+)/updates/', views.my_support_group_updates, name='my_support_group_updates'),
    re_path('my-MobilisationCampaign/(?P<ID>[0-9]+)/edit/', views.my_support_group_edit, name='my_support_group_edit'),
    re_path('my-MobilisationCampaign/(?P<ID>[0-9]+)/user/', views.my_support_group_user, name='my_support_group_user'),
    path('my-MobilisationCampaign/', views.my_support_group, name='my_support_group'),

    path('my-supported-fundraise/(?P<ID>[0-9,a-z,A-Z]+)/request-refund/', views.my_supported_fundraise_request_refund, name='my_supported_fundraise_request_refund'),
    path('my-supported-fundraise/(?P<ID>[0-9,a-z,A-Z]+)/history/', views.my_supported_fundraise_history, name='my_supported_fundraise_history'),
    re_path('my-profile/(?P<ID>[0-9,a-z,A-Z]+)/', views.view_user_profile, name='view_user_profile'),
    path('my-profile/', views.my_profile, name='my_profile'),


    # selected dashboard
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/dashboard/', views.my_fundraiser_campaign_dashboard, name='my_fundraiser_campaign_dashboard'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/modify/', views.my_fundraiser_campaign_modify, name='my_fundraiser_campaign_modify'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/supporter/', views.my_fundraiser_campaign_supporter, name='my_fundraiser_campaign_supporter'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/Premium-Services/', views.my_fundraiser_campaign_premium_services, name='my_fundraiser_campaign_premium_services'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/document/', views.my_fundraiser_campaign_document, name='my_fundraiser_campaign_document'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/Withdraw-Funds/', views.my_fundraiser_campaign_withdraw_funds, name='my_fundraiser_campaign_withdraw_funds'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/Custome-Note/', views.my_fundraiser_campaign_custome_note, name='my_fundraiser_campaign_custome_note'),
    re_path('my-FundraiserCampaign/supporter/(?P<id>[0-9]+)/reminder/', views.my_fundraiser_campaign_supporter_reminder, name='my_fundraiser_campaign_supporter_reminder'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/comment/', views.my_fundraiser_campaign_comment, name='my_fundraiser_campaign_comment'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/donor-info/', views.my_fundraiser_campaign_supporter_donor_info, name='my_fundraiser_campaign_supporter_donor_info'),
    
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/update/(?P<id>[0-9]+)/delete/', views.my_fundraiser_campaign_updates_delete, name='my_fundraiser_campaign_updates_delete'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/buzz/(?P<id>[0-9]+)/delete/', views.my_fundraiser_campaign_buzz_delete, name='my_fundraiser_campaign_buzz_delete'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/updates/', views.my_fundraiser_campaign_updates, name='my_fundraiser_campaign_updates'),
    re_path('my-FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/buzz/', views.my_fundraiser_campaign_buzz, name='my_fundraiser_campaign_buzz'),


    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/dashboard/', views.my_mobilisation_campaign_dashboard, name='my_mobilisation_campaign_dashboard'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/modify/', views.my_mobilisation_campaign_modify, name='my_mobilisation_campaign_modify'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/supporter/', views.my_mobilisation_campaign_supporter, name='my_mobilisation_campaign_supporter'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/Premium-Services/', views.my_mobilisation_campaign_premium_services, name='my_mobilisation_campaign_premium_services'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/Custome-Note/', views.my_mobilisation_campaign_custome_note, name='my_mobilisation_campaign_custome_note'),
    re_path('my-MobilisationCampaign/supporter/(?P<id>[0-9]+)/reminder/', views.my_mobilisation_campaign_supporter_reminder, name='my_mobilisation_campaign_supporter_reminder'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/update/(?P<id>[0-9]+)/delete/', views.my_mobilisation_campaign_updates_delete, name='my_mobilisation_campaign_updates_delete'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/buzz/(?P<id>[0-9]+)/delete/', views.my_mobilisation_campaign_buzz_delete, name='my_mobilisation_campaign_buzz_delete'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/updates/', views.my_mobilisation_campaign_updates, name='my_mobilisation_campaign_updates'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/buzz/', views.my_mobilisation_campaign_buzz, name='my_mobilisation_campaign_buzz'),
    re_path('my-MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/comment/', views.my_mobilisation_campaign_comment, name='my_mobilisation_campaign_comment'),
    re_path('my-MobilisationCampaign/supporter/(?P<url_text>[0-9,a-z,A-Z]+)/donor-info/', views.my_mobilisation_campaign_supporter_donor_info, name='my_mobilisation_campaign_supporter_donor_info'),



    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/dashboard/', views.my_event_dashboard, name='my_event_dashboard'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/modify/', views.my_event_campaign_modify, name='my_event_campaign_modify'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/supporter/', views.my_event_campaign_supporter, name='my_event_campaign_supporter'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/Premium-Services/', views.my_event_campaign_premium_services, name='my_event_campaign_premium_services'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/Custome-Note/', views.my_event_campaign_custome_note, name='my_event_campaign_custome_note'),
    re_path('my-event/supporter/(?P<id>[0-9]+)/reminder/', views.my_event_campaign_supporter_reminder, name='my_event_campaign_supporter_reminder'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/update/(?P<id>[0-9]+)/delete/', views.my_event_campaign_updates_delete, name='my_event_campaign_updates_delete'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/buzz/(?P<id>[0-9]+)/delete/', views.my_event_campaign_buzz_delete, name='my_event_campaign_buzz_delete'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/updates/', views.my_event_campaign_updates, name='my_event_campaign_updates'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/buzz/', views.my_event_campaign_buzz, name='my_event_campaign_buzz'),
    re_path('my-event/(?P<url_text>[0-9,a-z,A-Z]+)/comment/', views.my_event_campaign_comment, name='my_event_campaign_comment'),
    re_path('my-event/supporter/(?P<url_text>[0-9,a-z,A-Z]+)/donor-info/', views.my_event_campaign_supporter_donor_info, name='my_event_campaign_supporter_donor_info'),



    #--------------- login user ----------------------------#

    #------------------- all user -----------------------------#
    re_path('report/FundraiserCampaign/(?P<ID>[0-9]+)/', views.report_campaign_selected, name='report_campaign_selected'),
    re_path('ask-update/FundraiserCampaign/(?P<ID>[0-9]+)/', views.ask_update_campaign_selected, name='ask_update_campaign_selected'),
    re_path('FundraiserCampaign/(?P<ID>[0-9]+)/payment/(?P<OID>[0-9,a-z,A-Z]+)/', views.campaign_payment, name='campaign_payment'),
    re_path('FundraiserCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/', views.campaign_selected, name='campaign_selected'),
    path('payment/check/', views.payment_check, name='payment_check'),


    re_path('report/event/(?P<ID>[0-9]+)/', views.report_event_selected, name='report_event_selected'),
    re_path('ask-update/event/(?P<ID>[0-9]+)/', views.ask_update_event_selected, name='ask_update_event_selected'),
    re_path('event/(?P<url_text>[0-9,a-z,A-Z]+)/', views.event_selected, name='event_selected'),



    re_path('report/MobilisationCampaign/(?P<ID>[0-9]+)/', views.report_support_group_selected, name='report_support_group_selected'),
    re_path('ask-update/MobilisationCampaign/(?P<ID>[0-9]+)/', views.ask_update_support_group_selected, name='ask_update_support_group_selected'),
    re_path('MobilisationCampaign/(?P<url_text>[0-9,a-z,A-Z]+)/', views.support_group_selected, name='support_group_selected'),

    
    path('discover/', views.discover, name='discover'),
    path('how-it-works/', views.how_it_works, name='how_it_works'),
    path('services/', views.services, name='services'),
    path('tips/', views.tips, name='tips'),
    path('Medias/', views.media, name='media'),
    path('campaign-criteria/', views.campaign_criteria, name='campaign_criteria'),
    path('terms-conditions/', views.terms_conditions, name='terms_conditions'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('pricing/', views.pricing, name='pricing'),
    path('about-us/', views.about_us, name='about_us'),
    path('contact-us/', views.contact_us, name='contact_us'),
    #------------------- all user -----------------------------#


    #-----------------------> Ajax validation <-----------------------#
    path('category/get/sub_category/', views.get_sub_category, name='get_sub_category'),
    #-----------------------> Ajax validation <-----------------------#

    path('', views.landingpage, name='landingpage'),
    path('api/',include('webapi.urls')),
    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
