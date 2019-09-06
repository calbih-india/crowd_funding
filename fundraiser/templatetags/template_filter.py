from django import template
register = template.Library()

from fundraiser.models import *


@register.filter
def get_short_name(name, is_hide):
    if is_hide:
        return "A"
    else:
        short_name = ""
        short_name_list = (name).split()
        for i in short_name_list:
            try:
                short_name += i[0]
            except:
                pass
        return short_name.upper()

@register.filter
def get_unauthorized_event(name):
    return Event.objects.filter(is_active=False).count()

@register.filter
def get_unauthorized_supportgroup(name):
    return SupportGroup.objects.filter(is_active=False).count()

@register.filter
def get_unauthorized_campaign(name):
    return CampaignFundRaiser.objects.filter(is_active=False).count()

@register.filter
def check_support_group(user_id):
    instance_SupportGroup = SupportGroup.objects.filter(group_leader__id=user_id).count()
    if instance_SupportGroup == 0:
        return False
    else:
        return True
        