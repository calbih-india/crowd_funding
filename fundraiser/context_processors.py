from fundraiser.models import *


def all_active_campaign_category(request):
    instance_active_campaign_category = CampaignCategory.objects.filter(is_active=True)[0:5]
    return {'instance_active_campaign_category':instance_active_campaign_category}