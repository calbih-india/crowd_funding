from django.contrib import admin

## user model view
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import ugettext_lazy as _

from fundraiser.models import *


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    """Define admin model for custom User model with no email field."""

    fieldsets = (
        (None, {'fields': ('email', 'name', 'mobile_no', 'user_type', 'is_indian', 'password')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
        (_('Account Confirmation'), {'fields': ('email_confirm', 'mobile_confirm', 'i_agree')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'user_type', 'password1', 'password2',),
        }),
    )
    list_display = ('email', 'name', 'user_type')
    search_fields = ('email', 'name', 'user_type')
    ordering = ('-id',)


class UserUniqueTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'unique_token',)
admin.site.register(UserUniqueToken, UserUniqueTokenAdmin)

#----------------------- Start Campaign -----------------------#

class CampaignCategoryAdmin(admin.ModelAdmin):
    list_display = ('category', 'is_active',)
admin.site.register(CampaignCategory, CampaignCategoryAdmin)


class CampaignFundRaiserAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'category', 'goal',)
admin.site.register(CampaignFundRaiser, CampaignFundRaiserAdmin)


class CampaignDonersAdmin(admin.ModelAdmin):
    list_display = ('name', 'campaign_fund_raiser', 'amount', 'payment_status', 'payment_id',)
admin.site.register(CampaignDoners, CampaignDonersAdmin)


class CampaignTotalAmountAdmin(admin.ModelAdmin):
    list_display = ('campaign_fund_raiser', 'total_amount', 'total_supporters',)
admin.site.register(CampaignTotalAmount, CampaignTotalAmountAdmin)


class CampaignCommentsAdmin(admin.ModelAdmin):
    list_display = ('campaign_fund_raiser', 'comment_user', 'comment',)
admin.site.register(CampaignComments, CampaignCommentsAdmin)


class CampaignEnqiryAdmin(admin.ModelAdmin):
    list_display = ('enqiry_user', 'name', 'email',)
admin.site.register(CampaignEnqiry, CampaignEnqiryAdmin)


class CampaignUpdatesAdmin(admin.ModelAdmin):
    list_display = ('title', 'campaign_fund_raiser',)
admin.site.register(CampaignUpdates, CampaignUpdatesAdmin)


class CampaignBuzzAdmin(admin.ModelAdmin):
    list_display = ('title', 'campaign_fund_raiser',)
admin.site.register(CampaignBuzz, CampaignBuzzAdmin)

#----------------------- End Campaign -----------------------#

#----------------------- Start Support Group -----------------------#

class SupportGroupAdmin(admin.ModelAdmin):
    list_display = ('group_leader', 'title', 'goal')
admin.site.register(SupportGroup, SupportGroupAdmin)


class SupportGroupMembersAdmin(admin.ModelAdmin):
    list_display = ('support_group', 'name', 'email')
admin.site.register(SupportGroupMembers, SupportGroupMembersAdmin)


class SupportCommentsAdmin(admin.ModelAdmin):
    list_display = ('support_group', 'comment_user', 'comment')
admin.site.register(SupportComments, SupportCommentsAdmin)


class SupportEnqiryAdmin(admin.ModelAdmin):
    list_display = ('support_group', 'enqiry_user',)
admin.site.register(SupportEnqiry, SupportEnqiryAdmin)


class SupportUpdatesAdmin(admin.ModelAdmin):
    list_display = ('support_group', 'title',)
admin.site.register(SupportUpdates, SupportUpdatesAdmin)


class SupportBuzzAdmin(admin.ModelAdmin):
    list_display = ('support_group', 'title',)
admin.site.register(SupportBuzz, SupportBuzzAdmin)

#----------------------- End Support Group -----------------------#

admin.site.register(Event)
admin.site.register(Beneficiary)
admin.site.register(WithdrawalRequest)


class SupportVisitHistoryAdmin(admin.ModelAdmin):
    list_display = ('path', 'ip','request_type', 'location', 'created_at')
admin.site.register(SupportVisitHistory, SupportVisitHistoryAdmin)