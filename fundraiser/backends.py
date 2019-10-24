from fundraiser.models import User

class EmailBackend(object):
	def authenticate(self,username,password=None,**kwargs):
		try:
			user = User.objects.get(email__iexact=username)
			print("user in bend",user.username)
		except User.MultipleObjectsReturned:
			user = User.objects.filter(email=username).order_by('id').first()
		except User.DoesNotExist:
			return None

		if getattr(user,'is_active') and user.check_password(password):
			return user
		return None
		#


	def get_user(self,user_id):
		try:
			return User.objects.get(pk=user_id)
		except User.DoesNotExist:
			return None

