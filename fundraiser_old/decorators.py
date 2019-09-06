from django.shortcuts import render,redirect
from django.core.exceptions import PermissionDenied
from django.contrib import messages 
from fundraiser.models import *


def anonymous_user_required(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_anonymous:
            return function(request, *args, **kwargs)
        else:
            if request.user.user_type == 'Admin':
                return redirect('admin_dashboard')
            elif request.user.user_type == 'Backend User':
                return redirect('admin_dashboard')
            else:
                return redirect('dashboard')
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap


def admin_or_backend_user_required(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect('login')
        else:
            if request.user.user_type == 'Admin' or request.user.user_type == 'Backend User':
                return function(request, *args, **kwargs)
            else:
                return redirect('dashboard')
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap


def admin_user_required(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect('login')
        else:
            if request.user.user_type == 'Admin':
                return function(request, *args, **kwargs)
            elif request.user.user_type == 'Backend User':
                return redirect('admin_dashboard')
            else:
                return redirect('dashboard')
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap

def backend_user_required(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect('login')
        else:
            if request.user.user_type == 'Backend User':
                return function(request, *args, **kwargs)
            elif request.user.user_type == 'Admin':
                return redirect('admin_dashboard')
            else:
                return redirect('dashboard')
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap

def end_user_required(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect('login')
        else:
            if request.user.user_type == 'Backend User':
                return redirect('admin_dashboard')
            elif request.user.user_type == 'Admin':
                return redirect('admin_dashboard')
            else:
                return function(request, *args, **kwargs)
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap

def beneficiary_completed_required(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect('login')
        else:
            if request.user.user_type == 'Backend User':
                return redirect('admin_dashboard')
            elif request.user.user_type == 'Admin':
                return redirect('admin_dashboard')
            else:
                if request.user.beneficiary.name and request.user.beneficiary.email and  request.user.beneficiary.mobile_no:
                    return function(request, *args, **kwargs)
                else:
                    messages.add_message(request,messages.ERROR,'To continue please add your bank account details in the profile.')
                    return redirect('my_profile')
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap