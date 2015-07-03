from django.db import models
from django.contrib.auth.models import User
from django import forms
from PIL import *


# Create your models here.
class Link(models.Model):
    url = models.URLField(unique=True)


class m_USER(models.Model):
    U_name = models.CharField(max_length=30, unique=True)
    U_password = models.CharField(max_length=16)
    U_Email = models.EmailField()


class m_IMAGE(models.Model):
    U_ID = models.ForeignKey(m_USER, related_name='m_Image')
    I_space = models.BigIntegerField()
    Like_number = models.IntegerField()
    m_Priority = models.BigIntegerField()
    Update_date = models.DateTimeField(auto_now_add=True)
    I_origin = models.ImageField(upload_to='./media/upload/origin')
    I_big = models.ImageField(upload_to='./media/upload/big')
    I_small = models.ImageField(upload_to='./media/upload/small')


class m_BLACKLIST(models.Model):
    U_ID_from = models.ForeignKey(m_USER, related_name='black_list')
    U_ID_to = models.ForeignKey(m_USER)


class m_COMMENT(models.Model):
    U_ID = models.ForeignKey(m_USER, related_name='comment')
    I_ID = models.ForeignKey(m_IMAGE, related_name='comment')
    Update_date = models.DateTimeField(auto_now_add=True)
    Comment = models.CharField(max_length=255)


class m_CONCERN(models.Model):
    U_ID_from = models.ForeignKey(m_USER, related_name='concern')
    U_ID_to = models.ForeignKey(m_USER)


class m_LIKE(models.Model):
    U_ID = models.ForeignKey(m_USER, related_name='like')
    I_ID = models.ForeignKey(m_IMAGE, related_name='liked')


class m_TAG(models.Model):
    U_ID = models.ForeignKey(m_USER, related_name='tag')
    I_ID = models.ForeignKey(m_IMAGE, related_name='tag')
    tag = models.CharField(max_length=12)


class imageForm(forms.Form):
    file0 = forms.FileField()


class User(models.Model):
    username = models.CharField(max_length = 30)
    headImg = models.FileField(upload_to = './upload/')

    def __unicode__(self):
        return self.username


class UserForm(forms.Form):
    headImg = forms.FileField()