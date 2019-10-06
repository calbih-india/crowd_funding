# Generated by Django 2.0.4 on 2019-10-06 11:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fundraiser', '0012_auto_20191006_1621'),
    ]

    operations = [
        migrations.AddField(
            model_name='supportgroupmembers',
            name='country',
            field=models.CharField(default='India', max_length=50),
        ),
        migrations.AlterField(
            model_name='supportgroupmembers',
            name='facbook',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='supportgroupmembers',
            name='twitter',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
