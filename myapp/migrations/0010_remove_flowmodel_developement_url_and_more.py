# Generated by Django 4.2.11 on 2024-04-24 07:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0009_apimodel_flowmodel_remove_usermodel_card_added_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='flowmodel',
            name='developement_url',
        ),
        migrations.AddField(
            model_name='apimodel',
            name='developement_url',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
