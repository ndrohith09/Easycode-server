# Generated by Django 4.2.11 on 2024-04-23 12:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0004_remove_databasemodel_provider_databasemodel_uri'),
    ]

    operations = [
        migrations.AddField(
            model_name='databasemodel',
            name='name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]