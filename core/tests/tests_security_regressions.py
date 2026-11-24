"""Proof-of-concept tests for suspected authorization/configuration gaps.

These tests intentionally document the current behavior; they do not change
application code or weaken any security checks.
"""

import tempfile

import tablib
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from core import admin as core_admin
from core import models


class ImportPermissionPoCTestCase(TestCase):
    """Check whether add-only staff can overwrite an existing imported row."""

    fixtures = ["tests.json"]

    def test_add_only_staff_can_update_existing_note_by_import(self):
        child = models.Child.objects.first()
        note = models.Note.objects.create(
            child=child, note="Original note", time=timezone.now()
        )
        staff = get_user_model().objects.create_user(
            username="add-only-importer", password="test-password", is_staff=True
        )
        add_note = Permission.objects.get(
            content_type__app_label="core", codename="add_note"
        )
        staff.user_permissions.add(add_note)

        self.assertTrue(staff.has_perm("core.add_note"))
        self.assertFalse(staff.has_perm("core.change_note"))

        request = RequestFactory().get("/admin/core/note/import/")
        request.user = staff
        model_admin = core_admin.NoteAdmin(models.Note, admin.site)
        self.assertTrue(model_admin.has_import_permission(request))

        dataset = tablib.Dataset(headers=["id", "child_id", "note", "time"])
        dataset.append(
            [note.pk, child.pk, "Overwritten by add-only user", note.time.isoformat()]
        )
        result = core_admin.NoteImportExportResource().import_data(
            dataset, dry_run=False
        )

        self.assertFalse(result.has_errors(), result.row_errors())
        note.refresh_from_db()
        self.assertEqual(note.note, "Overwritten by add-only user")


class CaregiverAuthorizationPoCTestCase(APITestCase):
    """Exercise timer ownership and upload-setting enforcement over the API."""

    fixtures = ["tests.json"]

    def setUp(self):
        self.caregiver = get_user_model().objects.create_user(
            username="security-poc-caregiver",
            password="caregiver-password",
            is_active=True,
        )
        self.caregiver.groups.add(
            Group.objects.get(name=settings.BABY_BUDDY["CAREGIVER_GROUP_NAME"])
        )
        self.caregiver = get_user_model().objects.get(
            username="security-poc-caregiver"
        )
        self.assertTrue(
            self.client.login(
                username="security-poc-caregiver", password="caregiver-password"
            )
        )
        self.other_user = get_user_model().objects.get(username="admin")

    def test_caregiver_can_create_timer_owned_by_another_user(self):
        response = self.client.post(
            reverse("api:timer-list"),
            {"name": "POC timer", "user": self.other_user.pk},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        timer = models.Timer.objects.get(pk=response.data["id"])
        self.assertEqual(timer.user_id, self.other_user.pk)
        self.assertFalse(self.caregiver.has_perm("core.delete_timer"))

    def test_note_image_upload_works_when_uploads_are_disabled(self):
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
            b"\x00\x00\x00\x1f\x15\xc4\x89"
            b"\x00\x00\x00\x0bIDAT\x08\xd7c\xf8\x0f"
            b"\x00\x01\x01\x01\x00\x18\xdd\x8d\xb4"
            b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
        )
        with tempfile.TemporaryDirectory() as media_root:
            disabled_baby_buddy = {
                **settings.BABY_BUDDY,
                "ALLOW_UPLOADS": False,
            }
            with override_settings(
                BABY_BUDDY=disabled_baby_buddy, MEDIA_ROOT=media_root
            ):
                image = SimpleUploadedFile(
                    "upload-disabled-poc.png", png, content_type="image/png"
                )
                response = self.client.post(
                    reverse("api:note-list"),
                    {
                        "child": 1,
                        "note": "Upload restriction PoC",
                        "image": image,
                    },
                    format="multipart",
                )

        self.assertEqual(response.status_code, 201, response.data)
        note = models.Note.objects.get(pk=response.data["id"])
        self.assertTrue(note.image.name)
