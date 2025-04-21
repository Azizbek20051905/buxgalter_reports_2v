# your_app_name/tests.py

import json
from decimal import Decimal
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

# Modellar va Serializerlarni import qilish (kerak bo'lsa)
from .models import *
from .serializers import * # Serializer testlari uchun kerak bo'lishi mumkin

User = get_user_model()

# --- Helper Functions (Optional) ---
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# --- Test Classes ---

class AuthTests(APITestCase):
    """Autentifikatsiya va Profil testlari"""

    @classmethod
    def setUpTestData(cls):
        cls.client_user = User.objects.create_user(
            email='client@example.com',
            password='testpassword',
            full_name='Test Client',
            phone_number='+998901234567',
            role='mijoz',
            company_name='Client Company',
            stir='123456789'
        )
        cls.accountant_user = User.objects.create_user(
            email='accountant@example.com',
            password='testpassword',
            full_name='Test Accountant',
            phone_number='+998901234568',
            role='buxgalter',
        )
        # Buxgalter uchun profil yaratish
        cls.accountant_profile = Accountant.objects.create(
            user=cls.accountant_user,
            experience=5,
            specialty='Soliq',
            address='Accountant Address',
            skills='Excel, 1C',
            languages='Uzbek, Russian',
            bio='Experienced accountant',
            certifications='ACCA',
            fee=Decimal('500.00')
        )
        cls.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='testpassword',
            full_name='Test Admin',
            phone_number='+998901234569',
            role='admin'
        )

        cls.signup_url = reverse('signup')
        cls.login_url = reverse('login')
        cls.profile_url = reverse('user-profile')
        cls.profile_edit_url = reverse('profile-edit')
        cls.password_change_url = reverse('password_change')
        cls.password_reset_request_url = reverse('password_reset_request')
        cls.password_reset_confirm_url = reverse('password_reset_confirm')

    def test_signup_client_success(self):
        data = {
            'email': 'newclient@example.com',
            'password': 'newpassword123',
            'full_name': 'New Client',
            'phone_number': '+998911112233',
            'role': 'mijoz',
            'company_name': 'New Company',
            'stir': '987654321'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='newclient@example.com', role='mijoz').exists())
        # Buxgalter profili yaratilmaganligini tekshirish
        new_user = User.objects.get(email='newclient@example.com')
        self.assertFalse(hasattr(new_user, 'accountant_profile'))

    def test_signup_accountant_success(self):
        data = {
            'email': 'newaccountant@example.com',
            'password': 'newpassword123',
            'full_name': 'New Accountant',
            'phone_number': '+998911112244',
            'role': 'buxgalter',
            'experience': 3,
            'specialty': 'Audit',
            'address': 'Test Address',
            'skills': 'Python, SQL',
            'languages': 'English',
            'bio': 'Detail oriented',
            'certifications': 'CPA',
            'fee': '300.50'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='newaccountant@example.com', role='buxgalter').exists())
        # Buxgalter profili yaratilganligini tekshirish
        new_user = User.objects.get(email='newaccountant@example.com')
        self.assertTrue(hasattr(new_user, 'accountant_profile'))
        self.assertEqual(new_user.accountant_profile.experience, 3)
        self.assertEqual(new_user.accountant_profile.fee, Decimal('300.50'))


    def test_signup_missing_fields_for_role(self):
        # Mijoz uchun 'company_name' yo'q
        client_data = {
            'email': 'invalidclient@example.com',
            'password': 'newpassword123',
            'full_name': 'Invalid Client',
            'phone_number': '+998911112255',
            'role': 'mijoz',
            # 'company_name': 'Missing',
            'stir': '987654321'
        }
        # SignupSerializerda mijoz uchun bu maydonlar majburiy EMAS (pass qilingan)
        # Shuning uchun bu test muvaffaqiyatli o'tishi kerak
        response = self.client.post(self.signup_url, client_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED) # Yaratilishi kerak

        # Buxgalter uchun 'experience' yo'q
        accountant_data = {
            'email': 'invalidaccountant@example.com',
            'password': 'newpassword123',
            'full_name': 'Invalid Accountant',
            'phone_number': '+998911112266',
            'role': 'buxgalter',
            # 'experience': 2, # Missing
            'specialty': 'Audit',
            'address': 'Test Address',
            'skills': 'Python, SQL',
            'languages': 'English',
            'bio': 'Detail oriented',
            'certifications': 'CPA',
            'fee': '300.50'
        }
        response = self.client.post(self.signup_url, accountant_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('experience', response.data)

    def test_signup_duplicate_email_or_phone(self):
        # Mavjud email bilan
        data = {
            'email': 'client@example.com', # Mavjud
            'password': 'newpassword123',
            'full_name': 'Duplicate Client',
            'phone_number': '+998911112277',
            'role': 'mijoz',
            'company_name': 'Duplicate Company',
            'stir': '111111111'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

        # Mavjud telefon raqami bilan
        data['email'] = 'anotherclient@example.com'
        data['phone_number'] = '+998901234567' # Mavjud
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('phone_number', response.data)

    def test_login_success(self):
        data = {'email': 'client@example.com', 'password': 'testpassword'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(response.data['role'], 'mijoz')
        self.assertEqual(response.data['full_name'], 'Test Client')
        self.assertEqual(response.data['user_id'], self.client_user.id)

    def test_login_fail_wrong_password(self):
        data = {'email': 'client@example.com', 'password': 'wrongpassword'}
        response = self.client.post(self.login_url, data, format='json')
        # DRF SimpleJWT odatda 401 Unauthorized qaytaradi
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('detail', response.data) # Yoki 'error' custom responsega qarab

    def test_login_fail_nonexistent_user(self):
        data = {'email': 'client@example.com', 'password': 'wrongpassword'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_own_profile_success(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.accountant_user.email)
        self.assertEqual(response.data['role'], 'buxgalter')
        # Buxgalter profilini tekshirish
        self.assertIsNotNone(response.data.get('accountant_profile'))
        self.assertEqual(response.data['accountant_profile']['experience'], 5)

    def test_get_profile_unauthenticated(self):
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_client_success(self):
        self.client.force_authenticate(user=self.client_user)
        data = {
            'full_name': 'Updated Client Name',
            'phone_number': '+998998887766',
            'company_name': 'Updated Company Name'
            # STIR ni o'zgartirmaymiz
        }
        response = self.client.patch(self.profile_edit_url, data, format='json') # PATCH qisman yangilash uchun
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client_user.refresh_from_db()
        self.assertEqual(self.client_user.full_name, 'Updated Client Name')
        self.assertEqual(self.client_user.phone_number, '+998998887766')
        self.assertEqual(self.client_user.company_name, 'Updated Company Name')

    def test_update_profile_accountant_success(self):
        self.client.force_authenticate(user=self.accountant_user)
        data = {
            'full_name': 'Updated Accountant Name',
            'experience': 7, # Buxgalter ma'lumoti
            'fee': '600.00'   # Buxgalter ma'lumoti
        }
        # UserUpdateSerializer 'accountant_profile' ichidagi maydonlarni to'g'ridan-to'g'ri kutadi
        # source='accountant_profile.experience' ishlatilgani uchun
        response = self.client.patch(self.profile_edit_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.accountant_user.refresh_from_db()
        self.accountant_profile.refresh_from_db()
        self.assertEqual(self.accountant_user.full_name, 'Updated Accountant Name')
        self.assertEqual(self.accountant_profile.experience, 7)
        self.assertEqual(self.accountant_profile.fee, Decimal('600.00'))

    def test_update_profile_phone_number_conflict(self):
        # Boshqa userga tegishli raqamni o'rnatishga harakat
        self.client.force_authenticate(user=self.client_user)
        data = {'phone_number': self.accountant_user.phone_number} # accountant raqami
        response = self.client.patch(self.profile_edit_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('phone_number', response.data)

    def test_password_change_success(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'old_password': 'testpassword', 'new_password': 'newsecurepassword'}
        response = self.client.post(self.password_change_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Yangi parol bilan login qilib tekshirish
        self.client.logout()
        login_data = {'email': self.client_user.email, 'password': 'newsecurepassword'}
        login_response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

    def test_password_change_fail_wrong_old_password(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'old_password': 'wrongoldpassword', 'new_password': 'newsecurepassword'}
        response = self.client.post(self.password_change_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('old_password', response.data)

    def test_password_reset_request_success(self):
        data = {'email': self.client_user.email}
        response = self.client.post(self.password_reset_request_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.client_user.email, mail.outbox[0].to)
        self.assertIn('Parolni tiklash', mail.outbox[0].subject)

    def test_password_reset_request_fail_nonexistent_email(self):
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.password_reset_request_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertEqual(len(mail.outbox), 0)

    def test_password_reset_confirm_success(self):
        # Token va uid generatsiya qilish
        user = self.client_user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        new_password = 'resetpassword123'
        data = {'uidb64': uid, 'token': token, 'new_password': new_password}

        response = self.client.post(self.password_reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Yangi parol bilan login qilib tekshirish
        login_data = {'email': user.email, 'password': new_password}
        login_response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

    def test_password_reset_confirm_fail_invalid_token(self):
        user = self.client_user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = 'invalidtoken'
        new_password = 'resetpassword123'
        data = {'uidb64': uid, 'token': token, 'new_password': new_password}
        response = self.client.post(self.password_reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data) # Yoki field nomi (token, uidb64)


class ReportTypeViewSetTests(APITestCase):
    """ReportTypeViewSet uchun testlar"""

    @classmethod
    def setUpTestData(cls):
        cls.admin_user = User.objects.create_user(
            email='admin@example.com', full_name='my admin', password='password', role='admin', phone_number='+998900000001'
        )
        cls.client_user = User.objects.create_user(
            email='client@example.com', full_name='my admin', password='password', role='mijoz', phone_number='+998900000002'
        )
        cls.report_type = ReportType.objects.create(name="Soliq Hisoboti", price=Decimal("100.00"))
        cls.list_url = reverse('report-type-list')
        cls.detail_url = reverse('report-type-detail', kwargs={'pk': cls.report_type.pk})

    def test_list_report_types_authenticated(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_list_report_types_unauthenticated(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_report_type_authenticated(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.report_type.name)

    def test_create_report_type_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'name': 'Moliyaviy Hisobot', 'description': 'Yillik', 'price': '150.00'}
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(ReportType.objects.filter(name='Moliyaviy Hisobot').exists())

    def test_create_report_type_non_admin(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'name': 'Boshqa Hisobot', 'price': '50.00'}
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_report_type_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'price': '120.50'}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_type.refresh_from_db()
        self.assertEqual(self.report_type.price, Decimal('120.50'))

    def test_delete_report_type_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ReportType.objects.filter(pk=self.report_type.pk).exists())

    def test_delete_report_type_non_admin(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class ReportViewSetTests(APITestCase):
    """ReportViewSet uchun testlar"""

    @classmethod
    def setUpTestData(cls):
        cls.client_user = User.objects.create_user(
            email='client@example.com', password='password', role='mijoz', full_name='Client User', phone_number='+998901111111'
        )
        cls.client_user_2 = User.objects.create_user(
             email='client2@example.com', password='password', role='mijoz', full_name='Client 2', phone_number='+998901111113'
        )
        cls.accountant_user = User.objects.create_user(
            email='accountant@example.com', password='password', role='buxgalter', full_name='Acc User', phone_number='+998902222222'
        )
        Accountant.objects.create(user=cls.accountant_user, experience=2, specialty="Tax", address="Tash", skills="1c", languages="uz", bio="bio", certifications="none", fee=100)
        cls.accountant_user_2 = User.objects.create_user(
            email='accountant2@example.com', password='password', role='buxgalter', full_name='Acc 2', phone_number='+998902222223'
        )
        Accountant.objects.create(user=cls.accountant_user_2, experience=3, specialty="Audit", address="Sam", skills="Excel", languages="ru", bio="bio2", certifications="ACCA", fee=200)
        cls.admin_user = User.objects.create_user(
            email='admin@example.com', password='password', role='admin', full_name='Admin User', phone_number='+998903333333'
        )
        cls.report_type = ReportType.objects.create(name="Type 1", price=50)

        # Turli statusdagi hisobotlar
        cls.report_draft = Report.objects.create(
            title="Draft Report", client=cls.client_user, status='draft', category=cls.report_type
        )
        cls.report_submitted = Report.objects.create(
            title="Submitted Report", client=cls.client_user, status='submitted', accountant=cls.accountant_user, category=cls.report_type
        )
        cls.report_in_review = Report.objects.create(
             title="Review Report", client=cls.client_user_2, status='in_review', accountant=cls.accountant_user, category=cls.report_type
         )
        cls.report_approved = Report.objects.create(
            title="Approved Report", client=cls.client_user, status='approved', accountant=cls.accountant_user
        )
        cls.report_rejected = Report.objects.create(
            title="Rejected Report", client=cls.client_user_2, status='rejected', accountant=cls.accountant_user_2
        )

        cls.list_create_url = reverse('report-list')
        cls.detail_url_draft = reverse('report-detail', kwargs={'pk': cls.report_draft.pk})
        cls.detail_url_submitted = reverse('report-detail', kwargs={'pk': cls.report_submitted.pk})
        cls.submit_url = reverse('report-submit', kwargs={'pk': cls.report_draft.pk})
        cls.assign_url = reverse('report-assign-accountant', kwargs={'pk': cls.report_submitted.pk})
        cls.update_status_url = reverse('report-update-status', kwargs={'pk': cls.report_submitted.pk})
        cls.statistics_url = reverse('report-statistics')


    # --- List Tests ---
    def test_list_reports_client(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Faqat client_user ga tegishli hisobotlar sonini tekshirish
        client_report_count = Report.objects.filter(client=self.client_user).count()
        self.assertEqual(len(response.data), client_report_count)
        for report_data in response.data:
            self.assertEqual(report_data['client']['id'], self.client_user.id)

    def test_list_reports_accountant(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Faqat accountant_user ga biriktirilgan hisobotlar sonini tekshirish
        accountant_report_count = Report.objects.filter(accountant=self.accountant_user).count()
        self.assertEqual(len(response.data), accountant_report_count)
        for report_data in response.data:
            if report_data.get('accountant'): # Buxgalter None bo'lmasligi kerak
                self.assertEqual(report_data['accountant']['id'], self.accountant_user.id)

    def test_list_reports_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), Report.objects.count())

    def test_list_reports_unauthenticated(self):
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # --- Create Tests ---
    def test_create_report_client_success(self):
        self.client.force_authenticate(user=self.client_user)
        data = {
            'title': 'New Client Report',
            'description': 'Monthly report',
            'category_id': self.report_type.pk,
            'start_date': '2023-01-01',
            'end_date': '2023-01-31'
        }
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_report = Report.objects.get(pk=response.data['id'])
        self.assertEqual(new_report.client, self.client_user)
        self.assertEqual(new_report.status, 'draft')
        self.assertEqual(new_report.category, self.report_type)
        self.assertIsNotNone(new_report.start_date)

    def test_create_report_accountant_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user)
        data = {'title': 'Acc Report', 'category_id': self.report_type.pk}
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_report_admin_forbidden(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'title': 'Admin Report', 'category_id': self.report_type.pk}
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- Retrieve Tests ---
    def test_retrieve_report_owner_client(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.detail_url_draft)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.report_draft.id)

    def test_retrieve_report_assigned_accountant(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.get(self.detail_url_submitted)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.report_submitted.id)

    def test_retrieve_report_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.detail_url_draft)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_report_other_client_forbidden(self):
        self.client.force_authenticate(user=self.client_user_2)
        response = self.client.get(self.detail_url_draft) # Belongs to client_user
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND) # Yoki 403, Permissionga qarab

    def test_retrieve_report_unassigned_accountant_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user_2)
        response = self.client.get(self.detail_url_submitted) # Assigned to accountant_user
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND) # Yoki 403

    # --- Update Tests ---
    def test_update_report_owner_client_draft_success(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'title': 'Updated Draft Title'}
        response = self.client.patch(self.detail_url_draft, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_draft.refresh_from_db()
        self.assertEqual(self.report_draft.title, 'Updated Draft Title')

    def test_update_report_owner_client_submitted_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'title': 'Trying to update submitted'}
        response = self.client.patch(self.detail_url_submitted, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_report_admin_any_status_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'description': 'Admin updated description'}
        response = self.client.patch(self.detail_url_submitted, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_submitted.refresh_from_db()
        self.assertEqual(self.report_submitted.description, 'Admin updated description')

    def test_update_report_accountant_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user)
        data = {'title': 'Accountant trying update'}
        response = self.client.patch(self.detail_url_submitted, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- Delete Tests ---
    def test_delete_report_owner_client_draft_success(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.delete(self.detail_url_draft)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Report.objects.filter(pk=self.report_draft.pk).exists())

    def test_delete_report_owner_client_submitted_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.delete(self.detail_url_submitted)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_report_admin_any_status_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url_submitted)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Report.objects.filter(pk=self.report_submitted.pk).exists())

    def test_delete_report_accountant_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.delete(self.detail_url_submitted)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- Action Tests ---
    def test_action_submit_report_client_draft_success(self):
        self.client.force_authenticate(user=self.client_user)
        # Fayl qo'shish (agar submit uchun talab qilinmasa, bu qismni olib tashlang)
        # test_file = SimpleUploadedFile("file.txt", b"file_content")
        # Attachment.objects.create(report=self.report_draft, uploaded_by=self.client_user, file=test_file)
        response = self.client.post(self.submit_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_draft.refresh_from_db()
        self.assertEqual(self.report_draft.status, 'submitted')
        self.assertIsNotNone(self.report_draft.submitted_at)

    def test_action_submit_report_client_submitted_fail(self):
        self.client.force_authenticate(user=self.client_user)
        submit_url_for_submitted = reverse('report-submit', kwargs={'pk': self.report_submitted.pk})
        response = self.client.post(submit_url_for_submitted)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) # Yoki 403 permissionga qarab

    def test_action_submit_report_admin_forbidden(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.post(self.submit_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_action_assign_accountant_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        assign_url = reverse('report-assign-accountant', kwargs={'pk': self.report_draft.pk}) # Draftga assign qilamiz
        data = {'accountant_id': self.accountant_user_2.pk}
        response = self.client.put(assign_url, data, format='json') # PUT ishlatilgan viewda
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_draft.refresh_from_db()
        self.assertEqual(self.report_draft.accountant, self.accountant_user_2)

    def test_action_assign_accountant_non_admin_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'accountant_id': self.accountant_user_2.pk}
        response = self.client.put(self.assign_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_action_update_status_accountant_success(self):
        self.client.force_authenticate(user=self.accountant_user) # report_submitted ga tayinlangan
        data = {'status': 'in_review'}
        response = self.client.put(self.update_status_url, data, format='json') # PUT ishlatilgan
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_submitted.refresh_from_db()
        self.assertEqual(self.report_submitted.status, 'in_review')

        # Yana bir o'tishni sinab ko'rish
        data = {'status': 'approved'}
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_submitted.refresh_from_db()
        self.assertEqual(self.report_submitted.status, 'approved')

    def test_action_update_status_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'status': 'rejected', 'comment': 'Admin rejected'} # Rad etish uchun izoh
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report_submitted.refresh_from_db()
        self.assertEqual(self.report_submitted.status, 'rejected')
        # Izoh yaratilganini tekshirish
        self.assertTrue(ReportComment.objects.filter(report=self.report_submitted, author=self.admin_user).exists())

    def test_action_update_status_client_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'status': 'approved'}
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_action_update_status_reject_without_comment_fail(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'status': 'rejected'} # Izoh yo'q
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_action_statistics_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.statistics_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_reports', response.data)
        self.assertIn('reports_by_status', response.data)
        self.assertIn('reports_by_accountant', response.data)
        self.assertIn('reports_by_client', response.data)
        self.assertEqual(response.data['total_reports'], Report.objects.count())

    def test_action_statistics_non_admin_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.statistics_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class NestedAttachmentViewSetTests(APITestCase):
    """Reportga bog'liq AttachmentViewSet uchun testlar"""

    @classmethod
    def setUpTestData(cls):
        # Userlarni yaratish (ReportViewSetTests dan ko'chirish yoki meros olish mumkin)
        cls.client_user = User.objects.create_user(email='client@example.com', full_name='test client', password='password', role='mijoz', phone_number='+998901111111')
        cls.accountant_user = User.objects.create_user(email='accountant@example.com', full_name='test accountant', password='password', role='buxgalter', phone_number='+998902222222')
        Accountant.objects.create(user=cls.accountant_user, experience=1, specialty="S", address="A", skills="K", languages="L", bio="B", certifications="C", fee=1)
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='test admin', password='password', role='admin', phone_number='+998903333333')

        cls.report_draft = Report.objects.create(title="Draft Report", client=cls.client_user, status='draft')
        cls.report_submitted = Report.objects.create(title="Submitted Report", client=cls.client_user, status='submitted', accountant=cls.accountant_user)

        cls.list_create_url = reverse('report-attachments-list', kwargs={'report_pk': cls.report_draft.pk})
        cls.attachment = Attachment.objects.create(report=cls.report_draft, uploaded_by=cls.client_user, file='attachments/test.txt') # Fayl manzilini to'g'rilang
        cls.detail_url = reverse('report-attachments-detail', kwargs={'report_pk': cls.report_draft.pk, 'pk': cls.attachment.pk})


    def test_create_attachment_client_draft_success(self):
        self.client.force_authenticate(user=self.client_user)
        test_file = SimpleUploadedFile("file.pdf", b"file_content", content_type="application/pdf")
        data = {'file': test_file}
        response = self.client.post(self.list_create_url, data, format='multipart') # format='multipart' fayl uchun
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Attachment.objects.filter(report=self.report_draft, file_name="file.pdf").exists())

    def test_create_attachment_client_submitted_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        url = reverse('report-attachments-list', kwargs={'report_pk': self.report_submitted.pk})
        test_file = SimpleUploadedFile("file2.txt", b"file_content")
        data = {'file': test_file}
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) # CanManageAttachment permission

    def test_create_attachment_accountant_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user)
        test_file = SimpleUploadedFile("file3.txt", b"file_content")
        data = {'file': test_file}
        response = self.client.post(self.list_create_url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_attachments_allowed_users(self):
        # Client
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

        # Accountant (submitted report uchun)
        self.client.force_authenticate(user=self.accountant_user)
        url_submitted = reverse('report-attachments-list', kwargs={'report_pk': self.report_submitted.pk})
        response = self.client.get(url_submitted)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Admin
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_attachment_owner_client_draft_success(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Attachment.objects.filter(pk=self.attachment.pk).exists())

    def test_delete_attachment_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_attachment_owner_client_submitted_forbidden(self):
        # Submitted reportga attachment qo'shib, keyin o'chirishni sinash
        self.client.force_authenticate(user=self.admin_user) # Admin qo'shsin
        att_sub = Attachment.objects.create(report=self.report_submitted, uploaded_by=self.client_user, file='attachments/test_sub.txt')
        detail_url_sub = reverse('report-attachments-detail', kwargs={'report_pk': self.report_submitted.pk, 'pk': att_sub.pk})

        self.client.force_authenticate(user=self.client_user) # Endi mijoz o'chirishga harakat qilsin
        response = self.client.delete(detail_url_sub)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) # CanManageAttachment

    def test_delete_attachment_accountant_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) # Yoki 404


class NestedReportCommentViewSetTests(APITestCase):
    """Reportga bog'liq ReportCommentViewSet uchun testlar"""

    @classmethod
    def setUpTestData(cls):
        # Userlar va Hisobotlar (oldingi test classlaridan)
        cls.client_user = User.objects.create_user(email='client@example.com', full_name='test client', password='password', role='mijoz', phone_number='+998901111111')
        cls.accountant_user = User.objects.create_user(email='accountant@example.com', full_name='test accountant', password='password', role='buxgalter', phone_number='+998902222222')
        Accountant.objects.create(user=cls.accountant_user, experience=1, specialty="S", address="A", skills="K", languages="L", bio="B", certifications="C", fee=1)
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='test admin', password='password', role='admin', phone_number='+998903333333')
        cls.report = Report.objects.create(title="Report for Comments", client=cls.client_user, status='submitted', accountant=cls.accountant_user)
        cls.comment_by_client = ReportComment.objects.create(report=cls.report, author=cls.client_user, comment="Client comment")
        cls.comment_by_accountant = ReportComment.objects.create(report=cls.report, author=cls.accountant_user, comment="Accountant comment")

        cls.list_create_url = reverse('report-comments-list', kwargs={'report_pk': cls.report.pk})
        cls.detail_url_client = reverse('report-comments-detail', kwargs={'report_pk': cls.report.pk, 'pk': cls.comment_by_client.pk})
        cls.detail_url_accountant = reverse('report-comments-detail', kwargs={'report_pk': cls.report.pk, 'pk': cls.comment_by_accountant.pk})


    def test_create_comment_allowed_users_success(self):
        users = [self.client_user, self.accountant_user, self.admin_user]
        for user in users:
            self.client.force_authenticate(user=user)
            data = {'comment': f'Comment by {user.role}'}
            response = self.client.post(self.list_create_url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_201_CREATED, f"Failed for user {user.role}")
            self.assertTrue(ReportComment.objects.filter(report=self.report, author=user).exists())
            self.client.logout() # Keyingi user uchun logout

    def test_list_comments_allowed_users(self):
         users = [self.client_user, self.accountant_user, self.admin_user]
         initial_comment_count = ReportComment.objects.filter(report=self.report).count()
         for user in users:
            self.client.force_authenticate(user=user)
            response = self.client.get(self.list_create_url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertGreaterEqual(len(response.data), initial_comment_count)
            self.client.logout()

    def test_update_comment_author_success(self):
        self.client.force_authenticate(user=self.client_user) # comment_by_client muallifi
        data = {'comment': 'Updated client comment'}
        response = self.client.patch(self.detail_url_client, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.comment_by_client.refresh_from_db()
        self.assertEqual(self.comment_by_client.comment, 'Updated client comment')

    def test_update_comment_non_author_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user) # comment_by_client muallifi emas
        data = {'comment': 'Trying to update client comment'}
        response = self.client.patch(self.detail_url_client, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) # CanManageComment

    def test_delete_comment_author_success(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.delete(self.detail_url_client)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ReportComment.objects.filter(pk=self.comment_by_client.pk).exists())

    def test_delete_comment_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url_accountant) # Boshqa userning kommentini o'chirish
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ReportComment.objects.filter(pk=self.comment_by_accountant.pk).exists())

    def test_delete_comment_non_author_non_admin_forbidden(self):
        self.client.force_authenticate(user=self.accountant_user) # comment_by_client muallifi emas
        response = self.client.delete(self.detail_url_client)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) # CanManageComment


class TaskViewSetTests(APITestCase):
    """TaskViewSet uchun testlar"""
    @classmethod
    def setUpTestData(cls):
        # Userlar va Hisobotlar (oldingi test classlaridan)
        cls.client_user = User.objects.create_user(email='client@example.com', full_name='test client', password='password', role='mijoz', phone_number='+998901111111')
        cls.accountant_user = User.objects.create_user(email='accountant@example.com', full_name='test accountant', password='password', role='buxgalter', phone_number='+998902222222')
        Accountant.objects.create(user=cls.accountant_user, experience=1, specialty="S", address="A", skills="K", languages="L", bio="B", certifications="C", fee=1)
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='test admin', password='password', role='admin', phone_number='+998903333333')
        cls.report = Report.objects.create(
            title="Report for Tasks", client=cls.client_user, status='in_review', accountant=cls.accountant_user
        )
        cls.task_pending = Task.objects.create(
            title="Pending Task", accountant=cls.accountant_user, client=cls.client_user, report=cls.report, status='pending'
        )
        cls.task_in_progress = Task.objects.create(
            title="In Progress Task", accountant=cls.accountant_user, client=cls.client_user, status='in_progress', priority='high'
        )
        cls.task_completed = Task.objects.create(
             title="Completed Task", accountant=cls.admin_user, client=cls.client_user, status='completed' # Admin ham task yaratishi mumkin
        )

        cls.list_create_url = reverse('task-list')
        cls.detail_url_pending = reverse('task-detail', kwargs={'pk': cls.task_pending.pk})
        cls.update_status_url = reverse('task-update-status', kwargs={'pk': cls.task_pending.pk})

    # --- Create Tests ---
    def test_create_task_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {
            'title': 'Admin Created Task',
            'accountant_id': self.accountant_user.pk,
            'client_id': self.client_user.pk, # Hisobotsiz task uchun mijoz kerak bo'lishi mumkin
            'description': 'Urgent task',
            'priority': 'high',
            'due_date': '2024-12-31T18:00:00Z'
        }
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_task = Task.objects.get(pk=response.data['id'])
        self.assertEqual(new_task.status, 'pending')
        self.assertEqual(new_task.accountant, self.accountant_user)
        self.assertEqual(new_task.client, self.client_user)

    def test_create_task_accountant_from_report_success(self):
        self.client.force_authenticate(user=self.accountant_user) # Hisobotga tayinlangan buxgalter
        data = {
            'title': 'Task from Report',
            'report_id': self.report.pk, # Avtomatik accountant va client ni olishi kerak
            'description': 'Follow up on report',
            'priority': 'medium'
        }
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_task = Task.objects.get(pk=response.data['id'])
        self.assertEqual(new_task.accountant, self.accountant_user) # Reportdan keldi
        self.assertEqual(new_task.client, self.client_user) # Reportdan keldi
        self.assertEqual(new_task.status, 'pending')

    def test_create_task_client_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'title': 'Client Task', 'accountant_id': self.accountant_user.pk}
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- List Tests ---
    def test_list_tasks_accountant(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        accountant_task_count = Task.objects.filter(accountant=self.accountant_user).count()
        self.assertEqual(len(response.data), accountant_task_count)

        # Filter test
        response_filtered = self.client.get(self.list_create_url, {'status': 'pending'})
        self.assertEqual(response_filtered.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_filtered.data), 1)
        self.assertEqual(response_filtered.data[0]['id'], self.task_pending.id)

    def test_list_tasks_client(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        client_task_count = Task.objects.filter(client=self.client_user).count()
        self.assertEqual(len(response.data), client_task_count)

    def test_list_tasks_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), Task.objects.count())

        # Filter test (clientId)
        response_filtered = self.client.get(self.list_create_url, {'clientId': self.client_user.pk})
        self.assertEqual(response_filtered.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_filtered.data), Task.objects.filter(client=self.client_user).count())


    # --- Update / Retrieve / Delete ---
    def test_retrieve_task_allowed_users(self):
        # Accountant, Client, Admin
        users_allowed = [self.accountant_user, self.client_user, self.admin_user]
        for user in users_allowed:
            self.client.force_authenticate(user=user)
            response = self.client.get(self.detail_url_pending)
            self.assertEqual(response.status_code, status.HTTP_200_OK, f"Failed for {user.role}")
            self.assertEqual(response.data['id'], self.task_pending.id)
            self.client.logout()

    def test_update_task_accountant_success(self):
        self.client.force_authenticate(user=self.accountant_user)
        data = {'title': 'Updated Task Title', 'priority': 'low'}
        response = self.client.patch(self.detail_url_pending, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task_pending.refresh_from_db()
        self.assertEqual(self.task_pending.title, 'Updated Task Title')
        self.assertEqual(self.task_pending.priority, 'low')

    def test_update_task_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'description': 'Admin updated task desc'}
        response = self.client.patch(self.detail_url_pending, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task_pending.refresh_from_db()
        self.assertEqual(self.task_pending.description, 'Admin updated task desc')

    def test_update_task_client_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'title': 'Client trying to update'}
        response = self.client.patch(self.detail_url_pending, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_task_accountant_success(self):
        self.client.force_authenticate(user=self.accountant_user)
        response = self.client.delete(self.detail_url_pending)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Task.objects.filter(pk=self.task_pending.pk).exists())

    def test_delete_task_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url_pending)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_task_client_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.delete(self.detail_url_pending)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- Action update_status ---
    def test_action_update_status_accountant_success(self):
        self.client.force_authenticate(user=self.accountant_user)
        data = {'status': 'in_progress'}
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task_pending.refresh_from_db()
        self.assertEqual(self.task_pending.status, 'in_progress')

        # Yana bir o'tish
        data = {'status': 'completed'}
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task_pending.refresh_from_db()
        self.assertEqual(self.task_pending.status, 'completed')
        self.assertIsNotNone(self.task_pending.completed_at)


    def test_action_update_status_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'status': 'cancelled'}
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task_pending.refresh_from_db()
        self.assertEqual(self.task_pending.status, 'cancelled')


    def test_action_update_status_client_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        data = {'status': 'in_progress'}
        response = self.client.put(self.update_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_action_update_status_invalid_transition(self):
        self.client.force_authenticate(user=self.accountant_user)
        # Completed task ni o'zgartirishga harakat
        completed_task_status_url = reverse('task-update-status', kwargs={'pk': self.task_completed.pk})
        data = {'status': 'pending'}
        response = self.client.put(completed_task_status_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) # Yoki 403 permission ga qarab


# --- Boshqa ViewSetlar uchun testlar (AboutUs, Message, PaymentCard, UserAdmin) ---
# Quyida bir nechta namunaviy testlar keltirilgan, ularni to'ldirish kerak bo'ladi.

class AboutUsViewSetTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='my admin', password='password', role='admin', phone_number='+998903333333')
        cls.about_us = AboutUs.objects.create(title="About", text="Some text")
        cls.list_url = reverse('aboutus-list')
        cls.detail_url = reverse('aboutus-detail', kwargs={'pk': cls.about_us.pk})

    def test_list_aboutus_anyone(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_aboutus_anyone(self):
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_aboutus_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'title': 'New About', 'text': 'More text'}
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_aboutus_non_admin(self):
        # Authenticate as client or accountant if needed
        response = self.client.post(self.list_url, {'title': 'Fail'}, format='json')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])


class MessageViewSetTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user1 = User.objects.create_user(email='user1@example.com', full_name='my admin1', password='password', role='mijoz', phone_number='+998901111111')
        cls.user2 = User.objects.create_user(email='user2@example.com', full_name='my admin2', password='password', role='buxgalter', phone_number='+998902222222')
        Accountant.objects.create(user=cls.user2, experience=1, specialty="S", address="A", skills="K", languages="L", bio="B", certifications="C", fee=1)
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='my admin', password='password', role='admin', phone_number='+998903333333')
        cls.message = Message.objects.create(sender=cls.user1, recipient=cls.user2, message="Hello")
        cls.list_create_url = reverse('message-list')
        cls.detail_url = reverse('message-detail', kwargs={'pk': cls.message.pk})


    def test_create_message_authenticated_success(self):
        self.client.force_authenticate(user=self.user1)
        data = {'recipient': self.user2.pk, 'message': 'Another message'}
        response = self.client.post(self.list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_message = Message.objects.get(pk=response.data['id'])
        self.assertEqual(new_message.sender, self.user1)
        self.assertEqual(new_message.recipient, self.user2)

    def test_list_messages_own_success(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['id'], self.message.id)

        # User2 uchun tekshirish
        self.client.force_authenticate(user=self.user2)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_delete_message_sender_success(self):
        self.client.force_authenticate(user=self.user1) # Sender
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_message_recipient_forbidden(self):
        self.client.force_authenticate(user=self.user2) # Recipient
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) # MessageViewSet permission

    def test_delete_message_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)


class PaymentCardViewSetTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='my admin', password='password', role='admin', phone_number='+998903333333')
        cls.card = PaymentCard.objects.create(card_number='8600111122223333', owner_name='Test', bank_name='Admin')
        cls.random_url = reverse('payment-card-random')
        cls.list_url = reverse('payment-card-list')

    def test_get_random_card_anyone(self):
        response = self.client.get(self.random_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['card_number'], self.card.card_number)

    def test_list_cards_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_cards_non_admin(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED) # Yoki 403 agar login bo'lsa


class UserAdminViewSetTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin_user = User.objects.create_user(email='admin@example.com', full_name='my admin', password='password', role='admin', phone_number='+998903333333')
        cls.client_user = User.objects.create_user(email='client@example.com', full_name='my client', password='password', role='mijoz', phone_number='+998901111111')
        cls.list_create_url = reverse('admin-users-list')
        cls.detail_url = reverse('admin-users-detail', kwargs={'pk': cls.client_user.pk})

    def test_list_users_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Admin va client user bo'lishi kerak
        self.assertGreaterEqual(len(response.data), 2)

    def test_list_users_non_admin_forbidden(self):
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_user_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {
            'email': 'newuser@example.com',
            'password': 'password123', # Password yuborish kerakmi? ModelViewSet create qanday ishlaydi?
            'full_name': 'New User by Admin',
            'phone_number': '+998955554433',
            'role': 'mijoz',
            'company_name': 'AdminCreated Co',
            'stir': '112233445'
        }
        # UserAdminViewSet qaysi serializerni ishlatishiga qarab 'password' ni handle qilish kerak bo'lishi mumkin
        # Agar UserSerializer ishlatsa, password create da o'rnatilmaydi
        # Maxsus serializer yoki viewsetda `perform_create` override qilinishi kerak
        # Hozircha UserSerializer deb taxmin qilamiz va parol yaratilmaydi
        response = self.client.post(self.list_create_url, data, format='json')
        # Agar UserSerializer `password`ni write_only qilib olmasa, bu 201 qaytaradi lekin parol o'rnatilmaydi
        # Agar password yozilmasa 400 qaytarishi mumkin
        # Keling, UserSerializer da password yo'q deb hisoblaymiz:
        if 'password' in response.data: # Yoki UserSerializerga qarab
           del data['password'] # Agar serializer passwordni olmasa
        response = self.client.post(self.list_create_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED) # Yoki 400 agar parol majburiy bo'lsa
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())

    def test_update_user_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {'full_name': 'Updated by Admin', 'is_active': False}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client_user.refresh_from_db()
        self.assertEqual(self.client_user.full_name, 'Updated by Admin')
        self.assertFalse(self.client_user.is_active)

    def test_delete_user_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(pk=self.client_user.pk).exists())