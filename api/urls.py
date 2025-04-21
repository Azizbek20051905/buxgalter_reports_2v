from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers # Nested router uchun
from .views import *

# Asosiy router
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user') # Admin uchun foydalanuvchilar ro'yxati
router.register(r'report-types', ReportTypeViewSet, basename='report-type') # Hisobot turlari/kategoriyalari
router.register(r'accountants', AccountantViewSet, basename='accountant') # Buxgalterlar ro'yxati (ReadOnly)
router.register(r'reports', ReportViewSet, basename='report') # Asosiy hisobotlar endpointi
router.register(r'tasks', TaskViewSet, basename='task') # Vazifalar endpointi
router.register(r'messages', MessageViewSet, basename='message') # Xabarlar CRUD (ehtiyot bo'lish kerak)
router.register(r'payment-cards', PaymentCardViewSet, basename='payment-card') # To'lov kartalari (Admin)
router.register(r'admin-users', UserAdminViewSet, basename='admin-users') # Admin uchun User CRUD
router.register(r'aboutus', AboutUsViewSet, basename='aboutus') # About Us (Admin/ReadOnly)
router.register(r'chats', ChatViewSet, basename='chats') # Chatlar ro'yxati (ReadOnly)
router.register(r'admin-chats', AdminChatViewSet, basename='admin-chats') # Admin uchun chatlar

# Hisobotlar uchun nested router (Attachments va Comments)
reports_router = routers.NestedDefaultRouter(router, r'reports', lookup='report')
reports_router.register(r'attachments', AttachmentViewSet, basename='report-attachments')
reports_router.register(r'comments', ReportCommentViewSet, basename='report-comments')
# Hisobotdan vazifa yaratish uchun alohida URL kerak emas, TaskViewSet create ishlatiladi (report_id bilan)

urlpatterns = [
    # Autentifikatsiya va Profil
    path('auth/signup/', SignupView.as_view(), name='signup'),
    path('auth/login/', LoginView.as_view(), name='login'),
    # Token yangilash uchun (Simple JWT standart)
    path('auth/token/refresh/', TokenObtainPairView.as_view(), name='token_refresh'), # Buni qo'shish kerak
    path('auth/profile/', UserProfileView.as_view(), name='user-profile'),
    path('auth/profile/edit/', UserProfileUpdateView.as_view(), name='profile-edit'),
    path('auth/password-change/', PasswordChangeView.as_view(), name='password_change'),
    path('auth/password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    # URL tuzilishi TZ ga moslashtirildi (uid/token parametr sifatida)
    # Frontend bu URL ni qayta ishlaydi, backendga faqat POST so'rov keladi
    path('auth/password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    # API endpointlar
    path('', include(router.urls)),
    path('admin/', include(reports_router.urls)), # Nested routerlarni qo'shish
]

# Eslatma: TZ dagi /api/client/, /api/accountant/, /api/admin/ prefikslari o'rniga
# yagona /api/reports/, /api/tasks/ endpointlari ishlatildi va ruxsatnomalar
# orqali kirish boshqarildi. Bu DRF da keng tarqalgan va qulayroq yondashuv.
# Agar frontend talabi qat'iy bo'lsa, viewsetlarni klonlash yoki alohida viewlar yozish kerak bo'ladi.