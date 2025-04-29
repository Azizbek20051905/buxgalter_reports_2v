from datetime import timedelta
import random
from decimal import Decimal # Qo'shildi
from django.conf import settings
from rest_framework.exceptions import PermissionDenied, NotFound
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode # decode qo'shildi
from django.contrib.auth.tokens import default_token_generator # Qo'shildi
from django.utils import timezone # Qo'shildi
from django.shortcuts import get_object_or_404 # Qo'shildi
from django.db.models import Q, Count # Q va Count qo'shildi
from rest_framework import generics, status, viewsets, permissions, views, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny, IsAuthenticated # IsAdminUser o'rniga custom
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import PermissionDenied, NotFound # Qo'shildi
from django.db.models import Sum, Count, F, DecimalField
from django.db.models.functions import TruncMonth, TruncYear, Coalesce

# Serializerlarni va Modellarni import qilish
from django_filters.rest_framework import DjangoFilterBackend # DjangoFilterBackend uchun
from .filters import UserFilter, PaymentFilter, PaymentModelFilter  # Yangi filter klassi
from dateutil.relativedelta import relativedelta
from .serializers import *
from .models import *
import calendar
# Yangi ruxsatnomalarni import qilish
from .permissions import (
    IsAdminUser, IsAccountantUser, IsClientUser,
    IsOwnerOrAdmin, IsAssignedAccountantOrAdmin,
    CanManageReport, CanManageTask, CanManageAttachment, CanManageComment
)

User = get_user_model()



class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [AllowAny]

class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as e:
             # Agar xatolik lug'at ko'rinishida bo'lsa
             if isinstance(e.detail, dict):
                  error_message = ", ".join([f"{k}: {v[0]}" for k, v in e.detail.items()])
             else:
                  error_message = str(e.detail[0]) if isinstance(e.detail, list) else str(e.detail)
             return Response({"error": f"Login xatosi: {error_message}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Boshqa kutilmagan xatolar uchun
            return Response({"error": f"Login amalga oshmadi: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


        user = serializer.user
        refresh = serializer.validated_data.get('refresh')
        access = serializer.validated_data.get('access')

        # Token payloadidan role va ismni olish (CustomTokenObtainPairSerializer ga bog'liq)
        # Yoki to'g'ridan-to'g'ri user obyektidan:
        role = user.role
        full_name = user.full_name


        return Response({
            "message": "Tizimga muvaffaqiyatli kirdingiz!",
            "access": access,
            "refresh": refresh,
            "role": role,
            "full_name": full_name,
            # Frontendga kerak bo'lsa user ID sini ham qo'shish mumkin
            "user_id": user.id
        }, status=status.HTTP_200_OK)


# UserViewSet ni admin uchun qoldiramiz, lekin UserAdminViewSet ham bor
class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.all().order_by('full_name')
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        queryset = super().get_queryset()
        role = self.request.query_params.get('role')
        if role in ['mijoz', 'buxgalter', 'admin']:
            queryset = queryset.filter(role=role)
        search = self.request.query_params.get('search')
        if search:
             queryset = queryset.filter(
                 Q(full_name__icontains=search) | Q(email__icontains=search)
             )
        return queryset


class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer # UserSerializer Accountant ma'lumotlarini ham ko'rsatadi
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class UserProfileUpdateView(generics.RetrieveUpdateAPIView): # Destroy olib tashlandi
    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser] # Rasm yuklash uchun

    def get_object(self):
        # Faqat o'z profilini o'zgartira oladi
        return self.request.user

    def perform_update(self, serializer):
        # `update` metodi serializer ichida logikani bajaradi
        serializer.save()


class PasswordChangeView(generics.GenericAPIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        new_password = serializer.validated_data['new_password']
        user.set_password(new_password)
        user.save()

        return Response({"detail": "Parol muvaffaqiyatli o‘zgartirildi."}, status=status.HTTP_200_OK)


class AboutUsViewSet(viewsets.ModelViewSet):
    queryset = AboutUs.objects.all()
    serializer_class = AboutUsSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAdminUser()] # Faqat admin o'zgartira oladi


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [AllowAny] # Hamma uchun ochiq

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.get(email=email) # Validatorda tekshirilgan

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        # Frontend URL ni sozlamalardan olish yaxshiroq
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000') # Default qiymat
        reset_link = f"{frontend_url}/reset-password/{uid}/{token}" # TZ ga mos endpoint

        try:
            send_mail(
                "Parolni tiklash",
                f"Parolingizni tiklash uchun quyidagi havolaga bosing: {reset_link}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            return Response({"detail": "Parolni tiklash bo‘yicha email yuborildi."}, status=status.HTTP_200_OK)
        except Exception as e:
             # Email yuborishda xatolik
             # Log yozish kerak
             print(f"Email yuborishda xatolik: {e}")
             return Response({"error": "Email yuborishda xatolik yuz berdi. Iltimos keyinroq urinib ko'ring."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny] # Token orqali tekshiriladi

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        new_password = serializer.validated_data['new_password']
        user.set_password(new_password)
        user.save()

        return Response({"detail": "Parol muvaffaqiyatli o‘zgartirildi."}, status=status.HTTP_200_OK)




class ReportTypeViewSet(viewsets.ModelViewSet):
    """
    Hisobot turlari (kategoriyalar) uchun CRUD operatsiyalari.
    Faqat adminlar uchun to'liq ruxsat, qolganlar faqat o'qishi mumkin.
    """
    queryset = ReportType.objects.all().order_by('name')
    serializer_class = ReportTypeSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticated()] # Hamma login qilganlar ko'ra oladi
        return [IsAdminUser()] # Faqat admin yaratishi/o'zgartirishi/o'chirishi mumkin


class AccountantViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Buxgalterlar ro'yxatini ko'rish (Admin va Mijozlar uchun).
    Buxgalter yaratish/o'zgartirish Signup/UserProfileUpdate orqali amalga oshiriladi.
    """
    queryset = Accountant.objects.select_related('user').filter(user__role='buxgalter', user__is_active=True).order_by('user__full_name')
    serializer_class = AccountantSerializer
    permission_classes = [IsAuthenticated] # Hamma login qilganlar ko'ra oladi

    # Adminlar uchun CRUD operatsiyalari UserAdminViewSet orqali bo'ladi
    # Bu yerda faqat ReadOnly


class ReportViewSet(viewsets.ModelViewSet):
    """
    Hisobotlar uchun asosiy CRUD va qo'shimcha actionlar.
    Ruxsatnomalar CanManageReport orqali boshqariladi.
    """
    queryset = Report.objects.select_related('client', 'accountant', 'category')\
                           .prefetch_related('comments', 'attachments', 'tasks')\
                           .all().order_by('-created_at')
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]



    def get_queryset(self):
        # --- Swagger schema generation uchun tekshiruv ---
        if getattr(self, 'swagger_fake_view', False):
            return Report.objects.none()

        user = self.request.user
        if not user.is_authenticated:
            return Report.objects.none()

        queryset = super().get_queryset()

        # Rolga qarab asosiy filterlash
        if user.role == 'mijoz':
            queryset = queryset.filter(client=user)
        elif user.role == 'buxgalter':
            queryset = queryset.filter(accountant=user)
        elif user.role == 'admin':
            pass



        return queryset

    def perform_create(self, serializer):
        # Client avtomatik ravishda joriy foydalanuvchi sifatida o'rnatiladi
        # Serializerda status='draft' o'rnatilgan
        serializer.save(client=self.request.user)

    def perform_update(self, serializer):
        # Update logikasi CanManageReport permission va serializerda
        instance = serializer.save()
        # Agar status o'zgargan bo'lsa, bildirishnoma yuborish logikasi qo'shilishi mumkin

    # --- Custom Actions ---

    @action(detail=True, methods=['post'], permission_classes=[CanManageReport]) # Ruxsat CanManageReport ichida
    def submit(self, request, pk=None):
        """
        3.1.5: Mijoz hisobotni ko'rib chiqish uchun yuboradi.
        Faqat 'draft' yoki 'rejected' statusdagi hisobotlar uchun ishlaydi.
        """
        report = self.get_object() # Permission obyektni tekshiradi

        if report.status not in ['draft', 'rejected']:
             return Response({"error": "Faqat qoralama yoki rad etilgan hisobotlarni yuborish mumkin."}, status=status.HTTP_400_BAD_REQUEST)

        # Minimal talablar (masalan, fayl biriktirilganmi?) tekshirilishi mumkin
        # if not report.attachments.exists():
        #     return Response({"error": "Hisobot yuborishdan oldin kamida bitta fayl yuklang."}, status=status.HTTP_400_BAD_REQUEST)


        report.status = 'submitted'
        report.submitted_at = timezone.now()
        report.save(update_fields=['status', 'submitted_at'])

        # Bildirishnoma yuborish (admin/buxgalterga)
        # ...

        serializer = self.get_serializer(report)
        return Response(serializer.data)


    @action(detail=True, methods=['put'], url_path='assign', permission_classes=[IsAdminUser]) # Faqat Admin
    def assign_accountant(self, request, pk=None):
        """
        3.3.3: Admin hisobotni buxgalterga tayinlaydi.
        """
        report = self.get_object()
        accountant_id = request.data.get('accountant_id')

        if not accountant_id:
            return Response({"error": "accountant_id maydoni majburiy."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            accountant = User.objects.get(pk=accountant_id, role='buxgalter', is_active=True)
        except User.DoesNotExist:
            return Response({"error": "Bunday faol buxgalter topilmadi."}, status=status.HTTP_404_NOT_FOUND)

        report.accountant = accountant
        # Tayinlanganda statusni 'in_review' ga o'tkazish mumkin (ixtiyoriy)
        # if report.status == 'submitted':
        #     report.status = 'in_review'
        report.save(update_fields=['accountant']) # 'status' ham qo'shilishi mumkin

        # Bildirishnoma yuborish (buxgalterga)
        # ...

        serializer = self.get_serializer(report)
        return Response(serializer.data)


    @action(detail=True, methods=['put'], url_path='status', permission_classes=[CanManageReport]) # Ruxsat CanManageReport ichida
    def update_status(self, request, pk=None):
        """
        3.2.6, 3.3.4: Buxgalter yoki Admin hisobot statusini yangilaydi.
        """
        report = self.get_object() # Permission tekshiradi
        new_status = request.data.get('status')

        if not new_status or new_status not in [s[0] for s in Report.STATUS_CHOICES]:
            return Response({"error": "Yangi status ('status' maydoni) noto'g'ri yoki ko'rsatilmagan."}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        allowed_transitions = {
            'submitted': ['in_review'], # Buxgalter/Admin
            'in_review': ['approved', 'rejected'], # Buxgalter/Admin
             # Boshqa o'tishlar submit yoki assign orqali bo'ladi
        }

        # Kim qaysi statusga o'tkaza olishini tekshirish
        can_change = False
        if user.role == 'admin':
             # Admin deyarli hamma statusga o'tkaza oladi (logikaga qarab)
             can_change = True # Yoki aniqroq qoidalar
        elif user.role == 'buxgalter' and report.accountant == user:
             # Buxgalter faqat ruxsat etilgan o'tishlarni qila oladi
             if report.status in allowed_transitions and new_status in allowed_transitions[report.status]:
                 can_change = True

        if not can_change:
            raise PermissionDenied("Sizda bu statusga o'zgartirish uchun ruxsat yo'q.")
            # Yoki: return Response({"error": f"'{report.status}' statusidan '{new_status}' statusiga o'tish mumkin emas."}, status=status.HTTP_400_BAD_REQUEST)


        # Status o'zgarishiga qarab qo'shimcha logikalar
        if new_status == 'approved':
             # Tasdiqlanganda bajariladigan ishlar
             pass
        elif new_status == 'rejected':
             # Rad etilganda bajariladigan ishlar (masalan, mijozga bildirishnoma)
             # Izoh qo'shish talab qilinishi mumkin
             comment = request.data.get('comment')
             if not comment:
                 return Response({"error": "Rad etish sababini ('comment' maydoni) kiriting."}, status=status.HTTP_400_BAD_REQUEST)
             # Avtomatik izoh qo'shish
             ReportComment.objects.create(report=report, author=user, comment=f"Rad etildi: {comment}")
             pass

        report.status = new_status
        report.save(update_fields=['status'])

        # Bildirishnoma yuborish
        # ...

        serializer = self.get_serializer(report)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='statistics', permission_classes=[IsAdminUser]) # Faqat Admin
    def statistics(self, request):
        """
        3.3.5: Admin uchun hisobotlar statistikasi.
        """
        queryset = Report.objects # Filterlanmagan queryset
        period = request.query_params.get('period') # 'year', 'month', 'all'

        # Davrga qarab filterlash (hozircha oddiy)
        # ...

        total_reports = queryset.count()
        status_counts = queryset.values('status').annotate(count=Count('status')).order_by('status')
        accountant_counts = queryset.filter(accountant__isnull=False)\
                                   .values('accountant__full_name')\
                                   .annotate(count=Count('id'))\
                                   .order_by('-count')
        client_counts = queryset.values('client__full_name')\
                                .annotate(count=Count('id'))\
                                .order_by('-count')

        return Response({
            "total_reports": total_reports,
            "reports_by_status": {item['status']: item['count'] for item in status_counts},
            "reports_by_accountant": {item['accountant__full_name']: item['count'] for item in accountant_counts},
            "reports_by_client": {item['client__full_name']: item['count'] for item in client_counts},
             # Vaqt bo'yicha statistika qo'shilishi mumkin
        })

    # Nested ViewSet'lar uchun yo'l ochish (URL'larda sozlanadi)
    # Masalan: /api/reports/{report_pk}/attachments/


class AttachmentViewSet(viewsets.ModelViewSet):
    serializer_class = AttachmentSerializer
    permission_classes = [IsAuthenticated, CanManageAttachment]
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        report_pk = self.kwargs.get('report_pk')
        # --- Swagger schema generation va pk yo'qligi uchun tekshiruv ---
        if not report_pk:
            if getattr(self, 'swagger_fake_view', False):
                 return Attachment.objects.none() # Swagger uchun bo'sh qaytarish
            # Haqiqiy so'rovda pk yo'q bo'lsa xatolik beramiz
            raise NotFound("Hisobot ID si (report_pk) URLda ko'rsatilmagan.")

        # Ruxsat permission classda tekshiriladi
        return Attachment.objects.filter(report_id=report_pk).select_related('uploaded_by').order_by('-uploaded_at')

    def perform_create(self, serializer):
        report_pk = self.kwargs.get('report_pk')
        try:
            report = Report.objects.get(pk=report_pk)
            # CanManageAttachment permissionida report statusi tekshiriladi
        except Report.DoesNotExist:
             raise NotFound("Hisobot topilmadi.")

        # Permission classda create uchun ruxsat tekshirilgan
        serializer.save(report=report, uploaded_by=self.request.user)

    def perform_destroy(self, instance):
         # Faylni diskdan ham o'chirish (agar kerak bo'lsa)
         # instance.file.delete(save=False) # save=False muhim!
         instance.delete()


class ReportCommentViewSet(viewsets.ModelViewSet):
    serializer_class = ReportCommentSerializer
    permission_classes = [IsAuthenticated, CanManageComment]

    def get_queryset(self):
        report_pk = self.kwargs.get('report_pk')
        # --- Swagger schema generation va pk yo'qligi uchun tekshiruv ---
        if not report_pk:
            if getattr(self, 'swagger_fake_view', False):
                return ReportComment.objects.none() # Swagger uchun bo'sh qaytarish
            # Haqiqiy so'rovda pk yo'q bo'lsa xatolik beramiz
            raise NotFound("Hisobot ID si (report_pk) URLda ko'rsatilmagan.")

        # Ruxsat permission classda tekshiriladi
        return ReportComment.objects.filter(report_id=report_pk).select_related('author').order_by('created_at')

    def perform_create(self, serializer):
        report_pk = self.kwargs.get('report_pk')
        try:
             report = Report.objects.get(pk=report_pk)
             # CanManageComment permissionida reportga kirish tekshiriladi
        except Report.DoesNotExist:
            raise NotFound("Hisobot topilmadi.")

        serializer.save(report=report, author=self.request.user)

    # Update/Destroy ruxsatlari CanManageCommentda tekshiriladi


class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.select_related('accountant', 'client', 'report').all().order_by('-created_at')
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated, CanManageTask]

    def get_queryset(self):
        # --- Swagger schema generation uchun tekshiruv ---
        if getattr(self, 'swagger_fake_view', False):
            return Task.objects.none() # Bo'sh queryset qaytarish

        user = self.request.user
        # --- Autentifikatsiya tekshiruvi ---
        if not user.is_authenticated:
            return Task.objects.none()

        queryset = super().get_queryset()

        # Rolga qarab filter
        if user.role == 'buxgalter':
            queryset = queryset.filter(accountant=user)
        elif user.role == 'mijoz':
            queryset = queryset.filter(client=user)
        elif user.role == 'admin':
            pass

        # Query params filter
        status_filter = self.request.query_params.get('status')
        if status_filter and status_filter in [s[0] for s in Task.STATUS_CHOICES]:
            queryset = queryset.filter(status=status_filter)

        priority_filter = self.request.query_params.get('priority')
        if priority_filter and priority_filter in [p[0] for p in Task.PRIORITY_CHOICES]:
             queryset = queryset.filter(priority=priority_filter)

        # Accountant va Admin uchun Client ID filter
        if user.role in ['admin', 'buxgalter']:
            client_id_filter = self.request.query_params.get('clientId')
            if client_id_filter:
                queryset = queryset.filter(client__id=client_id_filter)

        # Admin uchun Accountant ID filter
        if user.role == 'admin':
            accountant_id_filter = self.request.query_params.get('accountantId')
            if accountant_id_filter:
                 queryset = queryset.filter(accountant__id=accountant_id_filter)


        return queryset

    def perform_create(self, serializer):
        # Kim yaratishi mumkinligi CanManageTask da tekshiriladi
        # Serializerda status='pending' o'rnatiladi
        # Agar report_id berilsa, serializer clientni avtomatik to'ldiradi
        # Agar report_id berilmasa, accountant_id va client_id majburiy bo'lishi kerak (serializerda emas, viewda tekshirish mumkin)
        report_id = serializer.validated_data.get('report_id')
        client_id = serializer.validated_data.get('client_id')

        # Agar reportdan yaratilmayotgan bo'lsa (admin tomonidan), client kerak bo'lishi mumkin
        # if not report_id and not client_id and self.request.user.role == 'admin':
             # raise serializers.ValidationError({"client_id": "Hisobotsiz vazifa uchun mijoz ko'rsatilishi kerak."})

        serializer.save() # Status va completed_at model save() da boshqariladi

    @action(detail=True, methods=['put'], url_path='status', permission_classes=[CanManageTask]) # Ruxsat permissionda
    def update_status(self, request, pk=None):
        """
        3.2.3: Buxgalter (yoki Admin) vazifa statusini yangilaydi.
        """
        task = self.get_object() # Permission tekshiradi
        new_status = request.data.get('status')

        if not new_status or new_status not in [s[0] for s in Task.STATUS_CHOICES]:
             return Response({"error": "Yangi status ('status' maydoni) noto'g'ri yoki ko'rsatilmagan."}, status=status.HTTP_400_BAD_REQUEST)

        # Status o'tishlarini cheklash mumkin
        allowed_transitions = {
            'pending': ['in_progress', 'cancelled'],
            'in_progress': ['completed', 'cancelled', 'pending'], # Qaytarish mumkinmi?
             # Bajarilgan yoki bekor qilingandan o'tish yo'q
        }

        if task.status in allowed_transitions and new_status not in allowed_transitions[task.status]:
             return Response({"error": f"'{task.status}' statusidan '{new_status}' statusiga o'tish mumkin emas."}, status=status.HTTP_400_BAD_REQUEST)
        elif task.status in ['completed', 'cancelled']:
              return Response({"error": f"'{task.status}' statusidagi vazifani o'zgartirib bo'lmaydi."}, status=status.HTTP_400_BAD_REQUEST)


        task.status = new_status
        task.save(update_fields=['status', 'completed_at']) # completed_at avtomatik o'zgaradi

        # Bildirishnoma yuborish
        # ...

        serializer = self.get_serializer(task)
        return Response(serializer.data)


# --- Mavjud Chat, Message, PaymentCard ViewSetlar ---
# Bu qismlarni TZ ga bevosita aloqasi yo'q, lekin Message uchun ruxsatlarni ko'rib chiqish kerak

class ChatViewSet(viewsets.ReadOnlyModelViewSet):
    # ... (mavjud kod)
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated] # O'z chatlarini ko'rish

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Message.objects.none()
        # Foydalanuvchi ishtirok etgan chatlar (oxirgi xabarlar bo'yicha guruhlash kerak)
        # Bu murakkabroq query talab qiladi, hozircha shunday qoldiramiz
        return Message.objects.filter(Q(sender=user) | Q(recipient=user)).select_related('sender', 'recipient').order_by('-created_at')


class AdminChatViewSet(viewsets.ModelViewSet): # Yoki ReadOnly?
    # ... (mavjud kod)
    serializer_class = MessageSerializer
    permission_classes = [IsAdminUser] # Faqat Admin
    queryset = Message.objects.select_related('sender', 'recipient').all().order_by('-created_at')

    # O'chirish logikasi mavjud kodda bor


class MessageViewSet(viewsets.ModelViewSet):
    # Bu viewset ChatViewSet bilan bir xil vazifani bajaradi, bittasini qoldirish mumkin
    # Yoki bu faqat xabar yaratish/o'chirish uchun bo'lishi mumkin
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated] # Xabar yuborish/o'chirish

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Message.objects.none()
        # Faqat o'ziga tegishli xabarlarni (yuborgan yoki qabul qilgan) ko'ra oladi/o'zgartira oladi
        return Message.objects.filter(Q(sender=user) | Q(recipient=user)).select_related('sender', 'recipient').order_by('-created_at')

    def perform_create(self, serializer):
        # Sender avtomatik o'rnatiladi
        serializer.save(sender=self.request.user)

    def check_object_permissions(self, request, obj):
        super().check_object_permissions(request, obj)
        # Faqat sender (yoki admin?) o'z xabarini o'chira oladi/o'zgartira oladi
        if request.method not in permissions.SAFE_METHODS:
            if obj.sender != request.user and request.user.role != 'admin':
                self.permission_denied(request, message="Faqat o'z xabaringizni o'zgartira olasiz.")


class PaymentCardViewSet(viewsets.ModelViewSet):
    # ... (mavjud kod)
    queryset = PaymentCard.objects.all()
    serializer_class = PaymentCardSerializer

    def get_permissions(self):
        if self.action == 'get_random_card':
             return [AllowAny()] # Random kartani hamma ko'rishi mumkin
        return [IsAdminUser()] # Faqat admin boshqara oladi

    @action(detail=False, methods=['get'], url_path='random', permission_classes=[AllowAny])
    def get_random_card(self, request):
        # ... (mavjud kod)
        cards = PaymentCard.objects.all()
        if not cards:
            return Response({"error": "Hech qanday karta topilmadi."}, status=status.HTTP_404_NOT_FOUND)
        random_card = random.choice(cards)
        serializer = self.get_serializer(random_card)
        return Response(serializer.data)


class UserAdminViewSet(viewsets.ModelViewSet):
    """
    Admin uchun foydalanuvchilarni boshqarish (CRUD).
    """
    queryset = User.objects.all().order_by('full_name')
    serializer_class = UserSerializer # O'qish uchun UserSerializer
    permission_classes = [IsAdminUser] # Faqat Admin

    def get_serializer_class(self):
        # Yaratish va yangilash uchun boshqa serializer ishlatish mumkin (masalan, parolni ham o'zgartirish uchun)
        if self.action in ['create', 'update', 'partial_update']:
            # Oddiy UserSerializer ni ishlatsak, parol o'zgarmaydi
            # Maxsus AdminUserUpdateSerializer yaratish kerak bo'lishi mumkin
             return UserSerializer # Hozircha shu
        return super().get_serializer_class()

    # Create, Update, Destroy metodlari standart ModelViewSet da mavjud
    # Zarur bo'lsa override qilish mumkin (masalan, parol o'rnatish uchun create da)

class AccountingServiceViewSet(viewsets.ModelViewSet):
    queryset = AccountingService.objects.all()
    serializer_class = AccountingServiceSerializer
    # permission_classes = [IsAdminUser]


class DashboardStatsView(views.APIView): # APIView dan meros olamiz
    """
    Foydalanuvchi roli asosida dashboard uchun statistikani qaytaradi.
    """
    permission_classes = [IsAuthenticated] # Faqat login qilganlar ko'ra oladi

    def get(self, request, *args, **kwargs):
        user = request.user
        thirty_days_ago = timezone.now() - timedelta(days=30)

        # --- Hisobotlarni (Buyurtmalarni) rolga qarab filterlash ---
        base_report_queryset = Report.objects.none() # Boshlang'ich bo'sh queryset
        if user.role == 'mijoz':
            base_report_queryset = Report.objects.filter(client=user)
        elif user.role == 'buxgalter':
            base_report_queryset = Report.objects.filter(accountant=user)
        elif user.role == 'admin':
            base_report_queryset = Report.objects.all() # Admin hamma hisobotni ko'radi

        # --- Statistikani hisoblash ---

        # 1. Faol buyurtmalar (Report statuslari: 'in_progress', 'in_review')
        # Rasmda "Jarayonda" va "Kutilmoqda" bor. Modellardagi 'in_progress' va 'in_review' ga mos keladi deb taxmin qilamiz.
        faol_statuslar = ['in_progress', 'in_review']
        faol_buyurtmalar_soni = base_report_queryset.filter(status__in=faol_statuslar).count()
        faol_buyurtmalar_oxirgi_30_kun = base_report_queryset.filter(
            status__in=faol_statuslar,
            updated_at__gte=thirty_days_ago # Status oxirgi marta shu vaqtda o'zgarganlar
        ).count()

        # 2. Jami tayyor hisobotlar (Report statusi: 'approved')
        # Rasmda "Tugallangan" bor, modelda 'approved' ga mos keladi.
        tayyor_status = 'approved'
        jami_tayyor_hisobotlar_soni = base_report_queryset.filter(status=tayyor_status).count()
        tayyor_hisobotlar_oxirgi_30_kun = base_report_queryset.filter(
            status=tayyor_status,
            updated_at__gte=thirty_days_ago # Tasdiqlangan sana (updated_at orqali)
        ).count()

        # 3. O'qilmagan xabarlar (Message modeli)
        unread_messages_qs = Message.objects.filter(recipient=user, read=False)
        oqilmagan_xabarlar_soni = unread_messages_qs.count()

        # "N ta buxgalterdan" ma'lumotini olish (hozircha oddiyroq)
        # Agar admin bo'lmasa, faqat buxgalterlardan kelgan xabarlarni sanash mumkin
        oqilmagan_xabarlar_info = ""
        if oqilmagan_xabarlar_soni > 0:
            senders_count = unread_messages_qs.values('sender__role').annotate(count=Count('sender')).order_by()
            sender_info_parts = []
            for item in senders_count:
                # Rol nomini olish (agar kerak bo'lsa)
                # role_display = dict(User.ROLE_CHOICES).get(item['sender__role'], item['sender__role'])
                # sender_info_parts.append(f"{item['count']} ta {role_display}")

                # Rasmga yaqinroq qilish uchun:
                if item['sender__role'] == 'buxgalter':
                    sender_info_parts.append(f"{item['count']} ta buxgalterdan")
                elif item['sender__role'] == 'admin':
                    sender_info_parts.append(f"{item['count']} ta admindan")
                elif item['sender__role'] == 'mijoz':
                    sender_info_parts.append(f"{item['count']} ta mijozdan")
            oqilmagan_xabarlar_info = ", ".join(sender_info_parts) if sender_info_parts else ""


        # 4. Balans
        # Sizning kodingizda balans uchun alohida model/maydon ko'rinmayapti.
        # Hozircha rasmda ko'rsatilgan statik qiymatni qaytaramiz.
        # Haqiqiy implementatsiya uchun User modelini kengaytirish yoki UserProfile yaratish kerak.
        balans = Decimal('120000.00') # Rasmdeki qiymat, Decimal sifatida

        # --- Ma'lumotlarni tayyorlash ---
        data = {
            'faol_buyurtmalar_soni': faol_buyurtmalar_soni,
            'jami_tayyor_hisobotlar_soni': jami_tayyor_hisobotlar_soni,
            'oqilmagan_xabarlar_soni': oqilmagan_xabarlar_soni,
            'balans': balans,
            'faol_buyurtmalar_oxirgi_30_kun': faol_buyurtmalar_oxirgi_30_kun, # Frontend buni "+N" qilib ko'rsatadi
            'tayyor_hisobotlar_oxirgi_30_kun': tayyor_hisobotlar_oxirgi_30_kun, # Frontend buni "+N" qilib ko'rsatadi
            'oqilmagan_xabarlar_info': oqilmagan_xabarlar_info,
        }

        # Serializer orqali javobni formatlash
        serializer = DashboardStatsSerializer(data=data)
        serializer.is_valid(raise_exception=True) # Validatsiya

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


# --- Mavjud UserAdminViewSet ni YANGILASH ---
class UserAdminViewSet(viewsets.ModelViewSet):
    """
    Admin uchun foydalanuvchilarni boshqarish (CRUD, Tasdiqlash/Rad etish).
    """
    queryset = User.objects.all().order_by('-date_joined') # Yangi qo'shilganlar tepada
    permission_classes = [IsAdminUser] # Faqat Admin

    # Filter va Search backendlarini qo'shish
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_class = UserFilter # Filterlash uchun klass
    search_fields = ['full_name', 'email'] # Qidirish uchun maydonlar (?search=...)

    def get_serializer_class(self):
        # Ro'yxatni ko'rish uchun maxsus serializer
        if self.action == 'list':
            return AdminUserListSerializer
        # Boshqa actionlar (retrieve, create, update) uchun standart UserSerializer (yoki kerak bo'lsa boshqasi)
        # Masalan, yaratishda SignupSerializer dan foydalanish mumkin
        # if self.action == 'create':
        #     return SignupSerializer # Admin ham shu orqali yaratishi mumkin
        elif self.action in ['update', 'partial_update']:
             return UserUpdateSerializer # Profilni tahrirlash uchun
        return UserSerializer # Default (retrieve, create)

    # --- Foydalanuvchini TASDIQLASH uchun custom action ---
    @action(detail=True, methods=['post'], url_path='approve')
    def approve_user(self, request, pk=None):
        """
        Foydalanuvchini tasdiqlaydi (is_active=True qiladi).
        """
        user = self.get_object() # Foydalanuvchini olish (pk orqali)
        if not user.is_active:
            user.is_active = True
            user.save(update_fields=['is_active'])
            # Bildirishnoma yuborish (ixtiyoriy)
            # send_mail(...)
            serializer = AdminUserListSerializer(user, context={'request': request}) # Yangilangan ma'lumotni qaytarish
            return Response({"message": "Foydalanuvchi muvaffaqiyatli tasdiqlandi.", "user": serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Foydalanuvchi allaqachon faol."}, status=status.HTTP_400_BAD_REQUEST)

    # --- Foydalanuvchini RAD ETISH/DEAKTIVLASHTIRISH uchun custom action ---
    @action(detail=True, methods=['post'], url_path='reject')
    def reject_user(self, request, pk=None):
        """
        Foydalanuvchini rad etadi (is_active=False qiladi).
        Bu aslida deaktivatsiya. Agar butunlay o'chirish kerak bo'lsa, DELETE ishlatiladi.
        """
        user = self.get_object()
        if user.is_active:
            user.is_active = False
            user.save(update_fields=['is_active'])
            # Bildirishnoma yuborish (ixtiyoriy)
            serializer = AdminUserListSerializer(user, context={'request': request})
            return Response({"message": "Foydalanuvchi muvaffaqiyatli deaktiv qilindi.", "user": serializer.data}, status=status.HTTP_200_OK)
        else:
            # Agar allaqachon nofaol bo'lsa, balki xato qaytarish kerak emasdir
             serializer = AdminUserListSerializer(user, context={'request': request})
             return Response({"message": "Foydalanuvchi allaqachon nofaol edi.", "user": serializer.data}, status=status.HTTP_200_OK)
            # Yoki: return Response({"message": "Foydalanuvchi allaqachon nofaol."}, status=status.HTTP_400_BAD_REQUEST)

    # perform_destroy (DELETE) metodi ModelViewSet da mavjud. Agar "Rad etish" o'chirish bo'lsa,
    # frontend DELETE so'rovini yuborishi kerak. Agar deaktivatsiya bo'lsa, reject_user ishlaydi.


# --- YANGI Statistika View ---
class UserManagementStatsView(views.APIView):
    """
    Foydalanuvchilarni boshqarish sahifasi uchun statistikani qaytaradi.
    """
    permission_classes = [IsAdminUser] # Faqat Admin

    def get(self, request, *args, **kwargs):
        # Barcha aktiv foydalanuvchilar sonini rol bo'yicha hisoblash
        active_users_by_role = User.objects.filter(is_active=True)\
                                     .values('role')\
                                     .annotate(count=Count('id'))\
                                     .order_by('role')

        mijozlar_soni = 0
        buxgalterlar_soni = 0
        for item in active_users_by_role:
            if item['role'] == 'mijoz':
                mijozlar_soni = item['count']
            elif item['role'] == 'buxgalter':
                buxgalterlar_soni = item['count']
            # Agar boshqa aktiv rollar bo'lsa, ularni ham hisoblash mumkin

        # Yangi (tasdiqlanmagan) foydalanuvchilar soni
        yangi_foydalanuvchilar_soni = User.objects.filter(is_active=False).count()

        data = {
            'mijozlar_soni': mijozlar_soni,
            'buxgalterlar_soni': buxgalterlar_soni,
            'yangi_foydalanuvchilar_soni': yangi_foydalanuvchilar_soni,
        }

        serializer = UserManagementStatsSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class PaymentViewSet(viewsets.ModelViewSet): # CRUD uchun ModelViewSet
    """
    To'lovlarni ko'rish va boshqarish uchun API endpoint.
    """
    serializer_class = PaymentSerializer
    permission_classes = [IsAuthenticated] # Asosiy ruxsatnoma
    filter_backends = [DjangoFilterBackend, filters.SearchFilter] # Filter va Search
    filterset_class = PaymentModelFilter # Yangi filter
    search_fields = [ # Qidirish uchun
        'client__full_name', 'client__email',
        'accountant__full_name', 'accountant__email',
        'report__title', 'report__category__name',
        'transaction_id'
    ]
    # pagination_class = ... # Agar kerak bo'lsa

    def get_queryset(self):
        user = self.request.user
        if getattr(self, 'swagger_fake_view', False):
            return Payment.objects.none()

        if user.role == 'admin':
            return Payment.objects.select_related('client', 'accountant', 'report', 'report__category').all()
        elif user.role == 'buxgalter':
            # Buxgalter o'zi qabul qilgan yoki o'ziga tegishli hisobotlar uchun qilingan to'lovlar
            return Payment.objects.filter(
                Q(accountant=user) | Q(report__accountant=user)
            ).select_related('client', 'accountant', 'report', 'report__category').distinct()
        elif user.role == 'mijoz':
            # Mijoz faqat o'zi qilgan to'lovlarni ko'radi
             return Payment.objects.filter(client=user).select_related('client', 'accountant', 'report', 'report__category')
        else:
            return Payment.objects.none()

    def get_permissions(self):
        # Qo'lda to'lov yaratish/o'zgartirish/o'chirish faqat Admin uchun (hozircha)
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAdminUser()]
        # Ro'yxatni ko'rish hamma (login qilgan) uchun (get_queryset filterlaydi)
        return [IsAuthenticated()]

    # perform_create, perform_update ni override qilish mumkin (agar maxsus logika kerak bo'lsa)


# --- O'ZGARTIRILGAN IncomeSummaryDynamicsView ---
class IncomeSummaryDynamicsView(views.APIView):
    """
    Daromadlar sahifasi uchun umumiy statistika va oylik dinamikani
    YANGI Payment modelidan oladi.
    """
    permission_classes = [IsAuthenticated] # Yoki IsAdminUser, IsAccountantUser

    def get(self, request, *args, **kwargs):
        user = request.user
        now = timezone.now()
        # --- Sana hisob-kitoblari (o'zgarmaydi) ---
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        prev_month_start = current_month_start - relativedelta(months=1)
        prev_month_end = current_month_start - relativedelta(microseconds=1)
        current_year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        prev_year_start = current_year_start - relativedelta(years=1)
        prev_year_end = current_year_start - relativedelta(microseconds=1)

        # --- Rolga qarab asosiy Payment queryset ---
        base_payment_qs = Payment.objects.none()
        if user.role == 'admin':
            base_payment_qs = Payment.objects.all()
        elif user.role == 'buxgalter':
            # Buxgalter qabul qilgan yoki unga tegishli hisobotlar uchun to'lovlar
            base_payment_qs = Payment.objects.filter(
                Q(accountant=user) | Q(report__accountant=user)
            ).distinct()
        elif user.role == 'mijoz':
             raise PermissionDenied("Mijozlar uchun bu sahifa mavjud emas.")
        else:
             raise PermissionDenied("Noma'lum rol.")

        # --- Statistikani YANGI Payment modelidan hisoblash ---
        # Faqat 'completed' statusdagilar haqiqiy daromad
        completed_qs = base_payment_qs.filter(status='completed')

        # 1. Oylik daromad
        current_month_income = completed_qs.filter(
            payment_date__gte=current_month_start
        ).aggregate(
            total=Coalesce(Sum('amount'), Decimal(0), output_field=DecimalField())
        )['total']

        prev_month_income = completed_qs.filter(
            payment_date__range=(prev_month_start, prev_month_end)
        ).aggregate(
            total=Coalesce(Sum('amount'), Decimal(0), output_field=DecimalField())
        )['total']

        oylik_foiz_ozgarish = 0.0
        if prev_month_income > 0:
            oylik_foiz_ozgarish = float(((current_month_income - prev_month_income) / prev_month_income) * 100)

        # 2. Yillik daromad
        current_year_income = completed_qs.filter(
            payment_date__gte=current_year_start
        ).aggregate(
            total=Coalesce(Sum('amount'), Decimal(0), output_field=DecimalField())
        )['total']

        prev_year_income = completed_qs.filter(
            payment_date__range=(prev_year_start, prev_year_end)
        ).aggregate(
            total=Coalesce(Sum('amount'), Decimal(0), output_field=DecimalField())
        )['total']

        yillik_foiz_ozgarish = 0.0
        if prev_year_income > 0:
            yillik_foiz_ozgarish = float(((current_year_income - prev_year_income) / prev_year_income) * 100)

        # 3. Kutilayotgan daromad (Endi 'pending' statusdagi Paymentlardan)
        pending_qs = base_payment_qs.filter(status='pending')
        pending_aggregation = pending_qs.aggregate(
            total_sum=Coalesce(Sum('amount'), Decimal(0), output_field=DecimalField()),
            total_count=Count('id')
        )
        kutilayotgan_daromad_summa = pending_aggregation['total_sum']
        kutilayotgan_daromad_soni = pending_aggregation['total_count']

        # --- Daromad Dinamikasi ('completed' Paymentlardan) ---
        monthly_income_data = completed_qs.filter(
            payment_date__gte=current_year_start
        ).annotate(
            month=TruncMonth('payment_date')
        ).values('month').annotate(
            monthly_total=Sum('amount')
        ).order_by('month')

        # Dinamikani formatlash (o'zgarmaydi)
        oy_nomlari_uz = {1: 'Yan', 2: 'Fev', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Iyun', 7: 'Iyul', 8: 'Avg', 9: 'Sen', 10: 'Okt', 11: 'Noy', 12: 'Dek'}
        dynamics_data = {oy_nomlari_uz[i]: Decimal(0) for i in range(1, 13)}
        for item in monthly_income_data:
            month_num = item['month'].month
            if month_num in oy_nomlari_uz:
                dynamics_data[oy_nomlari_uz[month_num]] = item['monthly_total'] or Decimal(0)

        # --- Javobni tayyorlash (o'zgarmaydi) ---
        stats_data = {
            'oylik_daromad': current_month_income,
            'oylik_foiz_ozgarish': round(oylik_foiz_ozgarish, 2),
            'yillik_daromad': current_year_income,
            'yillik_foiz_ozgarish': round(yillik_foiz_ozgarish, 2),
            'kutilayotgan_daromad_summa': kutilayotgan_daromad_summa,
            'kutilayotgan_daromad_soni': kutilayotgan_daromad_soni,
        }
        stats_serializer = IncomeStatsSerializer(data=stats_data)
        stats_serializer.is_valid(raise_exception=True)

        dynamics_list_data = [{'month': k, 'amount': v} for k, v in dynamics_data.items()]

        return Response({
            "statistics": stats_serializer.validated_data,
            "dynamics": dynamics_list_data
        }, status=status.HTTP_200_OK)


# --- YANGI To'lovlar Tarixi ViewSet ---
# class PaymentHistoryViewSet(viewsets.ReadOnlyModelViewSet):
#     """
#     To'lovlar tarixini ko'rsatish uchun ViewSet (Report modeliga asoslangan).
#     Filterlash: ?status=completed yoki ?status=pending
#     """
#     serializer_class = PaymentHistorySerializer
#     permission_classes = [IsAuthenticated] # Yoki IsAdminUser, IsAccountantUser
#     filter_backends = [DjangoFilterBackend]
#     filterset_class = PaymentFilter # Yuqorida yaratilgan filter
#     # Pagination DRF sozlamalaridan keladi (agar sozlanmagan bo'lsa, qo'shish kerak)
#     # pagination_class = StandardResultsSetPagination # Masalan

#     def get_queryset(self):
#         user = self.request.user
#         # --- Swagger schema generation uchun tekshiruv ---
#         if getattr(self, 'swagger_fake_view', False):
#             return Report.objects.none()

#         # Rolga qarab asosiy querysetni aniqlash
#         if user.role == 'admin':
#             # Admin barcha 'to'lov'larni ko'radi (tasdiqlangan va kutilayotgan)
#             # Filter class statuslarni to'g'ri filterlaydi
#             return Report.objects.select_related('client', 'category').all().order_by('-created_at')
#         elif user.role == 'buxgalter':
#             # Buxgalter o'ziga tegishli (tayinlangan) hisobotlarga aloqador to'lovlarni ko'radi
#              return Report.objects.filter(accountant=user).select_related('client', 'category').order_by('-created_at')
#         elif user.role == 'mijoz':
#              # Mijoz bu yerga kira olmasligi kerak (yuqoridagi viewda tekshirilgan)
#              # Agar kerak bo'lsa, o'z hisobotlarini ko'rishi mumkin:
#              # return Report.objects.filter(client=user).select_related('client', 'category').order_by('-created_at')
#              return Report.objects.none() # Mijoz uchun bo'sh qaytarish
#         else:
#              return Report.objects.none() # Boshqa rollar uchun bo'sh
