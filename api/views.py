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
from rest_framework import generics, status, viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny, IsAuthenticated # IsAdminUser o'rniga custom
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import PermissionDenied, NotFound # Qo'shildi

# Serializerlarni va Modellarni import qilish
from .serializers import *
from .models import *
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