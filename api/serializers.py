from decimal import Decimal

from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import * # Barcha modellarni import qilish
from django.utils.formats import date_format

User = get_user_model()

# --- Mavjud Serializerlar (Signup, Token, LoginResponse, User, UserUpdate, PasswordReset, AboutUs, PasswordChange) ---
# ... (bu qismlar deyarli o'zgarishsiz qoladi, faqat UserSerializerda role ko'rsatilganiga ishonch hosil qiling)

class SignupSerializer(serializers.ModelSerializer):
    # ... (mavjud kod)
    experience = serializers.IntegerField(required=False, allow_null=True, write_only=True) # write_only qo'shildi
    specialty = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True, write_only=True)
    address = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True, write_only=True)
    skills = serializers.CharField(required=False, allow_blank=True, allow_null=True, write_only=True)
    languages = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True, write_only=True)
    bio = serializers.CharField(required=False, allow_blank=True, allow_null=True, write_only=True)
    certifications = serializers.CharField(required=False, allow_blank=True, allow_null=True, write_only=True)
    fee = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, default=0, write_only=True)


    class Meta:
        model = User
        fields = [
            'id', 'full_name', 'email', 'phone_number', 'password', 'role', 'img', # read_only uchun id, img qo'shildi
            'company_name', 'stir',  # Mijoz uchun
            # Buxgalter uchun alohida serializer orqali emas, shu yerda write_only sifatida qabul qilinadi
            'experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'role': {'read_only': False}, # Ro'yxatdan o'tishda rol tanlanishi mumkin
             # write_only bo'lmaganlar GET so'rovlarda ko'rinadi
            'img': {'read_only': True}, # Ro'yxatdan o'tishda rasm yuklanmaydi
            'company_name': {'required': False, 'allow_blank': True, 'allow_null': True},
            'stir': {'required': False, 'allow_blank': True, 'allow_null': True},
        }
        read_only_fields = ['id']


    def validate(self, data):
        role = data.get('role', 'mijoz') # Default 'mijoz'
        if role == 'mijoz':
            required_fields = ['company_name', 'stir']
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                 # Mijoz ro'yxatdan o'tayotganda bu maydonlar majburiy emas
                 pass # raise serializers.ValidationError({field: f"{field} mijoz uchun majburiy." for field in missing_fields})
            # Buxgalter maydonlarini tozalash (agar kiritilgan bo'lsa)
            for field in ['experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee']:
                data.pop(field, None)
        elif role == 'buxgalter':
            required_fields = ['experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'fee', 'certifications']
            missing_fields = [field for field in required_fields if data.get(field) is None or data.get(field) == '']
            if missing_fields:
                raise serializers.ValidationError({field: f"{field} buxgalter uchun majburiy." for field in missing_fields})
            # Mijoz maydonlarini tozalash
            for field in ['company_name', 'stir']:
                data.pop(field, None)
        elif role == 'admin':
             for field in ['company_name', 'stir', 'experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee']:
                data.pop(field, None)
        else:
             raise serializers.ValidationError({"role": "Noto'g'ri rol tanlandi."})

        # Telefon raqam va email unikaligini tekshirish (modelda bor, lekin serializerda ham bo'lishi mumkin)
        if User.objects.filter(email=data['email']).exists():
             raise serializers.ValidationError({"email": "Bu email allaqachon mavjud."})
        if User.objects.filter(phone_number=data['phone_number']).exists():
            raise serializers.ValidationError({"phone_number": "Bu telefon raqami allaqachon mavjud."})

        return data

    def create(self, validated_data):
        accountant_fields = ['experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee']
        accountant_data = {field: validated_data.pop(field) for field in accountant_fields if field in validated_data}

        user = User.objects.create_user(**validated_data)

        if user.role == 'buxgalter' and accountant_data:
            # Fee Decimal turiga o'tkazish
            accountant_data['fee'] = Decimal(accountant_data.get('fee', 0))
            Accountant.objects.create(user=user, **accountant_data)
        elif user.role == 'buxgalter' and not accountant_data:
             # Agar buxgalter tanlansa lekin ma'lumotlar kelmasa, xatolik berish yoki default yaratish
             # Hozircha xatolik bermaymiz, lekin Accountant profili bo'sh bo'ladi
             Accountant.objects.create(user=user) # Minimal profil yaratish

        return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['full_name'] = user.full_name # Qo'shimcha ma'lumot
        return token

class LoginResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    access = serializers.CharField()
    refresh = serializers.CharField()
    role = serializers.CharField()
    full_name = serializers.CharField()

class UserSerializer(serializers.ModelSerializer):
    # Buxgalter profilini ko'rsatish (agar mavjud bo'lsa)
    accountant_profile = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'phone_number', 'role', 'img', 'company_name', 'stir', 'accountant_profile', 'is_active', 'is_staff']
        read_only_fields = ['id', 'email', 'role', 'accountant_profile', 'is_active', 'is_staff'] # O'zgartirib bo'lmaydiganlar

    def get_accountant_profile(self, obj):
        if obj.role == 'buxgalter':
            try:
                # AccountantSerializer ni chaqirish (pastda define qilinadi)
                return AccountantSerializer(obj.accountant_profile, context=self.context).data
            except Accountant.DoesNotExist:
                return None
        return None


class UserUpdateSerializer(serializers.ModelSerializer):
    # Buxgalter profilini ham yangilash uchun
    experience = serializers.IntegerField(source='accountant_profile.experience', required=False, allow_null=True)
    specialty = serializers.CharField(source='accountant_profile.specialty', max_length=100, required=False, allow_blank=True, allow_null=True)
    address = serializers.CharField(source='accountant_profile.address', max_length=255, required=False, allow_blank=True, allow_null=True)
    skills = serializers.CharField(source='accountant_profile.skills', required=False, allow_blank=True, allow_null=True)
    languages = serializers.CharField(source='accountant_profile.languages', max_length=255, required=False, allow_blank=True, allow_null=True)
    bio = serializers.CharField(source='accountant_profile.bio', required=False, allow_blank=True, allow_null=True)
    certifications = serializers.CharField(source='accountant_profile.certifications', required=False, allow_blank=True, allow_null=True)
    fee = serializers.DecimalField(source='accountant_profile.fee', max_digits=10, decimal_places=2, required=False)


    class Meta:
        model = User
        fields = [
            'full_name', 'phone_number', 'img', # Umumiy
            'company_name', 'stir', # Mijoz uchun
            # Buxgalter uchun (source orqali bog'langan)
            'experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee'
        ]
        extra_kwargs = {
            'full_name': {'required': False},
            'phone_number': {'required': False},
            'img': {'required': False, 'allow_null': True},
            'company_name': {'required': False, 'allow_blank': True, 'allow_null': True},
            'stir': {'required': False, 'allow_blank': True, 'allow_null': True},
            # Buxgalter maydonlari ham ixtiyoriy
        }

    def validate_phone_number(self, value):
        user = self.context['request'].user
        if User.objects.filter(phone_number=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("Bu telefon raqami boshqa foydalanuvchi tomonidan ishlatilmoqda.")
        return value

    def update(self, instance, validated_data):
        # Accountant ma'lumotlarini ajratib olish
        accountant_data = {}
        accountant_profile_fields = ['experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee']

        # Pop accountant fields from validated_data if they exist
        profile_data_from_payload = validated_data.pop('accountant_profile', {})

        # Update instance fields (User model)
        instance.full_name = validated_data.get('full_name', instance.full_name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.img = validated_data.get('img', instance.img)

        if instance.role == 'mijoz':
            instance.company_name = validated_data.get('company_name', instance.company_name)
            instance.stir = validated_data.get('stir', instance.stir)
        elif instance.role == 'buxgalter':
            # Get or create accountant profile
            accountant_profile, created = Accountant.objects.get_or_create(user=instance)
            # Update accountant profile fields
            for field in accountant_profile_fields:
                 if field in profile_data_from_payload: # Use popped data
                    setattr(accountant_profile, field, profile_data_from_payload[field])
            accountant_profile.save()

        instance.save()
        return instance


class PasswordResetRequestSerializer(serializers.Serializer):
    # ... (mavjud kod)
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Bunday email ro'yxatdan o'tmagan.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    # ... (mavjud kod)
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uidb64']))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError): # OverflowError qo'shildi
            raise serializers.ValidationError("Noto'g'ri havola yoki token.")

        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError("Token noto‘g‘ri yoki eskirgan.")

        attrs['user'] = user
        return attrs

class AboutUsSerializer(serializers.ModelSerializer):
    # ... (mavjud kod)
     class Meta:
        model = AboutUs
        fields = ['id', 'img', 'title', 'text']


class PasswordChangeSerializer(serializers.Serializer):
    # ... (mavjud kod)
    old_password = serializers.CharField(write_only=True, min_length=6)
    new_password = serializers.CharField(write_only=True, min_length=6)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Joriy parol noto‘g‘ri.")
        return value

# --- Yangi va Yangilangan Serializerlar ---

class ReportTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportType
        fields = ['id', 'name', 'description', 'price']

class AccountantSerializer(serializers.ModelSerializer):
    # User ma'lumotlarini o'qish uchun UserSerializer ishlatamiz
    # UserSerializerda 'accountant_profile' ni olib tashlash kerak rekursiyani oldini olish uchun
    user = serializers.SerializerMethodField(read_only=True) # UserSerializer(read_only=True) o'rniga
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='buxgalter'), # Faqat buxgalterlarni tanlash
        write_only=True,
        source='user', # Bu user maydoniga yozadi
        required=False # Chunki UserUpdateSerializer da ham ishlatiladi
    )
    fee = serializers.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        model = Accountant
        fields = [
            'id', 'user', 'user_id', # user_id faqat yozish uchun
            'certifications', 'fee', 'experience', 'specialty',
            'address', 'skills', 'languages', 'bio'
        ]
        read_only_fields = ['id', 'user']

    def get_user(self, obj):
        # Rekursiyani oldini olish uchun UserSerializer ning minimal variantini qaytaramiz
        user = obj.user
        return {
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone_number': user.phone_number,
            'role': user.role,
            'img': user.img.url if user.img else None
        }


    # Bu validatsiya endi SignupSerializer ichida bajariladi
    # def validate_user_id(self, value):
    #     if Accountant.objects.filter(user=value).exists():
    #         raise serializers.ValidationError("Bu foydalanuvchi allaqachon buxgalter sifatida ro'yxatdan o'tgan.")
    #     if value.role != 'buxgalter':
    #         raise serializers.ValidationError("Faqat 'buxgalter' roli bo'lgan foydalanuvchilar Accountant sifatida qo'shilishi mumkin.")
    #     return value

class MiniUserSerializer(serializers.ModelSerializer):
     """Faqat asosiy ma'lumotlarni ko'rsatish uchun"""
     class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'role']


class AttachmentSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField(read_only=True)
    uploaded_by = MiniUserSerializer(read_only=True)
    file = serializers.FileField(write_only=True, required=True) # Yuklash uchun
    # report maydoni nested routerdan keladi, serializerda alohida ko'rsatmaymiz
    # report = serializers.PrimaryKeyRelatedField(...)

    class Meta:
        model = Attachment
        fields = [
            'id', 'file', 'file_name', 'file_size', # 'report' olib tashlandi
            'file_type', 'uploaded_by', 'uploaded_at', 'file_url'
        ]
        # 'report' endi read_only emas
        read_only_fields = ['id', 'file_name', 'file_size', 'file_type', 'uploaded_by', 'uploaded_at', 'file_url']
        # extra_kwargs dan 'report' ni olib tashlaymiz, chunki u fields da yo'q
        # extra_kwargs = {
        #      'report': {'write_only': True, 'required': False},
        # }

    def get_file_url(self, obj):
        request = self.context.get('request')
        return obj.get_file_url(request=request)

    # create metodida report viewsetdan olinadi, validated_data da bo'lmaydi
    # def create(self, validated_data):
    #      return super().create(validated_data)



class ReportCommentSerializer(serializers.ModelSerializer):
    author = MiniUserSerializer(read_only=True)
    user_type = serializers.CharField(source='author.role', read_only=True)
    # report maydoni nested routerdan keladi
    # report = serializers.PrimaryKeyRelatedField(...)

    class Meta:
        model = ReportComment
        fields = ['id', 'author', 'user_type', 'comment', 'created_at']
        # 'report' endi read_only emas
        read_only_fields = ['id', 'author', 'user_type', 'created_at']
        # extra_kwargs dan 'report' ni olib tashlaymiz
        # extra_kwargs = {
        #     'report': {'write_only': True, 'required': False},
        #     'comment': {'required': True}
        # }
        extra_kwargs = { # Faqat comment qoladi
             'comment': {'required': True}
        }

    # create metodida report viewsetdan olinadi
    # def create(self, validated_data):
    #     return super().create(validated_data)

# Report uchun serializer TZ ga moslashtiriladi
class ReportSerializer(serializers.ModelSerializer):
    # Bog'liq modellarni ko'rsatish uchun nested serializerlar
    client = MiniUserSerializer(read_only=True)
    accountant = MiniUserSerializer(read_only=True, allow_null=True) # Null bo'lishi mumkin
    category = ReportTypeSerializer(read_only=True, allow_null=True) # Kategoriya obyekti
    comments = ReportCommentSerializer(many=True, read_only=True) # Read only
    attachments = AttachmentSerializer(many=True, read_only=True) # Read only

    # Yozish uchun (Create/Update)
    client_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='mijoz'),
        source='client', write_only=True, required=False # Avtomatik o'rnatiladi
    )
    accountant_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='buxgalter'),
        source='accountant', write_only=True, required=False, allow_null=True # Admin tayinlaydi
    )
    category_id = serializers.PrimaryKeyRelatedField(
        queryset=ReportType.objects.all(),
        source='category', write_only=True, required=False, allow_null=True # Ixtiyoriy bo'lishi mumkin
    )
    # Period alohida maydonlar sifatida
    period = serializers.SerializerMethodField(read_only=True) # O'qish uchun

    class Meta:
        model = Report
        fields = [
            'id', 'title', 'description', 'client', 'client_id', 'accountant', 'accountant_id',
            'status', 'created_at', 'updated_at', 'submitted_at',
            'category', 'category_id', 'period', 'start_date', 'end_date', # period alohida
            'comments', 'attachments'
        ]
        read_only_fields = [
            'id', 'client', 'accountant', 'status', # Status alohida action bilan o'zgartiriladi
            'created_at', 'updated_at', 'submitted_at',
            'category', 'period', 'comments', 'attachments'
        ]
        # Yozish mumkin bo'lganlar (Create/Update)
        extra_kwargs = {
            'title': {'required': True},
            'description': {'required': False},
            'start_date': {'write_only': True, 'required': False, 'allow_null': True},
            'end_date': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_period(self, obj):
        if obj.start_date or obj.end_date:
            return {
                'startDate': obj.start_date,
                'endDate': obj.end_date
            }
        return None

    def validate(self, data):
        # Start date <= End date tekshiruvi
        start_date = data.get('start_date', getattr(self.instance, 'start_date', None))
        end_date = data.get('end_date', getattr(self.instance, 'end_date', None))
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError("Boshlanish sanasi tugash sanasidan keyin bo'lishi mumkin emas.")

        # Status validatsiyasi (agar statusni shu serializerda o'zgartirishga ruxsat berilsa)
        # Lekin statusni alohida action bilan o'zgartirgan ma'qul

        return data

    def create(self, validated_data):
        # client avtomatik o'rnatiladi (viewda)
        validated_data['client'] = self.context['request'].user
        # Boshlang'ich status 'draft'
        validated_data['status'] = 'draft'
        return super().create(validated_data)


# Task uchun serializer

class TaskSerializer(serializers.ModelSerializer):
    accountant = MiniUserSerializer(read_only=True)
    client = MiniUserSerializer(read_only=True, allow_null=True)
    report = serializers.PrimaryKeyRelatedField(read_only=True, allow_null=True) # Faqat ID sini ko'rsatamiz

    # Yozish uchun
    accountant_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='buxgalter'),
        source='accountant', write_only=True, required=True
    )
    client_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='mijoz'),
        source='client', write_only=True, required=False, allow_null=True # Reportdan olinishi mumkin
    )
    report_id = serializers.PrimaryKeyRelatedField(
        queryset=Report.objects.all(),
        source='report', write_only=True, required=False, allow_null=True # Ixtiyoriy
    )

    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'accountant', 'accountant_id', 'client', 'client_id',
            'report', 'report_id', 'status', 'priority', 'due_date',
            'created_at', 'updated_at', 'completed_at'
        ]
        read_only_fields = [
            'id', 'accountant', 'client', 'report', # Obyektlarni ko'rsatish
            'status', # Alohida action bilan o'zgartiriladi
            'created_at', 'updated_at', 'completed_at'
        ]
        extra_kwargs = {
             'title': {'required': True},
             'description': {'required': False},
             'priority': {'required': False}, # Default 'medium'
             'due_date': {'required': False, 'allow_null': True},
        }

    def validate(self, data):
         # Agar report_id berilgan bo'lsa, accountant_id reportning accountantiga mos kelishini tekshirish
         report = data.get('report')
         accountant = data.get('accountant') # Bu source='accountant' orqali keladi
         if report and report.accountant and accountant != report.accountant:
             # Agar reportga buxgalter tayinlangan bo'lsa, task ham shu buxgalterga bo'lishi kerak
             # Yoki admin yaratayotgan bo'lsa, istalgan buxgalterni tanlashi mumkin
             user = self.context['request'].user
             if user.role != 'admin':
                 raise serializers.ValidationError({
                     "accountant_id": "Vazifa faqat hisobotga tayinlangan buxgalter uchun yaratilishi mumkin."
                 })

         # Agar report_id berilgan bo'lsa va client_id berilmagan bo'lsa, reportning clientini olish
         if report and not data.get('client'):
             data['client'] = report.client

         # Agar client_id berilgan bo'lsa, u reportning clientiga mos kelishini tekshirish
         client = data.get('client')
         if report and client and report.client != client:
              raise serializers.ValidationError({
                  "client_id": "Vazifadagi mijoz hisobotdagi mijozga mos kelmadi."
              })

         return data

    def create(self, validated_data):
         # Boshlang'ich status 'pending'
         validated_data['status'] = 'pending'
         # Agar report berilgan bo'lsa va accountant belgilanmagan bo'lsa (admin yaratayotganda)
         # report.accountant ni olish kerak (lekin validatsiyada tekshirdik)
         return super().create(validated_data)


# --- Mavjud Message va PaymentCard Serializerlar ---
class MessageSerializer(serializers.ModelSerializer):
    # ... (mavjud kod, o'zgartirishsiz ishlatish mumkin)
    from_user = serializers.SerializerMethodField()
    to_user = serializers.SerializerMethodField()
    sender = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), write_only=True, required=False)
    recipient = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=True)

    class Meta:
        model = Message
        fields = ['id', 'sender', 'from_user', 'recipient', 'to_user', 'message', 'read', 'created_at']
        read_only_fields = ['id', 'created_at', 'from_user', 'to_user']

    def get_from_user(self, obj):
        return MiniUserSerializer(obj.sender).data # Minimal ma'lumot

    def get_to_user(self, obj):
        return MiniUserSerializer(obj.recipient).data # Minimal ma'lumot

class ServiceItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceItem
        fields = ['id', 'name']

class AccountingServiceSerializer(serializers.ModelSerializer):
    items = ServiceItemSerializer(many=True, read_only=True)
    category = serializers.StringRelatedField()

    class Meta:
        model = AccountingService
        fields = ['id', 'title', 'slug', 'description', 'price', 'is_popular', 'category', 'items']


class PaymentCardSerializer(serializers.ModelSerializer):
    # ... (mavjud kod)
    class Meta:
        model = PaymentCard
        fields = '__all__'


class DashboardStatsSerializer(serializers.Serializer): # Nomini to'g'riladik
    """
    Foydalanuvchi dashboardi uchun statistik ma'lumotlar.
    """
    faol_buyurtmalar_soni = serializers.IntegerField()
    jami_tayyor_hisobotlar_soni = serializers.IntegerField()
    oqilmagan_xabarlar_soni = serializers.IntegerField()
    balans = serializers.DecimalField(max_digits=15, decimal_places=2) # Balans uchun DecimalField

    # Rasmga mos qo'shimcha ma'lumotlar
    faol_buyurtmalar_oxirgi_30_kun = serializers.IntegerField(required=False)
    tayyor_hisobotlar_oxirgi_30_kun = serializers.IntegerField(required=False)
    oqilmagan_xabarlar_info = serializers.CharField(required=False, allow_blank=True)

class AdminUserListSerializer(serializers.ModelSerializer):
    """
    Admin panelida foydalanuvchilar ro'yxatini ko'rsatish uchun serializer.
    """
    status_display = serializers.SerializerMethodField(read_only=True)
    date_joined_display = serializers.SerializerMethodField(read_only=True)
    # Agar rasmga o'xshatish kerak bo'lsa, image URL ni ham qo'shish mumkin
    img_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'full_name', 'email', 'role', 'img_url', # Asosiy ma'lumotlar
            'is_active', # Haqiqiy status
            'status_display', # Ko'rsatish uchun status ("Faol", "Kutilmoqda")
            'date_joined', # Original sana
            'date_joined_display' # Ko'rsatish uchun sana ("YYYY-MM-DD")
        ]
        read_only_fields = fields # Bu serializer faqat o'qish uchun

    def get_status_display(self, obj):
        # Rasmdagi statuslarga moslashtirish
        if obj.is_active:
            return "Faol" # Tasdiqlangan
        else:
            # Bu yerda "Faol emas" (rad etilgan) va "Kutilmoqda" (yangi) ni farqlash kerak bo'lishi mumkin
            # Hozircha faqat is_active ga qaraymiz
            return "Kutilmoqda" # Yoki "Faol emas"

    def get_date_joined_display(self, obj):
        # Sanani 'YYYY-MM-DD' formatida qaytarish
        return date_format(obj.date_joined, format='Y-m-d', use_l10n=False) # use_l10n=False muhim

    def get_img_url(self, obj):
        request = self.context.get('request')
        if obj.img and hasattr(obj.img, 'url'):
             if request:
                 return request.build_absolute_uri(obj.img.url)
             return obj.img.url
        return None # Rasm yo'q bo'lsa

class UserManagementStatsSerializer(serializers.Serializer):
    """
    Foydalanuvchilarni boshqarish sahifasi uchun statistika.
    """
    mijozlar_soni = serializers.IntegerField()
    buxgalterlar_soni = serializers.IntegerField()
    yangi_foydalanuvchilar_soni = serializers.IntegerField() # Tasdiqlashni kutayotganlar


class IncomeStatsSerializer(serializers.Serializer):
    """
    Daromadlar sahifasining yuqori qismi uchun statistika.
    """
    oylik_daromad = serializers.DecimalField(max_digits=15, decimal_places=2)
    oylik_foiz_ozgarish = serializers.FloatField() # Foiz o'zgarish
    yillik_daromad = serializers.DecimalField(max_digits=15, decimal_places=2)
    yillik_foiz_ozgarish = serializers.FloatField()
    kutilayotgan_daromad_summa = serializers.DecimalField(max_digits=15, decimal_places=2)
    kutilayotgan_daromad_soni = serializers.IntegerField()

# Dinamika uchun alohida serializer shart emas, viewda list/dict qaytarishimiz mumkin
class PaymentSerializer(serializers.ModelSerializer):
    """
    To'lovlar ro'yxati va detali uchun serializer.
    """
    client = MiniUserSerializer(read_only=True) # Mijoz ma'lumotlari
    accountant = MiniUserSerializer(read_only=True, allow_null=True) # Buxgalter ma'lumotlari
    report_title = serializers.CharField(source='report.title', read_only=True, default='N/A') # Hisobot nomi
    payment_date_display = serializers.SerializerMethodField(read_only=True) # Formatlangan sana
    status_display = serializers.CharField(source='get_status_display', read_only=True) # Status nomi
    # Jadval uchun "Xizmat turi" ni report.category.name dan olish
    xizmat_turi = serializers.CharField(source='report.category.name', read_only=True, default='Noma\'lum')

    # Agar Admin qo'lda Payment yaratishi/o'zgartirishi kerak bo'lsa:
    client_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(role='mijoz'), source='client', write_only=True, required=True)
    report_id = serializers.PrimaryKeyRelatedField(queryset=Report.objects.all(), source='report', write_only=True, required=False, allow_null=True)
    accountant_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(role='buxgalter'), source='accountant', write_only=True, required=False, allow_null=True)

    class Meta:
        model = Payment
        fields = [
            'id', 'client', 'client_id', 'accountant', 'accountant_id',
            'report', 'report_id', 'report_title', 'xizmat_turi', # report va xizmat turi qo'shildi
            'amount', 'status', 'status_display',
            'payment_date', 'payment_date_display',
            'payment_method', 'transaction_id',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'client', 'accountant', 'report_title', 'xizmat_turi',
            'status_display', 'payment_date_display', 'created_at', 'updated_at',
            'report' # Read-only qilsak, faqat ID ko'rinadi, bog'langan obyekt emas
        ]
        # Yaratish/O'zgartirish uchun kerakli maydonlar
        extra_kwargs = {
            'amount': {'required': True},
            'status': {'required': False}, # Default 'pending'
            'payment_date': {'required': False}, # Default timezone.now()
        }

    def get_payment_date_display(self, obj):
        # Sanani kerakli formatda qaytarish (vaqt bilan yoki vaqtsiz)
        return date_format(obj.payment_date, format='Y-m-d H:i', use_l10n=False)

# class PaymentHistorySerializer(serializers.ModelSerializer):
#     """
#     To'lovlar tarixi jadvali uchun serializer (Report modelidan olingan).
#     """
#     mijoz_nomi = serializers.CharField(source='client.full_name', read_only=True)
#     xizmat_turi = serializers.CharField(source='category.name', read_only=True, default='Noma\'lum') # Agar category null bo'lsa
#     sana = serializers.SerializerMethodField(read_only=True)
#     summa = serializers.DecimalField(source='category.price', max_digits=10, decimal_places=2, read_only=True, default=Decimal('0.00')) # Agar category null bo'lsa
#     status_display = serializers.SerializerMethodField(read_only=True)

#     class Meta:
#         model = Report # Asosiy model Report
#         fields = [
#             'id', # Report IDsi
#             'mijoz_nomi',
#             'xizmat_turi',
#             'sana',
#             'summa',
#             'status', # Original status (filterlash uchun kerak bo'lishi mumkin)
#             'status_display' # Ko'rsatish uchun status
#         ]
#         read_only_fields = fields

#     def get_sana(self, obj):
#         # Tasdiqlangan bo'lsa, updated_at ni olamiz, aks holda created_at ni
#         # Yoki har doim created_at ni ko'rsatish mumkin
#         # return date_format(obj.updated_at if obj.status == 'approved' else obj.created_at, format='Y-m-d', use_l10n=False)
#         return date_format(obj.created_at, format='Y-m-d', use_l10n=False) # Yaratilgan sanani ko'rsatamiz

#     def get_status_display(self, obj):
#         if obj.status == 'approved':
#             return "To'langan"
#         elif obj.status in ['submitted', 'in_review', 'draft']: # Yoki boshqa kutilayotgan statuslar
#             return "Kutilmoqda"
#         elif obj.status == 'rejected':
#             return "Rad etilgan" # Jadvalda ko'rsatilmaydi, lekin bo'lishi mumkin
#         else:
#             return obj.get_status_display() # Modelning standart statusi
