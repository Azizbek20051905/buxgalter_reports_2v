import uuid
from django.db import models
from django.conf import settings # User modelini olish uchun
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# --- User va Accountant modellari (o'zgarishsiz qoldiriladi) ---
class UserManager(BaseUserManager):
    def create_user(self, email, phone_number, full_name, password=None, role='mijoz', **extra_fields):
        if not email:
            raise ValueError("Email kiritish majburiy")
        email = self.normalize_email(email)
        user = self.model(email=email, phone_number=phone_number, full_name=full_name, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone_number, full_name, password):
        user = self.create_user(email, phone_number, full_name, password, role='admin')
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('mijoz', 'Mijoz'),         # TZ: client
        ('buxgalter', 'Buxgalter'), # TZ: accountant
        ('admin', 'Admin'),         # TZ: admin
    ]

    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    full_name = models.CharField(max_length=255)
    img = models.ImageField(upload_to='user_images/', blank=True, null=True)

    # Mijozlar uchun
    company_name = models.CharField(max_length=255, blank=True, null=True)
    stir = models.CharField(max_length=20, blank=True, null=True)

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='mijoz')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False) # Admin paneliga kirish uchun

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number', 'full_name']

    def __str__(self):
        return f"{self.full_name} ({self.get_role_display()})" # Rolni ko'rsatish

class Accountant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='accountant_profile') # related_name qo'shildi
    certifications = models.TextField(blank=True, null=True)
    fee = models.DecimalField(max_digits=10, decimal_places=2, default=0) # DecimalField yaxshiroq
    experience = models.IntegerField(blank=True, null=True)
    specialty = models.CharField(max_length=100, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    skills = models.TextField(blank=True, null=True)
    languages = models.CharField(max_length=255, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.user.full_name

# --- ReportType (o'zgarishsiz qoldiriladi, lekin TZ da 'category' sifatida ishlatilishi mumkin) ---
class ReportType(models.Model):
    name = models.CharField(max_length=255) # TZ dagi category ga mos kelishi mumkin
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0) # Narx ixtiyoriy bo'lishi mumkin

    def __str__(self):
        return self.name

# --- Report modelini TZ ga moslash ---
class Report(models.Model):
    STATUS_CHOICES = [
        ('draft', 'Qoralama'),         # TZ: draft
        ('submitted', 'Yuborilgan'),   # TZ: submitted
        ('in_review', 'Ko‘rib chiqilmoqda'), # TZ: in_review
        ('approved', 'Tasdiqlandi'),    # TZ: approved
        ('rejected', 'Rad etildi'),     # TZ: rejected
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) # TZ: string/uuid
    title = models.CharField(max_length=255) # TZ: title
    description = models.TextField(blank=True, null=True) # TZ: description
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='client_reports', limit_choices_to={'role': 'mijoz'}) # TZ: clientId
    accountant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_reports', limit_choices_to={'role': 'buxgalter'}) # TZ: accountantId
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft') # TZ: status
    created_at = models.DateTimeField(auto_now_add=True) # TZ: createdAt
    updated_at = models.DateTimeField(auto_now=True) # TZ: updatedAt
    submitted_at = models.DateTimeField(null=True, blank=True) # TZ: submittedAt

    # ReportType ni category sifatida ishlatsak bo'ladi yoki alohida category field qo'shish mumkin
    category = models.ForeignKey(ReportType, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports') # TZ: category (ReportType bilan bog'ladik)
    # Yoki alohida CharField: category_name = models.CharField(max_length=100, blank=True, null=True)

    # Period
    start_date = models.DateField(null=True, blank=True) # TZ: period.startDate
    end_date = models.DateField(null=True, blank=True) # TZ: period.endDate

    # Eski report_types va total_price ni olib tashlaymiz yoki moslashtiramiz
    # report_types = models.ManyToManyField(ReportType) # Bu endi category orqali
    # total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0) # Narxni category dan olsak bo'ladi

    # calculate_total_price va save metodlarini moslashtirish kerak bo'ladi (agar narx kerak bo'lsa)

    def __str__(self):
        return f"Report {self.id} by {self.client.full_name} ({self.get_status_display()})"


# --- Yangi Attachment modeli ---
def report_attachment_path(instance, filename):
    # Faylni report ID si bilan papkaga joylash: reports/<report_id>/<filename>
    return f'reports/{instance.report.id}/attachments/{filename}'

class Attachment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) # TZ: id
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='attachments') # TZ: reportId
    file = models.FileField(upload_to=report_attachment_path) # Faylning o'zi
    file_name = models.CharField(max_length=255, blank=True) # TZ: fileName (avtomatik to'ldiriladi)
    file_size = models.PositiveIntegerField(blank=True, null=True) # TZ: fileSize (avtomatik to'ldiriladi)
    file_type = models.CharField(max_length=100, blank=True) # TZ: fileType (avtomatik to'ldiriladi)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='uploaded_attachments') # TZ: uploadedBy
    uploaded_at = models.DateTimeField(auto_now_add=True) # TZ: uploadedAt
    # fileUrl - serializerda dinamik generatsiya qilinadi

    def save(self, *args, **kwargs):
        if self.file and not self.file_name:
            self.file_name = self.file.name
        if self.file and not self.file_size:
             try:
                self.file_size = self.file.size
             except Exception: # Agar fayl hali saqlanmagan bo'lsa
                 pass
        if self.file and not self.file_type:
            # Mime turini aniqlash (python-magic kabi kutubxona kerak bo'lishi mumkin)
            # Hozircha fayl kengaytmasidan olamiz
            parts = self.file.name.split('.')
            if len(parts) > 1:
                self.file_type = parts[-1].lower()
        super().save(*args, **kwargs)

    def get_file_url(self, request=None):
        if self.file:
            if request:
                return request.build_absolute_uri(self.file.url)
            return self.file.url # Faqat nisbiy URL
        return None

    def __str__(self):
        return f"Attachment {self.file_name} for Report {self.report.id}"


# --- ReportComment modelini TZ ga moslash ---
class ReportComment(models.Model):
    # id avtomatik generatsiya qilinadi (agar primary_key=True qilinmasa)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) # TZ: id
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='comments') # TZ: reportId
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='report_comments') # TZ: userId
    # userType ni author.role orqali olamiz
    comment = models.TextField() # TZ: text
    created_at = models.DateTimeField(auto_now_add=True) # TZ: createdAt

    def __str__(self):
        return f"Comment by {self.author.full_name} on Report {self.report.id}"

    @property
    def user_type(self): # TZ: userType
        return self.author.role


# --- Yangi Task modeli ---
class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Kutilmoqda'),         # TZ: pending
        ('in_progress', 'Jarayonda'),    # TZ: in_progress
        ('completed', 'Bajarildi'),      # TZ: completed
        ('cancelled', 'Bekor qilindi'),    # TZ: cancelled
    ]
    PRIORITY_CHOICES = [
        ('low', 'Past'),       # TZ: low
        ('medium', 'O\'rta'),  # TZ: medium
        ('high', 'Yuqori'),     # TZ: high
        ('urgent', 'Shoshilinch'), # TZ: urgent
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) # TZ: id
    title = models.CharField(max_length=255) # TZ: title
    description = models.TextField(blank=True, null=True) # TZ: description
    accountant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='tasks', limit_choices_to={'role': 'buxgalter'}) # TZ: accountantId
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='related_tasks', limit_choices_to={'role': 'mijoz'}) # TZ: clientId (Reportdan olinishi ham mumkin)
    report = models.ForeignKey(Report, on_delete=models.SET_NULL, null=True, blank=True, related_name='tasks') # TZ:  
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending') # TZ: status
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium') # TZ: priority
    due_date = models.DateField(null=True, blank=True) # TZ: dueDate
    created_at = models.DateTimeField(auto_now_add=True) # TZ: createdAt
    updated_at = models.DateTimeField(auto_now=True) # TZ: updatedAt
    completed_at = models.DateTimeField(null=True, blank=True) # TZ: completedAt

    def save(self, *args, **kwargs):
        # Agar client belgilanmagan bo'lsa va report mavjud bo'lsa, reportning clientini olish
        if not self.client and self.report:
            self.client = self.report.client
        # Agar status 'completed' ga o'zgarsa va completed_at bo'sh bo'lsa, vaqtni belgilash
        if self.status == 'completed' and self.completed_at is None:
            from django.utils import timezone
            self.completed_at = timezone.now()
        elif self.status != 'completed': # Agar status boshqasiga o'zgarsa, completed_at ni bo'shatish
            self.completed_at = None
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Task '{self.title}' for {self.accountant.full_name}"


# --- Qolgan modellar (Message, PaymentCard, AboutUs) (o'zgarishsiz) ---
class Message(models.Model):
    # ... (mavjud kod)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender.full_name} → {self.recipient.full_name}: {self.message[:30]}..."

class PaymentCard(models.Model):
    # ... (mavjud kod)
    card_number = models.CharField(max_length=16, unique=True)
    owner_name = models.CharField(max_length=255)
    bank_name = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.bank_name} - {self.card_number[-4:]}"


class AboutUs(models.Model):
    # ... (mavjud kod)
    img = models.ImageField(upload_to='aboutus/', blank=True, null=True)
    title = models.CharField(max_length=255)
    text = models.TextField()

    def __str__(self):
        return self.title




























