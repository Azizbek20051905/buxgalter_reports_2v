from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin, UserAdmin
# Attachment va Task ni ham import qiling
from .models import User, Accountant, ReportType, Report, ReportComment, Message, PaymentCard, AboutUs, Attachment, Task
from django.utils.html import format_html # Linklar uchun
from django.urls import reverse # Linklar uchun

class UserAdmin(BaseUserAdmin):
    # Maxsus formalar ishlatilmasa, BaseUserAdmin standart formalar bilan ishlashga harakat qiladi
    # form = CustomUserChangeForm
    # add_form = CustomUserCreationForm

    # --- api.User modeliga mos konfiguratsiyalar ---
    # list_display da 'username', 'first_name', 'last_name' yo'qligiga ishonch hosil qiling
    list_display = ('email', 'full_name', 'phone_number', 'role', 'is_active', 'is_staff')
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('email', 'full_name', 'phone_number')
    # ordering da 'username' yo'qligiga ishonch hosil qiling
    ordering = ('email',)

    # Fieldsets (mavjud foydalanuvchini tahrirlash uchun)
    # Barcha maydonlar api.User da mavjudligiga ishonch hosil qiling
    fieldsets = (
        (None, {'fields': ('email', 'password')}), # Parol odatda o'zgartirilmaydi, lekin ko'rsatiladi
        ('Personal Info', {'fields': ('full_name', 'phone_number', 'img')}),
        # Rolga qarab ko'rsatish/yashirish mumkin, lekin hozircha shunday qoldiramiz
        ('Mijoz Info', {'fields': ('company_name', 'stir')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        # AbstractBaseUser dan keladigan maydonni qo'shish
        ('Important dates', {'fields': ('last_login',)}),
    )

    # Add_fieldsets (yangi foydalanuvchi qo'shish uchun)
    # Barcha maydonlar api.User da mavjudligi va yaratish uchun mosligi
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            # Yaratish formasi uchun maydonlar (parol ham kerak!)
            # UserCreationForm ishlatilsa, u parol maydonlarini o'zi qo'shadi
            # Agar add_form aniqlanmasa, BaseUserAdmin standart UserCreationForm ni ishlatadi
            # va u 'username' ni qidirishi mumkin. Shu sababli maxsus add_form kerak bo'lishi ehtimoli bor.
            # Hozircha faqat mavjud maydonlarni ko'rsatamiz:
            'fields': ('email', 'phone_number', 'full_name', 'role', 'password'), # Password ni create_user ga moslab qo'shing
        }),
    )

    filter_horizontal = ('groups', 'user_permissions',)


# Report modeli uchun admin
class ReportAdmin(admin.ModelAdmin):
    # 'total_price' ni olib tashladik, 'category' va 'get_category_price' ni qo'shdik
    list_display = ('id', 'title', 'client', 'accountant', 'status', 'category', 'get_category_price', 'created_at', 'submitted_at')
    # 'category' va 'submitted_at' bo'yicha filterlash qo'shildi
    list_filter = ('status', 'category', 'created_at', 'submitted_at', 'accountant')
    search_fields = ('id', 'title', 'client__full_name', 'accountant__full_name') # id va title bo'yicha qidiruv
    # 'category' uchun ham raw_id_fields qo'shish mumkin
    raw_id_fields = ('client', 'accountant', 'category')
    # filter_horizontal olib tashlandi
    # filter_horizontal = ('report_types',)
    readonly_fields = ('id', 'created_at', 'updated_at', 'submitted_at') # O'zgarmas maydonlar
    date_hierarchy = 'created_at' # Sana bo'yicha navigatsiya

    # Kategoriya narxini ko'rsatish uchun metod
    def get_category_price(self, obj):
        if obj.category and obj.category.price is not None:
             # Narxni formatlash (ixtiyoriy)
             from django.contrib.humanize.templatetags.humanize import intcomma
             return f"{intcomma(obj.category.price)} so'm"
        return "N/A"
    get_category_price.short_description = 'Narxi (Kategoriya)' # Ustun sarlavhasi
    get_category_price.admin_order_field = 'category__price' # Narx bo'yicha saralash

# ReportComment modeli uchun admin (yaxshilangan)
class ReportCommentAdmin(admin.ModelAdmin):
    list_display = ('report_link', 'author', 'comment_short', 'created_at')
    list_filter = ('created_at', 'author__role')
    search_fields = ('comment', 'author__full_name', 'report__id', 'report__title')
    raw_id_fields = ('report', 'author')
    readonly_fields = ('created_at',)

    def report_link(self, obj):
        link = reverse("admin:api_report_change", args=[obj.report.id]) # 'api' - app nomingiz
        return format_html('<a href="{}">Report {}</a>', link, obj.report.id)
    report_link.short_description = 'Hisobot'

    def comment_short(self, obj):
        return obj.comment[:70] + '...' if len(obj.comment) > 70 else obj.comment
    comment_short.short_description = 'Izoh'

class AccountantAdmin(admin.ModelAdmin):
    list_display = ('user', 'experience', 'specialty', 'fee', 'address')
    list_filter = ('specialty',)
    search_fields = ('user__full_name', 'user__email', 'specialty')
    raw_id_fields = ('user',)

# --- ReportTypeAdmin ---
class ReportTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'price')
    search_fields = ('name',)
    list_filter = ('price',)

# --- ReportAdmin --- (O'tgan safargi tuzatishlar bilan)



# Message modeli uchun admin (yaxshilangan)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'recipient', 'message_short', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('sender__full_name', 'recipient__full_name', 'message')
    raw_id_fields = ('sender', 'recipient')
    readonly_fields = ('created_at',)

    def message_short(self, obj):
         return obj.message[:70] + '...' if len(obj.message) > 70 else obj.message
    message_short.short_description = 'Xabar'


# --- Yangi Modellar uchun Admin Classlar ---

class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('report_link', 'file_name', 'file_type', 'file_size_display', 'uploaded_by', 'uploaded_at')
    list_filter = ('file_type', 'uploaded_at')
    search_fields = ('file_name', 'report__id', 'report__title', 'uploaded_by__full_name')
    raw_id_fields = ('report', 'uploaded_by')
    readonly_fields = ('uploaded_at', 'file_name', 'file_size', 'file_type', 'id')

    def report_link(self, obj):
        link = reverse("admin:api_report_change", args=[obj.report.id])
        return format_html('<a href="{}">Report {}</a>', link, obj.report.id)
    report_link.short_description = 'Hisobot'

    def file_size_display(self, obj):
         if obj.file_size:
            if obj.file_size < 1024: return f"{obj.file_size} bytes"
            elif obj.file_size < 1024**2: return f"{obj.file_size/1024:.1f} KB"
            else: return f"{obj.file_size/(1024**2):.1f} MB"
         return "N/A"
    file_size_display.short_description = 'Hajmi'


class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'accountant', 'client', 'report_link', 'status', 'priority', 'due_date', 'created_at')
    list_filter = ('status', 'priority', 'due_date', 'created_at', 'accountant')
    search_fields = ('title', 'description', 'accountant__full_name', 'client__full_name', 'report__id', 'id')
    raw_id_fields = ('accountant', 'client', 'report')
    readonly_fields = ('created_at', 'updated_at', 'completed_at', 'id')
    date_hierarchy = 'created_at'

    def report_link(self, obj):
        if obj.report:
            link = reverse("admin:api_report_change", args=[obj.report.id])
            return format_html('<a href="{}">Report {}</a>', link, obj.report.id)
        return "Yo'q"
    report_link.short_description = 'Hisobot'


# Modellarni ro‘yxatdan o‘tkazish
admin.site.register(User, UserAdmin)
admin.site.register(Accountant, AccountantAdmin)
admin.site.register(ReportType, ReportTypeAdmin)
admin.site.register(Report, ReportAdmin) # Yangilandi
admin.site.register(ReportComment, ReportCommentAdmin) # Yangilandi
admin.site.register(Message, MessageAdmin) # Yangilandi
admin.site.register(PaymentCard),
admin.site.register(AboutUs)
admin.site.register(Attachment, AttachmentAdmin) # Yangi
admin.site.register(Task, TaskAdmin) # Yangi