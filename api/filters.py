import django_filters
from django.contrib.auth import get_user_model
from .models import Report, Payment, User

User = get_user_model()

class UserFilter(django_filters.FilterSet):
    # Rol bo'yicha filterlash uchun (URL query: ?role=mijoz)
    role = django_filters.ChoiceFilter(choices=User.ROLE_CHOICES)

    # Status bo'yicha filterlash uchun ('tasdiqlangan', 'kutilmoqda')
    # 'status' nomli query parametrini ishlatamiz
    status = django_filters.ChoiceFilter(
        choices=[('active', 'Faol'), ('inactive', 'Kutilmoqda')], # Frontendga qulay nomlar
        method='filter_by_status' # Custom filter metodi
    )

    class Meta:
        model = User
        fields = ['role', 'status'] # Qidirish (search) alohida handle qilinadi

    def filter_by_status(self, queryset, name, value):
        if value == 'active':
            return queryset.filter(is_active=True)
        elif value == 'inactive':
            return queryset.filter(is_active=False)
        return queryset # Agar status berilmasa yoki noto'g'ri bo'lsa


class PaymentFilter(django_filters.FilterSet):
    # Status bo'yicha filterlash ('completed', 'pending')
    status = django_filters.ChoiceFilter(
        choices=[('completed', 'Qabul qilingan'), ('pending', 'Kutilayotgan')],
        method='filter_by_payment_status',
        label='To\'lov Statusi'
    )
    # Mijoz yoki Xizmat turi bo'yicha filter qo'shish mumkin
    # client_name = django_filters.CharFilter(field_name='client__full_name', lookup_expr='icontains')
    # service_type = django_filters.CharFilter(field_name='category__name', lookup_expr='icontains')


    class Meta:
        model = Report # Biz Report modelini filterlayapmiz
        fields = ['status'] # Faqat status bo'yicha filter

    def filter_by_payment_status(self, queryset, name, value):
        if value == 'completed':
            # Tasdiqlangan ('approved') hisobotlarni "Qabul qilingan" deb olamiz
            return queryset.filter(status='approved')
        elif value == 'pending':
            # 'submitted', 'in_review' kabi statuslarni "Kutilayotgan" deb olamiz
            # 'draft' ni ham qo'shish/olib tashlash mumkin
            return queryset.filter(status__in=['submitted', 'in_review', 'draft'])
        return queryset

class PaymentModelFilter(django_filters.FilterSet): # Nomini o'zgartirdim
    """
    Yangi Payment modeli uchun filter.
    """
    status = django_filters.ChoiceFilter(choices=Payment.STATUS_CHOICES, label='Status')
    # Mijoz bo'yicha filterlash
    client = django_filters.ModelChoiceFilter(
        queryset=User.objects.filter(role='mijoz'),
        field_name='client',
        label='Mijoz'
    )
    # Buxgalter bo'yicha filterlash (Admin/Buxgalter uchun)
    accountant = django_filters.ModelChoiceFilter(
        queryset=User.objects.filter(role='buxgalter'),
        field_name='accountant',
        label='Buxgalter'
    )
    # Sana bo'yicha filterlash
    start_date = django_filters.DateFilter(field_name='payment_date', lookup_expr='gte', label='Boshlanish sanasi (YYYY-MM-DD)')
    end_date = django_filters.DateFilter(field_name='payment_date', lookup_expr='lte', label='Tugash sanasi (YYYY-MM-DD)')
    # Xizmat turi bo'yicha (Report category orqali)
    service_type = django_filters.CharFilter(field_name='report__category__name', lookup_expr='icontains', label='Xizmat turi')


    class Meta:
        model = Payment
        fields = ['status', 'client', 'accountant', 'start_date', 'end_date', 'service_type']