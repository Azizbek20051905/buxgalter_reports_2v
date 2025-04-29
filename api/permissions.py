from rest_framework import permissions

from api.models import Report


class IsAdminUser(permissions.BasePermission):
    """
    Faqat 'admin' rolidagi foydalanuvchilarga ruxsat beradi.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'admin')

class IsAccountantUser(permissions.BasePermission):
    """
    Faqat 'buxgalter' rolidagi foydalanuvchilarga ruxsat beradi.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'buxgalter')

class IsClientUser(permissions.BasePermission):
    """
    Faqat 'mijoz' rolidagi foydalanuvchilarga ruxsat beradi.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'mijoz')

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Obyekt egasi (client) yoki 'admin' rolidagilarga ruxsat beradi.
    Obyektda 'client' nomli ForeignKey bo'lishi kerak.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
             # Admin hamma narsani ko'ra oladi
            if request.user.role == 'admin':
                return True
            # Buxgalter o'ziga tayinlanganlarni ko'ra oladi
            if hasattr(obj, 'accountant') and obj.accountant == request.user and request.user.role == 'buxgalter':
                 return True
            # Mijoz o'zinikini ko'ra oladi
            if hasattr(obj, 'client') and obj.client == request.user and request.user.role == 'mijoz':
                 return True
            # Task uchun tekshirish
            if hasattr(obj, 'accountant') and obj.accountant == request.user and request.user.role == 'buxgalter': # Task uchun accountant
                 return True
            if hasattr(obj, 'client') and obj.client == request.user and request.user.role == 'mijoz': # Task uchun client
                 return True
            return False


        # Write permissions are only allowed to the owner of the snippet or admin.
        return obj.client == request.user or request.user.role == 'admin'

class IsAssignedAccountantOrAdmin(permissions.BasePermission):
    """
    Obyektga biriktirilgan buxgalter yoki 'admin' rolidagilarga ruxsat beradi.
    Obyektda 'accountant' nomli ForeignKey bo'lishi kerak.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions
        if request.method in permissions.SAFE_METHODS:
            if request.user.role == 'admin':
                return True
            if hasattr(obj, 'accountant') and obj.accountant == request.user:
                 return True
            # Agar report bo'lsa, uning mijoziga ham ko'rishga ruxsat
            if hasattr(obj, 'client') and obj.client == request.user:
                 return True
            return False

        # Write permissions
        return (hasattr(obj, 'accountant') and obj.accountant == request.user) or request.user.role == 'admin'


class CanManageReport(permissions.BasePermission):
    """
    Hisobotni boshqarish uchun murakkab ruxsatnoma:
    - GET: Owner (Client), Assigned Accountant, Admin
    - POST (create): Client
    - PUT/PATCH (update): Owner (Client) if draft/rejected, Admin
    - DELETE: Owner (Client) if draft, Admin
    - submit (action): Owner (Client) if draft/rejected
    - assign (action): Admin
    - update_status (action): Assigned Accountant, Admin
    """
    def has_permission(self, request, view):
        # List uchun: Hamma autentifikatsiyalangan foydalanuvchi
        if view.action == 'list':
            return request.user.is_authenticated
        # Create uchun: Faqat Client
        if view.action == 'create':
            return request.user.is_authenticated and request.user.role == 'mijoz'
        # Boshqa actionlar uchun obyekt darajasida tekshiriladi
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Admin hamma narsani qila oladi (deyarli)
        if request.user.role == 'admin':
            # Admin submit qila olmaydi
            if view.action == 'submit':
                return False
            return True

        is_owner = obj.client == request.user
        is_assigned_accountant = obj.accountant == request.user

        # GET, HEAD, OPTIONS
        if request.method in permissions.SAFE_METHODS or view.action == 'retrieve':
            return is_owner or is_assigned_accountant or request.user.role == 'admin' # Admin allaqachon tekshirilgan

        # Mijoz (Owner) uchun ruxsatlar
        if is_owner and request.user.role == 'mijoz':
            if view.action == 'update' or view.action == 'partial_update':
                # Faqat 'draft' yoki 'rejected' statusdagini o'zgartira oladi
                return obj.status in ['draft', 'rejected']
            if view.action == 'destroy':
                 # Faqat 'draft' statusdagini o'chira oladi
                return obj.status == 'draft'
            if view.action == 'submit':
                # Faqat 'draft' yoki 'rejected' statusdagini yubora oladi
                return obj.status in ['draft', 'rejected']
            # Mijoz assign yoki statusni o'zi o'zgartira olmaydi
            if view.action in ['assign', 'update_status', 'create_task']: # create_task ham qo'shildi
                return False

        # Buxgalter (Assigned) uchun ruxsatlar
        if is_assigned_accountant and request.user.role == 'buxgalter':
            # Buxgalter faqat statusni o'zgartira oladi va task yarata oladi
            if view.action == 'update_status':
                # Qaysi statuslarga o'tkaza olishini cheklash mumkin
                return obj.status in ['submitted', 'in_review'] # Masalan: faqat shu statuslardan keyin
            if view.action == 'create_task':
                 return True
            # Buxgalter update, delete, submit, assign qila olmaydi
            return False

        # Agar yuqoridagilar bajarilmasa, ruxsat yo'q
        return False


class CanManageTask(permissions.BasePermission):
    """
    Vazifani boshqarish uchun ruxsatnoma:
    - GET: Assigned Accountant, Related Client (agar bog'langan bo'lsa), Admin
    - POST (create): Assigned Accountant (from report), Admin
    - PUT/PATCH (update): Assigned Accountant, Admin
    - DELETE: Assigned Accountant, Admin
    - update_status (action): Assigned Accountant, Admin
    """
    def has_permission(self, request, view):
        # List: Faqat Accountant va Admin
        if view.action == 'list':
            return request.user.is_authenticated and request.user.role in ['buxgalter', 'admin']
        # Create: Accountant (reportdan) yoki Admin
        # Create logikasi viewda tekshiriladi (reportId bormi?)
        if view.action == 'create':
             return request.user.is_authenticated and request.user.role in ['buxgalter', 'admin']
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        is_assigned_accountant = obj.accountant == request.user
        is_related_client = obj.client == request.user
        is_admin = request.user.role == 'admin'

        # Admin hamma narsaga ruxsat (deyarli)
        if is_admin:
            return True

        # Accountant uchun ruxsatlar
        if is_assigned_accountant and request.user.role == 'buxgalter':
            # GET, PUT, PATCH, DELETE, update_status
            return True

        # Client uchun ruxsatlar
        if is_related_client and request.user.role == 'mijoz':
            # Faqat GET (ko'rish)
            if request.method in permissions.SAFE_METHODS or view.action == 'retrieve':
                 return True
        
        return False


class CanManageAttachment(permissions.BasePermission):
    """
    Ilovani boshqarish ruxsatnomasi (Reportga bog'liq):
    - GET: Reportni ko'ra oladiganlar (Owner, Assigned Accountant, Admin)
    - POST (create): Report egasi (Client) agar report draft/rejected bo'lsa
    - DELETE: Report egasi (Client) agar report draft/rejected bo'lsa, Admin
    """
    def has_permission(self, request, view):
        # report_pk ni view.kwargs dan olish kerak
        report_id = view.kwargs.get('report_pk')
        if not report_id:
            return False
        try:
            report = Report.objects.get(pk=report_id)
        except Report.DoesNotExist:
            return False

        # Ruxsatni report uchun tekshirish orqali aniqlaymiz
        report_permission = CanManageReport()

        # POST (create)
        if view.action == 'create':
            # Faqat report egasi va status mos kelsa
            return report.client == request.user and report.status in ['draft', 'rejected']

        # List uchun GET
        if view.action == 'list':
            return report_permission.has_object_permission(request, view, report)

        # Boshqa actionlar (retrieve, destroy) obyekt darajasida
        return request.user.is_authenticated # Dastlabki tekshiruv

    def has_object_permission(self, request, view, obj):
        report = obj.report
        is_owner = report.client == request.user
        is_admin = request.user.role == 'admin'

        report_permission = CanManageReport() # Reportni ko'rish ruxsatini tekshirish uchun

        # GET (retrieve)
        if request.method in permissions.SAFE_METHODS or view.action == 'retrieve':
            # Reportni ko'ra oladigan har kim ilovani ham ko'ra oladi
            return report_permission.has_object_permission(request, view, report)

        # DELETE (destroy)
        if view.action == 'destroy':
            # Faqat owner (agar status mos kelsa) yoki admin
            return (is_owner and report.status in ['draft', 'rejected']) or is_admin

        return False

class CanManageComment(permissions.BasePermission):
    """
    Izohni boshqarish ruxsatnomasi (Reportga bog'liq):
    - GET: Reportni ko'ra oladiganlar (Owner, Assigned Accountant, Admin)
    - POST (create): Reportni ko'ra oladiganlar (Owner, Assigned Accountant, Admin)
    - PUT/PATCH: Izoh muallifi
    - DELETE: Izoh muallifi, Admin
    """
    def has_permission(self, request, view):
        report_id = view.kwargs.get('report_pk')
        if not report_id:
             return False
        try:
            report = Report.objects.get(pk=report_id)
        except Report.DoesNotExist:
            return False

        report_permission = CanManageReport()

        # POST (create) yoki List (GET)
        if view.action in ['create', 'list']:
             # Reportni ko'ra oladigan har kim izoh qoldira oladi yoki ko'ra oladi
            return report_permission.has_object_permission(request, view, report)

        return request.user.is_authenticated # Dastlabki tekshiruv

    def has_object_permission(self, request, view, obj):
        report = obj.report
        is_author = obj.author == request.user
        is_admin = request.user.role == 'admin'
        report_permission = CanManageReport()

        # GET (retrieve)
        if request.method in permissions.SAFE_METHODS or view.action == 'retrieve':
            return report_permission.has_object_permission(request, view, report)

        # PUT/PATCH (update)
        if view.action in ['update', 'partial_update']:
             # Faqat muallif o'zgartira oladi
            return is_author

        # DELETE (destroy)
        if view.action == 'destroy':
             # Mu   allif yoki Admin o'chira oladi
            return is_author or is_admin

        return False